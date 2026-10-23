"""ger コマンド。

  ger verify  <ger-input.json> --operator NAME
  ger dry-run <ger-input.json> --operator NAME -o remediation-log.json
  ger apply   <ger-input.json> --operator NAME -o remediation-log.json
  ger verify-log [LOG]   監査ログのハッシュチェーンを検証する（読むだけ。監査ログには記録しない）

終了コード: 0=成功 / 3=ゲートで拒否（何も変更していない） / 4=失敗しロールバック済み /
           5=ロールバックも失敗、または適用後に remediation-log を書けなかった（要手動対応） /
           64=引数・環境エラー / 70=内部エラー（verify-log: 0=健全 / 3=破損 / 64=ログが無い）
環境変数: GER_LOG_DIR（監査ログ。起動時に実パスへ解決する）、GER_DRYRUN_TTL（dry-run 記録の有効秒数、既定 86400）、
         GER_ALLOW_NOW_OVERRIDE（=1 のときだけ --now を受け付ける。テスト専用）
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys

from pathlib import Path

from . import audit, executor
from .core import Rejection, canonical, fmt_ts, input_hash, load_json, now_utc, plan_hash, sha256, validator, write_atomic
from .gates import check_gates, with_ancestors
from .jsonschema_lite import safe_text

EXIT_OK, EXIT_REJECTED, EXIT_ROLLED_BACK, EXIT_ROLLBACK_FAILED, EXIT_USAGE, EXIT_INTERNAL = 0, 3, 4, 5, 64, 70
_PERSON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        _err(f"ger: {message}")
        sys.exit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ger", description="GER — Gated-Exec Remediation（修復層）")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("verify-log", help="監査ログのハッシュチェーンを検証する")
    s.add_argument("log", nargs="?", help="検証するログ（既定 $GER_LOG_DIR/ger-audit.jsonl）")
    for name in ("verify", "dry-run", "apply"):
        s = sub.add_parser(name)
        s.add_argument("input")
        s.add_argument("--operator", required=True, help="実行者。承認者と同一人物は不可（G-4）")
        s.add_argument("--now", help="現在時刻の上書き（RFC 3339 UTC、テスト専用。GER_ALLOW_NOW_OVERRIDE=1 が必要）")
        if name != "verify":
            s.add_argument("-o", "--output", required=True, help="remediation-log.json の出力先")
    return p


def _err(text: str) -> None:
    """標準エラー出力へ。入力由来の文字列（キー名・対象パス・例外の文言）を含みうるため制御文字をエスケープする。"""
    print(safe_text(text), file=sys.stderr)


def _ttl() -> int:
    raw = os.environ.get("GER_DRYRUN_TTL", "86400")
    if not raw.isdigit() or not 0 < int(raw) <= 7 * 86400:
        raise ValueError("GER_DRYRUN_TTL は 1〜604800 の整数（秒）で指定してください")
    return int(raw)


def _verify_log(path: str | None) -> int:
    p = Path(path) if path else audit.log_path()
    if not p.exists():
        _err(f"ger verify-log: 監査ログがありません: {p}")
        return EXIT_USAGE
    try:
        n, problems = audit.scan_chain(p)
    except OSError as e:
        _err(f"ger verify-log: 監査ログを読めません（{e}）")
        return EXIT_USAGE
    if problems:
        _err(f"ger verify-log: ハッシュチェーンが壊れています（{len(problems)} 件、全 {n} 行）: {p}")
        for x in problems:
            _err(f"  {x}")
        return EXIT_REJECTED
    _err(f"ger verify-log: OK（{n} 件、ハッシュチェーンは健全）: {p}")
    return EXIT_OK


def _same_path(a: str, b: str) -> bool:
    """a と b が同じファイルを指すか（実パスが同じ、または既存なら同じ (st_dev, st_ino)。ハードリンクも検出する）。"""
    if os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:  # どちらかが存在しない
        return False


def _check_output(path: str, input_path: str) -> None:
    """変更を始める前に -o の出力先を検証する（書けないと分かっている出力先で apply しない）。

    os.replace で置き換えるため、監査ログ（とそのディレクトリ内のファイル）や入力ファイルは指定できない。
    既存のパスは通常ファイルに限る（シンボリックリンク・FIFO・ソケット・デバイスは置き換えずに拒否する）。
    """
    if not path or path.endswith("/"):  # abspath は "" を cwd に、末尾の / を落として解釈してしまう
        raise ValueError(f"-o にはファイルのパスを指定してください（空のパス・末尾が / のパスは不可）: {path!r}")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as e:  # 途中の要素がファイル（ENOTDIR）など
        raise ValueError(f"-o の出力先を確認できません: {path}（{e.strerror}）") from None
    if st is not None and stat.S_ISDIR(st.st_mode):
        raise ValueError(f"-o にディレクトリは指定できません: {path}")
    if st is not None and stat.S_ISLNK(st.st_mode):  # os.replace はリンク先ではなくリンク自体を置き換えるため拒否する
        raise ValueError(f"-o にシンボリックリンクは指定できません: {path}")
    if st is not None and not stat.S_ISREG(st.st_mode):  # FIFO・ソケット・デバイス（/dev/null など）を置き換えない
        raise ValueError(f"-o に通常ファイル以外は指定できません: {path}")
    d = os.path.dirname(path) or "."  # 与えられたパスのままの親（abspath で .. などを畳まない）
    if not os.path.isdir(d):
        raise ValueError(f"-o の出力先ディレクトリがありません: {d}")
    if not os.access(d, os.W_OK | os.X_OK):
        raise ValueError(f"-o の出力先ディレクトリに書き込めません: {d}")
    if _same_path(path, str(audit.log_path())):
        raise ValueError(f"-o に監査ログは指定できません: {path}")
    if any(_same_path(x, str(audit.log_dir())) for x in (d, os.path.dirname(os.path.realpath(path)))):
        raise ValueError(f"-o に監査ログのディレクトリ内のファイルは指定できません: {path}")
    if _same_path(path, input_path):
        raise ValueError(f"-o に入力ファイルは指定できません: {path}")


def _output_clash(path: str, prepared) -> str | None:
    """-o が計画の対象（chmod するファイル）と同じファイルなら理由を返す。対象は入力を読んだ後にしか分からない。"""
    try:
        st = os.stat(path)
        ino = (st.st_dev, st.st_ino)
    except OSError:
        ino = None
    # 出力先ディレクトリやその上位を変更すると apply 後に remediation-log を書けなくなる
    dir_paths, dir_ino = with_ancestors(os.path.dirname(path) or ".")
    for p in prepared:
        if os.path.realpath(path) == p.target or ino == p.ident[:2]:
            return f"-o に計画の対象は指定できません（{p.target}）"
        if p.target in dir_paths or p.ident[:2] in dir_ino:
            return f"-o の出力先ディレクトリやその上位ディレクトリは計画の対象にできません（{p.target}）"
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    audit.configure()  # GER_LOG_DIR をここで一度だけ実パスに解決し、以後のログの読み書きはそのパスで行う
    if args.command == "verify-log":
        return _verify_log(args.log)
    if not _PERSON.fullmatch(args.operator):
        _err("ger: --operator の形式が不正です")
        return EXIT_USAGE
    if args.now and os.environ.get("GER_ALLOW_NOW_OVERRIDE") != "1":
        _err("ger: --now はテスト専用です（GER_ALLOW_NOW_OVERRIDE=1 のときだけ受け付けます）")
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
        ttl = _ttl()
        if getattr(args, "output", None) is not None:
            _check_output(args.output, args.input)
    except ValueError as e:
        _err(f"ger: {e}")
        return EXIT_USAGE
    try:
        audit.ensure_writable()
    except OSError as e:
        _err(f"ger: {e}（記録できないため実行しません）")
        return EXIT_USAGE

    clock = (lambda: now) if args.now else now_utc
    record = {"command": args.command, "operator": args.operator, "started_at": fmt_ts(clock())}
    if args.now:  # --now 付きの dry-run 記録は --now なしの apply の根拠にしない（G-8）
        record["now_override"] = True
    code = EXIT_OK
    rejections = []
    log_obj = None
    changed = unlogged = False  # apply が変更を残している可能性（成功、またはロールバック失敗）
    outcome = None  # executor.apply の結果（None は全件適用、またはまだ apply していない）
    result = None  # 終了コードから決まらない監査ログの result（変更は適用したが remediation-log を書けなかった）
    try:
        inp = load_json(args.input)
    except (OSError, ValueError) as e:
        _err(f"ger: 入力を読めません: {e}")
        inp, code = None, EXIT_REJECTED
        rejections = [Rejection("G-1", f"入力を JSON として読めません: {e}")]
    if inp is not None:
        if isinstance(inp, dict):
            record["input_hash"] = input_hash(inp)
            plan = inp.get("plan") if isinstance(inp.get("plan"), dict) else {}
            if isinstance(plan.get("plan_id"), str):
                record["plan_id"] = plan["plan_id"]
            try:
                record["plan_hash"] = plan_hash(plan)
            except (TypeError, ValueError):
                pass
        try:
            rejections, prepared = check_gates(inp, args.operator, now, args.command, ttl, now_override=bool(args.now))
            clash = None if rejections or args.command == "verify" else _output_clash(args.output, prepared)
            if rejections:
                code = EXIT_REJECTED
            elif clash:  # 変更を始める前に止める（ゲートの拒否ではなく引数エラーとして記録する）
                _err(f"ger: {clash}（何も変更していません）")
                record["error"] = clash
                code = EXIT_USAGE
            elif args.command == "dry-run":
                log_obj = _log(inp, "dry-run", record["started_at"], clock(), executor.dry_run(inp["plan"], prepared), "ok")
            elif args.command == "apply":
                results, outcome = executor.apply(inp["plan"], prepared, clock)
                changed = outcome in (None, executor.ROLLBACK_FAILED)
                status = "error" if outcome else ("partial" if inp["plan"]["status"] == "partial" else "ok")
                log_obj = _log(inp, "apply", record["started_at"], clock(), results, status)
                code = {None: EXIT_OK, executor.ROLLED_BACK: EXIT_ROLLED_BACK}.get(outcome, EXIT_ROLLBACK_FAILED)
        except Exception as e:  # 想定外は fail-closed
            _err(f"ger: 内部エラー: {type(e).__name__}: {str(e)[:200]}")
            code = EXIT_INTERNAL

    if rejections:
        _err(f"ger {args.command}: 拒否 {len(rejections)} 件（何も変更していません）")
        for r in rejections:
            fid = f" [{r.finding_id}]" if r.finding_id else ""
            _err(f"  {r.gate}{fid}: {r.message}")
        record["gate_failed"] = sorted({r.gate for r in rejections})
    if log_obj is not None:
        errs = validator("remediation-log.schema.json").errors(log_obj)
        if errs:  # 自分の出力が契約に合わない場合も fail-closed
            _err(f"ger: 出力が remediation-log スキーマに不適合: {errs[0]}")
            code = EXIT_INTERNAL if code == EXIT_OK else code
        # 監査ログより先に書き出す。書けなければ output_hash を記録せず、成功（ok）としても記録しない
        try:
            write_atomic(args.output, log_obj)
            record["output_hash"] = sha256(canonical(log_obj))
        except OSError as e:
            _err(f"ger: remediation-log を書き出せません（{e}）")
            unlogged = changed
            _remove_stale_output(args.output)
            if changed:
                if outcome is None:  # 全件適用した（ロールバックはしていない）。rollback_failed とは記録しない
                    result = "applied_unlogged"
                code = EXIT_ROLLBACK_FAILED
                _err(f"ger {args.command}: 変更を適用した可能性がありますが remediation-log を残せませんでした。"
                     "監査ログと対象の権限を確認して手動で対応してください")
            elif code == EXIT_OK:
                code = EXIT_USAGE
    result = result or {EXIT_OK: "ok", EXIT_REJECTED: "rejected", EXIT_ROLLED_BACK: "rolled_back",
                        EXIT_ROLLBACK_FAILED: "rollback_failed"}.get(code, "error")
    record.update({"finished_at": fmt_ts(clock()), "result": result})
    try:
        audit.append(record)
    except OSError as e:
        _err(f"ger: 監査ログに記録できません（{e}）")
        # apply は既に変更している可能性があるため要手動対応として扱う
        return EXIT_ROLLBACK_FAILED if args.command == "apply" and code != EXIT_REJECTED else EXIT_USAGE
    if unlogged:
        return code  # remediation-log を書けなかった旨は表示済み
    msg = {EXIT_OK: "OK", EXIT_ROLLED_BACK: "失敗したため全件ロールバックしました",
           EXIT_ROLLBACK_FAILED: "失敗し、ロールバックも完了できませんでした。remediation-log を確認して手動で対応してください"}.get(code)
    if msg:
        _err(f"ger {args.command}: {msg}")
    return code


def _remove_stale_output(path: str) -> None:
    """書き出しに失敗したとき、以前の実行の remediation-log が今回のものと取り違えられないよう消す。

    出力先は _check_output で通常ファイル（または未作成）と確認済みで、成功していれば置き換えていたもの。
    """
    try:
        os.unlink(path)
        _err(f"ger: 以前の remediation-log を削除しました: {path}")
    except FileNotFoundError:
        pass
    except OSError as e:
        _err(f"ger: 以前の remediation-log を削除できません。今回の実行の記録ではありません: {path}（{e}）")


def _log(inp: dict, mode: str, started_at: str, finished, results: list[dict], status: str) -> dict:
    return {"schema_version": "1.0", "plan_id": inp["plan"]["plan_id"], "plan_hash": inp["plan"]["plan_hash"],
            "mode": mode, "started_at": started_at, "finished_at": fmt_ts(finished), "status": status, "results": results}
