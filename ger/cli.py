"""ger コマンド。

  ger verify  <ger-input.json> --operator NAME
  ger dry-run <ger-input.json> --operator NAME -o remediation-log.json
  ger apply   <ger-input.json> --operator NAME -o remediation-log.json

終了コード: 0=成功 / 3=ゲートで拒否（何も変更していない） / 4=失敗しロールバック済み /
           5=ロールバックも失敗（要手動対応） / 64=引数・環境エラー / 70=内部エラー
環境変数: GER_LOG_DIR（監査ログ）、GER_DRYRUN_TTL（dry-run 記録の有効秒数、既定 86400）、
         GER_ALLOW_NOW_OVERRIDE（=1 のときだけ --now を受け付ける。テスト専用）
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from . import audit, executor
from .core import Rejection, canonical, fmt_ts, input_hash, load_json, now_utc, plan_hash, sha256, validator, write_atomic
from .gates import check_gates

EXIT_OK, EXIT_REJECTED, EXIT_ROLLED_BACK, EXIT_ROLLBACK_FAILED, EXIT_USAGE, EXIT_INTERNAL = 0, 3, 4, 5, 64, 70
_PERSON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"ger: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ger", description="GER — Gated-Exec Remediation（修復層）")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("verify", "dry-run", "apply"):
        s = sub.add_parser(name)
        s.add_argument("input")
        s.add_argument("--operator", required=True, help="実行者。承認者と同一人物は不可（G-4）")
        s.add_argument("--now", help="現在時刻の上書き（RFC 3339 UTC、テスト専用。GER_ALLOW_NOW_OVERRIDE=1 が必要）")
        if name != "verify":
            s.add_argument("-o", "--output", required=True, help="remediation-log.json の出力先")
    return p


def _ttl() -> int:
    raw = os.environ.get("GER_DRYRUN_TTL", "86400")
    if not raw.isdigit() or not 0 < int(raw) <= 7 * 86400:
        raise ValueError("GER_DRYRUN_TTL は 1〜604800 の整数（秒）で指定してください")
    return int(raw)


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
    """
    if os.path.isdir(path):
        raise ValueError(f"-o にディレクトリは指定できません: {path}")
    d = os.path.dirname(os.path.abspath(path))
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
    for p in prepared:
        if os.path.realpath(path) == p.target or ino == p.ident[:2]:
            return f"-o に計画の対象は指定できません（{p.target}）"
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _PERSON.fullmatch(args.operator):
        print("ger: --operator の形式が不正です", file=sys.stderr)
        return EXIT_USAGE
    if args.now and os.environ.get("GER_ALLOW_NOW_OVERRIDE") != "1":
        print("ger: --now はテスト専用です（GER_ALLOW_NOW_OVERRIDE=1 のときだけ受け付けます）", file=sys.stderr)
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
        ttl = _ttl()
        if getattr(args, "output", None) is not None:
            _check_output(args.output, args.input)
    except ValueError as e:
        print(f"ger: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        audit.ensure_writable()
    except OSError as e:
        print(f"ger: {e}（記録できないため実行しません）", file=sys.stderr)
        return EXIT_USAGE

    clock = (lambda: now) if args.now else now_utc
    record = {"command": args.command, "operator": args.operator, "started_at": fmt_ts(clock())}
    code = EXIT_OK
    rejections = []
    log_obj = None
    changed = unlogged = False  # apply が変更を残している可能性（成功、またはロールバック失敗）
    try:
        inp = load_json(args.input)
    except (OSError, ValueError) as e:
        print(f"ger: 入力を読めません: {e}", file=sys.stderr)
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
            rejections, prepared = check_gates(inp, args.operator, now, args.command, ttl)
            clash = None if rejections or args.command == "verify" else _output_clash(args.output, prepared)
            if rejections:
                code = EXIT_REJECTED
            elif clash:  # 変更を始める前に止める（ゲートの拒否ではなく引数エラーとして記録する）
                print(f"ger: {clash}（何も変更していません）", file=sys.stderr)
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
            print(f"ger: 内部エラー: {e!r}", file=sys.stderr)
            code = EXIT_INTERNAL

    if rejections:
        print(f"ger {args.command}: 拒否 {len(rejections)} 件（何も変更していません）", file=sys.stderr)
        for r in rejections:
            fid = f" [{r.finding_id}]" if r.finding_id else ""
            print(f"  {r.gate}{fid}: {r.message}", file=sys.stderr)
        record["gate_failed"] = sorted({r.gate for r in rejections})
    if log_obj is not None:
        errs = validator("remediation-log.schema.json").errors(log_obj)
        if errs:  # 自分の出力が契約に合わない場合も fail-closed
            print(f"ger: 出力が remediation-log スキーマに不適合: {errs[0]}", file=sys.stderr)
            code = EXIT_INTERNAL if code == EXIT_OK else code
        # 監査ログより先に書き出す。書けなければ output_hash を記録せず、成功（ok）としても記録しない
        try:
            write_atomic(args.output, log_obj)
            record["output_hash"] = sha256(canonical(log_obj))
        except OSError as e:
            print(f"ger: remediation-log を書き出せません（{e}）", file=sys.stderr)
            unlogged = changed
            if changed:
                code = EXIT_ROLLBACK_FAILED
                print(f"ger {args.command}: 変更を適用した可能性がありますが remediation-log を残せませんでした。"
                      "監査ログと対象の権限を確認して手動で対応してください", file=sys.stderr)
            elif code == EXIT_OK:
                code = EXIT_USAGE
    record.update({"finished_at": fmt_ts(clock()),
                   "result": {EXIT_OK: "ok", EXIT_REJECTED: "rejected", EXIT_ROLLED_BACK: "rolled_back",
                              EXIT_ROLLBACK_FAILED: "rollback_failed"}.get(code, "error")})
    try:
        audit.append(record)
    except OSError as e:
        print(f"ger: 監査ログに記録できません（{e}）", file=sys.stderr)
        # apply は既に変更している可能性があるため要手動対応として扱う
        return EXIT_ROLLBACK_FAILED if args.command == "apply" and code != EXIT_REJECTED else EXIT_USAGE
    if unlogged:
        return code  # remediation-log を書けなかった旨は表示済み
    msg = {EXIT_OK: "OK", EXIT_ROLLED_BACK: "失敗したため全件ロールバックしました",
           EXIT_ROLLBACK_FAILED: "失敗し、ロールバックも完了できませんでした。remediation-log を確認して手動で対応してください"}.get(code)
    if msg:
        print(f"ger {args.command}: {msg}", file=sys.stderr)
    return code


def _log(inp: dict, mode: str, started_at: str, finished, results: list[dict], status: str) -> dict:
    return {"schema_version": "1.0", "plan_id": inp["plan"]["plan_id"], "plan_hash": inp["plan"]["plan_hash"],
            "mode": mode, "started_at": started_at, "finished_at": fmt_ts(finished), "status": status, "results": results}
