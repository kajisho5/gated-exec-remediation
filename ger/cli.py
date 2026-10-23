"""ger コマンド。

  ger verify  <ger-input.json> --operator NAME
  ger dry-run <ger-input.json> --operator NAME -o remediation-log.json
  ger apply   <ger-input.json> --operator NAME -o remediation-log.json
  ger preview <draft-plan.json> --operator NAME -o previewed-plan.json [--report R] [--diff]
                         下書きの action の params（ハッシュ・ops・expected_after_sha256）を現在の内容から埋める（変更しない）
  ger confirm <ger-input.json> --operator NAME --item FINDING_ID --step CL-XXX:sN
                         checklist / followup の手順を作業者が確認したことを監査ログに記録する
  ger restore <restore-request.json> --operator NAME -o remediation-log.json
                         隔離ストアのエントリを元の場所へ戻す（承認者 2 名、dry-run 必須）
  ger recover <ger-input.json> --operator NAME -o remediation-log.json
                         途中で落ちた apply をジャーナルから巻き戻す
  ger quarantine-list [--json] [--plan-id ID]   隔離ストアの一覧とマニフェストの検証（読むだけ）
  ger verify-log [LOG]   監査ログのハッシュチェーンを検証する（読むだけ。監査ログには記録しない）

終了コード: 0=成功 / 3=ゲートで拒否（何も変更していない） / 4=失敗しロールバック済み /
           5=ロールバックも失敗、または適用後に remediation-log を書けなかった（要手動対応） /
           64=引数・環境エラー / 70=内部エラー（verify-log: 0=健全 / 3=破損 / 64=ログが無い）
環境変数: GER_LOG_DIR（監査ログ。起動時に実パスへ解決する）、GER_DRYRUN_TTL（dry-run 記録の有効秒数、既定 86400）、
         GER_APPROVAL_MAX_AGE（承認の有効秒数、既定 604800）、
         GER_QUARANTINE_DIR（隔離ストア。既定 $XDG_STATE_HOME/ger/quarantine または ~/.local/state/ger/quarantine）、
         GER_ALLOW_NOW_OVERRIDE（=1 のときだけ --now と now_override: true の計画を受け付ける。テスト専用）
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys

from pathlib import Path

import copy
import json

from . import audit, executor, fsutil, store
from . import restore as restore_mod
from .actions import FS_CHANGING, REGISTRY
from .actions.base import ActionError, Item
from .core import Rejection, canonical, fmt_ts, input_hash, load_json, now_utc, plan_hash, sha256, validator, write_atomic
from .gates import _groups, check_gates, in_scope, make_ctx, protected_reason, with_ancestors
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
    s = sub.add_parser("quarantine-list", help="隔離ストアの一覧（読むだけ）")
    s.add_argument("--json", action="store_true")
    s.add_argument("--plan-id")
    for name in ("verify", "dry-run", "apply", "preview", "confirm", "restore", "recover"):
        s = sub.add_parser(name)
        s.add_argument("input")
        s.add_argument("--operator", required=True, help="実行者。承認者と同一人物は不可（G-4）")
        s.add_argument("--now", help="現在時刻の上書き（RFC 3339 UTC、テスト専用。GER_ALLOW_NOW_OVERRIDE=1 が必要）")
        if name not in ("verify", "confirm"):
            s.add_argument("-o", "--output", required=True,
                           help="previewed-plan.json の出力先" if name == "preview" else "remediation-log.json の出力先")
        if name == "preview":
            s.add_argument("--report", help="item ごとの結果（ok / rejected と理由）の JSON の出力先")
            s.add_argument("--diff", action="store_true", help="編集の unified diff を標準エラー出力に出す（ログには残さない）")
        if name == "confirm":
            s.add_argument("--item", required=True, help="finding_id")
            s.add_argument("--step", required=True, help="CL-XXX:sN（template と手順の id）")
    return p


def _err(text: str) -> None:
    """標準エラー出力へ。入力由来の文字列（キー名・対象パス・例外の文言）を含みうるため制御文字をエスケープする。"""
    print(safe_text(text), file=sys.stderr)


def _ttl() -> int:
    raw = os.environ.get("GER_DRYRUN_TTL", "86400")
    if not raw.isdigit() or not 0 < int(raw) <= 7 * 86400:
        raise ValueError("GER_DRYRUN_TTL は 1〜604800 の整数（秒）で指定してください")
    return int(raw)


def _approval_max_age() -> int:
    raw = os.environ.get("GER_APPROVAL_MAX_AGE", str(7 * 86400))
    if not raw.isascii() or not raw.isdigit() or not 0 < int(raw) <= 366 * 86400:
        raise ValueError("GER_APPROVAL_MAX_AGE は 1〜31622400 の整数（秒）で指定してください")
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


def _output_clash(path: str, steps) -> str | None:
    """-o が計画の対象（変更するファイル・隔離するツリーの中）と同じなら理由を返す。対象は入力を読んだ後にしか分からない。"""
    try:
        st = os.stat(path)
        ino = (st.st_dev, st.st_ino)
    except OSError:
        ino = None
    real = os.path.realpath(path)
    # 出力先ディレクトリやその上位を変更すると apply 後に remediation-log を書けなくなる
    dir_paths, dir_ino = with_ancestors(os.path.dirname(path) or ".")
    for s in steps:
        if s.type not in FS_CHANGING or s.target is None:
            continue
        paths = s.paths() if hasattr(s, "paths") else [s.target]
        idents = []
        for x in (getattr(s, "ident", None),):
            if x:
                idents.append(tuple(x[:2]))
        for m in getattr(s, "moves", []):
            idents.append(tuple(m[2][:2]))
        for t in paths:
            if t in dir_paths:
                return f"-o の出力先ディレクトリやその上位ディレクトリは計画の対象にできません（{t}）"
            if real == t or fsutil.is_under(real, t) or ino in idents:
                return f"-o に計画の対象は指定できません（{t}）"
        if any(i in dir_ino for i in idents):
            return f"-o の出力先ディレクトリやその上位ディレクトリは計画の対象にできません（{s.target}）"
    return None


def _print_followups(plan: dict, results: list[dict]) -> None:
    """apply の後に残る手作業（checklist と followup）を表示する（入力由来の文字列はエスケープ）。"""
    by = {it["finding_id"]: it for it in plan["items"]}
    shown = set()
    for r in results:
        it = by.get(r["finding_id"])
        if not it or not it["action"] or r["result"] not in ("applied", "pending_manual", "skipped"):
            continue
        a = it["action"]
        lists = ([a["params"]] if a["type"] == "checklist" else []) + list(a.get("followup", []))
        for cl in lists:
            key = (r["finding_id"], cl["template"])
            if key in shown or (r["result"] == "skipped" and r["reason"] != "already_compliant"):
                continue
            shown.add(key)
            _err(f"  [手作業] {cl['template']} {r['finding_id'][:19]}… {a['target'] or '(path なし)'}")
            for st in cl["steps"]:
                _err(f"    {cl['template']}:{st['id']}{' *' if st['blocking'] else ''} {st['text']}")
    if shown:
        _err("  （* は必須。完了したら ger confirm --item <finding_id> --step <template>:<id> で記録する）")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    audit.configure()  # GER_LOG_DIR をここで一度だけ実パスに解決し、以後のログの読み書きはそのパスで行う
    store.configure()
    if args.command == "verify-log":
        return _verify_log(args.log)
    if args.command == "quarantine-list":
        return _quarantine_list(args)
    if not _PERSON.fullmatch(args.operator):
        _err("ger: --operator の形式が不正です")
        return EXIT_USAGE
    if args.now and os.environ.get("GER_ALLOW_NOW_OVERRIDE") != "1":
        _err("ger: --now はテスト専用です（GER_ALLOW_NOW_OVERRIDE=1 のときだけ受け付けます）")
        return EXIT_USAGE
    try:
        now = now_utc(args.now)
        ttl = _ttl()
        max_age = _approval_max_age()
        if getattr(args, "output", None) is not None:
            _check_output(args.output, args.input)
        if getattr(args, "report", None):
            _check_output(args.report, args.input)
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
    st = {"code": EXIT_OK, "rejections": [], "log_obj": None, "changed": False, "outcome": None, "result": None,
          "out_obj": None}
    try:
        inp = load_json(args.input)
    except (OSError, ValueError) as e:
        _err(f"ger: 入力を読めません: {e}")
        inp = None
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"入力を JSON として読めません: {e}")])
    pool = fsutil.FdPool()
    if inp is not None:
        try:
            handler = {"preview": _cmd_preview, "restore": _cmd_restore, "confirm": _cmd_confirm,
                       "recover": _cmd_recover}.get(args.command, _cmd_plan)
            handler(args, inp, now, clock, ttl, max_age, record, st, pool)
        except Exception as e:  # 想定外は fail-closed
            _err(f"ger: 内部エラー: {type(e).__name__}: {str(e)[:200]}")
            st["code"] = EXIT_INTERNAL
        finally:
            pool.close()
    return _finish(args, record, st, clock)


def _finish(args, record: dict, st: dict, clock) -> int:
    code, rejections, log_obj, changed, outcome = st["code"], st["rejections"], st["log_obj"], st["changed"], st["outcome"]
    result = st["result"]
    unlogged = False
    if rejections:
        _err(f"ger {args.command}: 拒否 {len(rejections)} 件（何も変更していません）")
        for r in rejections:
            fid = f" [{r.finding_id}]" if r.finding_id else ""
            _err(f"  {r.gate}{fid}: {r.message}")
        record["gate_failed"] = sorted({r.gate for r in rejections})
    out_obj = st["out_obj"] if st["out_obj"] is not None else log_obj
    if log_obj is not None:
        errs = validator("remediation-log.schema.json").errors(log_obj)
        if errs:  # 自分の出力が契約に合わない場合も fail-closed
            _err(f"ger: 出力が remediation-log スキーマに不適合: {errs[0]}")
            code = EXIT_INTERNAL if code == EXIT_OK else code
    if out_obj is not None:
        # 監査ログより先に書き出す。書けなければ output_hash を記録せず、成功（ok）としても記録しない
        try:
            write_atomic(args.output, out_obj)
            record["output_hash"] = sha256(canonical(out_obj))
        except OSError as e:
            _err(f"ger: 出力を書き出せません（{e}）")
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
        mutating = args.command in ("apply", "restore", "recover")
        return EXIT_ROLLBACK_FAILED if mutating and code != EXIT_REJECTED else EXIT_USAGE
    if unlogged:
        return code  # remediation-log を書けなかった旨は表示済み
    msg = {EXIT_OK: "OK", EXIT_ROLLED_BACK: "失敗したため全件ロールバックしました",
           EXIT_ROLLBACK_FAILED: "失敗し、ロールバックも完了できませんでした。remediation-log を確認して手動で対応してください"}.get(code)
    if msg:
        _err(f"ger {args.command}: {msg}")
    return code


def _plan_record(inp, record):
    if isinstance(inp, dict):
        record["input_hash"] = input_hash(inp)
        plan = inp.get("plan") if isinstance(inp.get("plan"), dict) else {}
        if isinstance(plan.get("plan_id"), str):
            record["plan_id"] = plan["plan_id"]
        try:
            record["plan_hash"] = plan_hash(plan)
        except (TypeError, ValueError):
            pass


def _cmd_plan(args, inp, now, clock, ttl, max_age, record, st, pool):
    _plan_record(inp, record)
    rejections, steps = check_gates(inp, args.operator, now, args.command, ttl, now_override=bool(args.now),
                                    approval_max_age=max_age,
                                    allow_now_override_plan=os.environ.get("GER_ALLOW_NOW_OVERRIDE") == "1", pool=pool)
    clash = None if rejections or args.command == "verify" else _output_clash(args.output, steps)
    if rejections:
        st.update(code=EXIT_REJECTED, rejections=rejections)
    elif clash:  # 変更を始める前に止める（ゲートの拒否ではなく引数エラーとして記録する）
        _err(f"ger: {clash}（何も変更していません）")
        record["error"] = clash
        st["code"] = EXIT_USAGE
    elif args.command == "dry-run":
        res = executor.dry_run(inp["plan"], steps)
        st["log_obj"] = _log(inp, "dry-run", record["started_at"], clock(), res, "ok")
    elif args.command == "apply":
        results, outcome = executor.apply(inp["plan"], steps, clock, plan_hash=record.get("plan_hash"),
                                          input_hash=record.get("input_hash"))
        status = "error" if outcome else ("partial" if inp["plan"]["status"] == "partial" else "ok")
        st.update(outcome=outcome, changed=outcome in (None, executor.ROLLBACK_FAILED),
                  log_obj=_log(inp, "apply", record["started_at"], clock(), results, status),
                  code={None: EXIT_OK, executor.ROLLED_BACK: EXIT_ROLLED_BACK}.get(outcome, EXIT_ROLLBACK_FAILED))
        record["items"] = [_audit_item(s, r) for s in steps for r in results if r["finding_id"] in s.finding_ids
                           and r["action_type"] == s.type][:512]
        if outcome is None:
            _print_followups(inp["plan"], results)


def _audit_item(step, r) -> dict:
    """監査ログの item ごとの記録。内容は残さず、ハッシュ・実体 ID・隔離 ID だけ（§4.5）。"""
    a = step.audit()
    rec = {"finding_id": r["finding_id"], "type": step.type, "target": step.target, "result": r["result"],
           "before": r["before"], "after": r["after"]}
    for k in ("relation", "ops_digest", "quarantine_ids", "manifest_sha256", "template"):
        if a.get(k) not in (None, [], ""):
            rec[k] = a[k]
    if getattr(step, "ident", None):
        rec["ident_before"] = list(step.ident[:2])
    return rec


# --- preview ------------------------------------------------------------------------------------
def _cmd_preview(args, inp, now, clock, ttl, max_age, record, st, pool):
    """下書き plan の action の params を、現在のファイルの内容から埋める（読むだけ）。"""
    plan = inp
    errs = validator("vendor/remediation-plan.schema.json").errors(plan) if isinstance(plan, dict) else ["not an object"]
    if errs:
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"plan{e}") for e in errs])
        return
    if isinstance(plan.get("plan_id"), str):
        record["plan_id"] = plan["plan_id"]
    out = copy.deepcopy(plan)
    items = [it for it in out["items"] if it.get("action")]
    report = []
    ctx = make_ctx(out, pool)
    scope = out.get("scope")
    try:
        ctx.store_dev = store.device()
    except (OSError, store.StoreError) as e:
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-9", f"隔離ストアを用意できません（{e}）")])
        return
    bad = 0
    for grp in _groups(items):
        its = [it for _i, it in grp]
        a0 = its[0]["action"]
        fids = [it["finding_id"] for it in its]
        try:
            if a0["type"] not in REGISTRY:
                raise ActionError(f"操作 {a0['type']} は GER 未対応です")
            if any(it["action"]["type"] != a0["type"] or it["action"]["target"] != a0["target"] for it in its):
                raise ActionError("同じ group の item の type / target が一致しません")
            t = a0["target"]
            if a0["type"] in FS_CHANGING:
                if t is None:
                    raise ActionError("ファイルを変える操作の target は null にできません")
                if not scope or not in_scope(t, scope):
                    raise ActionError("G-9: 対象が plan.scope（承認する検査範囲）の外にあります")
                why = protected_reason(t)
                if why:
                    raise ActionError(f"G-9: {why}")
            objs = [Item(it["finding_id"], copy.deepcopy(it["action"]), it.get("approved_by", []), i)
                    for i, it in grp]
            pr = REGISTRY[a0["type"]].preview(ctx, objs)
            for it in its:
                it["action"]["params"] = copy.deepcopy(pr.params)
            report.append({"finding_ids": fids, "type": a0["type"], "target": t, "status": "ok", "summary": pr.summary})
            _err(f"ger preview: ok   {a0['type']} {t}: {pr.summary}")
            if args.diff and pr.diff:
                _err(pr.diff)
        except FileNotFoundError:
            bad += 1
            report.append({"finding_ids": fids, "type": a0["type"], "target": a0["target"], "status": "rejected",
                           "reason": "対象が存在しません"})
            _err(f"ger preview: NG   {a0['type']} {a0['target']}: 対象が存在しません")
        except (ActionError, fsutil.FsError, OSError, ValueError) as e:
            bad += 1
            report.append({"finding_ids": fids, "type": a0["type"], "target": a0["target"], "status": "rejected",
                           "reason": str(e)})
            _err(f"ger preview: NG   {a0['type']} {a0['target']}: {e}")
    st["out_obj"] = out
    record["preview"] = {"ok": len(report) - bad, "rejected": bad}
    if args.report:
        try:
            write_atomic(args.report, {"plan_id": out.get("plan_id"), "items": report})
        except OSError as e:
            _err(f"ger: --report を書き出せません（{e}）")
    if bad:
        st["code"] = EXIT_REJECTED
        st["result"] = "partial"


# --- restore ------------------------------------------------------------------------------------
def _cmd_restore(args, inp, now, clock, ttl, max_age, record, st, pool):
    req = inp
    if isinstance(req, dict):
        record["input_hash"] = input_hash(req)
        if isinstance(req.get("restore_id"), str):
            record["plan_id"] = req["restore_id"]
    rej = restore_mod.check_request(req, args.operator, now, max_age)
    if rej:
        st.update(code=EXIT_REJECTED, rejections=rej)
        return
    tok = restore_mod.request_token(req)
    record["plan_hash"] = tok
    mode = req["mode"]
    record["command"] = "restore-dry-run" if mode == "dry-run" else "restore-apply"
    steps, rej = restore_mod.prepare(req)
    if rej:
        st.update(code=EXIT_REJECTED, rejections=rej)
        return
    clash = _restore_clash(args.output, steps)
    if clash:
        _err(f"ger: {clash}（何も変更していません）")
        record["error"] = clash
        st["code"] = EXIT_USAGE
        return
    log = {"schema_version": "1.1", "plan_id": req["restore_id"], "plan_hash": tok, "started_at": record["started_at"]}
    if mode == "dry-run":
        st["log_obj"] = dict(log, mode="restore-dry-run", finished_at=fmt_ts(clock()), status="ok",
                             results=restore_mod.dry_run(steps))
        return
    broken = audit.verify_chain()
    if broken:
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-8", f"監査ログのハッシュチェーンが壊れています（{broken[0]}）")])
        return
    if audit.find_dry_run(tok, record["input_hash"], now, ttl, bool(args.now), dry_cmd="restore-dry-run",
                          apply_cmd="restore-apply") is None:
        st.update(code=EXIT_REJECTED,
                  rejections=[Rejection("G-8", f"同一の restore-request の dry-run 成功記録が {ttl} 秒以内にありません")])
        return
    results, ok = restore_mod.run(steps, req["restore_id"], fmt_ts(clock()))
    st["changed"] = ok is not False
    st["outcome"] = None if ok else (executor.ROLLED_BACK if ok is False else executor.ROLLBACK_FAILED)
    st["code"] = EXIT_OK if ok else (EXIT_ROLLED_BACK if ok is False else EXIT_ROLLBACK_FAILED)
    st["log_obj"] = dict(log, mode="restore", finished_at=fmt_ts(clock()), status="ok" if ok else "error", results=results)
    record["items"] = [{"quarantine_id": s.qid, "target": s.target, "manifest_sha256": s.mhash} for s in steps]


def _restore_clash(path: str, steps) -> str | None:
    real = os.path.realpath(path)
    for s in steps:
        if fsutil.is_under(real, s.target):
            return f"-o に戻し先（{s.target}）やその中は指定できません"
    return None


# --- confirm ------------------------------------------------------------------------------------
def _cmd_confirm(args, inp, now, clock, ttl, max_age, record, st, pool):
    _plan_record(inp, record)
    rej, _steps = check_gates(inp, args.operator, now, "confirm", ttl, approval_max_age=max_age,
                              allow_now_override_plan=os.environ.get("GER_ALLOW_NOW_OVERRIDE") == "1")
    if rej:
        st.update(code=EXIT_REJECTED, rejections=rej)
        return
    plan = inp["plan"]
    tmpl, _, sid = args.step.partition(":")
    record.update(finding_id=args.item, step=args.step)
    it = next((x for x in plan["items"] if x["finding_id"] == args.item and x["decision"] == "remediate"), None)
    a = it["action"] if it else None
    lists = ([a["params"]] if a and a["type"] == "checklist" else []) + (list(a.get("followup", [])) if a else [])
    cl = next((c for c in lists if c["template"] == tmpl), None)
    step = next((s for s in cl["steps"] if s["id"] == sid), None) if cl else None
    if step is None:
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"item {args.item} に手順 {args.step} がありません", args.item)])
        return
    ph = plan_hash(plan)
    recs = audit.records()
    if not any(r.get("command") == "apply" and r.get("plan_hash") == ph and r.get("result") == "ok" for r in recs):
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-8", "この計画の apply の成功記録がありません（確認は apply の後に記録する）")])
        return
    if any(r.get("command") == "confirm" and r.get("plan_hash") == ph and r.get("finding_id") == args.item
           and r.get("step") == args.step and r.get("result") == "ok" for r in recs):
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"手順 {args.step} は既に確認済みです", args.item)])
        return
    verify = a["params"].get("verify", {}).get("kind") if a["type"] == "checklist" and cl is a["params"] else None
    vr = "self_attested"
    if verify == "path_absent" and a["target"]:
        if os.path.lexists(a["target"]):
            st.update(code=EXIT_REJECTED, rejections=[Rejection("G-7", f"verify path_absent: まだ存在します: {a['target']}", args.item)])
            return
        vr = "verified:path_absent"
    elif verify == "file_hash_changed" and a["target"]:
        ev = a.get("evidence", {}).get("hash") or a.get("evidence_hash")
        try:
            r = fsutil.resolve(a["target"])
            try:
                cur = fsutil.hash_file(r.parent_fd, r.name, r.st)
            finally:
                r.close()
        except (OSError, fsutil.FsError):
            cur = None
        if cur is not None and cur == ev:
            st.update(code=EXIT_REJECTED, rejections=[Rejection("G-7", "verify file_hash_changed: 内容が検知時から変わっていません", args.item)])
            return
        vr = "verified:file_hash_changed"
    record.update(template=tmpl, verify_result=vr, blocking=step["blocking"])
    _err(f"ger confirm: {args.step} を記録しました（{vr}。外部の作業は本人の確認として記録し、GER は検証していません）"
         if vr == "self_attested" else f"ger confirm: {args.step} を記録しました（{vr}）")


# --- recover ------------------------------------------------------------------------------------
def _cmd_recover(args, inp, now, clock, ttl, max_age, record, st, pool):
    from .actions import base as base_mod
    from .actions import chmod as chmod_mod
    _plan_record(inp, record)
    rej, _ = check_gates(inp, args.operator, now, "recover", ttl, approval_max_age=max_age,
                         allow_now_override_plan=os.environ.get("GER_ALLOW_NOW_OVERRIDE") == "1")
    if rej:
        st.update(code=EXIT_REJECTED, rejections=rej)
        return
    ph, ih = record["plan_hash"], record["input_hash"]
    results, failed = [], False
    found = 0
    for run_id, recs in store.open_journals():
        head = recs[0] if recs else {}
        if head.get("plan_hash") != ph or head.get("input_hash") != ih:
            continue
        found += 1
        last: dict[int, dict] = {}
        undone = set()
        for r in recs:
            if r.get("event") == "step":
                last[r["step"]] = r["undo"]
            elif r.get("event") == "step_rolled_back":
                undone.add(r["step"])
        for n in sorted(last, reverse=True):
            if n in undone:
                continue
            u = last[n]
            fid = (head.get("steps") or [{}])[n].get("finding_ids", ["sha256:" + "0" * 64])[0] if n < len(head.get("steps") or []) else "sha256:" + "0" * 64
            tgt = (head.get("steps") or [{}])[n].get("target") if n < len(head.get("steps") or []) else None
            try:
                if u.get("op") == "chmod":
                    chmod_mod.rollback_undo(u)
                else:
                    base_mod.rollback_undo(u)
                store.append_journal(run_id, {"event": "step_rolled_back", "step": n})
                results.append({"finding_id": fid, "action_type": "recover", "target": tgt, "before": None, "after": None,
                                "result": "rolled_back", "reason": f"recovered:{run_id}", "applied_at": fmt_ts(clock())})
            except Exception as e:
                failed = True
                results.append({"finding_id": fid, "action_type": "recover", "target": tgt, "before": None, "after": None,
                                "result": "failed", "reason": f"{type(e).__name__}: {e}", "applied_at": None})
        if not failed:
            store.append_journal(run_id, {"event": "recovered", "operator": args.operator})
    if not found:
        _err("ger recover: この計画・入力の未完了のジャーナルはありません")
    st["changed"] = bool(results)
    st["code"] = EXIT_ROLLBACK_FAILED if failed else EXIT_OK
    st["outcome"] = executor.ROLLBACK_FAILED if failed else None
    st["log_obj"] = _log(inp, "recover", record["started_at"], clock(), results, "error" if failed else "ok")
    record["recovered_journals"] = found


# --- quarantine-list ----------------------------------------------------------------------------
def _quarantine_list(args) -> int:
    ents = store.list_entries()
    if args.plan_id:
        ents = [e for e in ents if e.get("plan_id") == args.plan_id]
    if args.json:
        print(json.dumps({"store": store.store_dir(), "entries": ents}, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        _err(f"隔離ストア: {store.store_dir()}（{len(ents)} 件）")
        for e in ents:
            _err(f"  {e['quarantine_id']}  {e.get('status')}  {e.get('operation')}  {e.get('original_path')}  {e.get('manifest_sha256')}")
    return EXIT_OK


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
    return {"schema_version": "1.1", "plan_id": inp["plan"]["plan_id"], "plan_hash": inp["plan"]["plan_hash"],
            "mode": mode, "started_at": started_at, "finished_at": fmt_ts(finished), "status": status, "results": results}
