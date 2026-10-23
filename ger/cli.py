"""The ger command.

  ger verify  <ger-input.json> --operator NAME
  ger dry-run <ger-input.json> --operator NAME -o remediation-log.json
  ger apply   <ger-input.json> --operator NAME -o remediation-log.json
  ger preview <draft-plan.json> --operator NAME -o previewed-plan.json [--report R] [--diff]
                         fills the params of the draft actions (hashes, ops, expected_after_sha256) from the current content (changes nothing)
  ger confirm <ger-input.json> --operator NAME --item FINDING_ID --step CL-XXX:sN
                         records in the audit log that the worker confirmed a checklist / followup step
  ger restore <restore-request.json> --operator NAME -o remediation-log.json
                         moves quarantine store entries back to their original location (2 approvers, dry-run required)
  ger recover <ger-input.json> --operator NAME -o remediation-log.json
                         rolls back an apply that died halfway, using the journal
  ger quarantine-list [--json] [--plan-id ID]   lists the quarantine store and verifies manifests (read only)
  ger verify-log [LOG]   verifies the hash chain of the audit log (read only; not recorded in the audit log)

Exit codes: 0=success / 3=rejected by a gate (nothing changed) / 4=failed and rolled back /
           5=rollback also failed, or remediation-log could not be written after applying (manual action required) /
           64=argument or environment error / 70=internal error (verify-log: 0=intact / 3=broken / 64=no log)
Environment: GER_LOG_DIR (audit log; resolved to a real path at startup), GER_DRYRUN_TTL (validity of a dry-run record in seconds, default 86400),
         GER_APPROVAL_MAX_AGE (validity of an approval in seconds, default 604800),
         GER_QUARANTINE_DIR (quarantine store; default $XDG_STATE_HOME/ger/quarantine or ~/.local/state/ger/quarantine),
         GER_ALLOW_NOW_OVERRIDE (only =1 accepts --now and plans with now_override: true; for tests only)
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
    p = _Parser(prog="ger", description="GER - Gated-Exec Remediation (remediation layer)")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("verify-log", help="verify the hash chain of the audit log")
    s.add_argument("log", nargs="?", help="log to verify (default $GER_LOG_DIR/ger-audit.jsonl)")
    s = sub.add_parser("quarantine-list", help="list the quarantine store (read only)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--plan-id")
    for name in ("verify", "dry-run", "apply", "preview", "confirm", "restore", "recover"):
        s = sub.add_parser(name)
        s.add_argument("input")
        s.add_argument("--operator", required=True, help="the operator. Must not be one of the approvers (G-4)")
        s.add_argument("--now", help="override the current time (RFC 3339 UTC, for tests only; requires GER_ALLOW_NOW_OVERRIDE=1)")
        if name not in ("verify", "confirm"):
            s.add_argument("-o", "--output", required=True,
                           help="output path of previewed-plan.json" if name == "preview" else "output path of remediation-log.json")
        if name == "preview":
            s.add_argument("--report", help="output path of the per-item result JSON (ok / rejected and the reason)")
            s.add_argument("--diff", action="store_true", help="print the unified diff of edits to standard error (not kept in logs)")
        if name == "confirm":
            s.add_argument("--item", required=True, help="finding_id")
            s.add_argument("--step", required=True, help="CL-XXX:sN (template and step id)")
    return p


def _err(text: str) -> None:
    """To standard error. Escapes control characters because the text may contain strings from input (key names, target paths, exception text)."""
    print(safe_text(text), file=sys.stderr)


def _ttl() -> int:
    raw = os.environ.get("GER_DRYRUN_TTL", "86400")
    if not raw.isdigit() or not 0 < int(raw) <= 7 * 86400:
        raise ValueError("GER_DRYRUN_TTL must be an integer from 1 to 604800 (seconds)")
    return int(raw)


def _approval_max_age() -> int:
    raw = os.environ.get("GER_APPROVAL_MAX_AGE", str(7 * 86400))
    if not raw.isascii() or not raw.isdigit() or not 0 < int(raw) <= 366 * 86400:
        raise ValueError("GER_APPROVAL_MAX_AGE must be an integer from 1 to 31622400 (seconds)")
    return int(raw)


def _verify_log(path: str | None) -> int:
    p = Path(path) if path else audit.log_path()
    if not p.exists():
        _err(f"ger verify-log: audit log not found: {p}")
        return EXIT_USAGE
    try:
        n, problems = audit.scan_chain(p)
    except OSError as e:
        _err(f"ger verify-log: cannot read the audit log ({e})")
        return EXIT_USAGE
    if problems:
        _err(f"ger verify-log: the hash chain is broken (problems: {len(problems)}, lines: {n}): {p}")
        for x in problems:
            _err(f"  {x}")
        return EXIT_REJECTED
    _err(f"ger verify-log: OK (records: {n}, hash chain intact): {p}")
    return EXIT_OK


def _same_path(a: str, b: str) -> bool:
    """Whether a and b point to the same file (same real path, or the same (st_dev, st_ino) if they exist; detects hard links too)."""
    if os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:  # One of them does not exist
        return False


def _check_output(path: str, input_path: str) -> None:
    """Checks the -o output path before any change starts (never apply with an output path known to be unwritable).

    The output is replaced with os.replace, so the audit log (and files in its directory) and the input file cannot be given.
    An existing path must be a regular file (symbolic links, FIFOs, sockets and devices are rejected, not replaced).
    """
    if not path or path.endswith("/"):  # abspath would read "" as cwd and drop a trailing /
        raise ValueError(f"-o needs a file path (an empty path or a path ending in / is not allowed): {path!r}")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as e:  # An intermediate element is a file (ENOTDIR) and so on
        raise ValueError(f"cannot check the -o output path: {path} ({e.strerror})") from None
    if st is not None and stat.S_ISDIR(st.st_mode):
        raise ValueError(f"-o cannot be a directory: {path}")
    if st is not None and stat.S_ISLNK(st.st_mode):  # os.replace replaces the link itself, not its target, so reject it
        raise ValueError(f"-o cannot be a symbolic link: {path}")
    if st is not None and not stat.S_ISREG(st.st_mode):  # Never replace FIFOs, sockets, devices (/dev/null and so on)
        raise ValueError(f"-o must be a regular file: {path}")
    d = os.path.dirname(path) or "."  # The parent of the path as given (abspath would collapse .. and so on)
    if not os.path.isdir(d):
        raise ValueError(f"the -o output directory does not exist: {d}")
    if not os.access(d, os.W_OK | os.X_OK):
        raise ValueError(f"cannot write to the -o output directory: {d}")
    if _same_path(path, str(audit.log_path())):
        raise ValueError(f"-o cannot be the audit log: {path}")
    if any(_same_path(x, str(audit.log_dir())) for x in (d, os.path.dirname(os.path.realpath(path)))):
        raise ValueError(f"-o cannot be a file in the audit log directory: {path}")
    if _same_path(path, input_path):
        raise ValueError(f"-o cannot be the input file: {path}")


def _output_clash(path: str, steps) -> str | None:
    """Returns a reason if -o is the same as a plan target (a file to change, or inside a tree to quarantine). Targets are known only after reading the input."""
    try:
        st = os.stat(path)
        ino = (st.st_dev, st.st_ino)
    except OSError:
        ino = None
    real = os.path.realpath(path)
    # Changing the output directory or a directory above it would make remediation-log unwritable after apply
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
                return f"the -o output directory or a directory above it cannot be a plan target ({t})"
            if real == t or fsutil.is_under(real, t) or ino in idents:
                return f"-o cannot be a plan target ({t})"
        if any(i in dir_ino for i in idents):
            return f"the -o output directory or a directory above it cannot be a plan target ({s.target})"
    return None


def _print_followups(plan: dict, results: list[dict]) -> None:
    """Shows the manual work left after apply (checklists and followups; strings from input are escaped)."""
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
            _err(f"  [manual] {cl['template']} {r['finding_id'][:19]}... {a['target'] or '(no path)'}")
            for st in cl["steps"]:
                _err(f"    {cl['template']}:{st['id']}{' *' if st['blocking'] else ''} {st['text']}")
    if shown:
        _err("  (* = required. When done, record it with ger confirm --item <finding_id> --step <template>:<id>)")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    audit.configure()  # Resolve GER_LOG_DIR to a real path once here; every later log read and write uses that path
    store.configure()
    if args.command == "verify-log":
        return _verify_log(args.log)
    if args.command == "quarantine-list":
        return _quarantine_list(args)
    if not _PERSON.fullmatch(args.operator):
        _err("ger: invalid --operator format")
        return EXIT_USAGE
    if args.now and os.environ.get("GER_ALLOW_NOW_OVERRIDE") != "1":
        _err("ger: --now is for tests only (accepted only when GER_ALLOW_NOW_OVERRIDE=1)")
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
        _err(f"ger: {e} (not running because nothing could be recorded)")
        return EXIT_USAGE

    clock = (lambda: now) if args.now else now_utc
    record = {"command": args.command, "operator": args.operator, "started_at": fmt_ts(clock())}
    if args.now:  # A dry-run record made with --now never justifies an apply without --now (G-8)
        record["now_override"] = True
    st = {"code": EXIT_OK, "rejections": [], "log_obj": None, "changed": False, "outcome": None, "result": None,
          "out_obj": None}
    try:
        inp = load_json(args.input)
    except (OSError, ValueError) as e:
        _err(f"ger: cannot read the input: {e}")
        inp = None
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"cannot read the input as JSON: {e}")])
    pool = fsutil.FdPool()
    if inp is not None:
        try:
            handler = {"preview": _cmd_preview, "restore": _cmd_restore, "confirm": _cmd_confirm,
                       "recover": _cmd_recover}.get(args.command, _cmd_plan)
            handler(args, inp, now, clock, ttl, max_age, record, st, pool)
        except Exception as e:  # Anything unexpected fails closed
            _err(f"ger: internal error: {type(e).__name__}: {str(e)[:200]}")
            st["code"] = EXIT_INTERNAL
        finally:
            pool.close()
    return _finish(args, record, st, clock)


def _finish(args, record: dict, st: dict, clock) -> int:
    code, rejections, log_obj, changed, outcome = st["code"], st["rejections"], st["log_obj"], st["changed"], st["outcome"]
    result = st["result"]
    unlogged = False
    if rejections:
        _err(f"ger {args.command}: rejections: {len(rejections)} (nothing changed)")
        for r in rejections:
            fid = f" [{r.finding_id}]" if r.finding_id else ""
            _err(f"  {r.gate}{fid}: {r.message}")
        record["gate_failed"] = sorted({r.gate for r in rejections})
    out_obj = st["out_obj"] if st["out_obj"] is not None else log_obj
    if log_obj is not None:
        errs = validator("remediation-log.schema.json").errors(log_obj)
        if errs:  # Fail closed also when our own output breaks the contract
            _err(f"ger: output does not conform to the remediation-log schema: {errs[0]}")
            code = EXIT_INTERNAL if code == EXIT_OK else code
    if out_obj is not None:
        # Written before the audit log. If it cannot be written, output_hash is not recorded and the run is not recorded as ok
        try:
            write_atomic(args.output, out_obj)
            record["output_hash"] = sha256(canonical(out_obj))
        except OSError as e:
            _err(f"ger: cannot write the output ({e})")
            unlogged = changed
            _remove_stale_output(args.output)
            if changed:
                if outcome is None:  # Everything was applied (no rollback). Not recorded as rollback_failed
                    result = "applied_unlogged"
                code = EXIT_ROLLBACK_FAILED
                _err(f"ger {args.command}: the changes may have been applied, but remediation-log could not be written. "
                     "Check the audit log and the permissions of the targets and resolve this by hand")
            elif code == EXIT_OK:
                code = EXIT_USAGE
    result = result or {EXIT_OK: "ok", EXIT_REJECTED: "rejected", EXIT_ROLLED_BACK: "rolled_back",
                        EXIT_ROLLBACK_FAILED: "rollback_failed"}.get(code, "error")
    record.update({"finished_at": fmt_ts(clock()), "result": result})
    try:
        audit.append(record)
    except OSError as e:
        _err(f"ger: cannot record in the audit log ({e})")
        # apply may already have changed things, so this requires manual action
        mutating = args.command in ("apply", "restore", "recover")
        return EXIT_ROLLBACK_FAILED if mutating and code != EXIT_REJECTED else EXIT_USAGE
    if unlogged:
        return code  # The failure to write remediation-log was already shown
    msg = {EXIT_OK: "OK", EXIT_ROLLED_BACK: "failed; everything was rolled back",
           EXIT_ROLLBACK_FAILED: "failed, and the rollback could not be completed. Check remediation-log and resolve this by hand"}.get(code)
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
    elif clash:  # Stop before any change starts (recorded as an argument error, not a gate rejection)
        _err(f"ger: {clash} (nothing changed)")
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
    """Per-item record for the audit log. No contents, only hashes, object IDs and quarantine IDs (§4.5)."""
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
    """Fills the params of the draft plan's actions from the current file contents (read only)."""
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
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-9", f"cannot prepare the quarantine store ({e})")])
        return
    bad = 0
    for grp in _groups(items):
        its = [it for _i, it in grp]
        a0 = its[0]["action"]
        fids = [it["finding_id"] for it in its]
        try:
            if a0["type"] not in REGISTRY:
                raise ActionError(f"operation {a0['type']} is not supported by GER")
            if any(it["action"]["type"] != a0["type"] or it["action"]["target"] != a0["target"] for it in its):
                raise ActionError("type / target differ between items of the same group")
            t = a0["target"]
            if a0["type"] in FS_CHANGING:
                if t is None:
                    raise ActionError("the target of an operation that changes files cannot be null")
                if not scope or not in_scope(t, scope):
                    raise ActionError("G-9: the target is outside plan.scope (the scan scope to approve)")
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
                           "reason": "the target does not exist"})
            _err(f"ger preview: NG   {a0['type']} {a0['target']}: the target does not exist")
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
            _err(f"ger: cannot write --report ({e})")
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
        _err(f"ger: {clash} (nothing changed)")
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
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-8", f"the hash chain of the audit log is broken ({broken[0]})")])
        return
    if audit.find_dry_run(tok, record["input_hash"], now, ttl, bool(args.now), dry_cmd="restore-dry-run",
                          apply_cmd="restore-apply") is None:
        st.update(code=EXIT_REJECTED,
                  rejections=[Rejection("G-8", f"no successful dry-run record of the same restore-request within {ttl} seconds")])
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
            return f"-o cannot be a restore destination ({s.target}) or inside one"
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
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"item {args.item} has no step {args.step}", args.item)])
        return
    ph = plan_hash(plan)
    recs = audit.records()
    if not any(r.get("command") == "apply" and r.get("plan_hash") == ph and r.get("result") == "ok" for r in recs):
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-8", "no successful apply record for this plan (confirmations are recorded after apply)")])
        return
    if any(r.get("command") == "confirm" and r.get("plan_hash") == ph and r.get("finding_id") == args.item
           and r.get("step") == args.step and r.get("result") == "ok" for r in recs):
        st.update(code=EXIT_REJECTED, rejections=[Rejection("G-1", f"step {args.step} is already confirmed", args.item)])
        return
    verify = a["params"].get("verify", {}).get("kind") if a["type"] == "checklist" and cl is a["params"] else None
    vr = "self_attested"
    if verify == "path_absent" and a["target"]:
        if os.path.lexists(a["target"]):
            st.update(code=EXIT_REJECTED, rejections=[Rejection("G-7", f"verify path_absent: still exists: {a['target']}", args.item)])
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
            st.update(code=EXIT_REJECTED, rejections=[Rejection("G-7", "verify file_hash_changed: the content has not changed since detection", args.item)])
            return
        vr = "verified:file_hash_changed"
    record.update(template=tmpl, verify_result=vr, blocking=step["blocking"])
    _err(f"ger confirm: recorded {args.step} ({vr}; external work is recorded as the person's own confirmation, GER has not verified it)"
         if vr == "self_attested" else f"ger confirm: recorded {args.step} ({vr})")


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
        _err("ger recover: no unfinished journal for this plan and input")
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
        _err(f"quarantine store: {store.store_dir()} (entries: {len(ents)})")
        for e in ents:
            _err(f"  {e['quarantine_id']}  {e.get('status')}  {e.get('operation')}  {e.get('original_path')}  {e.get('manifest_sha256')}")
    return EXIT_OK


def _remove_stale_output(path: str) -> None:
    """When writing fails, removes the remediation-log of an earlier run so it cannot be mistaken for this run's.

    _check_output already confirmed the output path is a regular file (or does not exist yet); on success it would have been replaced.
    """
    try:
        os.unlink(path)
        _err(f"ger: removed the earlier remediation-log: {path}")
    except FileNotFoundError:
        pass
    except OSError as e:
        _err(f"ger: cannot remove the earlier remediation-log; it is not the record of this run: {path} ({e})")


def _log(inp: dict, mode: str, started_at: str, finished, results: list[dict], status: str) -> dict:
    return {"schema_version": "1.1", "plan_id": inp["plan"]["plan_id"], "plan_hash": inp["plan"]["plan_hash"],
            "mode": mode, "started_at": started_at, "finished_at": fmt_ts(finished), "status": status, "results": results}
