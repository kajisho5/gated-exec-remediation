"""Pre-execution gates G-1 to G-10. If any one fails, nothing is changed.

check_gates() changes nothing (stat, reads and hash computation only). It returns the list of steps (transactions);
items with the same action.group form one step (the file is written once). Execution order is
(1) edits that remove references (edit_* / remove_line / disable_mcp_server) -> (2) quarantine -> (3) chmod -> (4) checklist.

approval_token (= plan_hash) only shows that "the plan has not changed since approval" (integrity).
If the plan is rewritten and its plan_hash recomputed, this cannot be detected cryptographically (authenticity needs the approvers' signatures; future work).
Therefore the ZET invariants that can be evaluated from the plan alone (_zet_invariants) are checked again here, and
definition T (narrowing only: removed units match GER's table H, added values are only constants from table K, the T-3 re-parse)
and the relation between target and finding (G-9) are evaluated by GER itself against the current file system, without trusting the plan.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import posixpath
import stat
from collections import Counter

from . import audit, fsutil, hazards, store
from .actions import FS_CHANGING, REGISTRY
from .actions import checklist as checklist_mod
from .actions.base import ActionError, Ctx, Item
from .core import ROOT, RISKY_EFFECTS, Rejection, input_hash, parse_ts, plan_hash, validator

EVIDENCE_FULL_HASH_MAX = 104857600  # Same as ZES: up to 100MB the SHA-256 of the content, above that the SHA-256 of path, size and mtime
MAX_REMEDIATE_ITEMS = 256


def with_ancestors(*given) -> tuple[set[str], set[tuple[int, int]]]:
    """(set of paths, set of (st_dev, st_ino) of the existing ones) for each given path and all directories above it.

    Returns the union of the lexical ancestors (intermediate elements of the given path, including symbolic links) and the ancestors of the real path.
    The real-path ancestors alone would miss the directory holding an intermediate symbolic link (A in A/link -> B/dir);
    a chmod 0000 on it would make writes through that path impossible.
    """
    paths: set[str] = set()
    idents: set[tuple[int, int]] = set()
    starts: set[str] = set()
    for g in given:
        g = os.fspath(g)
        g = g if os.path.isabs(g) else os.path.join(os.getcwd(), g)
        parts = g.split("/")
        for i in range(1, len(parts) + 1):  # Each intermediate element (lexical, before folding ../), both lexically and as a real path
            pre = "/".join(parts[:i]) or "/"
            starts.add(os.path.abspath(pre))
            starts.add(os.path.realpath(pre))
    for p in starts:
        while True:
            if p in paths:
                break
            paths.add(p)
            try:
                st = os.stat(p)
                idents.add((st.st_dev, st.st_ino))
            except OSError:
                pass
            parent = os.path.dirname(p)
            if parent == p:
                break
            p = parent
    return paths, idents


def _audit_protected() -> tuple[set[str], set[tuple[int, int]]]:
    """What would stop GER from writing its own audit log if changed: the audit log, its directory and every directory above it
    (both the lexical ancestors of the given GER_LOG_DIR and the ancestors of the real path resolved at startup). The quarantine store and its ancestors are treated the same."""
    paths, idents = with_ancestors(audit.given_log_dir(), audit.log_dir(), store.store_dir())
    lp = audit.log_path()
    paths.add(os.path.realpath(lp))
    try:
        st = os.stat(lp)
        idents.add((st.st_dev, st.st_ino))
    except OSError:  # Does not exist yet (first run)
        pass
    return paths, idents


def _schema(name: str, inst, label: str, gate: str = "G-1") -> list[Rejection]:
    return [Rejection(gate, f"{label}{e}") for e in validator(name).errors(inst)]


def _names(xs) -> set[str]:
    return {x.casefold() for x in xs}


def _target_shape_ok(t: str) -> bool:
    """Same as ZET I-4: a normalized absolute path (no . / .., no repeated / (including a leading //))."""
    return t.startswith("/") and "//" not in t and posixpath.normpath(t) == t and ".." not in t.split("/")


def is_v11(plan: dict) -> bool:
    return plan.get("schema_version") == "1.1"


def needs_two(a: dict) -> bool:
    """Actions that require 2 approvers (table in §4.3): irreversible or destructive operations, targets that require root (lexically)."""
    mod = REGISTRY.get(a.get("type"))
    if a.get("reversible") is False or (mod is not None and getattr(mod, "DESTRUCTIVE", False)):
        return True
    t = a.get("target")
    return a.get("type") in FS_CHANGING and isinstance(t, str) and hazards.root_required_lexical(t)


def _zet_invariants(plan: dict, now: dt.datetime) -> list[Rejection]:
    """The ZET invariants I-1 to I-13 that can be evaluated from the plan alone, without findings or policy (G-1).

    Those that cannot (I-2 existence of the finding, I-4 relation between target and the finding's path, I-8 approver allowlist,
    I-9 number of days to the deadline, I-10 undecided modules, I-13 operations per finding type) are left to ZET's check.
    (The I-4 relation is derived again from the file system by G-9.)
    """
    rej: list[Rejection] = []

    def bad(code: str, msg: str, fid=None) -> None:
        rej.append(Rejection("G-1", f"ZET {code} equivalent: {msg}", fid))

    created = parse_ts(plan["created_at"])
    v11 = is_v11(plan)
    # I-11: dates and times that exist
    for it in plan["items"]:
        for k in ("decided_at", "due_at", "recheck_at"):
            if it[k] is not None:
                try:
                    parse_ts(it[k])
                except ValueError:
                    bad("I-11", f"{k} is not a valid date and time: {it[k]}", it["finding_id"])
    if rej:
        return rej
    # I-1: each finding appears only once across items and held
    seen = Counter(e["finding_id"] for e in plan["items"] + plan["held"] if e["finding_id"] is not None)
    for fid in sorted(f for f, c in seen.items() if c > 1):
        bad("I-1", "finding_id is duplicated in items / held", fid)
    # I-12: a partial plan has a non-empty held
    if plan["status"] == "partial" and not plan["held"]:
        bad("I-12", "status is partial but held is empty")
    for it in plan["items"]:
        fid, d, a = it["finding_id"], it["decision"], it["action"]
        appr = _names(it["approved_by"])
        if len(appr) != len(it["approved_by"]):
            bad("I-6", "approved_by contains duplicates (including differences in case only)", fid)
        if it["decided_by"].casefold() in appr:
            bad("I-3", "the decider is in approved_by (self-approval)", fid)
        if d == "exception":
            if it["exception_type"] is None or not (it["reason"] or "").strip() or it["recheck_at"] is None:
                bad("I-3", "exception requires exception_type, reason and recheck_at", fid)
            if not appr:
                bad("I-3", "exception requires at least 1 approver other than the decider", fid)
        elif it["exception_type"] is not None:
            bad("I-3", "exception_type is set although the decision is not exception", fid)
        if d == "defer" and it["level_effective"] != "INFO" and (not (it["reason"] or "").strip() or it["recheck_at"] is None):
            bad("I-3", "defer (level_effective other than INFO) requires reason and recheck_at", fid)
        if d == "remediate":
            if not (it["owner"] or "").strip() or it["due_at"] is None or a is None:
                bad("I-4", "remediate requires owner, due_at and action", fid)
        elif a is not None:
            bad("I-4", "action is set although the decision is not remediate", fid)
        if a is not None:
            t = a["target"]
            if t is None:
                if a["type"] != checklist_mod.TYPE:
                    bad("I-4", "only checklist may have a null action.target", fid)
            elif not _target_shape_ok(t):
                bad("I-4", "action.target must be a normalized absolute path (no . / .., no repeated /)", fid)
            fp = a.get("finding_path")
            if fp is not None and not _target_shape_ok(fp):
                bad("I-4", "action.finding_path must be a normalized absolute path", fid)
            if v11:
                for k in ("relation", "finding_path", "evidence"):
                    if k not in a:
                        bad("I-4", f"an action in a finalized plan 1.1 requires {k}", fid)
                if "relation" in a and (a["relation"] == "none") != (t is None):
                    bad("I-4", "relation none only for a checklist with a null target (and vice versa)", fid)
                if a["type"] != checklist_mod.TYPE and t is None:
                    bad("I-4", "only checklist actions may have a null target", fid)
            elif a["type"] != "chmod" and a["type"] in REGISTRY:
                bad("I-4", f"plan 1.0 can only execute chmod ({a['type']} requires plan 1.1)", fid)
            if a["type"] == checklist_mod.TYPE and "followup" in a:
                bad("I-4", "a checklist action cannot have followup (put the steps in params.steps)", fid)
            for fu in a.get("followup", []):
                try:
                    checklist_mod.validate_steps(fu, "action.followup[]")
                except ActionError as e:
                    bad("I-4", str(e), fid)
            if v11 and needs_two(a) and len(appr) < 2 and d == "remediate":
                bad("I-6", "remediate of a target that requires root, or of an irreversible or destructive operation, requires 2 or more approvers on the item", fid)
        # I-5 / I-6 / I-7 and consistency of skillpact_effects (against the summary of the finding's skillpact that ZET copied in finalize)
        sp = it.get("skillpact")
        if sp is not None:
            if sp["divergence"] and d == "exception":
                bad("I-5", "a finding with a non-empty skillpact.divergence cannot be an exception", fid)
            if sp["diff_anomaly"] and len(appr) < 2:
                bad("I-6", "a finding with skillpact.diff_anomaly requires 2 or more approvers", fid)
            if sp["signed"] and sp["divergence"] and it["level_effective"] != "CRITICAL":
                bad("I-7", "level_effective of a finding with a signature field and a divergence must be CRITICAL", fid)
            if a is not None and "skillpact_effects" in a and sorted(a["skillpact_effects"]) != sorted(sp["declared_effects"]):
                bad("I-4", "action.skillpact_effects does not match the item's skillpact.declared_effects", fid)
        if d == "remediate" and a is not None and any(e in RISKY_EFFECTS for e in a.get("skillpact_effects", [])) and len(appr) < 2:
            bad("I-6", "remediate of a skill that declares exec / network / spend / send requires 2 or more approvers", fid)
        # I-9: order of dates (the number of days to the deadline needs the policy, so it is left to ZET)
        dec = parse_ts(it["decided_at"])
        if dec < created:
            bad("I-9", "decided_at is earlier than the plan's created_at", fid)
        if dec > now:
            bad("I-9", "decided_at is later than the current time", fid)
        for k in ("due_at", "recheck_at"):
            if it[k] is not None and parse_ts(it[k]) < dec:
                bad("I-9", f"{k} is earlier than decided_at", fid)
    return rej


def evidence_digest(target: str, st: os.stat_result) -> str | None:
    """Computes the hash of the current file with the same rule as ZES evidence_hash. None for targets that cannot be compared (directories).

    For a regular file up to 100MB the SHA-256 of the content, above 100MB the SHA-256 of "path|size|mtime (seconds)".
    ActionError if it cannot be read (what cannot be checked does not pass).
    """
    if not stat.S_ISREG(st.st_mode):
        return None  # ZES uses the hash of detail for non-regular files. GER has no detail, so it does not compare
    if st.st_size > EVIDENCE_FULL_HASH_MAX:
        return "sha256:" + hashlib.sha256(f"{target}|{st.st_size}|{int(st.st_mtime)}".encode("utf-8", "surrogateescape")).hexdigest()
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise ActionError(f"cannot read the target to check evidence_hash ({e.strerror})") from None
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise ActionError("the target was replaced during pre-validation")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def check_evidence(a: dict) -> None:
    """Compares action.evidence (the state of finding_path when ZES detected it) with the present (G-7).
    kind=detail (directories, links and so on from ZES 1.0) cannot be compared, so the preview hash fixed in params is relied on."""
    if "evidence" in a:
        ev, fp = a["evidence"], a.get("finding_path")
        kind, want = ev["kind"], ev["hash"]
    elif "evidence_hash" in a:  # plan 1.0
        kind, want, fp = "file", a["evidence_hash"], a["target"]
    else:
        return
    if fp is None or kind == "detail":
        return
    try:
        st = os.lstat(fp)
    except FileNotFoundError:
        raise ActionError("the finding's target (finding_path) does not exist. Detect it again with ZES") from None
    if kind in ("file", "large_file"):
        got = evidence_digest(fp, st)
        if got is not None and got != want:
            raise ActionError("the target content changed since detection (the finding's evidence_hash). Detect it again with ZES")
    elif kind in ("tree", "symlink"):
        r = fsutil.resolve(fp)
        try:
            if kind == "tree" and stat.S_ISDIR(r.st.st_mode):
                got = fsutil.tree_hash(r.parent_fd, r.name, r.st.st_dev).hash
            elif kind == "symlink" and stat.S_ISLNK(r.st.st_mode):
                got = "sha256:" + hashlib.sha256(os.fsencode(fsutil.readlink(r.parent_fd, r.name))).hexdigest()
            else:
                got = None
        finally:
            r.close()
        if got != want:
            raise ActionError("the target changed since detection (the finding's evidence). Detect it again with ZES")


# --- Protected targets and scope (G-9) ----------------------------------------------------------
def _stdlib_dir() -> str:
    return os.path.dirname(os.path.realpath(os.__file__))


def protected_reason(t: str) -> str | None:
    """Protected targets of §4.4 (never a target, nor a directory above a target)."""
    home = os.path.realpath(os.path.expanduser("~"))
    if t in hazards.SYSTEM_TOP or t == "/":
        return "a top-level system directory cannot be a target"
    for p, what in ((home, "$HOME"), (str(ROOT), "the GER installation directory"), (_stdlib_dir(), "the Python standard library"),
                    (store.store_dir(), "the quarantine store")):
        if fsutil.is_under(p, t):
            return f"{what} itself or a directory above it cannot be a target"
    if fsutil.is_under(t, str(ROOT)):
        return "nothing inside the GER installation directory can be a target"
    if fsutil.is_under(t, store.store_dir()):
        return "nothing inside the quarantine store can be a target"
    sd = _stdlib_dir()
    if fsutil.is_under(t, sd):
        rest = t[len(sd) + 1:].split("/")
        if not rest or rest[0] not in ("site-packages", "dist-packages"):
            return "the Python standard library (except site-packages) cannot be a target"
    if t.startswith("/etc/") and not hazards.ETC_ALLOW.match(t):
        return "under /etc only /etc/ld.so.preload, /etc/hosts and /etc/cron.d/* can be targets"
    return None


def store_placement_reason(scope: dict | None) -> str | None:
    """Places where the quarantine store must not be (§3.5)."""
    sd = store.store_dir()
    parts = sd.split("/")
    if any(p in ("site-packages", "dist-packages", "node_modules", "Extensions") for p in parts):
        return f"the quarantine store is under site-packages / node_modules / an extensions directory: {sd}"
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.isabs(d) and fsutil.is_under(sd, os.path.realpath(d)):
            return f"the quarantine store is under a PATH directory: {sd}"
    for r in (scope or {}).get("roots", []):
        if fsutil.is_under(sd, r):
            return f"the quarantine store is under a scan root (scope.roots): {sd} (place it outside with GER_QUARANTINE_DIR)"
    return None


def in_scope(t: str, scope: dict) -> bool:
    places = list(scope.get("roots", [])) + ([scope["home"]] if scope.get("home") else [])
    return any(fsutil.is_under(t, r) for r in places)


def _groups(items: list[dict]) -> list[list[tuple[int, dict]]]:
    """Groups items with the same action.group. Items without a group stay one per step."""
    by: dict = {}
    order = []
    for i, it in enumerate(items):
        g = it["action"].get("group") if it["action"] else None
        key = ("g", g) if g else ("i", i)
        if key not in by:
            by[key] = []
            order.append(key)
        by[key].append((i, it))
    return [by[k] for k in order]


def check_gates(inp, operator: str, now: dt.datetime, command: str, dry_run_ttl: int,
                now_override: bool = False, approval_max_age: int = 7 * 86400,
                allow_now_override_plan: bool = False, pool: fsutil.FdPool | None = None):
    # G-1 schema, pinned versions, no skipping
    if isinstance(inp, dict) and "findings" in inp:
        return [Rejection("G-1", "the input has findings (the remediation layer does not read ZES output directly)")], []
    r = _schema("ger-input.schema.json", inp, "input")
    if r:
        return r, []
    plan = inp["plan"]
    r = _schema("vendor/remediation-plan.schema.json", plan, "plan")
    if r:
        return r, []
    if command in ("dry-run", "apply") and inp["mode"] != command:
        return [Rejection("G-1", f"mode={inp['mode']} in the input does not match the command {command}")], []
    # G-1 dates and times exist (the pattern lets 2026-02-30 or T25:00:00 through, so check here that they parse)
    bad_ts = []
    for label, v in (("approval.approved_at", inp["approval"]["approved_at"]), ("plan.created_at", plan["created_at"])):
        try:
            parse_ts(v)
        except ValueError:
            bad_ts.append(Rejection("G-1", f"{label} is not a valid date and time: {v}"))
    if bad_ts:
        return bad_ts, []
    # G-1 duplicate finding_id (a plan whose results and rollbacks cannot be mapped one-to-one to items is malformed)
    counts = Counter(it["finding_id"] for it in plan["items"] if it["decision"] == "remediate")  # O(n)
    dup = sorted(f for f, c in counts.items() if c > 1)
    if dup:
        return [Rejection("G-1", "finding_id is duplicated among remediate items", f) for f in dup], []
    if sum(counts.values()) > MAX_REMEDIATE_ITEMS:
        return [Rejection("G-1", f"a plan may have at most {MAX_REMEDIATE_ITEMS} remediate items")], []
    # G-2 plan status
    if plan["status"] not in ("ok", "partial"):
        return [Rejection("G-2", f"a plan with plan.status={plan['status']} cannot be executed (finalized ok / partial only)")], []
    # G-1 the ZET invariants that can be evaluated from the plan alone (checked again because the approval token only shows integrity).
    # Done after G-2 confirmed a finalized plan (decision, decided_by and decided_at are always present)
    r = _zet_invariants(plan, now)
    if r:
        return r, []
    if plan.get("now_override") and not allow_now_override_plan:
        return [Rejection("G-2", "the plan was made by ZET with --now (time override for tests) (now_override: true). "
                                 "It is accepted only when GER_ALLOW_NOW_OVERRIDE=1")], []
    dues = [parse_ts(it["due_at"]) for it in plan["items"] if it["decision"] == "remediate" and it["due_at"] is not None]
    if dues and now > max(dues):
        return [Rejection("G-2", f"the plan has expired (past the latest remediate due_at {max(dues).strftime('%Y-%m-%dT%H:%M:%SZ')}). "
                                 "Decide again with ZET")], []

    rej: list[Rejection] = []
    # G-3 binding of the approval
    appr = inp["approval"]
    ph = plan_hash(plan)
    if plan["plan_hash"] != ph:
        rej.append(Rejection("G-3", "plan_hash does not match the plan body (the plan was altered)"))
    if appr["plan_id"] != plan["plan_id"]:
        rej.append(Rejection("G-3", "approval.plan_id does not match plan.plan_id"))
    if appr["approval_token"] != ph:
        rej.append(Rejection("G-3", "approval_token does not match the plan_hash of the approved plan (the plan may have been replaced after approval)"))
    if parse_ts(appr["approved_at"]) > now:
        rej.append(Rejection("G-3", "approved_at is in the future"))
    if parse_ts(appr["approved_at"]) < parse_ts(plan["created_at"]):
        rej.append(Rejection("G-3", "approved_at is earlier than the creation of the plan"))
    age = (now - parse_ts(appr["approved_at"])).total_seconds()
    if age > approval_max_age and command != "recover":
        rej.append(Rejection("G-3", f"the approval is too old ({int(age)} seconds since approved_at; limit {approval_max_age} seconds, "
                                    "configurable with GER_APPROVAL_MAX_AGE). Get a new approval"))
    # G-4 no self-approval
    # Names are case-insensitive (ASCII only by the pattern; "OPS" and "ops" are treated as the same person)
    approvers = {a.casefold() for a in appr["approved_by"]}
    if operator.casefold() in approvers:
        rej.append(Rejection("G-4", "the operator (--operator) is one of the approvers"))
    if rej:
        return rej, []
    if command in ("confirm", "recover"):
        return [], []
    # G-8 an unfinished journal (an apply that was killed, or whose rollback failed) must be recovered first. Running
    #   another apply on top of it would leave a journal that ger recover replays later, undoing the newer changes
    r = _open_journal_rejections()
    if r:
        return r, []

    items = [it for it in plan["items"] if it["decision"] == "remediate"]
    allowed = set(inp["allowed_actions"])
    for it in items:
        a, fid = it["action"], it["finding_id"]
        if a is None:
            rej.append(Rejection("G-5", "a remediate item has no action", fid))
            continue
        # G-5 allowlist, supported by GER
        if a["type"] not in allowed:
            rej.append(Rejection("G-5", f"operation {a['type']} is not in allowed_actions", fid))
        if a["type"] not in REGISTRY:
            rej.append(Rejection("G-5", f"operation {a['type']} is not supported by GER (the whole plan is rejected)", fid))
            continue
        # G-1 params per operation (actions.schema.json and the meaning checks of the operation)
        r = _schema("actions.schema.json", {"type": a["type"], "params": a["params"]}, "action")
        if r:
            rej.extend(Rejection("G-1", x.message, fid) for x in r)
            continue
        try:
            REGISTRY[a["type"]].validate_params(a["params"])
        except ActionError as e:
            rej.append(Rejection("G-1", f"params: {e}", fid))
            continue
        # G-6 two approvers, SkillPact
        if "reversible" not in a or "skillpact_effects" not in a:
            rej.append(Rejection("G-6", "the action has no reversible / skillpact_effects (only plans finalized by ZET are accepted)", fid))
            continue
        mod = REGISTRY[a["type"]]
        if a["reversible"] != mod.REVERSIBLE:
            rej.append(Rejection("G-6", f"action.reversible does not match the nature of operation {a['type']}", fid))
        if a["reversible"] is False and len(approvers) < 2:
            rej.append(Rejection("G-6", "an irreversible operation requires 2 or more approvers", fid))
        if needs_two(a) and len(approvers) < 2:
            rej.append(Rejection("G-6", "a target that requires root, or a destructive operation, requires 2 or more approvers", fid))
        risky = [e for e in a["skillpact_effects"] if e in RISKY_EFFECTS]
        if risky and a["type"] not in allowed:
            rej.append(Rejection("G-6", f"an operation on a skill that declares {','.join(risky)} must be listed explicitly in allowed_actions", fid))
        if risky and len(approvers) < 2:
            rej.append(Rejection("G-6", f"an operation on a skill that declares {','.join(risky)} requires 2 or more approvers", fid))
    if rej:
        return rej, []

    # G-7 / G-9 / G-10 pre-validation of the targets (all of them)
    own_pool = pool is None
    pool = pool or fsutil.FdPool()
    steps = []
    try:
        steps, rej = _prepare_all(plan, items, approvers, pool)
    finally:
        if own_pool and (rej or command == "verify"):
            pool.close()
    if rej:
        return rej, []

    # G-8 dry-run record (apply only)
    if command == "apply":
        broken = audit.verify_chain()
        if broken:
            pool.close()
            return [Rejection("G-8", f"the dry-run record cannot be trusted because the hash chain of the audit log is broken ({broken[0]})")], []
        if audit.find_dry_run(ph, input_hash(inp), now, dry_run_ttl, now_override) is None:
            pool.close()
            return [Rejection("G-8", f"no successful dry-run record of the same plan and input within {dry_run_ttl} seconds")], []
    return [], steps


def _open_journal_rejections() -> list[Rejection]:
    try:
        journals = store.open_journals()
    except OSError as e:
        return [Rejection("G-8", f"cannot read the journals of the quarantine store ({e.strerror or e})")]
    out = []
    for run_id, recs, damaged in journals[:8]:
        head = recs[0] if recs and isinstance(recs[0], dict) else {}
        if damaged is not None:
            out.append(Rejection("G-8", f"the journal of an earlier apply is damaged (run {run_id}, plan {head.get('plan_id')}, "
                                        f"line {damaged} cannot be read): ger recover does not replay it. Check its targets by "
                                        "hand, then move the journal out of the journal directory of the quarantine store"))
            continue
        out.append(Rejection("G-8", f"an earlier apply did not finish (run {run_id}, plan {head.get('plan_id')}): its journal is still "
                                    "open. Run ger recover with that plan's input first (nothing is applied while a journal is open)"))
    return out


def make_ctx(plan: dict, pool: fsutil.FdPool) -> Ctx:
    prot_paths, prot_ino = _audit_protected()
    scope = plan.get("scope") or {}
    ctx = Ctx(plan, list(scope.get("roots", [])), scope.get("home"), pool, prot_paths, prot_ino)
    return ctx


def _prepare_all(plan: dict, items: list[dict], approvers: set, pool: fsutil.FdPool):
    rej: list[Rejection] = []
    ctx = make_ctx(plan, pool)
    scope = plan.get("scope")
    fs_items = [it for it in items if it["action"]["type"] in FS_CHANGING]
    # chmod (the original operation) works without scope (if there is a scope, the chmod target must be under it too)
    if any(it["action"]["type"] != "chmod" for it in fs_items) and is_v11(plan):
        if not scope or not scope.get("roots"):
            return [], [Rejection("G-9", "operations that change files require plan.scope.roots (the approved scan scope)")]
        why = store_placement_reason(scope)
        if why:
            return [], [Rejection("G-9", why)]
    if any(it["action"]["type"] in ("quarantine",) or it["action"]["type"] in REGISTRY and REGISTRY[it["action"]["type"]].ORDER == 0
           for it in fs_items):
        try:
            ctx.store_dev = store.device()
        except (OSError, store.StoreError) as e:
            return [], [Rejection("G-9", f"cannot prepare the quarantine store ({e})")]
    steps = []
    seen_targets: dict[str, str] = {}
    seen_ino: set = set()
    touched: list[tuple[str, str]] = []  # (path, finding_id)
    root_kinds = set()
    for grp in _groups(items):
        idx, it0 = grp[0]
        a0, fid = it0["action"], it0["finding_id"]
        t = a0["target"]
        try:
            # Items of the same group must have the same type, target and evidence
            for _i, it in grp[1:]:
                a = it["action"]
                if a["type"] != a0["type"] or a["target"] != t:
                    raise ActionError(f"type / target differ between items of group {a0.get('group')}")
            # Items with the same finding_path must have the same content-based evidence (file / tree / symlink).
            # Items with different finding_path values (a skill directory tree and skill.contract.json file in findings 1.1,
            # node_modules/<name>/package.json and a lockfile) are evidence of different things and are not compared. The evidence of every
            # item is derived again from its own finding_path and compared by check_evidence below (per item, all items).
            # detail (directories and links from ZES 1.0) is a hash of each finding's wording and does not match. In that case
            # the preview hash fixed in params is relied on
            content = {"file", "large_file", "tree", "symlink"}
            by_fp: dict = {}
            for _i, it in grp:
                a = it["action"]
                ev = a.get("evidence", {})
                if a0["type"] == checklist_mod.TYPE or ev.get("kind") not in content:
                    continue
                ev0 = by_fp.setdefault(a.get("finding_path"), ev)
                if ev.get("hash") != ev0.get("hash"):
                    raise ActionError(f"evidence.hash differs between items of group {a0.get('group')} (same finding_path)")
            if t is not None:
                if not _target_shape_ok(t):
                    raise ActionError("the target must be a normalized absolute path (no . / .., no repeated /)")
                if a0["type"] != checklist_mod.TYPE:
                    if t in seen_targets:
                        raise ActionError("the plan has more than one operation on the same target (group several findings on the same file with action.group)")
                    seen_targets[t] = fid
            mod = REGISTRY[a0["type"]]
            if a0["type"] in FS_CHANGING:
                if scope is not None and not in_scope(t, scope):
                    raise ActionError("G-9: the target is outside the approved scan scope (plan.scope)")
                why = protected_reason(t)
                if why:
                    raise ActionError(f"G-9: {why}")
                try:
                    lst = os.lstat(t)
                    if t in ctx.protected_paths or (lst.st_dev, lst.st_ino) in ctx.protected_ino:
                        raise ActionError("the audit log, its directory and the directories above it cannot be targets (nothing could be recorded after the change)")
                    own_root = lst.st_uid != ctx.euid
                except FileNotFoundError:
                    own_root = False
                if hazards.root_required_lexical(t) or own_root:
                    root_kinds.add(True)
                    if len(approvers) < 2:
                        raise ActionError("G-6: a target that requires root (owner is not the executing user, or a system directory) requires 2 or more approvers")
                else:
                    root_kinds.add(False)
            items_ = [Item(it["finding_id"], it["action"], it["approved_by"], i, it.get("level_effective", ""))
                      for i, it in grp]
            step = mod.prepare(ctx, items_)
            if a0["type"] in FS_CHANGING and not step.noop:
                for it in grp:
                    check_evidence(it[1]["action"])
                for p in (step.paths() if hasattr(step, "paths") else [t]):
                    for q, qf in touched:
                        if fsutil.is_under(p, q) or fsutil.is_under(q, p):
                            raise ActionError(f"overlaps the target of another item ({qf[:15]}...) (one is above the other). Group the same target")
                    touched.append((p, fid))
                ino = getattr(step, "st", None) or getattr(getattr(step, "res", None), "st", None)
                if ino is not None:
                    key = (ino.st_dev, ino.st_ino)
                    if key in seen_ino:
                        raise ActionError("the plan has more than one operation on the same object (hard link)")
                    seen_ino.add(key)
            steps.append(step)
        except FileNotFoundError:
            rej.append(Rejection("G-7", "the target does not exist", fid))
        except fsutil.FsError as e:
            rej.append(Rejection("G-7", str(e), fid))
        except (ActionError, OSError, ValueError) as e:  # ValueError: a NUL character in the path and so on
            msg = str(e)
            # Only a fixed prefix or the gate set where the error is raised decides the gate: the message can contain
            #   names from the scanned content (a server name, a RECORD path)
            gate = msg[:3] if msg.startswith(("G-6:", "G-9:")) else "G-7"
            if getattr(e, "gate", None) == "G-10" or msg.startswith("Q-6:"):
                gate = "G-10"
            rej.append(Rejection(gate, msg[5:] if gate in ("G-6", "G-9") else msg, fid))
    if len(root_kinds) > 1:
        rej.append(Rejection("G-9", "the plan mixes targets that require root and targets that do not. Split the plan"))
    steps.sort(key=lambda s: (s.order, s.items[0].index))
    return steps, rej
