"""dry-run and apply. If one step fails, the rest is not executed and the applied steps are undone in reverse order.

Steps (transactions) are built by gates.check_gates. The items of one group form one step; results are reported per item.
Steps that change files (quarantine / edits) write their intent to the journal (journal/<run_id>.jsonl in the quarantine store)
with fsync before running. If the process dies halfway, ger recover rolls back from the journal.
"""
from __future__ import annotations

from . import store
from .actions.base import Runtime
from .core import fmt_ts, now_utc

ROLLED_BACK, ROLLBACK_FAILED, JOURNAL_FAILED = "rolled_back", "rollback_failed", "journal_failed"
JOURNALED = ("quarantine", "edit_json", "edit_toml", "remove_line", "disable_mcp_server")


def _result(fid, atype, target, before, after, result, reason, applied_at=None, extra=None) -> dict:
    r = {"finding_id": fid, "action_type": atype, "target": target, "before": before, "after": after,
         "result": result, "reason": reason, "applied_at": applied_at}
    if extra:
        r.update(extra)
    return r


def skipped_decisions(plan: dict) -> list[dict]:
    return [_result(it["finding_id"], None, None, None, None, "skipped", f"decision:{it['decision']}")
            for it in plan["items"] if it["decision"] != "remediate"]


def _extra(step, item) -> dict:
    e = {}
    if item.action.get("group"):
        e["group"] = item.action["group"]
    if item.action.get("followup"):
        e["followup"] = [f["template"] for f in item.action["followup"]]
    x = step.result_extra()
    if x.get("quarantine_ids"):
        e["quarantine_ids"] = x["quarantine_ids"]
    return e


def _reason_ok(step, item) -> str:
    g = item.action.get("group")
    return f"group:{g}" if g else "ok"


def dry_run(plan: dict, steps) -> list[dict]:
    out = []
    for s in steps:
        b, a = s.before_after()
        for it in s.items:
            if s.type == "checklist":
                reason = "dry_run:would_record_checklist"
            else:
                reason = "already_compliant" if s.noop else "dry_run:would_apply"
            if s.type == "quarantine" and not s.noop:
                a = "quarantine"
            out.append(_result(it.finding_id, s.type, s.target, b, a, "skipped", reason, extra=_extra(s, it)))
    return out + skipped_decisions(plan)


def _items_results(step, result, reason, applied_at=None, after_override=False, after=None):
    b, a = step.before_after()
    if after_override:
        a = after
    return [_result(it.finding_id, step.type, step.target, b, a, result, reason, applied_at, _extra(step, it))
            for it in step.items]


def apply(plan: dict, steps, clock=now_utc, run_id: str | None = None, plan_hash: str | None = None,
          input_hash: str | None = None) -> tuple[list[dict], str | None]:
    """Returns (results, outcome). outcome is None (success) / rolled_back / rollback_failed / journal_failed.

    journal_failed: a journal line could not be written (short write, ENOSPC). The apply stops before the next change and
    rolls back in process what it did; the records after the failure are written as far as the file system allows
    (store.Journal cuts a failed line back, so the journal never holds a partial record in the middle). An apply is
    committed only when its commit record is in the journal: a commit that cannot be written rolls everything back."""
    journal = None
    jerr: list[str] = []

    def jwrite(rec: dict) -> bool:
        try:
            journal.write(rec)
            return True
        except store.JournalWriteError as e:
            jerr.append(str(e))
            return False

    if any(s.type in JOURNALED and not s.noop for s in steps):
        run_id = run_id or store.new_run_id(clock())
        try:
            journal = store.Journal(run_id, {"plan_id": plan["plan_id"], "plan_hash": plan_hash, "input_hash": input_hash,
                                             "steps": [s.audit() for s in steps]})
        except OSError as e:  # Nothing changed yet (the journal is written before the first change)
            reason = f"aborted: the journal could not be created ({type(e).__name__}: {e})"
            return [r for s in steps for r in _items_results(s, "skipped", reason, after_override=True)] \
                + skipped_decisions(plan), JOURNAL_FAILED
    rt = Runtime(run_id or "norun", journal, plan["plan_id"], plan_hash, clock)
    results: list[list[dict]] = []  # Results per step
    done: list[tuple[int, object]] = []
    failure = None
    outcome = ROLLED_BACK
    try:
        for i, s in enumerate(steps):
            if s.noop:
                results.append(_items_results(s, "skipped", "already_compliant"))
                continue
            rt.step_no = i
            try:
                s.apply(rt)
            except Exception as e:  # Any failure triggers a rollback of everything
                if isinstance(e, store.JournalWriteError):
                    jerr.append(str(e))
                reason = f"{type(e).__name__}: {e}"
                if getattr(e, "applied", False):  # May already be changed and the object cannot be confirmed as the same, so it cannot be undone
                    outcome = ROLLBACK_FAILED
                    reason = f"applied_unverified: the change may have been applied, but it can be neither verified nor rolled back ({reason})"
                elif s.undo and _noted(s):  # Undo what was done so far (temporary file, some members, the mode)
                    try:
                        s.rollback(rt)
                        if journal:
                            jwrite({"event": "step_rolled_back", "step": i})
                    except Exception as e2:
                        outcome = ROLLBACK_FAILED
                        reason += f"; cannot undo the partial change: {type(e2).__name__}: {e2}"
                results.append(_items_results(s, "failed", reason, after_override=True))
                failure = i
                break
            done.append((len(results), s))
            if s.type == "checklist":
                results.append(_items_results(s, "pending_manual", f"checklist:{s.items[0].action['params']['template']}"))
            else:
                results.append([dict(r, reason=_reason_ok(s, it)) for r, it in
                                zip(_items_results(s, "applied", "ok", fmt_ts(clock())), s.items)])
            if journal and s.type in JOURNALED and not jwrite({"event": "step_done", "step": i}):
                failure = i  # Done, but not recorded as done: stop before the next change and undo it with the rest
                break
        if failure is None:
            if not journal or jwrite({"event": "commit"}):
                return [r for rs in results for r in rs] + skipped_decisions(plan), None
            failure = len(steps)  # Every step done, but the commit is not in the journal: not committed, undo everything
        for s in steps[failure + 1:]:
            results.append(_items_results(s, "skipped", "aborted_after_failure", after_override=True))
        for idx, s in reversed(done):
            try:
                rt.step_no = steps.index(s)
                s.rollback(rt)
                b, _a = s.before_after()
                for r in results[idx]:
                    r.update(result="rolled_back", after=b if s.type != "chmod" else r["before"],
                             reason="rolled_back_after_failure" if not jerr else
                             f"rolled_back_after_failure: the journal could not be written ({jerr[0]})")
                if journal and _noted(s):
                    jwrite({"event": "step_rolled_back", "step": rt.step_no})
            except Exception as e:
                outcome = ROLLBACK_FAILED
                for r in results[idx]:
                    r.update(reason=f"rollback_failed: {type(e).__name__}: {e}")
        if journal:
            # rollback_failed keeps the journal open (target of ger recover)
            jwrite({"event": "rolled_back" if outcome == ROLLED_BACK else "rollback_failed"})
        if jerr and outcome == ROLLED_BACK:
            outcome = JOURNAL_FAILED
        return [r for rs in results for r in rs] + skipped_decisions(plan), outcome
    finally:
        if journal:
            journal.close()


def _noted(step) -> bool:
    """Steps that note their progress in the journal (rt.note) and are undone from it by ger recover."""
    return step.type in JOURNALED or step.type == "chmod"
