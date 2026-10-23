"""dry-run と apply。1 件でも失敗したら残りを実行せず、適用済みを逆順に戻す。

ステップ（トランザクション）は gates.check_gates が作る。同じ group の item は 1 つのステップで、結果は item ごとに出す。
ファイルを変えるステップ（quarantine / 編集）は、実行の前に意図をジャーナル（隔離ストアの journal/<run_id>.jsonl）に
fsync 付きで書く。途中でプロセスが落ちた場合は ger recover でジャーナルから巻き戻す。
"""
from __future__ import annotations

from . import store
from .actions.base import Runtime
from .core import fmt_ts, now_utc

ROLLED_BACK, ROLLBACK_FAILED = "rolled_back", "rollback_failed"
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
    """戻り値: (results, outcome)。outcome は None（成功）/ rolled_back / rollback_failed。"""
    journal = None
    if any(s.type in JOURNALED and not s.noop for s in steps):
        run_id = run_id or store.new_run_id(clock())
        journal = store.Journal(run_id, {"plan_id": plan["plan_id"], "plan_hash": plan_hash, "input_hash": input_hash,
                                         "steps": [s.audit() for s in steps]})
    rt = Runtime(run_id or "norun", journal, plan["plan_id"], plan_hash, clock)
    results: list[list[dict]] = []  # ステップごとの結果
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
            except Exception as e:  # 失敗は全件ロールバックの契機
                reason = f"{type(e).__name__}: {e}"
                if getattr(e, "applied", False):  # 変更済みの可能性があり、同一実体と確認できないため戻せない
                    outcome = ROLLBACK_FAILED
                    reason = f"applied_unverified: 変更が適用された可能性がありますが、検証もロールバックもできません（{reason}）"
                elif s.undo and s.type in JOURNALED:  # 途中まで進んだ分（一時ファイル・一部のメンバー）を戻す
                    try:
                        s.rollback(rt)
                        if journal:
                            journal.write({"event": "step_rolled_back", "step": i})
                    except Exception as e2:
                        outcome = ROLLBACK_FAILED
                        reason += f"; 途中まで進んだ変更を戻せません: {type(e2).__name__}: {e2}"
                results.append(_items_results(s, "failed", reason, after_override=True))
                failure = i
                break
            if journal and s.type in JOURNALED:
                journal.write({"event": "step_done", "step": i})
            done.append((len(results), s))
            if s.type == "checklist":
                results.append(_items_results(s, "pending_manual", f"checklist:{s.items[0].action['params']['template']}"))
            else:
                results.append([dict(r, reason=_reason_ok(s, it)) for r, it in
                                zip(_items_results(s, "applied", "ok", fmt_ts(clock())), s.items)])
        if failure is None:
            if journal:
                journal.write({"event": "commit"})
            return [r for rs in results for r in rs] + skipped_decisions(plan), None
        for s in steps[failure + 1:]:
            results.append(_items_results(s, "skipped", "aborted_after_failure", after_override=True))
        for idx, s in reversed(done):
            try:
                rt.step_no = steps.index(s)
                s.rollback(rt)
                b, _a = s.before_after()
                for r in results[idx]:
                    r.update(result="rolled_back", after=b if s.type != "chmod" else r["before"],
                             reason="rolled_back_after_failure")
                if journal and s.type in JOURNALED:
                    journal.write({"event": "step_rolled_back", "step": rt.step_no})
            except Exception as e:
                outcome = ROLLBACK_FAILED
                for r in results[idx]:
                    r.update(reason=f"rollback_failed: {type(e).__name__}: {e}")
        if journal:
            # rollback_failed はジャーナルを開いたままにする（ger recover の対象）
            journal.write({"event": "rolled_back" if outcome == ROLLED_BACK else "rollback_failed"})
        return [r for rs in results for r in rs] + skipped_decisions(plan), outcome
    finally:
        if journal:
            journal.close()
