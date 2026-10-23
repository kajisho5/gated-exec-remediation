"""dry-run と apply。1 件でも失敗したら残りを実行せず、適用済みを逆順に戻す。"""
from __future__ import annotations

from .actions import REGISTRY
from .actions.chmod import fmt
from .core import fmt_ts, now_utc
from .gates import Prepared

ROLLED_BACK, ROLLBACK_FAILED = "rolled_back", "rollback_failed"


def _result(fid, atype, target, before, after, result, reason, applied_at=None) -> dict:
    return {"finding_id": fid, "action_type": atype, "target": target, "before": before, "after": after,
            "result": result, "reason": reason, "applied_at": applied_at}


def skipped_decisions(plan: dict) -> list[dict]:
    return [_result(it["finding_id"], None, None, None, None, "skipped", f"decision:{it['decision']}")
            for it in plan["items"] if it["decision"] != "remediate"]


def dry_run(plan: dict, prepared: list[Prepared]) -> list[dict]:
    out = []
    for p in prepared:
        reason = "already_compliant" if p.before == p.mode else "dry_run:would_apply"
        out.append(_result(p.finding_id, p.action_type, p.target, fmt(p.before), fmt(p.mode), "skipped", reason))
    return out + skipped_decisions(plan)


def apply(plan: dict, prepared: list[Prepared], clock=now_utc) -> tuple[list[dict], str | None]:
    """戻り値: (results, outcome)。outcome は None（成功）/ rolled_back / rollback_failed。"""
    results: list[dict] = []
    done: list[tuple[Prepared, tuple[int, int, int]]] = []  # (計画, 適用後の実体 ID)
    failure = None
    outcome = ROLLED_BACK
    for i, p in enumerate(prepared):
        if p.before == p.mode:
            results.append(_result(p.finding_id, p.action_type, p.target, fmt(p.before), fmt(p.mode), "skipped", "already_compliant"))
            continue
        try:
            new_ident = REGISTRY[p.action_type].set_mode(p.target, p.mode, p.ident)
        except Exception as e:  # 失敗は全件ロールバックの契機
            reason = f"{type(e).__name__}: {e}"
            if getattr(e, "applied", False):  # 変更済みの可能性があり、同一実体と確認できないため戻せない
                outcome = ROLLBACK_FAILED
                reason = f"applied_unverified: 変更が適用された可能性がありますが、検証もロールバックもできません（{reason}）"
            results.append(_result(p.finding_id, p.action_type, p.target, fmt(p.before), None, "failed", reason))
            failure = i
            break
        done.append((p, new_ident))
        results.append(_result(p.finding_id, p.action_type, p.target, fmt(p.before), fmt(p.mode), "applied", "ok", fmt_ts(clock())))
    if failure is None:
        return results + skipped_decisions(plan), None
    for p in prepared[failure + 1:]:
        results.append(_result(p.finding_id, p.action_type, p.target, fmt(p.before), None, "skipped", "aborted_after_failure"))
    by_fid = {r["finding_id"]: r for r in results}
    for p, applied_ident in reversed(done):
        r = by_fid[p.finding_id]
        try:
            REGISTRY[p.action_type].set_mode(p.target, p.before, applied_ident)
            r.update(result="rolled_back", after=fmt(p.before), reason="rolled_back_after_failure")
        except Exception as e:
            outcome = ROLLBACK_FAILED
            r.update(reason=f"rollback_failed: {type(e).__name__}: {e}")
    return results + skipped_decisions(plan), outcome
