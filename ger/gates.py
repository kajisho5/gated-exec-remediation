"""実行前ゲート G-1〜G-8。1 つでも失敗したら何も変更しない。

check_gates() は変更を一切行わない（stat の取得のみ）。戻り値の Prepared は実行に必要な
最小限の情報（対象・目標 mode・事前検証時の実体 ID・現在の mode）。
"""
from __future__ import annotations

import datetime as dt
import os
from collections import Counter
from dataclasses import dataclass

from . import audit
from .actions import REGISTRY
from .actions.chmod import ActionError
from .core import RISKY_EFFECTS, Rejection, input_hash, parse_ts, plan_hash, validator


@dataclass(frozen=True)
class Prepared:
    finding_id: str
    action_type: str
    target: str
    mode: int
    ident: tuple[int, int, int]  # (st_dev, st_ino, st_ctime_ns)
    before: int


def _schema(name: str, inst, label: str, gate: str = "G-1") -> list[Rejection]:
    return [Rejection(gate, f"{label}{e}") for e in validator(name).errors(inst)]


def check_gates(inp, operator: str, now: dt.datetime, command: str, dry_run_ttl: int) -> tuple[list[Rejection], list[Prepared]]:
    # G-1 スキーマ・版固定・飛び越し禁止
    if isinstance(inp, dict) and "findings" in inp:
        return [Rejection("G-1", "入力に findings があります（修復層は ZES の出力を直接読まない）")], []
    r = _schema("ger-input.schema.json", inp, "input")
    if r:
        return r, []
    plan = inp["plan"]
    r = _schema("vendor/remediation-plan.schema.json", plan, "plan")
    if r:
        return r, []
    if command in ("dry-run", "apply") and inp["mode"] != command:
        return [Rejection("G-1", f"入力の mode={inp['mode']} とコマンド {command} が一致しません")], []
    # G-1 日時の実在（パターンは 2026-02-30 や T25:00:00 も通すため、ここで解釈できることを確かめる）
    bad_ts = []
    for label, v in (("approval.approved_at", inp["approval"]["approved_at"]), ("plan.created_at", plan["created_at"])):
        try:
            parse_ts(v)
        except ValueError:
            bad_ts.append(Rejection("G-1", f"{label} が実在しない日時です: {v}"))
    if bad_ts:
        return bad_ts, []
    # G-1 finding_id の重複（実行結果・ロールバックを item に一意に対応づけられない計画は構造不正）
    counts = Counter(it["finding_id"] for it in plan["items"] if it["decision"] == "remediate")  # O(n)
    dup = sorted(f for f, c in counts.items() if c > 1)
    if dup:
        return [Rejection("G-1", "remediate の item で finding_id が重複しています", f) for f in dup], []

    # G-2 計画状態
    if plan["status"] not in ("ok", "partial"):
        return [Rejection("G-2", f"plan.status={plan['status']} の計画は実行できません（確定済み ok / partial のみ）")], []

    rej: list[Rejection] = []
    # G-3 承認の束縛
    appr = inp["approval"]
    ph = plan_hash(plan)
    if plan["plan_hash"] != ph:
        rej.append(Rejection("G-3", "plan_hash が plan 本体と一致しません（計画が改変されています）"))
    if appr["plan_id"] != plan["plan_id"]:
        rej.append(Rejection("G-3", "approval.plan_id が plan.plan_id と一致しません"))
    if appr["approval_token"] != ph:
        rej.append(Rejection("G-3", "approval_token が承認対象の plan_hash と一致しません（承認後に計画が差し替えられた可能性）"))
    if parse_ts(appr["approved_at"]) > now:
        rej.append(Rejection("G-3", "approved_at が未来の時刻です"))
    if parse_ts(appr["approved_at"]) < parse_ts(plan["created_at"]):
        rej.append(Rejection("G-3", "approved_at が計画の作成より前です"))
    # G-4 自己承認防止
    # 人名は大文字小文字を区別しない（パターン上 ASCII のみ。"OPS" と "ops" は同一人物として扱う）
    approvers = {a.casefold() for a in appr["approved_by"]}
    if operator.casefold() in approvers:
        rej.append(Rejection("G-4", "実行者（--operator）が承認者に含まれています"))
    if rej:
        return rej, []

    items = [it for it in plan["items"] if it["decision"] == "remediate"]
    allowed = set(inp["allowed_actions"])
    for it in items:
        a, fid = it["action"], it["finding_id"]
        if a is None:
            rej.append(Rejection("G-5", "remediate の item に action がありません", fid))
            continue
        # G-5 許可リスト・GER 対応
        if a["type"] not in allowed:
            rej.append(Rejection("G-5", f"操作 {a['type']} は allowed_actions にありません", fid))
        if a["type"] not in REGISTRY:
            rej.append(Rejection("G-5", f"操作 {a['type']} は GER 未対応です（計画全体を拒否）", fid))
        # G-6 二重承認・SkillPact
        if "reversible" not in a or "skillpact_effects" not in a:
            rej.append(Rejection("G-6", "action に reversible / skillpact_effects がありません（ZET finalize 済みの計画のみ受理）", fid))
            continue
        mod = REGISTRY.get(a["type"])
        if mod is not None and a["reversible"] != mod.REVERSIBLE:
            rej.append(Rejection("G-6", f"action.reversible が操作 {a['type']} の性質と一致しません", fid))
        if a["reversible"] is False and len(approvers) < 2:
            rej.append(Rejection("G-6", "不可逆な操作には承認者 2 名以上が必要です", fid))
        risky = [e for e in a["skillpact_effects"] if e in RISKY_EFFECTS]
        if risky and a["type"] not in allowed:
            rej.append(Rejection("G-6", f"{','.join(risky)} を宣言したスキルへの操作は allowed_actions に明示が必要です", fid))
    if rej:
        return rej, []

    # G-7 対象の事前検証（全件）
    prepared: list[Prepared] = []
    seen: set[str] = set()
    seen_ino: set[tuple[int, int]] = set()
    for it in items:
        a, fid = it["action"], it["finding_id"]
        t = a["target"]
        try:
            if not os.path.isabs(t) or ".." in t.split("/") or os.path.normpath(t) != t:
                raise ActionError("対象は正規化済みの絶対パスであること（.. 不可）")
            if t in seen:
                raise ActionError("同じ対象への操作が計画内で重複しています")
            seen.add(t)
            mode = REGISTRY[a["type"]].parse_params(a["params"])
            st = REGISTRY[a["type"]].inspect(t)
            if (st.st_dev, st.st_ino) in seen_ino:
                raise ActionError("同じ実体（ハードリンク）への操作が計画内で重複しています")
            seen_ino.add((st.st_dev, st.st_ino))
            if os.path.realpath(t) != t:
                raise ActionError("パスの途中にシンボリックリンクがあります")
            prepared.append(Prepared(fid, a["type"], t, mode, (st.st_dev, st.st_ino, st.st_ctime_ns), st.st_mode & 0o7777))
        except FileNotFoundError:
            rej.append(Rejection("G-7", "対象が存在しません", fid))
        except (ActionError, OSError, ValueError) as e:  # ValueError: パスに NUL 文字など
            rej.append(Rejection("G-7", str(e), fid))
    if rej:
        return rej, []

    # G-8 dry-run 記録（apply のみ）
    if command == "apply":
        broken = audit.verify_chain()
        if broken:
            return [Rejection("G-8", f"監査ログのハッシュチェーンが壊れているため dry-run 記録を信用できません（{broken[0]}）")], []
        if audit.find_dry_run(ph, input_hash(inp), now, dry_run_ttl) is None:
            return [Rejection("G-8", f"同一計画・同一入力の dry-run 成功記録が {dry_run_ttl} 秒以内にありません")], []
    return [], prepared
