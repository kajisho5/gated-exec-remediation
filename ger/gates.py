"""実行前ゲート G-1〜G-8。1 つでも失敗したら何も変更しない。

check_gates() は変更を一切行わない（stat の取得と、evidence_hash の確認のための読み取りのみ）。
戻り値の Prepared は実行に必要な最小限の情報（対象・目標 mode・事前検証時の実体 ID・現在の mode）。

approval_token（= plan_hash）は「承認後に plan が変わっていない」ことしか示さない（完全性）。
plan を書き換えて plan_hash を計算し直すと暗号的には検出できない（真正性は承認者の署名が必要。将来の課題）。
そのため ZET の不変条件のうち plan だけで評価できるもの（_zet_invariants）をここで再検査し、
chmod は現在の mode に無い権限を足せない（G-7）ようにして、改ざんされた plan でも権限を緩められないようにする。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import posixpath
import stat
from collections import Counter
from dataclasses import dataclass

from . import audit
from .actions import REGISTRY
from .actions.chmod import ActionError, fmt
from .core import RISKY_EFFECTS, Rejection, input_hash, parse_ts, plan_hash, validator

EVIDENCE_FULL_HASH_MAX = 104857600  # ZES と同じ: 100MB 以下は内容の SHA-256、超えるとパス・サイズ・mtime の SHA-256


@dataclass(frozen=True)
class Prepared:
    finding_id: str
    action_type: str
    target: str
    mode: int
    ident: tuple[int, int, int]  # (st_dev, st_ino, st_ctime_ns)
    before: int


def with_ancestors(*given) -> tuple[set[str], set[tuple[int, int]]]:
    """given の各パスとその上位ディレクトリすべての (パスの集合, 存在するものの (st_dev, st_ino) の集合)。

    字句上の上位（与えられたパスの途中の要素。シンボリックリンクを含む）と実パスの上位の和集合を返す。
    実パスの上位だけでは、途中のシンボリックリンクを置いたディレクトリ（A/link → B/dir の A）が漏れ、
    そこを chmod 0000 されるとそのパス経由で書けなくなる。
    """
    paths: set[str] = set()
    idents: set[tuple[int, int]] = set()
    starts: set[str] = set()
    for g in given:
        g = os.fspath(g)
        g = g if os.path.isabs(g) else os.path.join(os.getcwd(), g)
        parts = g.split("/")
        for i in range(1, len(parts) + 1):  # 途中の各要素（../ を畳む前の字句どおり）を、字句上と実パスの両方で
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
    """変更すると GER 自身が監査ログを書けなくなるもの: 監査ログ、そのディレクトリとその上位すべて
    （指定された GER_LOG_DIR の字句上の上位と、起動時に解決した実パスの上位の両方）。"""
    paths, idents = with_ancestors(audit.given_log_dir(), audit.log_dir())
    lp = audit.log_path()
    paths.add(os.path.realpath(lp))
    try:
        st = os.stat(lp)
        idents.add((st.st_dev, st.st_ino))
    except OSError:  # まだ無い（初回）
        pass
    return paths, idents


def _schema(name: str, inst, label: str, gate: str = "G-1") -> list[Rejection]:
    return [Rejection(gate, f"{label}{e}") for e in validator(name).errors(inst)]


def _names(xs) -> set[str]:
    return {x.casefold() for x in xs}


def _target_shape_ok(t: str) -> bool:
    """ZET の I-4 と同じ: 正規化済みの絶対パス（. / .. / 連続した /（先頭の // を含む）を含まない）。"""
    return t.startswith("/") and "//" not in t and posixpath.normpath(t) == t and ".." not in t.split("/")


def _zet_invariants(plan: dict, now: dt.datetime) -> list[Rejection]:
    """ZET の不変条件 I-1〜I-12 のうち、findings やポリシーを見ずに plan だけで評価できるもの（G-1）。

    評価できないもの（I-2 finding の実在、I-4 target と finding の path の一致、I-8 承認者の許可リスト、
    I-9 の期限日数、I-10 の未確定モジュール）は ZET の check に任せる。
    """
    rej: list[Rejection] = []

    def bad(code: str, msg: str, fid=None) -> None:
        rej.append(Rejection("G-1", f"ZET {code} 相当: {msg}", fid))

    created = parse_ts(plan["created_at"])
    # I-11: 存在する日時
    for it in plan["items"]:
        for k in ("decided_at", "due_at", "recheck_at"):
            if it[k] is not None:
                try:
                    parse_ts(it[k])
                except ValueError:
                    bad("I-11", f"{k} が実在しない日時です: {it[k]}", it["finding_id"])
    if rej:
        return rej
    # I-1: finding は items と held を通じて 1 回だけ
    seen = Counter(e["finding_id"] for e in plan["items"] + plan["held"] if e["finding_id"] is not None)
    for fid in sorted(f for f, c in seen.items() if c > 1):
        bad("I-1", "finding_id が items / held に重複しています", fid)
    # I-12: partial の plan は held が空でない
    if plan["status"] == "partial" and not plan["held"]:
        bad("I-12", "status が partial なのに held が空です")
    for it in plan["items"]:
        fid, d, a = it["finding_id"], it["decision"], it["action"]
        appr = _names(it["approved_by"])
        if len(appr) != len(it["approved_by"]):
            bad("I-6", "approved_by に重複があります（大文字小文字だけの違いを含む）", fid)
        if it["decided_by"].casefold() in appr:
            bad("I-3", "判断者本人が approved_by に含まれています（自己承認）", fid)
        if d == "exception":
            if it["exception_type"] is None or not (it["reason"] or "").strip() or it["recheck_at"] is None:
                bad("I-3", "exception には exception_type・reason・recheck_at が必要です", fid)
            if not appr:
                bad("I-3", "exception には判断者以外の承認者が 1 名以上必要です", fid)
        elif it["exception_type"] is not None:
            bad("I-3", "exception 以外で exception_type が設定されています", fid)
        if d == "defer" and it["level_effective"] != "INFO" and (not (it["reason"] or "").strip() or it["recheck_at"] is None):
            bad("I-3", "defer（level_effective が INFO 以外）には reason と recheck_at が必要です", fid)
        if d == "remediate":
            if not (it["owner"] or "").strip() or it["due_at"] is None or a is None:
                bad("I-4", "remediate には owner・due_at・action が必要です", fid)
        elif a is not None:
            bad("I-4", "remediate 以外で action が設定されています", fid)
        if a is not None and not _target_shape_ok(a["target"]):
            bad("I-4", "action.target は正規化された絶対パスにすること（. / .. / 連続した / を含まない）", fid)
        # I-5 / I-6 / I-7 と skillpact_effects の整合（ZET が finalize で写した finding の skillpact の要約に対して）
        sp = it.get("skillpact")
        if sp is not None:
            if sp["divergence"] and d == "exception":
                bad("I-5", "skillpact.divergence が空でない finding は exception にできません", fid)
            if sp["diff_anomaly"] and len(appr) < 2:
                bad("I-6", "skillpact.diff_anomaly の finding は承認者 2 名以上が必要です", fid)
            if sp["signed"] and sp["divergence"] and it["level_effective"] != "CRITICAL":
                bad("I-7", "署名フィールドがあり乖離のある finding の level_effective は CRITICAL です", fid)
            if a is not None and "skillpact_effects" in a and sorted(a["skillpact_effects"]) != sorted(sp["declared_effects"]):
                bad("I-4", "action.skillpact_effects が item の skillpact.declared_effects と一致しません", fid)
        if d == "remediate" and a is not None and any(e in RISKY_EFFECTS for e in a.get("skillpact_effects", [])) and len(appr) < 2:
            bad("I-6", "exec / network / spend / send を宣言したスキルへの remediate は承認者 2 名以上が必要です", fid)
        # I-9: 日付の前後関係（期限の日数はポリシーが必要なため ZET に任せる）
        dec = parse_ts(it["decided_at"])
        if dec < created:
            bad("I-9", "decided_at が plan の created_at より前です", fid)
        if dec > now:
            bad("I-9", "decided_at が現在時刻より後です", fid)
        for k in ("due_at", "recheck_at"):
            if it[k] is not None and parse_ts(it[k]) < dec:
                bad("I-9", f"{k} が decided_at より前です", fid)
    return rej


def evidence_digest(target: str, st: os.stat_result) -> str | None:
    """ZES の evidence_hash と同じ規則で現在のファイルのハッシュを計算する。比べられない対象（ディレクトリ）は None。

    100MB 以下の通常ファイルは内容の SHA-256、100MB 超は「パス|サイズ|mtime（秒）」の SHA-256。
    読めない場合は ActionError（確かめられないものは通さない）。
    """
    if not stat.S_ISREG(st.st_mode):
        return None  # ZES は通常ファイル以外では detail のハッシュを使う。GER には detail が無いため比べない
    if st.st_size > EVIDENCE_FULL_HASH_MAX:
        return "sha256:" + hashlib.sha256(f"{target}|{st.st_size}|{int(st.st_mtime)}".encode("utf-8", "surrogateescape")).hexdigest()
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise ActionError(f"evidence_hash を確かめるために対象を読めません（{e.strerror}）") from None
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise ActionError("事前検証中に対象が差し替えられました")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def check_gates(inp, operator: str, now: dt.datetime, command: str, dry_run_ttl: int,
                now_override: bool = False, approval_max_age: int = 7 * 86400,
                allow_now_override_plan: bool = False) -> tuple[list[Rejection], list[Prepared]]:
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
    # G-1 ZET の不変条件のうち plan だけで評価できるもの（承認トークンは完全性しか示さないため再検査する）。
    # 確定 plan（decision・decided_by・decided_at が必ずある）であることを G-2 で確かめてから行う
    r = _zet_invariants(plan, now)
    if r:
        return r, []
    if plan.get("now_override") and not allow_now_override_plan:
        return [Rejection("G-2", "ZET が --now（テスト用の時刻上書き）で作った計画です（now_override: true）。"
                                 "GER_ALLOW_NOW_OVERRIDE=1 のときだけ受理します")], []
    dues = [parse_ts(it["due_at"]) for it in plan["items"] if it["decision"] == "remediate" and it["due_at"] is not None]
    if dues and now > max(dues):
        return [Rejection("G-2", f"計画の期限切れです（remediate の due_at の最大 {max(dues).strftime('%Y-%m-%dT%H:%M:%SZ')} を過ぎています）。"
                                 "ZET で判断し直してください")], []

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
    age = (now - parse_ts(appr["approved_at"])).total_seconds()
    if age > approval_max_age:
        rej.append(Rejection("G-3", f"承認が古すぎます（approved_at から {int(age)} 秒。上限 {approval_max_age} 秒、"
                                    "GER_APPROVAL_MAX_AGE で変更可）。承認を取り直してください"))
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
        if risky and len(approvers) < 2:
            rej.append(Rejection("G-6", f"{','.join(risky)} を宣言したスキルへの操作には承認者 2 名以上が必要です", fid))
    if rej:
        return rej, []

    # G-7 対象の事前検証（全件）
    prepared: list[Prepared] = []
    seen: set[str] = set()
    seen_ino: set[tuple[int, int]] = set()
    prot_paths, prot_ino = _audit_protected()
    for it in items:
        a, fid = it["action"], it["finding_id"]
        t = a["target"]
        try:
            if not _target_shape_ok(t):
                raise ActionError("対象は正規化済みの絶対パスであること（. / .. / 連続した / 不可）")
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
            if t in prot_paths or (st.st_dev, st.st_ino) in prot_ino:
                raise ActionError("監査ログ・そのディレクトリ・その上位ディレクトリは対象にできません（変更後に記録できなくなる）")
            before = st.st_mode & 0o7777
            added = mode & ~before
            if added:  # 修復は権限を絞る操作に限る。改ざんされた plan でも権限を緩められないようにする
                raise ActionError(f"chmod {fmt(mode)} は現在の mode {fmt(before)} に無い権限（{added:04o}）を足します"
                                  "（権限を絞る操作だけを受け付けます）")
            if "evidence_hash" in a:
                got = evidence_digest(t, st)
                if got is not None and got != a["evidence_hash"]:
                    raise ActionError("対象の内容が検知時（finding の evidence_hash）から変わっています。ZES で再検知してください")
            prepared.append(Prepared(fid, a["type"], t, mode, (st.st_dev, st.st_ino, st.st_ctime_ns), before))
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
        if audit.find_dry_run(ph, input_hash(inp), now, dry_run_ttl, now_override) is None:
            return [Rejection("G-8", f"同一計画・同一入力の dry-run 成功記録が {dry_run_ttl} 秒以内にありません")], []
    return [], prepared
