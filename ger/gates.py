"""実行前ゲート G-1〜G-10。1 つでも失敗したら何も変更しない。

check_gates() は変更を一切行わない（stat・読み取り・ハッシュ計算のみ）。戻り値はステップ（トランザクション）の一覧で、
同じ action.group の item は 1 つのステップにまとめる（ファイルの書き込みは 1 回）。実行順は
(1) 参照を取り除く編集（edit_* / remove_line / disable_mcp_server）→ (2) quarantine → (3) chmod → (4) checklist。

approval_token（= plan_hash）は「承認後に plan が変わっていない」ことしか示さない（完全性）。
plan を書き換えて plan_hash を計算し直すと暗号的には検出できない（真正性は承認者の署名が必要。将来の課題）。
そのため ZET の不変条件のうち plan だけで評価できるもの（_zet_invariants）をここで再検査し、さらに
定義 T（絞るだけ。取り除く単位は GER の表 H に一致、足すものは表 K の定数だけ、T-3 の再パース）と、
対象と finding の関係（G-9）を、計画を信用せず現在のファイルシステムに対して GER 自身が評価する。
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

EVIDENCE_FULL_HASH_MAX = 104857600  # ZES と同じ: 100MB 以下は内容の SHA-256、超えるとパス・サイズ・mtime の SHA-256
MAX_REMEDIATE_ITEMS = 256


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
    （指定された GER_LOG_DIR の字句上の上位と、起動時に解決した実パスの上位の両方）。隔離ストアとその上位も同じ扱い。"""
    paths, idents = with_ancestors(audit.given_log_dir(), audit.log_dir(), store.store_dir())
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


def is_v11(plan: dict) -> bool:
    return plan.get("schema_version") == "1.1"


def needs_two(a: dict) -> bool:
    """承認者 2 名が要る action（§4.3 の表）: 不可逆・破壊的な操作、root が必要な対象（字句上）。"""
    mod = REGISTRY.get(a.get("type"))
    if a.get("reversible") is False or (mod is not None and getattr(mod, "DESTRUCTIVE", False)):
        return True
    t = a.get("target")
    return a.get("type") in FS_CHANGING and isinstance(t, str) and hazards.root_required_lexical(t)


def _zet_invariants(plan: dict, now: dt.datetime) -> list[Rejection]:
    """ZET の不変条件 I-1〜I-13 のうち、findings やポリシーを見ずに plan だけで評価できるもの（G-1）。

    評価できないもの（I-2 finding の実在、I-4 target と finding の path の関係、I-8 承認者の許可リスト、
    I-9 の期限日数、I-10 の未確定モジュール、I-13 の finding の種類ごとの操作）は ZET の check に任せる。
    （I-4 の関係は G-9 でファイルシステムから導き直す。）
    """
    rej: list[Rejection] = []

    def bad(code: str, msg: str, fid=None) -> None:
        rej.append(Rejection("G-1", f"ZET {code} 相当: {msg}", fid))

    created = parse_ts(plan["created_at"])
    v11 = is_v11(plan)
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
        if a is not None:
            t = a["target"]
            if t is None:
                if a["type"] != checklist_mod.TYPE:
                    bad("I-4", "action.target が null にできるのは checklist だけです", fid)
            elif not _target_shape_ok(t):
                bad("I-4", "action.target は正規化された絶対パスにすること（. / .. / 連続した / を含まない）", fid)
            fp = a.get("finding_path")
            if fp is not None and not _target_shape_ok(fp):
                bad("I-4", "action.finding_path は正規化された絶対パスにすること", fid)
            if v11:
                for k in ("relation", "finding_path", "evidence"):
                    if k not in a:
                        bad("I-4", f"確定 plan 1.1 の action には {k} が必要です", fid)
                if "relation" in a and (a["relation"] == "none") != (t is None):
                    bad("I-4", "relation none は target が null の checklist のときだけ（逆も同じ）", fid)
                if a["type"] != checklist_mod.TYPE and t is None:
                    bad("I-4", "target が null の action は checklist だけです", fid)
            elif a["type"] != "chmod" and a["type"] in REGISTRY:
                bad("I-4", f"plan 1.0 で実行できる操作は chmod だけです（{a['type']} は plan 1.1 が必要）", fid)
            if a["type"] == checklist_mod.TYPE and "followup" in a:
                bad("I-4", "checklist の action に followup は付けられません（手順は params.steps に書く）", fid)
            for fu in a.get("followup", []):
                try:
                    checklist_mod.validate_steps(fu, "action.followup[]")
                except ActionError as e:
                    bad("I-4", str(e), fid)
            if v11 and needs_two(a) and len(appr) < 2 and d == "remediate":
                bad("I-6", "root が必要な対象・不可逆・破壊的な操作への remediate は item の承認者 2 名以上が必要です", fid)
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


def check_evidence(a: dict) -> None:
    """action.evidence（ZES が検知したときの finding_path の状態）と現在を照合する（G-7）。
    kind=detail（ZES 1.0 のディレクトリ・リンクなど）は照合できないため、params に固定した preview のハッシュに任せる。"""
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
        raise ActionError("finding の対象（finding_path）がありません。ZES で再検知してください") from None
    if kind in ("file", "large_file"):
        got = evidence_digest(fp, st)
        if got is not None and got != want:
            raise ActionError("対象の内容が検知時（finding の evidence_hash）から変わっています。ZES で再検知してください")
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
            raise ActionError("対象が検知時（finding の evidence）から変わっています。ZES で再検知してください")


# --- 保護対象・範囲（G-9） ----------------------------------------------------------------------
def _stdlib_dir() -> str:
    return os.path.dirname(os.path.realpath(os.__file__))


def protected_reason(t: str) -> str | None:
    """§4.4 の保護対象（対象にも、その上位にもしない）。"""
    home = os.path.realpath(os.path.expanduser("~"))
    if t in hazards.SYSTEM_TOP or t == "/":
        return "システムのトップレベルのディレクトリは対象にできません"
    for p, what in ((home, "$HOME"), (str(ROOT), "GER のインストール先"), (_stdlib_dir(), "Python の標準ライブラリ"),
                    (store.store_dir(), "隔離ストア")):
        if fsutil.is_under(p, t):
            return f"{what}そのもの、またはその上位は対象にできません"
    if fsutil.is_under(t, str(ROOT)):
        return "GER のインストール先の中は対象にできません"
    if fsutil.is_under(t, store.store_dir()):
        return "隔離ストアの中は対象にできません"
    sd = _stdlib_dir()
    if fsutil.is_under(t, sd):
        rest = t[len(sd) + 1:].split("/")
        if not rest or rest[0] not in ("site-packages", "dist-packages"):
            return "Python の標準ライブラリ（site-packages を除く）は対象にできません"
    if t.startswith("/etc/") and not hazards.ETC_ALLOW.match(t):
        return "/etc の下で対象にできるのは /etc/ld.so.preload・/etc/hosts・/etc/cron.d/* だけです"
    return None


def store_placement_reason(scope: dict | None) -> str | None:
    """隔離ストアを置いてはいけない場所（§3.5）。"""
    sd = store.store_dir()
    parts = sd.split("/")
    if any(p in ("site-packages", "dist-packages", "node_modules", "Extensions") for p in parts):
        return f"隔離ストアが site-packages / node_modules / 拡張機能のディレクトリの下にあります: {sd}"
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.isabs(d) and fsutil.is_under(sd, os.path.realpath(d)):
            return f"隔離ストアが PATH のディレクトリの下にあります: {sd}"
    for r in (scope or {}).get("roots", []):
        if fsutil.is_under(sd, r):
            return f"隔離ストアが検査ルート（scope.roots）の下にあります: {sd}（GER_QUARANTINE_DIR で外に置いてください）"
    return None


def in_scope(t: str, scope: dict) -> bool:
    places = list(scope.get("roots", [])) + ([scope["home"]] if scope.get("home") else [])
    return any(fsutil.is_under(t, r) for r in places)


def _groups(items: list[dict]) -> list[list[tuple[int, dict]]]:
    """同じ action.group の item をまとめる。group の無い item は 1 件ずつ。"""
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
    if sum(counts.values()) > MAX_REMEDIATE_ITEMS:
        return [Rejection("G-1", f"remediate の item は 1 計画につき {MAX_REMEDIATE_ITEMS} 件までです")], []
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
    if age > approval_max_age and command != "recover":
        rej.append(Rejection("G-3", f"承認が古すぎます（approved_at から {int(age)} 秒。上限 {approval_max_age} 秒、"
                                    "GER_APPROVAL_MAX_AGE で変更可）。承認を取り直してください"))
    # G-4 自己承認防止
    # 人名は大文字小文字を区別しない（パターン上 ASCII のみ。"OPS" と "ops" は同一人物として扱う）
    approvers = {a.casefold() for a in appr["approved_by"]}
    if operator.casefold() in approvers:
        rej.append(Rejection("G-4", "実行者（--operator）が承認者に含まれています"))
    if rej:
        return rej, []
    if command in ("confirm", "recover"):
        return [], []

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
            continue
        # G-1 操作ごとの params（actions.schema.json と操作の意味の検査）
        r = _schema("actions.schema.json", {"type": a["type"], "params": a["params"]}, "action")
        if r:
            rej.extend(Rejection("G-1", x.message, fid) for x in r)
            continue
        try:
            REGISTRY[a["type"]].validate_params(a["params"])
        except ActionError as e:
            rej.append(Rejection("G-1", f"params: {e}", fid))
            continue
        # G-6 二重承認・SkillPact
        if "reversible" not in a or "skillpact_effects" not in a:
            rej.append(Rejection("G-6", "action に reversible / skillpact_effects がありません（ZET finalize 済みの計画のみ受理）", fid))
            continue
        mod = REGISTRY[a["type"]]
        if a["reversible"] != mod.REVERSIBLE:
            rej.append(Rejection("G-6", f"action.reversible が操作 {a['type']} の性質と一致しません", fid))
        if a["reversible"] is False and len(approvers) < 2:
            rej.append(Rejection("G-6", "不可逆な操作には承認者 2 名以上が必要です", fid))
        if needs_two(a) and len(approvers) < 2:
            rej.append(Rejection("G-6", "root が必要な対象・破壊的な操作には承認者 2 名以上が必要です", fid))
        risky = [e for e in a["skillpact_effects"] if e in RISKY_EFFECTS]
        if risky and a["type"] not in allowed:
            rej.append(Rejection("G-6", f"{','.join(risky)} を宣言したスキルへの操作は allowed_actions に明示が必要です", fid))
        if risky and len(approvers) < 2:
            rej.append(Rejection("G-6", f"{','.join(risky)} を宣言したスキルへの操作には承認者 2 名以上が必要です", fid))
    if rej:
        return rej, []

    # G-7 / G-9 / G-10 対象の事前検証（全件）
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

    # G-8 dry-run 記録（apply のみ）
    if command == "apply":
        broken = audit.verify_chain()
        if broken:
            pool.close()
            return [Rejection("G-8", f"監査ログのハッシュチェーンが壊れているため dry-run 記録を信用できません（{broken[0]}）")], []
        if audit.find_dry_run(ph, input_hash(inp), now, dry_run_ttl, now_override) is None:
            pool.close()
            return [Rejection("G-8", f"同一計画・同一入力の dry-run 成功記録が {dry_run_ttl} 秒以内にありません")], []
    return [], steps


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
    # chmod（従来の操作）は scope が無くても可（scope があれば chmod の対象もその下にあること）
    if any(it["action"]["type"] != "chmod" for it in fs_items) and is_v11(plan):
        if not scope or not scope.get("roots"):
            return [], [Rejection("G-9", "ファイルを変える操作には plan.scope.roots（承認された検査範囲）が必要です")]
        why = store_placement_reason(scope)
        if why:
            return [], [Rejection("G-9", why)]
    if any(it["action"]["type"] in ("quarantine",) or it["action"]["type"] in REGISTRY and REGISTRY[it["action"]["type"]].ORDER == 0
           for it in fs_items):
        try:
            ctx.store_dev = store.device()
        except (OSError, store.StoreError) as e:
            return [], [Rejection("G-9", f"隔離ストアを用意できません（{e}）")]
    steps = []
    seen_targets: dict[str, str] = {}
    seen_ino: set = set()
    touched: list[tuple[str, str]] = []  # (パス, finding_id)
    root_kinds = set()
    for grp in _groups(items):
        idx, it0 = grp[0]
        a0, fid = it0["action"], it0["finding_id"]
        t = a0["target"]
        try:
            # 同じ group の item は type・target・evidence が一致すること
            for _i, it in grp[1:]:
                a = it["action"]
                if a["type"] != a0["type"] or a["target"] != t:
                    raise ActionError(f"group {a0.get('group')} の item の type / target が一致しません")
            # 同じ finding_path の item どうしは、内容に基づく evidence（file / tree / symlink）が一致すること。
            # finding_path が違う item（findings 1.1 のスキルのディレクトリの tree と skill.contract.json の file、
            # node_modules/<name>/package.json とロックファイル）は別のものの evidence なので比べない。どの item の
            # evidence も、下の check_evidence でそれぞれの finding_path から導き直して照合する（item ごと・全件）。
            # detail（ZES 1.0 のディレクトリ・リンク）は finding ごとの文言のハッシュなので一致しない。その場合は
            # params に固定した preview のハッシュに任せる
            content = {"file", "large_file", "tree", "symlink"}
            by_fp: dict = {}
            for _i, it in grp:
                a = it["action"]
                ev = a.get("evidence", {})
                if a0["type"] == checklist_mod.TYPE or ev.get("kind") not in content:
                    continue
                ev0 = by_fp.setdefault(a.get("finding_path"), ev)
                if ev.get("hash") != ev0.get("hash"):
                    raise ActionError(f"group {a0.get('group')} の item の evidence.hash が一致しません（同じ finding_path）")
            if t is not None:
                if not _target_shape_ok(t):
                    raise ActionError("対象は正規化済みの絶対パスであること（. / .. / 連続した / 不可）")
                if a0["type"] != checklist_mod.TYPE:
                    if t in seen_targets:
                        raise ActionError("同じ対象への操作が計画内で重複しています（同じファイルへの複数の finding は action.group でまとめること）")
                    seen_targets[t] = fid
            mod = REGISTRY[a0["type"]]
            if a0["type"] in FS_CHANGING:
                if scope is not None and not in_scope(t, scope):
                    raise ActionError("G-9: 対象が承認された検査範囲（plan.scope）の外にあります")
                why = protected_reason(t)
                if why:
                    raise ActionError(f"G-9: {why}")
                try:
                    lst = os.lstat(t)
                    if t in ctx.protected_paths or (lst.st_dev, lst.st_ino) in ctx.protected_ino:
                        raise ActionError("監査ログ・そのディレクトリ・その上位ディレクトリは対象にできません（変更後に記録できなくなる）")
                    own_root = lst.st_uid != ctx.euid
                except FileNotFoundError:
                    own_root = False
                if hazards.root_required_lexical(t) or own_root:
                    root_kinds.add(True)
                    if len(approvers) < 2:
                        raise ActionError("G-6: root が必要な対象（所有者が実行ユーザーでない・システムのディレクトリ）には承認者 2 名以上が必要です")
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
                            raise ActionError(f"他の item（{qf[:15]}…）の対象と重なっています（一方が他方の上位）。同じ対象は group でまとめること")
                    touched.append((p, fid))
                ino = getattr(step, "st", None) or getattr(getattr(step, "res", None), "st", None)
                if ino is not None:
                    key = (ino.st_dev, ino.st_ino)
                    if key in seen_ino:
                        raise ActionError("同じ実体（ハードリンク）への操作が計画内で重複しています")
                    seen_ino.add(key)
            steps.append(step)
        except FileNotFoundError:
            rej.append(Rejection("G-7", "対象が存在しません", fid))
        except fsutil.FsError as e:
            rej.append(Rejection("G-7", str(e), fid))
        except (ActionError, OSError, ValueError) as e:  # ValueError: パスに NUL 文字など
            msg = str(e)
            gate = msg[:4] if msg.startswith(("G-6:", "G-9:")) else "G-7"
            if msg.startswith(("T-", "Q-6")) or "（T-" in msg:
                gate = "G-10"
            rej.append(Rejection(gate, msg[5:] if gate in ("G-6", "G-9") and msg[:4] == gate else msg, fid))
    if len(root_kinds) > 1:
        rej.append(Rejection("G-9", "root が必要な対象とそうでない対象が同じ計画にあります。計画を分けてください"))
    steps.sort(key=lambda s: (s.order, s.items[0].index))
    return steps, rej
