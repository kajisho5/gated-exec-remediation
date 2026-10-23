"""GER のテスト。一時ディレクトリの実ファイルに対して chmod を検証する。標準ライブラリの unittest のみ。"""
from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import hashlib
import io
import json
import os
import socket
import stat
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from ger import audit, cli, executor, gates
from ger.actions import chmod
from ger.core import ROOT, canonical, fmt_ts, input_hash, now_utc, plan_hash, validator

FIX = ROOT / "tests" / "fixtures"
PLAN_ID = "11111111-2222-4333-8444-555555555555"
NOW = "2026-10-22T12:00:00Z"
FID = ["sha256:" + hashlib.sha256(str(i).encode()).hexdigest() for i in range(5)]


def setUpModule():
    os.environ["GER_ALLOW_NOW_OVERRIDE"] = "1"  # テストでは --now を使う


def tearDownModule():
    os.environ.pop("GER_ALLOW_NOW_OVERRIDE", None)


def mode_of(p: Path) -> int:
    return os.lstat(p).st_mode & 0o7777


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(os.path.realpath(self.tmp.name))
        os.environ["GER_LOG_DIR"] = str(self.d / "log")
        os.environ.pop("GER_DRYRUN_TTL", None)
        self.targets = []
        for i in range(3):
            t = self.d / f"key{i}"
            t.write_text("x")
            os.chmod(t, 0o644)
            self.targets.append(t)

    def tearDown(self):
        os.environ.pop("GER_LOG_DIR", None)
        self.tmp.cleanup()

    def plan(self, targets=None, **over) -> dict:
        targets = self.targets if targets is None else targets
        items = []
        for i, t in enumerate(targets):
            items.append({
                "finding_id": FID[i], "decision": "remediate", "exception_type": None, "reason": None,
                "owner": "team-a", "decided_by": "alice", "decided_at": "2026-10-22T10:00:00Z",
                "due_at": "2026-10-29T10:00:00Z", "recheck_at": None, "approved_by": [],
                "level_effective": "HIGH",
                "action": {"type": "chmod", "target": str(t), "params": {"mode": "0600"},
                           "reversible": True, "skillpact_effects": []},
            })
        items.append({
            "finding_id": FID[4], "decision": "exception", "exception_type": "risk_accepted", "reason": "x",
            "owner": None, "decided_by": "alice", "decided_at": "2026-10-22T10:00:00Z", "due_at": None,
            "recheck_at": "2026-11-01T10:00:00Z", "approved_by": ["security-lead"], "level_effective": "LOW", "action": None,
        })
        p = {"schema_version": "1.0", "plan_id": PLAN_ID, "created_at": "2026-10-22T10:00:00Z",
             "status": "ok", "items": items, "held": []}
        p.update(over)
        p["plan_hash"] = plan_hash(p)
        return p

    def ger_input(self, plan=None, mode="dry-run", approvers=("security-lead",), allowed=("chmod",)) -> dict:
        plan = plan or self.plan()
        return {"schema_version": "1.0", "plan": plan, "mode": mode, "allowed_actions": list(allowed),
                "approval": {"plan_id": plan["plan_id"], "approved_by": list(approvers),
                             "approved_at": "2026-10-22T11:00:00Z", "approval_token": plan.get("plan_hash", "sha256:" + "0" * 64)}}

    def write_raw(self, text, name="raw.json") -> str:
        p = self.d / name
        p.write_text(text, encoding="utf-8")
        return str(p)

    def write(self, obj, name="in.json") -> str:
        p = self.d / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = cli.main(list(args))
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def ger(self, command, inp, operator="ops", now=NOW):
        args = [command, self.write(inp, f"{command}.json"), "--operator", operator] + (["--now", now] if now else [])
        if command != "verify":
            args += ["-o", str(self.d / f"{command}-log.json")]
        return self.run_cli(*args)

    def dry_then_apply(self, inp, **kw):
        dr = copy.deepcopy(inp); dr["mode"] = "dry-run"
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        c1, e1 = self.ger("dry-run", dr, **kw)
        self.assertEqual(c1, 0, e1)
        return self.ger("apply", ap, **kw)

    def log(self, command):
        return json.loads((self.d / f"{command}-log.json").read_text())


class TestVendorAndCompat(Base):
    def test_vendor_pins(self):
        meta = json.loads((ROOT / "schemas/vendor/VENDOR.json").read_text())
        for f in meta["files"]:
            self.assertEqual(hashlib.sha256((ROOT / f["path"]).read_bytes()).hexdigest(), f["sha256"], f["path"])

    def test_zet_finalized_plan_is_compatible(self):
        plan = json.loads((FIX / "zet-final-plan.json").read_text())
        self.assertEqual(validator("vendor/remediation-plan.schema.json").errors(plan), [])
        self.assertEqual(plan_hash(plan), plan["plan_hash"], "plan_hash の定義が ZET と一致しません")

    def test_zet_r3_finalized_plan_passes_reverified_invariants(self):
        # ZET（round 3 以降）の finalize の実出力: items[].skillpact と action.evidence_hash を持つ。
        # G-1 で再検査する ZET の不変条件に、正しく作られた計画が引っかからないこと
        plan = json.loads((FIX / "zet-final-plan-r3.json").read_text())
        self.assertEqual(validator("vendor/remediation-plan.schema.json").errors(plan), [])
        self.assertEqual(plan_hash(plan), plan["plan_hash"])
        self.assertTrue(any("skillpact" in it for it in plan["items"]))
        self.assertTrue(all("evidence_hash" in it["action"] for it in plan["items"] if it["action"]))
        self.assertEqual(gates._zet_invariants(plan, now_utc(NOW)), [])
        bad = copy.deepcopy(plan)
        it = next(i for i in bad["items"] if i.get("skillpact") and i["skillpact"]["divergence"])
        it.update(decision="exception", exception_type="risk_accepted", reason="x", action=None)
        self.assertIn("I-5", " ".join(r.message for r in gates._zet_invariants(bad, now_utc(NOW))))

    def test_lite_validator_agrees_with_jsonschema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema 未導入（開発依存）")
        inp = self.ger_input()
        bad = copy.deepcopy(inp); bad["allowed_actions"] = ["*"]
        bad2 = copy.deepcopy(inp); bad2["findings"] = {}
        cases = [("ger-input.schema.json", x) for x in (inp, bad, bad2)]
        cases.append(("vendor/remediation-plan.schema.json", json.loads((FIX / "zet-final-plan.json").read_text())))
        r3 = json.loads((FIX / "zet-final-plan-r3.json").read_text())
        cases.append(("vendor/remediation-plan.schema.json", r3))
        bad3 = copy.deepcopy(r3); next(i for i in bad3["items"] if i["action"])["action"]["skillpact_effects"] = ["EXEC"]
        cases.append(("vendor/remediation-plan.schema.json", bad3))
        for name, inst in cases:
            schema = json.loads((ROOT / "schemas" / name).read_text())
            self.assertEqual(validator(name).is_valid(inst), Draft202012Validator(schema).is_valid(inst), name)


class TestGates(Base):
    def assertRejected(self, inp, gate, command="verify", **kw):
        code, err = self.ger(command, inp, **kw)
        self.assertEqual(code, 3, err)
        self.assertIn(gate, err)
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "拒否時に変更されています")

    def test_verify_ok(self):
        self.assertEqual(self.ger("verify", self.ger_input())[0], 0)

    def test_g1_findings_and_schema(self):
        inp = self.ger_input(); inp["findings"] = {"findings": []}
        self.assertRejected(inp, "G-1")
        inp = self.ger_input(); inp["allowed_actions"] = ["*"]
        self.assertRejected(inp, "G-1")
        inp = self.ger_input(mode="apply")
        self.assertRejected(inp, "G-1", command="dry-run")

    def test_g2_draft_rejected(self):
        p = self.plan(); p["status"] = "draft"; del p["plan_hash"]
        inp = self.ger_input(plan=p)
        self.assertRejected(inp, "G-2")  # 下書き（status: draft）は確定 plan ではない
        p = self.plan(status="error")
        self.assertRejected(self.ger_input(plan=p), "G-2")

    def test_g3_approval_binding(self):
        inp = self.ger_input()
        inp["plan"]["items"][0]["action"]["target"] = "/etc/passwd"  # 承認後の差し替え
        self.assertRejected(inp, "G-3")
        inp = self.ger_input(); inp["approval"]["plan_id"] = "99999999-2222-4333-8444-555555555555"
        self.assertRejected(inp, "G-3")
        inp = self.ger_input(); inp["approval"]["approved_at"] = "2027-01-01T00:00:00Z"
        self.assertRejected(inp, "G-3")

    def test_g4_self_approval(self):
        self.assertRejected(self.ger_input(approvers=("ops",)), "G-4", operator="ops")

    def test_names_compared_case_insensitively(self):
        self.assertRejected(self.ger_input(approvers=("ops",)), "G-4", operator="OPS")
        self.assertRejected(self.ger_input(approvers=("Ops",)), "G-4", operator="ops")
        p = self.plan()
        p["items"][0]["action"]["reversible"] = False
        p["plan_hash"] = plan_hash(p)
        code, err = self.ger("verify", self.ger_input(plan=p, approvers=("alice", "ALICE")))
        self.assertEqual(code, 3, err)
        self.assertIn("承認者 2 名以上", err)

    def test_g5_allowlist_and_unsupported(self):
        self.assertRejected(self.ger_input(allowed=()), "G-5")
        p = self.plan()
        p["items"][0]["action"].update(type="rotate_secret", reversible=False)
        p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p, allowed=("chmod", "rotate_secret"), approvers=("a", "b")), "G-5")

    def test_g6_reversible_and_derived_fields(self):
        p = self.plan(); p["items"][0]["action"]["reversible"] = False; p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p), "G-6")
        p = self.plan(); del p["items"][0]["action"]["skillpact_effects"]; p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p), "G-6")

    def test_g6_risky_effects_need_explicit_action(self):
        # SkillPact 0.8: exec / network / spend / send を宣言したスキルへの操作は allowed_actions に明示が必要
        for eff, risky in (("exec", True), ("network", True), ("spend", True), ("send", True), ("read", False), ("write", False)):
            p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = [eff]
            p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]  # ZET I-6: 危険な効果の remediate は 2 名
            p["plan_hash"] = plan_hash(p)
            code, err = self.ger("verify", self.ger_input(plan=p, allowed=(), approvers=("security-lead", "platform-owner")))
            self.assertEqual(code, 3, err)
            self.assertEqual(f"{eff} を宣言したスキルへの操作" in err, risky, eff)
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["read", "write", "network", "exec", "spend", "send"]
        p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]
        p["plan_hash"] = plan_hash(p)
        self.assertEqual(self.ger("verify", self.ger_input(plan=p, approvers=("a", "b")))[0], 0)

    def test_g7_targets(self):
        link = self.d / "link"; link.symlink_to(self.targets[0])
        self.assertRejected(self.ger_input(plan=self.plan([link])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "missing"])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([Path(str(self.d) + "/sub/../key0")])), "I-4")  # G-1（ZET I-4 相当）
        self.assertRejected(self.ger_input(plan=self.plan([self.targets[0], self.targets[0]])), "G-7")
        sub = self.d / "realdir"; sub.mkdir(); (sub / "f").write_text("x")
        (self.d / "dirlink").symlink_to(sub)
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "dirlink" / "f"])), "G-7")
        p = self.plan(); p["items"][0]["action"]["params"] = {"mode": "4755"}; p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p), "G-7")
        fifo = self.d / "fifo"; os.mkfifo(fifo)
        self.assertRejected(self.ger_input(plan=self.plan([fifo])), "G-7")

    def test_g7_audit_log_and_its_directories_rejected(self):
        # 監査ログ・そのディレクトリ・その上位ディレクトリを chmod すると、apply 後に記録できなくなる
        self.assertEqual(self.ger("dry-run", self.ger_input())[0], 0)
        hl = self.d / "audit-hardlink"; os.link(audit.log_path(), hl)
        for t in (audit.log_path(), hl, audit.log_dir(), self.d):
            code, err = self.ger("verify", self.ger_input(plan=self.plan([t])))
            self.assertEqual(code, 3, (t, err))
            self.assertIn("G-7", err); self.assertIn("監査ログ", err)
        self.assertEqual(stat.S_IMODE(os.stat(audit.log_dir()).st_mode), 0o700)

    def test_g1_duplicate_finding_id(self):
        p = self.plan(); p["items"][1]["finding_id"] = FID[0]; p["plan_hash"] = plan_hash(p)
        code, err = self.ger("verify", self.ger_input(plan=p))
        self.assertEqual(code, 3, err)
        self.assertIn("G-1", err); self.assertIn("finding_id が重複", err)

    def test_g1_duplicate_finding_id_check_is_linear(self):
        # 重複検査が O(n^2)（list.count）だと 20000 件で数秒かかる。スキーマ検証を外し、G-2 で止めて重複検査だけを測る
        item = self.plan()["items"][0]
        items = [dict(item, finding_id="sha256:%064x" % i) for i in range(20000)]
        items.append(dict(item, finding_id="sha256:%064x" % 7))
        p = {"plan_id": PLAN_ID, "status": "draft", "items": items}
        inp = {"plan": p, "mode": "dry-run", "approval": {"approved_at": NOW}}
        p["created_at"] = NOW
        with mock.patch.object(gates, "_schema", return_value=[]):
            t0 = time.monotonic()
            rej, _ = gates.check_gates(inp, "ops", now_utc(NOW), "verify", 86400)
            elapsed = time.monotonic() - t0
        self.assertEqual([(r.gate, r.finding_id) for r in rej], [("G-1", "sha256:%064x" % 7)])
        self.assertLess(elapsed, 2.5)  # 修正前は約 5 秒。CI の遅いランナーでも誤検知しない上限

    def test_g1_invalid_calendar_timestamps(self):
        inp = self.ger_input(); inp["approval"]["approved_at"] = "2026-02-30T11:00:00Z"
        self.assertRejected(inp, "G-1")
        p = self.plan(created_at="2026-10-22T25:00:00Z")
        code, err = self.ger("verify", self.ger_input(plan=p))
        self.assertEqual(code, 3, err)
        self.assertIn("plan.created_at が実在しない日時です", err)

    def test_g8_unparseable_dry_run_record_is_ignored(self):
        inp = self.ger_input(mode="apply")
        audit.append({"command": "dry-run", "result": "ok", "plan_hash": inp["plan"]["plan_hash"],
                      "input_hash": input_hash(inp), "finished_at": "2026-02-30T00:00:00Z"})
        self.assertRejected(inp, "G-8", command="apply")

    def test_g7_nul_byte_in_target(self):
        self.assertRejected(self.ger_input(plan=self.plan([str(self.targets[0]) + "\x00x"])), "G-7")

    def test_g7_hardlink_alias_rejected(self):
        hl = self.d / "hardlink"; os.link(self.targets[0], hl)
        code, err = self.ger("verify", self.ger_input(plan=self.plan([self.targets[0], hl])))
        self.assertEqual(code, 3, err)
        self.assertIn("G-7", err); self.assertIn("ハードリンク", err)

    def test_trailing_newline_rejected_by_patterns(self):
        # Python の $ は末尾の改行の直前にも一致する。"ops\n" で G-4（自己承認防止）を回避できないこと
        self.assertRejected(self.ger_input(approvers=("ops\n",)), "G-1", operator="ops")
        self.assertRejected(self.ger_input(approvers=("ops\n",)), "G-1", command="dry-run", operator="ops")
        inp = self.ger_input(); inp["approval"]["plan_id"] += "\n"
        self.assertFalse(validator("ger-input.schema.json").is_valid(inp))
        self.assertEqual(self.ger("verify", self.ger_input(), operator="ops\n")[0], 64)
        with self.assertRaises(chmod.ActionError):
            chmod.parse_params({"mode": "0600\n"})

    def test_g1_lone_surrogate_and_non_finite(self):
        inp = json.dumps(self.ger_input())
        for bad, why in ((inp.replace('"security-lead"', '"\\udc80"'), "サロゲート"), (inp[:-1] + ', "x": 1e400}', "有限でない")):
            code, err = self.run_cli("verify", self.write_raw(bad), "--operator", "ops", "--now", NOW)
            self.assertEqual(code, 3, err)
            self.assertIn("G-1", err); self.assertIn(why, err)
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([(r["result"], r["gate_failed"]) for r in recs], [("rejected", ["G-1"])] * 2)
        with self.assertRaises(ValueError):
            canonical({"x": float("nan")})

    def test_g1_duplicate_keys_rejected(self):
        inp = json.dumps(self.ger_input())
        dup = inp.replace('"approved_by": ["security-lead"]', '"approved_by": ["ops"], "approved_by": ["security-lead"]')
        self.assertNotEqual(dup, inp)
        code, err = self.run_cli("verify", self.write_raw(dup), "--operator", "ops", "--now", NOW)
        self.assertEqual(code, 3, err)
        self.assertIn("G-1", err); self.assertIn("重複", err)

    def test_g1_deep_nesting_rejected(self):
        inp = json.dumps(self.ger_input())
        for depth in (100, 200000):  # 200000 は json.loads 自体が RecursionError になる深さ
            deep = inp[:-1] + ', "x": ' + "[" * depth + "]" * depth + "}"
            code, err = self.run_cli("verify", self.write_raw(deep), "--operator", "ops", "--now", NOW)
            self.assertEqual(code, 3, err)
            self.assertIn("G-1", err); self.assertIn("入れ子が深すぎます", err)

    def test_g8_apply_requires_dry_run(self):
        self.assertRejected(self.ger_input(mode="apply"), "G-8", command="apply")

    def test_g8_dry_run_expires(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.assertRejected(ap, "G-8", command="apply", now="2026-10-23T12:00:01Z")

    def test_g8_dry_run_must_match_input(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = self.ger_input(mode="apply", approvers=("security-lead", "platform-owner"))
        self.assertRejected(ap, "G-8", command="apply")

    def test_g8_broken_chain(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        self.assertEqual(self.ger("verify", inp)[0], 0)
        self.assertEqual(self.ger("verify", inp)[0], 0)  # 末尾の連結は健全なまま、途中だけを壊す
        lines = audit.log_path().read_text().splitlines()
        lines[0] = lines[0].replace('"operator":"ops"', '"operator":"evil"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.assertRejected(ap, "G-8", command="apply")

    def test_g8_now_override_dry_run_does_not_unlock_real_apply(self):
        # --now 付きの dry-run は記録に now_override: true を残し、--now なしの apply の根拠にならない
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp, now=fmt_ts(now_utc()))[0], 0)
        rec = json.loads(audit.log_path().read_text().splitlines()[-1])
        self.assertIs(rec["now_override"], True)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.assertRejected(ap, "G-8", command="apply", now=None)
        self.assertNotIn("now_override", json.loads(audit.log_path().read_text().splitlines()[-1]))
        self.assertEqual(self.ger("verify", inp, now=None)[0], 0)
        self.assertNotIn("now_override", json.loads(audit.log_path().read_text().splitlines()[-1]))

    def test_g8_garbage_audit_log_is_rejected_not_crash(self):
        # 多バイト文字の途中で切れた最終行・object でない JSON 行・任意のバイト列: 途中にあれば G-8 の拒否（70 ではない）、
        # 末尾にあれば壊れたチェーンには追記しないため何もせず 64（R3 F15）
        inp = self.ger_input()
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        for garbage in ('{"operator":"あ'.encode()[:-1], b"null", b"[1,2]", b'"x"', bytes(range(256))):
            audit.log_path().unlink(missing_ok=True)
            self.assertEqual(self.ger("dry-run", inp)[0], 0)
            with open(audit.log_path(), "ab") as f:
                f.write(garbage + b"\n")
            self.assertTrue(audit.verify_chain(), garbage)
            self.assertIsNotNone(audit.find_dry_run(inp["plan"]["plan_hash"], input_hash(inp), now_utc(NOW), 86400, True))
            before = audit.log_path().read_bytes()
            code, err = self.ger("apply", ap)
            self.assertEqual(code, 64, err); self.assertIn("verify-log", err)
            self.assertEqual(audit.log_path().read_bytes(), before)
            # 途中にある場合（末尾は健全な記録）は G-8
            last = [x for x in before.split(b"\n") if x.strip()][-1]
            audit.log_path().write_bytes(before + json.dumps({"prev_hash": audit._line_hash(last)}).encode() + b"\n")
            self.assertRejected(ap, "G-8", command="apply")
            self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets))


class TestExecution(Base):
    def test_dry_run_changes_nothing(self):
        code, err = self.ger("dry-run", self.ger_input())
        self.assertEqual(code, 0, err)
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets))
        log = self.log("dry-run")
        self.assertEqual(log["mode"], "dry-run")
        self.assertEqual({r["reason"] for r in log["results"] if r["action_type"]}, {"dry_run:would_apply"})
        self.assertEqual(validator("remediation-log.schema.json").errors(log), [])

    def test_apply_and_idempotent(self):
        code, err = self.dry_then_apply(self.ger_input())
        self.assertEqual(code, 0, err)
        self.assertTrue(all(mode_of(t) == 0o600 for t in self.targets))
        log = self.log("apply")
        self.assertEqual(log["status"], "ok")
        res = {r["finding_id"]: r for r in log["results"]}
        self.assertEqual(res[FID[0]]["before"], "0644"); self.assertEqual(res[FID[0]]["after"], "0600")
        self.assertEqual(res[FID[4]]["reason"], "decision:exception")
        # 2 回目は already_compliant
        code, err = self.dry_then_apply(self.ger_input())
        self.assertEqual(code, 0, err)
        self.assertEqual({r["reason"] for r in self.log("apply")["results"] if r["action_type"]}, {"already_compliant"})

    def test_unreadable_target(self):
        os.chmod(self.targets[0], 0o300)  # 所有者が読めない（権限を絞る chmod 0200 だけが通る）
        if os.access(self.targets[0], os.R_OK):
            self.skipTest("root では読み取り不可のファイルを作れない")
        p = self.plan(); p["items"][0]["action"]["params"]["mode"] = "0200"; p["plan_hash"] = plan_hash(p)
        code, err = self.dry_then_apply(self.ger_input(plan=p))
        self.assertEqual(code, 0, err)
        self.assertEqual(mode_of(self.targets[0]), 0o200)

    def test_failure_rolls_back_everything(self):
        real = chmod.set_mode
        calls = {"n": 0}

        def flaky(target, mode, ident):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("injected failure")
            return real(target, mode, ident)
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        with mock.patch.object(chmod, "set_mode", flaky):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 4, err)
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "ロールバックされていません")
        results = {r["finding_id"]: r["result"] for r in self.log("apply")["results"]}
        self.assertEqual([results[f] for f in FID[:3]], ["rolled_back", "rolled_back", "failed"])
        self.assertEqual(self.log("apply")["status"], "error")

    def test_rollback_tracks_items_by_position_not_finding_id(self):
        # 同じ finding_id の item があっても、ロールバック結果を別の item に書き込まないこと
        rej, prepared = gates.check_gates(self.ger_input(mode="apply"), "ops", now_utc(NOW), "verify", 86400)
        self.assertEqual(rej, [])
        prepared = [dataclasses.replace(p, finding_id=FID[0] if i != 1 else FID[1]) for i, p in enumerate(prepared)]
        real, calls = chmod.set_mode, {"n": 0}

        def flaky(target, mode, ident):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("injected failure")
            return real(target, mode, ident)
        with mock.patch.object(chmod, "set_mode", flaky):
            results, outcome = executor.apply(self.plan(), prepared)
        self.assertEqual(outcome, executor.ROLLED_BACK)
        self.assertEqual([(r["result"], r["reason"]) for r in results[:3]],
                         [("rolled_back", "rolled_back_after_failure"), ("failed", "OSError: injected failure"),
                          ("skipped", "aborted_after_failure")])
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets))

    def test_swapped_target_detected(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        real_inspect = chmod.inspect

        def swap_after_inspect(target):
            st = real_inspect(target)
            if target.endswith("key1"):  # 事前検証の直後に差し替える
                os.unlink(target); Path(target).write_text("evil"); os.chmod(target, 0o644)
            return st
        with mock.patch.object(chmod, "inspect", swap_after_inspect):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 4, err)
        self.assertEqual(mode_of(self.targets[0]), 0o644)
        self.assertEqual(mode_of(self.targets[1]), 0o644)

    def test_unverifiable_after_apply_is_rollback_failed(self):
        # fchmod の後に対象が差し替えられた（事後確認に失敗）場合、その item は戻せないため rollback_failed
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        real_fchmod, calls = os.fchmod, {"n": 0}

        def fchmod_then_swap(fd, mode):
            real_fchmod(fd, mode)
            calls["n"] += 1
            if calls["n"] == 2:  # key1 の適用直後に差し替える
                os.rename(self.targets[1], self.d / "moved"); self.targets[1].write_text("evil"); os.chmod(self.targets[1], 0o644)
        with mock.patch.object(chmod.os, "fchmod", fchmod_then_swap):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 5, err)
        res = {r["finding_id"]: r for r in self.log("apply")["results"]}
        self.assertEqual(res[FID[0]]["result"], "rolled_back")
        self.assertEqual(mode_of(self.targets[0]), 0o644)
        self.assertEqual(res[FID[1]]["result"], "failed")
        self.assertIn("applied_unverified", res[FID[1]]["reason"])
        self.assertEqual(mode_of(self.d / "moved"), 0o600)  # 実際に変更が残っている

    def test_output_path_validated_before_changes(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        n = len(audit.log_path().read_text().splitlines())
        for out in ("/nonexistent/dir/x.json", str(self.d)):
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", out)
            self.assertEqual(code, 64, err)
            self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "出力先が不正なのに変更されています")
        self.assertEqual(len(audit.log_path().read_text().splitlines()), n)

    def test_output_empty_or_trailing_slash_rejected_before_changes(self):
        # abspath は "" を cwd に、末尾の / を落として解釈するため、書けない出力先が事前確認を通っていた
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        existing = self.d / "existing.json"; existing.write_text("old")
        n = len(audit.log_path().read_text().splitlines())
        for out in ("", str(self.d / "nd") + "/", str(existing) + "/", str(existing) + "/x", str(self.d / "nd" / "..")):
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", out)
            self.assertEqual(code, 64, (out, err))
            self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), f"出力先が不正なのに変更されています: {out!r}")
        self.assertEqual(len(audit.log_path().read_text().splitlines()), n)
        self.assertEqual(existing.read_text(), "old")
        self.assertFalse((self.d / "nd").exists())

    def test_output_must_be_regular_file_not_symlink(self):
        # FIFO・ソケット・デバイスやシンボリックリンクを通常ファイルで置き換えない（root で -o /dev/null を壊さない）
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        fifo = self.d / "out.fifo"; os.mkfifo(fifo)
        sock = self.d / "out.sock"
        s = socket.socket(socket.AF_UNIX); s.bind(str(sock)); self.addCleanup(s.close)
        real = self.d / "real.json"; real.write_text("old")
        link = self.d / "out-link.json"; link.symlink_to(real)
        dangling = self.d / "dangling.json"; dangling.symlink_to(self.d / "nowhere.json")
        n = len(audit.log_path().read_text().splitlines())
        for command, src in (("dry-run", inp), ("apply", ap)):
            for out in (fifo, sock, link, dangling):
                code, err = self.run_cli(command, self.write(src), "--operator", "ops", "--now", NOW, "-o", str(out))
                self.assertEqual(code, 64, (command, out, err))
        self.assertTrue(stat.S_ISFIFO(os.lstat(fifo).st_mode)); self.assertTrue(stat.S_ISSOCK(os.lstat(sock).st_mode))
        self.assertTrue(link.is_symlink() and dangling.is_symlink())
        self.assertEqual(real.read_text(), "old"); self.assertFalse((self.d / "nowhere.json").exists())
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets))
        self.assertEqual(len(audit.log_path().read_text().splitlines()), n)

    def test_output_must_not_be_audit_log_or_input(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        before = audit.log_path().read_bytes()
        src = self.write(inp, "dr.json"); src_bytes = Path(src).read_bytes()
        hl = self.d / "input-hardlink"; os.link(src, hl)
        for out in (str(audit.log_path()), str(audit.log_dir() / "other.json"), src, str(hl)):
            code, err = self.run_cli("dry-run", src, "--operator", "ops", "--now", NOW, "-o", out)
            self.assertEqual(code, 64, (out, err))
        self.assertEqual(audit.log_path().read_bytes(), before, "監査ログが置き換えられています")
        self.assertEqual(Path(src).read_bytes(), src_bytes, "入力が上書きされています")
        self.assertFalse((audit.log_dir() / "other.json").exists())

    def test_output_must_not_be_plan_target(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        hl = self.d / "target-hardlink"; os.link(self.targets[1], hl)
        for command in ("dry-run", "apply"):
            src = copy.deepcopy(inp); src["mode"] = command
            for out in (str(self.targets[1]), str(hl)):
                code, err = self.run_cli(command, self.write(src), "--operator", "ops", "--now", NOW, "-o", out)
                self.assertEqual(code, 64, (command, out, err))
                self.assertIn("計画の対象", err)
        self.assertTrue(all(mode_of(t) == 0o644 and t.read_text() == "x" for t in self.targets), "対象が変更されています")
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([r["result"] for r in recs[1:]], ["error"] * 4)
        self.assertTrue(all("計画の対象" in r["error"] for r in recs[1:]))
        self.assertEqual(audit.verify_chain(), [])

    def test_output_parent_directories_must_not_be_plan_targets(self):
        # -o の親ディレクトリやその上位を chmod すると、apply 後に remediation-log を書けなくなる
        out = self.d / "out"; sub = out / "sub"; sub.mkdir(parents=True)
        os.chmod(out, 0o755); os.chmod(sub, 0o755)
        for t in (sub, out):
            inp = self.ger_input(plan=self.plan([t]))
            self.assertEqual(self.ger("dry-run", inp)[0], 0)
            ap = copy.deepcopy(inp); ap["mode"] = "apply"
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(sub / "x.json"))
            self.assertEqual(code, 64, (t, err))
            self.assertIn("-o の出力先ディレクトリ", err)
            self.assertEqual(stat.S_IMODE(os.stat(t).st_mode), 0o755, "対象が変更されています")
        self.assertFalse((sub / "x.json").exists())

    def test_output_write_failure_after_apply_is_not_rollback_failed(self):
        # 変更をすべて適用した後に remediation-log を書けなかった場合、ロールバックはしていないので
        # rollback_failed と記録しない。以前の実行の remediation-log を今回のものと取り違えないよう消す
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        stale = self.d / "apply-log.json"; stale.write_text('{"stale": true}')
        with mock.patch.object(cli, "write_atomic", side_effect=OSError("disk full")):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 5, err)
        self.assertTrue(all(mode_of(t) == 0o600 for t in self.targets))
        rec = json.loads(audit.log_path().read_text().splitlines()[-1])
        self.assertEqual(rec["result"], "applied_unlogged")
        self.assertNotIn("output_hash", rec)
        self.assertFalse(stale.exists(), "以前の remediation-log が残っています")

    def test_output_write_failure(self):
        inp = self.ger_input()
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        with mock.patch.object(cli, "write_atomic", side_effect=OSError("disk full")):
            code, err = self.ger("dry-run", inp)
            self.assertNotEqual(code, 0, err)
            code, err = self.ger("apply", ap)
            self.assertEqual(code, 3, err); self.assertIn("G-8", err)  # 書けなかった dry-run では apply できない
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        with mock.patch.object(cli, "write_atomic", side_effect=OSError("disk full")):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 5, err)
        self.assertIn("手動で対応", err)
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([r["result"] for r in recs], ["error", "rejected", "ok", "applied_unlogged"])
        self.assertNotIn("output_hash", recs[0]); self.assertNotIn("output_hash", recs[-1])

    def test_now_override_requires_env(self):
        with mock.patch.dict(os.environ):
            del os.environ["GER_ALLOW_NOW_OVERRIDE"]
            for command in ("verify", "dry-run", "apply"):
                code, err = self.ger(command, self.ger_input(mode="dry-run" if command == "verify" else command))
                self.assertEqual(code, 64, err)
                self.assertIn("テスト専用", err)
            self.assertEqual(self.ger("verify", self.ger_input(), now=None)[0], 0)
        self.assertFalse(audit.log_path().exists() and "dry-run" in audit.log_path().read_text())

    def test_audit_torn_last_line_and_symlink(self):
        audit.ensure_writable()
        audit.log_path().write_bytes(b'{"skill":"ger","comm')  # クラッシュで途中まで書かれた最終行
        with self.assertRaises(audit.BrokenChain):  # R3 F15: 壊れたチェーンの後ろには追記しない
            audit.append({"command": "verify", "result": "ok"})
        self.assertEqual(audit.log_path().read_bytes(), b'{"skill":"ger","comm')
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)
        other = self.d / "elsewhere"; other.write_text("")
        audit.log_path().unlink(); audit.log_path().symlink_to(other)
        for check in (audit.ensure_writable, lambda: None):  # 事前確認と O_NOFOLLOW の両方で拒否する
            with mock.patch.object(audit, "ensure_writable", check), self.assertRaises(OSError):
                audit.append({"command": "verify", "result": "ok"})
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)
        self.assertEqual(other.read_text(), "")

    def test_audit_dir_must_be_private_and_owned(self):
        d = audit.log_dir(); d.mkdir()
        for m in (0o777, 0o730, 0o702):
            os.chmod(d, m)
            code, err = self.ger("verify", self.ger_input())
            self.assertEqual(code, 64, err); self.assertIn("書き込み可能", err)
        os.chmod(d, 0o700)
        with mock.patch.object(audit.os, "geteuid", return_value=os.geteuid() + 1):
            code, err = self.ger("verify", self.ger_input())
        self.assertEqual(code, 64, err); self.assertIn("所有者", err)
        self.assertFalse(audit.log_path().exists())
        self.assertEqual(self.ger("verify", self.ger_input())[0], 0)

    def test_audit_records_every_command(self):
        self.dry_then_apply(self.ger_input())
        self.ger("verify", self.ger_input(allowed=()))
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([(r["command"], r["result"]) for r in recs], [("dry-run", "ok"), ("apply", "ok"), ("verify", "rejected")])
        self.assertEqual(recs[-1]["gate_failed"], ["G-5"])
        self.assertEqual(audit.verify_chain(), [])
        self.assertTrue(all(stat.S_IMODE(os.stat(audit.log_path()).st_mode) == 0o600 for _ in [0]))

    def test_usage(self):
        self.assertEqual(self.run_cli("verify", self.write(self.ger_input()))[0], 64)
        os.environ["GER_DRYRUN_TTL"] = "-1"
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)
        os.environ.pop("GER_DRYRUN_TTL")
        os.environ["GER_LOG_DIR"] = "/proc/ger-cannot-write"
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)


class TestRegressionsR3Fixes(Base):
    """round 3 の指摘（F1 / F2 / F3 / F5 / F6 / F7 / F8 / F10 / F14 / F15）の回帰テスト。"""

    def reject_msg(self, inp, gate, text, command="verify", **kw):
        code, err = self.ger(command, inp, **kw)
        self.assertEqual(code, 3, err)
        self.assertIn(gate, err)
        self.assertIn(text, err)
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "拒否時に変更されています")
        return err

    def rehash(self, p):
        p["plan_hash"] = plan_hash(p)
        return p

    # F1: plan を書き換えて plan_hash と approval_token を計算し直しても、plan だけで評価できる ZET の不変条件で止める
    def test_f1_tampered_and_rehashed_plan_rechecked(self):
        sp = {"signed": True, "divergence": ["network"], "diff_anomaly": False, "declared_effects": ["exec"]}
        cases = []
        p = self.plan(); p["items"][3].update(skillpact=dict(sp), level_effective="CRITICAL"); cases.append((p, "I-5", "exception にできません"))
        p = self.plan(); p["items"][0]["skillpact"] = dict(sp, divergence=[]); p["items"][0]["approved_by"] = ["a", "b"]
        p["items"][0]["action"]["skillpact_effects"] = []; cases.append((p, "I-4", "declared_effects と一致しません"))
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, divergence=[], declared_effects=[], diff_anomaly=True))
        cases.append((p, "I-6", "diff_anomaly"))
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, declared_effects=[]), level_effective="HIGH")
        cases.append((p, "I-7", "CRITICAL"))
        p = self.plan(); p["items"][3]["approved_by"] = ["alice"]; cases.append((p, "I-3", "自己承認"))
        p = self.plan(); p["items"][3]["approved_by"] = []; cases.append((p, "I-3", "1 名以上"))
        p = self.plan(); p["items"][3]["reason"] = " "; cases.append((p, "I-3", "reason"))
        p = self.plan(); p["items"][1]["decision"] = "defer"; cases.append((p, "I-4", "remediate 以外で action"))
        p = self.plan(); p["items"][0]["owner"] = None; cases.append((p, "I-4", "owner"))
        p = self.plan(); p["items"][0]["action"]["target"] = "/" + str(self.targets[0]); cases.append((p, "I-4", "正規化"))
        p = self.plan(); p["held"] = [{"finding_id": FID[0], "reason": "x"}]; cases.append((p, "I-1", "重複"))
        p = self.plan(status="partial"); cases.append((p, "I-12", "held"))
        p = self.plan(); p["items"][0]["decided_at"] = "2026-10-22T12:00:01Z"; cases.append((p, "I-9", "現在時刻より後"))
        p = self.plan(); p["items"][0]["due_at"] = "2026-10-22T09:00:00Z"; cases.append((p, "I-9", "decided_at より前"))
        p = self.plan(); p["items"][0]["decided_at"] = "2026-10-22T09:00:00Z"; cases.append((p, "I-9", "created_at より前"))
        p = self.plan(); p["items"][0]["approved_by"] = ["Lead", "lead"]; cases.append((p, "I-6", "重複"))
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["exec"]; cases.append((p, "I-6", "exec"))
        for p, code, text in cases:
            err = self.reject_msg(self.ger_input(plan=self.rehash(p), approvers=("lead1", "lead2")), "G-1", text)
            self.assertIn(f"ZET {code} 相当", err)
        # skillpact の要約が整合していれば通る（ZET が finalize で付けた形）
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, declared_effects=[]), level_effective="CRITICAL")
        self.assertEqual(self.ger("verify", self.ger_input(plan=self.rehash(p)))[0], 0)

    # F7: chmod は権限を絞るだけ（現在の mode に無いビットを足さない）。world-writable も拒否
    def test_f7_chmod_only_tightens(self):
        for before, mode, ok in ((0o644, "0600", True), (0o644, "0644", True), (0o644, "0000", True), (0o600, "0640", False),
                                 (0o640, "0604", False), (0o600, "0700", False), (0o666, "0666", False), (0o777, "0757", False)):
            os.chmod(self.targets[0], before)
            p = self.plan(); p["items"][0]["action"]["params"]["mode"] = mode
            code, err = self.ger("verify", self.ger_input(plan=self.rehash(p)))
            self.assertEqual(code == 0, ok, (oct(before), mode, err))
            if not ok:
                self.assertIn("G-7", err)
                self.assertTrue("権限" in err or "world-writable" in err, err)
            self.assertEqual(mode_of(self.targets[0]), before)
        os.chmod(self.targets[0], 0o644)

    # F2: GER_LOG_DIR をシンボリックリンク経由で指定しても、リンクを置いたディレクトリ（字句上の上位）を対象にできない
    def test_f2_log_dir_symlink_ancestors_protected(self):
        a, b = self.d / "A", self.d / "B" / "ger"
        a.mkdir(); b.mkdir(parents=True); os.chmod(b, 0o700); os.chmod(a, 0o755)
        (a / "logdir").symlink_to(b)
        os.environ["GER_LOG_DIR"] = str(a / "logdir")
        err = self.reject_msg(self.ger_input(plan=self.plan([a])), "G-7", "監査ログ")
        self.assertIn("G-7", err)
        self.assertEqual(stat.S_IMODE(os.stat(a).st_mode), 0o755)
        # 起動時に解決した実パスへ書く（リンクを後から差し替えられても別の場所に書かない）
        self.assertEqual(audit.log_dir(), Path(os.path.realpath(b)))
        self.assertTrue((b / "ger-audit.jsonl").exists())

    # F3: -o の親がシンボリックリンク経由でも、リンクを置いたディレクトリを計画の対象にできない
    def test_f3_output_parent_symlink_ancestors_protected(self):
        a, out = self.d / "A", self.d / "B" / "out"
        a.mkdir(); out.mkdir(parents=True); os.chmod(a, 0o755)
        (a / "outdir").symlink_to(out)
        inp = self.ger_input(plan=self.plan([a]))
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(a / "outdir" / "x.json"))
        self.assertEqual(code, 64, err)
        self.assertIn("-o の出力先ディレクトリ", err)
        self.assertEqual(stat.S_IMODE(os.stat(a).st_mode), 0o755)

    # F5: dry-run 記録は 1 回の apply で使い切る（拒否・変更前の引数エラーでは使わない）
    def test_f5_dry_run_record_consumed_by_apply(self):
        inp = self.ger_input()
        code, err = self.dry_then_apply(inp)
        self.assertEqual(code, 0, err)
        for t in self.targets:
            os.chmod(t, 0o644)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.reject_msg(ap, "G-8", "dry-run", command="apply")
        self.assertEqual(self.dry_then_apply(inp)[0], 0)  # 新しい dry-run なら再び実行できる
        for t in self.targets:
            os.chmod(t, 0o644)
        # 引数エラー（変更前に止まった apply）は dry-run を使用済みにしない
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(self.targets[0]))
        self.assertEqual(code, 64, err)
        self.assertEqual(self.ger("apply", ap)[0], 0)

    # F5: 承認の有効期限（既定 7 日、GER_APPROVAL_MAX_AGE）と、remediate の due_at の最大値を過ぎた計画
    def test_f5_approval_max_age_and_plan_due(self):
        inp = self.ger_input()
        p = self.plan(); [it.update(due_at="2026-12-31T00:00:00Z") for it in p["items"] if it["decision"] == "remediate"]
        inp2 = self.ger_input(plan=self.rehash(p))
        self.assertEqual(self.ger("verify", inp2, now="2026-10-29T11:00:00Z")[0], 0)  # ちょうど 7 日
        self.reject_msg(inp2, "G-3", "GER_APPROVAL_MAX_AGE", now="2026-10-29T11:00:01Z")
        os.environ["GER_APPROVAL_MAX_AGE"] = str(30 * 86400)
        try:
            self.assertEqual(self.ger("verify", inp2, now="2026-11-20T00:00:00Z")[0], 0)
            for bad in ("0", "-1", "1e3", "x", "٣"):
                os.environ["GER_APPROVAL_MAX_AGE"] = bad
                self.assertEqual(self.ger("verify", inp2)[0], 64, bad)
        finally:
            os.environ.pop("GER_APPROVAL_MAX_AGE", None)
        # due_at の最大値（2026-10-29T10:00:00Z）を過ぎたら、承認が新しくても実行しない
        self.reject_msg(inp, "G-2", "期限切れ", now="2026-10-29T10:00:01Z")

    # F5: ZET が --now で作った計画（now_override: true）は GER_ALLOW_NOW_OVERRIDE=1 のときだけ
    def test_f5_now_override_plan_refused_by_default(self):
        now = now_utc()
        ts = lambda d: fmt_ts(now + dt.timedelta(seconds=d))  # noqa: E731
        p = self.plan(created_at=ts(-3600))
        for it in p["items"]:
            it["decided_at"] = ts(-3600)
            if it["due_at"]:
                it["due_at"] = ts(86400)
            if it["recheck_at"]:
                it["recheck_at"] = ts(86400)
        p["now_override"] = True
        inp = self.ger_input(plan=self.rehash(p)); inp["approval"]["approved_at"] = ts(-60)
        self.assertEqual(self.ger("verify", inp, now=None)[0], 0)  # テスト環境では GER_ALLOW_NOW_OVERRIDE=1
        os.environ.pop("GER_ALLOW_NOW_OVERRIDE")
        try:
            self.reject_msg(inp, "G-2", "now_override", now=None)
        finally:
            os.environ["GER_ALLOW_NOW_OVERRIDE"] = "1"
        # ZET の旧版の確定 plan（now_override なし）はそのまま受理する（後方互換）
        self.assertEqual(self.ger("verify", self.ger_input(), now=NOW)[0], 0)

    # F6: --now 付きの apply は --now 付きの dry-run 記録だけを数える（実時刻の古い記録を --now で期限内に見せない）
    def test_f6_now_override_apply_counts_only_override_dry_runs(self):
        now = now_utc()
        ts = lambda d: fmt_ts(now + dt.timedelta(seconds=d))  # noqa: E731
        p = self.plan(created_at=ts(-7200))
        for it in p["items"]:
            it["decided_at"] = ts(-7200)
            it["due_at"] = it["due_at"] and ts(86400)
            it["recheck_at"] = it["recheck_at"] and ts(86400)
        inp = self.ger_input(plan=self.rehash(p)); inp["approval"]["approved_at"] = ts(-3600)
        self.assertEqual(self.ger("dry-run", inp, now=None)[0], 0)  # 実時刻の dry-run
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        dry_at = json.loads(audit.log_path().read_text().splitlines()[-1])["finished_at"]
        self.reject_msg(ap, "G-8", "dry-run", command="apply", now=dry_at)
        self.assertEqual(self.ger("dry-run", inp, now=dry_at)[0], 0)  # --now 付きの dry-run なら --now 付きの apply に使える
        self.assertEqual(self.ger("apply", ap, now=dry_at)[0], 0)

    # F8: 入力由来の文字列（キー名・対象パス）の制御文字をエスケープして表示する
    def test_f8_control_characters_escaped(self):
        bad = self.ger_input(); bad["x\x1b]0;PWNED\x07\x1b[2J\x9b"] = 1
        code, err = self.ger("verify", bad)
        self.assertEqual(code, 3)
        for c in ("\x1b", "\x07", "\x9b"):
            self.assertNotIn(c, err)
        self.assertIn("\\x1b]0;PWNED", err)
        t = self.d / "evil\x1b[2Jdir"; t.mkdir(); os.chmod(t, 0o755)
        inp = self.ger_input(plan=self.plan([t]))
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(t / "x.json"))
        self.assertEqual(code, 64, err)
        self.assertNotIn("\x1b", err)
        self.assertIn("evil\\x1b[2Jdir", err)

    # F10: exec / network / spend / send を宣言したスキルへの操作は allowed_actions の明示と承認者 2 名以上。効果名は 6 種のみ
    def test_f10_risky_effects_need_two_approvers_and_enum(self):
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["network"]
        p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]
        self.reject_msg(self.ger_input(plan=self.rehash(p)), "G-6", "承認者 2 名以上")
        self.assertEqual(self.ger("verify", self.ger_input(plan=p, approvers=("lead1", "LEAD2")))[0], 0)
        self.reject_msg(self.ger_input(plan=p, approvers=("lead1", "LEAD1")), "G-6", "承認者 2 名以上")  # 大文字小文字だけの違いは 1 名
        for eff in ("EXEC", " exec ", "exec​", "bogus-effect", "secrets"):
            p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = [eff]
            self.reject_msg(self.ger_input(plan=self.rehash(p)), "G-1", "action")

    # F14: evidence_hash があれば G-7 で現在のファイルと比べる（ZES の規則: 100MB 以下は内容、超えたらパス|サイズ|mtime）
    def test_f14_evidence_hash_checked(self):
        def with_ev(ev, targets=None):
            p = self.plan(targets)
            p["items"][0]["action"]["evidence_hash"] = ev
            return self.ger_input(plan=self.rehash(p))
        good = "sha256:" + hashlib.sha256(b"x").hexdigest()
        self.assertEqual(self.ger("verify", with_ev(good))[0], 0)
        self.targets[0].write_text("changed")
        self.reject_msg(with_ev(good), "G-7", "evidence_hash")
        st = os.stat(self.targets[0])
        big = "sha256:" + hashlib.sha256(f"{self.targets[0]}|{st.st_size}|{int(st.st_mtime)}".encode()).hexdigest()
        with mock.patch.object(gates, "EVIDENCE_FULL_HASH_MAX", 3):
            self.assertEqual(self.ger("verify", with_ev(big))[0], 0)
            self.reject_msg(with_ev(good), "G-7", "evidence_hash")
        sub = self.d / "dir"; sub.mkdir(); os.chmod(sub, 0o755)  # ディレクトリは ZES が detail のハッシュを使うため比べない
        self.assertEqual(self.ger("verify", with_ev("sha256:" + "0" * 64, [sub]))[0], 0)

    # F15: ger verify-log
    def test_f15_verify_log(self):
        self.assertEqual(self.run_cli("verify-log")[0], 64)
        for _ in range(3):
            self.assertEqual(self.ger("verify", self.ger_input())[0], 0)
        code, err = self.run_cli("verify-log")
        self.assertEqual(code, 0, err); self.assertIn("3 件", err)
        lines = audit.log_path().read_text().splitlines()
        lines[0] = lines[0].replace('"operator":"ops"', '"operator":"evil"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        code, err = self.run_cli("verify-log", str(audit.log_path()))
        self.assertEqual(code, 3, err); self.assertIn("line 2: prev_hash 不一致", err)


if __name__ == "__main__":
    unittest.main()
