"""GER のテスト。一時ディレクトリの実ファイルに対して chmod を検証する。標準ライブラリの unittest のみ。"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from ger import audit, cli
from ger.actions import chmod
from ger.core import ROOT, plan_hash, validator

FIX = ROOT / "tests" / "fixtures"
PLAN_ID = "11111111-2222-4333-8444-555555555555"
NOW = "2026-10-22T12:00:00Z"
FID = ["sha256:" + hashlib.sha256(str(i).encode()).hexdigest() for i in range(5)]


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
        args = [command, self.write(inp, f"{command}.json"), "--operator", operator, "--now", now]
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

    def test_g7_targets(self):
        link = self.d / "link"; link.symlink_to(self.targets[0])
        self.assertRejected(self.ger_input(plan=self.plan([link])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "missing"])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([Path(str(self.d) + "/sub/../key0")])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([self.targets[0], self.targets[0]])), "G-7")
        sub = self.d / "realdir"; sub.mkdir(); (sub / "f").write_text("x")
        (self.d / "dirlink").symlink_to(sub)
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "dirlink" / "f"])), "G-7")
        p = self.plan(); p["items"][0]["action"]["params"] = {"mode": "4755"}; p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p), "G-7")
        fifo = self.d / "fifo"; os.mkfifo(fifo)
        self.assertRejected(self.ger_input(plan=self.plan([fifo])), "G-7")

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
        lines = audit.log_path().read_text().splitlines()
        lines[0] = lines[0].replace('"operator":"ops"', '"operator":"evil"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.assertRejected(ap, "G-8", command="apply")


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
        os.chmod(self.targets[0], 0o000)
        if os.access(self.targets[0], os.R_OK):
            self.skipTest("root では読み取り不可のファイルを作れない")
        code, err = self.dry_then_apply(self.ger_input())
        self.assertEqual(code, 0, err)
        self.assertEqual(mode_of(self.targets[0]), 0o600)

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


if __name__ == "__main__":
    unittest.main()
