"""GER tests. Checks chmod against real files in a temporary directory. Standard library unittest only."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import json
import os
import socket
import stat
import subprocess
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
    os.environ["GER_ALLOW_NOW_OVERRIDE"] = "1"  # The tests use --now


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
        self.assertEqual(plan_hash(plan), plan["plan_hash"], "the plan_hash definition does not match ZET")

    def test_zet_plan_11_passes_schema_and_reverified_invariants(self):
        # Actual output of ZET 0.2 finalize (plan 1.1: scope / relation / finding_path / group / evidence / followup,
        # checklist, params filled by ger preview). Made with the E2E of the ZES chaindrop fixture, with paths replaced
        # by /srv/zes-fixtures and plan_hash recomputed
        plan = json.loads((FIX / "zet-final-plan-11.json").read_text())
        self.assertEqual(plan["schema_version"], "1.1")
        self.assertEqual(validator("vendor/remediation-plan.schema.json").errors(plan), [])
        self.assertEqual(plan_hash(plan), plan["plan_hash"])
        self.assertEqual(gates._zet_invariants(plan, now_utc(plan["created_at"])), [])
        for it in plan["items"]:
            a = it["action"]
            if a:
                self.assertEqual(validator("actions.schema.json").errors({"type": a["type"], "params": a["params"]}), [])
        self.assertTrue(any(it["action"] and it["action"].get("group") for it in plan["items"]))
        self.assertTrue(any(it["action"] and it["action"].get("followup") for it in plan["items"]))

    def test_zet_r3_finalized_plan_passes_reverified_invariants(self):
        # Actual output of ZET finalize (round 3 and later): has items[].skillpact and action.evidence_hash.
        # A correctly built plan must not trip the ZET invariants checked again by G-1
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
            self.skipTest("jsonschema not installed (development dependency)")
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
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "changed although rejected")

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
        self.assertRejected(inp, "G-2")  # A draft (status: draft) is not a finalized plan
        p = self.plan(status="error")
        self.assertRejected(self.ger_input(plan=p), "G-2")

    def test_g3_approval_binding(self):
        inp = self.ger_input()
        inp["plan"]["items"][0]["action"]["target"] = str(self.d / "other")  # Replaced after approval
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
        self.assertIn("2 or more approvers", err)

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
        # SkillPact 0.8: an operation on a skill that declares exec / network / spend / send must be listed explicitly in allowed_actions
        for eff, risky in (("exec", True), ("network", True), ("spend", True), ("send", True), ("read", False), ("write", False)):
            p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = [eff]
            p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]  # ZET I-6: remediate with risky effects needs 2
            p["plan_hash"] = plan_hash(p)
            code, err = self.ger("verify", self.ger_input(plan=p, allowed=(), approvers=("security-lead", "platform-owner")))
            self.assertEqual(code, 3, err)
            self.assertEqual(f"an operation on a skill that declares {eff}" in err, risky, eff)
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["read", "write", "network", "exec", "spend", "send"]
        p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]
        p["plan_hash"] = plan_hash(p)
        self.assertEqual(self.ger("verify", self.ger_input(plan=p, approvers=("a", "b")))[0], 0)

    def test_g7_targets(self):
        link = self.d / "link"; link.symlink_to(self.targets[0])
        self.assertRejected(self.ger_input(plan=self.plan([link])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "missing"])), "G-7")
        self.assertRejected(self.ger_input(plan=self.plan([Path(str(self.d) + "/sub/../key0")])), "I-4")  # G-1 (ZET I-4 equivalent)
        self.assertRejected(self.ger_input(plan=self.plan([self.targets[0], self.targets[0]])), "G-7")
        sub = self.d / "realdir"; sub.mkdir(); (sub / "f").write_text("x")
        (self.d / "dirlink").symlink_to(sub)
        self.assertRejected(self.ger_input(plan=self.plan([self.d / "dirlink" / "f"])), "G-7")
        p = self.plan(); p["items"][0]["action"]["params"] = {"mode": "4755"}; p["plan_hash"] = plan_hash(p)
        self.assertRejected(self.ger_input(plan=p), "G-1")  # params are validated by G-1 (actions.schema.json)
        fifo = self.d / "fifo"; os.mkfifo(fifo)
        self.assertRejected(self.ger_input(plan=self.plan([fifo])), "G-7")

    def test_g7_audit_log_and_its_directories_rejected(self):
        # A chmod of the audit log, its directory or a directory above it would make recording impossible after apply
        self.assertEqual(self.ger("dry-run", self.ger_input())[0], 0)
        hl = self.d / "audit-hardlink"; os.link(audit.log_path(), hl)
        for t in (audit.log_path(), hl, audit.log_dir(), self.d):
            code, err = self.ger("verify", self.ger_input(plan=self.plan([t])))
            self.assertEqual(code, 3, (t, err))
            self.assertIn("G-7", err); self.assertIn("audit log", err)
        self.assertEqual(stat.S_IMODE(os.stat(audit.log_dir()).st_mode), 0o700)

    def test_g1_duplicate_finding_id(self):
        p = self.plan(); p["items"][1]["finding_id"] = FID[0]; p["plan_hash"] = plan_hash(p)
        code, err = self.ger("verify", self.ger_input(plan=p))
        self.assertEqual(code, 3, err)
        self.assertIn("G-1", err); self.assertIn("finding_id is duplicated", err)

    def test_g1_duplicate_finding_id_check_is_linear(self):
        # With an O(n^2) duplicate check (list.count), 20000 items take seconds. Skip schema validation, stop at G-2 and time only the duplicate check
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
        self.assertLess(elapsed, 2.5)  # About 5 seconds before the fix. An upper bound that slow CI runners do not trip

    def test_g1_invalid_calendar_timestamps(self):
        inp = self.ger_input(); inp["approval"]["approved_at"] = "2026-02-30T11:00:00Z"
        self.assertRejected(inp, "G-1")
        p = self.plan(created_at="2026-10-22T25:00:00Z")
        code, err = self.ger("verify", self.ger_input(plan=p))
        self.assertEqual(code, 3, err)
        self.assertIn("plan.created_at is not a valid date and time", err)

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
        self.assertIn("G-7", err); self.assertIn("hard link", err)

    def test_trailing_newline_rejected_by_patterns(self):
        # Python's $ also matches right before a trailing newline. "ops\n" must not get around G-4 (no self-approval)
        self.assertRejected(self.ger_input(approvers=("ops\n",)), "G-1", operator="ops")
        self.assertRejected(self.ger_input(approvers=("ops\n",)), "G-1", command="dry-run", operator="ops")
        inp = self.ger_input(); inp["approval"]["plan_id"] += "\n"
        self.assertFalse(validator("ger-input.schema.json").is_valid(inp))
        self.assertEqual(self.ger("verify", self.ger_input(), operator="ops\n")[0], 64)
        with self.assertRaises(chmod.ActionError):
            chmod.parse_params({"mode": "0600\n"})

    def test_g1_lone_surrogate_and_non_finite(self):
        inp = json.dumps(self.ger_input())
        for bad, why in ((inp.replace('"security-lead"', '"\\udc80"'), "surrogate"), (inp[:-1] + ', "x": 1e400}', "non-finite")):
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
        self.assertIn("G-1", err); self.assertIn("duplicate key", err)

    def test_g1_deep_nesting_rejected(self):
        inp = json.dumps(self.ger_input())
        for depth in (100, 200000):  # 200000 is deep enough for json.loads itself to raise RecursionError
            deep = inp[:-1] + ', "x": ' + "[" * depth + "]" * depth + "}"
            code, err = self.run_cli("verify", self.write_raw(deep), "--operator", "ops", "--now", NOW)
            self.assertEqual(code, 3, err)
            self.assertIn("G-1", err); self.assertIn("nesting is too deep", err)

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
        self.assertEqual(self.ger("verify", inp)[0], 0)  # The link at the end stays intact; only the middle is broken
        lines = audit.log_path().read_text().splitlines()
        lines[0] = lines[0].replace('"operator":"ops"', '"operator":"evil"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.assertRejected(ap, "G-8", command="apply")

    def test_g8_now_override_dry_run_does_not_unlock_real_apply(self):
        # A dry-run with --now records now_override: true and never justifies an apply without --now
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
        # A last line cut inside a multi-byte character, a JSON line that is not an object, arbitrary bytes: in the middle they cause a G-8 rejection (not 70),
        # at the end nothing is appended to a broken chain, so nothing happens and the exit code is 64 (R3 F15)
        inp = self.ger_input()
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        for garbage in (b'{"operator":"\xe3\x81', b"null", b"[1,2]", b'"x"', bytes(range(256))):
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
            # In the middle (the last record is intact): G-8
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
        # Second run: already_compliant
        code, err = self.dry_then_apply(self.ger_input())
        self.assertEqual(code, 0, err)
        self.assertEqual({r["reason"] for r in self.log("apply")["results"] if r["action_type"]}, {"already_compliant"})

    def test_unreadable_target(self):
        os.chmod(self.targets[0], 0o300)  # The owner cannot read it (only chmod 0200, which narrows, passes)
        if os.access(self.targets[0], os.R_OK):
            self.skipTest("root cannot create an unreadable file")
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
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "not rolled back")
        results = {r["finding_id"]: r["result"] for r in self.log("apply")["results"]}
        self.assertEqual([results[f] for f in FID[:3]], ["rolled_back", "rolled_back", "failed"])
        self.assertEqual(self.log("apply")["status"], "error")

    def test_rollback_tracks_items_by_position_not_finding_id(self):
        # Even with items sharing a finding_id, rollback results must not be written to another item
        rej, prepared = gates.check_gates(self.ger_input(mode="apply"), "ops", now_utc(NOW), "verify", 86400)
        self.assertEqual(rej, [])
        for i, s in enumerate(prepared):
            s.items[0].finding_id = FID[0] if i != 1 else FID[1]
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
            if target.endswith("key1"):  # Replace right after pre-validation
                os.unlink(target); Path(target).write_text("evil"); os.chmod(target, 0o644)
            return st
        with mock.patch.object(chmod, "inspect", swap_after_inspect):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 4, err)
        self.assertEqual(mode_of(self.targets[0]), 0o644)
        self.assertEqual(mode_of(self.targets[1]), 0o644)

    def test_unverifiable_after_apply_is_rollback_failed(self):
        # If the target is replaced after fchmod (the post-check fails), that item cannot be undone: rollback_failed
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        real_fchmod, calls = os.fchmod, {"n": 0}

        def fchmod_then_swap(fd, mode):
            real_fchmod(fd, mode)
            calls["n"] += 1
            if calls["n"] == 2:  # Replace right after key1 is applied
                os.rename(self.targets[1], self.d / "moved"); self.targets[1].write_text("evil"); os.chmod(self.targets[1], 0o644)
        with mock.patch.object(chmod.os, "fchmod", fchmod_then_swap):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 5, err)
        res = {r["finding_id"]: r for r in self.log("apply")["results"]}
        self.assertEqual(res[FID[0]]["result"], "rolled_back")
        self.assertEqual(mode_of(self.targets[0]), 0o644)
        self.assertEqual(res[FID[1]]["result"], "failed")
        self.assertIn("applied_unverified", res[FID[1]]["reason"])
        self.assertEqual(mode_of(self.d / "moved"), 0o600)  # The change really remains

    def test_output_path_validated_before_changes(self):
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        n = len(audit.log_path().read_text().splitlines())
        for out in ("/nonexistent/dir/x.json", str(self.d)):
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", out)
            self.assertEqual(code, 64, err)
            self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "changed although the output path is invalid")
        self.assertEqual(len(audit.log_path().read_text().splitlines()), n)

    def test_output_empty_or_trailing_slash_rejected_before_changes(self):
        # abspath reads "" as cwd and drops a trailing /, so unwritable output paths used to pass the pre-check
        inp = self.ger_input()
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        existing = self.d / "existing.json"; existing.write_text("old")
        n = len(audit.log_path().read_text().splitlines())
        for out in ("", str(self.d / "nd") + "/", str(existing) + "/", str(existing) + "/x", str(self.d / "nd" / "..")):
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", out)
            self.assertEqual(code, 64, (out, err))
            self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), f"changed although the output path is invalid: {out!r}")
        self.assertEqual(len(audit.log_path().read_text().splitlines()), n)
        self.assertEqual(existing.read_text(), "old")
        self.assertFalse((self.d / "nd").exists())

    def test_output_must_be_regular_file_not_symlink(self):
        # Never replace FIFOs, sockets, devices or symbolic links with a regular file (as root, -o /dev/null must not be broken)
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
        self.assertEqual(audit.log_path().read_bytes(), before, "the audit log was replaced")
        self.assertEqual(Path(src).read_bytes(), src_bytes, "the input was overwritten")
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
                self.assertIn("plan target", err)
        self.assertTrue(all(mode_of(t) == 0o644 and t.read_text() == "x" for t in self.targets), "a target was changed")
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([r["result"] for r in recs[1:]], ["error"] * 4)
        self.assertTrue(all("plan target" in r["error"] for r in recs[1:]))
        self.assertEqual(audit.verify_chain(), [])

    def test_output_parent_directories_must_not_be_plan_targets(self):
        # A chmod of the parent directory of -o or a directory above it would make remediation-log unwritable after apply
        out = self.d / "out"; sub = out / "sub"; sub.mkdir(parents=True)
        os.chmod(out, 0o755); os.chmod(sub, 0o755)
        for t in (sub, out):
            inp = self.ger_input(plan=self.plan([t]))
            self.assertEqual(self.ger("dry-run", inp)[0], 0)
            ap = copy.deepcopy(inp); ap["mode"] = "apply"
            code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(sub / "x.json"))
            self.assertEqual(code, 64, (t, err))
            self.assertIn("the -o output directory", err)
            self.assertEqual(stat.S_IMODE(os.stat(t).st_mode), 0o755, "a target was changed")
        self.assertFalse((sub / "x.json").exists())

    def test_output_write_failure_after_apply_is_not_rollback_failed(self):
        # If remediation-log cannot be written after every change was applied, there was no rollback, so
        # it is not recorded as rollback_failed. The remediation-log of an earlier run is removed so it is not mistaken for this one
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
        self.assertFalse(stale.exists(), "the earlier remediation-log is still there")

    def test_output_write_failure(self):
        inp = self.ger_input()
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        with mock.patch.object(cli, "write_atomic", side_effect=OSError("disk full")):
            code, err = self.ger("dry-run", inp)
            self.assertNotEqual(code, 0, err)
            code, err = self.ger("apply", ap)
            self.assertEqual(code, 3, err); self.assertIn("G-8", err)  # A dry-run whose log could not be written does not allow apply
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        with mock.patch.object(cli, "write_atomic", side_effect=OSError("disk full")):
            code, err = self.ger("apply", ap)
        self.assertEqual(code, 5, err)
        self.assertIn("by hand", err)
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        # The start record (started) is appended before the first change and uses up the dry-run record
        self.assertEqual([r["result"] for r in recs], ["error", "rejected", "ok", "started", "applied_unlogged"])
        self.assertEqual(recs[-2]["run_id"], recs[-1]["run_id"])
        self.assertNotIn("output_hash", recs[0]); self.assertNotIn("output_hash", recs[-1])

    def test_now_override_requires_env(self):
        with mock.patch.dict(os.environ):
            del os.environ["GER_ALLOW_NOW_OVERRIDE"]
            for command in ("verify", "dry-run", "apply"):
                code, err = self.ger(command, self.ger_input(mode="dry-run" if command == "verify" else command))
                self.assertEqual(code, 64, err)
                self.assertIn("for tests only", err)
            self.assertEqual(self.ger("verify", self.ger_input(), now=None)[0], 0)
        self.assertFalse(audit.log_path().exists() and "dry-run" in audit.log_path().read_text())

    def test_audit_torn_last_line_and_symlink(self):
        audit.ensure_writable()
        audit.log_path().write_bytes(b'{"skill":"ger","comm')  # A last line half written by a crash
        with self.assertRaises(audit.BrokenChain):  # R3 F15: nothing is appended after a broken chain
            audit.append({"command": "verify", "result": "ok"})
        self.assertEqual(audit.log_path().read_bytes(), b'{"skill":"ger","comm')
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)
        other = self.d / "elsewhere"; other.write_text("")
        audit.log_path().unlink(); audit.log_path().symlink_to(other)
        for check in (audit.ensure_writable, lambda: None):  # Rejected by both the pre-check and O_NOFOLLOW
            with mock.patch.object(audit, "ensure_writable", check), self.assertRaises(OSError):
                audit.append({"command": "verify", "result": "ok"})
        self.assertEqual(self.ger("verify", self.ger_input())[0], 64)
        self.assertEqual(other.read_text(), "")

    def test_audit_dir_must_be_private_and_owned(self):
        d = audit.log_dir(); d.mkdir()
        for m in (0o777, 0o730, 0o702):
            os.chmod(d, m)
            code, err = self.ger("verify", self.ger_input())
            self.assertEqual(code, 64, err); self.assertIn("writable by group or others", err)
        os.chmod(d, 0o700)
        with mock.patch.object(audit.os, "geteuid", return_value=os.geteuid() + 1):
            code, err = self.ger("verify", self.ger_input())
        self.assertEqual(code, 64, err); self.assertIn("not owned by", err)
        self.assertFalse(audit.log_path().exists())
        self.assertEqual(self.ger("verify", self.ger_input())[0], 0)

    def test_audit_records_every_command(self):
        self.dry_then_apply(self.ger_input())
        self.ger("verify", self.ger_input(allowed=()))
        recs = [json.loads(line) for line in audit.log_path().read_text().splitlines()]
        self.assertEqual([(r["command"], r["result"]) for r in recs],
                         [("dry-run", "ok"), ("apply", "started"), ("apply", "ok"), ("verify", "rejected")])
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
    """Regression tests for the round 3 findings (F1 / F2 / F3 / F5 / F6 / F7 / F8 / F10 / F14 / F15)."""

    def reject_msg(self, inp, gate, text, command="verify", **kw):
        code, err = self.ger(command, inp, **kw)
        self.assertEqual(code, 3, err)
        self.assertIn(gate, err)
        self.assertIn(text, err)
        self.assertTrue(all(mode_of(t) == 0o644 for t in self.targets), "changed although rejected")
        return err

    def rehash(self, p):
        p["plan_hash"] = plan_hash(p)
        return p

    # F1: even if the plan is rewritten and plan_hash and approval_token recomputed, the ZET invariants that can be evaluated from the plan alone stop it
    def test_f1_tampered_and_rehashed_plan_rechecked(self):
        sp = {"signed": True, "divergence": ["network"], "diff_anomaly": False, "declared_effects": ["exec"]}
        cases = []
        p = self.plan(); p["items"][3].update(skillpact=dict(sp), level_effective="CRITICAL"); cases.append((p, "I-5", "cannot be an exception"))
        p = self.plan(); p["items"][0]["skillpact"] = dict(sp, divergence=[]); p["items"][0]["approved_by"] = ["a", "b"]
        p["items"][0]["action"]["skillpact_effects"] = []; cases.append((p, "I-4", "does not match the item's skillpact.declared_effects"))
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, divergence=[], declared_effects=[], diff_anomaly=True))
        cases.append((p, "I-6", "diff_anomaly"))
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, declared_effects=[]), level_effective="HIGH")
        cases.append((p, "I-7", "CRITICAL"))
        p = self.plan(); p["items"][3]["approved_by"] = ["alice"]; cases.append((p, "I-3", "self-approval"))
        p = self.plan(); p["items"][3]["approved_by"] = []; cases.append((p, "I-3", "at least 1 approver"))
        p = self.plan(); p["items"][3]["reason"] = " "; cases.append((p, "I-3", "reason"))
        p = self.plan(); p["items"][1]["decision"] = "defer"; cases.append((p, "I-4", "action is set although the decision is not remediate"))
        p = self.plan(); p["items"][0]["owner"] = None; cases.append((p, "I-4", "owner"))
        p = self.plan(); p["items"][0]["action"]["target"] = "/" + str(self.targets[0]); cases.append((p, "I-4", "normalized"))
        p = self.plan(); p["held"] = [{"finding_id": FID[0], "reason": "x"}]; cases.append((p, "I-1", "duplicated"))
        p = self.plan(status="partial"); cases.append((p, "I-12", "held"))
        p = self.plan(); p["items"][0]["decided_at"] = "2026-10-22T12:00:01Z"; cases.append((p, "I-9", "later than the current time"))
        p = self.plan(); p["items"][0]["due_at"] = "2026-10-22T09:00:00Z"; cases.append((p, "I-9", "earlier than decided_at"))
        p = self.plan(); p["items"][0]["decided_at"] = "2026-10-22T09:00:00Z"; cases.append((p, "I-9", "earlier than the plan's created_at"))
        p = self.plan(); p["items"][0]["approved_by"] = ["Lead", "lead"]; cases.append((p, "I-6", "duplicates"))
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["exec"]; cases.append((p, "I-6", "exec"))
        for p, code, text in cases:
            err = self.reject_msg(self.ger_input(plan=self.rehash(p), approvers=("lead1", "lead2")), "G-1", text)
            self.assertIn(f"ZET {code} equivalent", err)
        # A consistent skillpact summary passes (the shape ZET adds in finalize)
        p = self.plan(); p["items"][0].update(skillpact=dict(sp, declared_effects=[]), level_effective="CRITICAL")
        self.assertEqual(self.ger("verify", self.ger_input(plan=self.rehash(p)))[0], 0)

    # F7: chmod only narrows permissions (never adds bits missing from the current mode). world-writable is rejected too
    def test_f7_chmod_only_tightens(self):
        for before, mode, ok in ((0o644, "0600", True), (0o644, "0644", True), (0o644, "0000", True), (0o600, "0640", False),
                                 (0o640, "0604", False), (0o600, "0700", False), (0o666, "0666", False), (0o777, "0757", False)):
            os.chmod(self.targets[0], before)
            p = self.plan(); p["items"][0]["action"]["params"]["mode"] = mode
            code, err = self.ger("verify", self.ger_input(plan=self.rehash(p)))
            self.assertEqual(code == 0, ok, (oct(before), mode, err))
            if not ok:  # A statically known world-writable is G-1 (params check); adding a permission to the current mode is G-7
                self.assertIn("G-1" if int(mode, 8) & 0o002 else "G-7", err)
                self.assertTrue("permission" in err or "world-writable" in err, err)
            self.assertEqual(mode_of(self.targets[0]), before)
        os.chmod(self.targets[0], 0o644)

    # F2: even if GER_LOG_DIR is given through a symbolic link, the directory holding the link (lexical ancestor) cannot be a target
    def test_f2_log_dir_symlink_ancestors_protected(self):
        a, b = self.d / "A", self.d / "B" / "ger"
        a.mkdir(); b.mkdir(parents=True); os.chmod(b, 0o700); os.chmod(a, 0o755)
        (a / "logdir").symlink_to(b)
        os.environ["GER_LOG_DIR"] = str(a / "logdir")
        err = self.reject_msg(self.ger_input(plan=self.plan([a])), "G-7", "audit log")
        self.assertIn("G-7", err)
        self.assertEqual(stat.S_IMODE(os.stat(a).st_mode), 0o755)
        # Writes go to the real path resolved at startup (a link replaced later does not redirect them)
        self.assertEqual(audit.log_dir(), Path(os.path.realpath(b)))
        self.assertTrue((b / "ger-audit.jsonl").exists())

    # F3: even if the parent of -o is reached through a symbolic link, the directory holding the link cannot be a plan target
    def test_f3_output_parent_symlink_ancestors_protected(self):
        a, out = self.d / "A", self.d / "B" / "out"
        a.mkdir(); out.mkdir(parents=True); os.chmod(a, 0o755)
        (a / "outdir").symlink_to(out)
        inp = self.ger_input(plan=self.plan([a]))
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(a / "outdir" / "x.json"))
        self.assertEqual(code, 64, err)
        self.assertIn("the -o output directory", err)
        self.assertEqual(stat.S_IMODE(os.stat(a).st_mode), 0o755)

    # F5: a dry-run record is used up by one apply (rejections and argument errors before any change do not use it)
    def test_f5_dry_run_record_consumed_by_apply(self):
        inp = self.ger_input()
        code, err = self.dry_then_apply(inp)
        self.assertEqual(code, 0, err)
        for t in self.targets:
            os.chmod(t, 0o644)
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        self.reject_msg(ap, "G-8", "dry-run", command="apply")
        self.assertEqual(self.dry_then_apply(inp)[0], 0)  # A new dry-run allows running again
        for t in self.targets:
            os.chmod(t, 0o644)
        # An argument error (an apply stopped before any change) does not mark the dry-run as used
        self.assertEqual(self.ger("dry-run", inp)[0], 0)
        code, err = self.run_cli("apply", self.write(ap), "--operator", "ops", "--now", NOW, "-o", str(self.targets[0]))
        self.assertEqual(code, 64, err)
        self.assertEqual(self.ger("apply", ap)[0], 0)

    # F5: approval expiry (default 7 days, GER_APPROVAL_MAX_AGE) and plans past the latest remediate due_at
    def test_f5_approval_max_age_and_plan_due(self):
        inp = self.ger_input()
        p = self.plan(); [it.update(due_at="2026-12-31T00:00:00Z") for it in p["items"] if it["decision"] == "remediate"]
        inp2 = self.ger_input(plan=self.rehash(p))
        self.assertEqual(self.ger("verify", inp2, now="2026-10-29T11:00:00Z")[0], 0)  # Exactly 7 days
        self.reject_msg(inp2, "G-3", "GER_APPROVAL_MAX_AGE", now="2026-10-29T11:00:01Z")
        os.environ["GER_APPROVAL_MAX_AGE"] = str(30 * 86400)
        try:
            self.assertEqual(self.ger("verify", inp2, now="2026-11-20T00:00:00Z")[0], 0)
            for bad in ("0", "-1", "1e3", "x", "٣"):
                os.environ["GER_APPROVAL_MAX_AGE"] = bad
                self.assertEqual(self.ger("verify", inp2)[0], 64, bad)
        finally:
            os.environ.pop("GER_APPROVAL_MAX_AGE", None)
        # Past the latest due_at (2026-10-29T10:00:00Z), nothing runs even with a fresh approval
        self.reject_msg(inp, "G-2", "expired", now="2026-10-29T10:00:01Z")

    # F5: a plan made by ZET with --now (now_override: true) is accepted only when GER_ALLOW_NOW_OVERRIDE=1
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
        self.assertEqual(self.ger("verify", inp, now=None)[0], 0)  # GER_ALLOW_NOW_OVERRIDE=1 in the test environment
        os.environ.pop("GER_ALLOW_NOW_OVERRIDE")
        try:
            self.reject_msg(inp, "G-2", "now_override", now=None)
        finally:
            os.environ["GER_ALLOW_NOW_OVERRIDE"] = "1"
        # A finalized plan from an older ZET (no now_override) is accepted as is (backward compatibility)
        self.assertEqual(self.ger("verify", self.ger_input(), now=NOW)[0], 0)

    # F6: an apply with --now counts only dry-run records made with --now (an old real-time record cannot look unexpired with --now)
    def test_f6_now_override_apply_counts_only_override_dry_runs(self):
        now = now_utc()
        ts = lambda d: fmt_ts(now + dt.timedelta(seconds=d))  # noqa: E731
        p = self.plan(created_at=ts(-7200))
        for it in p["items"]:
            it["decided_at"] = ts(-7200)
            it["due_at"] = it["due_at"] and ts(86400)
            it["recheck_at"] = it["recheck_at"] and ts(86400)
        inp = self.ger_input(plan=self.rehash(p)); inp["approval"]["approved_at"] = ts(-3600)
        self.assertEqual(self.ger("dry-run", inp, now=None)[0], 0)  # dry-run in real time
        ap = copy.deepcopy(inp); ap["mode"] = "apply"
        dry_at = json.loads(audit.log_path().read_text().splitlines()[-1])["finished_at"]
        self.reject_msg(ap, "G-8", "dry-run", command="apply", now=dry_at)
        self.assertEqual(self.ger("dry-run", inp, now=dry_at)[0], 0)  # A dry-run with --now can be used by an apply with --now
        self.assertEqual(self.ger("apply", ap, now=dry_at)[0], 0)

    # F8: control characters in strings from input (key names, target paths) are escaped when shown
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

    # F10: an operation on a skill that declares exec / network / spend / send needs an explicit allowed_actions entry and 2 or more approvers. Only the 6 effect names
    def test_f10_risky_effects_need_two_approvers_and_enum(self):
        p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = ["network"]
        p["items"][0]["approved_by"] = ["security-lead", "platform-owner"]
        self.reject_msg(self.ger_input(plan=self.rehash(p)), "G-6", "2 or more approvers")
        self.assertEqual(self.ger("verify", self.ger_input(plan=p, approvers=("lead1", "LEAD2")))[0], 0)
        self.reject_msg(self.ger_input(plan=p, approvers=("lead1", "LEAD1")), "G-6", "2 or more approvers")  # Names differing only in case count as 1
        for eff in ("EXEC", " exec ", "exec​", "bogus-effect", "secrets"):
            p = self.plan(); p["items"][0]["action"]["skillpact_effects"] = [eff]
            self.reject_msg(self.ger_input(plan=self.rehash(p)), "G-1", "action")

    # F14: if there is an evidence_hash, G-7 compares it with the current file (ZES rule: up to 100MB the content, above that path|size|mtime)
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
        sub = self.d / "dir"; sub.mkdir(); os.chmod(sub, 0o755)  # Directories are not compared because ZES uses the hash of detail for them
        self.assertEqual(self.ger("verify", with_ev("sha256:" + "0" * 64, [sub]))[0], 0)

    # F15: ger verify-log
    def test_f15_verify_log(self):
        self.assertEqual(self.run_cli("verify-log")[0], 64)
        for _ in range(3):
            self.assertEqual(self.ger("verify", self.ger_input())[0], 0)
        code, err = self.run_cli("verify-log")
        self.assertEqual(code, 0, err); self.assertIn("records: 3", err)
        lines = audit.log_path().read_text().splitlines()
        lines[0] = lines[0].replace('"operator":"ops"', '"operator":"evil"')
        audit.log_path().write_text("\n".join(lines) + "\n")
        code, err = self.run_cli("verify-log", str(audit.log_path()))
        self.assertEqual(code, 3, err); self.assertIn("line 2: prev_hash mismatch", err)


class TestLauncherNoSite(unittest.TestCase):
    """bin/ger does not load site (-S). .pth files in site-packages are executed by import site, so
    -I alone is not enough to keep code from running inside the tool itself."""

    def test_launcher_passes_I_and_S(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "argv")
            shim = os.path.join(d, "python3")
            with open(shim, "w") as fh:
                fh.write('#!/bin/sh\nprintf "%s\\n" "$@" > "' + log + '"\n')
            os.chmod(shim, 0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
            subprocess.run([str(Path(__file__).resolve().parents[1] / "bin" / "ger"), "--help"],
                           env=env, check=False, capture_output=True)
            with open(log) as fh:
                args = fh.read().split("\n")
            self.assertEqual(args[:2], ["-I", "-S"])


if __name__ == "__main__":
    unittest.main()
