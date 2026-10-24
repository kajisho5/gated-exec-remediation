"""E2E (success criterion): runs ZES -> ZET -> GER end to end on the fixture trees and rescans with ZES.

  python3 -I tests/e2e_zes.py [--zes DIR] [--zet DIR] [--jobs N] [--json OUT] [FIXTURE ...]

The ZES repository is --zes, or the environment variable ZES_REPO / ZES_HOME (the directory with zes-scan.sh).
The ZET repository is --zet, or the environment variable ZET_HOME (otherwise zero-exec-triage next to GER).
If either is missing: SKIP (exit code 0, prints "SKIP:"). The ZES repository is only read; fixtures are copied to a temporary directory.
(For zes-scan.sh itself, ZES_HOME is also the environment variable that names the target of the home checks. This E2E reads it
as the location of the ZES repository and overrides it with the fixture's home when it starts zes-scan.sh.)

Steps per fixture (design doc §7.7):
  1. zes-scan.sh (mode from tests/expected/<name>.json; ZES_HOST_CHECKS=0 ZES_OFFLINE=1)
  2. zet draft (policy.scope set to the fixture's root and home)
  3. a test decider adopts the proposals (auto if there is one, otherwise checklist; the default defer for INFO stays)
  4. ger preview (a rejected auto is switched to checklist together with the findings in the same group, then previewed again)
  5. zet finalize -> approval (2 test approvers) -> ger dry-run -> ger apply
  6. rescan with zes-scan.sh
  7. ger restore (every entry of this fixture's quarantine store; dry-run -> apply) -> rescan with zes-scan.sh
Pass conditions:
  - the set of findings of the rescan (multiset of level / module / campaign / fixture-relative path) equals exactly
    the set of the plan's checklist / defer / exception items and held, except those whose path is inside a target
    that an applied quarantine moved away (a fixture with only auto items ends with 0 findings). So the expected set
    does not depend on the age of the fixture files (findings such as s35.mtime_before_birth come and go with it)
  - the rescan after restore equals the first scan (ids match too)
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

GER = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, GER)

from ger.core import canonical, plan_hash, sha256  # noqa: E402

TYPES = ["chmod", "quarantine", "edit_json", "edit_toml", "remove_line", "disable_mcp_server", "checklist"]


def ts(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def find_repos(args):
    zes = args.zes or os.environ.get("ZES_REPO") or os.environ.get("ZES_HOME")
    zet = args.zet or os.environ.get("ZET_HOME") or os.path.join(os.path.dirname(GER), "zero-exec-triage")
    if not zes or not os.path.isfile(os.path.join(zes, "zes-scan.sh")):
        return None, None, "ZES repository (zes-scan.sh) not found (--zes / ZES_REPO / ZES_HOME)"
    if not os.path.isfile(os.path.join(zet, "bin", "zet")):
        return None, None, f"ZET repository not found (--zet / ZET_HOME): {zet}"
    return os.path.realpath(zes), os.path.realpath(zet), None


class Fx:
    def __init__(self, name, zes, zet, work):
        self.name, self.zes_dir, self.zet_dir = name, zes, zet
        exp = json.load(open(os.path.join(zes, "tests", "expected", name + ".json")))
        self.mode = exp.get("mode", "full")
        home = exp.get("home") or "_home"
        self.dir = os.path.join(work, name)
        os.makedirs(self.dir)
        self.root = os.path.join(self.dir, "fx", name)
        shutil.copytree(os.path.join(zes, "tests", "fixtures", name), self.root, symlinks=True)
        if home == "self":
            self.home = self.root
        else:
            self.home = os.path.join(self.dir, "fx", home)
            shutil.copytree(os.path.join(zes, "tests", "fixtures", home), self.home, symlinks=True)
        self.env = dict(os.environ, GER_LOG_DIR=os.path.join(self.dir, "gerlog"), ZET_LOG_DIR=os.path.join(self.dir, "zetlog"),
                        GER_QUARANTINE_DIR=os.path.join(self.dir, "store"))
        self.env.pop("GER_ALLOW_NOW_OVERRIDE", None)
        self.env.pop("ZET_ALLOW_NOW_OVERRIDE", None)
        self.log = []

    def p(self, n):
        return os.path.join(self.dir, n)

    def run(self, argv, ok=(0,), env=None):
        r = subprocess.run(argv, env=env or self.env, capture_output=True, text=True)
        self.log.append((" ".join(os.path.basename(a) if i == 0 else a for i, a in enumerate(argv)), r.returncode, r.stderr[-4000:]))
        if r.returncode not in ok:
            raise RuntimeError(f"{os.path.basename(argv[0])} {argv[1] if len(argv) > 1 else ''} → {r.returncode}\n{r.stderr[-3000:]}")
        return r

    def scan(self, out):
        env = dict(os.environ, ZES_HOST_CHECKS="0", ZES_OFFLINE="1", ZES_HOME=self.home, ZES_NOW="1792800000",
                   ZES_SKILLPACT_CACHE="")
        r = subprocess.run(["bash", os.path.join(self.zes_dir, "zes-scan.sh"), "--" + self.mode, "--root", self.root, "--json"],
                           env=env, capture_output=True, text=True)
        if r.returncode not in (0, 1, 2):
            raise RuntimeError(f"zes-scan.sh → {r.returncode}: {r.stderr[-2000:]}")
        doc = json.loads(r.stdout)
        json.dump(doc, open(self.p(out), "w"), ensure_ascii=False, indent=1)
        return doc

    def zet(self, *a, ok=(0,)):
        return self.run([os.path.join(self.zet_dir, "bin", "zet"), *a], ok=ok)

    def ger(self, *a, ok=(0,)):
        return self.run([os.path.join(GER, "bin", "ger"), *a], ok=ok)

    def key(self, f):
        path = f["path"]
        if path is not None:
            for base, tag in ((self.root, "."), (self.home, "~")):
                if path == base:
                    path = tag
                    break
                if path.startswith(base + "/"):
                    path = tag + "/" + path[len(base) + 1:]
                    break
        return (f["level"], f["module"], f.get("campaign"), path)


def decide(draft: dict, use_checklist: set, created: str) -> dict:
    plan = json.loads(json.dumps(draft))
    for it in plan["items"]:
        c = it.get("constraints", {})
        sug = c.get("suggested_actions", [])
        auto = next((s for s in sug if s["label"] == "auto"), None)
        chk = next((s for s in sug if s["label"] == "checklist"), None)
        pick = None
        if auto and it["finding_id"] not in use_checklist:
            pick = auto
        elif chk:
            pick = chk
        if pick:
            it.update(decision="remediate", owner="team-sec", decided_by="alice", decided_at=created,
                      exception_type=None, reason=None, recheck_at=None, action=json.loads(json.dumps(pick["action"])))
            need = max(c.get("min_approvers", 0), 1 if pick["label"] == "auto" else 0)
            it["approved_by"] = ["sec-a", "sec-b"][:max(need, 0)] if need else []
        elif it["decision"] is None:
            it.update(decision="defer", reason="e2e: no proposal", decided_by="alice", decided_at=created, due_at=None)
        if it["decision"] in ("defer", "exception"):
            it["action"] = None
            it["due_at"] = None if it["decision"] == "defer" and it["level_effective"] == "INFO" else it["due_at"]
    return plan


def quarantined_targets(final: dict, log: dict) -> list[str]:
    """The targets that apply moved into the quarantine store (quarantine items whose result is applied)."""
    applied = {r["finding_id"] for r in log["results"] if r["result"] == "applied" and r["action_type"] == "quarantine"}
    return sorted({it["action"]["target"] for it in final["items"] if it["finding_id"] in applied
                   and it["action"] and it["action"]["type"] == "quarantine" and it["action"]["target"]})


def inside(path, targets) -> bool:
    return isinstance(path, str) and any(path == t or path.startswith(t.rstrip("/") + "/") for t in targets)


def classify_expected(final: dict, findings: dict, log: dict | None = None) -> collections.Counter:
    """The findings expected after apply: those of the plan's checklist / defer / exception items and held, except the
    ones whose path is inside a target that an applied quarantine moved away (they cannot be reported there any more,
    whatever they are). Without this, the expected set depended on findings that only some copies of the fixtures have
    (s35.mtime_before_birth appears once a checkout is older than a day, because the copy keeps the mtimes)."""
    by = {f["id"]: f for f in findings["findings"]}
    gone = quarantined_targets(final, log) if log is not None else []
    out = collections.Counter()
    for it in final["items"]:
        a = it["action"]
        if it["decision"] != "remediate" or (a and a["type"] == "checklist"):
            out[it["finding_id"]] += 1
    for h in final["held"]:
        if h["finding_id"]:
            out[h["finding_id"]] += 1
    return collections.Counter({fid: n for fid, n in out.items() if fid in by and not inside(by[fid]["path"], gone)})


def run_fixture(name, zes, zet, work) -> dict:
    fx = Fx(name, zes, zet, work)
    res = {"fixture": name, "ok": False}
    try:
        f1 = fx.scan("findings-1.json")
        by1 = {f["id"]: f for f in f1["findings"]}
        res["before"] = len(f1["findings"])
        tin = {"schema_version": "1.0", "findings": f1,
               "policy": {"deadlines": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 90}, "decision_window_days": 30,
                          "approvers": ["sec-a", "sec-b"], "scope": {"roots": [fx.root], "home": fx.home}},
               "skillpact_policy": {"l3_trusted": False}}
        json.dump(tin, open(fx.p("triage-input.json"), "w"), ensure_ascii=False)
        fx.zet("draft", fx.p("triage-input.json"), "--operator", "alice", "-o", fx.p("draft.json"))
        draft = json.load(open(fx.p("draft.json")))
        use_cl: set = set()
        for _round in range(4):
            plan = decide(draft, use_cl, draft["created_at"])
            json.dump(plan, open(fx.p("decided.json"), "w"), ensure_ascii=False, indent=1)
            r = fx.ger("preview", fx.p("decided.json"), "--operator", "alice", "-o", fx.p("previewed.json"),
                       "--report", fx.p("preview-report.json"), ok=(0, 3))
            rep = json.load(open(fx.p("preview-report.json")))
            bad = [x for x in rep["items"] if x["status"] == "rejected"]
            if not bad:
                break
            for x in bad:
                use_cl.update(x["finding_ids"])
            res.setdefault("preview_rejected", []).extend(
                {"key": fx.key(by1[fid]), "reason": x["reason"][:160]} for x in bad for fid in x["finding_ids"])
        else:
            raise RuntimeError("preview rejections do not converge")
        fx.zet("finalize", fx.p("triage-input.json"), fx.p("previewed.json"), "--operator", "alice", "-o", fx.p("final.json"))
        final = json.load(open(fx.p("final.json")))
        assert plan_hash(final) == final["plan_hash"]
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        gin = {"schema_version": "1.0", "plan": final, "mode": "dry-run", "allowed_actions": TYPES,
               "approval": {"plan_id": final["plan_id"], "approved_by": ["sec-a", "sec-b"], "approved_at": ts(now),
                            "approval_token": final["plan_hash"]}}
        json.dump(gin, open(fx.p("ger-dry.json"), "w"), ensure_ascii=False)
        json.dump(dict(gin, mode="apply"), open(fx.p("ger-apply.json"), "w"), ensure_ascii=False)
        fx.ger("dry-run", fx.p("ger-dry.json"), "--operator", "ops", "-o", fx.p("log-dry.json"))
        fx.ger("apply", fx.p("ger-apply.json"), "--operator", "ops", "-o", fx.p("log-apply.json"))
        log = json.load(open(fx.p("log-apply.json")))
        acts = collections.Counter()
        for it in final["items"]:
            if it["decision"] == "remediate":
                acts[it["action"]["type"]] += 1
            else:
                acts[it["decision"]] += 1
        res["plan"] = dict(acts)
        res["held"] = sum(1 for h in final["held"] if h["finding_id"])
        res["auto_items"] = sum(1 for r in log["results"] if r["result"] in ("applied", "skipped") and r["action_type"]
                                not in (None, "checklist"))
        res["checklist_items"] = sum(1 for r in log["results"] if r["result"] == "pending_manual")
        res["defer_exception_items"] = sum(1 for it in final["items"] if it["decision"] in ("defer", "exception"))
        res["followup_items"] = sum(1 for r in log["results"] if r.get("followup"))
        f2 = fx.scan("findings-2.json")
        res["after"] = len(f2["findings"])
        want = collections.Counter(fx.key(by1[fid]) for fid, n in classify_expected(final, f1, log).items() for _ in range(n))
        got = collections.Counter(fx.key(f) for f in f2["findings"])
        res["after_matches_plan"] = want == got
        if want != got:
            res["unexpected_after"] = [list(k) for k in (got - want).elements()]
            res["missing_after"] = [list(k) for k in (want - got).elements()]
        # restore
        r = fx.ger("quarantine-list", "--json", "--plan-id", final["plan_id"])
        ents = [e for e in json.loads(r.stdout)["entries"] if e.get("status") == "quarantined"]
        res["quarantine_entries"] = len(ents)
        if ents:
            rid = str(uuid.uuid4())
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            req = {"schema_version": "1.0", "restore_id": rid, "created_at": ts(now - dt.timedelta(seconds=1)),
                   "mode": "dry-run", "reason": "e2e restore round trip",
                   "entries": [{"quarantine_id": e["quarantine_id"], "manifest_sha256": e["manifest_sha256"]} for e in ents]}
            tok = sha256(canonical({k: v for k, v in req.items() if k not in ("approval", "mode")}))
            req["approval"] = {"restore_id": rid, "approved_by": ["sec-a", "sec-b"], "approved_at": ts(now), "approval_token": tok}
            json.dump(req, open(fx.p("restore-dry.json"), "w"))
            json.dump(dict(req, mode="apply"), open(fx.p("restore-apply.json"), "w"))
            fx.ger("restore", fx.p("restore-dry.json"), "--operator", "ops", "-o", fx.p("log-restore-dry.json"))
            fx.ger("restore", fx.p("restore-apply.json"), "--operator", "ops", "-o", fx.p("log-restore.json"))
        f3 = fx.scan("findings-3.json")
        res["after_restore"] = len(f3["findings"])
        k1 = collections.Counter((f["id"], fx.key(f)) for f in f1["findings"])
        k3 = collections.Counter((f["id"], fx.key(f)) for f in f3["findings"])
        res["restore_matches_before"] = k1 == k3
        if k1 != k3:
            d1 = {f["id"]: f["detail"] for f in f1["findings"]}
            d3 = {f["id"]: f["detail"] for f in f3["findings"]}
            res["restore_diff"] = {"extra": [list(k[1]) + [d3.get(k[0], "")[:200]] for k in (k3 - k1).elements()],
                                   "missing": [list(k[1]) + [d1.get(k[0], "")[:200]] for k in (k1 - k3).elements()]}
        r = fx.ger("verify-log")
        res["ok"] = res["after_matches_plan"] and res["restore_matches_before"]
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:3000]
    res["workdir"] = fx.dir
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fixtures", nargs="*")
    ap.add_argument("--zes")
    ap.add_argument("--zet")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json")
    ap.add_argument("--keep", action="store_true", help="keep the working directory")
    args = ap.parse_args(argv)
    zes, zet, why = find_repos(args)
    if why:
        print(f"SKIP: {why}")
        return 0
    names = args.fixtures or sorted(n[:-5] for n in os.listdir(os.path.join(zes, "tests", "expected"))
                                    if n.endswith(".json") and not n.startswith("_"))
    work = tempfile.mkdtemp(prefix="ger-e2e-")
    results = []
    try:
        with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
            for r in ex.map(lambda n: run_fixture(n, zes, zet, work), names):
                results.append(r)
                flag = "ok  " if r["ok"] else "FAIL"
                print(f"{flag} {r['fixture']:28s} before={r.get('before')} auto={r.get('auto_items')} "
                      f"checklist={r.get('checklist_items')} defer/exc={r.get('defer_exception_items')} held={r.get('held')} "
                      f"after={r.get('after')} restore={r.get('after_restore')}"
                      + (f"  ERROR {r['error'][:300]}" if r.get("error") else "")
                      + (f"  unexpected={r.get('unexpected_after')} missing={r.get('missing_after')}" if r.get("after_matches_plan") is False else "")
                      + (f"  restore_diff={r.get('restore_diff')}" if r.get("restore_matches_before") is False else ""),
                      flush=True)
    finally:
        if args.json:
            json.dump({"zes": zes, "zet": zet, "results": results}, open(args.json, "w"), ensure_ascii=False, indent=1)
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"working directory: {work}")
    bad = [r for r in results if not r["ok"]]
    print(f"Result: {len(results) - len(bad)}/{len(results)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
