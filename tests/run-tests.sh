#!/usr/bin/env bash
# GER テスト一式: 単体テスト → 外部プロセスゼロ検証（strace で bash/python3 以外の execve が無いこと）
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FAIL=0
echo "== unit tests =="
python3 -I "$ROOT/tests/run.py" || FAIL=1

echo "== zero external process =="
if ! command -v strace >/dev/null 2>&1 || ! strace -f -qq -e trace=execve -o /dev/null true 2>/dev/null; then
  echo "SKIP: strace を使えません（Linux で実行してください）"
else
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  export GER_LOG_DIR="$TMP/log"
  printf 'x' >"$TMP/key"; chmod 644 "$TMP/key"
  python3 -I - "$ROOT" "$TMP" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from ger.core import plan_hash
t = sys.argv[2]
plan = {"schema_version": "1.0", "plan_id": "11111111-2222-4333-8444-555555555555", "created_at": "2026-01-01T00:00:00Z",
        "status": "ok", "held": [], "items": [{
            "finding_id": "sha256:" + "a" * 64, "decision": "remediate", "exception_type": None, "reason": None,
            "owner": "team-a", "decided_by": "alice", "decided_at": "2026-10-22T10:00:00Z", "due_at": "2026-10-29T10:00:00Z",
            "recheck_at": None, "approved_by": [], "level_effective": "HIGH",
            "action": {"type": "chmod", "target": f"{t}/key", "params": {"mode": "0600"}, "reversible": True, "skillpact_effects": []}}]}
plan["plan_hash"] = plan_hash(plan)
for mode in ("dry-run", "apply"):
    json.dump({"schema_version": "1.0", "plan": plan, "mode": mode, "allowed_actions": ["chmod"],
               "approval": {"plan_id": plan["plan_id"], "approved_by": ["security-lead"], "approved_at": "2026-01-01T01:00:00Z",
                            "approval_token": plan["plan_hash"]}}, open(f"{t}/{mode}.json", "w"))
PY
  for c in dry-run apply; do
    strace -f -qq -e trace=execve -o "$TMP/trace" "$ROOT/bin/ger" "$c" "$TMP/$c.json" --operator ci -o "$TMP/$c-log.json" >/dev/null 2>&1
    rc=$?
    bad="$(grep -E 'execve\(' "$TMP/trace" | grep ' = 0' | grep -v -E 'execve\("([^"]*/(env|bash|python3(\.[0-9]+)?)|'"$ROOT"'/bin/ger)"' || true)"
    if [ "$rc" -ne 0 ]; then echo "FAIL: ger $c の終了コードが $rc"; FAIL=1
    elif [ -n "$bad" ]; then echo "FAIL: ger $c が外部プロセスを起動:"; echo "$bad"; FAIL=1
    else echo "ok   ger $c: execve は bash/python3 のみ（chmod も os.fchmod で実行）"; fi
  done
  if [ "$(stat -c %a "$TMP/key")" = "600" ]; then echo "ok   apply 後の権限 0600"
  else echo "FAIL: apply 後の権限が 0600 ではない"; FAIL=1; fi
fi
[ "$FAIL" -eq 0 ] && echo "結果: OK" || echo "結果: FAIL"
exit "$FAIL"
