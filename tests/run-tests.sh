#!/usr/bin/env bash
# GER test suite: unit tests -> zero external process / zero network check (strace) -> E2E (when GER_E2E=1)
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FAIL=0
echo "== unit tests =="
python3 -I "$ROOT/tests/run.py" || FAIL=1

echo "== zero external process / zero network =="
if ! command -v strace >/dev/null 2>&1 || ! strace -f -qq -e trace=execve -o /dev/null true 2>/dev/null; then
  echo "SKIP: strace is not available (run on Linux)"
else
  # For every command and every operation type: execve only bash / python3, zero network system calls
  python3 -I "$ROOT/tests/zero_exec.py" || FAIL=1
fi

echo "== E2E (ZES -> ZET -> GER -> ZES) =="
# SKIP if the ZES repository (ZES_REPO / ZES_HOME) is missing. Slow, so it runs only when GER_E2E=1
if [ "${GER_E2E:-0}" = "1" ]; then
  "$ROOT/tests/run-e2e.sh" || FAIL=1
else
  echo "E2E skipped (run with GER_E2E=1; tests/run-e2e.sh)"
fi
[ "$FAIL" -eq 0 ] && echo "Result: OK" || echo "Result: FAIL"
exit "$FAIL"
