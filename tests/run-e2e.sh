#!/usr/bin/env bash
# E2E (success criterion): copies the ZES fixtures to a temporary directory, then ZES -> ZET -> GER apply -> ZES rescan -> ger restore -> ZES rescan.
#   ZES_REPO (or ZES_HOME) = the ZES repository (the directory with zes-scan.sh; read only)
#   ZET_HOME = the ZET repository (default: zero-exec-triage next to GER)
# If either is missing: SKIP (exit code 0). Extra arguments go to tests/e2e_zes.py (fixture names, --jobs N, --json OUT).
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ZES="${ZES_REPO:-${ZES_HOME:-}}"
if [ -z "$ZES" ] || [ ! -f "$ZES/zes-scan.sh" ]; then
  echo "SKIP: ZES repository (zes-scan.sh) not found (set ZES_REPO / ZES_HOME)"
  exit 0
fi
command -v jq >/dev/null 2>&1 || { echo "SKIP: zes-scan.sh needs jq"; exit 0; }
exec python3 -I "$ROOT/tests/e2e_zes.py" --zes "$ZES" "$@"
