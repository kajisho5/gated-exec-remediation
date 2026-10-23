#!/usr/bin/env bash
# E2E（成功基準）: ZES のフィクスチャを一時ディレクトリに写し、ZES → ZET → GER apply → ZES 再スキャン → ger restore → ZES 再スキャン。
#   ZES_REPO（または ZES_HOME）= ZES のリポジトリ（zes-scan.sh のあるディレクトリ。読むだけ）
#   ZET_HOME = ZET のリポジトリ（既定: GER の隣の zero-exec-triage）
# どちらかが無ければ SKIP（終了コード 0）。追加の引数は tests/e2e_zes.py に渡す（フィクスチャ名、--jobs N、--json OUT）。
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ZES="${ZES_REPO:-${ZES_HOME:-}}"
if [ -z "$ZES" ] || [ ! -f "$ZES/zes-scan.sh" ]; then
  echo "SKIP: ZES のリポジトリ（zes-scan.sh）がありません（ZES_REPO / ZES_HOME を指定してください）"
  exit 0
fi
command -v jq >/dev/null 2>&1 || { echo "SKIP: zes-scan.sh には jq が必要です"; exit 0; }
exec python3 -I "$ROOT/tests/e2e_zes.py" --zes "$ZES" "$@"
