#!/usr/bin/env bash
# GER テスト一式: 単体テスト → 外部プロセス・ネットワークゼロ検証（strace）→（GER_E2E=1 のとき）E2E
set -u
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FAIL=0
echo "== unit tests =="
python3 -I "$ROOT/tests/run.py" || FAIL=1

echo "== zero external process / zero network =="
if ! command -v strace >/dev/null 2>&1 || ! strace -f -qq -e trace=execve -o /dev/null true 2>/dev/null; then
  echo "SKIP: strace を使えません（Linux で実行してください）"
else
  # 全コマンド・全操作種別で、execve が bash / python3 だけで、ネットワークのシステムコールが 0 件であること
  python3 -I "$ROOT/tests/zero_exec.py" || FAIL=1
fi

echo "== E2E（ZES → ZET → GER → ZES） =="
# ZES のリポジトリ（ZES_REPO / ZES_HOME）が無ければ SKIP。時間がかかるため GER_E2E=1 のときだけ実行する
if [ "${GER_E2E:-0}" = "1" ]; then
  "$ROOT/tests/run-e2e.sh" || FAIL=1
else
  echo "E2E は省略（GER_E2E=1 で実行。tests/run-e2e.sh）"
fi
[ "$FAIL" -eq 0 ] && echo "結果: OK" || echo "結果: FAIL"
exit "$FAIL"
