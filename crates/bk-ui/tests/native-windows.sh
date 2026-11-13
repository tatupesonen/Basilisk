#!/usr/bin/env bash
# Checks native detached windows in the real application (macOS; needs a
# display and permission for System Events to send keys). Headless tests
# cannot open operating-system windows; this drives the binary's self-test
# (crates/bk-ui/src/shell/selftest.rs) and types G into the detached window.
#
#   crates/bk-ui/tests/native-windows.sh [path/to/basilisk]
#
# Settings live in a temporary folder, never in the user's own.
set -euo pipefail
bin="${1:-target/debug/basilisk}"
dir="$(mktemp -d "${TMPDIR:-/tmp}/bk-ui-native.XXXXXX")"
export BASILISK_UI_SELF_TEST_DIR="$dir"

BASILISK_UI_SELF_TEST=run "$bin" &
pid=$!
# Type G into the focused (detached) window while the self-test waits for it.
for _ in $(seq 1 600); do
  if [ -e "$dir/ready-for-keys" ]; then
    osascript -e "tell application \"System Events\" to set frontmost of (first process whose unix id is $pid) to true" >/dev/null 2>&1 || true
    sleep 0.5
    osascript -e 'tell application "System Events" to keystroke "g"' >/dev/null 2>&1 || true
    sleep 1
  fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.2
done
wait "$pid" || true

BASILISK_UI_SELF_TEST=restore "$bin" || true

cat "$dir/report-run.txt" "$dir/report-restore.txt"
grep -q '^PASS$' "$dir/report-run.txt" && grep -q '^PASS$' "$dir/report-restore.txt"
