#!/usr/bin/env bash
# Entry point of the nightly run on the build host (docs/agents/testbed.md).
# `scripts/remote.sh nightly install` copies tools/testbed to ~/bk/testbed/tools
# and puts this script in the user's crontab; `nightly run` starts it at once.
#
# It never runs twice at a time (flock), checks out the host's `master`
# (pushed by `scripts/remote.sh sync` from a checkout on master, or
# `scripts/remote.sh publish`) in ~/bk/nightly/wt, and runs that checkout's
# tools/testbed/nightly.sh — or, while master has none yet, the installed
# copy's.
set -euo pipefail
BK=$HOME/bk
[ ! -f "$HOME/.cargo/env" ] || . "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
mkdir -p "$BK/locks" "$BK/reports" "$BK/nightly"
boot_log="$BK/reports/boot.log"
[ ! -f "$boot_log" ] || [ "$(stat -c %s "$boot_log")" -lt 1000000 ] || mv "$boot_log" "$boot_log.old"
exec >> "$boot_log" 2>&1
echo "$(date -Is) nightly-boot starting"
exec 9>"$BK/locks/@nightly.lock"
flock -n 9 || { echo "$(date -Is) skipped: the previous nightly run is still going"; exit 0; }

sha=$(git -C "$BK/repo.git" rev-parse --verify -q refs/heads/master^{commit}) \
  || { echo "$(date -Is) no master on the build host (scripts/remote.sh publish)"; exit 1; }
wt="$BK/nightly/wt"
[ -d "$wt/.git" ] || git clone -q --shared --no-checkout "$BK/repo.git" "$wt"
git -C "$wt" -c advice.detachedHead=false checkout -q -f --detach "$sha"
git -C "$wt" clean -fdq
tools="$wt/tools/testbed"
[ -x "$tools/nightly.sh" ] || tools=$(cd "$(dirname "$0")" && pwd)
echo "$(date -Is) master $(git -C "$wt" log -1 --format='%h %s'), tools from $tools"
cd "$wt"
"$tools/nightly.sh" && code=0 || code=$?
echo "$(date -Is) nightly-boot done, exit $code"
exit "$code"
