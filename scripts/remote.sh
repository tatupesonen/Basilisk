#!/usr/bin/env bash
# Runs the quality gate and other commands on the project's Linux build host
# (docs/agents/remote-build.md). Works from any worktree; sends the committed
# HEAD only.
#
#   scripts/remote.sh setup                     install toolchains, create ~/bk, build the reference tools
#   scripts/remote.sh sync                      send HEAD and check it out in ~/bk/wt/<branch>
#   scripts/remote.sh gate [--no-ref]           sync, run scripts/gate.sh there; log in gate-remote.log
#   scripts/remote.sh run [--no-ref] -- CMD...  sync, run CMD in the remote checkout
#   scripts/remote.sh log                       reattach to (or fetch) this branch's latest job
#   scripts/remote.sh status                    disk, load, checkouts and their sizes
#   scripts/remote.sh clean BRANCH|--merged|--all|--target BRANCH
# Testbed (docs/agents/testbed.md; the work is in tools/testbed/):
#   scripts/remote.sh wine [--no-ref] [--msvc] [-- CARGO-TEST-ARGS]   Windows tests under Wine
#   scripts/remote.sh ubuntu [--no-ref]          C crates + reference tools, Ubuntu 26.04, GCC 15
#   scripts/remote.sh arm64 [--no-ref] [-- CARGO-TEST-ARGS]  Linux AArch64 tests under qemu-user
#   scripts/remote.sh long [--no-ref] miri|fuzz [SECONDS [TARGET...]]|proptest [CASES]|sanitizers|differential|all
#   scripts/remote.sh publish                    send local master to the host (what the nightly run tests)
#   scripts/remote.sh nightly install|remove|run [ITEM...]|status
#   scripts/remote.sh report [--all|DATE]        the nightly report (latest, list, or one day)
#
# Configuration: BK_REMOTE (ssh destination) and BK_REMOTE_KEY (identity file)
# from the environment, else from $BK_REMOTE_CONFIG (default
# ~/.config/basilisk/remote, lines KEY=VALUE). Without a destination the
# script exits 2: run scripts/gate.sh locally instead.
# Also: BK_REMOTE_JOBS (CARGO_BUILD_JOBS there, default 20), BK_REMOTE_TIMEOUT
# (seconds for gate/run, default 5400), BK_TESTBED_CORES (core budget of the
# testbed commands, default 12), BK_TESTBED_TIMEOUT (their bound; default
# 5400 for wine/ubuntu/arm64, 14400 for long).
set -euo pipefail

die() { printf 'remote: %s\n' "$*" >&2; exit 1; }
# Bounds a local command to N seconds (macOS has no `timeout`); the alarm
# survives exec.
bounded() { local s=$1; shift; perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "$s" "$@"; }

conf="${BK_REMOTE_CONFIG:-$HOME/.config/basilisk/remote}"
if [ -r "$conf" ]; then
  while IFS='=' read -r k v; do
    case "$k" in BK_REMOTE|BK_REMOTE_KEY|BK_REMOTE_JOBS|BK_REMOTE_TIMEOUT|BK_TESTBED_CORES|BK_TESTBED_TIMEOUT) ;; *) continue ;; esac
    v="${v/#\~/$HOME}"
    [ -n "${!k:-}" ] || printf -v "$k" '%s' "$v"
  done < "$conf"
fi
if [ -z "${BK_REMOTE:-}" ]; then
  echo "remote: no build host configured (set BK_REMOTE, or write $conf); run scripts/gate.sh locally" >&2
  exit 2
fi
JOBS="${BK_REMOTE_JOBS:-20}"
TMO="${BK_REMOTE_TIMEOUT:-5400}"
TB_JOBS="${BK_TESTBED_CORES:-12}"

ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
[ -z "${BK_REMOTE_KEY:-}" ] || ssh_opts+=(-i "$BK_REMOTE_KEY" -o IdentitiesOnly=yes)

top=$(git rev-parse --show-toplevel 2>/dev/null) || die "run inside a Basilisk worktree"
cd "$top"
branch=$(git symbolic-ref -q --short HEAD || echo "detached-$(git rev-parse --short=10 HEAD)")
slug=$(printf '%s' "$branch" | tr -c 'A-Za-z0-9._-' '-')

# The remote half. Sent on stdin to `bash -s` with its arguments set first;
# everything is inside one function so that nothing it runs reads the rest of
# the script from stdin.
read -r -d '' REMOTE_LIB <<'EOF' || true
bk() {
set -euo pipefail
BK="$HOME/bk"
[ ! -f "$HOME/.cargo/env" ] || . "$HOME/.cargo/env"
lock() {  # one sync, gate or run per branch at a time; the job inherits fd 9
  mkdir -p "$BK/locks"; exec 9>"$BK/locks/$1.lock"
  flock -n 9 || { echo "remote: branch $1 is busy on the build host (a sync, gate or run of it is in progress)" >&2; exit 75; }
}
checkout() {
  wt="$BK/wt/$1"
  [ -d "$wt/.git" ] || git clone -q --shared --no-checkout "$BK/repo.git" "$wt"
  git -C "$wt" -c advice.detachedHead=false checkout -q -f --detach "$2"
  git -C "$wt" clean -fdq
  echo "remote: $1 at $(git -C "$wt" log -1 --format='%h %s')"
}
op=$1; shift
case "$op" in
setup)
  mkdir -p "$BK/wt" "$BK/logs" "$BK/locks"
  if [ ! -d "$BK/repo.git" ]; then
    git init -q --bare "$BK/repo.git"
    git -C "$BK/repo.git" config gc.auto 0   # the checkouts borrow its objects
    git -C "$BK/repo.git" config receive.autogc false
  fi
  if [ ! -x "$HOME/.cargo/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none
  fi
  . "$HOME/.cargo/env"
  rustup toolchain install "$1" --profile minimal -c clippy -c rustfmt
  rustup toolchain install nightly --profile minimal -c miri -c rust-src
  rustup default "$1" >/dev/null
  cargo deny --version 2>/dev/null | grep -qx 'cargo-deny 0.20.2' || cargo install --locked cargo-deny --version 0.20.2
  cargo fuzz --version 2>/dev/null | grep -qx 'cargo-fuzz 0.13.2' || cargo install --locked cargo-fuzz --version 0.13.2
  rustup show active-toolchain; cargo deny --version; cargo fuzz --version
  ;;
checkout) lock "$1"; checkout "$1" "$2" ;;
start)  # slug sha mode timeout jobs ref|noref cmd...
  slug=$1 sha=$2 mode=$3 tmo=$4 jobs=$5 ref=$6; shift 6
  lock "$slug"
  free=$(df -Pk "$BK" | awk 'NR==2 {print int($4 / 1048576)}')
  [ "$free" -ge 40 ] || { echo "remote: only $free GB free on the build host; scripts/remote.sh clean first" >&2; exit 1; }
  checkout "$slug" "$sha" >&2
  mkdir -p "$BK/logs/$slug"
  log="$BK/logs/$slug/$(date +%Y%m%d-%H%M%S)-$mode.log"
  find "$BK/logs/$slug" -type f -mtime +14 -delete
  # Temporary files (gate.sh keeps its test log there) stay under ~/bk.
  mkdir -p "$BK/tmp/$slug"
  export CARGO_BUILD_JOBS="$jobs" CARGO_TERM_COLOR=never TMPDIR="$BK/tmp/$slug"
  if [ "$ref" = ref ]; then
    export BASILISK_GHIDRA_DIR="$HOME/basilisk-ref/ghidra" BASILISK_REFERENCE_DIR="$BK/reference"
  else
    unset BASILISK_GHIDRA_DIR BASILISK_REFERENCE_DIR
  fi
  cd "$wt"
  # Results a job wants copied back (the testbed checks) go to BK_OUT.
  export BK_OUT="${log%.log}.out"
  mkdir -p "$BK_OUT"
  # The testbed's checks run below normal priority so that the gates of
  # agents working at the same time keep the machine's attention.
  nice=0; case "$mode" in gate|run|reference) ;; *) nice=10 ;; esac
  # Detached from the ssh session and bounded: a dropped connection neither
  # stops the job nor leaves it running for ever. timeout signals the whole
  # process group. First, inside the job so its reason lands in the log:
  # every platform's crates (the gate's `cargo deny --offline` reads the
  # metadata of all of them, and a build downloads only the host's).
  setsid nohup bash -c '
    echo "$$" > "$2.pid"
    if ! out=$(timeout 600 cargo fetch --locked 2>&1); then
      echo "remote: cargo fetch --locked failed (the job goes on; offline steps such as cargo deny may then fail):"
      printf "%s\n" "$out" | grep -v "^ *\(Downloaded\|Downloading\|Updating\|Locking\) " | tail -n 8 | sed "s/^/remote:   /"
    fi
    timeout -k 60 "$1" nice -n "$3" "${@:4}"; echo $? > "$2.exit"' \
    bk-job "$tmo" "$log" "$nice" "$@" </dev/null >"$log" 2>&1 &
  echo "$log"
  ;;
wait)  # log timeout: stream the log until the job ends, then print its exit code last
  log=$1
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$log.pid" ] && break; sleep 1; done
  timeout "$2" tail -n +1 -F --pid="$(cat "$log.pid")" "$log" 2>/dev/null || true
  echo "@@exit $(cat "$log.exit" 2>/dev/null || echo 255)"
  ;;
latest) ls -t "$BK/logs/$1"/*.log 2>/dev/null | head -1 ;;
status)
  df -h "$BK" | tail -1 | awk '{print "disk: " $4 " free of " $2}'
  echo "load: $(cut -d' ' -f1-3 /proc/loadavg)  memory: $(free -g | awk '/Mem:/ {print $7 " GB available of " $2}')"
  for d in "$BK"/wt/*/; do
    [ -d "$d" ] || continue
    s=$(basename "$d")
    busy=idle; (flock -n 9 || exit 1) 9>"$BK/locks/$s.lock" || busy=busy
    printf '%-32s %-5s %-8s target %s\n' "$s" "$busy" "$(git -C "$d" rev-parse --short HEAD)" \
      "$(du -sh "$d/target" 2>/dev/null | cut -f1 || echo -)"
  done
  [ ! -f "$BK/reference/STAMP" ] || echo "reference: $BK/reference ($(sed -n 's/^generated: //p' "$BK/reference/STAMP"))"
  ;;
heads) for d in "$BK"/wt/*/; do [ -d "$d" ] && echo "$(basename "$d") $(git -C "$d" rev-parse HEAD)"; done; true ;;
pack)  # a job's results directory as a tar stream on stdout (nothing when empty)
  case "$1" in "$BK"/logs/*.out) ;; *) exit 2 ;; esac
  [ -d "$1" ] && [ -n "$(ls -A "$1")" ] && tar -C "$1" -czf - . || true
  ;;
clean-target)  # slug: build output only, the checkout stays
  lock "$1"; rm -rf "${BK:?}/wt/$1/target" "$BK/tmp/$1"; echo "remote: removed the build output of $1"
  ;;
nightly-install)  # slug schedule: the branch's tools/testbed becomes the installed copy
  [ -d "$BK/wt/$1/tools/testbed" ] || { echo "remote: $1 has no tools/testbed" >&2; exit 1; }
  mkdir -p "$BK/testbed" "$BK/reports"
  rm -rf "$BK/testbed/tools.new"; cp -r "$BK/wt/$1/tools/testbed" "$BK/testbed/tools.new"
  rm -rf "$BK/testbed/tools"; mv "$BK/testbed/tools.new" "$BK/testbed/tools"
  { crontab -l 2>/dev/null | grep -v '# basilisk-testbed$' || true
    echo "$2 $BK/testbed/tools/nightly-boot.sh >/dev/null 2>&1 # basilisk-testbed"; } | crontab -
  echo "remote: installed the nightly run from $1 ($(git -C "$BK/wt/$1" log -1 --format=%h)): $2 (host time, $(date +%Z))"
  ;;
nightly-remove)
  { crontab -l 2>/dev/null | grep -v '# basilisk-testbed$' || true; } | crontab -
  echo "remote: the nightly run is no longer scheduled (reports kept in $BK/reports)"
  ;;
nightly-run)  # [items]: a run now, optionally with BK_NIGHTLY_ITEMS
  [ -x "$BK/testbed/tools/nightly-boot.sh" ] || { echo "remote: not installed (scripts/remote.sh nightly install)" >&2; exit 1; }
  [ -z "${1:-}" ] || export BK_NIGHTLY_ITEMS="$*"
  setsid nohup "$BK/testbed/tools/nightly-boot.sh" </dev/null >/dev/null 2>&1 &
  echo "remote: nightly run started; scripts/remote.sh report shows its report when it ends"
  ;;
nightly-status)
  crontab -l 2>/dev/null | grep '# basilisk-testbed$' || echo "not scheduled"
  (flock -n 9 || exit 1) 9>"$BK/locks/@nightly.lock" && echo "idle" || echo "running: $(cat "$BK/reports/current" 2>/dev/null)"
  { ls "$BK/reports"/*.txt 2>/dev/null || true; } | tail -1 | sed 's/^/latest report: /'
  ;;
report)  # [--all|DATE]
  case "${1:-}" in
    --all) for f in "$BK"/reports/*.txt; do [ -f "$f" ] && echo "$(basename "$f" .txt)  $(sed -n 's/^overall: //p' "$f")"; done; true ;;
    "") f=$(ls "$BK"/reports/*.txt 2>/dev/null | tail -1); [ -n "$f" ] || { echo "remote: no report yet" >&2; exit 1; }; cat "$f" ;;
    *) cat "$BK/reports/$1.txt" ;;
  esac
  ;;
clean)  # slug...
  for s in "$@"; do
    ( lock "$s"; rm -rf "${BK:?}/wt/$s" "$BK/logs/$s" "$BK/tmp/$s"
      for r in $(git -C "$BK/repo.git" for-each-ref --format='%(refname)' refs/heads); do
        if [ "$(printf '%s' "${r#refs/heads/}" | tr -c 'A-Za-z0-9._-' '-')" = "$s" ]; then
          git -C "$BK/repo.git" update-ref -d "$r"
        fi
      done
      rm -f "$BK/locks/$s.lock"; echo "remote: removed $s" ) || true
  done
  ;;
*) echo "remote: unknown remote op $op" >&2; exit 2 ;;
esac
}
EOF

# Runs one op of the remote half: rcall SECONDS op args...
rcall() {
  local s=$1; shift
  { printf 'set --'; printf ' %q' "$@"; printf '\n%s\nbk "$@" </dev/null\n' "$REMOTE_LIB"; } \
    | bounded "$s" ssh "${ssh_opts[@]}" "$BK_REMOTE" bash -s
}

push_head() {
  local sha
  sha=$(git rev-parse HEAD)
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "remote: the worktree has uncommitted changes; sending only the committed HEAD ($(git rev-parse --short HEAD))" >&2
  fi
  GIT_SSH_COMMAND="ssh$(printf ' %q' "${ssh_opts[@]}")" \
    bounded 600 git push -q --force "$BK_REMOTE:bk/repo.git" "$sha:refs/heads/$branch" \
    || die "push to the build host failed (is it up? scripts/remote.sh setup done?)"
  echo "$sha"
}

# Streams a job's log (to stdout) until it ends; returns the job's exit code.
follow() {
  local log=$1 code=255 line
  while IFS= read -r line; do
    case "$line" in "@@exit "*) code=${line#@@exit } ;; *) printf '%s\n' "$line" ;; esac
  done < <(rcall $((TMO + 900)) wait "$log" $((TMO + 600)) || true)
  return "$code"
}

lost() {
  echo "remote: lost the connection; the job goes on on the build host (bounded by ${TMO} s)." >&2
  echo "remote: scripts/remote.sh log  reattaches and fetches its output" >&2
}

start_job() {  # mode ref cmd...
  local mode=$1 ref=$2 sha log; shift 2
  sha=$(push_head)
  log=$(rcall 900 start "$slug" "$sha" "$mode" "$TMO" "$JOBS" "$ref" "$@") || exit $?
  [ -n "$log" ] || die "the job did not start"
  printf '%s' "$log"
}

# Copies a job's results directory (BK_OUT there) to target/testbed/<job>/.
fetch_out() {
  local dest
  dest="target/testbed/$(basename "${1%.log}")"
  mkdir -p "$dest"
  rcall 600 pack "${1%.log}.out" | tar -xzf - -C "$dest" 2>/dev/null || true
  if [ -n "$(ls -A "$dest")" ]; then
    echo "remote: results in $dest"
    [ ! -f "$dest/summary.txt" ] || sed 's/^/remote: /' "$dest/summary.txt"
  else
    rmdir "$dest"
  fi
}

# A testbed job: testbed_job MODE REF CMD... (log in MODE-remote.log).
testbed_job() {
  local mode=$1 r=$2 log code; shift 2
  JOBS=$TB_JOBS
  log=$(start_job "$mode" "$r" "$@")
  echo "remote: $mode of $branch running on the build host ($JOBS cores, ${TMO} s bound, reference: $r); log: $mode-remote.log"
  set +e; follow "$log" > "$mode-remote.log"; code=$?; set -e
  tail -n 25 "$mode-remote.log"
  [ "$code" -ne 255 ] || lost
  [ "$code" -eq 255 ] || fetch_out "$log"
  echo "remote: $mode exit $code"
  exit "$code"
}

ref=ref
cmd=${1:-}
[ $# -eq 0 ] || shift
if [ "${1:-}" = --no-ref ]; then ref=noref; shift; fi

case "$cmd" in
setup)
  chan=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
  [ -n "$chan" ] || die "no channel in rust-toolchain.toml"
  rcall 3600 setup "$chan"
  # The reference tools (ADR-007), built natively by the repository's own
  # script into ~/bk/reference; incremental, so a rerun with nothing changed
  # is quick.
  TMO=5400; log=$(start_job reference ref scripts/build-reference.sh --jobs 20)
  set +e; follow "$log"; code=$?; set -e
  [ "$code" -ne 255 ] || lost
  exit "$code"
  ;;
sync)
  sha=$(push_head)
  rcall 300 checkout "$slug" "$sha"
  ;;
gate)
  log=$(start_job gate "$ref" scripts/gate.sh)
  echo "remote: gate of $branch running on the build host (CARGO_BUILD_JOBS=$JOBS, ${TMO} s bound, reference: $ref); log: gate-remote.log"
  set +e; follow "$log" > gate-remote.log; code=$?; set -e
  tail -n 25 gate-remote.log
  [ "$code" -ne 255 ] || lost
  echo "remote: gate exit $code"
  exit "$code"
  ;;
run)
  [ "${1:-}" = -- ] && shift
  [ $# -gt 0 ] || die "usage: scripts/remote.sh run [--no-ref] -- COMMAND..."
  log=$(start_job run "$ref" "$@")
  set +e; follow "$log"; code=$?; set -e
  [ "$code" -ne 255 ] || lost
  exit "$code"
  ;;
log)
  log=$(rcall 60 latest "$slug")
  [ -n "$log" ] || die "no job of $branch on the build host"
  echo "remote: $log" >&2
  set +e
  mode=$(basename "$log" .log); mode=${mode#*-*-}
  case "$mode" in long-*) TMO=${BK_TESTBED_TIMEOUT:-14400} ;; wine*|ubuntu|arm64) TMO=${BK_TESTBED_TIMEOUT:-5400} ;; esac
  case "$mode" in
    run|reference) follow "$log"; code=$? ;;
    *) follow "$log" > "$mode-remote.log"; code=$?; tail -n 25 "$mode-remote.log" ;;
  esac
  [ "$code" -eq 255 ] || [ "$mode" = gate ] || fetch_out "$log"
  echo "remote: exit $code" >&2
  exit "$code"
  ;;
status) rcall 300 status ;;
clean)
  case "${1:-}" in
    "") die "usage: scripts/remote.sh clean BRANCH|--merged|--all|--target BRANCH" ;;
    --target)
      [ -n "${2:-}" ] || die "usage: scripts/remote.sh clean --target BRANCH"
      rcall 600 clean-target "$(printf '%s' "$2" | tr -c 'A-Za-z0-9._-' '-')"; exit ;;
    --all) victims=$(rcall 60 heads | cut -d' ' -f1) ;;
    --merged)
      victims=$(rcall 60 heads | while read -r s h; do
        git merge-base --is-ancestor "$h" master 2>/dev/null && echo "$s"; done; true) ;;
    *) victims=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-') ;;
  esac
  [ -n "$victims" ] || { echo "remote: nothing to clean"; exit 0; }
  # shellcheck disable=SC2086
  rcall 600 clean $victims
  ;;
wine)
  flavour=wine
  if [ "${1:-}" = --msvc ]; then flavour=wine-msvc; shift; fi
  [ "${1:-}" != -- ] || shift
  TMO=${BK_TESTBED_TIMEOUT:-5400}
  if [ "$flavour" = wine ]; then testbed_job wine "$ref" tools/testbed/wine.sh "$@"
  else testbed_job wine-msvc "$ref" tools/testbed/wine.sh --msvc "$@"; fi
  ;;
ubuntu)
  [ "${1:-}" != -- ] || shift
  TMO=${BK_TESTBED_TIMEOUT:-5400}
  testbed_job ubuntu "$ref" tools/testbed/ubuntu.sh "$@"
  ;;
arm64)
  [ "${1:-}" != -- ] || shift
  TMO=${BK_TESTBED_TIMEOUT:-5400}
  testbed_job arm64 "$ref" tools/testbed/arm64.sh "$@"
  ;;
long)
  what=${1:-}; [ $# -eq 0 ] || shift
  case "$what" in miri|fuzz|proptest|sanitizers|differential|all) ;;
    *) die "usage: scripts/remote.sh long [--no-ref] miri|fuzz [SECONDS [TARGET...]]|proptest [CASES]|sanitizers|differential|all" ;; esac
  TMO=${BK_TESTBED_TIMEOUT:-14400}
  testbed_job "long-$what" "$ref" tools/testbed/long.sh "$what" "$@"
  ;;
publish)  # local master becomes the host's master, which the nightly run tests
  sha=$(git rev-parse --verify -q master^{commit}) || die "no local master"
  GIT_SSH_COMMAND="ssh$(printf ' %q' "${ssh_opts[@]}")" \
    bounded 600 git push -q --force "$BK_REMOTE:bk/repo.git" "$sha:refs/heads/master" \
    || die "push to the build host failed"
  echo "remote: master on the build host is now $(git log -1 --format='%h %s' "$sha")"
  ;;
nightly)
  case "${1:-}" in
    install)
      sha=$(push_head); rcall 300 checkout "$slug" "$sha" >/dev/null
      rcall 120 nightly-install "$slug" "${2:-30 1 * * *}" ;;
    run) shift; rcall 120 nightly-run "$@" ;;
    remove|status) rcall 120 "nightly-$1" ;;
    *) die "usage: scripts/remote.sh nightly install [CRON-SCHEDULE]|remove|run [ITEM...]|status" ;;
  esac
  ;;
report) rcall 120 report "${1:-}" ;;
*) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; [ "$cmd" = help ] || [ "$cmd" = -h ] || exit 2 ;;
esac
