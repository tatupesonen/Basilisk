# Shared helpers for the testbed checks (docs/agents/testbed.md). Sourced by
# the scripts in tools/testbed/, which run on the build host from a checkout
# of the repository (the current directory).
#
# Contract of every check script:
#   * the current directory is the checkout under test;
#   * CARGO_BUILD_JOBS is the core budget (default 12);
#   * BK_OUT is a directory for its results (default target/testbed/out):
#     it writes `summary.txt` (one line), `failures.txt` (one identifier per
#     failure, sorted, for the nightly comparison) and any files worth
#     keeping (crash inputs, logs); remote.sh copies BK_OUT back;
#   * its exit status is 0 only when everything passed.
set -euo pipefail

TB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TB_ROOT=$PWD
[ -f "$TB_ROOT/Cargo.toml" ] && [ -d "$TB_ROOT/crates" ] || {
  echo "testbed: run from the root of a Basilisk checkout" >&2; exit 2; }
TB_CORES=${CARGO_BUILD_JOBS:-12}
TB_STATE=${BK_TESTBED_STATE:-$HOME/bk/testbed}
TB_OUT=${BK_OUT:-$TB_ROOT/target/testbed/out}
mkdir -p "$TB_STATE" "$TB_OUT"
TB_OUT=$(cd "$TB_OUT" && pwd)
export CARGO_TERM_COLOR=never

say() { printf 'testbed: %s\n' "$*"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
toolchain() { sed -n 's/^channel *= *"\(.*\)"/\1/p' "$TB_ROOT/rust-toolchain.toml"; }

# Writes the result files: tb_result "<summary line>" (failures from stdin).
tb_result() {
  printf '%s\n' "$1" > "$TB_OUT/summary.txt"
  LC_ALL=C sort -u > "$TB_OUT/failures.txt"
  say "result: $1"
}

# Summarises a `cargo test` log. tb_counts LOG prints
# "N passed, N failed, N ignored"; tb_failed LOG prints one line per failing
# test, "-p <crate> --test <target> <test>" (what reproduces it, as cargo
# names the target), a whole target that failed without naming a test
# (a crash), and compile failures.
tb_counts() {
  awk '/^test result:/ {p += $4; f += $6; i += $8}
       END {printf "%d passed, %d failed, %d ignored", p, f, i}' "$1"
}
tb_failed() {
  awk '
    /^failures:$/ { inlist = 1; n = 0; next }
    /^---- / || /^test result:/ { inlist = 0 }
    inlist && /^    [^ ]+$/ { sub(/^ +/, ""); names[++n] = $0; next }
    /^error: test failed, to rerun pass `/ {
      t = $0; sub(/.*pass `/, "", t); sub(/`.*/, "", t)
      for (i = 1; i <= n; i++) print t " " names[i]
      if (n == 0) print t " (the test binary failed)"
      n = 0; inlist = 0
    }
    /^error: (could not compile|failed to run custom build command)/ { print "build: " $0 }
  ' "$1" | LC_ALL=C sort -u
}

# Builds tools/testbed/<name>/Dockerfile once per content and toolchain and
# prints the image tag. Images carry the label bk-testbed for pruning.
tb_image() {
  local dir="$TB_DIR/$1" chan hash tag
  chan=$(toolchain)
  hash=$( (cat "$dir/Dockerfile"; echo "$chan") | sha256sum | cut -c1-12)
  tag="bk-testbed-$1:$hash"
  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    say "building image $tag (Rust $chan)" >&2
    timeout 3600 docker build -q --label bk-testbed=1 --build-arg RUST_CHANNEL="$chan" \
      -t "$tag" "$dir" >&2
  fi
  printf '%s\n' "$tag"
}

# Runs a container bounded in time, cores and memory, as the calling user,
# and removes it however this script ends:
#   tb_docker <name> <seconds> <docker-run-args...> <image> <command...>
TB_CONTAINERS=()
tb_cleanup() {
  local c
  for c in "${TB_CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
}
trap tb_cleanup EXIT
trap 'exit 143' TERM INT HUP
tb_docker() {
  local name="bk-testbed-$1-$$" secs=$2; shift 2
  TB_CONTAINERS+=("$name")
  timeout -k 30 "$secs" docker run --rm --init --name "$name" \
    --cpus="$TB_CORES" --memory="${BK_TESTBED_MEMORY:-16g}" \
    --user "$(id -u):$(id -g)" --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS="$TB_CORES" -e RUST_TEST_THREADS="$TB_CORES" \
    -e CARGO_TERM_COLOR=never -e HOME=/tmp "$@"
}

# Seconds as "1h02m03s".
tb_dur() { local s=$1; printf '%dh%02dm%02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60)); }
