#!/usr/bin/env bash
# Runs every fuzz target (or the given ones) for SECONDS each, several at a
# time within the core budget, natively on the build host
# (docs/agents/testbed.md). Longer than scripts/fuzz-smoke.sh, and it does
# not stop at the first finding.
#
#   tools/testbed/fuzz.sh [SECONDS [TARGET...]]      (default 600 s, every target)
#
# * One `cargo fuzz build` of all targets, with binutils' C instrumented as
#   fuzz/README.md says (clang, coverage, AddressSanitizer, trapping UBSan).
# * Then one libFuzzer process per target, CARGO_BUILD_JOBS at a time. The
#   corpus of each target persists between runs in
#   $BK_TESTBED_STATE/fuzz/corpus/<target> (seeded from fuzz/corpus and
#   fuzz/regressions), so repeated runs go deeper.
# * Every crash, timeout or out-of-memory input lands in BK_OUT/crashes/,
#   one log per target in BK_OUT/fuzz/; failures.txt names each with its
#   reproduction command. Exit 1 when anything was found.
. "$(dirname "$0")/lib.sh"

secs=${1:-600}
[ $# -eq 0 ] || shift
case "$secs" in *[!0-9]*|"") echo "usage: tools/testbed/fuzz.sh [SECONDS [TARGET...]]" >&2; exit 2 ;; esac
cargo +nightly fuzz --version >/dev/null 2>&1 || { say "cargo-fuzz on nightly is needed"; exit 1; }

tdir="$TB_ROOT/target/testbed/fuzz"
if [ $# -gt 0 ]; then targets=("$@"); else
  # shellcheck disable=SC2207
  targets=($(cargo +nightly fuzz list --fuzz-dir fuzz))
fi
[ ${#targets[@]} -gt 0 ] || { tb_result "fuzz: no targets" </dev/null; exit 0; }

say "$(now) building ${#targets[@]} fuzz targets ($TB_CORES jobs)"
start=$(date +%s)
export CC=clang
export CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=bounds,null,vla-bound,return,unreachable,builtin -fno-omit-frame-pointer -g"
if ! timeout 3600 cargo +nightly fuzz build --fuzz-dir fuzz --target-dir "$tdir" > "$TB_OUT/fuzz-build.log" 2>&1; then
  tail -n 30 "$TB_OUT/fuzz-build.log"
  echo "build: cargo fuzz build failed" | tb_result "fuzz: the build failed"
  exit 1
fi
bin="$tdir/x86_64-unknown-linux-gnu/release"
built=$(($(date +%s) - start))
say "built in $(tb_dur "$built"); running each target for $secs s, $TB_CORES at a time"

mkdir -p "$TB_OUT/fuzz" "$TB_OUT/crashes"
export TB_OUT TB_STATE TB_ROOT bin secs
run_one() {
  t=$1
  corpus="$TB_STATE/fuzz/corpus/$t"; mkdir -p "$corpus"
  seeds=()
  for d in "$TB_ROOT/fuzz/corpus/$t" "$TB_ROOT/fuzz/regressions/$t"; do
    [ -d "$d" ] && [ -n "$(ls -A "$d")" ] && seeds+=("$d")
  done
  extra=()
  case "$t" in bk_binutils_sys_*) extra=(-max_len=512 -rss_limit_mb=1536) ;; *) extra=(-rss_limit_mb=2048) ;; esac
  ASAN_OPTIONS=detect_leaks=0 timeout -k 30 $((secs + 600)) "$bin/$t" "$corpus" "${seeds[@]}" \
    -max_total_time="$secs" -timeout=10 -detect_leaks=0 -print_final_stats=1 \
    -artifact_prefix="$TB_OUT/crashes/$t-" "${extra[@]}" > "$TB_OUT/fuzz/$t.log" 2>&1
  echo "$t $?" >> "$TB_OUT/fuzz/status.txt"
}
export -f run_one
: > "$TB_OUT/fuzz/status.txt"
printf '%s\n' "${targets[@]}" | xargs -P "$TB_CORES" -I{} bash -c 'run_one "$1"' _ {}

# Table: target, exit, executions, coverage, corpus size.
{
  printf '%-36s %4s %12s %8s %8s\n' target exit execs cov corpus
  for t in "${targets[@]}"; do
    code=$(awk -v t="$t" '$1 == t {print $2}' "$TB_OUT/fuzz/status.txt")
    execs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$TB_OUT/fuzz/$t.log" | tail -1)
    cov=$(grep -o 'cov: [0-9]*' "$TB_OUT/fuzz/$t.log" | tail -1 | cut -d' ' -f2)
    printf '%-36s %4s %12s %8s %8s\n' "$t" "${code:-?}" "${execs:--}" "${cov:--}" \
      "$(find "$TB_STATE/fuzz/corpus/$t" -type f | wc -l)"
  done
} | tee "$TB_OUT/fuzz/table.txt"

{
  for f in "$TB_OUT"/crashes/*; do
    [ -f "$f" ] || continue
    n=$(basename "$f"); t=unknown
    for c in "${targets[@]}"; do case "$n" in "$c"-*) t=$c ;; esac; done
    echo "fuzz $t: $n (cargo +nightly fuzz run --fuzz-dir fuzz $t <file>)"
  done
  awk '$2 != 0 {print "fuzz " $1 ": exit " $2 " (log fuzz/" $1 ".log)"}' "$TB_OUT/fuzz/status.txt"
} | tb_result "fuzz: ${#targets[@]} targets x $secs s on $TB_CORES cores, $(ls "$TB_OUT/crashes" | wc -l) findings ($(tb_dur $(($(date +%s) - start))))"
[ ! -s "$TB_OUT/failures.txt" ]
