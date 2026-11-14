#!/usr/bin/env bash
# Runs the property tests at a high case count (docs/agents/testbed.md).
#
#   tools/testbed/proptest.sh [CASES]          (default 1000000)
#
# Proptest reads PROPTEST_CASES only where a suite leaves the count to it:
# `ProptestConfig::with_cases(256)` or `cases: 512` in the source fixes the
# count and the variable changes nothing. So the suites are found in the
# source each time (files with `proptest!`): those that leave the count open
# run here at CASES (or the cap below), each bounded in time; those that fix
# it are listed in BK_OUT/fixed.txt and not run (the gate runs them).
#
# Optimised build with debug assertions and overflow checks on (an overflow
# is a panic, as in the gate), in target/testbed/proptest. A failure's
# proptest-regressions file is copied to BK_OUT/regressions/.
# Environment: BK_PROPTEST_TIMEOUT (seconds per suite, default 1500).
. "$(dirname "$0")/lib.sh"

cases=${1:-1000000}
per=${BK_PROPTEST_TIMEOUT:-1500}
# Suites that cannot bear the full count in the time bound, measured on the
# build host: "<crate> <target> <cases>".
caps="
"
cap_for() { printf '%s\n' "$caps" | awk -v c="$1" -v t="$2" '$1 == c && $2 == t {print $3}'; }

: > "$TB_OUT/fixed.txt"
suites=()
while IFS= read -r f; do
  crate=${f#crates/}; crate=${crate%%/*}
  if grep -Eq 'with_cases\( *[0-9_]+ *\)|cases: *[0-9_]+' "$f"; then
    echo "$f: $(grep -Eo 'with_cases\( *[0-9_]+ *\)|cases: *[0-9_]+' "$f" | tr '\n' ' ')" >> "$TB_OUT/fixed.txt"
    continue
  fi
  case "$f" in
    crates/*/tests/*/*) continue ;;                        # a module of another test target
    crates/*/tests/*.rs) t=$(basename "$f" .rs); suites+=("$crate --test $t") ;;
    *) suites+=("$crate --lib") ;;
  esac
done < <(grep -rl --include='*.rs' 'proptest!' crates | LC_ALL=C sort)
# shellcheck disable=SC2207
IFS=$'\n' suites=($(printf '%s\n' "${suites[@]}" | LC_ALL=C sort -u)); unset IFS

export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true
export CARGO_TARGET_DIR="$TB_ROOT/target/testbed/proptest"
say "$(now) ${#suites[@]} suites at up to $cases cases ($TB_CORES threads, $per s each); fixed counts: $(wc -l < "$TB_OUT/fixed.txt") files"
start=$(date +%s)
if ! timeout 3600 cargo build --release --tests --workspace --all-features --locked --quiet > "$TB_OUT/build.log" 2>&1; then
  tail -n 30 "$TB_OUT/build.log"
  echo "build: cargo build --release --tests failed" | tb_result "proptest: the build failed"
  exit 1
fi
: > "$TB_OUT/table.txt"; : > "$TB_OUT/fails.tmp"
for s in "${suites[@]}"; do
  read -r crate kind target <<< "$s"
  n=$(cap_for "$crate" "${target:---lib}"); n=${n:-$cases}
  name="$crate ${kind}${target:+ $target}"
  log="$TB_OUT/$crate-${target:-lib}.log"
  t0=$(date +%s)
  # shellcheck disable=SC2086
  PROPTEST_CASES=$n timeout -k 30 "$per" cargo test --release --all-features --locked -p "$crate" $kind $target \
    -- --test-threads="$TB_CORES" > "$log" 2>&1 && code=0 || code=$?
  dt=$(($(date +%s) - t0))
  case $code in
    0) r=pass ;;
    124) r="timeout after $per s"; echo "proptest -p $name: timed out at $n cases" >> "$TB_OUT/fails.tmp" ;;
    *) r=FAIL
       tb_failed "$log" | sed "s/^/proptest /; s/\$/ (PROPTEST_CASES=$n)/" > "$TB_OUT/one.tmp"
       [ -s "$TB_OUT/one.tmp" ] || echo "proptest -p $name: exit $code" > "$TB_OUT/one.tmp"
       cat "$TB_OUT/one.tmp" >> "$TB_OUT/fails.tmp" ;;
  esac
  printf '%-48s %9s cases %8s  %s\n' "$name" "$n" "$(tb_dur "$dt")" "$r" | tee -a "$TB_OUT/table.txt"
done

mkdir -p "$TB_OUT/regressions"
{ git status --porcelain --untracked-files=all | awk '{print $2}' | grep 'proptest-regressions' || true; } \
  | while IFS= read -r f; do cp --parents "$f" "$TB_OUT/regressions/"; done
nf=$(wc -l < "$TB_OUT/fails.tmp")
tb_result "proptest: ${#suites[@]} suites at up to $cases cases, $nf failed ($(tb_dur $(($(date +%s) - start))))" < "$TB_OUT/fails.tmp"
rm -f "$TB_OUT/fails.tmp" "$TB_OUT/one.tmp"
[ "$nf" -eq 0 ]
