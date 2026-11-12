#!/usr/bin/env bash
# Runs the cargo-fuzz targets in fuzz/ (see fuzz/README.md).
#
#   scripts/fuzz.sh [-t seconds] [target ...]
#
# With no target, every target listed in fuzz/Cargo.toml runs in turn. Each
# runs for the given time (default 60 s, the acceptance bar of the feature
# specs) on a corpus under fuzz/corpus/<target>, seeded from
# fuzz/seeds/<target> and fuzz/regressions/<target> when they exist. A crash
# leaves its input in fuzz/artifacts/<target>/; copy it to
# fuzz/regressions/<target>/ once fixed. Prints one summary line per target
# and exits non-zero if any target failed.
set -uo pipefail
cd "$(dirname "$0")/.."

seconds=60
if [ "${1:-}" = "-t" ]; then
  seconds="$2"
  shift 2
fi

if [ "$#" -gt 0 ]; then
  targets=("$@")
else
  read -r -a targets <<< "$(cargo +nightly fuzz list --fuzz-dir fuzz | tr '\n' ' ')"
fi

mkdir -p fuzz/artifacts
failed=0
for target in "${targets[@]}"; do
  corpus="fuzz/corpus/$target"
  mkdir -p "$corpus" "fuzz/artifacts/$target"
  extra=()
  for dir in "fuzz/seeds/$target" "fuzz/regressions/$target"; do
    [ -d "$dir" ] && extra+=("$dir")
  done
  log="fuzz/artifacts/$target.log"
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  cargo +nightly fuzz run --fuzz-dir fuzz "$target" "$corpus" "${extra[@]}" -- \
    -max_total_time="$seconds" -print_final_stats=1 > "$log" 2>&1
  status=$?
  runs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$log" | grep -o '[0-9]*$' | tail -1)
  corpus_size=$(find "$corpus" -type f | wc -l | tr -d ' ')
  if [ "$status" -eq 0 ]; then
    result=ok
  else
    result="FAILED (exit $status, see $log)"
    failed=1
  fi
  echo "fuzz: $started $target ${seconds} s, ${runs:-?} runs, corpus $corpus_size: $result"
done
exit "$failed"
