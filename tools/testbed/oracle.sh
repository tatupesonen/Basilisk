#!/usr/bin/env bash
# The decompiler oracle's nightly item (docs/features/decomp-oracle.md 4.14):
# brings the host's reference tools up to date (scripts/build-reference.sh
# is incremental: nothing is rebuilt unless its inputs changed), captures
# every corpus twice with bk-oracle (the two captures must be identical),
# and reports the drift of the capture against fixtures/decomp-oracle, by
# file. Needs BASILISK_GHIDRA_DIR and BASILISK_REFERENCE_DIR.
#
# Results in BK_OUT: summary.txt, failures.txt (one line per error, per
# nondeterministic capture file and per drifting fixture entry),
# capture-summary.txt, captures.<library>.txt, check.txt, the logs.
. "$(dirname "$0")/lib.sh"

if [ -z "${BASILISK_REFERENCE_DIR:-}" ] || [ -z "${BASILISK_GHIDRA_DIR:-}" ]; then
  echo "oracle: needs BASILISK_GHIDRA_DIR and BASILISK_REFERENCE_DIR (run without --no-ref)" \
    | tb_result "oracle: no reference (not run)"
  exit 1
fi

t0=$(date +%s)
build_status=0
timeout 3000 scripts/build-reference.sh --jobs "$TB_CORES" > "$TB_OUT/build-reference.log" 2>&1 || build_status=$?
if [ "$build_status" -ne 0 ]; then
  tail -n 20 "$TB_OUT/build-reference.log"
  echo "oracle build-reference exit $build_status" | tb_result "oracle: build-reference.sh failed (exit $build_status)"
  exit 1
fi

cap=$TB_OUT/cap
capture_status=0
timeout 3000 cargo run -q --locked -p bk-testkit --bin bk-oracle -- capture all "$cap" --runs 2 --jobs "$TB_CORES" \
  > "$TB_OUT/capture.log" 2>&1 || capture_status=$?
check_status=0
if [ -f "$cap/summary.txt" ]; then
  cargo run -q --locked -p bk-testkit --bin bk-oracle -- check "$cap" fixtures/decomp-oracle \
    > "$TB_OUT/check.txt" 2>&1 || check_status=$?
  cp "$cap/summary.txt" "$TB_OUT/capture-summary.txt"
  cp "$cap"/captures.*.txt "$TB_OUT/" 2>/dev/null || true
fi
# The captures themselves are large and regenerated every night.
rm -rf "$cap/run1" "$cap/run2"

{
  sed -n 's/^error: \(.*\)$/oracle error \1/p' "$TB_OUT/capture.log"
  awk '/differs from run 1/ {d = 1; next} d && /^  / {sub(/^  /, ""); print "oracle nondeterministic " $0; next} {d = 0}' "$TB_OUT/capture.log"
  sed -n 's/^  \(changed\|gone\|new\) *\(.*\)$/oracle drift \1 \2/p' "$TB_OUT/check.txt" 2>/dev/null
  grep -q '^summary.txt: drift' "$TB_OUT/check.txt" 2>/dev/null && echo "oracle drift summary.txt"
  [ "$capture_status" -eq 0 ] || [ -f "$cap/summary.txt" ] || echo "oracle capture exit $capture_status"
  true
} | tb_result "oracle: $(tail -n 1 "$cap/summary.txt" 2>/dev/null | cut -f2- | tr '\t' ' '), capture exit $capture_status, drift check exit $check_status, $(( $(date +%s) - t0 )) s"

[ "$capture_status" -eq 0 ] && [ "$check_status" -eq 0 ]
