#!/usr/bin/env bash
# Reruns the whole spike: builds the instrumented console, runs the corpus
# through it and the reference console (byte identity), and compares every
# logged function's Emit calls with the prototype's printing of its tree.
#
#   docs/research/decomp-out-spike/prototype/rerun.sh [WORKDIR]
#
# Needs BASILISK_GHIDRA_DIR and BASILISK_REFERENCE_DIR (as scripts/remote.sh
# run sets them on the build host). WORKDIR defaults to target/spike; the
# build goes to WORKDIR/instr, logs to WORKDIR/run. Results: WORKDIR/results/
# (identity.txt, summary.txt, failures.txt, coverage.txt); also copied to
# $BK_OUT when set (scripts/remote.sh log fetches them).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
work=${1:-$root/target/spike}
mkdir -p "$work"
work=$(cd "$work" && pwd)
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

"$root/tools/reference/patches-instr/build-instr.sh" --jobs "$jobs" "$work/instr" | tail -2
rm -rf "$work/run"
id_status=0
python3 "$here/run_corpus.py" --instr "$work/instr/bin/decomp_instr" --out "$work/run" --jobs "$jobs" || id_status=$?
mkdir -p "$work/results"
cp "$work/run/identity.txt" "$work/results/"
cmp_status=0
(cd "$here" && python3 compare.py "$work/run/logs/orig" "$work/run/logs/xml" "$work/run/logs/flat" "$work/run/logs/java" "$work/run/logs/options" \
   --summary "$work/results/summary.txt" --failures "$work/results/failures.txt" \
   --coverage "$work/results/coverage.txt") || cmp_status=$?
cat "$work"/run/logs/*/*.diag | awk -F'\t' '$1=="S" {d+=$3; i+=$5} $1=="D" {print}' > "$work/results/diag.txt"
awk -F'\t' '$1=="S" {d+=$3; i+=$5} END {print "direct emits " d ", interleaved " i}' "$work"/run/logs/*/*.diag \
  >> "$work/results/diag.txt"
tail -1 "$work/results/diag.txt"
# Console errors (the same in both consoles, identity checks that), per variant
grep -c "Execution error\|Low-level ERROR" "$work"/run/logs/*/*.out | grep -v ':0$' > "$work/results/console-errors.txt" || true
if [ -n "${BK_OUT:-}" ]; then
  cp "$work"/results/* "$BK_OUT/"
  (cd "$work/run" && tar -czf "$BK_OUT/logs-orig.tgz" logs/orig logs/xml/*.out logs/flat/*.out logs/java/*.out logs/options/*.out)
fi
echo "identity exit $id_status, comparison exit $cmp_status"
[ "$id_status" -eq 0 ]
