#!/usr/bin/env bash
# Single-thread comparison of bk-sleigh with Ghidra's C++ engine (slabench),
# interleaved in one job and pinned to one core: REPS rounds, each running
# the bench_pcode sweeps (best of 5 inside) and then slabench (best of 5
# inside); prints every round and then the best and the median of the rounds.
# Pinned with taskset where there is one (Linux); unpinned elsewhere (macOS
# has no way to pin a thread). Run build.sh first.
# Usage: crates/bk-sleigh/tests/reference_bench/compare.sh [REFERENCE_DIR] [REPS] [CORE]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
REF=${1:-${BASILISK_REFERENCE_DIR:-$root/../reference}}
REPS=${2:-5}
CORE=${3:-7}
bench=$root/target/bench
langs=$REF/Ghidra/Processors/x86/data/languages
cd "$root"
exe=$(cargo test --release -p bk-sleigh --test bench_pcode --no-run --message-format=json 2> /dev/null |
  python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "bench_pcode":
        print(m["executable"])')
cpu() {
  if [ -r /proc/cpuinfo ]; then grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'
  else sysctl -n machdep.cpu.brand_string; fi
}
load() {
  if [ -r /proc/loadavg ]; then cut -d' ' -f1-3 /proc/loadavg; else sysctl -n vm.loadavg; fi
}
if command -v taskset > /dev/null; then pin=(taskset -c "$CORE"); else pin=(); fi
echo "cpu: $(cpu)"
echo "load before: $(load)"
log=$(mktemp)
for rep in $(seq "$REPS"); do
  BK_BENCH_SINGLE=1 BASILISK_REFERENCE_DIR=$REF ${pin[@]+"${pin[@]}"} "$exe" bench_pcode_x86_64 \
    --exact --ignored --nocapture 2>&1 |
    sed -n -e "s/^\(decode[^:]*\): \([0-9.]*\) M instructions\/s.*/bk \1\t\2/p" -e "s/^x86-64 code: [0-9]* bytes, \([0-9]*\) instructions, \([0-9]*\) ops/bk instructions\t\1\nbk ops\t\2/p" | tee -a "$log"
  ${pin[@]+"${pin[@]}"} "$bench/slabench" "$langs/x86-64.sla" "$langs/x86-64.pspec" "$bench/x86-64-code.bin" 5 |
    awk -F'\t' '$1 == "decode_mips" { print "ref decode only\t" $2 }
      $1 == "text_mips" { print "ref decode + text\t" $2 }
      $1 == "lift_mips" { print "ref decode + lift (counting emitter)\t" $2 }
      $1 == "text_lift_mips" { print "ref decode + text + lift\t" $2 }
      $1 == "instructions" || $1 == "ops" { print "ref " $1 "\t" $2 }' | tee -a "$log"
done
echo "load after: $(load)"
python3 - "$log" << 'EOF'
import statistics, sys
rows = {}
for line in open(sys.argv[1]):
    key, value = line.rstrip("\n").split("\t")
    rows.setdefault(key, []).append(float(value))
print("M instructions/s over %d rounds: best / median" % max(len(v) for v in rows.values()))
for key in sorted(rows):
    v = rows[key]
    print("%-45s %8.3f / %8.3f" % (key, max(v), statistics.median(v)))
EOF
rm -f "$log"
