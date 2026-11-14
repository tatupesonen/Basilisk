#!/usr/bin/env bash
# Run every data-test script written by dt_scripts.py through the reference
# console; one output per test, `internal=0x…` (host addresses) removed.
# usage: dt_run.sh REFERENCE_DIR GHIDRA_DIR OUTDIR [BINARY]
set -u
ref=$1; ghidra=$2; out=$3; bin=${4:-$ref/bin/decomp}
here=$(cd "$(dirname "$0")" && pwd)
dt=$ghidra/Ghidra/Features/Decompiler/src/decompile/datatests
mkdir -p "$out/scripts" "$out/raw"
python3 -I "$here/dt_scripts.py" "$dt" "$out/scripts"
for s in "$out"/scripts/*.txt; do
  n=$(basename "$s" .txt)
  echo | SLEIGHHOME=$ref perl -e 'alarm 60; exec @ARGV' "$bin" -i "$s" > "$out/raw/$n.out" 2>&1
  echo "$? $n" >> "$out/status.txt"
  sed -E 's/internal=0x[0-9a-f]+/internal=X/g' "$out/raw/$n.out" > "$out/raw/$n.norm"
done
(cd "$out/raw" && shasum -a 256 *.norm 2>/dev/null || sha256sum *.norm) > "$out/hashes.txt"
