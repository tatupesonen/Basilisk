#!/usr/bin/env bash
# Runs inside the Ubuntu 26.04 image (tools/testbed/ubuntu.sh): /src is the
# checkout, /out the results, /ghidra and /hostref (read-only) when present.
# Each step appends "<name> <exit> <seconds> <note>" to /out/steps.txt.
set -uo pipefail
cd /src
: > /out/steps.txt
step() {  # name command...: runs one step, its output to /out/<name>.log
  local name=$1 t0 code; shift
  t0=$(date +%s)
  echo "ubuntu: $(date -u +%FT%TZ) $name: $*"
  "$@" > "/out/$name.log" 2>&1; code=$?
  tail -n 15 "/out/$name.log"
  echo "$name $code $(($(date +%s) - t0)) ${NOTE:-}" >> /out/steps.txt
  NOTE=
  return $code
}
gcc --version | head -1
echo "C default: $(echo | gcc -dM -E -x c - | sed -n 's/#define __STDC_VERSION__ //p'), $(rustc --version)"
c_crates=(-p bk-binutils-sys -p bk-gnu-disasm)
export CARGO_TARGET_DIR=/src/target/testbed/ubuntu/cargo
[ ! -d /ghidra ] || export BASILISK_GHIDRA_DIR=/ghidra

step test cargo test --locked --no-fail-fast "${c_crates[@]}" "$@"
step clippy cargo clippy --locked "${c_crates[@]}" --all-targets -- -D warnings

if [ -d /ghidra ]; then
  ref=/src/target/testbed/ubuntu/reference
  step reference env BASILISK_GHIDRA_DIR=/ghidra BASILISK_REFERENCE_DIR="$ref" CC=gcc CXX=g++ \
    scripts/build-reference.sh --jobs "${CARGO_BUILD_JOBS:-12}"
  if [ -d /hostref ]; then
    sums() { (cd "$1" && find . -name '*.sla' | LC_ALL=C sort | xargs sha256sum); }
    sums "$ref" > /out/sla-gcc15.sha; sums /hostref > /out/sla-host.sha
    n=$(wc -l < /out/sla-gcc15.sha); same=$(LC_ALL=C comm -12 /out/sla-gcc15.sha /out/sla-host.sha | wc -l)
    NOTE="$same of $n .sla identical to the host's reference (GCC 14)"
    step sla-identical test "$n" -gt 0 -a "$same" -eq "$n" -a "$n" -eq "$(wc -l < /out/sla-host.sha)"
  fi
else
  echo "ubuntu: no Ghidra tree; the reference tools are not built"
fi
awk '$2 != 0 {bad = 1} END {exit bad}' /out/steps.txt
