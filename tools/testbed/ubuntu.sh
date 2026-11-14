#!/usr/bin/env bash
# The crates that compile C (bk-binutils-sys, bk-gnu-disasm) and the
# reference tools on a newer distribution: Ubuntu 26.04 with GCC 15, in the
# image tools/testbed/ubuntu/Dockerfile, amd64 natively
# (docs/agents/testbed.md).
#
#   tools/testbed/ubuntu.sh [CARGO-TEST-ARGS...]
#
# Steps (tools/testbed/ubuntu/inside.sh): the two crates' tests and clippy;
# with BASILISK_GHIDRA_DIR set, also scripts/build-reference.sh with GCC 15
# (its own unit and data tests included) into target/testbed/ubuntu/, and
# every .sla compared byte for byte with the host's reference
# (BASILISK_REFERENCE_DIR, built with Debian's GCC 14).
. "$(dirname "$0")/lib.sh"

image=$(tb_image ubuntu)
mkdir -p "$TB_STATE/cargo-home" "$TB_ROOT/target/testbed/ubuntu"
args=(-v "$TB_ROOT:/src" -v "$TB_OUT:/out" -v "$TB_STATE/cargo-home:/cargo" -e CARGO_HOME=/cargo)
[ -z "${BASILISK_GHIDRA_DIR:-}" ] || [ ! -d "$BASILISK_GHIDRA_DIR" ] || args+=(-v "$BASILISK_GHIDRA_DIR:/ghidra:ro")
[ -z "${BASILISK_REFERENCE_DIR:-}" ] || [ ! -d "$BASILISK_REFERENCE_DIR" ] || args+=(-v "$BASILISK_REFERENCE_DIR:/hostref:ro")
start=$(date +%s)
tb_docker ubuntu "${BK_TESTBED_UBUNTU_TIMEOUT:-5000}" "${args[@]}" "$image" \
  bash /src/tools/testbed/ubuntu/inside.sh "$@" && code=0 || code=$?
[ -f "$TB_OUT/steps.txt" ] || echo "container $code 0 the container did not run" > "$TB_OUT/steps.txt"
tests=$(tb_counts "$TB_OUT/test.log" 2>/dev/null || echo "no tests")
{ tb_failed "$TB_OUT/test.log" 2>/dev/null | sed 's/^/ubuntu /'
  awk '$2 != 0 {print "ubuntu step " $1 ": exit " $2}' "$TB_OUT/steps.txt"; } \
  | tb_result "ubuntu 26.04 GCC 15: $(awk '{printf "%s%s %s", (NR > 1 ? ", " : ""), $1, ($2 == 0 ? "ok" : "FAIL")}' "$TB_OUT/steps.txt"); tests $tests; $(awk 'NF > 3 {$1 = $2 = $3 = ""; sub(/^ +/, ""); print}' "$TB_OUT/steps.txt" | paste -sd';' -) ($(tb_dur $(($(date +%s) - start))))"
exit "$code"
