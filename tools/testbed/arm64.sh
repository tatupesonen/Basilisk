#!/usr/bin/env bash
# Tests on Linux AArch64 (docs/agents/testbed.md): built on the build host
# for aarch64-unknown-linux-gnu with Debian's cross GCC and run under
# qemu-user, in the image tools/testbed/arm64/Dockerfile. Cheap: only the
# test binaries are emulated, not the compiler.
#
#   tools/testbed/arm64.sh [CARGO-TEST-ARGS...]
#
# Default: the crates whose results depend on floating point and on how it
# is contracted (ADR-029, ADR-032, ADR-039): bk-sleigh-compiler (the
# decision-tree score and its `log`, all 150 .sla byte for byte), bk-pcode
# (float ops) and bk-sla. AArch64 is the platform where a C compiler fuses
# multiply-adds by default, so it is the test that Rust's never does.
# With BASILISK_GHIDRA_DIR / BASILISK_REFERENCE_DIR set they are mounted
# read-only at the same paths; the x86-64 reference tools run natively when
# a test starts them.
. "$(dirname "$0")/lib.sh"

[ "${1:-}" != -- ] || shift
[ $# -gt 0 ] || set -- -p bk-sleigh-compiler -p bk-pcode -p bk-sla --all-features
image=$(tb_image arm64)
mkdir -p "$TB_STATE/cargo-home"
args=(-v "$TB_ROOT:/src" -w /src -v "$TB_STATE/cargo-home:/cargo" -e CARGO_HOME=/cargo
      -e CARGO_TARGET_DIR=/src/target/testbed/arm64
      -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
      -e CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc -e CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
      -e "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64 -L /usr/aarch64-linux-gnu"
      -e INSTA_UPDATE=no)
for v in BASILISK_GHIDRA_DIR BASILISK_REFERENCE_DIR; do
  d=${!v:-}
  [ -z "$d" ] || [ ! -d "$d" ] || args+=(-v "$d:$d:ro" -e "$v=$d")
done
log="$TB_OUT/arm64-test.log"
start=$(date +%s)
say "$(now) cargo test --target aarch64-unknown-linux-gnu $* (qemu-user, $TB_CORES cores)"
tb_docker arm64 "${BK_TESTBED_ARM64_TIMEOUT:-5000}" "${args[@]}" "$image" \
  cargo test --target aarch64-unknown-linux-gnu --locked --no-fail-fast "$@" 2>&1 | tee "$log" \
  && code=0 || code=${PIPESTATUS[0]}
tb_failed "$log" | tb_result "arm64 (qemu): $(tb_counts "$log"), $(grep -c SKIPPED "$log") SKIPPED (exit $code, $(tb_dur $(($(date +%s) - start))))"
exit "$code"
