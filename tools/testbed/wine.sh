#!/usr/bin/env bash
# Builds the workspace's tests for Windows and runs them under Wine, in the
# image tools/testbed/wine/Dockerfile (docs/agents/testbed.md).
#
#   tools/testbed/wine.sh [--msvc] [CARGO-TEST-ARGS...]
#
# Default: `cargo test --target x86_64-pc-windows-gnu --workspace
# --all-features --locked --no-fail-fast`. Given arguments replace
# `--workspace --all-features` (for example `-p bk-lang -p bk-elf`).
# --msvc builds for x86_64-pc-windows-msvc with cargo-xwin (clang-cl, lld,
# Microsoft's CRT and SDK, downloaded on first use into the testbed cache)
# instead of MinGW-w64.
#
# When BASILISK_GHIDRA_DIR is set it is mounted read-only and given to the
# tests as Z:\ghidra; the reference tools are Unix-only development tooling
# (ADR-022), so BASILISK_REFERENCE_DIR is never passed in.
# Environment: CARGO_BUILD_JOBS (cores, default 12), BK_OUT (results),
# BK_TESTBED_WINE_TIMEOUT (seconds, default 5000).
. "$(dirname "$0")/lib.sh"

flavour=gnu
if [ "${1:-}" = --msvc ]; then flavour=msvc; shift; fi
[ "${1:-}" != -- ] || shift
[ $# -gt 0 ] || set -- --workspace --all-features

image=$(tb_image wine)
mkdir -p "$TB_STATE/cargo-home" "$TB_STATE/xwin-cache" "$TB_ROOT/target/testbed"
mounts=(-v "$TB_ROOT:/src" -v "$TB_STATE/cargo-home:/cargo" -w /src -e CARGO_HOME=/cargo)
if [ -n "${BASILISK_GHIDRA_DIR:-}" ] && [ -d "$BASILISK_GHIDRA_DIR" ]; then
  mounts+=(-v "$BASILISK_GHIDRA_DIR:/ghidra:ro" -e 'BASILISK_GHIDRA_DIR=Z:\ghidra')
  say "Ghidra tree mounted as Z:\\ghidra"
else
  say "no Ghidra tree: the tests that need it skip"
fi
# A cross-built test binary cannot run `cargo metadata`, so insta is told
# where the workspace is (as Wine sees it) and never to write snapshots.
mounts+=(-e 'INSTA_WORKSPACE_ROOT=Z:\src' -e INSTA_UPDATE=no -e WINEDEBUG=-all
         -e WINEPREFIX=/tmp/wineprefix -e RUST_BACKTRACE=1)

case $flavour in
  gnu)
    triple=x86_64-pc-windows-gnu
    cmd=(cargo test --target "$triple" --locked --no-fail-fast "$@")
    mounts+=(-e CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine) ;;
  msvc)
    triple=x86_64-pc-windows-msvc
    cmd=(cargo xwin test --target "$triple" --locked --no-fail-fast "$@")
    mounts+=(-v "$TB_STATE/xwin-cache:/xwin" -e XWIN_CACHE_DIR=/xwin -e XWIN_ACCEPT_LICENSE=1
             -e CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=wine) ;;
esac
mounts+=(-e "CARGO_TARGET_DIR=/src/target/testbed/wine-$flavour")

log="$TB_OUT/wine-$flavour-test.log"
say "$(now) ${cmd[*]} (Wine, $TB_CORES cores)"
start=$(date +%s)
set +e
tb_docker "wine-$flavour" "${BK_TESTBED_WINE_TIMEOUT:-5000}" "${mounts[@]}" "$image" \
  bash -c 'mkdir -p "$WINEPREFIX"; wine --version; wineboot -i >/dev/null 2>&1; exec "$@"' wine "${cmd[@]}" 2>&1 | tee "$log"
code=${PIPESTATUS[0]}
set -e
counts=$(tb_counts "$log")
tb_failed "$log" | tb_result "wine $flavour: $counts (exit $code, $(tb_dur $(($(date +%s) - start))))"
[ "$code" -ne 0 ] || [ -s "$TB_OUT/failures.txt" ] || exit 0
[ "$code" -ne 0 ] || code=1
exit "$code"
