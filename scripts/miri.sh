#!/usr/bin/env bash
# Runs Miri over every crate that is allowed `unsafe` and marked `miri` in
# unsafe-crates.txt (ADR-020). Needs a nightly toolchain with the miri
# component: rustup +nightly component add miri
# Usage: scripts/miri.sh [crate ...]   (default: all crates marked `miri`)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$#" -gt 0 ]; then
  crates="$*"
else
  crates=$(awk '!/^[[:space:]]*#/ && $2 == "miri" {print $1}' unsafe-crates.txt)
fi
if [ -z "$crates" ]; then
  echo "miri: no crates contain unsafe code; nothing to check"
  exit 0
fi
if ! cargo +nightly miri --version >/dev/null 2>&1; then
  echo "miri: not installed (rustup +nightly component add miri)"
  exit 1
fi
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-symbolic-alignment-check}"
for c in $crates; do
  echo "miri: $c"
  cargo +nightly miri test -p "$c" --all-features
done
