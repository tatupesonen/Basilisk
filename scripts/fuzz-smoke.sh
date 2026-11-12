#!/usr/bin/env bash
# Runs every fuzz target in fuzz/ for a short time (default 60 s each) and
# stops at the first finding. See fuzz/README.md.
# Usage: scripts/fuzz-smoke.sh [seconds-per-target] [target ...]
set -euo pipefail
cd "$(dirname "$0")/.."
seconds="${1:-60}"
if [ "$#" -gt 0 ]; then shift; fi
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  echo "fuzz: cargo-fuzz on nightly is needed (cargo install cargo-fuzz; rustup toolchain install nightly)"
  exit 1
fi
if [ "$#" -gt 0 ]; then
  targets="$*"
else
  targets=$(cargo +nightly fuzz list)
fi
if [ -z "$targets" ]; then
  echo "fuzz: no targets yet"
  exit 0
fi
for t in $targets; do
  echo "fuzz: $t for ${seconds} s"
  cargo +nightly fuzz run "$t" -- -max_total_time="$seconds"
done
echo "fuzz: all targets ran without a finding"
