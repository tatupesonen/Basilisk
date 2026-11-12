#!/usr/bin/env bash
# Quality gate (see docs/LOOP.md). Exits non-zero on the first failure.
# Run as `scripts/gate.sh > gate.log 2>&1; echo $?` and never pipe it.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/check-file-size.sh
scripts/check-unsafe.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --quiet -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --quiet

# Licences, banned and duplicate crates, crate sources (deny.toml). The
# advisory database needs the network, so CI checks advisories instead.
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --offline check licenses bans sources
else
  echo "gate: cargo-deny is not installed; licence check skipped (cargo install cargo-deny)"
fi

cargo test --workspace --all-features --quiet 2>&1 | tee "${TMPDIR:-/tmp}/bk-gate-test-$$.log" \
  | grep -E '^test result|panicked|FAILED' \
  | awk '/test result/{p+=$4; f+=$6} /panicked|FAILED/{print} END {printf "tests: %d passed, %d failed\n", p, f; exit (f>0)}'
