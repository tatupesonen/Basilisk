#!/usr/bin/env bash
# Regenerates tests/data/structure_corpus.<library>.txt.gz
# (docs/features/decomp-cfg.md 6.3.2): every structuring run of the data
# tests and the research fragments, captured with D00's `bk capture
# structure`, and Ghidra's `bk structure … asgiven trace` on each captured
# graph. Usage:
#   regen_corpus.sh [REFERENCE_DIR [OUT_DIR]]
# On the build host (fetch with scripts/remote.sh log):
#   scripts/remote.sh run -- crates/bk-decomp-cfg/tests/oracle/regen_corpus.sh "" "$BK_OUT"
set -euo pipefail
cd "$(dirname "$0")/../../../.."
if [ -n "${1:-}" ]; then export BASILISK_REFERENCE_DIR="$1"; fi
if [ -n "${2:-}" ]; then mkdir -p "$2"; export BK_CFG_TABLE_OUT="$(cd "$2" && pwd)"; fi
export BASILISK_REQUIRE_REFERENCE=1
exec cargo test --release -p bk-decomp-cfg --test corpus -- --ignored capture --nocapture
