#!/usr/bin/env bash
# Regenerates tests/data/structure_blocks.txt.gz (docs/features/decomp-cfg.md
# 6.2): generated graphs through the reference console's `structure blocks`,
# run twice (the two runs must agree). Usage:
#   regen_xml.sh [REFERENCE_DIR [OUT]]
# REFERENCE_DIR defaults to $BASILISK_REFERENCE_DIR, else ../reference beside
# the checkout; OUT to the checked-in table. On the build host:
#   scripts/remote.sh run -- crates/bk-decomp-cfg/tests/oracle/regen_xml.sh "" target/structure_blocks.host.txt.gz
set -euo pipefail
cd "$(dirname "$0")/../../../.."
if [ -n "${1:-}" ]; then export BASILISK_REFERENCE_DIR="$1"; fi
if [ -n "${2:-}" ]; then export BK_CFG_TABLE_OUT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"; fi
export BASILISK_REQUIRE_REFERENCE=1
exec cargo test -p bk-decomp-cfg --test structure_blocks -- --ignored regen --nocapture
