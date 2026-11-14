#!/usr/bin/env bash
# Regenerates tests/data/cfg_oracle.<library>.txt.gz (docs/features/decomp-cfg.md
# 6.3.1, 6.3.3) with D00's extended console `decomp_bk`, twice; the two
# tables must be byte-identical. The library (libcxx, libstdcxx) comes from
# the reference build's STAMP. Usage:
#   regen.sh [REFERENCE_DIR [OUT_DIR]]
# On the build host (fetch the result with scripts/remote.sh log):
#   scripts/remote.sh run -- crates/bk-decomp-cfg/tests/oracle/regen.sh "" "$BK_OUT"
set -euo pipefail
cd "$(dirname "$0")/../../../.."
if [ -n "${1:-}" ]; then export BASILISK_REFERENCE_DIR="$1"; fi
out=${2:-crates/bk-decomp-cfg/tests/data}
mkdir -p "$out"; out="$(cd "$out" && pwd)"
first="$out/first"; mkdir -p "$first"
export BASILISK_REQUIRE_REFERENCE=1
BK_CFG_TABLE_OUT="$first" cargo test --release -p bk-decomp-cfg --test oracle_bk -- --ignored regen --nocapture
BK_CFG_TABLE_OUT="$out" cargo test --release -p bk-decomp-cfg --test oracle_bk -- --ignored regen --nocapture
for f in "$first"/cfg_oracle.*.txt.gz; do
  if ! cmp -s <(gzip -dc "$f") <(gzip -dc "$out/$(basename "$f")"); then
    echo "regen.sh: the two runs differ ($(basename "$f"))" >&2
    exit 1
  fi
  echo "regen.sh: $out/$(basename "$f") (two runs identical)"
done
rm -rf "$first"
