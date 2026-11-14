#!/usr/bin/env bash
# Regenerates tests/data/cfg_oracle.txt.gz (docs/features/decomp-cfg.md
# 6.3.1, 6.3.3) with D00's extended console `decomp_bk`, twice; the two
# tables must be byte-identical. Usage:
#   regen.sh [REFERENCE_DIR [OUT]]
# On the build host:
#   scripts/remote.sh run -- crates/bk-decomp-cfg/tests/oracle/regen.sh "" "$BK_OUT/cfg_oracle.host.txt.gz"
set -euo pipefail
cd "$(dirname "$0")/../../../.."
if [ -n "${1:-}" ]; then export BASILISK_REFERENCE_DIR="$1"; fi
out=${2:-crates/bk-decomp-cfg/tests/data/cfg_oracle.txt.gz}
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
export BASILISK_REQUIRE_REFERENCE=1
BK_CFG_TABLE_OUT="$out.first" cargo test --release -p bk-decomp-cfg --test oracle_bk -- --ignored regen --nocapture
BK_CFG_TABLE_OUT="$out" cargo test --release -p bk-decomp-cfg --test oracle_bk -- --ignored regen --nocapture
if ! cmp -s <(gzip -dc "$out.first") <(gzip -dc "$out"); then
  echo "regen.sh: the two runs differ" >&2
  diff <(gzip -dc "$out.first") <(gzip -dc "$out") | head -20 >&2
  exit 1
fi
rm -f "$out.first"
echo "regen.sh: $out (two runs identical)"
