#!/usr/bin/env bash
# Regenerates tests/data/types_oracle.txt.gz and tests/data/types_orgs.txt.gz
# from Ghidra's compiled decompiler. Needs the reference build
# (scripts/build-reference.sh): its source copy and the decomp_opt objects
# in src/cpp/com_opt. Usage: crates/bk-decomp-types/tests/oracle/regen.sh [reference-dir]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ref="${1:-$here/../../../../../reference}"
src="$ref/src/cpp"
data="$here/../data"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
objs=$(ls "$src"/com_opt/*.o | grep -v '/consolemain\.o$')
# The standard is pinned (GCC 15 defaults to newer ones); flags follow the
# reference build (scripts/build-reference.sh): -fsigned-char, LOCAL_ZLIB.
c++ -std=c++11 -O1 -w -fno-access-control -fsigned-char -DLOCAL_ZLIB -I"$src" \
  "$here/types_oracle.cc" $objs "$ref/src/zlib/libz.a" -o "$work/types_oracle"
mkdir -p "$data"
langs="x86:LE:64:default:gcc x86:LE:32:default:gcc ARM:LE:32:v8:default PowerPC:BE:32:default:default AARCH64:LE:64:v8A:default 8051:BE:16:default:default"
"$work/types_oracle" "$ref" "$here/decls.txt" $langs | gzip -9n > "$data/types_oracle.txt.gz"
"$work/types_oracle" "$ref" --orgs | gzip -9n > "$data/types_orgs.txt.gz"
echo "wrote $data/types_oracle.txt.gz ($(gzip -dc "$data/types_oracle.txt.gz" | wc -l | tr -d ' ') lines)"
echo "wrote $data/types_orgs.txt.gz ($(gzip -dc "$data/types_orgs.txt.gz" | wc -l | tr -d ' ') lines)"
echo "host $(uname -sm), $(c++ --version | head -1)"
