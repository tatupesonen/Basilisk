#!/usr/bin/env bash
# Regenerates tests/data/cspec_oracle.txt.gz from Ghidra's compiled
# decompiler. Needs the reference build (scripts/build-reference.sh): its
# source copy and objects in src/cpp/com_opt, and its copy of the processor
# files. Usage: crates/bk-cspec/tests/oracle/regen.sh [reference-dir]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ref="${1:-$here/../../../../../reference}"
src="$ref/src/cpp"
data="$here/../data"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
objs=$(ls "$src"/com_opt/*.o | grep -v '/consolemain\.o$')
# The C++ standard is pinned; flags follow the reference build
# (-fsigned-char, LOCAL_ZLIB, -ffp-contract=off).
c++ -std=c++11 -O1 -w -fno-access-control -fsigned-char -ffp-contract=off -DLOCAL_ZLIB -I"$src" \
  "$here/cspec_oracle.cc" $objs "$ref/src/zlib/libz.a" -o "$work/cspec_oracle"
mkdir -p "$data"
"$work/cspec_oracle" "$ref" "$here/signatures.txt" "$ref/Ghidra/Processors" | gzip -9n > "$data/cspec_oracle.txt.gz"
echo "wrote $data/cspec_oracle.txt.gz ($(gzip -dc "$data/cspec_oracle.txt.gz" | wc -l | tr -d ' ') lines)"
echo "host $(uname -sm), $(c++ --version | head -1)"
