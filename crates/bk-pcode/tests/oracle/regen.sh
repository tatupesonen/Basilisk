#!/usr/bin/env bash
# Regenerates tests/data/opbehavior_cpp.txt.gz from Ghidra's C++ behaviours.
# Needs the reference build (scripts/build-reference.sh): its sources and
# libsla.a. Usage: crates/bk-pcode/tests/oracle/regen.sh [reference-dir]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ref="${1:-$here/../../../../../reference}"
src="$ref/src/cpp"
out="$here/../data/opbehavior_cpp.txt.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
c++ -std=c++11 -O2 -w -I"$src" "$here/opbehavior_oracle.cc" "$src/libsla.a" "$ref/src/zlib/libz.a" \
  -o "$work/oracle"
mkdir -p "$(dirname "$out")"
"$work/oracle" | gzip -9n > "$out"
echo "wrote $out ($(gzip -dc "$out" | wc -l | tr -d ' ') cases), host $(uname -sm)"
