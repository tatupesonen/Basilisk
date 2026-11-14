#!/usr/bin/env bash
# Regenerates tests/data/cspec_oracle.<lib>.txt.gz from Ghidra's compiled
# decompiler, where <lib> is the C++ standard library the compiler uses
# (libcxx: LLVM libc++, macOS; libstdcxx: GNU libstdc++, Linux). Ghidra's
# answers depend on it (tests/data/README.md). Needs the reference build
# (scripts/build-reference.sh): its source copy and objects in
# src/cpp/com_opt, and its copy of the processor files.
# Usage: crates/bk-cspec/tests/oracle/regen.sh [reference-dir [output-dir]]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ref="${1:-$here/../../../../../reference}"
data="${2:-$here/../data}"
src="$ref/src/cpp"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '#include <cstddef>\n#if defined(_LIBCPP_VERSION)\nlibcxx\n#elif defined(__GLIBCXX__)\nlibstdcxx\n#else\nunknown\n#endif\n' \
  > "$work/lib.cc"
lib=$(c++ -E -P -x c++ "$work/lib.cc" | grep -v '^\s*$' | tail -1)
[ "$lib" != unknown ] || { echo "regen: unknown C++ standard library" >&2; exit 1; }
objs=$(ls "$src"/com_opt/*.o | grep -v '/consolemain\.o$')
# The C++ standard is pinned; flags follow the reference build
# (-fsigned-char, LOCAL_ZLIB, -ffp-contract=off).
c++ -std=c++11 -O1 -w -fno-access-control -fsigned-char -ffp-contract=off -DLOCAL_ZLIB -I"$src" \
  "$here/cspec_oracle.cc" $objs "$ref/src/zlib/libz.a" -o "$work/cspec_oracle"
mkdir -p "$data"
find "$ref/Ghidra/Processors" -path '*/data/languages/*.cspec' | LC_ALL=C sort > "$work/cspecs.txt"
out="$data/cspec_oracle.$lib.txt.gz"
"$work/cspec_oracle" "$ref" "$here/signatures.txt" "$work/cspecs.txt" > "$work/table.txt"
# REGEN_RUNS=N runs the generator N-1 more times and requires every output
# to be byte-identical to the first (the determinism check).
runs="${REGEN_RUNS:-1}"
for ((i = 2; i <= runs; i++)); do
  "$work/cspec_oracle" "$ref" "$here/signatures.txt" "$work/cspecs.txt" > "$work/again.txt" \
    || { echo "regen: run $i of $runs failed (exit $?)" >&2; exit 1; }
  cmp -s "$work/table.txt" "$work/again.txt" || { echo "regen: run $i of $runs differs from run 1" >&2; exit 1; }
done
[ "$runs" -le 1 ] || echo "regen: $runs runs, all complete and byte-identical"
gzip -9n < "$work/table.txt" > "$out"
echo "wrote $out ($(wc -l < "$work/table.txt" | tr -d ' ') lines, sha256 $(shasum -a 256 "$work/table.txt" 2>/dev/null | cut -c1-16 || sha256sum "$work/table.txt" | cut -c1-16))"
echo "host $(uname -sm), $(c++ --version | head -1), $lib"
