#!/usr/bin/env bash
# Builds what the bk-sleigh benchmarks compare against (macOS; development
# tooling only):
#   target/bench/x86-64-code.bin  text sections of four of Ghidra's C++ files
#                                 (ruleaction, coreaction, fspec, type) built
#                                 -O2 -arch x86_64, concatenated (the input of
#                                 inventory 8a and docs/agents/spec-sleigh.md)
#   target/bench/slabench         slabench.cc linked against the reference
#                                 build's libsla.a
# Usage: crates/bk-sleigh/tests/reference_bench/build.sh [REFERENCE_DIR]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
REF=${1:-${BASILISK_REFERENCE_DIR:-$root/../reference}}
out=$root/target/bench
mkdir -p "$out"
: > "$out/x86-64-code.bin"
for name in ruleaction coreaction fspec type; do
  c++ -std=c++11 -O2 -w -arch x86_64 -c "$REF/src/cpp/$name.cc" -o "$out/code.o"
  # shellcheck disable=SC2046
  set -- $(otool -l "$out/code.o" | awk '
    $1 == "sectname" { name = $2 }
    $1 == "size" && name == "__text" && !size { size = $2 }
    $1 == "offset" && name == "__text" && !offset { offset = $2 }
    END { print offset, size }')
  { tail -c +"$(($1 + 1))" "$out/code.o" | head -c "$(($2))" >> "$out/x86-64-code.bin"; } || true
done
rm -f "$out/code.o"
c++ -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -I"$REF/src/cpp" \
  "$here/slabench.cc" "$REF/src/cpp/libsla.a" "$REF/src/zlib/libz.a" -o "$out/slabench"
echo "built $out/x86-64-code.bin ($(wc -c < "$out/x86-64-code.bin" | tr -d ' ') bytes) and $out/slabench"
