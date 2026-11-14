#!/usr/bin/env bash
# Builds what the bk-sleigh benchmarks compare against (macOS or Linux;
# development tooling only):
#   target/bench/x86-64-code.bin  text sections of four of Ghidra's C++ files
#                                 (ruleaction, coreaction, fspec, type) built
#                                 -O2 for x86-64, concatenated (the input of
#                                 inventory 8a and docs/agents/spec-sleigh.md).
#                                 macOS: Apple clang -arch x86_64, Mach-O
#                                 __text. Linux on x86-64: clang++ (else c++)
#                                 -O2, ELF .text; the bytes differ from the
#                                 Mac's, so compare engines on one host only.
#   target/bench/x86-64-code-778k.bin  the same plus printc, funcdata_varnode,
#                                 block and database (the 778 kB input of the
#                                 end-to-end pcodedump comparison, PERF.md)
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
: > "$out/x86-64-code-778k.bin"
# text_section OBJECT: prints "offset size" of the object's main text section.
text_section() {
  if [ "$(uname)" = Darwin ]; then
    otool -l "$1" | awk '
      $1 == "sectname" { name = $2 }
      $1 == "size" && name == "__text" && !size { size = $2 }
      $1 == "offset" && name == "__text" && !offset { offset = $2 }
      END { print offset, size }'
  else
    readelf -SW "$1" | awk '
      { sub(/^ *\[ *[0-9]+\] */, "") }
      $1 == ".text" { print "0x" $4, "0x" $5; exit }'
  fi
}
if [ "$(uname)" = Darwin ]; then
  cc_code=(c++ -arch x86_64)
elif command -v clang++ > /dev/null; then
  cc_code=(clang++)
else
  cc_code=(c++)
fi
for name in ruleaction coreaction fspec type printc funcdata_varnode block database; do
  "${cc_code[@]}" -std=c++11 -O2 -w -c "$REF/src/cpp/$name.cc" -o "$out/code.o"
  # shellcheck disable=SC2046
  set -- $(text_section "$out/code.o")
  case $name in
    ruleaction|coreaction|fspec|type)
      { tail -c +"$(($1 + 1))" "$out/code.o" | head -c "$(($2))" >> "$out/x86-64-code.bin"; } || true ;;
  esac
  { tail -c +"$(($1 + 1))" "$out/code.o" | head -c "$(($2))" >> "$out/x86-64-code-778k.bin"; } || true
done
rm -f "$out/code.o"
c++ -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -I"$REF/src/cpp" \
  "$here/slabench.cc" "$REF/src/cpp/libsla.a" "$REF/src/zlib/libz.a" -o "$out/slabench"
echo "built $out/x86-64-code.bin ($(wc -c < "$out/x86-64-code.bin" | tr -d ' ') bytes) and $out/slabench"
