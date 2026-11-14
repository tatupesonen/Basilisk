#!/bin/bash
# Decodes the same bytes with the reference pcodedump twice, once with the
# macOS .sla and once with the x86-64 Linux .sla of each host-dependent
# specification, and compares the output (disassembly and p-code records).
#
#   pcodedump-compare.sh OUTDIR [MEGABYTES]
#
# Bytes: MEGABYTES (default 4) of seeded pseudo-random data per language;
# for TI_MSP430/TI_MSP430X also every 16-bit first word, each followed by
# four seeded random bytes.
set -euo pipefail
OUT=$1; MB=${2:-4}
REF=${REF:-/Users/tatu/slop/reference}
X86=${X86:-/Users/tatu/slop/reference-x86_64/x86_64-linux}
mkdir -p "$OUT"
# A root that is the reference with the .sla files replaced by x86-64's.
ROOT86=$OUT/root-x86
rm -rf "$ROOT86"
for m in AARCH64 ARM MIPS PowerPC TI_MSP430 tricore x86; do
  d=$ROOT86/Ghidra/Processors/$m/data/languages
  mkdir -p "$d"
  for f in "$REF/Ghidra/Processors/$m/data/languages/"*; do
    b=$(basename "$f")
    case $b in
      *.sla) ln -s "$X86/Ghidra/Processors/$m/data/languages/$b" "$d/$b" ;;
      *) ln -s "$f" "$d/$b" ;;
    esac
  done
done
while read -r spec lang; do
  python3 -I -c '
import random, sys
spec, mb = sys.argv[1], int(sys.argv[2])
r = random.Random(spec)
out = bytearray(r.getrandbits(8) for _ in range(mb << 20))
if spec.startswith("TI_MSP430"):
    for w in range(65536):
        out += w.to_bytes(2, "little") + bytes(r.getrandbits(8) for _ in range(4))
sys.stdout.buffer.write(out)
' "$spec" "$MB" > "$OUT/$spec.bin"
  # pcodedump can crash on random bytes (it did for MIPS); compare anyway.
  e1=0; e2=0
  "$REF/bin/pcodedump" "$REF" "$lang" 0x10000 < "$OUT/$spec.bin" > "$OUT/$spec.mac.txt" 2> "$OUT/$spec.mac.err" || e1=$?
  "$REF/bin/pcodedump" "$ROOT86" "$lang" 0x10000 < "$OUT/$spec.bin" > "$OUT/$spec.x86.txt" 2> "$OUT/$spec.x86.err" || e2=$?
  if cmp -s "$OUT/$spec.mac.txt" "$OUT/$spec.x86.txt" && [ "$e1" = "$e2" ]; then r=identical; else r=DIFFERENT; fi
  printf '%-24s %-28s %s exit %s/%s, %s lines  %s\n' "$spec" "$lang" "$(tail -1 "$OUT/$spec.mac.txt" | tr '\t' ' ')" "$e1" "$e2" "$(wc -l < "$OUT/$spec.mac.txt" | tr -d ' ')" "$r"
done <<'LIST'
AARCH64 AARCH64:LE:64:v8A
AARCH64BE AARCH64:BE:64:v8A
AARCH64_AppleSilicon AARCH64:LE:64:AppleSilicon
ARM8_le ARM:LE:32:v8
ARM8m_le ARM:LE:32:v8-m
mips32le MIPS:LE:32:default
mips32R6le MIPS:LE:32:R6
ppc_64_isa_le PowerPC:LE:64:A2-32addr
ppc_64_isa_altivec_le PowerPC:LE:64:A2ALT-32addr
TI_MSP430 TI_MSP430:LE:16:default
TI_MSP430X TI_MSP430X:LE:32:default
tricore tricore:LE:32:default
x86 x86:LE:32:default
x86-64 x86:LE:64:default
LIST
