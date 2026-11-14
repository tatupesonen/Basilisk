#!/usr/bin/env bash
# Build Ghidra's decomp_dbg (CPUI_DEBUG) from a copy of the reference build's
# sources into OUTDIR, with build-reference.sh's make overrides.
# usage: build_dbg.sh REFERENCE_DIR OUTDIR
set -eu
ref=$1; out=$2
rm -rf "$out"; mkdir -p "$out"
cp -Rp "$ref/src/cpp" "$ref/src/zlib" "$out/"
bfd="analyzesigs bfd_arch codedata loadimage_bfd"
for g in grammar.cc xml.cc pcodeparse.cc slghparse.cc slghparse.hh slghscan.cc; do touch "$out/cpp/$g"; done
make -C "$out/cpp" -j"$(nproc 2>/dev/null || echo 4)" decomp_dbg \
  "CXX=${CXX:-g++} -std=c++11" ARCH_TYPE= "ADDITIONAL_FLAGS=-w -DLOCAL_ZLIB -fsigned-char -ffp-contract=off" \
  BFDLIB= LNK=../zlib/libz.a \
  "EXTRA=\$(filter-out $bfd \$(CORE) \$(DECCORE) \$(SLEIGH) \$(GHIDRA) \$(SLACOMP) \$(SPECIAL),\$(ALL_NAMES))" > "$out/make.log" 2>&1
ls -l "$out/cpp/decomp_dbg"
