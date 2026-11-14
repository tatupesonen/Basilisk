#!/bin/sh
# Builds Ghidra's C++ `sleigh` compiler from a source copy and compiles a
# list of specifications with it. Runs on the host or inside a container.
#
#   build-sleigh.sh WORK NAME CXX "EXTRA_FLAGS" [SPEC...]
#
# WORK      directory holding src/ (cpp + zlib, copied from
#           ../reference/src) and langs/<Module>/ (copies of the reference's
#           Ghidra/Processors/<Module>/data/languages); written to.
# NAME      name of this configuration: the build goes to WORK/build-NAME,
#           the compiled files to WORK/out-NAME/<spec>.sla, logs beside them.
# CXX       compiler command, e.g. "g++" or "clang++ -stdlib=libc++".
# EXTRA     extra compiler flags appended to Ghidra's (e.g.
#           "-ffp-contract=off"); may be empty.
# SPEC      specification names (default: the 14 host-dependent ones).
#           Module options (-l for AARCH64 and MIPS) are those of
#           ../reference/.state/lang/<Module>.opts.
#
# The make line is the one scripts/build-reference.sh uses.
set -eu
WORK=$1; NAME=$2; CXXCMD=$3; EXTRA=$4; shift 4
[ $# -gt 0 ] || set -- AARCH64 AARCH64BE AARCH64_AppleSilicon ARM8_le ARM8m_le \
  mips32le mips32R6le ppc_64_isa_le ppc_64_isa_altivec_le TI_MSP430 TI_MSP430X tricore x86 x86-64
B=$WORK/build-$NAME
O=$WORK/out-$NAME
rm -rf "$B" "$O"
mkdir -p "$B" "$O"
cp -Rp "$WORK/src/cpp" "$WORK/src/zlib" "$B/"
# Patches for this configuration (instrumentation), applied in order.
for p in "$WORK"/patches-"$NAME"/*.patch; do
  [ -f "$p" ] || continue
  echo "applying $(basename "$p")"
  patch -s -p1 -d "$B" < "$p"
done
{
  echo "name: $NAME"
  echo "host: $(uname -s) $(uname -m)"
  echo "cxx: $CXXCMD"; $CXXCMD --version 2>&1 | head -1
  echo "extra: $EXTRA"
  (ldd --version 2>&1 | head -1) || true
} > "$O/CONFIG"
cd "$B/zlib"
for c in *.c; do cc -O2 -w -DNO_GZIP -c "$c" -o "${c%.c}.o"; done
ar qc libz.a ./*.o && ranlib libz.a
cd "$B/cpp"
make -j3 sleigh_opt "CXX=$CXXCMD -std=c++11" ARCH_TYPE= \
  "ADDITIONAL_FLAGS=-w -DLOCAL_ZLIB -fsigned-char $EXTRA" BFDLIB= \
  LNK=../zlib/libz.a > "$O/make.log" 2>&1 || { tail -30 "$O/make.log"; exit 1; }
# Read by the instrumentation patch (patches/0001-trace-score.patch) only.
export SLEIGH_TRACE_SCORE=1
for spec in "$@"; do
  f=$(ls "$WORK"/langs/*/"$spec".slaspec)
  module=$(basename "$(dirname "$f")")
  opts=""
  case $module in AARCH64|MIPS) opts=-l ;; esac
  # shellcheck disable=SC2086
  if "$B/cpp/sleigh_opt" $opts "-DBaseDir=$WORK" "$f" "$O/$spec.sla" > "$O/$spec.log" 2>&1; then
    echo "compiled $spec"
  else
    echo "FAILED $spec (log $O/$spec.log)"
  fi
done
