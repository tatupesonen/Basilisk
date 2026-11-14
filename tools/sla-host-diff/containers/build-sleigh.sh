#!/bin/sh
# Builds Ghidra's C++ `sleigh` compiler from a source copy and compiles a
# list of specifications with it. Runs on the host or inside a container.
#
#   build-sleigh.sh WORK NAME CXX "EXTRA_FLAGS" [SPEC...|all]
#
# WORK      directory holding src/ (cpp + zlib, copied from
#           ../reference/src), langs/<Module>/ (copies of the reference's
#           Ghidra/Processors/<Module>/data/languages without .sla) and
#           opts/<Module>.opts (copies of ../reference/.state/lang); written to.
# NAME      name of this configuration: the build goes to WORK/build-NAME,
#           the compiled files to WORK/out-NAME/<spec>.sla, logs beside them.
#           Patches in WORK/patches-NAME/*.patch are applied to the copy.
# CXX       compiler command, e.g. "g++" or "clang++ -stdlib=libc++".
# EXTRA     extra compiler flags appended to Ghidra's (e.g.
#           "-ffp-contract=off"); may be empty.
# SPEC      specification names; "all" for every .slaspec under langs/;
#           default: the 14 host-dependent ones.
#
# Environment:
#   SKIP_BUILD=1   reuse WORK/build-NAME (compile specifications only)
#   OUT=dir        output directory name instead of out-NAME
#   SLEIGH_LOG, SLEIGH_FUSE, SLEIGH_TRACE_SCORE: read by the instrumentation
#                  patches (patches/*.patch), passed through to sleigh.
#
# The make line is the one scripts/build-reference.sh uses.
set -eu
WORK=$1; NAME=$2; CXXCMD=$3; EXTRA=$4; shift 4
[ $# -gt 0 ] || set -- AARCH64 AARCH64BE AARCH64_AppleSilicon ARM8_le ARM8m_le \
  mips32le mips32R6le ppc_64_isa_le ppc_64_isa_altivec_le TI_MSP430 TI_MSP430X tricore x86 x86-64
if [ "$1" = all ]; then
  set -- $(cd "$WORK/langs" && ls ./*/*.slaspec | sed 's|.*/||; s|\.slaspec$||' | sort)
fi
B=$WORK/build-$NAME
O=$WORK/${OUT:-out-$NAME}
rm -rf "$O"
mkdir -p "$O"
if [ "${SKIP_BUILD:-}" != 1 ]; then
  rm -rf "$B"
  mkdir -p "$B"
  cp -Rp "$WORK/src/cpp" "$WORK/src/zlib" "$B/"
  for p in "$WORK"/patches-"$NAME"/*.patch; do
    [ -f "$p" ] || continue
    echo "applying $(basename "$p")"
    patch -s -p1 -d "$B" < "$p"
  done
  cd "$B/zlib"
  for c in *.c; do cc -O2 -w -DNO_GZIP -c "$c" -o "${c%.c}.o"; done
  ar qc libz.a ./*.o && ranlib libz.a
  cd "$B/cpp"
  make -j3 sleigh_opt "CXX=$CXXCMD -std=c++11" ARCH_TYPE= \
    "ADDITIONAL_FLAGS=-w -DLOCAL_ZLIB -fsigned-char $EXTRA" BFDLIB= \
    LNK=../zlib/libz.a > "$B/make.log" 2>&1 || { tail -30 "$B/make.log"; exit 1; }
fi
{
  echo "name: $NAME"
  echo "host: $(uname -s) $(uname -m)"
  echo "cxx: $CXXCMD"; $CXXCMD --version 2>&1 | head -1
  echo "extra: $EXTRA"
  echo "patches: $(ls "$WORK"/patches-"$NAME"/ 2>/dev/null | tr '\n' ' ')"
  echo "env: SLEIGH_LOG=${SLEIGH_LOG:-} SLEIGH_FUSE=${SLEIGH_FUSE:-}"
  (ldd --version 2>&1 | head -1) || true
} > "$O/CONFIG"
export SLEIGH_TRACE_SCORE=${SLEIGH_TRACE_SCORE:-1} SLEIGH_LOG=${SLEIGH_LOG:-} SLEIGH_FUSE=${SLEIGH_FUSE:-}
compile_one() {
  spec=$1
  f=$(ls "$WORK"/langs/*/"$spec".slaspec)
  module=$(basename "$(dirname "$f")")
  opts=""
  if [ -f "$WORK/opts/$module.opts" ]; then
    opts=$(cat "$WORK/opts/$module.opts")
  else
    case $module in AARCH64|MIPS) opts=-l ;; esac
  fi
  # shellcheck disable=SC2086
  if "$B/cpp/sleigh_opt" $opts "-DBaseDir=$WORK" "$f" "$O/$spec.sla" > "$O/$spec.log" 2>&1; then
    echo "compiled $spec"
  else
    echo "FAILED $spec (log $O/$spec.log)"
  fi
}
i=0
for spec in "$@"; do
  compile_one "$spec" &
  i=$((i + 1))
  if [ "$i" -ge 3 ]; then wait; i=0; fi   # three at a time
done
wait
