#!/usr/bin/env bash
# Builds the instrumented decompiler console (the printer log of
# docs/research/decomp-out-spike) into the directory given as argument:
#
#   tools/reference/patches-instr/build-instr.sh [--jobs N] OUT
#
# OUT/src/{cpp,zlib}   a copy of Ghidra's decompiler sources with
#                      tools/reference/patches/*.patch (as the reference
#                      consoles have them) and then this directory's *.patch
# OUT/bin/decomp_instr decomp_opt's objects from that copy + bk_printlog.cc
#
# It reads the Ghidra tree (BASILISK_GHIDRA_DIR, default ../ghidra) and writes
# only below OUT. It never touches the reference directory or the reference
# consoles; OUT must be neither of those nor inside the Ghidra tree. The
# compiler flags and make overrides are scripts/build-reference.sh's, so the
# copy is compiled exactly as the reference console is. Reruns are
# incremental: only changed sources are copied, so make rebuilds the minimum.
#
# The console behaves as Ghidra's unless BK_PRINTLOG=<prefix> is set in its
# environment; then it writes <prefix>.tree, .emit and .diag
# (tools/reference/README.md, "The printer log").
set -euo pipefail

die() { printf 'build-instr: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

JOBS=${JOBS:-}
OUT=
while [ $# -gt 0 ]; do
  case "$1" in
    --jobs) shift; JOBS=${1:-} ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$OUT" ] || die "one output directory only"; OUT=$1 ;;
  esac
  shift
done
[ -n "$OUT" ] || die "usage: build-instr.sh [--jobs N] OUT"
[ -n "$JOBS" ] || JOBS=$(( $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2) / 2 ))
[ "$JOBS" -ge 1 ] || JOBS=1

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
GHIDRA=${BASILISK_GHIDRA_DIR:-$ROOT/../ghidra}
[ -d "$GHIDRA" ] || die "Ghidra source tree not found at $GHIDRA (set BASILISK_GHIDRA_DIR)"
GHIDRA=$(cd "$GHIDRA" && pwd -P)
DEC=$GHIDRA/Ghidra/Features/Decompiler/src/decompile
[ -f "$DEC/cpp/Makefile" ] || die "$GHIDRA is not a Ghidra source tree"

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)
case "$OUT/" in "$GHIDRA"/*) die "OUT must not be inside the Ghidra tree" ;; esac
if [ -n "${BASILISK_REFERENCE_DIR:-}" ] && [ -d "$BASILISK_REFERENCE_DIR" ]; then
  REFP=$(cd "$BASILISK_REFERENCE_DIR" && pwd -P)
  case "$OUT/" in "$REFP"/*) die "OUT must not be inside the reference directory" ;; esac
fi

CXX_CMD=${CXX:-g++}
CC_CMD=${CC:-cc}
# As scripts/build-reference.sh (its comments give the reasons).
CXX_EXTRA_FLAGS="-w -DLOCAL_ZLIB -fsigned-char -ffp-contract=off"
ZLIB_CFLAGS="-O2 -w -DNO_GZIP -ffp-contract=off"
BFD_NAMES=$(cd "$DEC/cpp" && grep -lE '#include "(loadimage_bfd|bfd_arch)\.hh"' ./*.cc | sed -e 's#^\./##' -e 's#\.cc$##' | LC_ALL=C sort | tr '\n' ' ')

# ------------------------------------------------------------ sources
stage=$OUT/src.stage
rm -rf "$stage"
mkdir -p "$stage" "$OUT/src"
cp -R "$DEC/cpp" "$stage/cpp"
cp -R "$DEC/zlib" "$stage/zlib"
chmod -R u+w "$stage"
for p in "$ROOT"/tools/reference/patches/*.patch "$HERE"/*.patch; do
  [ -f "$p" ] || continue
  say "applying $(basename "$p")"
  patch -s -p1 -d "$stage" < "$p" || die "$(basename "$p") does not apply to this Ghidra commit"
done
find "$stage" -name '*.orig' -exec rm -f {} +
copied=0
while IFS= read -r f; do
  if ! cmp -s "$stage/$f" "$OUT/src/$f" 2>/dev/null; then
    mkdir -p "$(dirname "$OUT/src/$f")"
    cp "$stage/$f" "$OUT/src/$f"
    copied=$((copied + 1))
  fi
done < <(cd "$stage" && find . -type f | LC_ALL=C sort)
rm -rf "$stage"
say "$copied source files updated"
# Keep make from regenerating the checked-in parsers (build-reference.sh).
for pair in grammar.cc:grammar.y xml.cc:xml.y pcodeparse.cc:pcodeparse.y \
            slghparse.cc:slghparse.y slghparse.hh:slghparse.y slghparse.hh:slghparse.cc \
            slghscan.cc:slghscan.l slghscan.cc:slghparse.hh slghscan.cc:slgh_compile.hh; do
  gen=$OUT/src/cpp/${pair%%:*}; src=$OUT/src/cpp/${pair##*:}
  if [ -n "$(find "$src" -newer "$gen")" ]; then touch "$gen"; fi
done

# ------------------------------------------------------------ zlib
zdir=$OUT/src/zlib
if [ ! -f "$zdir/libz.a" ] || [ -n "$(find "$zdir" -type f \( -name '*.c' -o -name '*.h' \) -newer "$zdir/libz.a" | head -1)" ]; then
  say "compiling the bundled zlib"
  rm -f "$zdir"/*.o "$zdir/libz.a"
  for c in "$zdir"/*.c; do
    # shellcheck disable=SC2086
    $CC_CMD $ZLIB_CFLAGS -c "$c" -o "${c%.c}.o" || die "zlib: $c failed"
  done
  ar qc "$zdir/libz.a" "$zdir"/*.o
  ranlib "$zdir/libz.a"
fi

# ------------------------------------------------------------ console
cmake_() {
  make -C "$OUT/src/cpp" "$@" \
    "CXX=$CXX_CMD -std=c++11" ARCH_TYPE= "ADDITIONAL_FLAGS=$CXX_EXTRA_FLAGS" BFDLIB= \
    LNK=../zlib/libz.a \
    "EXTRA=\$(filter-out $BFD_NAMES \$(CORE) \$(DECCORE) \$(SLEIGH) \$(GHIDRA) \$(SLACOMP) \$(SPECIAL),\$(ALL_NAMES))"
}
mkdir -p "$OUT/logs" "$OUT/bin" "$OUT/obj"
say "make -j$JOBS decomp_opt (log: $OUT/logs/make.log)"
cmake_ -j"$JOBS" decomp_opt > "$OUT/logs/make.log" 2>&1 \
  || { grep -n -B2 -A6 'error' "$OUT/logs/make.log" | head -60 >&2; die "make failed"; }
cmake_ -s -f Makefile -f "$ROOT/tools/reference/consoleext/vars.mk" bk-vars > "$OUT/logs/vars.txt" 2>/dev/null \
  || die "reading the Makefile's variables failed"
var() { sed -n "s/^$1=//p" "$OUT/logs/vars.txt"; }
say "compiling bk_printlog.cc"
# shellcheck disable=SC2046,SC2086
(cd "$OUT/src/cpp" && $(var BK_CXX) $(var BK_ARCH_TYPE) $(var BK_OPT_CXXFLAGS) $(var BK_ADDITIONAL_FLAGS) \
    $(var BK_COMMANDLINE_OPT) -fno-access-control -I "$OUT/src/cpp" -c "$HERE/bk_printlog.cc" -o "$OUT/obj/bk_printlog.o") \
  || die "compiling bk_printlog.cc failed"
# shellcheck disable=SC2046,SC2086
(cd "$OUT/src/cpp" && $(var BK_CXX) $(var BK_OPT_CXXFLAGS) $(var BK_ARCH_TYPE) -o "$OUT/bin/decomp_instr.new" \
    $(var BK_OPT_OBJS) "$OUT/obj/bk_printlog.o" $(var BK_BFDLIB) $(var BK_LNK)) \
  || die "linking decomp_instr failed"
mv "$OUT/bin/decomp_instr.new" "$OUT/bin/decomp_instr"
say "built $OUT/bin/decomp_instr"
