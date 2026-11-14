#!/usr/bin/env bash
# Builds the reference tools Basilisk is measured against (ADR-007,
# docs/features/reference-tools.md): Ghidra's SLEIGH compiler, decompiler
# console (optimised and CPUI_DEBUG) and decompiler test runner, Basilisk's
# pcodedump and snippetdump oracles, the two consoles with Basilisk's console
# extension (ADR-042), and a compiled .sla for every processor language.
#
# Everything is written under one directory outside both repositories
# (BASILISK_REFERENCE_DIR, default ../reference). The Ghidra tree
# (BASILISK_GHIDRA_DIR, default ../ghidra) is only ever read.
#
# The script is incremental: each step records a fingerprint of its inputs
# under <reference>/.state and is skipped when the fingerprint is unchanged
# and its outputs exist. A second run with nothing changed does no work.
#
# Written for bash 3.2 (what macOS ships): no associative arrays, no mapfile.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/build-reference.sh [--force] [--jobs N] [--help]

  --force     discard the reference directory's build state and rebuild everything
  --jobs N    parallel jobs for make and for .sla compilation
              (default: $JOBS, else $CARGO_BUILD_JOBS, else half the cores)

environment:
  BASILISK_GHIDRA_DIR      Ghidra source tree, read-only   (default ../ghidra)
  BASILISK_REFERENCE_DIR   where everything is built       (default ../reference)
  CXX, CC                  compilers                       (default g++, cc)
EOF
}

say() { printf '%s\n' "$*"; }
die() { printf 'build-reference: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- hashing

# SHA is expanded unquoted on purpose: it is a command and its arguments, and
# xargs needs a real command rather than a shell function.
if command -v sha256sum >/dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA="shasum -a 256"
else
  die "need sha256sum or shasum"
fi

hash_stdin() { $SHA | cut -d' ' -f1; }
hash_file() { $SHA "$1" | cut -d' ' -f1; }

# Hash of the names and contents of every file under a directory, compiled
# .sla files excepted (they are outputs, never inputs).
hash_tree() {
  (cd "$1" && find . -type f ! -name '*.sla' | LC_ALL=C sort | tr '\n' '\0' | xargs -0 $SHA) | hash_stdin
}

file_size() { wc -c < "$1" | tr -d ' '; }

# ------------------------------------------------- .sla worker (re-entrant)
#
# `build-reference.sh __compile_one <spec>` compiles one .slaspec of the
# overlay. It is what the parallel step runs through xargs; the options of
# the spec's module were written to .state/lang/<Module>.opts beforehand.

compile_one() {
  local spec=$1
  local ref=$BK_REFERENCE_DIR
  local rel=${spec#"$ref/Ghidra/Processors/"}
  local module=${rel%%/*}
  local name
  name=$(basename "$spec" .slaspec)
  local out=${spec%.slaspec}.sla
  local logdir=$ref/logs/sleigh/$module
  mkdir -p "$logdir"
  local log=$logdir/$name.log
  local timefile=$logdir/$name.time
  rm -f "$out" "$out.part" "$logdir/$name.failed"

  local opts=()
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && opts[${#opts[@]}]=$line
  done < "$ref/.state/lang/$module.opts"

  local status=0
  TIMEFORMAT=%3R
  # shellcheck disable=SC2086
  { time "$ref/bin/sleigh" ${opts[@]+"${opts[@]}"} "-DBaseDir=$ref" "$spec" "$out.part" > "$log" 2>&1; } \
    2> "$timefile" || status=$?
  if [ "$status" -ne 0 ] || [ ! -s "$out.part" ]; then
    rm -f "$out.part"
    printf '%s\n' "$status" > "$logdir/$name.failed"
    printf '  FAILED   %s/%s.slaspec (exit %s)\n' "$module" "$name" "$status"
    return 1
  fi
  mv "$out.part" "$out"
  printf '  compiled %s/%s.sla (%s s)\n' "$module" "$name" "$(cat "$timefile")"
}

if [ "${1:-}" = "__compile_one" ]; then
  compile_one "$2"
  exit $?
fi

# ------------------------------------------------------------- arguments

FORCE=0
JOBS=${JOBS:-${CARGO_BUILD_JOBS:-}}
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --jobs) shift; [ $# -gt 0 ] || die "--jobs needs a number"; JOBS=$1 ;;
    --jobs=*) JOBS=${1#--jobs=} ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

if [ -z "$JOBS" ]; then
  cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
  JOBS=$((cores / 2))
fi
case "$JOBS" in ''|*[!0-9]*) die "bad job count: $JOBS" ;; esac
[ "$JOBS" -ge 1 ] || JOBS=1

SCRIPT=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CXX_CMD=${CXX:-g++}
CC_CMD=${CC:-cc}

# ------------------------------------------------------- 1. locate Ghidra

GHIDRA=${BASILISK_GHIDRA_DIR:-$ROOT/../ghidra}
[ -d "$GHIDRA" ] || die "Ghidra source tree not found at $GHIDRA (set BASILISK_GHIDRA_DIR)"
GHIDRA=$(cd "$GHIDRA" && pwd -P)
DEC=$GHIDRA/Ghidra/Features/Decompiler/src/decompile
PROCESSORS=$GHIDRA/Ghidra/Processors
[ -f "$DEC/cpp/Makefile" ] || die "$GHIDRA is not a Ghidra source tree (no decompiler Makefile)"
[ -d "$PROCESSORS" ] || die "$GHIDRA is not a Ghidra source tree (no Ghidra/Processors)"

REF=${BASILISK_REFERENCE_DIR:-$ROOT/../reference}
mkdir -p "$REF"
REF=$(cd "$REF" && pwd -P)
case "$REF/" in
  "$GHIDRA"/*) die "the reference directory ($REF) must not be inside the Ghidra tree" ;;
esac

if [ "$FORCE" -eq 1 ]; then
  say "forced: discarding build state in $REF"
  rm -rf "$REF/.state" "$REF/src" "$REF/bin" "$REF/Ghidra" "$REF/logs" "$REF/STAMP"
fi
STATE=$REF/.state
LOGS=$REF/logs
mkdir -p "$STATE/lang" "$LOGS" "$REF/bin"

# --no-optional-locks: a plain `git status` may rewrite .git/index, and
# nothing in the Ghidra tree is ours to write.
ghidra_git() { git --no-optional-locks -C "$GHIDRA" "$@" 2>/dev/null; }
GHIDRA_COMMIT=$(ghidra_git rev-parse HEAD || echo unknown)
if [ "$GHIDRA_COMMIT" = unknown ]; then
  GHIDRA_DIRTY=unknown
elif [ -n "$(ghidra_git status --porcelain -- Ghidra/Features/Decompiler/src/decompile Ghidra/Processors || true)" ]; then
  GHIDRA_DIRTY=yes
else
  GHIDRA_DIRTY=no
fi

say "ghidra:    $GHIDRA (commit $GHIDRA_COMMIT, modified: $GHIDRA_DIRTY)"
say "reference: $REF"
say "jobs:      $JOBS"

SECONDS=0
CHANGED=0   # set when any step did work, so STAMP is rewritten

# ------------------------------------------------- 2. sources and tools

PATCH_DIR=$ROOT/tools/reference/patches
PATCHES=()
if [ -d "$PATCH_DIR" ]; then
  for p in "$PATCH_DIR"/*.patch; do
    [ -f "$p" ] && PATCHES[${#PATCHES[@]}]=$p
  done
fi

# Sources that need GNU BFD (not on a stock machine, and GPL): anything that
# includes the BFD load image. The Makefile sweeps every *.cc into EXTRA, so
# EXTRA is recomputed on the make command line without them.
BFD_NAMES=$(cd "$DEC/cpp" && grep -lE '#include "(loadimage_bfd|bfd_arch)\.hh"' ./*.cc | sed -e 's#^\./##' -e 's#\.cc$##' | LC_ALL=C sort | tr '\n' ' ')

CXX_VERSION=$($CXX_CMD --version 2>/dev/null | head -1 || true)
[ -n "$CXX_VERSION" ] || die "C++ compiler '$CXX_CMD' not found (set CXX)"
MAKE_VERSION=$(make --version 2>/dev/null | head -1 || true)
[ -n "$MAKE_VERSION" ] || die "make not found"
HOST=$(uname -sm)

# What the Makefile gets instead of its own settings:
#   ARCH_TYPE=            it forces -arch x86_64 on macOS and -m32 on non-x86 Linux; build native
#   ADDITIONAL_FLAGS      -w (Ghidra's warnings are not ours), LOCAL_ZLIB (use the bundled zlib,
#                         as Ghidra's Gradle build does), -fsigned-char and -ffp-contract=off
#                         (see below); drops -mmacosx-version-min=10.6
#   BFDLIB=               no GNU BFD
#   LNK                   the bundled zlib instead of -lz
#   EXTRA                 as in the Makefile, minus the BFD-dependent sources
#
# -fsigned-char: Ghidra's C++ assumes `char` is signed, as it is on x86 and
# on macOS arm64. On Linux aarch64, where it is unsigned, decomp_test built
# without the flag spins at full CPU on every data test (measured with
# g++ 14 in a container; the unit tests pass). The flag changes nothing
# where `char` is already signed.
#
# -ffp-contract=off (ADR-032, docs/research/sla-host-dependence.md): no
# fusing of a multiply and an add into one instruction. Compilers targeting
# AArch64 contract by default, and Ghidra's SLEIGH compiler then breaks
# score ties in its decision trees differently from x86-64 (14 of 150 .sla
# files differ). With the flag every host builds x86-64 Linux's bytes. It is
# passed to every compile (tools, pcodedump, zlib) so that no reference
# tool's floating point depends on contraction.
FP_FLAGS="-ffp-contract=off"
CXX_EXTRA_FLAGS="-w -DLOCAL_ZLIB -fsigned-char $FP_FLAGS"
ZLIB_CFLAGS="-O2 -w -DNO_GZIP $FP_FLAGS"
MAKE_FLAGS_DESC="CXX=$CXX_CMD -std=c++11; ARCH_TYPE=; ADDITIONAL_FLAGS=$CXX_EXTRA_FLAGS; BFDLIB=; LNK=../zlib/libz.a; EXTRA without: $BFD_NAMES"

tools_fingerprint() {
  {
    echo "host: $HOST"
    echo "cxx: $CXX_VERSION"
    echo "cc: $CC_CMD"
    echo "make: $MAKE_FLAGS_DESC"
    echo "zlib: $ZLIB_CFLAGS"
    for d in cpp zlib unittests; do
      echo "tree $d: $(hash_tree "$DEC/$d")"
    done
    for p in ${PATCHES[@]+"${PATCHES[@]}"}; do
      echo "patch $(basename "$p"): $(hash_file "$p")"
    done
  } | hash_stdin
}

# Bring <reference>/src up to date with Ghidra's sources plus our patches,
# touching only files whose content changed so make rebuilds the minimum.
sync_sources() {
  local stage=$REF/src.stage
  rm -rf "$stage"
  mkdir -p "$stage" "$REF/src"
  local d
  for d in cpp zlib unittests; do
    cp -R "$DEC/$d" "$stage/$d"
  done
  local p
  for p in ${PATCHES[@]+"${PATCHES[@]}"}; do
    say "  applying $(basename "$p")"
    patch -s -p1 -d "$stage" < "$p" || die "patch $(basename "$p") does not apply to this Ghidra commit"
  done
  find "$stage" -name '*.orig' -exec rm -f {} +

  local f copied=0
  (cd "$stage" && find . -type f | LC_ALL=C sort) > "$stage.list"
  while IFS= read -r f; do
    if ! cmp -s "$stage/$f" "$REF/src/$f" 2>/dev/null; then
      mkdir -p "$(dirname "$REF/src/$f")"
      cp "$stage/$f" "$REF/src/$f"
      copied=$((copied + 1))
    fi
  done < "$stage.list"
  # Sources that Ghidra no longer has must not linger: the Makefile compiles every *.cc.
  for d in cpp zlib unittests; do
    (cd "$REF/src/$d" && find . -maxdepth 1 -type f \( -name '*.cc' -o -name '*.hh' -o -name '*.c' -o -name '*.h' -o -name '*.y' -o -name '*.l' \) | LC_ALL=C sort) \
      | while IFS= read -r f; do
          [ -f "$stage/$d/$f" ] || { say "  removing stale $d/${f#./}"; rm -f "$REF/src/$d/$f"; }
        done
  done
  rm -rf "$stage" "$stage.list"
  say "  $copied source files updated"

  # The generated parsers are checked in. Keep make from regenerating them
  # (macOS ships bison 2.3, too old for these grammars): wherever the
  # Makefile makes a generated file depend on another file, the generated
  # file must not be the older of the two. The pairs are in dependency order.
  # `find -newer` compares full-resolution timestamps, as make does.
  local pair gen src
  for pair in grammar.cc:grammar.y xml.cc:xml.y pcodeparse.cc:pcodeparse.y \
              slghparse.cc:slghparse.y slghparse.hh:slghparse.y slghparse.hh:slghparse.cc \
              slghscan.cc:slghscan.l slghscan.cc:slghparse.hh slghscan.cc:slgh_compile.hh; do
    gen=$REF/src/cpp/${pair%%:*}
    src=$REF/src/cpp/${pair##*:}
    [ -f "$gen" ] || die "generated parser source ${pair%%:*} is missing from the Ghidra tree; regenerate it with bison >= 3 and flex"
    if [ -n "$(find "$src" -newer "$gen")" ]; then
      touch "$gen"
    fi
  done
}

build_zlib() {
  local dir=$REF/src/zlib newer
  newer=$(find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -newer "$dir/libz.a" 2>/dev/null | head -1 || true)
  if [ -f "$dir/libz.a" ] && [ -z "$newer" ] \
      && [ "$(cat "$STATE/zlib-flags" 2>/dev/null || true)" = "$ZLIB_CFLAGS" ]; then
    return 0
  fi
  say "  compiling the bundled zlib"
  rm -f "$dir"/*.o "$dir/libz.a"
  local c
  for c in "$dir"/*.c; do
    # NO_GZIP as in Ghidra's Gradle build (buildNatives.gradle).
    # shellcheck disable=SC2086
    $CC_CMD $ZLIB_CFLAGS -c "$c" -o "${c%.c}.o" || die "zlib: $c failed to compile"
  done
  ar qc "$dir/libz.a" "$dir"/*.o
  ranlib "$dir/libz.a"
  printf '%s\n' "$ZLIB_CFLAGS" > "$STATE/zlib-flags"
}

build_tools() {
  local log=$LOGS/make.log
  say "  make -j$JOBS sleigh_opt decomp_opt decomp_test_dbg libsla.a (log: $log)"
  # make does not track flags: when they change, start from no objects.
  if [ "$(cat "$STATE/make-flags" 2>/dev/null || true)" != "$MAKE_FLAGS_DESC" ]; then
    make -C "$REF/src/cpp" clean > /dev/null 2>&1 || true
    rm -f "$REF/src/cpp/libsla.a"
  fi
  # EXTRA is passed unexpanded: make evaluates it where the Makefile uses it.
  if ! make -C "$REF/src/cpp" -j"$JOBS" sleigh_opt decomp_opt decomp_test_dbg libsla.a \
      "CXX=$CXX_CMD -std=c++11" ARCH_TYPE= "ADDITIONAL_FLAGS=$CXX_EXTRA_FLAGS" BFDLIB= \
      LNK=../zlib/libz.a \
      "EXTRA=\$(filter-out $BFD_NAMES \$(CORE) \$(DECCORE) \$(SLEIGH) \$(GHIDRA) \$(SLACOMP) \$(SPECIAL),\$(ALL_NAMES))" \
      > "$log" 2>&1; then
    grep -n -B2 -A6 'error' "$log" | head -80 >&2 || true
    tail -5 "$log" >&2
    die "building Ghidra's tools failed; full log: $log"
  fi
  printf '%s\n' "$MAKE_FLAGS_DESC" > "$STATE/make-flags"
  local pair
  for pair in sleigh_opt:sleigh decomp_opt:decomp decomp_test_dbg:decomp_test; do
    cp "$REF/src/cpp/${pair%%:*}" "$REF/bin/${pair##*:}.new"
    mv "$REF/bin/${pair##*:}.new" "$REF/bin/${pair##*:}"
  done
}

say "[1/5] Ghidra tools"
TOOLS_FP=$(tools_fingerprint)
if [ "$(cat "$STATE/tools.fp" 2>/dev/null || true)" = "$TOOLS_FP" ] \
    && [ -x "$REF/bin/sleigh" ] && [ -x "$REF/bin/decomp" ] && [ -x "$REF/bin/decomp_test" ] \
    && [ -f "$REF/src/cpp/libsla.a" ] && [ -f "$REF/src/zlib/libz.a" ]; then
  say "  up to date"
else
  rm -f "$STATE/tools.fp"
  sync_sources
  build_zlib
  build_tools
  printf '%s\n' "$TOOLS_FP" > "$STATE/tools.fp"
  CHANGED=1
  say "  built bin/sleigh, bin/decomp, bin/decomp_test"
fi

# ------------------------------- 1b. decomp_dbg and the console extension
#
# docs/features/decomp-oracle.md 4.2, ADR-042. Three more consoles, all from
# the objects of step 1's source copy and none changing what step 1 built:
#   bin/decomp_dbg     Ghidra's own CPUI_DEBUG console (`make decomp_dbg`)
#   bin/decomp_bk      decomp_opt's objects + Basilisk's console extension
#   bin/decomp_bk_dbg  decomp_dbg's objects + the extension
# The extension (tools/reference/consoleext) is compiled outside Ghidra's
# Makefile, with the Makefile's own flags plus -fno-access-control, into
# <reference>/src/consoleext; it registers its commands through a static
# IfaceCapability, so linking its objects is enough. Each part has its own
# fingerprint: a change to the extension relinks only the two _bk consoles.

EXT_DIR=$ROOT/tools/reference/consoleext
[ -f "$EXT_DIR/vars.mk" ] || die "missing $EXT_DIR/vars.mk"
EXT_SOURCES=()
for f in "$EXT_DIR"/*.cc "$EXT_DIR"/*.hh; do
  [ -f "$f" ] && EXT_SOURCES[${#EXT_SOURCES[@]}]=$f
done
[ ${#EXT_SOURCES[@]} -gt 0 ] || die "no sources in $EXT_DIR"
# The hash of the extension's sources, concatenated in byte order of their names.
EXT_HASH=$(for f in "${EXT_SOURCES[@]}"; do basename "$f"; done | LC_ALL=C sort \
  | while IFS= read -r f; do cat "$EXT_DIR/$f"; done | hash_stdin)

# make with step 1's overrides (EXTRA unexpanded, as there).
ref_make() {
  make -C "$REF/src/cpp" "$@" \
    "CXX=$CXX_CMD -std=c++11" ARCH_TYPE= "ADDITIONAL_FLAGS=$CXX_EXTRA_FLAGS" BFDLIB= \
    LNK=../zlib/libz.a \
    "EXTRA=\$(filter-out $BFD_NAMES \$(CORE) \$(DECCORE) \$(SLEIGH) \$(GHIDRA) \$(SLACOMP) \$(SPECIAL),\$(ALL_NAMES))"
}

say "[1b/5] decomp_dbg and the console extension"
DBG_FP=$( { echo "tools: $TOOLS_FP"; echo "target: decomp_dbg"; } | hash_stdin)
if [ "$(cat "$STATE/decomp_dbg.fp" 2>/dev/null || true)" = "$DBG_FP" ] && [ -x "$REF/bin/decomp_dbg" ]; then
  say "  decomp_dbg up to date"
else
  rm -f "$STATE/decomp_dbg.fp"
  say "  make -j$JOBS decomp_dbg (log: $LOGS/make-dbg.log)"
  # Only com_dbg objects and decomp_dbg are made; step 1's outputs are not
  # targets here, and the generated parsers keep the time stamps step 1 gave them.
  if ! ref_make -j"$JOBS" decomp_dbg > "$LOGS/make-dbg.log" 2>&1; then
    grep -n -B2 -A6 'error' "$LOGS/make-dbg.log" | head -80 >&2 || true
    die "building decomp_dbg failed; full log: $LOGS/make-dbg.log"
  fi
  cp "$REF/src/cpp/decomp_dbg" "$REF/bin/decomp_dbg.new"
  mv "$REF/bin/decomp_dbg.new" "$REF/bin/decomp_dbg"
  printf '%s\n' "$DBG_FP" > "$STATE/decomp_dbg.fp"
  CHANGED=1
  say "  built bin/decomp_dbg"
fi

# The Makefile's variables as make evaluates them with the overrides above.
make_var() { sed -n "s/^$1=//p" "$STATE/consoleext.vars"; }
EXT_FP=$( { echo "tools: $TOOLS_FP"; echo "decomp_dbg: $DBG_FP"; echo "extension: $EXT_HASH"; } | hash_stdin)
if [ "$(cat "$STATE/consoleext.fp" 2>/dev/null || true)" = "$EXT_FP" ] \
    && [ -x "$REF/bin/decomp_bk" ] && [ -x "$REF/bin/decomp_bk_dbg" ]; then
  say "  decomp_bk, decomp_bk_dbg up to date"
else
  rm -f "$STATE/consoleext.fp"
  ref_make -s -f Makefile -f "$EXT_DIR/vars.mk" bk-vars > "$STATE/consoleext.vars" 2> "$LOGS/consoleext.log" \
    || die "reading the Makefile's variables failed; log: $LOGS/consoleext.log"
  EXT_OUT=$REF/src/consoleext
  rm -rf "$EXT_OUT"
  mkdir -p "$EXT_OUT/opt" "$EXT_OUT/dbg"
  : > "$LOGS/consoleext.log"
  # Compile one variant: ext_compile opt|dbg CXXFLAGS DEFINES
  ext_compile() {
    local variant=$1 flags=$2 defines=$3 src obj
    for src in "$EXT_DIR"/*.cc; do
      obj=$EXT_OUT/$variant/$(basename "$src" .cc).o
      # shellcheck disable=SC2086
      (cd "$REF/src/cpp" && $(make_var BK_CXX) $(make_var BK_ARCH_TYPE) $flags $(make_var BK_ADDITIONAL_FLAGS) \
          $defines -fno-access-control -I "$REF/src/cpp" -c "$src" -o "$obj") >> "$LOGS/consoleext.log" 2>&1 \
        || { cat "$LOGS/consoleext.log" >&2; die "compiling $(basename "$src") ($variant) failed"; }
    done
  }
  # Link one console: ext_link NAME CXXFLAGS OBJS-VARIABLE VARIANT
  ext_link() {
    local name=$1 flags=$2 objs=$3 variant=$4
    # shellcheck disable=SC2046,SC2086
    (cd "$REF/src/cpp" && $(make_var BK_CXX) $flags $(make_var BK_ARCH_TYPE) -o "$REF/bin/$name.new" \
        $(make_var "$objs") "$EXT_OUT/$variant"/*.o $(make_var BK_BFDLIB) $(make_var BK_LNK)) >> "$LOGS/consoleext.log" 2>&1 \
      || { cat "$LOGS/consoleext.log" >&2; die "linking $name failed"; }
    mv "$REF/bin/$name.new" "$REF/bin/$name"
  }
  say "  compiling the console extension ($(ls "$EXT_DIR"/*.cc | wc -l | tr -d ' ') files, twice)"
  ext_compile opt "$(make_var BK_OPT_CXXFLAGS)" "$(make_var BK_COMMANDLINE_OPT)"
  ext_compile dbg "$(make_var BK_DBG_CXXFLAGS)" "$(make_var BK_COMMANDLINE_DEBUG)"
  ext_link decomp_bk "$(make_var BK_OPT_CXXFLAGS)" BK_OPT_OBJS opt
  ext_link decomp_bk_dbg "$(make_var BK_DBG_CXXFLAGS)" BK_DBG_OBJS dbg
  printf '%s\n' "$EXT_FP" > "$STATE/consoleext.fp"
  CHANGED=1
  say "  built bin/decomp_bk, bin/decomp_bk_dbg"
fi

# -------------------------------------------------------- 3. languages
#
# Ghidra's Gradle build (gradle/processorProject.gradle, task sleighCompile)
# runs the compiler once per processor module with the options listed in the
# module's build.gradle (`sleighCompileOptions`) and -DBaseDir=<root>; a
# `%%Module%%` in an option is replaced by that module's path below the root
# so a spec can include files from another module. We do the same, per spec,
# with the overlay as the root.

# Print the sleighCompileOptions of a module's build.gradle, one per line.
module_sleigh_options() {
  local gradle=$1
  [ -f "$gradle" ] || return 0
  awk '
    /sleighCompileOptions[ \t]*=[ \t]*\[/ { inlist = 1 }
    {
      line = $0
      sub(/\/\/.*/, "", line)
      if (inlist || line ~ /sleighCompileOptions\.add/) {
        while (match(line, /"[^"]*"|\047[^\047]*\047/)) {
          print substr(line, RSTART + 1, RLENGTH - 2)
          line = substr(line, RSTART + RLENGTH)
        }
      }
      if (inlist && $0 ~ /\]/) inlist = 0
    }
  ' "$gradle"
}

# Translate a module's options for the C++ compiler: resolve %%Module%%
# (distribution layout: the path below the root is /Ghidra/Processors/<Module>)
# and drop options only the Java compiler knows.
write_module_options() {
  local module=$1 opt out=$STATE/lang/$1.opts
  : > "$out.new"
  module_sleigh_options "$PROCESSORS/$module/build.gradle" | while IFS= read -r opt; do
    opt=$(printf '%s' "$opt" | sed -e 's#%%\([A-Za-z0-9_.-]*\)%%#/Ghidra/Processors/\1#g')
    case "$opt" in
      -D*=*|-u|-l|-c|-n|-t|-e|-s) printf '%s\n' "$opt" >> "$out.new" ;;
      *) say "  note: $module: option '$opt' is not supported by the C++ compiler; ignored" ;;
    esac
  done
  mv "$out.new" "$out"
}

say "[2/5] languages"
SLEIGH_HASH=$(hash_file "$REF/bin/sleigh")
OVERLAY=$REF/Ghidra/Processors
mkdir -p "$OVERLAY"
: > "$STATE/compile.list"
: > "$STATE/modules.list"
for langdir in "$PROCESSORS"/*/data/languages; do
  [ -d "$langdir" ] || continue
  module=$(basename "$(dirname "$(dirname "$langdir")")")
  printf '%s\n' "$module" >> "$STATE/modules.list"
  write_module_options "$module"
  fp=$( { echo "sleigh: $SLEIGH_HASH"; echo "tree: $(hash_tree "$langdir")"; cat "$STATE/lang/$module.opts"; } | hash_stdin)
  dest=$OVERLAY/$module/data/languages
  if [ "$(cat "$STATE/lang/$module.fp" 2>/dev/null || true)" != "$fp" ] || [ ! -d "$dest" ]; then
    rm -f "$STATE/lang/$module.fp"
    rm -rf "$dest"
    mkdir -p "$OVERLAY/$module/data"
    cp -R "$langdir" "$dest"
    find "$dest" -name '*.sla' -exec rm -f {} +
  fi
  printf '%s\n' "$fp" > "$STATE/lang/$module.fp.pending"
  for spec in "$dest"/*.slaspec; do
    [ -f "$spec" ] || continue
    [ -s "${spec%.slaspec}.sla" ] || printf '%s\n' "$spec" >> "$STATE/compile.list"
  done
done
# Modules that no longer exist in Ghidra.
for dir in "$OVERLAY"/*; do
  [ -d "$dir" ] || continue
  if ! grep -qxF "$(basename "$dir")" "$STATE/modules.list"; then
    say "  removing stale module $(basename "$dir")"
    rm -rf "$dir" "$STATE/lang/$(basename "$dir")".*
    CHANGED=1
  fi
done

SPEC_TOTAL=$(find "$OVERLAY" -name '*.slaspec' | wc -l | tr -d ' ')
TO_COMPILE=$(wc -l < "$STATE/compile.list" | tr -d ' ')
if [ "$TO_COMPILE" -eq 0 ]; then
  say "  up to date ($SPEC_TOTAL languages)"
else
  say "  compiling $TO_COMPILE of $SPEC_TOTAL .slaspec files, $JOBS at a time"
  lang_start=$SECONDS
  export BK_REFERENCE_DIR=$REF
  mkdir -p "$LOGS/sleigh"
  find "$LOGS/sleigh" -name '*.failed' -exec rm -f {} +
  xargs_status=0
  tr '\n' '\0' < "$STATE/compile.list" | xargs -0 -n 1 -P "$JOBS" "$SCRIPT" __compile_one || xargs_status=$?
  failed=$(find "$LOGS/sleigh" -name '*.failed' | LC_ALL=C sort)
  if [ -n "$failed" ] || [ "$xargs_status" -ne 0 ]; then
    for f in $failed; do
      say "---- $(basename "$(dirname "$f")")/$(basename "$f" .failed).slaspec: sleigh exited $(cat "$f")"
      cat "${f%.failed}.log"
    done
    die "$(printf '%s\n' "$failed" | grep -c . || true) of $SPEC_TOTAL .slaspec files failed to compile (logs: $LOGS/sleigh)"
  fi
  printf '%s\n' "$((SECONDS - lang_start))" > "$STATE/lang-wall-seconds"
  printf '%s\n' "$JOBS" > "$STATE/lang-wall-jobs"
  printf '%s\n' "$TO_COMPILE" > "$STATE/lang-wall-count"
  CHANGED=1
fi
for pending in "$STATE"/lang/*.fp.pending; do
  [ -f "$pending" ] && mv "$pending" "${pending%.pending}"
done
SLA_TOTAL=$(find "$OVERLAY" -name '*.sla' | wc -l | tr -d ' ')
[ "$SLA_TOTAL" -eq "$SPEC_TOTAL" ] || die "$SPEC_TOTAL .slaspec files but $SLA_TOTAL .sla files in the overlay"

# -------------------------------------------------------- 4. pcodedump

say "[3/5] pcodedump"
PCODEDUMP_SRC=$ROOT/tools/reference/pcodedump.cc
[ -f "$PCODEDUMP_SRC" ] || die "missing $PCODEDUMP_SRC"
PCODEDUMP_FP=$( { echo "tools: $TOOLS_FP"; echo "libsla: $(hash_file "$REF/src/cpp/libsla.a")"; echo "source: $(hash_file "$PCODEDUMP_SRC")"; } | hash_stdin)
if [ "$(cat "$STATE/pcodedump.fp" 2>/dev/null || true)" = "$PCODEDUMP_FP" ] && [ -x "$REF/bin/pcodedump" ]; then
  say "  up to date"
else
  rm -f "$STATE/pcodedump.fp"
  if ! $CXX_CMD -std=c++11 -O2 $CXX_EXTRA_FLAGS -I "$REF/src/cpp" "$PCODEDUMP_SRC" \
      "$REF/src/cpp/libsla.a" "$REF/src/zlib/libz.a" -o "$REF/bin/pcodedump.new" > "$LOGS/pcodedump.log" 2>&1; then
    cat "$LOGS/pcodedump.log" >&2
    die "building pcodedump failed"
  fi
  mv "$REF/bin/pcodedump.new" "$REF/bin/pcodedump"
  printf '%s\n' "$PCODEDUMP_FP" > "$STATE/pcodedump.fp"
  CHANGED=1
  say "  built bin/pcodedump"
fi

# ------------------------------------------------------- 4b. snippetdump
# The p-code snippet oracle (tools/reference/snippetdump.cc), built like
# pcodedump against the same objects.

say "[3b/5] snippetdump"
SNIPPETDUMP_SRC=$ROOT/tools/reference/snippetdump.cc
[ -f "$SNIPPETDUMP_SRC" ] || die "missing $SNIPPETDUMP_SRC"
SNIPPETDUMP_FP=$( { echo "tools: $TOOLS_FP"; echo "libsla: $(hash_file "$REF/src/cpp/libsla.a")"; echo "source: $(hash_file "$SNIPPETDUMP_SRC")"; } | hash_stdin)
if [ "$(cat "$STATE/snippetdump.fp" 2>/dev/null || true)" = "$SNIPPETDUMP_FP" ] && [ -x "$REF/bin/snippetdump" ]; then
  say "  up to date"
else
  rm -f "$STATE/snippetdump.fp"
  if ! $CXX_CMD -std=c++11 -O2 $CXX_EXTRA_FLAGS -I "$REF/src/cpp" "$SNIPPETDUMP_SRC" \
      "$REF/src/cpp/libsla.a" "$REF/src/zlib/libz.a" -o "$REF/bin/snippetdump.new" > "$LOGS/snippetdump.log" 2>&1; then
    cat "$LOGS/snippetdump.log" >&2
    die "building snippetdump failed"
  fi
  mv "$REF/bin/snippetdump.new" "$REF/bin/snippetdump"
  printf '%s\n' "$SNIPPETDUMP_FP" > "$STATE/snippetdump.fp"
  CHANGED=1
  say "  built bin/snippetdump"
fi

# ------------------------------------------------- 5. Ghidra's own tests
#
# The result is a baseline, not a gate: failures are recorded and reported,
# and the script still succeeds, because what later tracks need to know is
# what Ghidra itself does on this host.

DATATESTS=$DEC/datatests
overlay_fingerprint() {
  (cd "$OVERLAY" && find . -type f -name '*.sla' | LC_ALL=C sort | tr '\n' '\0' | xargs -0 $SHA) | hash_stdin
}

# Run one decomp_test mode, recording its exit status and wall time.
run_decomp_test() {
  local name=$1; shift
  local status=0
  TIMEFORMAT=%3R
  { time "$REF/bin/decomp_test" "$@" > "$LOGS/$name.log" 2>&1; } 2> "$LOGS/$name.time.raw" || status=$?
  # When the runner is killed, bash writes its job message into the same
  # stream as `time`; the time is the last line.
  tail -n 1 "$LOGS/$name.time.raw" > "$LOGS/$name.time"
  rm -f "$LOGS/$name.time.raw"
  printf '%s\n' "$status" > "$LOGS/$name.status"
}

# A runner that died from a signal (exit status above 128) has no totals;
# say so instead of printing empty counts, and do not keep the result.
test_crash() {
  local status
  status=$(cat "$LOGS/$1.status")
  if [ "$status" -gt 128 ]; then
    echo "$2_crash: decomp_test $1 killed by signal $((status - 128)) after $(cat "$LOGS/$1.time") s (log: logs/$1.log)"
  fi
}

summarize_tests() {
  local out=$STATE/tests.summary
  {
    # Unit tests: "testing : NAME ..." followed by "  passed.", or by "  fail"
    # or "  fail: REASON" (after the assertion's own "  failed at ..." line),
    # then "P/T tests passed."
    awk '
      /^testing : / { name = $3 }
      /^  fail(:|$)/ { print "unit_failure: " name }
      /^[0-9]+\/[0-9]+ tests passed\.$/ { split($1, n, "/"); print "unit_passed: " n[1]; print "unit_total: " n[2] }
    ' "$LOGS/unittests.log"
    test_crash unittests unit
    echo "unit_exit: $(cat "$LOGS/unittests.status")"
    echo "unit_seconds: $(cat "$LOGS/unittests.time")"
    # Data tests: one "Success -- NAME" or "FAIL -- NAME" per <stringmatch>,
    # then the totals. A file that could not be run at all is reported in
    # separate lines and is not counted in the totals by decomp_test.
    awk '
      /^FAIL -- / { print "data_failure: " substr($0, 9) }
      /^Error (parsing|executing) / { print "data_error: " $0 }
      /^Error: Did not apply tests in / { print "data_error: " $0 }
      /^Total tests applied = / { print "data_total: " $5 }
      /^Total passing tests = / { print "data_passed: " $5 }
    ' "$LOGS/datatests.log"
    echo "data_files: $(find "$DATATESTS" -maxdepth 1 -name '*.xml' | wc -l | tr -d ' ')"
    test_crash datatests data
    echo "data_exit: $(cat "$LOGS/datatests.status")"
    echo "data_seconds: $(cat "$LOGS/datatests.time")"
  } > "$out"
}

summary_value() { sed -n "s/^$1: //p" "$STATE/tests.summary" | head -1; }

say "[4/5] Ghidra's unit tests and data tests"
TESTS_FP=$( { echo "decomp_test: $(hash_file "$REF/bin/decomp_test")"; echo "overlay: $(overlay_fingerprint)"; echo "datatests: $(hash_tree "$DATATESTS")"; } | hash_stdin)
if [ "$(cat "$STATE/tests.fp" 2>/dev/null || true)" = "$TESTS_FP" ] && [ -f "$STATE/tests.summary" ]; then
  say "  up to date"
else
  rm -f "$STATE/tests.fp"
  # Run from the log directory so nothing a test might write lands elsewhere.
  (cd "$LOGS" && run_decomp_test unittests -sleighpath "$REF" unittests)
  (cd "$LOGS" && run_decomp_test datatests -sleighpath "$REF" -path "$DATATESTS" datatests)
  summarize_tests
  # A crashed run is not a baseline: run the tests again next time.
  if ! grep -qE '^(unit|data)_crash: ' "$STATE/tests.summary"; then
    printf '%s\n' "$TESTS_FP" > "$STATE/tests.fp"
  fi
  CHANGED=1
fi
if [ -n "$(summary_value unit_total)" ]; then
  UNIT_RESULT="$(summary_value unit_passed)/$(summary_value unit_total) passed"
else
  UNIT_RESULT="did not finish"
fi
if [ -n "$(summary_value data_total)" ]; then
  DATA_RESULT="$(summary_value data_passed)/$(summary_value data_total) passed in $(summary_value data_files) files"
else
  DATA_RESULT="did not finish ($(summary_value data_files) files)"
fi
TEST_PROBLEMS=$(grep -cE '^(unit_failure|data_failure|data_error|unit_crash|data_crash): ' "$STATE/tests.summary" || true)
say "  unit tests: $UNIT_RESULT ($(summary_value unit_seconds) s, exit $(summary_value unit_exit))"
say "  data tests: $DATA_RESULT ($(summary_value data_seconds) s, exit $(summary_value data_exit))"
if [ "$TEST_PROBLEMS" -ne 0 ]; then
  say "  $TEST_PROBLEMS failures on this host:"
  grep -E '^(unit_failure|data_failure|data_error|unit_crash|data_crash): ' "$STATE/tests.summary" | sed 's/^/    /'
fi

# ------------------------------------------------------------ 6. STAMP

write_stamp() {
  local stamp=$REF/STAMP.new f
  {
    echo "Basilisk reference tools (scripts/build-reference.sh)"
    echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "ghidra_dir: $GHIDRA"
    echo "ghidra_commit: $GHIDRA_COMMIT"
    echo "ghidra_modified: $GHIDRA_DIRTY"
    echo "host: $HOST"
    echo "cxx: $CXX_VERSION"
    echo "make: $MAKE_VERSION"
    echo "bison: $(bison --version 2>/dev/null | head -1 || echo absent) (not used: checked-in parsers are kept)"
    echo "flex: $(flex --version 2>/dev/null | head -1 || echo absent) (not used: checked-in parsers are kept)"
    echo "make_overrides: $MAKE_FLAGS_DESC"
    echo "zlib_cflags: $ZLIB_CFLAGS"
    echo "fp_flags: $FP_FLAGS (every C and C++ compile; ADR-032)"
    if [ ${#PATCHES[@]} -eq 0 ]; then
      echo "patches: none"
    else
      for f in "${PATCHES[@]}"; do echo "patch: $(basename "$f") $(hash_file "$f")"; done
    fi
    echo "languages: $SLA_TOTAL compiled from $SPEC_TOTAL .slaspec files"
    if [ -f "$STATE/lang-wall-seconds" ]; then
      echo "languages_last_compile: $(cat "$STATE/lang-wall-count") files in $(cat "$STATE/lang-wall-seconds") s wall with $(cat "$STATE/lang-wall-jobs") jobs"
    fi
    echo "unit_tests: $UNIT_RESULT"
    echo "data_tests: $DATA_RESULT"
    grep -E '^(unit_failure|data_failure|data_error|unit_crash|data_crash|unit_exit|data_exit|unit_seconds|data_seconds): ' "$STATE/tests.summary" || true
    echo
    echo "== tools: sha256  bytes  path"
    for f in sleigh decomp decomp_test pcodedump snippetdump decomp_dbg decomp_bk decomp_bk_dbg; do
      printf '%s  %s  bin/%s\n' "$(hash_file "$REF/bin/$f")" "$(file_size "$REF/bin/$f")" "$f"
    done
    echo "console_extension: $EXT_HASH"
    echo
    echo "== languages: sha256  bytes  compile-seconds  path"
    (cd "$REF" && find Ghidra/Processors -type f -name '*.sla' | LC_ALL=C sort) | while IFS= read -r f; do
      local module name
      module=$(printf '%s' "$f" | cut -d/ -f3)
      name=$(basename "$f" .sla)
      printf '%s  %s  %s  %s\n' "$(hash_file "$REF/$f")" "$(file_size "$REF/$f")" \
        "$(cat "$LOGS/sleigh/$module/$name.time" 2>/dev/null || echo '?')" "$f"
    done
  } > "$stamp"
  mv "$stamp" "$REF/STAMP"
}

say "[5/5] STAMP"
if [ "$CHANGED" -eq 1 ] || [ ! -f "$REF/STAMP" ]; then
  write_stamp
  say "  wrote $REF/STAMP"
else
  say "  up to date"
fi

# ------------------------------------------------------------- summary

say
say "reference tools ready in $REF"
say "  tools:      bin/sleigh bin/decomp bin/decomp_test bin/pcodedump bin/snippetdump"
say "              bin/decomp_dbg bin/decomp_bk bin/decomp_bk_dbg"
say "  languages:  $SLA_TOTAL .sla files"
say "  unit tests: $UNIT_RESULT"
say "  data tests: $DATA_RESULT"
if [ "$CHANGED" -eq 1 ]; then
  say "  elapsed:    $SECONDS s"
else
  say "  elapsed:    $SECONDS s (nothing to do)"
fi
