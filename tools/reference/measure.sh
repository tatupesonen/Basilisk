#!/usr/bin/env bash
# Measures the reference tools: the baseline numbers in docs/PERF.md that
# Basilisk's SLEIGH compiler, decoder and decompiler are held against.
#
#   tools/reference/measure.sh [--x86-64-code FILE]
#
# Needs the reference directory built by scripts/build-reference.sh. Writes
# only below <reference>/measure, which it removes again. Everything is run
# one job at a time so the numbers are per-core costs; run it on an idle
# machine.
#
#   --x86-64-code FILE   raw x86-64 machine code to decode. Without it the
#                        script compiles some of Ghidra's own sources for
#                        x86-64 and uses the object files' text sections.
#
# Written for bash 3.2, like the build script.
set -euo pipefail

die() { printf 'measure: %s\n' "$*" >&2; exit 1; }

CODE_FILE=
while [ $# -gt 0 ]; do
  case "$1" in
    --x86-64-code) shift; [ $# -gt 0 ] || die "--x86-64-code needs a file"; CODE_FILE=$1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REF=${BASILISK_REFERENCE_DIR:-$ROOT/../reference}
[ -f "$REF/STAMP" ] || die "no reference directory at $REF; run scripts/build-reference.sh"
REF=$(cd "$REF" && pwd -P)
WORK=$REF/measure
rm -rf "$WORK"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

CXX_CMD=${CXX:-g++}
TIMEFORMAT=%3R

echo "host: $(uname -sm), $(getconf _NPROCESSORS_ONLN) cores"
echo "cxx: $($CXX_CMD --version 2>/dev/null | head -1)"
echo "ghidra: $(sed -n 's/^ghidra_commit: //p' "$REF/STAMP")"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ------------------------------------------------- SLEIGH compilation
#
# Every .slaspec of the overlay, compiled again one at a time with the
# options the build used, output discarded.

echo
echo "== SLEIGH compile (bin/sleigh, one at a time)"
: > "$WORK/compile-times"
find "$REF/Ghidra/Processors" -name '*.slaspec' | LC_ALL=C sort > "$WORK/specs"
while IFS= read -r spec; do
  rel=${spec#"$REF/Ghidra/Processors/"}
  module=${rel%%/*}
  opts=()
  while IFS= read -r line; do
    [ -n "$line" ] && opts[${#opts[@]}]=$line
  done < "$REF/.state/lang/$module.opts"
  { time "$REF/bin/sleigh" ${opts[@]+"${opts[@]}"} "-DBaseDir=$REF" "$spec" "$WORK/out.sla" > /dev/null 2>&1; } 2> "$WORK/time" \
    || die "$spec no longer compiles"
  printf '%s %s/%s\n' "$(cat "$WORK/time")" "$module" "$(basename "$spec")" >> "$WORK/compile-times"
done < "$WORK/specs"
awk '{ total += $1 } END { printf "languages: %d\ntotal: %.1f s\nmean: %.3f s\n", NR, total, total / NR }' "$WORK/compile-times"
echo "slowest five:"
sort -rn "$WORK/compile-times" | head -5 | awk '{ printf "  %6.3f s  %s\n", $1, $2 }'

# ----------------------------------------------------------- .sla sizes

echo
echo "== .sla sizes"
find "$REF/Ghidra/Processors" -name '*.sla' | LC_ALL=C sort | while IFS= read -r sla; do
  rel=${sla#"$REF/Ghidra/Processors/"}
  printf '%s %s/%s\n' "$(wc -c < "$sla" | tr -d ' ')" "${rel%%/*}" "$(basename "$sla")"
done | sort -n > "$WORK/sizes"
awk '
  { size[NR] = $1; total += $1 }
  END {
    printf "files: %d\ntotal: %.1f MB\nmedian: %.1f kB\nsmallest: %.1f kB\n", NR, total / 1e6, size[int((NR + 1) / 2)] / 1e3, size[1] / 1e3
  }' "$WORK/sizes"
echo "largest five:"
tail -5 "$WORK/sizes" | sort -rn | awk '{ printf "  %7.1f kB  %s\n", $1 / 1e3, $2 }'

# ------------------------------------------------------------ pcodedump

# Pick field NAME=VALUE out of a pcodedump --timing line.
timing_field() { tr '\t' '\n' | sed -n "s/^$1=//p"; }

# Best (smallest) of five runs of one timing field.
best_of_five() {
  local field=$1 i; shift
  for i in 1 2 3 4 5; do
    "$@" 2>&1 >/dev/null | timing_field "$field"
  done | sort -n | head -1
}

echo
echo "== pcodedump, x86:LE:64:default"
LANG_ID=x86:LE:64:default
load=$(best_of_five load_seconds "$REF/bin/pcodedump" "$REF" "$LANG_ID" 0 --timing --quiet --hex 90)
echo "language load (.sla to ready, best of 5): $(awk -v s="$load" 'BEGIN { printf "%.1f ms", s * 1000 }')"

if [ -z "$CODE_FILE" ]; then
  # Real compiler output: some of Ghidra's largest source files built for
  # x86-64, their text sections concatenated. (On macOS the text section
  # holds jump tables too, which a linear sweep reports as decode errors.)
  SOURCES="ruleaction coreaction fspec type printc funcdata_varnode block database"
  : > "$WORK/code.bin"
  for name in $SOURCES; do
    src=$REF/src/cpp/$name.cc
    case "$(uname -s)" in
      Darwin)
        $CXX_CMD -std=c++11 -O2 -w -arch x86_64 -c "$src" -o "$WORK/code.o" 2> "$WORK/cc.log" \
          || die "cannot compile $src for x86-64: $(head -3 "$WORK/cc.log")"
        # The (__TEXT,__text) section's file offset and size.
        # shellcheck disable=SC2046
        set -- $(otool -l "$WORK/code.o" | awk '
          $1 == "sectname" { name = $2 }
          $1 == "size" && name == "__text" && !size { size = $2 }
          $1 == "offset" && name == "__text" && !offset { offset = $2 }
          END { print offset, size }')
        [ $# -eq 2 ] || die "cannot find the text section of $WORK/code.o"
        # head leaves early, which is a broken pipe for tail, not a failure.
        { tail -c +"$(($1 + 1))" "$WORK/code.o" | head -c "$(($2))" > "$WORK/text.bin"; } || true
        [ "$(wc -c < "$WORK/text.bin" | tr -d ' ')" -eq "$(($2))" ] || die "cannot extract the text section"
        CODE_FLAGS="-O2 -arch x86_64"
        ;;
      *)
        [ "$(uname -m)" = x86_64 ] || die "not an x86-64 host; pass --x86-64-code FILE"
        $CXX_CMD -std=c++11 -O2 -w -c "$src" -o "$WORK/code.o" 2> "$WORK/cc.log" \
          || die "cannot compile $src: $(head -3 "$WORK/cc.log")"
        objcopy -O binary --only-section=.text "$WORK/code.o" "$WORK/text.bin"
        CODE_FLAGS="-O2"
        ;;
    esac
    cat "$WORK/text.bin" >> "$WORK/code.bin"
  done
  CODE_DESC="text sections of Ghidra's $(echo "$SOURCES" | sed 's/ /.cc, /g').cc built with $CXX_CMD $CODE_FLAGS"
  CODE_FILE=$WORK/code.bin
else
  CODE_DESC=$CODE_FILE
fi
[ -s "$CODE_FILE" ] || die "$CODE_FILE is empty"
echo "input: $CODE_DESC, $(wc -c < "$CODE_FILE" | tr -d ' ') bytes"

# Decode + lift only (--quiet), then the full text listing.
for mode in quiet listing; do
  if [ "$mode" = quiet ]; then flag=--quiet; else flag=; fi
  best=
  for i in 1 2 3 4 5; do
    # shellcheck disable=SC2086
    line=$("$REF/bin/pcodedump" "$REF" "$LANG_ID" 0x100000 --timing $flag < "$CODE_FILE" 2>&1 >/dev/null)
    seconds=$(printf '%s\n' "$line" | timing_field decode_seconds)
    if [ -z "$best" ] || awk -v a="$seconds" -v b="$best" 'BEGIN { exit !(a < b) }'; then
      best=$seconds
      best_line=$line
    fi
  done
  instructions=$(printf '%s\n' "$best_line" | timing_field instructions)
  ops=$(printf '%s\n' "$best_line" | timing_field ops)
  errors=$(printf '%s\n' "$best_line" | timing_field errors)
  bytes=$(printf '%s\n' "$best_line" | timing_field bytes)
  awk -v mode="$mode" -v s="$best" -v n="$instructions" -v ops="$ops" -v e="$errors" -v b="$bytes" 'BEGIN {
    what = (mode == "quiet") ? "decode + lift, no output" : "decode + lift + text listing"
    printf "%s (best of 5): %d instructions, %d p-code ops, %d errors in %.3f s\n", what, n, ops, e, s
    printf "  %.2f M instructions/s, %.2f M ops/s, %.1f MB/s, %.0f ns/instruction\n", n / s / 1e6, ops / s / 1e6, b / s / 1e6, s / n * 1e9
  }'
done

# ------------------------------------------------------------ data tests

echo
echo "== decompiler tests (bin/decomp_test)"
GHIDRA=$(sed -n 's/^ghidra_dir: //p' "$REF/STAMP")
DATATESTS=$GHIDRA/Ghidra/Features/Decompiler/src/decompile/datatests
[ -d "$DATATESTS" ] || die "no data tests at $DATATESTS"
best=
for i in 1 2 3; do
  (cd "$WORK" && { time "$REF/bin/decomp_test" -sleighpath "$REF" -path "$DATATESTS" datatests > data.log 2>&1 || true; } 2> time)
  seconds=$(cat "$WORK/time")
  if [ -z "$best" ] || awk -v a="$seconds" -v b="$best" 'BEGIN { exit !(a < b) }'; then best=$seconds; fi
done
applied=$(sed -n 's/^Total tests applied = //p' "$WORK/data.log")
passing=$(sed -n 's/^Total passing tests = //p' "$WORK/data.log")
files=$(find "$DATATESTS" -maxdepth 1 -name '*.xml' | wc -l | tr -d ' ')
echo "data tests: $files files, $passing/$applied checks pass, $best s (best of 3, includes loading each language once)"
best=
for i in 1 2 3; do
  (cd "$WORK" && { time "$REF/bin/decomp_test" -sleighpath "$REF" unittests > unit.log 2>&1 || true; } 2> time)
  seconds=$(cat "$WORK/time")
  if [ -z "$best" ] || awk -v a="$seconds" -v b="$best" 'BEGIN { exit !(a < b) }'; then best=$seconds; fi
done
echo "unit tests: $(tail -1 "$WORK/unit.log"), $best s (best of 3)"
