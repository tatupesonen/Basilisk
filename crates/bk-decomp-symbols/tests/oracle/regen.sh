#!/bin/sh
# Regenerates the oracle tables of bk-decomp-symbols against a reference
# build (spec 6.2). Usage: regen.sh REF GHIDRA OUTDIR LIBTAG
#   REF     the reference directory (its src/cpp holds the built objects)
#   GHIDRA  the Ghidra source tree (for the data tests and SLEIGHHOME)
#   OUTDIR  where the tables go
#   LIBTAG  libcxx or libstdcxx (the C++ library of the reference build)
# Builds each generator twice into a temporary directory (never into REF or
# GHIDRA), runs each twice and fails if the two runs differ.
set -eu
REF=$1; GHIDRA=$2; OUT=$3; TAG=$4
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export LC_ALL=C
DT="$GHIDRA/Ghidra/Features/Decompiler/src/decompile/datatests"
mkdir -p "$OUT"
for g in scope context image; do
  sh "$HERE/build.sh" "$REF" "$HERE/$g.cc" "$TMP/$g"
done
run() {  # name args...
  n=$1; shift
  "$TMP/$n" "$@" > "$TMP/$n.1"
  "$TMP/$n" "$@" > "$TMP/$n.2"
  cmp "$TMP/$n.1" "$TMP/$n.2"
}
run scope "$REF" "$DT/elseif.xml" 1 2000
run context "$REF" "$DT/elseif.xml" 1 2000
# Data tests in byte order of their names, so every host lists them alike.
FILES=$(cd "$DT" && ls *.xml | sort)
set --
for f in $FILES; do set -- "$@" "$DT/$f"; done
run image "$REF" "$@"
for g in scope context image; do
  gzip -9n < "$TMP/$g.1" > "$OUT/$g.$TAG.txt.gz"
  echo "$g: $(wc -l < "$TMP/$g.1") rows, sha256 $(sha256sum "$TMP/$g.1" 2>/dev/null | cut -c1-16 || shasum -a 256 "$TMP/$g.1" | cut -c1-16)"
done
