#!/usr/bin/env bash
# Produces vendor/binutils-2.41/, the subset of binutils 2.41 that
# crates/bk-binutils-sys compiles (docs/features/gnu-disasm.md, ADR-019).
#
#   scripts/vendor-binutils.sh <binutils checkout>          rewrite the directory
#   scripts/vendor-binutils.sh --check <binutils checkout>  compare only; exit 1 on any difference
#
# The checkout must contain the commit of tag binutils-2_41. Files are read
# from that commit, never from the working tree, so the result does not
# depend on the state of the checkout and is the same byte for byte every
# time. Nothing is written into the checkout.
#
# What is vendored:
#   * the compilation units named in crates/bk-binutils-sys/sources.list;
#   * every file those include, found by following #include lines through
#     the directories the build searches (whatever the preprocessor
#     conditions around them, so the set does not depend on the host);
#   * bfd/bfd-in2.h, from which the build generates bfd.h;
#   * opcodes/s390-opc.tab, which binutils generates at build time with a
#     small host program: it is generated here instead, and the generator
#     (opcodes/s390-mkopc.c) and its input (opcodes/s390-opc.txt) are kept;
#   * binutils' licence files.
# Patches in crates/bk-binutils-sys/patches/*.patch, if any, are applied in
# name order. A MANIFEST records the source commit and a SHA-256 per file.
#
# Needs: bash, git, tar, a C compiler (CC, default cc), shasum or sha256sum.
set -euo pipefail
export LC_ALL=C

COMMIT=2c73aeb8d2e02de7b69cbcb13361cfbca9d76a4e   # tag binutils-2_41, "The 2.41 release!"
TAG=binutils-2_41
SEARCH_DIRS="opcodes bfd include libiberty"       # the build's include directories
LICENCES="COPYING COPYING3 COPYING.LIB COPYING3.LIB"
EXTRA="bfd/bfd-in2.h opcodes/s390-mkopc.c opcodes/s390-opc.txt opcodes/s390-opc.tab"

check=0
if [ "${1:-}" = "--check" ]; then
  check=1
  shift
fi
if [ $# -ne 1 ]; then
  echo "usage: $0 [--check] <binutils checkout>" >&2
  exit 2
fi
checkout=$1
root=$(cd "$(dirname "$0")/.." && pwd)
list="$root/crates/bk-binutils-sys/sources.list"
patches="$root/crates/bk-binutils-sys/patches"
dest="$root/vendor/binutils-2.41"

if ! git -C "$checkout" cat-file -e "$COMMIT^{commit}" 2>/dev/null; then
  echo "$checkout does not contain commit $COMMIT (tag $TAG)" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/bk-vendor-binutils.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
src="$tmp/src"
out="$tmp/out"
mkdir -p "$src" "$out"

# 1. The four source directories and the licences, as of the tagged commit.
# shellcheck disable=SC2086
git -C "$checkout" archive "$COMMIT" $SEARCH_DIRS $LICENCES | tar -x -C "$src"

# 2. The table binutils generates at build time.
"${CC:-cc}" -O1 -w -I"$src/include" -o "$tmp/s390-mkopc" "$src/opcodes/s390-mkopc.c"
"$tmp/s390-mkopc" < "$src/opcodes/s390-opc.txt" > "$src/opcodes/s390-opc.tab"

# 3. The compilation units and everything they include.
grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$list" | sort -u > "$tmp/units"
while IFS= read -r f; do
  if [ ! -f "$src/$f" ]; then
    echo "sources.list names $f, which is not in binutils at $TAG" >&2
    exit 1
  fi
done < "$tmp/units"

# Prints the files (relative to $src) that the file $1 includes.
includes_of() {
  local f=$1 dir name d cand
  dir=$(dirname "$f")
  sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*["<]\([^">]*\)[">].*/\1/p' "$src/$f" |
    while IFS= read -r name; do
      for d in "$dir" $SEARCH_DIRS; do
        cand="$d/$name"
        # Collapse "x/../" so that bfd/../opcodes/a.h and opcodes/a.h are one file.
        while [ "$cand" != "${cand/\/..\//}" ]; do
          cand=$(printf '%s\n' "$cand" | sed 's#[^/][^/]*/\.\./##')
        done
        if [ -f "$src/$cand" ]; then
          printf '%s\n' "$cand"
        fi
      done
    done
}

# shellcheck disable=SC2086
{ cat "$tmp/units"; printf '%s\n' $EXTRA; } | sort -u > "$tmp/all"
cp "$tmp/all" "$tmp/frontier"
while [ -s "$tmp/frontier" ]; do
  while IFS= read -r f; do
    includes_of "$f"
  done < "$tmp/frontier" | sort -u > "$tmp/found"
  comm -13 "$tmp/all" "$tmp/found" > "$tmp/frontier"
  sort -u "$tmp/all" "$tmp/frontier" > "$tmp/all.next"
  mv "$tmp/all.next" "$tmp/all"
done

# 4. Copy, patch, and describe.
# shellcheck disable=SC2086
for f in $(cat "$tmp/all") $LICENCES; do
  mkdir -p "$out/$(dirname "$f")"
  cp "$src/$f" "$out/$f"
  chmod 644 "$out/$f"
done

patch_names=""
if [ -d "$patches" ]; then
  for p in "$patches"/*.patch; do
    [ -f "$p" ] || continue
    patch -s -p1 -d "$out" < "$p"
    patch_names="$patch_names $(basename "$p")"
  done
fi

{
  echo "# binutils subset vendored for crates/bk-binutils-sys."
  echo "# Produced by scripts/vendor-binutils.sh; do not edit this directory by hand."
  echo "source: git://sourceware.org/git/binutils-gdb.git"
  echo "tag: $TAG"
  echo "commit: $COMMIT"
  echo "generated: opcodes/s390-opc.tab (opcodes/s390-mkopc.c < opcodes/s390-opc.txt)"
  echo "patches:${patch_names:- none}"
  echo "files (sha256, path):"
  (cd "$out" && find . -type f | sed 's#^\./##' | sort) | while IFS= read -r f; do
    printf '%s  %s\n' "$(sha256 "$out/$f")" "$f"
  done
} > "$tmp/MANIFEST"
mv "$tmp/MANIFEST" "$out/MANIFEST"

if [ "$check" -eq 1 ]; then
  if diff -r "$out" "$dest" > "$tmp/diff" 2>&1; then
    echo "vendor/binutils-2.41 matches $TAG ($(($(wc -l < "$out/MANIFEST") - 8)) files)"
    exit 0
  fi
  echo "vendor/binutils-2.41 differs from what this script produces:" >&2
  head -40 "$tmp/diff" >&2
  exit 1
fi

rm -rf "$dest"
mkdir -p "$(dirname "$dest")"
mv "$out" "$dest"
echo "wrote $dest: $(find "$dest" -type f | wc -l | tr -d ' ') files, $(du -sk "$dest" | cut -f1) kB"
