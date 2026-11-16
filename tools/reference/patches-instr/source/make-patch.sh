#!/usr/bin/env bash
# Regenerates ../0001-printer-hooks.patch from Ghidra's sources:
#   tools/reference/patches-instr/source/make-patch.sh
# Copies the six files the patch touches from the Ghidra tree
# (BASILISK_GHIDRA_DIR, default ../ghidra) into a scratch directory under
# target/, applies edit_emit.py and edit_print.py (each edit asserts that its
# anchor occurs exactly once, so a changed Ghidra source fails loudly), adds
# bkinstr.hh, and writes the unified diff. Run it after a Ghidra update and
# review the diff.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
ghidra=${BASILISK_GHIDRA_DIR:-$root/../ghidra}
cpp=$ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
w=$root/target/patches-instr-work
rm -rf "$w"; mkdir -p "$w/a/cpp" "$w/b/cpp"
files="prettyprint.hh prettyprint.cc printlanguage.hh printlanguage.cc printc.cc"
for f in $files; do cp "$cpp/$f" "$w/a/cpp/"; cp "$cpp/$f" "$w/b/cpp/"; done
chmod -R u+w "$w"
cp "$here/bkinstr.hh" "$w/b/cpp/bkinstr.hh"
python3 "$here/edit_emit.py" "$w/b"
python3 "$here/edit_print.py" "$w/b"
out=$here/../0001-printer-hooks.patch
: > "$out"
(cd "$w" && diff -u --label /dev/null --label b/cpp/bkinstr.hh /dev/null b/cpp/bkinstr.hh) >> "$out" || true
for f in $files; do
  (cd "$w" && diff -u --label "a/cpp/$f" --label "b/cpp/$f" "a/cpp/$f" "b/cpp/$f") >> "$out" || true
done
echo "wrote $out"
