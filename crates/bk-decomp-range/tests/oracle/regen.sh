#!/usr/bin/env bash
# Regenerates tests/data/circlerange_oracle.<lib>.txt.gz from Ghidra's compiled
# CircleRange (rangeutil.cc), using the reference build's objects
# (scripts/build-reference.sh: its source copy and src/cpp/com_opt).
#
# Usage: crates/bk-decomp-range/tests/oracle/regen.sh [--marks] [--extended] [reference-dir [output-dir]]
#
# Without --marks the table is written bare, as the C++ library of the host
# compiler (libcxx or libstdcxx) produced it, to
# <output-dir>/circlerange_oracle.<lib>.txt.gz; the checked-in table is
# compared against that (tests/oracle_regen.rs ignores marks).
# With --marks (needs clang with UndefinedBehaviorSanitizer's minimal
# runtime, valgrind with its headers, and addr2line: the build host has
# them) every row is also run
#   - against rangeutil.cc and address.cc rebuilt with
#     -fsanitize=undefined -fsanitize-minimal-runtime -fsanitize-recover=all
#     (into a temporary directory, never the reference): each UB event of a
#     row is appended as ` #ub=<kind>@<file>:<line>`;
#   - under valgrind with the fields of every empty range left
#     uninitialised: a row whose result depends on them gets ` #uninit`;
# and the marked table is written to <output-dir>/circlerange_oracle.<lib>.txt.gz.
#
# With --extended the full case set of the spec (section 6.2: a 300-range
# sample squared, 200,000 random pairs, ...) is also written, bare, to
# <output-dir>/circlerange_oracle_extended.<lib>.txt.gz; it is not checked
# in (about 30 MB) but replayed live by tests/oracle_regen.rs.
#
# REGEN_RUNS=N runs the generator N times and requires byte-identical output
# (both case sets).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
marks=0
extended=0
while [ $# -gt 0 ]; do
  case "$1" in
    --marks) marks=1; shift ;;
    --extended) extended=1; shift ;;
    *) break ;;
  esac
done
ref="${1:-$here/../../../../../reference}"
data="${2:-$here/../data}"
src="$ref/src/cpp"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '#include <cstddef>\n#if defined(_LIBCPP_VERSION)\nlibcxx\n#elif defined(__GLIBCXX__)\nlibstdcxx\n#else\nunknown\n#endif\n' \
  > "$work/lib.cc"
lib=$(c++ -E -P -x c++ "$work/lib.cc" | grep -v '^\s*$' | tail -1)
[ "$lib" != unknown ] || { echo "regen: unknown C++ standard library" >&2; exit 1; }
objs=$(ls "$src"/com_opt/*.o | grep -v '/consolemain\.o$')
# Flags follow the reference build (-std=c++11, -fsigned-char,
# -ffp-contract=off, LOCAL_ZLIB); -fno-access-control reaches the fields.
flags=(-std=c++11 -w -fno-access-control -fsigned-char -ffp-contract=off -DLOCAL_ZLIB -I"$src")
c++ "${flags[@]}" -O1 "$here/circlerange_oracle.cc" $objs "$ref/src/zlib/libz.a" -o "$work/oracle"
"$work/oracle" > "$work/table.txt"
runs="${REGEN_RUNS:-1}"
for ((i = 2; i <= runs; i++)); do
  "$work/oracle" > "$work/again.txt" || { echo "regen: run $i of $runs failed (exit $?)" >&2; exit 1; }
  cmp -s "$work/table.txt" "$work/again.txt" || { echo "regen: run $i of $runs differs from run 1" >&2; exit 1; }
done
if [ "$extended" = 1 ]; then
  "$work/oracle" --extended > "$work/extended.txt"
  for ((i = 2; i <= runs; i++)); do
    "$work/oracle" --extended > "$work/again.txt" || { echo "regen: extended run $i of $runs failed" >&2; exit 1; }
    cmp -s "$work/extended.txt" "$work/again.txt" || { echo "regen: extended run $i of $runs differs from run 1" >&2; exit 1; }
  done
fi
[ "$runs" -le 1 ] || echo "regen: $runs runs, all complete and byte-identical"
mkdir -p "$data"
sum() { shasum -a 256 "$1" 2>/dev/null | cut -c1-16 || sha256sum "$1" | cut -c1-16; }
if [ "$extended" = 1 ]; then
  gzip -1n < "$work/extended.txt" > "$data/circlerange_oracle_extended.$lib.txt.gz"
  echo "wrote $data/circlerange_oracle_extended.$lib.txt.gz ($(wc -l < "$work/extended.txt" | tr -d ' ') lines, sha256 $(sum "$work/extended.txt"))"
fi
if [ "$marks" = 0 ]; then
  out="$data/circlerange_oracle.$lib.txt.gz"
  gzip -9n < "$work/table.txt" > "$out"
  echo "wrote $out ($(wc -l < "$work/table.txt" | tr -d ' ') lines, sha256 $(sum "$work/table.txt"))"
  echo "host $(uname -sm), $(c++ --version | head -1), $lib"
  exit 0
fi

# --- UndefinedBehaviorSanitizer: rangeutil.cc and address.cc instrumented.
# They are linked first, so their copies of inline functions are the ones used.
san=(-fsanitize=undefined -fno-sanitize=vptr,function -fsanitize-minimal-runtime -fsanitize-recover=all)
clang++ "${flags[@]}" -O1 -g "${san[@]}" -c "$src/rangeutil.cc" -o "$work/rangeutil.o"
clang++ "${flags[@]}" -O1 -g "${san[@]}" -c "$src/address.cc" -o "$work/address.o"
clang++ "${flags[@]}" -O1 -g -c "$here/circlerange_oracle.cc" -o "$work/oracle_ub_main.o"
clang++ "${flags[@]}" -O1 -g -c "$here/ubsan_hooks.cc" -o "$work/ubsan_hooks.o"
rest=$(echo "$objs" | grep -v -e '/rangeutil\.o$' -e '/address\.o$')
clang++ -no-pie "$work/rangeutil.o" "$work/address.o" "$work/oracle_ub_main.o" "$work/ubsan_hooks.o" \
  $rest "$ref/src/zlib/libz.a" -o "$work/oracle_ub"
"$work/oracle_ub" --marks=ub > "$work/ub_raw.txt"
# Resolve each pc (a return address: look one byte back) to file:line.
grep -o '@[0-9a-f]*' "$work/ub_raw.txt" | sort -u | tr -d @ > "$work/pcs.txt" || true
: > "$work/pcmap.txt"
while read -r pc; do
  loc=$(addr2line -e "$work/oracle_ub" "$(printf '0x%x' $((0x$pc - 1)))" | sed 's|.*/||; s| (discriminator.*||')
  echo "$pc $loc" >> "$work/pcmap.txt"
done < "$work/pcs.txt"
awk 'NR == FNR { m[$1] = $2; next }
     { s = ""; n = split($0, a, " ub=");
       for (i = 2; i <= n; i++) { split(a[i], kp, "@"); s = s " #ub=" kp[1] "@" m[kp[2]] }
       print s }' "$work/pcmap.txt" "$work/ub_raw.txt" > "$work/ub.txt"

# --- valgrind: the fields of empty ranges left undefined.
c++ "${flags[@]}" -O1 -DBK_VALGRIND "$here/circlerange_oracle.cc" $objs "$ref/src/zlib/libz.a" -o "$work/oracle_vg"
valgrind -q --error-limit=no --track-origins=yes --log-file="$work/valgrind.log" \
  "$work/oracle_vg" --marks=uninit > "$work/uninit_raw.txt"
sed 's/ uninit/ #uninit/' "$work/uninit_raw.txt" > "$work/uninit.txt"

n=$(wc -l < "$work/table.txt")
for f in ub uninit; do
  [ "$(wc -l < "$work/$f.txt")" = "$n" ] || { echo "regen: $f marks have the wrong number of rows" >&2; exit 1; }
done
paste -d '' "$work/table.txt" "$work/ub.txt" "$work/uninit.txt" > "$work/marked.txt"
out="$data/circlerange_oracle.$lib.txt.gz"
gzip -9n < "$work/marked.txt" > "$out"
echo "wrote $out ($n lines, bare sha256 $(sum "$work/table.txt"))"
echo "ub rows: $(grep -c '#ub=' "$work/marked.txt" || true), uninit rows: $(grep -c '#uninit' "$work/marked.txt" || true)"
echo "valgrind: $(grep -c "^==" "$work/valgrind.log" || true) log lines (-q: errors only)"
echo "ub kinds:"; grep -o '#ub=[^ ]*' "$work/marked.txt" | sort | uniq -c | sort -rn || true
echo "host $(uname -sm), $(c++ --version | head -1), $lib; sanitizer $(clang++ --version | head -1); $(valgrind --version)"
