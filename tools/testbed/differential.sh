#!/usr/bin/env bash
# The full differential runs that are too heavy for the gate, at full size,
# in one place (docs/agents/testbed.md). Needs BASILISK_GHIDRA_DIR and
# BASILISK_REFERENCE_DIR (remote.sh sets both unless --no-ref).
#
#   tools/testbed/differential.sh [ITEM...]     (default: all, in this order)
#
# sleigh-every-language  bk-sleigh `every_language` (#[ignore]d): every
#                        (.sla, .pspec) pair against pcodedump, decode and
#                        p-code, with the coverage thresholds; BK_THREADS =
#                        the core budget (docs/agents/sleigh-decode.md,
#                        sleigh-pcode.md).
# require-reference      the whole test suite in release with
#                        BASILISK_REQUIRE_REFERENCE=1: every differential test
#                        of the gate (all 150 .sla byte for byte, sleigh -y
#                        text, decompiler data tests, …) must run; a missing
#                        oracle fails instead of skipping.
# gnu-objdump            bk-gnu-disasm's goldens also compared with GNU objdump
#                        built from binutils 2.41 (BK_GNU_OBJDUMP; built once
#                        into the testbed cache, docs/agents/gnu-disasm.md).
# cspec-oracle           bk-cspec's oracle table regenerated on this host
#                        (regen.sh, three runs that must agree) and compared
#                        byte for byte with the checked-in table of this
#                        host's C++ library (libstdc++ here; ADR-040).
. "$(dirname "$0")/lib.sh"

all=(sleigh-every-language require-reference gnu-objdump cspec-oracle)
[ $# -gt 0 ] || set -- "${all[@]}"
if [ -z "${BASILISK_REFERENCE_DIR:-}" ] || [ -z "${BASILISK_GHIDRA_DIR:-}" ]; then
  echo "differential: needs BASILISK_GHIDRA_DIR and BASILISK_REFERENCE_DIR (run without --no-ref)" \
    | tb_result "differential: not run (no reference)"
  exit 1
fi
export BASILISK_REQUIRE_REFERENCE=1 RUST_TEST_THREADS="$TB_CORES"
: > "$TB_OUT/fails.tmp"; : > "$TB_OUT/table.txt"; rc=0

# binutils 2.41's objdump, built once (cached by version).
BINUTILS_SHA256=ae9a5789e23459e59606e6714723f2d3ffc31c03174191ef0d015bdf06007450
objdump_241() {
  local dir="$TB_STATE/binutils-2.41" tmp
  [ -x "$dir/bin/objdump" ] && { echo "$dir/bin/objdump"; return; }
  tmp=$(mktemp -d "$TB_STATE/binutils-build.XXXXXX")
  # (Each step chained: errexit does not apply inside `$(…) ||`.)
  ( cd "$tmp" \
    && curl -sSfL --retry 3 -o b.tar.xz https://ftp.gnu.org/gnu/binutils/binutils-2.41.tar.xz \
    && echo "$BINUTILS_SHA256  b.tar.xz" | sha256sum -c --quiet \
    && tar -xJf b.tar.xz && mkdir build && cd build \
    && ../binutils-2.41/configure --prefix="$dir" --enable-targets=all --disable-nls --disable-werror \
      --disable-gdb --disable-gdbserver --disable-sim --disable-gprof --disable-gprofng --disable-ld \
      --disable-gold --disable-libctf --without-zstd --disable-readline MAKEINFO=true > ../configure.log 2>&1 \
    && make -j "$TB_CORES" MAKEINFO=true all-binutils > ../make.log 2>&1 \
    && mkdir -p "$dir/bin" && cp binutils/objdump "$dir/bin/objdump" ) >&2 \
    || { tail -n 20 "$tmp"/*.log >&2 2>/dev/null; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  echo "$dir/bin/objdump"
}

item() {  # name: runs one item, appends to table and fails
  local name=$1 log="$TB_OUT/$1.log" t0 code note
  t0=$(date +%s)
  say "$(now) $name"
  "run_${name//-/_}" > "$log" 2>&1 && code=0 || code=$?
  note=$(tail -n 1 "$TB_OUT/$name.note" 2>/dev/null || echo "")
  # Snapshots a failing test wrote come back with the results.
  find crates -name '*.snap.new' -newer "$TB_OUT/table.txt" 2>/dev/null | while IFS= read -r f; do
    mkdir -p "$TB_OUT/snapshots"; mv "$f" "$TB_OUT/snapshots/"; done
  if [ "$code" -ne 0 ]; then
    rc=1
    tb_failed "$log" | sed "s/^/$name /" > "$TB_OUT/one.tmp"
    [ -s "$TB_OUT/one.tmp" ] || echo "$name: exit $code${note:+ ($note)}" > "$TB_OUT/one.tmp"
    cat "$TB_OUT/one.tmp" >> "$TB_OUT/fails.tmp"
  fi
  printf '%-24s %-5s %9s  %s\n' "$name" "$([ "$code" -eq 0 ] && echo pass || echo FAIL)" \
    "$(tb_dur $(($(date +%s) - t0)))" "$note" | tee -a "$TB_OUT/table.txt"
}

run_sleigh_every_language() {
  BK_THREADS=$TB_CORES timeout -k 30 7200 cargo test --release --locked -p bk-sleigh --test differential \
    -- --ignored --exact every_language --nocapture
  local c=$? log="$TB_OUT/sleigh-every-language.log" snap
  # The test prints "<language>: <record difference>" for each difference
  # and "<language>: oracle crashed on …" for each pcodedump crash; the
  # coverage table is an insta snapshot (checked first).
  snap=ok; grep -q 'snapshot assertion for .coverage_table. failed' "$log" && snap=DIFFERS
  grep '│[-+]' "$log" > "$TB_OUT/coverage-table.diff" || true
  echo "$(grep -E '^[^ ]+:[A-Z]+:[0-9]+:[^ ]+: ' "$log" | grep -vc ': oracle crashed on ') record differences, $(grep -c ': oracle crashed on ' "$log") oracle crashes, coverage snapshot $snap" \
    > "$TB_OUT/sleigh-every-language.note"
  return $c
}
run_require_reference() {
  timeout -k 30 7200 cargo test --release --locked --workspace --all-features --no-fail-fast
  local c=$?
  echo "$(tb_counts "$TB_OUT/require-reference.log"), $(grep -c 'SKIPPED' "$TB_OUT/require-reference.log") SKIPPED" \
    > "$TB_OUT/require-reference.note"
  return $c
}
run_gnu_objdump() {
  local od
  od=$(objdump_241) || { echo "could not build binutils 2.41" > "$TB_OUT/gnu-objdump.note"; return 1; }
  "$od" --version | head -1
  BK_GNU_OBJDUMP=$od timeout -k 30 3600 cargo test --release --locked -p bk-gnu-disasm --test golden -- --nocapture
  local c=$?
  echo "$(tb_counts "$TB_OUT/gnu-objdump.log") against $("$od" --version | head -1)" > "$TB_OUT/gnu-objdump.note"
  return $c
}
run_cspec_oracle() {
  # regen.sh (two-table layout, ADR-040) writes cspec_oracle.<lib>.txt.gz for
  # this host's C++ library into the directory given; REGEN_RUNS=3 also
  # requires three byte-identical runs. The result must equal the
  # checked-in table of the same library byte for byte.
  local w new old lib lines
  w=$(mktemp -d "$TB_OUT/cspec.XXXXXX")
  REGEN_RUNS=3 timeout 1800 crates/bk-cspec/tests/oracle/regen.sh "$BASILISK_REFERENCE_DIR" "$w" \
    || { echo "regen.sh failed (3 runs required)" > "$TB_OUT/cspec-oracle.note"; rm -rf "$w"; return 1; }
  new=$(ls "$w"/cspec_oracle.*.txt.gz); lib=${new##*/cspec_oracle.}; lib=${lib%.txt.gz}
  old="crates/bk-cspec/tests/data/cspec_oracle.$lib.txt.gz"
  lines=$(gzip -dc "$new" | wc -l)
  if [ -f "$old" ] && cmp -s <(gzip -dc "$old") <(gzip -dc "$new"); then
    echo "$lib: $lines records, 3 runs byte-identical, identical to the checked-in table" > "$TB_OUT/cspec-oracle.note"
    rm -rf "$w"; return 0
  fi
  cp "$new" "$TB_OUT/"
  [ -f "$old" ] && LC_ALL=C comm -3 <(gzip -dc "$old" | LC_ALL=C sort) <(gzip -dc "$new" | LC_ALL=C sort) > "$TB_OUT/cspec-oracle.diff"
  echo "$lib: $lines records; differs from the checked-in $old ($(wc -l < "$TB_OUT/cspec-oracle.diff" 2>/dev/null || echo all) records, cspec-oracle.diff)" \
    > "$TB_OUT/cspec-oracle.note"
  rm -rf "$w"; return 1
}

start=$(date +%s)
for i in "$@"; do
  case " ${all[*]} " in *" $i "*) item "$i" ;; *) echo "differential: unknown item $i (${all[*]})" >&2; exit 2 ;; esac
done
tb_result "differential: $(awk '{print $1 " " $2}' "$TB_OUT/table.txt" | paste -sd, -) ($(tb_dur $(($(date +%s) - start))))" < "$TB_OUT/fails.tmp"
rm -f "$TB_OUT/fails.tmp" "$TB_OUT/one.tmp"
exit "$rc"
