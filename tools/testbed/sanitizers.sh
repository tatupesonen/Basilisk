#!/usr/bin/env bash
# The C-binding crates' tests under AddressSanitizer and
# UndefinedBehaviorSanitizer, natively on the build host with Debian's clang
# and Rust nightly (docs/agents/testbed.md; method from fuzz/README.md and
# docs/agents/gnu-disasm.md).
#
#   tools/testbed/sanitizers.sh [asan|ubsan]...     (default both)
#
# asan:  C compiled by clang with -fsanitize=address, Rust with
#        -Zsanitizer=address; leak detection off (binutils keeps small
#        allocations for the life of the process by design).
# ubsan: C with -fsanitize=undefined; UB that means memory unsafety is
#        fatal, the rest is reported once per site. Every reported site is
#        listed in BK_OUT/<mode>-sites.txt and in failures.txt (so that a new
#        site shows up in the nightly comparison), but only failing tests
#        make the exit status non-zero.
. "$(dirname "$0")/lib.sh"

[ $# -gt 0 ] || set -- asan ubsan
crates=(-p bk-binutils-sys -p bk-gnu-disasm)
T=x86_64-unknown-linux-gnu
UB_FATAL="-fno-sanitize-recover=bounds,null,vla-bound,return,unreachable,builtin"
start=$(date +%s); rc=0; : > "$TB_OUT/fails.tmp"; parts=()
for mode in "$@"; do
  log="$TB_OUT/$mode.log"
  case $mode in
    asan)
      env CC=clang CFLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g" \
        RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS=detect_leaks=0 \
        timeout -k 30 3600 cargo +nightly test --target "$T" --target-dir target/testbed/asan "${crates[@]}" \
        > "$log" 2>&1 && code=0 || code=$? ;;
    ubsan)
      env CC=clang CFLAGS="-fsanitize=undefined $UB_FATAL -fno-omit-frame-pointer -O1 -g" \
        RUSTFLAGS="-C linker=clang -C link-arg=-fsanitize=undefined" \
        UBSAN_OPTIONS=print_stacktrace=1:report_error_type=1 \
        timeout -k 30 3600 cargo +nightly test --target "$T" --target-dir target/testbed/ubsan "${crates[@]}" \
        > "$log" 2>&1 && code=0 || code=$? ;;
    *) echo "usage: tools/testbed/sanitizers.sh [asan|ubsan]..." >&2; exit 2 ;;
  esac
  # A report's first line names the site: "file.c:170:13: runtime error: …"
  # (UBSan) or "ERROR: AddressSanitizer: …" with the frames below it.
  { grep -o '[^ ]*:[0-9]*:[0-9]*: runtime error: .*' "$log" | sed 's|^.*/vendor/|vendor/|' || true
    grep -o 'ERROR: AddressSanitizer: .*' "$log" || true; } | LC_ALL=C sort -u > "$TB_OUT/$mode-sites.txt"
  sed "s/^/$mode report: /" "$TB_OUT/$mode-sites.txt" >> "$TB_OUT/fails.tmp"
  tb_failed "$log" | sed "s/^/$mode /" >> "$TB_OUT/fails.tmp"
  [ "$code" -eq 0 ] || { rc=1; grep -q "^$mode -p" "$TB_OUT/fails.tmp" || echo "$mode: cargo test exit $code" >> "$TB_OUT/fails.tmp"; }
  parts+=("$mode $(tb_counts "$log"), $(wc -l < "$TB_OUT/$mode-sites.txt") report sites")
  say "$mode: exit $code, ${parts[-1]}"
done
tb_result "sanitizers: $(IFS=';'; echo "${parts[*]}") ($(tb_dur $(($(date +%s) - start))))" < "$TB_OUT/fails.tmp"
rm -f "$TB_OUT/fails.tmp"
exit "$rc"
