#!/usr/bin/env bash
# The long runs (docs/agents/testbed.md): one entry point for what is too
# slow for the gate.
#
#   tools/testbed/long.sh miri                       scripts/miri.sh (crates marked `miri`)
#   tools/testbed/long.sh fuzz [SECONDS [TARGET...]] every fuzz target, 600 s each by default
#   tools/testbed/long.sh proptest [CASES]           property tests, 1,000,000 cases by default
#   tools/testbed/long.sh sanitizers [asan|ubsan]    the C-binding crates under ASan and UBSan
#   tools/testbed/long.sh differential [ITEM...]     the full differential runs
#   tools/testbed/long.sh all                        each of these in turn, with their defaults
. "$(dirname "$0")/lib.sh"

what=${1:-}
[ $# -eq 0 ] || shift
case "$what" in
  fuzz) exec "$TB_DIR/fuzz.sh" "$@" ;;
  proptest) exec "$TB_DIR/proptest.sh" "$@" ;;
  sanitizers) exec "$TB_DIR/sanitizers.sh" "$@" ;;
  differential) exec "$TB_DIR/differential.sh" "$@" ;;
  miri)
    start=$(date +%s)
    scripts/miri.sh "$@" 2>&1 | tee "$TB_OUT/miri.log" && code=0 || code=${PIPESTATUS[0]}
    crates=$(awk '!/^[[:space:]]*#/ && $2 == "miri" {print $1}' unsafe-crates.txt | paste -sd' ' -)
    { [ "$code" -eq 0 ] || tb_failed "$TB_OUT/miri.log" | sed 's/^/miri /'
      [ "$code" -eq 0 ] || echo "miri: exit $code"; } \
      | tb_result "miri: crates ${crates:-none marked miri}; $(tb_counts "$TB_OUT/miri.log") (exit $code, $(tb_dur $(($(date +%s) - start))))"
    exit "$code" ;;
  all)
    rc=0; : > "$TB_OUT/fails.tmp"; : > "$TB_OUT/table.txt"
    for w in miri sanitizers proptest fuzz differential; do
      mkdir -p "$TB_OUT/$w"
      t0=$(date +%s)
      BK_OUT="$TB_OUT/$w" "$0" "$w" && c=0 || c=$?
      [ "$c" -eq 0 ] || rc=1
      cat "$TB_OUT/$w/failures.txt" >> "$TB_OUT/fails.tmp" 2>/dev/null || true
      printf '%-13s %-5s %9s  %s\n' "$w" "$([ "$c" -eq 0 ] && echo pass || echo FAIL)" \
        "$(tb_dur $(($(date +%s) - t0)))" "$(cat "$TB_OUT/$w/summary.txt" 2>/dev/null)" >> "$TB_OUT/table.txt"
    done
    cat "$TB_OUT/table.txt"
    tb_result "long all: $(awk '{print $1 " " $2}' "$TB_OUT/table.txt" | paste -sd, -)" < "$TB_OUT/fails.tmp"
    rm -f "$TB_OUT/fails.tmp"
    exit "$rc" ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
