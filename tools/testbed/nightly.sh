#!/usr/bin/env bash
# The nightly run (docs/agents/testbed.md), started by nightly-boot.sh from
# the checkout of master it prepared (the current directory).
#
# Every night: the gate (with the reference), the Windows tests under Wine
# and the decompiler oracle's captures (oracle.sh, about a minute). Then one
# slot of the long runs, in rotation by date:
#   0 fuzz (every target, 600 s each)   1 differential
#   2 proptest (1,000,000 cases)        3 sanitizers, miri, ubuntu, arm64
# within a core budget and a time bound, below normal priority. One report
# per night: ~/bk/reports/<date>.txt (logs and results in ~/bk/reports/<date>/).
#
# Environment (all optional): BK_NIGHTLY_CORES (12), BK_NIGHTLY_HOURS (6),
# BK_NIGHTLY_MIN_FREE_GB (60: refuse below), BK_NIGHTLY_ITEMS (replaces the
# list, e.g. "gate wine fuzz"), BK_NIGHTLY_FUZZ_SECONDS (600),
# BK_NIGHTLY_KEEP_DAYS (30).
. "$(dirname "$0")/lib.sh"
trap - TERM INT HUP

BK=$HOME/bk
R="$BK/reports"
cores=${BK_NIGHTLY_CORES:-12}
hours=${BK_NIGHTLY_HOURS:-6}
min_free=${BK_NIGHTLY_MIN_FREE_GB:-60}
keep=${BK_NIGHTLY_KEEP_DAYS:-30}
started=$(date +%s)
deadline=$((started + hours * 3600))
# One name per run, in an order that sorts chronologically: the date, and
# for a second run that day the date and time (2026-11-14T1458).
name=$(date +%F)
[ ! -e "$R/$name.txt" ] && [ ! -e "$R/$name" ] || name=$(date +%FT%H%M%S)
dir="$R/$name"; mkdir -p "$dir"
echo "$name (started $(date -Is))" > "$R/current"
free_gb() { df -Pk "$BK" | awk 'NR == 2 {print int($4 / 1048576)}'; }
gb_of() { du -s -BG "$1" 2>/dev/null | cut -f1 | tr -d G || echo 0; }
exec > >(tee "$dir/run.log") 2>&1
say "$(date -Is) nightly $name at $(git log -1 --format='%h %s')"

# ---------------------------------------------------------------- rotation
find "$R" -mindepth 1 -maxdepth 1 \( -name '20*' \) -mtime +"$keep" -exec rm -rf {} +
# Build output: rebuilt from scratch on Sundays, or when it grows past 80 GB.
if [ "$(date +%u)" = 7 ] || [ "$(gb_of target)" -gt 80 ]; then say "removing the build output ($(gb_of target) GB)"; rm -rf target; fi
# Fuzz corpora: dropped when they pass 4 GB together (they regrow from seeds).
if [ "$(gb_of "$TB_STATE/fuzz")" -gt 4 ]; then rm -rf "$TB_STATE/fuzz"; fi
docker image prune -af --filter label=bk-testbed=1 --filter until=336h >/dev/null 2>&1 || true
free_before=$(free_gb)
if [ "$free_before" -lt "$min_free" ]; then
  rm -rf target; free_before=$(free_gb)
fi

# ------------------------------------------------------------------- items
slots=("fuzz" "differential" "proptest" "sanitizers miri ubuntu arm64")
slot=$(( $(date +%s) / 86400 % ${#slots[@]} ))
items=${BK_NIGHTLY_ITEMS:-gate wine oracle ${slots[$slot]}}

export CARGO_BUILD_JOBS=$cores CARGO_TERM_COLOR=never TMPDIR="$BK/tmp/@nightly"
export BASILISK_GHIDRA_DIR="$HOME/basilisk-ref/ghidra" BASILISK_REFERENCE_DIR="$BK/reference"
mkdir -p "$TMPDIR"
: > "$dir/status.tsv"

run_item() {  # name bound command...
  local item=$1 bound=$2 t0 code left result summary; shift 2
  local out="$dir/$item.out"; mkdir -p "$out"
  left=$((deadline - $(date +%s)))
  if [ "$left" -lt 600 ]; then
    printf '%s\tSKIP\t0\tnot started: the night'"'"'s time bound was reached\n' "$item" >> "$dir/status.tsv"; return
  fi
  [ "$bound" -le "$left" ] || bound=$left
  say "$(date -Is) $item (bound $(tb_dur "$bound"))"
  t0=$(date +%s)
  BK_OUT=$out timeout -k 60 "$bound" nice -n 10 "$@" > "$dir/$item.log" 2>&1 && code=0 || code=$?
  [ "$item" != gate ] || gate_failures "$code" > "$out/failures.txt"
  case $code in 0) result=PASS ;; 124|137) result=TIMEOUT; echo "$item: timed out after $(tb_dur "$bound")" >> "$out/failures.txt" ;; *) result=FAIL ;; esac
  summary=$(head -n 1 "$out/summary.txt" 2>/dev/null || tail -n 1 "$dir/$item.log")
  [ ! -f "$out/failures.txt" ] || LC_ALL=C sort -u -o "$out/failures.txt" "$out/failures.txt"
  printf '%s\t%s\t%s\t%s\n' "$item" "$result" "$(($(date +%s) - t0))" "$summary" >> "$dir/status.tsv"
  say "$item: $result $summary"
}
gate_failures() {  # code: the gate has no result files of its own
  grep -E '^test .* FAILED$' "$dir/gate.log" | sed 's/^test /gate /; s/ \.\.\. FAILED$//' || true
  [ "$1" -eq 0 ] || grep -q '^tests: ' "$dir/gate.log" || echo "gate: a step before the tests failed (exit $1)"
}

if ! fetch=$(timeout 600 cargo fetch --locked 2>&1); then
  say "cargo fetch --locked failed:"; printf '%s\n' "$fetch" | tail -n 8
fi
if [ "$free_before" -lt "$min_free" ]; then
  printf 'all\tREFUSED\t0\tonly %s GB free (the guard is %s GB); nothing ran\n' "$free_before" "$min_free" >> "$dir/status.tsv"
else
  for item in $items; do
    case $item in
      gate) run_item gate 5400 scripts/gate.sh ;;
      wine) run_item wine 5400 "$TB_DIR/wine.sh" ;;
      oracle) run_item oracle 3600 "$TB_DIR/oracle.sh" ;;
      fuzz) run_item fuzz 10800 "$TB_DIR/fuzz.sh" "${BK_NIGHTLY_FUZZ_SECONDS:-600}" ;;
      differential) run_item differential 10800 "$TB_DIR/differential.sh" ;;
      proptest) run_item proptest 14400 "$TB_DIR/proptest.sh" ;;
      sanitizers) run_item sanitizers 3600 "$TB_DIR/sanitizers.sh" ;;
      miri) run_item miri 3600 "$TB_DIR/long.sh" miri ;;
      ubuntu) run_item ubuntu 5400 "$TB_DIR/ubuntu.sh" ;;
      arm64) run_item arm64 5400 "$TB_DIR/arm64.sh" ;;
      *) printf '%s\tSKIP\t0\tunknown item\n' "$item" >> "$dir/status.tsv" ;;
    esac
  done
fi

# ------------------------------------------------------------------ report
prev_with() {  # the latest earlier night in which ITEM ran: prints its directory
  local d
  for d in $(ls -d "$R"/20*/ 2>/dev/null | LC_ALL=C sort -r); do
    d=${d%/}
    [ "$d" != "$dir" ] && [ -f "$d/$1.out/failures.txt" ] && { echo "$d"; return; }
  done
  true
}
total=$(wc -l < "$dir/status.tsv"); passed=$(awk -F'\t' '$2 == "PASS"' "$dir/status.tsv" | wc -l)
overall=PASS; [ "$passed" -eq "$total" ] || overall=FAIL
{
  echo "Basilisk nightly $name, $(date -d "@$started" -Is) to $(date -Is) (host time)"
  echo "master: $(git log -1 --format='%h %s')"
  echo "overall: $overall ($passed of $total items passed; items: $items)"
  echo "budget: $cores cores, $hours h; disk free: $free_before GB before, $(free_gb) GB after; build output $(gb_of target) GB"
  echo
  awk -F'\t' '{printf "%-12s %-8s %9s  %s\n", $1, $2, sprintf("%dh%02dm%02ds", $3 / 3600, $3 % 3600 / 60, $3 % 60), $4}' "$dir/status.tsv"
  echo
  while IFS=$'\t' read -r item result _ _; do
    f="$dir/$item.out/failures.txt"; [ -f "$f" ] || continue
    p=$(prev_with "$item")
    if [ -n "$p" ]; then
      new=$(LC_ALL=C comm -13 "$p/$item.out/failures.txt" "$f"); fixed=$(LC_ALL=C comm -23 "$p/$item.out/failures.txt" "$f")
      since="since $(basename "$p")"
    else
      new=$(cat "$f"); fixed=; since="(no earlier night to compare with)"
    fi
    still=0; [ -z "$p" ] || still=$(LC_ALL=C comm -12 "$p/$item.out/failures.txt" "$f" | wc -l)
    [ -z "$new" ] || { echo "$item: new failures $since:"; printf '%s\n' "$new" | head -n 40 | sed 's/^/  /'; }
    [ -z "$fixed" ] || { echo "$item: fixed $since:"; printf '%s\n' "$fixed" | head -n 40 | sed 's/^/  /'; }
    [ "$still" -eq 0 ] || echo "$item: $still failures unchanged $since"
  done < "$dir/status.tsv"
  echo
  echo "logs and results: $dir/"
} > "$R/$name.txt"
rm -f "$R/current"
cat "$R/$name.txt"
[ "$overall" = PASS ]
