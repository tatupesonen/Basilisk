#!/usr/bin/env bash
# Per data test: sha256 of the dt_run.sh output with every line that carries
# a host pointer (#0x…/i0x… of 8+ hex digits) and every fspec varnode line
# (`= f…(free)`, ordered by pointer) removed. usage: dt_hash.sh OUTDIR
for f in "$1"/raw/*.norm; do
  h=$(grep -vE 'datatests/|(#|i)0x[0-9a-f]{8,}|^[a-z0-9_]+ = f[A-Za-z0-9_]+\(free\)' "$f" | (sha256sum 2>/dev/null || shasum -a 256) | cut -c1-16)
  echo "$h $(basename "$f" .norm)"
done
