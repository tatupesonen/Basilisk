#!/usr/bin/env bash
# Enforces the file-size rule in docs/LOOP.md: no hand-written Rust source file
# over 1,000 lines. A file may opt out with a first-line comment
# `// bk:allow-long-file: <reason>` (generated tables, ported test vectors).
set -euo pipefail
cd "$(dirname "$0")/.."
limit=1000
bad=0
while IFS= read -r f; do
  lines=$(wc -l < "$f")
  if [ "$lines" -gt "$limit" ] && ! head -1 "$f" | grep -q 'bk:allow-long-file:'; then
    echo "too long ($lines > $limit lines): $f"
    bad=1
  fi
done < <(find crates -name '*.rs' -not -path '*/target/*')
exit "$bad"
