#!/bin/sh
# Rust lines per crate of this repository: src/ (product code, unit tests
# included), tests/ and benches/. Used for the Java-to-Rust ratio of
# roadmap-check.md. Usage: rust-sizes.sh > rust-sizes.tsv (from the repo root)
printf 'crate\tsrc_lines\ttests_lines\n'
for c in crates/*/; do
  n=$(basename "$c")
  s=$(find "$c/src" -name '*.rs' -print0 2>/dev/null | xargs -0 cat 2>/dev/null | wc -l | tr -d ' ')
  t=$(find "$c/tests" "$c/benches" -name '*.rs' -print0 2>/dev/null | xargs -0 cat 2>/dev/null | wc -l | tr -d ' ')
  printf '%s\t%s\t%s\n' "$n" "$s" "$t"
done
