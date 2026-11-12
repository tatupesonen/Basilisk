#!/usr/bin/env bash
# Enforces ADR-020: `unsafe` appears only in crates listed in unsafe-crates.txt.
# The compiler already forbids it (workspace lint `unsafe_code = "forbid"`); this
# catches a crate that quietly overrides the lint.
set -euo pipefail
cd "$(dirname "$0")/.."
allowed=$(awk '!/^[[:space:]]*#/ && NF {print $1}' unsafe-crates.txt)
bad=0
for dir in crates/*/; do
  name=$(basename "$dir")
  if printf '%s\n' "$allowed" | grep -qx "$name"; then
    continue
  fi
  hits=$(grep -rnE '(^|[^a-zA-Z0-9_"])unsafe[[:space:]]+(\{|fn|impl|trait|extern)|allow\(unsafe_code\)|unsafe_code[[:space:]]*=' \
    "$dir" --include='*.rs' --include='Cargo.toml' 2>/dev/null | grep -v '/target/' || true)
  if [ -n "$hits" ]; then
    echo "unsafe outside unsafe-crates.txt (ADR-020) in $name:"
    echo "$hits"
    bad=1
  fi
done
exit "$bad"
