# Track `decomp-out-spike` (D16a) — status

Question: ADR-025 item 3c — can `PrintC`'s output be reproduced token for
token from a tree that is built first and printed afterwards?

## Done

- Read the printer sources (`printlanguage.*`, `printc.*`, `printjava.*`,
  `prettyprint.*`, `comment.*`, the block dispatch in `block.hh`).

## In progress

- Hook patch for a copy of Ghidra's source (`tools/reference/patches-instr/`)
  and the build script for the instrumented console.

## Next

- Corpus runner, byte-identity proof, the prototype, the report
  (`docs/research/decomp-out-spike/report.md`).
