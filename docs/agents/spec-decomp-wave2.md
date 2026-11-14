# Track `spec-decomp-wave2` — status report

Specification track for D06 (`decomp-symbols`, new document) and the
revision of D05 (`decomp-ir`) of `docs/features/decomp-plan.md`. Writes no
shipping code.

## State

- [x] Rules, plan (with its amendments), ADRs, D00/D04 specs and the
      wave-1 report read; existing crates' APIs read.
- [x] D06 source reading: `database.*`, `rangemap.hh`, `partmap.hh`,
      `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*.*`,
      `globalcontext.*`, `override.*`, the `ghidra_*` host classes,
      the parts of `architecture.cc`, `sleigh_arch.cc`, `xml_arch.cc`
      that build and fill these.
- [ ] D06 oracle prototypes run (in progress).
- [ ] `docs/features/decomp-symbols.md`.
- [ ] D05 revision.
- [ ] Final report.

## Next

Write the oracle generator prototypes under
`docs/research/decomp-wave2/`, run them on both reference builds, then
write the D06 document.
