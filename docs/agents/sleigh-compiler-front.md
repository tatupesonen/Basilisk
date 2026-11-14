# Track `sleigh-compiler-front` — status

Spec: `docs/features/sleigh-compiler-front.md`. Crate `crates/bk-sleigh-compiler`.
Worktree `/Users/tatu/slop/basilisk-wt/sleigh-compiler-front`, branch
`sleigh-compiler-front`.

## Done

- Elaborator (symbols, definitions, context layout, attach, constructors,
  display, pattern atoms, context blocks, `with`, sections, macros,
  finalize), public p-code builder (`pcode::Builder` over
  `pcode::SymbolResolver`), consistency checker (sizes, truncations,
  optimisation, temporaries), collisions, NOPs, case check, xrefs, crossbuild
  shift, purge, canonical form (`canon`).
- `tests/reference_sla.rs`: **150 of 150** shipped specifications equal the
  reference `.sla` in every compared category. Mutation check: swapping
  operand evaluation order, allocating the export temporary early, and
  skipping the context-layout sort each make many specifications fail.

## In progress / next

1. Diagnostics tests (`tests/diagnostics/`), one case per message, checked
   in expectations, compared with `REF/bin/sleigh` when present.
2. Self-contained fixtures and `insta` snapshots (CI).
3. Property tests, fuzz target `bk_sleigh_compiler_elaborate`.
4. Benchmarks, PERF.md, Windows clippy, gate, final report.
