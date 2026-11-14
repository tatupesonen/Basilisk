# Track `decomp-cspec` (D03) — status

Spec: `docs/features/decomp-cspec.md`. Crate: `crates/bk-cspec`.
Worktree `/Users/tatu/slop/basilisk-wt/decomp-cspec`, branch `decomp-cspec`.

## State

In progress. This file is kept current (done / in progress / next) so the
work can be continued from the files alone.

## Done

- Read the rules, spec, ADRs, D02's hooks, and the Ghidra sources
  (`fspec.*`, `modelrules.*`, `architecture.cc` decoding, `pcodeinject`,
  `inject_sleigh.cc`, `userop.cc` declarations, the two unit tests and the
  nine Java tests).
- Crate skeleton.

## In progress

- Core types and decoding.

## Next

- Assignment, trials, FuncProto, oracle generator, tests, benchmarks, docs.

## Notes found while reading (for the final report)

- `ProtoModel(Architecture*)` calls `defaultLocalRange`/`defaultParamRange`
  in its constructor, dereferencing the stack space: a `<prototype>` before
  `<stackpointer>` crashes Ghidra (null pointer), it is not "decoded without
  a stack". basilisk decodes it with empty default ranges.
- `std::sort` of the effect list (`EffectRecord::compareByAddress`) is not
  stable: equal addresses keep a library-dependent order.
- `MultiSlotAssign::checkFit` never advances its loop index (only the entry
  at `iter` is tested); reproduced.
- `ProtoModelMerged::foldIn` copies the first model's output list as a
  `ParamListStandardOut` even when it is a `ParamListRegisterOut` (slicing).
- `ParamListMerged` leaves `numgroup`, `maxdelay`, `thisbeforeret` and
  `autoKilledByCall` uninitialised.
