# Track `decomp-cspec` (D03) — status

Spec: `docs/features/decomp-cspec.md`. Crate: `crates/bk-cspec`.
Worktree `/Users/tatu/slop/basilisk-wt/decomp-cspec`, branch `decomp-cspec`.

## State

In progress (kept current so the work can be continued from the files).

## Done

- Crate `bk-cspec`: reader (`spec/`), entries, lists (assignment, trial
  classification, queries, merged lists), model rules, models (decode,
  merged, scoring, shared actions), `FuncProto` with internal store, codec,
  queries; payload declarations (`inject`); `FunctionSummary`/`CallSite`
  (`summary`); `ParamTypes` trait (`types`).
- `tests/funcproto.rs`: `testfuncproto.cc`, 21 tests, self-contained, pass.
- Oracle: `tests/oracle/cspec_oracle.cc` + `regen.sh` + `signatures.txt`;
  table `tests/data/cspec_oracle.txt.gz` (152k records, 856 kB).
- `tests/oracle_replay.rs` (G): 294 pairs, 106 readable `.cspec` files
  (V850's fails in Ghidra itself), 127,088 rows compared, 0 unexplained
  differences (1 known: order of entry-less trials left to `std::sort`).

- `tests/paramstore.rs`: `testparamstore.cc`, 5 tests (G), pass.
- `tests/java_protomodel.rs`: the nine Java classes, 12 test functions
  (the inventory counts 12, the spec says 13), all pass, no exceptions.

## In progress (paused by the coordinator, 2026-11-14)

- `tests/derived.rs` is written but **not yet compiled or run**
  (committed as WIP): error-path table with Ghidra's messages, path in
  errors, defaults/aliases/`__thiscall`, merged model scoring, FuncProto
  XML round trip over the signatures, Ghidra-form check, provenance in
  basilisk mode, locked-prototype queries, payload declarations, summary
  serde. Next step: `cargo test -p bk-cspec --test derived`, fix what fails
  (expected messages may need adjusting where my reader's message differs;
  keep Ghidra's text in `src`).

## Next

1. Finish `tests/derived.rs` (above).
2. Corpus counts test (G): over the heavy pairs of the oracle table, models
   / pentries / rules decoded vs substring counts of `<prototype`,
   `<resolveprototype`, `<pentry`, `<rule` in the files (spec: 180, 6,
   1,558, 230 over 107 files; V850's file fails in Ghidra too).
3. Property tests, fuzz target `bk_cspec_decode`, benchmarks + PERF.md.
4. Docs: spec differences/status, test checklists, final report; gate x2;
   Windows clippy; dep-age check.

## Notes found while reading (for the final report)

- `ProtoModel(Architecture*)` calls `defaultLocalRange`/`defaultParamRange`
  in its constructor, dereferencing the stack space: a `<prototype>` before
  `<stackpointer>` crashes Ghidra (null pointer), it is not "decoded without
  a stack". basilisk decodes it with empty default ranges.
- `std::sort` of the effect list and of trials is not stable: equal keys
  keep a library-dependent order (seen once in the table: golang output
  trials without an entry).
- `MultiSlotAssign::checkFit` never advances its loop index; reproduced.
- `ProtoModelMerged::foldIn` copies the first model's output list as a
  `ParamListStandardOut` even when it is a `ParamListRegisterOut`.
- `ParamListMerged` leaves `numgroup`, `maxdelay`, `thisbeforeret` and
  `autoKilledByCall` uninitialised.
- Aliases: rules are cloned pointing into the parent's list; shared
  actions are cloned by constructor, so `<sharestack first= align=>` is
  lost on aliases (x86-64 golang `__thiscall`); reproduced.
- The default model when none is named is the first by *name* (std::map),
  not the first in the file.
- `PreferSplitManager::initialize` sorts prefer-split records.
- Ghidra's C parser makes pointers the size of the default data space, not
  the data organisation's pointer size.
