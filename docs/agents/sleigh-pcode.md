# Track `sleigh-pcode` — status (in progress, paused)

Branch `sleigh-pcode`, worktree `/Users/tatu/slop/basilisk-wt/sleigh-pcode`.
Spec: `docs/features/sleigh-pcode.md`. Resumed 2026-11-14 after a pause.

## Done (code)

* `bk-sleigh`: `emit` (`PcodeEmit`, `PcodeCollector`, `PcodeCounter`,
  `PcodeRecords`, `write_record`), `pcode/{mod,buffer,location,build,nested,
  error}` (`Decoder::lift`, `lift_observed`, `build_template`,
  `BuildObserver`, `BuildFeature`, `InjectContext`, `LiftError`), `dump`
  (pcodedump sweep and record writer). `inst_next2` decode errors are kept
  (`Parse::next2_error`) and raised when a template needs `inst_next2`.
* `basilisk disasm` (`crates/basilisk/src/cmd/disasm.rs`): `cmp`-equal to
  `pcodedump` on 256 kB of arm64 code read as AARCH64, x86-64, MIPS BE,
  Hexagon (SPARC: `pcodedump` segfaults, basilisk does not).
* Harness compares `P`/`U` and full `T`; template coverage and feature
  columns (`tests/common/templates.rs`); model of Ghidra's parse cache
  (`tests/common/cache.rs`) for tolerated cache-history cases.
* Full run (every language): no difference left except tolerated ones:
  unset handles of subtables exporting nothing (Ghidra reads stale memory),
  one Toy harvard_rev record where Ghidra's 2-entry cache hands the builder
  a clobbered parse (delay slot `skvs` uses `inst_next2`).

## Done since (all committed)

* `bkpc` p-code fixture (`tests/fixture/pcode.rs`) with recorded pcodedump
  output (`tests/data/pcode-fixture-oracle.txt`), replayed in CI
  (`tests/pcode_fixture.rs`): every op template built, every feature column.
* Unit tests `tests/pcode_units.rs` (28), properties `tests/pcode_properties.rs`
  (PROPTEST_CASES honoured; run at 20,000), fuzz `bk_sleigh_lift` (60 s,
  1.94 M runs, clean), dhat: 0 allocations lifting 100,000 instructions.
* Full run every language passes (153 s): no unexplained difference;
  tolerated: unset handles (Ghidra reads uninitialised `FixedHandle`; null
  space → the ARM v8-m SIGSEGVs, confirmed by
  `arm_v8m_oracle_crashes_read_unset_handles`), one cache-clobber record.
* Benchmarks `tests/bench_pcode.rs`; `lift_decoded` (reuse last decode).
  Last numbers (load ~12): decode+lift 1.48 M/s vs ref 1.54; text+lift 1.28
  vs 0.99; disasm --quiet 0.190 s vs 0.201 s; full listing 0.396 vs 0.714.
  Working on closing the decode+lift gap.
* Coordinator: master moves to Rust 1.100.0; merge master when told, gates
  only after that merge.

## Done (reading)

* Read RULES, LOOP, DIRECTION, ADR-021/022/023/024/027/032, the spec,
  inventory 1.7, 5.1–5.2, 7, 8, 8a, part 1's report, `bk-sleigh` (decode,
  handles, tree, tables, translate, error), `bk-sla` templates and
  `SlaBuilder`, the test harness (`tests/common/*`, `differential.rs`,
  `fixture_oracle.rs`, `fixture/mod.rs`), `tools/reference/pcodedump.cc`,
  Ghidra `sleigh.cc` (builder, cacher, cache, `oneInstruction`),
  `semantics.cc` (`build`, `ConstTpl::fix`, `isDynamic`), `inject_sleigh.cc`.

## Facts established while reading (needed by the implementation)

* Op order for dynamic operands (`SleighBuilder::dump`): loads for dynamic
  inputs first (`INT_ADD ea` then `LOAD` when offset-plus low 16 bits ≠ 0;
  `ea` = `(unique, uniqbase+0x100, pointer size)` and the `LOAD` reads
  through it), then the op, then for a dynamic output `STORE` (preceded by
  `INT_ADD` when offset-plus). A label reference's calling index is the
  op's own index (after its loads).
* Delay slot inside a delay slot: Ghidra takes the parse from its cache; in
  `pcodedump`'s linear sweep only the parses `oneInstruction` made (main +
  the delay-slot run) can be there, so look the address up among main and
  prepared delay parses, else `LowlevelError` "Could not obtain cached delay
  slot instruction" (a `LiftError` variant the spec omits). `DELAY_SLOT` is
  a do-while: builds at least one instruction.
* Crossbuild (Hexagon only): targets are `inst_start`, `inst_start-4/8/12`
  (earlier packet members, in the 8-entry parse cache in a sweep). Use main
  or delay parse when the address matches, else decode on demand into a
  per-nesting-level scratch parse (pass `&mut [Parse]` down the recursion
  with `split_first_mut`). Constants `inst_start/next/next2` come from the
  current instruction; unique bits and handles from the target. Harness:
  count as tolerated when the target was not decoded earlier in the sweep
  (Ghidra's precondition failed) — needs the observer to report targets.
* `UnimplError` inside a delay slot or crossbuild crashes `pcodedump`
  (dangling walker); basilisk reports `Unimplemented` naming the instruction
  being built (its address and text), flow length = flow length.
* `pcodedump` prints a space-id constant as an index only for LOAD/STORE
  input 0; elsewhere it prints the host pointer (watch for this in the
  differential run; tolerate if it occurs).
* U record kinds: Unimplemented/Unaligned → `unimplemented` (flow length
  used only when > 0); other errors by `DecodeError::class()`; flow length
  is the plain length for non-Unimpl errors.
* `calc_mask(size)`: size ≥ 8 (as unsigned) → all bits.
* Inject: handles of parameters are static `(space, offset, size)` by
  operand index; `uniqmask` 0; flowref/flowdest = call address, sizes = its
  space's address size; BUILD has no subtable (no-op).

## Plan (next, in order; 1–3 done)

1. `src/pcode/{mod,buffer,location,build,delay,crossbuild,inject,error}.rs`,
   `src/emit.rs` (`PcodeEmit`, collecting/counting/`P`-record emitters),
   `Decoder::lift` / `lift_observed` (generic `BuildObserver` with no-op
   defaults for coverage: templates built, op templates, feature counters,
   crossbuild targets), `build_template` + `InjectContext`; precompute the
   main template id per constructor in `Tables`; `Language::unique_start`.
2. `src/dump.rs`: the `pcodedump`-format sweep in the library (used by the
   CLI and the harness).
3. `crates/basilisk/src/cmd/disasm.rs` (read `main.rs` first).
4. Harness: compare `P`/`U` and the full `T`; template coverage and feature
   columns; tolerated crossbuild-not-cached.
5. Second fixture language for p-code (`tests/fixture/pcode.rs`, every op
   kind, delay slot, crossbuild + section + uniqmask, user op, labels,
   dynamic load/store with truncation), recorded oracle data.
6. Unit tests (spec 6.3), snapshots, proptest, fuzz target `bk_sleigh_lift`,
   benchmarks + dhat + scaling, `PERF.md`, docs.

## Gaps / Follow-ups

Everything above is still to do.
