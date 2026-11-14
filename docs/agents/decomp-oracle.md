# Track `decomp-oracle` (D00) — status

Contract: `docs/features/decomp-oracle.md`. Branch `decomp-oracle`.

## `bk structure` and `bk cfg` are usable (for D04)

Since commit "feat(decomp-oracle): bk structure, bk cfg analyze, bk dump
blocks/structure …": the extension builds into `decomp_bk`/`decomp_bk_dbg`
with `scripts/build-reference.sh`; the formats `bkgraph 1`, `bkcfg 1`,
`bkstruct 1`, `bkactions 1` are documented in `tools/reference/README.md`
("The console extension") and read and written by
`bk_testkit::oracle::{GraphFile, CfgDump, StructureDump, ActionList}`.
The shared reference directories do **not** have `decomp_bk` yet (they are
rebuilt at the end of the track); to use the commands before that, build a
scratch copy: `cp -Rp ../reference target/ref` and run the script with
`BASILISK_REFERENCE_DIR=$PWD/target/ref`.

## State

Done (all committed):
- Build step `[1b/5]` (decomp_dbg, decomp_bk, decomp_bk_dbg); extension
  commands: version, list actions, break, dump blocks/structure/state,
  cfg analyze, structure, capture structure, pcode record/replay/stop,
  trace stream.
- `bk-testkit::oracle`: graph, cfgdump, structure, actions, state, trace,
  pcoderec readers/writers with property tests and five fuzz targets
  (`bk_testkit_{graph,structure,state,trace,pcoderec}`); generate; host
  (library detection, digests, named-cause classification); capture
  (driver library) and the `bk-oracle` binary.
- Captures on both machines (scratch references): 167 scripts, 607
  decompiles, 0 errors, two runs identical on each; Mac vs host differ in 5
  files (floatprint: nan-sign 48 lines, nan-order 8). Fixtures in
  `fixtures/decomp-oracle/`.
- valgrind on the host found three uninitialised reads in the dump
  (Action::count/lcount, FuncCallSpecs::matchCallCount, FuncProto::extrapop
  without a model) — fixed.

Next:
1. README sections for bkstate, pcoderec, trace, bk capture structure.
2. Split files over 600 lines (structure.rs, state/records.rs, state/sections.rs).
3. Nightly `oracle` item.
4. Build checks 6.7; rebuild both shared references with before/after hashes.
5. Optional logs (4.12): decide and report.
6. wine, fuzz 300 s, gates; feature doc sections 8–10; final report.

## Notes for whoever continues

- Scratch reference on the Mac: `target/ref` (copy of `../reference` with
  time stamps kept). Scratch outputs: `target/scratch/`.
- `list action`'s numbers are padded with the console stream's current
  fill (a space in a fresh console, not zeros as the spec says); `bk list
  actions` renders into a fresh stream.
