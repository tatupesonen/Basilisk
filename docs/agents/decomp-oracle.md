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

Done:
- Build script step `[1b/5]`: `decomp_dbg`, extension compiled outside the
  Makefile with the Makefile's flags (read through `consoleext/vars.mk`)
  plus `-fno-access-control`, `decomp_bk`, `decomp_bk_dbg`; own
  fingerprints; STAMP lines. Verified on a scratch copy of the Mac
  reference: steps 1–4 stay "up to date".
- Extension: `bk version`, `bk list actions`, `bk break start|action|clear`,
  `bk dump blocks`, `bk dump structure`, `bk cfg analyze`, `bk structure`
  (bare/asgiven/finish/trace/xml, trace replica checked against Ghidra's
  own `collapseAll`).
- `bk-testkit`: `Tool::{DecompDbg, DecompBk, DecompBkDbg}` (enum now
  `#[non_exhaustive]`), `ReferenceDir::{decomp_dbg, decomp_bk,
  decomp_bk_dbg}`, `LC_ALL=C` for every console run; `oracle::{graph,
  cfgdump, structure, actions, generate}` with unit and property tests;
  fuzz targets `bk_testkit_graph`, `bk_testkit_structure`; samples in
  `crates/bk-testkit/tests/data/oracle/`; `tests/oracle_cfg.rs`
  (regenerates every sample when `decomp_bk` exists; 3,000 generated graphs:
  `structure blocks` XML = `bk structure … xml` XML, 165 end in Ghidra's
  error, replica never differs — Mac).

In progress / next:
1. State dump (`bk dump state`, `bkstate 1`) and its reader.
2. Trace (`bk trace stream`, reader), recorded p-code (`bk pcode
   record|replay|stop`, `pcoderec 1`, reader).
3. Capture driver `bk-oracle`, fixtures, completeness checker, replay
   check, determinism on both hosts, `decomp_dbg` = `decomp`.
4. Optional logs (4.12): decide.
5. Nightly `oracle` item; rebuild both shared references (hash before and
   after); gates; final report.

## Notes for whoever continues

- Scratch reference on the Mac: `target/ref` (copy of `../reference` with
  time stamps kept). Scratch outputs: `target/scratch/`.
- `list action`'s numbers are padded with the console stream's current
  fill (a space in a fresh console, not zeros as the spec says); `bk list
  actions` renders into a fresh stream.
