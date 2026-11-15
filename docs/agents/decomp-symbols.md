# Track `decomp-symbols` — status

Spec: `docs/features/decomp-symbols.md` (D06). Crates: `crates/bk-context`
(step 0, ADR-043), `crates/bk-decomp-symbols` (new). State: in progress.

## Step 0 — the context store moves to `bk-context` (done)

- `crates/bk-sleigh/src/context/{mod,db,partmap,tracked}.rs` moved (git
  rename) to `crates/bk-context/src/{lib,db,partmap,tracked}.rs`;
  `bk-sleigh` has `pub use bk_context as context;` and keeps its
  `pub use context::{ContextDb, …}` line, so every path compiles unchanged.
- `PartMap` and `Bounds` are public in `bk-context` (documented, one new
  unit test; three small accessors added: `point_mut`, `len`,
  `clear_points`). The hot look-ups (`ContextDb::get`, `get_with_range`,
  `variable`, `context_at`, `PartMap::get`, `bounds`) are `#[inline]`.
- Tests on the build host: `cargo test -p bk-sleigh -p bk-context` all
  green (bk-context 9 unit tests; bk-sleigh unit and integration suites
  unchanged).
- Speed (build host, `crates/bk-sleigh/tests/reference_bench/compare.sh
  $BASILISK_REFERENCE_DIR 7 7`, pinned to one core, 7 rounds each, run as
  after / before (master `4d12e6e`) / after in one job). Ratio Basilisk /
  Ghidra, median of rounds:

  | | after (1) | before | after (2) |
  |---|---|---|---|
  | decode only | 1.174 | 1.111 | 1.169 |
  | decode + lift (counting emitter) | 1.033 | 1.008 | 1.032 |
  | decode + text | 1.509 | 1.449 | 1.533 |
  | decode + text + lift | 1.215 | 1.185 | 1.227 |

  Absolute: bk decode only 5.36 / 5.20 / 5.39 M instructions/s (best).
  No slowdown; the move is within noise (slightly faster).
- Gate on the build host at `de37c32`: exit 0, `tests: 2359 passed, 0 failed`.

## Done / in progress / next

- [x] Step 0.
- [x] `EntryMap` (`src/entrymap/`) + property test against a literal
      transliteration of `rangemap.hh` (`tests/entrymap_props.rs`).
- [x] Database, scopes, symbols, entries, queries, names, mutations,
      printing, symbol/scope/db codecs (`src/database/`, `src/scope/`,
      `src/print.rs`, `src/codec/`).
- [x] Scope oracle: generator `tests/oracle/scope.cc`, table
      `tests/data/scope.txt.gz` (205,124 rows incl. 20 header rows),
      replay `tests/scope_oracle.rs` — every row equal.
- [x] Context names + `<context_points>` (`src/context.rs`); oracle
      `tests/oracle/context.cc`, table `tests/data/context.txt.gz`
      (85,723 rows), replay `tests/context_oracle.rs` — every row equal.
- [x] Comments, strings, constant pool, load images (xml, raw, hex),
      overrides, arch filling (`src/arch.rs`).
- [x] Image oracle: table `tests/data/image.txt.gz` (8,435 rows),
      replay `tests/image_oracle.rs` (needs reference + Ghidra) — every row
      equal for all 93 data tests.
- [x] Tables regenerated twice on each host (`tests/oracle/regen.sh`):
      byte-identical between libc++ (Mac) and libstdc++ (build host).
- [x] `git merge master` (1 of 2) for bkstate version 2.
- [ ] Host trait, cache layer, scripted host; overlays and commit.
- [ ] `Spacebase` constructor in `bk-decomp-types`; `SpacebaseScopes`,
      `TypeSource`.
- [ ] `@scope` dump test (version 2), pspec volatility test, unit tests per
      behaviour table, codec property tests.
- [ ] Fuzz targets, benchmarks, testbed checks, both gates, report.

## Findings so far (for the report)

- Ghidra `rangemap::insert` inserts a record's last fragment twice when
  the record ends at an existing piece end (reproduced).
- Ghidra `rangemap::erase` re-sews `b|b+1` from the first following
  fragment only and can stretch a neighbour left of its start; queries
  then return it (reproduced). A later erase of that record leaves
  dangling fragments (use after free; Basilisk removes them). Confirmed
  with `tests/oracle/rangemap_defects.cc` against Ghidra's header.
- `Duplicate scope id: <full name>` always has an empty name (the new scope
  has no parent yet when Ghidra asks).
- `getLastAddrOpen` is never invalid (spec 4.3 wrong in detail).
- `decodeFlowOverride` does not close twice in this commit (spec 4.21
  row 16 wrong).
- `Funcdata::getName` is the name at creation; a rename of the function
  symbol does not change what `queryFunction` callers print (D07).
- Spec's "`Model` provenance for pspec default symbols": `Provenance::Model`
  is the AI provenance; Basilisk uses `Imported`.
