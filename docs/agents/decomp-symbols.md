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
- [ ] `bk-decomp-symbols`: crate skeleton, `EntryMap` + property test.
- [ ] Scopes, symbols, entries, queries, names, printing, codecs.
- [ ] Scope and context oracles (generators, tables on both hosts, replay).
- [ ] Image table replay (G), `print map` (L).
- [ ] Comments, strings, constant pool, load images, context names,
      overrides, arch filling.
- [ ] Host trait, cache layer, scripted host; overlays and commit.
- [ ] `Spacebase` constructor in `bk-decomp-types`; `SpacebaseScopes`.
- [ ] Fuzz targets, benchmarks, testbed checks, both gates, report.
