# Track `sla` — status

Branch `sla`, worktree `/Users/tatu/slop/basilisk-wt/sla`. Crate `crates/bk-sla`.
Spec: `docs/features/sla.md`.

## Done
- Model (`src/model/`), id table (`src/ids.rs`), packed cursor + bk-marshal
  adapter (`src/read/source.rs`), model decoder (`src/read/`), validation
  (`src/validate/`), packed/XML writer (`src/write/`), `build_spaces`.
- Test 1 (packed round trip, byte exact) passes on all 150 reference files,
  through both packed decoders.

## In progress
- XML writer check against `sleigh -y` (test 2), XML reader (test 3).

## Next
- Validation fixtures, limits, builder, structural diff, Template codec,
  property tests, fuzz targets, benchmarks, mutation check, report.
