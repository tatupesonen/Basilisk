# Track `sla` — status

Branch `sla`, worktree `/Users/tatu/slop/basilisk-wt/sla`. Crate `crates/bk-sla`.
Spec: `docs/features/sla.md`.

## Done
- Model (`src/model/`), id table (`src/ids.rs`), packed cursor + bk-marshal
  adapter (`src/read/source.rs`), model decoder (`src/read/`), validation
  (`src/validate/`), packed/XML writer (`src/write/`), `build_spaces`
  (`src/spaces.rs`), `SlaBuilder` (`src/builder.rs`), structural diff
  (`src/diff/`), lone `Template` codec + `SpaceTable` (`src/template_codec.rs`).
- Tests 1–3 pass on all 150 reference files (`tests/reference.rs`).
- Fixture with every element kind (`tests/common`, `tests/fixtures.rs`);
  one violating fixture per validation rule and per limit, container
  errors (`tests/validation.rs`).

## In progress
- Property tests, fuzz targets.

## Next
- Benchmarks + PERF.md, mutation check (test 4), Windows clippy, gate,
  spec Status/Differences, final report.
