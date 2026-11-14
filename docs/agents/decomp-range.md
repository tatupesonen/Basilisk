# Track `decomp-range` — status

Spec: `docs/features/decomp-range.md`. Crate: `crates/bk-decomp-range`.

## Done
- Crate with every `CircleRange` method in scope (`src/{range,setops,pull,push,compare,overlap,arith}.rs`).
- `testcirclerange.cc`: 117 cases ported (`tests/ghidra_unit.rs`, model in `tests/common/model.rs`), all pass on macOS.

## In progress
- Oracle generator `tests/oracle/` and table replay.

## Next
- Oracle on the build host (libstdc++), compare tables; UBSan and valgrind marks.
- Property tests, fuzz target, benchmark, PERF.md, spec sections 8–9, inventory mark.
