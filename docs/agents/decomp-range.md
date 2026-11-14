# Track `decomp-range` — status

Spec: `docs/features/decomp-range.md`. Crate: `crates/bk-decomp-range`.

## Done
- Crate with every `CircleRange` method in scope (`src/{range,setops,pull,push,compare,overlap,arith}.rs`).
- `testcirclerange.cc`: 117 cases ported (`tests/ghidra_unit.rs`, model in `tests/common/model.rs`).
- Oracle: generator `tests/oracle/circlerange_oracle.cc`, `regen.sh` (`--marks`: UBSan minimal runtime with
  custom handlers + valgrind; `--extended`: full spec counts), both hosts' tables in `tests/data/` (README there),
  replay `tests/oracle_replay.rs` (all x86-64 rows agree; 834 macOS rows = AArch64 USHL cause), live regen
  `tests/oracle_regen.rs` (passes on macOS: 592,213 extended rows).

## In progress
- Property tests, edge-case unit tests (step 0, huge max_step), no-allocation test.

## Next
- Fuzz target, benchmark + PERF.md, spec sections 8–9, inventory mark, gates.
