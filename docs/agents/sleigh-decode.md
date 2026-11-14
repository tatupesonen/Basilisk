# Track `sleigh-decode` — status report (in progress)

Branch `sleigh-decode`, worktree `/Users/tatu/slop/basilisk-wt/sleigh-decode`.
Crate `crates/bk-sleigh` (new). Spec: `docs/features/sleigh-decode.md`.

## Done
- Crate skeleton: `language/{mod,load,registers,setup,tables}`, `context/{mod,db,partmap,tracked}`,
  `decode/{mod,bytes,tree,expr,decision,resolve,handles,commit}`, `print`, `error`, `translate`.
- Harness support in `tests/common/` (basilisk sweep in pcodedump's record format, oracle run,
  record comparison with resynchronisation and the three tolerated differences).
- Smoke differential test (x86-64 and Toy) passes.

## In progress / next
1. Directed-sample harness per root leaf pair, random sweep, real code; all 150 languages.
2. Coverage table snapshot and exceptions file; recorded oracle output for CI.
3. Unit tests on SlaBuilder fixtures, proptest, fuzz targets, benchmarks, PERF.md.

## Notes for a successor
- Tests need `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference` (REF has no Module.manifest,
  so `tests/common/mod.rs` builds the registry with one `.module()` per processor directory).
- Flow length: a delay-slot instruction with its own delay slot whose instructions `prepare` did
  not decode makes Ghidra's p-code builder fail ("Could not obtain cached delay slot instruction"),
  so pcodedump's flow length is the plain length (`tests/common/sweep.rs::nested_delay_missing`).
