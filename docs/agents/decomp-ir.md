# Track `decomp-ir` (D05) — status (in progress)

Contract: `docs/features/decomp-ir.md`. Branch `decomp-ir`.

## Done
- Reading (rules, ADRs, spec, D00/D04 code, Ghidra sources).
- Crate skeleton: manifest (feature `bkstate`, default on, gates the
  bk-testkit dependency), `ids.rs`.

## Design decisions (so far)
- Arenas: ops 64 bytes (inputs inline up to 3, spill pool), varnodes about 96
  bytes; list links in parallel arrays.
- Bank orders: `BTreeMap` over key structs (Address, size, class, def SeqNum,
  create index); iop offsets store the `OpId`, keyed by the op's time.
- `FunctionEnv` stays one trait (settling open item 10.3): every mutation that
  queries it may also need its recording half (assign_high, laned register,
  wrapping address creates join records), so a split would mean passing two
  objects to the same methods.
- `print raw` names not in the IR (call names, user ops, cpool tokens, Java
  `>>>`) come through a `RawNames` trait; register names through the
  `SpaceManager` (bk-core) the `Ssa` holds in an `Arc`.

## Next
ids/error/flags/pool → varnode/op data → banks → op bank → blocks → mutation
→ print → state load/write → covers → props/semantics → units → tests.
