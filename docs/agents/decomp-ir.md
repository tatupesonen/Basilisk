# Track `decomp-ir` (D05) — status (in progress)

Contract: `docs/features/decomp-ir.md`. Branch `decomp-ir`. Crate
`crates/bk-decomp-ir`.

## Status and how to continue

### (a) Done (code written; see (b) for whether it compiles)

| Spec | What | Files | Commit |
|---|---|---|---|
| 5 | Crate, ids, errors, flag words, inline id lists with spill pool, intrusive op lists | `ids.rs`, `error.rs`, `flags.rs`, `pool.rs`, `list.rs` | `1a61eec`, `592878b` |
| 4.1 | Varnode record, flag getters, storage queries (overlap ×3, overlapJoin, intersects, contains, characterizeOverlap, termOrder, getUsePoint, isConstantExtended), shadows (isEventualConstant, copyShadow, find(Sub)PieceShadow, partialCopyShadow, isZeroExtended, contiguous_test) | `data.rs`, `varnode/` | `592878b` |
| 4.2 | Bank keys (loc/def with classes), create/createUnique/createDef/xref/replace/setInput/setDef/makeFree/destroy, every range query, find*, overlapLoc, cursors | `bank/` | `592878b` |
| 4.3 | Op record (64 bytes), op bank (both trees, alive/dead, code lists, deadandgone, changeOpcode moving INDIRECT out of alttree, insertAfterDead, moveSequenceDead, markIncidentalCopy, target, findOp, findLastOp, fallthru), op queries (getRepeatSlot, isCollapsible, cse, isMoveable, nextOp, compareOrder, getNZMaskLocal, collapse, executeSimple), PieceNode | `opbank.rs`, `op/` | `592878b` + uncommitted |
| 4.4 | BlockBasic: insert with order scheme, removeOp, setOrder, ranges, getStart/Stop/EntryAddr, contains, unblockedMulti, hasNoImmediateCopy, hasOnlyMarkers, isDoNothing, noInterveningStatement, findMultiequal, earliestUse, liftVerifyUnroll, isComplex, the four facts, `block_facts` | `block/` | `592878b` |
| 4.4 | Cover, CoverBlock, PcodeOpSet (recursion of addRefRecurse made an explicit stack in Ghidra's order) | `cover/` | `592878b` |
| 4.5 | `FunctionEnv` + `TableEnv`; every mutation method of 4.5; annotations | `mutate/` | uncommitted → next commit |
| 4.5 | Recorder trait, trace recorder | `record/` | uncommitted |
| 4.6 | Opcode property table | `props.rs` | `592878b` |
| 4.7 | `print raw` (block and function), op texts, printDebug, printInfo / print tree varnode, with a model of C++'s sticky stream base | `print/` | uncommitted |
| 4.5 | `op_semantics` | `semantics.rs` | uncommitted |
| 4.9 | Units, origins, soundness, table, Ghidra name list generated from the inventory | `unit/` | uncommitted |

### (b) In progress (paused at a clean point, usage limit)

- The crate compiles; unit tests and `tests/state_samples.rs` pass (the
  five `switchind` samples round-trip byte for byte, op texts and both bank
  orders included). Clippy is **not clean** (about 30 warnings, mostly
  pedantic: backticks, unused `self`, `ok_or` with a call, dead helpers).
- **Corpus (L), `tests/corpus.rs`**, run once on the build host (x86-64,
  libstdc++) before the last fix: 3,642 dumps loaded (all), 3,510 written
  back byte for byte; `print raw` at the first point equal to the console's
  in **607 of 607** decompilations. Differences: 76 `join-record-missing`
  (the dump has no join records, so join varnodes print `{unlinked:…}`;
  needs a dump-format addition), 56 user-op names of Ghidra's built-in user
  ops (`stringdata`, `read_volatile`, …, index 0x10000000+). The last commit
  adds those built-in names in `state/names.rs` (not yet re-run on the
  host). The test still asserts zero "other" differences, so it fails
  until the join cause is either accepted as a counted cause (change the
  assertion to pin the count, ADR-040 form) or the dump carries joins.
  Rerun: `scripts/remote.sh run -- cargo test -p bk-decomp-ir --test
  corpus -- --nocapture` (captures into `target/decomp-ir/capture` on the
  host, about 10 s; summary in `target/decomp-ir/corpus.txt`).
- Mac (libc++) corpus run not done yet.

### (c) Not started, in order

1. (done) `state/` (spec 4.8): build a `SpaceManager` from `@spaces` (+ a
   register table), load `@function K`, `@varnodes`, `@ops`, `@oplists`,
   `@blocks` (Cfg nodes/edges/idom/numdesc, ranges, op order) into an `Ssa`;
   keep the `StateDump` for pass-through; write back recomputing loc/def
   order with canonical keys (fspec → qlst position, dead call last), op
   texts with `op_text`, all other sections unchanged. Dump-local type ids:
   `t<n>` ↔ `TypeId::from_raw(n)`. `RawNames` from `@callspecs` (`C` name,
   entry).
2. Register/user-op tables for the S tests: generate per architecture from
   the language (bk-sleigh `Language::registers()`, `user_op_name`) in a G
   test, check them in gzipped.
3. Tests: unit tests per mutation method (cite C++ lines), properties
   (proptest, spec 6.6), round trip and text on `bk-testkit`'s samples
   (`crates/bk-testkit/tests/data/oracle/switchind.*.state.gz`, version 1),
   L test over a fresh capture (`bk_testkit::oracle::capture`), opcode table
   against the console, covers, block facts against `.blocks.bkg`, unit
   table (test 10), fuzz target `fuzz/fuzz_targets/bk_decomp_ir_state.rs`,
   benchmarks (`#[ignore]` release tests), size assertions.
4. Feature doc sections 8–10 append, inventory test lines, PERF.md.
5. Testbed: fuzz 300 s, wine, arm64, both gates.

### (d) Decisions and traps

- `Ssa` holds an `Arc<SpaceManager>` (bk-core) with the registers attached;
  printing uses its register lookup; join records are **not in the dump**,
  so join varnodes print `{unlinked:…}` from a loaded dump (follow-up for
  the dump format).
- An `iop` varnode's stored offset is the `OpId`; its bank key uses the
  op's time. An `fspec` offset is the `CallSpecId` (loaded: qlst position;
  `CallSpecId::DEAD` for `call:-`). A space constant's offset and `nzm` are
  the space index, marked in a parallel `vstate.space_const` flag.
- `FunctionEnv` is one trait (open item 10.3 settled; reasons in
  `mutate/env.rs`). `assign_high`, `laned_register`, `wrapping_address` are
  called at Ghidra's points; the env decides `minLanedSize`.
- `print raw` text depends on C++'s sticky number base (sizes after a
  register `+off` print in decimal, otherwise hex); `print/raw.rs::RawOut`
  models it. The dump's op text is printed after the seqnum in a fresh
  stream (`tools/reference/consoleext/bk_state.cc:181`).
- Errors: checks before changes. Ghidra behaviours made errors: duplicate
  sequence numbers, eraseDescend of a non-reader, null input slots in
  opUnlink/opDestroyRaw are skipped.
- `UnitInfo` has `groups` (a list), not `group`: `directwrite` and
  `unreachable` are placed with two groups each.

### (e) Gates

No gate run yet (neither remote run). The one allowed merge from `master` (bkstate v2) is used:
`6457fb4`.

### (f) Open questions, ADRs, Ghidra defects

- Ghidra defect candidate: `PieceNode::findRoot` (op.cc:883) uses
  `compareOrder`'s -1/0/1 result as a boolean, so "attach to the earliest"
  attaches to any ordered op. Basilisk reproduces it.
- Ghidra defect candidate: `VarnodeBank`'s template varnode `searchvn`
  never initialises `create_index` (varnode.cc:1220); read only for
  size-0 free varnodes, which do not occur.
- Follow-ups for other crates: `Cfg` has no allocation-free `size_out`,
  `out(i)`, `in(i)`; `bk-core` `write_raw_sized` (returns the implied size)
  is crate-private; the state dump lacks join records and register names.
