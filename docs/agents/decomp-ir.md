# Track `decomp-ir` (D05) — status (done, waiting for review)

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

### (b) Tests and results (2026-11-16)

| Spec test | What | Where | Result |
|---|---|---|---|
| 1 (L) | corpus round trip, all points | `tests/corpus.rs` | host and Mac: 3,642 loaded, 3,566 byte for byte, 76 pinned join dumps (`support/join_dumps.rs`), invariants hold in all |
| 1 (S) | checked-in subset: 120 dumps of 20 functions covering all 137 opcode and flag-bit features of the capture | `tests/subset.rs`, `tests/data/subset/` (selection `select_subset`, ignored) | pass |
| 2 | op texts (in 1), block `print raw` at p1 | `tests/corpus.rs` | 607 of 607 equal |
| 3 | orders after load (in 1); creation-order independence | `src/mutate/tests/props.rs` | pass |
| 4a | one or more unit tests per method of 4.5, citing the C++ | `src/mutate/tests/{op,insert,varnode,annotate}.rs` | 39 tests pass |
| 5 | trace recorder grammar and range filter | `src/record/tests.rs` | 2 tests pass |
| 6 | invariants under random calls; refused single-step calls change nothing; dump → load → dump on reachable states | `src/mutate/tests/props.rs`, `tests/state_props.rs` | pass (also at 50,000 cases) |
| 7 | opcode table = `typeop.cc` constructors (G, 73 opcodes); every dumped op's flags (S, L) | `tests/opcode_table.rs`, `tests/corpus.rs` | pass |
| 8 | covers | `src/cover/tests.rs` (from `cover.cc`) | pass; the console half is impossible (see the spec, 8) |
| 9 (L) | block facts = `bk dump blocks` at both `blockstructure` stops and after | `tests/block_facts.rs` | 1,684 stops, 6,065 blocks, 0 differ; 137 dumps unreadable (empty input slots, see follow-ups) |
| 10 | unit table = inventory 5.2/6; duplicates, unknown names, wrong groups refused | `tests/units.rs` | pass |
| 11 | fuzz `bk_decomp_ir_state` | `fuzz/fuzz_targets/` | see (e) |
| 12 | benchmarks, bytes per op/varnode | `tests/bench.rs` (ignored) | `docs/PERF.md` |

The invariant checker (`Ssa::invariant_violations`, `src/check.rs`) is run
by the corpus, subset, property and fuzz tests and by `load` itself.
Reruns: `scripts/remote.sh run -- cargo test -p bk-decomp-ir --test corpus
-- --nocapture` (captures into `target/decomp-ir/capture` when absent);
the same with `--test block_facts`; on the Mac set
`BASILISK_REFERENCE_DIR=/Users/…/reference` and `BASILISK_GHIDRA_DIR`.

### Join records (request for the dump format)

A join varnode's text is `JoinSpace::printRaw` (`space.cc:606`–`628`): the
record's pieces, each by `VarnodeData::printRaw` (`pcoderaw.hh:113`, which
prints a register name or a shortcut and offset, **never the piece's
size**), `pad:N` for a constant piece, and `:size` for a single piece. The
dump carries neither the records nor the piece sizes (an op text such as
`j{s0x00000000,s0xfffffffffffffffc}` does not say how 8 bytes split between
two stack pieces), so the records cannot be rebuilt exactly from a version-2
dump. Needed: a new section (a format version 3, or an optional section
version 2 readers skip), written by the console extension after `@spaces`:

    @joins	<count>
    J	<offset>	<size>	<npieces>	<piece>…

one `J` per record of `AddrSpaceManager::splitlist`
(`translate.hh:198`–`211`, filled by `findAddJoin`, `translate.cc:684`–`728`),
in `splitlist` order (= creation order = ascending offset), **all of them**,
not only those the function's varnodes name; `offset` is `unified.offset`
(hex), `size` is `unified.size` (decimal); each piece is
`<space name>:0x<offset>:<size>` (the form `@proto`'s model entries use),
most significant first, a constant-space piece for padding. Example: x86-64
`retstruct.0` returns `j{EDX,EAX}:8`: `J	0x0	8	2	register:0x10:4	register:0x0:4`
(offsets illustrative). Carrying all records in order lets the loader
replay them through `findAddJoin` (`bk_core::SpaceManager::find_add_join`)
on the dump's spaces and *check* each offset, with no new `bk-core` API:
`bk_decomp_ir::state::install_joins` does that today (test
`join_records_replay_at_the_offsets_the_dump_names`); once `bk-testkit`'s
`StateDump` parses the section, `load` calls it and the 76 dumps leave the
exception list.

### (c) Not done

- The join records (above): needs the dump format change.
- Spec test 8 against the console: impossible in Ghidra's console; a
  `bk print cover <varnode>` command in the console extension would make it
  possible (a request for D00's owner).
- Benchmarks have no reference-console time beside them.
- Spec 4.9's `Profile` is D07's (as the spec says).

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
