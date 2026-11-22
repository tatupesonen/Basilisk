# Track `decomp-ir` (D05) — status (done, waiting for review)

Contract: `docs/features/decomp-ir.md`. Branch `decomp-ir`. Crate
`crates/bk-decomp-ir`.

## Status and how to continue

### Review step B (API changes before other crates build on the crate)

| Item | State | Commits |
|---|---|---|
| 1. Borrowed accessors, cover walk without per-step allocation | done | `4e8fc30` (benchmark on the old code), `dd28ea7` |
| 2. Ranged cursors | done | `b95cca5` |
| 3. `cfg_mut` guard or contract | done (guard) | `39a3ce9` |
| 4. High-variable events | done | `e82557b` |
| 5. What D07 needs besides (key cursor over the op tree, `op_dead_and_gone`, unit brackets) | done | `abc0acc` |
| 6. Final gates, fuzz 300 s, `check-dep-age` | in progress: `scripts/remote.sh gate` started on `abc0acc` (log `gate-remote.log` / `scripts/remote.sh log`), result: **exit 101**, rustdoc `-D rustdoc::private-intra-doc-links` on `crates/bk-decomp-ir/src/list.rs:208` (the `OpIter` doc links to the private `ListHead::iter`; make it plain text and rerun); `gate --no-ref`, `long fuzz 300 bk_decomp_ir_state`, `check-dep-age.py master` not run | |

Item 1: `readers`, `op_inputs`, `block_ops` (an `OpIter` over the block's
intrusive list) and every bank range query (`loc_in_space`, `loc_at`,
`loc_sized`, `loc_class`, `loc_defined`, `def_class`, `def_class_at`) now
return borrowed iterators; `readers_vec`/`op_inputs_vec` are the snapshots
for loops that change the IR (`destroyVarnode`, `totalReplace*`,
`opDestroyRaw`); `reader(vn, i)` is `getDescend(i)`. `bk-decomp-cfg` has
`ins`/`outs` iterators and O(1) `in_edge`/`out_edge`/`in_len`/`out_len`
(`getIn`/`getOut`/`sizeIn`/`sizeOut`); `Cover::addRefRecurse`
(`cover.cc:524`–`557`) reads the in-edge by index and one walk stack is
reused per `rebuild`. Numbers in `docs/PERF.md` (0.379 → 0.032 ms on the
build host for a 1,000-way join). `ops_alive`, `ops_dead`, `ops_of` stay
snapshots: Ghidra's loops over those lists mutate them.

Item 2: `src/bank/cursor.rs`. `loc_cursor_in_space`, `loc_cursor_at`,
`loc_cursor_sized`, `loc_cursor_class`, `loc_cursor_defined`,
`def_cursor_class`, `def_cursor_class_at`, and `LocCursor::until_start_of`
/ `until_end_of` for loops between two begin/end iterators of different
queries (`Heritage::collect`, heritage.cc:315–323). Semantics of
`vn = *iter++` with the end iterator taken before the loop: the successor
is remembered at each step; the end is the *varnode* the end iterator
named (or `end()`), not a key bound, so a varnode inserted past the range
but before that varnode is visited, as `processJoins` expects
(heritage.cc:2282). Where Ghidra is undefined (successor or end varnode
destroyed) the walk continues from the next key / stops at the end's key.
Tests `src/bank/tests.rs` (6).

Item 3: a guard, not a contract. `cfg_mut()` returns `CfgMut`
(`src/block/edit.rs`): it reads as a `Cfg` and forwards every edit that
keeps the node set (edges, labels, flags, index, idom, structuring,
`remove_from_flow*`), but has no `add_node`, `remove_node`, `splice_node`.
Nodes come and go through the `Ssa`: `add_block`, `remove_block`
(`BlockGraph::removeBlock`, refused with `BlockHasOps` while the block
holds ops) and `splice_block_basic` (`Funcdata::spliceBlockBasic`,
funcdata_block.cc:927–967 without `structureReset`: destroys the closing
branch, moves the successor's ops, clears `startbasic`, `setOrder`,
`mergeRange`, graph splice; checks before changing). Why: D07's surgery
(`blockRemoveInternal` 272–343, `removeFromFlowSplit` 900–908,
`spliceBlockBasic`) always pairs a node removal with op-list work, and a
node added behind the `Ssa`'s back had no op list either; a documented
contract would leave both mistakes to the invariant check. Tests
`src/block/tests.rs` (3).

Item 4: `src/high.rs` (`HighEvent`, `high_events`, `take_high_events`,
`set_symbol_reference`, `clear_symbol_links`; the rules with C++ lines in
its module documentation and in spec 4.1). The bank primitives
(`add_descend`, `erase_descend`, `bank_set_def`, `bank_set_input`,
`xref`, `replace`, `bank_make_free` as three setter calls, `bank_destroy`
and `xref`'s merge as `Removed`), the annotation setters (split into the
ones Ghidra routes through `setFlags` and the direct stores),
`varnode_set_flags`/`clear_flags`, `update_type*`, `copy_symbol`,
`set_symbol_entry(Some)`, `calc_cover`, `varnode_cover` (updateCover's
clear reports `CoverDirty` too), `apply_properties`
(`setSymbolProperties`: only a *new* entry of a type-locked symbol is
taken and reported, as in Ghidra), `set_input_varnode` (`setUnaffected`
reports, `setReturnAddress` does not) record events. Tests
`src/mutate/tests/high.rs` (10) and `tests/subset.rs` (loading the
checked-in dumps, which have highs, records nothing).

Item 5 (spec-decomp-wave3 misfit 4, decomp-core.md 4.B pool walk):
`OpCursor` (`src/op_cursor.rs`, `Ssa::op_cursor_main`): `current` /
`advance` / `at_end` over the main tree with `op_state` semantics (moves
only when told, to the op after the current one *then*; an op that left
the tree leaves the cursor on the next); `op_dead_and_gone`
(`Funcdata::opDeadAndGone`, funcdata.hh:485 → `PcodeOpBank::destroy`,
op.cc:1047–1060; a live op is refused). Tests: 2 in `op_cursor.rs` (the
`processOp` order: a rule's later insert is visited, an earlier one not,
the killed op is visited dead and retired after the move). The unit
brackets were already there: `Ssa::begin_unit(unit, name)` /
`Ssa::end_unit()` (`src/record/mod.rs`; Ghidra `debugActivate` /
`debugModPrint(name)`: the name is given at the start, where Basilisk
knows it). Not added: a cursor over the per-opcode lists
(`beginOp(opc)`, std::list iterators); `ops_of` stays a snapshot.
Merged `master` (`f7b72cd`, step A) cleanly at `44506c5`.

Stopped 2026-11-22 on the owner's instruction (laptop shut down). Every
item 1–5 is committed, clippy clean (`cargo clippy -p bk-decomp-ir -p
bk-decomp-cfg --all-features --all-targets`) and `cargo test -p
bk-decomp-ir -p bk-decomp-cfg --all-features` passes on the Mac at
`abc0acc`. Next: item 6 only — both remote gates, the 300 s fuzz run,
`check-dep-age.py master` (one new dev-dependency use, `dhat`, already in
the workspace), the Windows cross-check clippy, then the final report.

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
| 1 (L) | corpus round trip, all points | `tests/corpus.rs` | host (libstdc++) and Mac (libc++): 3,642 loaded, 3,566 byte for byte, 76 pinned join dumps (`support/join_dumps.rs`), invariants hold in all. The two captures are byte-identical except 4 dumps of `datatests/floatprint` |
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
| 11 | fuzz `bk_decomp_ir_state` | `fuzz/fuzz_targets/`, replay `tests/fuzz_regressions.rs` | first 300 s run: 1 finding (a dump with a written varnode without a def was accepted; `load` now refuses states that break the invariants); second 300 s run: 0 findings, 69,332 execs; after review step A the target also mutates (new op, clear dead varnodes, covers): 300 s, 0 findings, 82,457 execs |
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

### (e) Gates and testbed

- `scripts/remote.sh long fuzz 300 bk_decomp_ir_state`: 0 findings (after
  the fix above).
- `scripts/remote.sh wine -- -p bk-decomp-ir`: 66 passed, 0 failed, 4 ignored.
- `scripts/remote.sh arm64 -- -p bk-decomp-ir`: 66 passed, 0 failed, 4 ignored.
- Windows cross-check: `cargo clippy -p bk-decomp-ir --all-targets
  --target x86_64-pc-windows-msvc` clean on the Mac.
- `scripts/remote.sh gate`: `tests: 2489 passed, 0 failed`, `remote: gate exit 0`.
- `scripts/remote.sh gate --no-ref`: `tests: 2489 passed, 0 failed`, `remote: gate exit 0`.
- `scripts/check-dep-age.py master`: 0 new registry packages; 0 younger than 14 days.

### (f) Open questions, ADRs, Ghidra defects

- Ghidra defect (confirmed by reading): `PieceNode::findRoot`
  (`op.cc:883`–`884`) uses `compareOrder` (`op.cc:808`–`820`, which
  returns -1, 0 or 1) as a boolean, so of several PIECEs naming a varnode
  the last in descend order wins unless two are unordered, not "the
  earliest". Basilisk reproduces it.
- `VarnodeBank::searchvn`'s `create_index` is never initialised
  (`Varnode::Varnode`, `varnode.cc:610`–`638`, does not set it;
  `searchvn` is built at `varnode.cc:1220`). Corrected (the first version
  of this note said its flags were never free, which is wrong:
  `beginDef`/`endDef(0, addr)` set `searchvn.flags = 0`, `varnode.cc:1916`
  and the `endDef` twin). The def-order comparator
  (`VarnodeCompareDefLoc`, `varnode.cc:60`–`77`) reads `create_index` only
  after the addresses and the sizes are equal and both are free; `searchvn`
  then has size 0 (`beginDef`) or 1,000,000 (`endDef`), and no varnode of
  either size is ever created, so the indeterminate value is never read
  in a comparison that decides anything, on any build. Basilisk's bound
  keys use create index 0 (`bank/range.rs`, `def_class_addr_bounds`), which
  gives the same ranges. A latent hazard, not an observable defect.
- Ghidra defect: `BlockBasic::insert` (`block.cc:2298`–`2301`) can repeat
  an `order` (`ordafter/2 + ordbefore/2`); corpus `divopt`. Basilisk
  reproduces it.
- Ghidra defect: the console cannot run `print cover varnode <vn>`
  (`ifacedecomp.cc:111`–`112` register `varnode` and `varnodehigh`;
  `IfaceStatus::expandCom`, `interface.cc:436`–`475`, then reads the
  varnode as a fourth command word). Reproduce: `decompile`, then
  `print cover varnode [register,0x0,4](i)` → "ERROR: Invalid command".
- Follow-ups: `bk-testkit`'s `StateDump` reads an op's inputs as a plain
  list, but the console writes an empty slot as `-`
  (`tools/reference/consoleext/bk_ids.cc:42`); 137 of 1,821 dumps taken at
  `blockstructure` have such slots and do not parse (the standard capture
  points happen to have none). The join records (above). A `bk print cover`
  console command for spec test 8. Reading and writing ops with empty
  input slots (mid-pass states) is waiting on that same `bk-testkit` reader
  change, which goes with the oracle track that adds `@joins`. `Cfg` has no allocation-free `size_out`,
  `out(i)`, `in(i)`; `bk-core` `write_raw_sized` is crate-private.
