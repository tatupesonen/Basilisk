# Decompiler IR: varnodes, ops, blocks (`bk-decomp-ir`)

Track `decomp-ir` (D05 of `docs/features/decomp-plan.md`), milestone M3,
wave 2. Format of this document: `docs/LOOP.md`, "Feature documents".
Needs merged: `decomp-oracle` (D00: state dumps), `decomp-types` (D02:
`TypeId`), `decomp-cfg` (D04: the block graph). It carries ADR-025's
property 3a and the data model of the unit table (ADR-025 item 1).

Path abbreviations: `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/`, `REF/` =
`../reference/`, under `../ghidra` and beside the checkout.

## 1. Purpose

The data every decompiler pass works on: a function's p-code operations
and the varnodes they read and write, in SSA form or on the way to it,
arranged in basic blocks; the containers that keep them in Ghidra's
orders; the one interface through which they are changed; and the means
to load this state from, and write it back in, the dump format the
reference console produces, so that each later pass can be developed and
checked from Ghidra's own intermediate state. No pass lives here.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/varnode.hh`, `CPP/varnode.cc` | `Varnode`, `VarnodeBank`, `VarnodeCompareLocDef`, `VarnodeCompareDefLoc`. **Authoritative** |
| `CPP/op.hh`, `CPP/op.cc` | `PcodeOp`, `PcodeOpBank`, `IopSpace`, `PieceNode`; `SeqNum` use |
| `CPP/cover.hh`, `CPP/cover.cc` | `CoverBlock`, `Cover`, `PcodeOpSet` |
| `CPP/block.hh`, `CPP/block.cc` | `BlockBasic` only (the graph is `bk-decomp-cfg`'s) |
| `CPP/funcdata_op.cc` | The op-level mutation methods (`newOp` … `opDestroyRaw`, `opInsert*`, `opUninsert`, `opUnlink`, `opSetOpcode`, `opSetInput`, `opSetOutput`, `opUnset*`, `opSwapInput`, `opRemoveInput`, `opInsertInput`, `opSetAllInput`, `opMarkHalt`, `newIndirectOp`, `newIndirectCreation`, `markIndirectCreation`, `opDeadAndGone`) |
| `CPP/funcdata_varnode.cc` | The varnode-level creation and replacement methods (`newConstant`, `newUnique`, `newUniqueOut`, `newVarnode`, `newVarnodeOut`, `newVarnodeIop`, `newVarnodeSpace`, `newVarnodeCallSpecs`, `newCodeRef`, `setInputVarnode`, `destroyVarnode`, `totalReplace`, `totalReplaceConstant`, `clearDeadVarnodes`, `cloneVarnode`) |
| `CPP/funcdata.cc` | `printRaw`, `printVarnodeTree`; the debug-trace functions `debugModCheck`, `debugModClear`, `debugModPrint`, `debugActivate`, `debugSetRange`, `debugCheckRange` |
| `CPP/typeop.cc`, the `TypeOp*` constructors only | The per-opcode property word (`opflags`) and printed name |
| `CPP/action.hh` (`Action`, `Rule`: `name`, `basegroup`) | Names and groups for the unit table |
| `tools/reference/README.md` (after D00) | The state-dump, trace and recording formats |

## 3. Scope

**In:**
1. Varnodes, ops and their two banks; basic blocks as op sequences over
   `bk-decomp-cfg` nodes; covers.
2. The **mutation interface**: every method of section 4.5, and nothing
   else that can change structure.
3. The per-opcode property table.
4. Text dumps equal to the console's `print raw` and `print tree
   varnode`; loading and writing D00's state-dump format for the parts
   of the state this crate holds.
5. ADR-025 3a: the recorder hook on the mutation interface; op
   semantics sufficient for an evaluator (the evaluator over a whole
   function is D07's).
6. ADR-025 item 1: `UnitId`, `UnitInfo`, `Origin`, `Soundness`,
   `UnitTable` as data.

**Crate owned:** `bk-decomp-ir`. Dependencies: `bk-core`, `bk-marshal`,
`bk-pcode`, `bk-decomp-types` (for `TypeId` and, in dumps, type names),
`bk-decomp-cfg`.

**Not in this track** (they need state this crate does not hold):
everything of `Funcdata` beyond the methods listed — symbols, call
specs, jump tables, heritage state, high variables, flow, `calcNZMask`,
the CSE helpers, `opBoolNegate` and the other compound edits (D07);
`TypeOp` beyond the property word (D08); `HighVariable` and `Merge`
(D14, though `VarnodeId → HighId` is a field here); the action and rule
drivers and profiles (D07); `Funcdata::encode`/`decode` of the function
for a host (D17).

## 4. Behaviour

### 4.1 Varnode
Fields as in inventory 3.2, with pointers replaced by ids: `flags`
(32 bits, all used), `addlflags` (16 bits), `size`, `create_index`,
`mergegroup`, `loc` (`bk_core::Address`), `def: Option<OpId>`, `high:
Option<HighId>`, `mapentry: Option<SymbolEntryId>`, `ty:
Option<TypeId>`, the reader list, `cover` (built on demand,
`coverdirty`), a scratch slot (Ghidra's union of temporary type and
value set), `consumed`, `nzm`. Keep every flag bit and its numeric value
(dumps print the words in hex).

* **State**: exactly one of free, input, written. Constants (`constant`)
  and annotations (`annotation`) are free-standing.
* **Readers** (`descend`): the ops reading the varnode, in the order they
  were attached (`addDescend` appends; `eraseDescend` removes the first
  match). The order is observable — rules walk it — and is dumped.
* **Special offsets.** An `iop`-space varnode's offset is the **`OpId`**
  of the op it names and an `fspec`-space varnode's the **`CallSpecId`**
  (Ghidra stores host pointers); both have size 8 (Ghidra:
  `sizeof(pointer)`, 8 on the reference host). The space input of
  `LOAD`/`STORE` is a constant holding the space index
  (`bk_core::Address::const_from_space`).
* Methods to port as queries on the store: the flag getters, `getDef`,
  `loneDescend`, `hasNoDescend`, `isHeritageKnown`, `overlap` (three
  forms), `intersects`, `contains`, `characterizeOverlap`, `termOrder`,
  `getUsePoint`, `getLocalType`'s storage-only part, `copySymbol`,
  `copySymbolIfValid`, `isConstantExtended`, `isEventualConstant`,
  `findSubpieceShadow`, `findPieceShadow`,
  `partialCopyShadow`, `printRaw`, `printRawNoMarkup`, `printInfo`,
  `printCover`. Those that need a type factory, a symbol or a high
  variable take them as arguments or are left to the crate that has
  them; list which in the status report.

### 4.2 The varnode bank
Two ordered indexes over all varnodes of a function:

* `loc` order (`VarnodeCompareLocDef`): address, then size, then class
  with **input before written before free** (the C++ compares
  `(flag − 1)` unsigned so that free, flag value 0, wraps to the
  largest), then for written varnodes the defining op's `SeqNum`, and for
  free ones `create_index`. Two inputs of the same address and size
  compare equal: there is at most one.
* `def` order (`VarnodeCompareDefLoc`): read the comparator; it is the
  class and definition first, location second.

A varnode's key changes when it becomes an input, gains or loses a
definition, or its defining op's `SeqNum` changes; only the bank's own
methods perform those changes and each re-keys (`xref`, `setInput`,
`setDef`, `makeFree`, `replace`, `destroy`). `xref`/`setInput` can find
an equal varnode already present and return **that** one, having
transferred the readers (read `VarnodeBank::xref`): callers must use the
returned id. Range queries to port: `beginLoc`/`endLoc` in their five
forms (all, by space, by address, by address and size, by address, size
and flag class/defining point), `beginDef`/`endDef` in theirs, `find`,
`findInput`, `findCoveredInput`, `findCoveringInput`, `hasInputIntersection`,
`overlapLoc`. The bank also allocates `unique`-space offsets (`uniqbase`,
`uniqid`, advanced by the varnode's size) and `create_index`.

Iteration during mutation: every loop in Ghidra that walks a bank range
while creating or destroying varnodes advances its iterator before the
body touches the tree. Offer cursors that hold a key and step to its
successor, so the same loops are expressible without borrowing the bank
across the body.

### 4.3 PcodeOp and the op bank
Fields as in inventory 3.3: opcode (`bk_pcode::OpCode`; behaviour and
type rules are looked up by opcode elsewhere), `flags`, `addlflags`,
`start: SeqNum` (instruction address, `time` unique per function, `order`
within the block), `parent: Option<BlockId>`, list links, `output:
Option<VarnodeId>`, inputs (inline storage for up to three or four,
spilling to the arena). `SeqNum` ordering is `bk_core`'s (address, then
time).

* **Alive and dead.** A new op is dead (`dead` flag, in the dead list).
  Inserting it into a block makes it alive; `opUninsert` and `opDestroy`
  make it dead again; `opDestroyRaw` and `opDeadAndGone` retire it. A
  retired op's slot is not reused until the function is cleared, and its
  `time` is never reused.
* **Indexes.** The main index by `SeqNum` (`optree`: iteration order of
  every rule pool); the alternate index for quarantined `INDIRECT`s
  (`alttree`; read `PcodeOpBank::markIncidentalCopy`-style users before
  deciding it is needed in wave 2 — if nothing in this track's scope
  touches it, declare the field and defer its methods); lists of alive
  ops, dead ops and per-category ops (`STORE`, `LOAD`, `RETURN`,
  `CALLOTHER`) in insertion order, with O(1) removal (links stored in
  the op, as Ghidra stores list iterators).
* `PcodeOpBank::create` gives the next `time`; `changeOpcode` moves the
  op between category lists; `markAlive`/`markDead`; `insertAfterDead`,
  `moveSequenceDead`, `markIncidentalCopy`; `target(addr)`, `findOp`,
  `fallthru`; `begin(addr)`/`end(addr)` ranges; `beginAlive`, `beginDead`,
  `begin(opcode)`.
* **Order within a block.** `BlockBasic::insert` places the op in the
  block's list and assigns `order` so that ops compare by position
  (`setOrder`/the midpoint scheme: read `BlockBasic::insert` and
  `setOrder`; when no gap is left the whole block is renumbered). Also
  maintains `startbasic` on the first op. `order` is what
  `SeqNum::getOrder` comparisons and covers use, and it is dumped.
* Queries: `getEvalType`, `getHaltType`, the flag getters, `getSlot`,
  `getRepeatSlot`, `isCseMatch`, `isCollapsible`, `isMoveable`,
  `nextOp`, `previousOp`, `target`, `getNZMaskLocal`, `compareOrder`,
  `printRaw`, `printDebug`, `getOpName`, `collapse`,
  `collapseConstantSymbol` — take the full list from the class
  declaration; those that need `TypeOp`
  behaviour beyond the property word are deferred to D08 and listed.
* `PieceNode` (`isLeaf`, `findRoot`, `gatherPieces`) is here: it reads
  only ops and varnodes.

### 4.4 Basic blocks and covers
A basic block is a `bk-decomp-cfg` node plus, in this crate, its op list
(intrusive, in `order`), the owning function and its original address
ranges (`RangeList cover`: `setInitialRange`, `copyRange`, `mergeRange`).
Port from `BlockBasic`: `insert`, `removeOp`, `setOrder`, `beginOp`/
`endOp`/`lastOp`/`firstOp`, `getEntryAddr`, `getStart`, `getStop`,
`contains`, `unblockedMulti`, `hasOnlyMarkers`, `isDoNothing`,
`findMultiequal`, `earliestUse`, `liftVerifyUnroll`, `noInterveningStatement`,
`printRaw`. `negateCondition`, `isComplex`, `flipInPlace*`, `getSplitPoint`
are the facts and edits the structurer exchanges with the IR (plan 9.1):
provide `isComplex` and the last-op facts as functions producing the
per-block input of `bk-decomp-cfg`, and condition negation as a mutation
method (section 4.5).

`Cover`: per block, the range of ops over which a varnode is live
(`CoverBlock` start/stop as op positions with the special "whole block",
"from the top", "empty" encodings — read the class); `addDefPoint`,
`addRefPoint` (walks predecessors until the definition), `intersect`,
`intersectByBlock`, `intersectList`, `merge`, `rebuild`, `compareTo`,
`containVarnodeDef`, `print`. `PcodeOpSet` is the abstract sorted op set
covers are tested against.

### 4.5 The mutation interface (ADR-025 3a)
All structural change goes through methods on one type (working name
`Ssa`, the IR of one function), mirroring `Funcdata`'s:

* ops: `new_op(inputs, addr)`, `new_op_with_seq`, `op_set_opcode`,
  `op_set_input`, `op_set_output`, `op_unset_input`, `op_unset_output`,
  `op_swap_input`, `op_remove_input`, `op_insert_input`,
  `op_set_all_input`, `op_insert_before/after/begin/end`, `op_insert(block,
  position)`, `op_uninsert`, `op_unlink`, `op_destroy`, `op_destroy_raw`,
  `op_dead_and_gone`, `op_mark_halt`, `op_flip_condition`, the
  `INDIRECT` constructors;
* varnodes: `new_constant`, `new_unique`, `new_unique_out`,
  `new_varnode`, `new_varnode_out`, `new_varnode_iop`,
  `new_varnode_space`, `new_varnode_callspecs`, `new_coderef`,
  `set_input_varnode`, `destroy_varnode`, `total_replace`,
  `total_replace_constant`, `clear_dead_varnodes`;
* annotations: setters for every flag bit Ghidra exposes a public setter
  for (13 on `PcodeOp`, about 50 on `Varnode` — the lists are in the
  class declarations), `update_type`, `set_consume`, `set_nzm`,
  `set_high`, `set_symbol_entry`, merge group.

Semantics that are easy to lose:

* `op_set_input` with a **constant that already has a reader** makes a
  fresh constant of the same size and value (copying its symbol) and
  attaches that, unless the constant is a spacebase placeholder: a
  constant has one reader. Setting the input already present is a no-op.
  The reader is added to the varnode **before** the op's slot is written.
* `op_set_output` on a varnode: the varnode becomes written and is
  re-keyed, and the bank may return a different (pre-existing) varnode.
* `op_destroy` destroys the output varnode, detaches the inputs, marks
  the op dead and removes it from its block; it does not retire it.
  `op_unlink` detaches without destroying the output.
* `op_set_opcode` re-derives the op's property flags from the property
  table (4.6), preserving the flags that are not opcode-derived (read
  `Funcdata::opSetOpcode` and `PcodeOp::setOpcode` for the mask), and
  moves the op between category lists.
* No method leaves the indexes inconsistent on error: checks first, then
  changes.

**Recorder.** The interface owns an optional `&mut dyn Recorder`. Each
structural method, before changing an op, calls `recorder.op_changing(op)`
— Ghidra's `debugModCheck`, which is called at twelve places in
`funcdata_op.cc` and stores the op's text the first time it is touched
within a unit — and the driver brackets a unit with `begin_unit(UnitId)`
and `end_unit()` (`debugActivate`, `debugModPrint`). The recorder decides
what to keep: Ghidra's trace keeps the before-text of each touched op and
prints it with the after-text at the end of the unit; a provenance
recorder keeps `(unit, op)` pairs. With no recorder attached the cost is
one branch. Annotation setters call `annotation_changing` only when the
recorder asks for annotations (off by default: the volume is large and
Ghidra's trace does not show them). The crate provides the
**trace recorder**, which reproduces Ghidra's `DEBUG n: name` records
exactly, including the address-range filter (`debugSetRange`,
`debugCheckRange`) and the rule that a unit which touched nothing prints
nothing.

**Evaluation.** At every unit boundary each live op has a defined
meaning, which this crate documents and exposes as data (the evaluator
that runs a function is D07's):

* ordinary ops: `bk_pcode::behavior` on the input values;
* `MULTIEQUAL`: the input whose slot is the index of the block edge
  control arrived by;
* `INDIRECT`: input 0 unless the op named by the `iop` input (a call or
  store) changes that storage, in which case the value the environment
  reports for the storage after that op; with `indirect_creation`, the
  value the environment reports;
* a **free** varnode denotes its storage (the latest value written to
  that address by an executed op), an input varnode its value at entry,
  a written varnode the value its defining op produced;
* `COPY` markers, `CAST`, `PTRADD` (`in0 + in1 * in2`), `PTRSUB`
  (`in0 + in1`), `PIECE`, `SUBPIECE`, `INSERT`, `ZPULL`, `SPULL` are
  ordinary; `LOAD`, `STORE`, `CALL*`, `BRANCHIND`, `RETURN`, `SEGMENTOP`,
  `CPOOLREF`, `NEW` need the environment (the ops Ghidra flags
  `special`).

Provide `op_semantics(op) -> Semantics` classifying each op this way, and
make it total over the opcode set.

### 4.6 Per-opcode properties
One static table: opcode → property word (the `PcodeOp` flag bits
`TypeOp` constructors pass as `opflags`: `unary`, `binary`, `special`,
`ternary`, `branch`, `call`, `returns`, `marker`, `booloutput`,
`commutative`, `coderef`, `nocollapse`, `has_callspec`, `nonprinting`…),
the name `print raw` uses, and the additional `TypeOp` flags
(`inherits_sign`, `inherits_sign_zero`, `shift_op`, `arithmetic_op`,
`logical_op`, `floatingpoint_op`, `boolean_reorder`). Generate it by reading the 63
constructors in `typeop.cc`; test it against a table dumped by the
oracle (`glb->inst[opc]->getFlags()` and `getName()` for every opcode).

### 4.7 Text dumps
`Funcdata::printRaw`: when blocks exist, each block's header and ops
(`BlockBasic::printRaw`); otherwise the ops in `SeqNum` order.
An op line is `<addr>:<time hex>:\t<output> = <expression>` where a
varnode prints as its storage (`RSP`, `u0x00008e00:4`, `#0xa:4`,
`s0xfffffffffffffff4:4`) followed by `(<def seqnum>)`, `(i)` for an input
or `(free)`, and the expression is written by the opcode's `printRaw`
(`TypeOp::printRaw` variants: infix, function-style, `*(space,ptr)`,
`goto`, `return(…)`, call forms, `[create]` and so on). Register names
come from a `RegisterLookup`; sizes are suppressed when they equal the
register's or the default. `printVarnodeTree` prints each varnode in
`def` order: type name, ` = `, the raw form, flag words as names
(`mapped`, `tlock`, `nlock`, `implied`, …), `(consumed=0x…)`,
`(internal=…)` and `(create=0x…)` — Basilisk omits `internal=` and the
comparison strips it from Ghidra's text. Exact formats are defined by
the captured console output; where this section and a capture disagree,
the capture is right and this section is corrected.

### 4.8 State load and dump
Implement D00's dump format for varnodes, ops, block op lists, block
address ranges and the function-level counters this crate owns
(`create_index`, `uniqid`, op `time`); ids in the dump are Ghidra's
creation indices and sequence numbers, and loading reproduces them, so
that anything created afterwards gets the numbers Ghidra would give.
Sections of the dump owned by other crates (symbols, call specs, heritage
state, types) are passed through opaquely by this crate's loader and
writer until their crates exist, so the round trip is byte-exact from
the first day.

### 4.9 Units (ADR-025 item 1)
Pure data, here because the recorder names units:

* `Origin`: `Ghidra`, `Basilisk`.
* `UnitKind`: `Action`, `Rule`, `MergePass`, `StructureStep`,
  `OutputPass`.
* `Soundness`: `Exact`, or `Assumes(AssumptionId)` with a registry of
  named assumptions (`no-nan`, `readonly-memory-constant`,
  `prototype-effects`, `dead-by-consume`, …) — what the stage-equivalence
  check uses to qualify a comparison (plan 9.1).
* `UnitInfo { name, origin, group, kind, opcodes (rules only),
  soundness }`; names and groups are Ghidra's strings (inventory 5.2
  and 6), interned.
* `UnitTable`: built once from the `&'static [UnitInfo]` slices each
  pass crate exports, giving `UnitId(u16)`; lookup by name; duplicate
  names of the same kind and origin are an error. Ghidra's universal
  action contains nine actions more than once with different groups
  (`directwrite` in `protorecovery_a` and `_b`, `deadcode`, `unreachable`,
  …): a unit is the action; its *placements* (position, group,
  constructor argument) belong to a profile.
* A `Profile` (the arrangement of placements into Ghidra's nested
  groups and pools, and the builder that turns it into a pipeline) is
  D07's; this crate defines only the table it is built from, and a
  consistency check: the Ghidra-origin units of a table can be compared
  with a checked-in list of all 161 rule names and 71 action names with
  their groups, generated from inventory 5.2 and 6.

## 5. Design

* **Storage** (ADR-012): arenas `Vec<VarnodeData>`, `Vec<OpData>` indexed
  by `VarnodeId(u32)`, `OpId(u32)`; ids are never reused within a
  function; hot fields (flags, opcode, sizes, inputs) packed first and
  the struct sizes asserted in a test (targets: op ≤ 64 bytes with three
  inline inputs, varnode ≤ 96 bytes). Whether a field lives in the
  struct or a parallel array is private: all access is through methods.
* **Ordered indexes**: `BTreeMap`/`BTreeSet` over explicit key structs
  (`LocKey`, `DefKey`, `SeqNum`) first; they are correct by construction
  and the dumps test them. Replace by something faster only on benchmark
  evidence. Reader lists: a small inline vector of `OpId` per varnode
  (most have one or two readers), order-preserving removal.
* **Intrusive lists** (block op list, alive/dead, per-category): `prev`/
  `next` `OpId` fields in the op and a head/tail per list. Removal O(1),
  no allocation, no dangling: a link is an index and liveness is a flag.
* **Borrowing.** Passes hold `&mut Ssa` and ids. Queries return copies of
  small values or short-lived references; iteration over anything that
  the body may change uses cursors (`let mut c = ssa.ops_from(seq);
  while let Some(op) = c.next(&ssa) { … ssa.op_destroy(op)?; }`).
  Stale ids are detected in debug builds by a generation or "retired"
  check and are an error value, never undefined behaviour (ADR-020: no
  `unsafe`).
* **Per function, no globals.** An `Ssa` owns everything of one function
  and is `Send`; program-wide data (spaces, types, registers) is
  borrowed per call. Join-space offsets a function creates go through a
  per-function table (plan 3.7).
* **Errors**: `IrError` (`thiserror`); the interface checks what Ghidra
  asserts or assumes (slot in range, op alive where required, varnode
  free before `set_output`) and returns an error naming the method and
  the ids.
* **Modules**: `ids`, `varnode/{data, flags, query, shadow, print}`,
  `bank/{loc, def, alloc, cursor}`, `op/{data, flags, query, print,
  piece}`, `opbank/{seq, lists, cursor}`, `block/{basic, order, facts}`,
  `cover/{block, cover, opset}`, `mutate/{op, varnode, annotate}`,
  `record/{recorder, trace}`, `semantics`, `props` (the opcode table),
  `dump/{raw, tree}`, `state/{load, write, format}`, `unit`, `error`.
  Every file under 600 lines.
* ADR-011: arena crates (`slotmap`, `typed-arena`, `la-arena`,
  `index_vec`/`typed-index-collections`) were considered. Ids here must
  equal Ghidra's creation order and never be reused, removal keeps the
  slot, and the layout must stay free to split into parallel arrays —
  a plain `Vec` with a newtype index does all of it; evaluate
  `typed-index-collections` or `index_vec` for the indexing boilerplate
  and record the outcome. `smallvec` for inline inputs and readers.
  `petgraph` is not suitable for the def-use graph (ordered multi-edges
  with slots, two custom orderings) and is not used here.

## 6. Tests

Kinds: **S** self-contained; **G** needs the spec root; **L** needs the
live reference tools (`decomp-plan.md` 4.5). Every test names the
profile whose state it uses (`ghidra` throughout).

1. **State round trip** (S for a checked-in subset, L for all): for
   every function of every data test and of the research corpus, dumps
   taken by the reference console at four break points — after
   `ActionStart`, at the first start of `oppool1` (after the first
   heritage pass), at the start of the `cleanup` pool, and at `stop` —
   load and write back byte for byte. The checked-in subset is the
   dumps of 20 functions chosen to cover every opcode and every flag
   bit that occurs in the full set (selected mechanically; the list and
   the selection script are checked in), gzip-compressed.
2. **Text dumps** (S): `print raw` and `print tree varnode` generated
   from each loaded state equal the console's captured text for the same
   break point (`internal=` stripped).
3. **Ordering** (S): after loading, iterating the `loc` index, the `def`
   index, the op index, each block's ops and each varnode's readers
   yields the dump's order; inserting the same varnodes and ops in
   shuffled order (property test) yields the same.
4. **Mutation replay** (S): the oracle console, between two dumps, logs
   every `Funcdata` mutation call it makes with its arguments (D00
   wraps the methods of section 4.5 in the extension when built for this
   purpose); replaying the log through the Rust interface on the first
   dump produces the second dump, for the rule-pool runs of the 20
   functions. This checks each method's semantics against Ghidra's,
   including the ids it allocates. If D00 cannot log calls without
   patching Ghidra, the fallback is the trace: replaying D07's rule
   drivers is not available here, so the fallback acceptance is items 1–3
   plus hand-derived unit tests for each method with the expected state
   written from the C++ source — state which was used.
5. **Trace recorder** (S): for the replayed runs, the trace recorder's
   output equals the reference debug console's `DEBUG` records.
6. **Properties** (`proptest`, S): random sequences of valid mutations
   keep the invariants — every reader list matches the ops' inputs, each
   written varnode's `def` has it as output, index keys match fields, a
   constant has at most one reader, alive ops are in exactly one block
   list, `order` increases along each block; dump → load → dump is the
   identity on any reachable state; invalid calls return errors and
   change nothing.
7. **Opcode properties** (S): the table against the oracle's dump of
   `TypeOp` flags and names; `op_semantics` total.
8. **Covers** (S): for loaded final states, the cover of each varnode
   printed (`printCover`) equals `print cover varnode` from the console
   for a sample of varnodes per function.
9. **Unit table** (S): Ghidra-origin names and groups equal the
   generated list; building with a duplicate or unknown name fails.
10. **Fuzz target** `bk_decomp_ir_state` (load arbitrary dump text).
11. **Benchmarks**: load of the largest dump; create/insert/destroy of
    one million ops; a full walk of the op index with a rule-like body
    that inserts and deletes; bytes per op and per varnode. Numbers in
    `PERF.md`, with the reference console's time to reach the same
    break point beside them.

## 7. Acceptance

1. Round trip (item 1) is byte-exact for the checked-in subset on
   Windows, macOS and Linux (S), and for every function of both corpora
   where the reference tools are present (L); any function that does not
   round-trip is listed with the first differing line.
2. Text dumps equal the console's (item 2).
3. Mutation replay reproduces the second dump for all recorded runs, or
   the stated fallback is met and D00's limitation is reported.
4. The trace recorder reproduces Ghidra's records for those runs.
5. No structural field of an op or varnode can be changed except through
   the mutation interface: the data structs' fields are private to the
   crate and the public API has no other `&mut` path (reviewed, and
   enforced by the module boundary).
6. The unit table's data model exists with test 9; `Soundness` is a
   field of `UnitInfo`.
7. Size assertions and benchmarks recorded; no `unsafe`; no panic on any
   dump text; gate green; files within the size limit; public items
   documented with the Ghidra member they correspond to.

## 8. Differences from Ghidra

- Ids instead of pointers; `iop` and `fspec` offsets are ids and their
  varnodes are 8 bytes on every host; no `internal=` in dumps.
- Pointer-keyed orders do not exist; every order is by key or creation.
- The debug trace is always available (a recorder), not a build option.
- `Funcdata`'s graph part is a separate value (`Ssa`); the rest of
  `Funcdata` is in `bk-decomp-core`.
- Units, origins and soundness have no Ghidra counterpart beyond name
  and group.

(The implementing agent appends further differences here.)

## 9. Status

Not started. Waits for D00, D02 and D04.

Not verified while writing this spec, to be settled by the implementer
from the source and the captures: the exact `order` numbering scheme of
`BlockBasic::insert`; the full list of `printRaw` forms per opcode; which
`PcodeOp`/`Varnode` queries need `TypeOp` or a type factory; whether the
`alttree` index is used by anything in this track's scope; whether D00
can log mutation calls without patching Ghidra (test 4).
