# Decompiler IR: varnodes, ops, blocks (`bk-decomp-ir`)

Track `decomp-ir` (D05 of `docs/features/decomp-plan.md`), milestone M3,
wave 2. Format of this document: `docs/LOOP.md`, "Feature documents".
Needs merged: `decomp-oracle` (D00: state dumps, `bk-testkit`'s
`oracle::state`), `decomp-types` (D02: `TypeId`, `TypeFactory`),
`decomp-cfg` (D04: `bk-decomp-cfg`, merged). It carries ADR-025's
property 3a and the data model of the unit table (ADR-025 item 1).

Path abbreviations: `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/` under `../ghidra`
(commit `42db038f3c`), `REF/` = the reference directory. **(read)** marks
a statement from the source (file:line), **(ran)** one checked against the
reference build (commands in `docs/research/decomp-wave2/runs.md`, W5–W6).
Revised 2026-11-15 by track `spec-decomp-wave2` against the source, D00
(`features/decomp-oracle.md`, `tools/reference/README.md`) and D04
(`features/decomp-cfg.md`, `bk-decomp-cfg`); the changes are listed in
`docs/agents/spec-decomp-wave2.md`.

## 1. Purpose

The data every decompiler pass works on: a function's p-code operations
and the varnodes they read and write, in SSA form or on the way to it,
arranged in basic blocks; the containers that keep them in Ghidra's
orders; the one interface through which they are changed; and the means
to load this state from, and write it back in, D00's state-dump format,
so that each later pass can be developed and checked from Ghidra's own
intermediate state. No pass lives here.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/varnode.hh`, `varnode.cc` | `Varnode`, `VarnodeBank`, `VarnodeCompareLocDef`, `VarnodeCompareDefLoc` (varnode.cc:30–79). **Authoritative** |
| `CPP/op.hh`, `op.cc` | `PcodeOp`, `PcodeOpBank` (op.hh:287–375, op.cc:940–1300), `IopSpace`, `PieceNode`; `SeqNum` use |
| `CPP/cover.hh`, `cover.cc` | `CoverBlock`, `Cover`, `PcodeOpSet` |
| `CPP/block.hh` 470–531, `block.cc` 2270–2720 | `BlockBasic` only (the graph and hierarchy are `bk-decomp-cfg`'s) |
| `CPP/funcdata_op.cc` 25–470, 630–764 | The op-level mutation methods: `opSetOpcode`, `opMarkHalt`, `opUnsetOutput`, `opSetOutput`, `opUnsetInput`, `opSetInput`, `opSwapInput`, `opInsert`, `opUninsert`, `opUnlink`, `opDestroy`, `opDestroyRecursive`, `opDestroyRaw`, `opSetAllInput`, `opRemoveInput`, `opInsertInput`, `newOp` (both), `newIndirect`, `opInsertBefore`/`After`/`Begin`/`End`, `cloneOp`, `newOpBefore`, `newIndirectOp`, `newIndirectCreation`, `markIndirectCreation` |
| `CPP/funcdata_varnode.cc` 25–310, 354–394, 860–883, 1544–1609 | `setVarnodeProperties`, `assignHigh` (as hook points, 4.5), `newConstant`, `newUnique`, `newVarnodeOut`, `newUniqueOut`, `newVarnode` (both), `newVarnodeIop`, `newVarnodeSpace`, `newVarnodeCallSpecs`, `newCodeRef`, `cloneVarnode`, `destroyVarnode`, `setInputVarnode`, `clearDeadVarnodes`, `totalReplace`, `totalReplaceConstant` |
| `CPP/funcdata.cc` 207–223, 576–588, 1118–1232 | `printRaw`, `printVarnodeTree`; the debug trace `debugModCheck`, `debugModClear`, `debugModPrint`, `debugActivate`, `debugSetRange`, `debugCheckRange` |
| `CPP/typeop.cc` (`registerInstructions` and the 74 `TypeOp*` constructors) | The per-opcode property word (`opflags`, `addlflags`) and printed name |
| `CPP/action.hh` (`Action`, `Rule`: `name`, `basegroup`) | Names and groups for the unit table |
| `tools/reference/README.md` (D00) | The state-dump (`bkstate` 1), trace and recording formats |

`funcdata_block.cc` (block removal, splitting, joining, jump-table
installation, `structureReset`, `spliceBlockBasic`, …) is D07's: those
methods combine D04's graph surgery with this crate's op primitives
(`op_insert`, `op_uninsert`, block op-list moves, block ranges) and
`Funcdata` state (jump tables, call specs).

## 3. Scope

**In:**
1. Varnodes, ops and their two banks; basic blocks as op lists over
   `bk-decomp-cfg` nodes; covers.
2. The **mutation interface**: every method of section 4.5, and nothing
   else that can change structure; with the hook trait through which the
   steps that need symbol, type, prototype or high-variable state are
   delegated (4.5).
3. The per-opcode property table (4.6).
4. Text dumps equal to the console's `print raw`, the op texts of D00's
   `@ops`, and `print tree varnode`'s per-varnode text; loading and writing
   D00's state dump for the parts of the state this crate holds, passing
   the other sections through (4.8).
5. ADR-025 3a: the recorder hook on the mutation interface; op semantics
   sufficient for an evaluator (the evaluator over a whole function is
   D07's).
6. ADR-025 item 1: `UnitId`, `UnitInfo`, `Origin`, `Soundness`,
   `UnitTable` as data.
7. The four per-block facts `bk-decomp-cfg` takes (`complex`,
   `switch_out`, `ends_in_return`, `negation_changes_dataflow`;
   decomp-cfg.md 4.1) computed from a function's blocks, and the op half
   of `BlockBasic::negateCondition` as a mutation (4.4).

**Crate owned:** `bk-decomp-ir`. Dependencies: `bk-core`, `bk-marshal`,
`bk-pcode` (`OpCode`, behaviours), `bk-decomp-types` (`TypeId`,
`TypeFactory` for default types and type names in dumps),
`bk-decomp-cfg` (`Cfg`, `NodeId`, `BlockFacts`, `Fact`). Not
`bk-decomp-symbols` (D06, same wave) nor `bk-cspec`: what the mutation
methods need from symbols and prototypes comes through the hook trait.

**Not in this track** (they need state this crate does not hold):
everything of `Funcdata` beyond the methods listed — symbols, call
specs, jump tables, heritage state, high variables, flow, `calcNZMask`,
the CSE helpers, `opBoolNegate`, `opUndoPtradd`, `opFlipInPlace*`,
`replaceLessequal` and the other compound edits, `funcdata_block.cc`
(D07); `TypeOp` beyond the property word and printing (D08);
`HighVariable` and `Merge` (D14; the `VarnodeId → HighId` field is
here); the action and rule drivers and profiles (D07);
`Funcdata::encode`/`decode` for a host (D17).

## 4. Behaviour

### 4.1 Varnode

Fields (read, varnode.hh:136–157), pointers replaced by ids: `flags` (32
bits, every bit defined, varnode.hh:79–115: `mark` 0x01 … `proto_partial`
0x80000000), `addlflags` (16 bits stored, values `activeheritage` 0x01 …
`has_implied_field` 0x2000), `size` (`int4`), `create_index` (`uint4`),
`mergegroup` (`int2`), `loc` (`bk_core::Address`), `def: Option<OpId>`,
`high: Option<HighId>`, `mapentry: Option<SymbolEntryRef>` (D06's entry,
named in dumps `s<symbol id>:<position>`), `ty: Option<TypeId>`, the
reader list, `cover` (built on demand, `coverdirty`), a scratch slot
(Ghidra's union of temporary type and value set, varnode.hh:152–155),
`consumed`, `nzm`. Every flag keeps its numeric value (dumps print the
words in hex); the symbol-related bits are shared with D06 (decomp-symbols
open item 10.1).

* **State**: exactly one of free, input, written. Constants (`constant`)
  and annotations (`annotation`) are free.
* **Readers** (`descend`, a list): `addDescend` appends, but for a free
  varnode that is not `spacebase` and already has a reader it is the error
  `Free varnode has multiple descendants` (varnode.cc:330–340);
  `eraseDescend` removes the first occurrence (Ghidra walks off the list
  when the op is absent — undefined; Basilisk returns an error). Both set
  `coverdirty`. The order is observable — rules walk it — and is dumped.
* **Special offsets.** Ghidra stores host pointers in three kinds of
  varnode offset (D00 4.3): an `iop` varnode's offset is the `PcodeOp *`
  it names, an `fspec` varnode's the `FuncCallSpecs *`, and the first
  input of `LOAD`/`STORE` is a constant of pointer size whose offset (and
  `nzm`) is an `AddrSpace *`. In Basilisk the stored offset is the
  `OpId`, the `CallSpecId` or the space index; their size is 8 on every
  host (Ghidra: `sizeof(pointer)`, 8 on both reference hosts). Ordering
  and dumps use D00's canonical keys (4.2, 4.8).
* Queries to port on the store: the flag getters, `getDef`,
  `loneDescend`, `hasNoDescend`, `isHeritageKnown`, `overlap` (three
  forms), `overlapJoin`, `intersects`, `contains`, `characterizeOverlap`,
  `termOrder`, `getUsePoint`, `getLocalType`'s storage-only part,
  `copySymbol`, `copySymbolIfValid`, `isConstantExtended`,
  `isEventualConstant`, `findSubpieceShadow`, `findPieceShadow`,
  `partialCopyShadow`, `printRaw`, `printRawNoMarkup`, `printInfo`,
  `printCover`. Those that need a type factory, a symbol or a high
  variable take them as arguments or are left to the crate that has them;
  the status report lists which.

### 4.2 The varnode bank (read, varnode.cc:30–79, 1219–1440)

Two ordered sets over all varnodes of a function. With `class(v)` = its
`input|written` bits (`input` 0x08, `written` 0x10) and classes compared
as `(class - 1)` in 32-bit unsigned arithmetic — so input < written <
free (0 − 1 wraps to the largest):

* **loc order** (`VarnodeCompareLocDef`): address, size, class; then for
  written varnodes the defining op's `SeqNum` (address, then time); for
  free varnodes `create_index`; otherwise equal (two inputs of one address
  and size are the same varnode).
* **def order** (`VarnodeCompareDefLoc`): class; then for written
  varnodes the defining op's `SeqNum`; then address, size; then for free
  varnodes `create_index`; otherwise equal.

Addresses compare by space index, then offset (address.hh:413). For the
three pointer-valued kinds (4.1) Ghidra's comparison reads heap
addresses, so its order among those varnodes differs between runs (ran:
D00 R5, GHIDRA-BUGS 27). **Basilisk's keys**: an `iop` offset compares
as its op's `time`, an `fspec` offset as its `CallSpecId` (creation
order), a space constant as its space index. The **dump writer** (4.8)
orders with D00's canonical keys — op time, call-spec position in `qlst`
at the time of writing (a call spec no longer in `qlst` sorting last,
written `call:-`), space index — which differ from the internal keys only
in the order of `fspec` varnodes when `qlst` has been re-sorted; the
writer sorts for output and the internal sets are not re-keyed. No pass is
known to iterate a bank range over these varnodes in a way that reaches
output (D00 open item 4).

Bank operations and their errors (read):

* `create(size, addr, type)`: new free varnode, `create_index` from the
  counter. `createUnique(size, type)`: at `unique:uniqid`, `uniqid +=
  size`. `uniqbase` = the translator's `getUniqueStart(ANALYSIS)`;
  `clear` resets `uniqid = uniqbase`, `create_index = 0`.
* `createDef`/`createDefUnique`: a new varnode already written, through
  `xref`.
* **`xref(vn)`**: insert into loc order; if an equal varnode exists, move
  every reader of `vn` to it (`replace`) and delete `vn` — its
  `create_index` is consumed and never reused — and return the existing
  one; otherwise set the `insert` flag, insert into def order, return
  `vn`. Callers must use the returned id.
* `replace(old, new)`: for each reader of `old` in order, except an op
  whose output is `new` (it cannot read its own output), move the reader:
  erase from `old`'s list, clear the slot, `new.addDescend(op)`, set the
  slot; both get `coverdirty`.
* `setInput(vn)`: errors `Making input out of varnode which is not free`,
  `Making input out of constant varnode`; set `input`, then `xref`.
* `setDef(vn, op)`: error `Defining varnode which is not free at
  <shortcut><addr of op>`; set the def, then `xref`.
* `makeFree(vn)`: out of both sets, def cleared, `insert`, `input`,
  `indirect_creation` cleared, back in.
* `destroy(vn)`: error `Deleting integrated varnode` if it has a def or
  readers.
* Range queries: `beginLoc`/`endLoc` in their forms (all; by space; by
  address; by address and size; by address, size and class or defining
  point), `beginDef`/`endDef` (by class; by class and address), `find`,
  `findInput`, `findCoveredInput`, `findCoveringInput`,
  `hasInputIntersection`, `overlapLoc`, `numVarnodes`.

Iteration during mutation: every Ghidra loop that walks a bank range
while creating or destroying varnodes advances its iterator before the
body touches the set (`clearDeadVarnodes`, funcdata_varnode.cc:860).
Offer cursors that hold a key and step to its successor, so the same
loops are expressible without borrowing the bank across the body.

### 4.3 PcodeOp and the op bank (read, op.hh, op.cc:940–1300)

Fields: opcode (`bk_pcode::OpCode`), `flags` (32 bits, op.hh:72–106:
`startbasic` 0x1 … `indirect_store` 0x80000000), `addlflags`
(op.hh:108–121), `start: SeqNum` (instruction address, `time` unique per
function, `order` within the block), `parent: Option<BlockId>`, list
links, `output`, inputs (inline storage for up to three, spilling).

* **Alive, dead, retired.** `create(inputs, pc)` takes the next `time`,
  puts the op in `optree` and at the end of the dead list, flagged
  `dead`. `create(inputs, seq)` uses the given `SeqNum` and raises the
  time counter past it. `markAlive` moves it to the end of the alive
  list, `markDead` back to the end of the dead list. `destroy(op)` (error
  `Deleting integrated op` unless dead) removes it from its tree, the dead
  list and its category list and appends it to `deadandgone`; a retired
  op's slot and `time` are never reused until the function is cleared.
* **Two trees.** `optree` (by `SeqNum`; the iteration order of every rule
  pool) and **`alttree`**, the quarantined `INDIRECT`s:
  `createIndirect` (used by `Funcdata::newIndirect`, which every
  `INDIRECT` the engine creates goes through: funcdata_op.cc:343, 704,
  729; coreaction.cc:1561; constseq.cc:456, 912; double.cc:1367;
  ruleaction.cc:1001; transform.cc:233) puts the op in `alttree`.
  `changeOpcode` of an op whose *current* opcode is `INDIRECT` moves it
  from `alttree` to `optree` (op.cc:1069–1074) — including a change to
  `INDIRECT` itself after the first assignment; the first assignment (from
  no opcode) does not move it. `destroy` erases from `alttree` if the op
  is `INDIRECT` now, else from `optree` (op.cc:1052–1056): an op in
  `optree` whose opcode is `INDIRECT` would leave a stale `optree` entry —
  no code path creates one today (latent; GHIDRA-BUGS candidate in the
  track report). `beginIndirect(addr)`/`endIndirect(addr)` walk
  `alttree` (used by `Funcdata::listOps`, funcdata_op.cc:981). D00 dumps
  both trees and marks each op `main`/`alt`.
* **Lists** (`std::list`, removal O(1) through iterators stored in the
  op): `alivelist`, `deadlist`, and the category lists `storelist`,
  `loadlist`, `returnlist`, `useroplist` (`CALLOTHER`), maintained by
  `changeOpcode` (`removeFromCodeList`, `addToCodeList`); `deadandgone`.
* `insertAfterDead(op, prev)` (both dead), `moveSequenceDead(first, last,
  prev)` (splice within the dead list), `markIncidentalCopy(first, last)`;
  `target(addr)`, `findOp`, `fallthru`; `begin(addr)`/`end(addr)`,
  `beginAlive`, `beginDead`, `begin(opcode)`.
* **`PcodeOp::setOpcode`** (op.cc:299): clears `branch | call | coderef |
  commutative | returns | nocollapse | marker | booloutput | unary |
  binary | ternary | special | has_callspec | return_copy` and ORs in the
  new `TypeOp`'s flags; other bits stay.
* **Order within a block** (`BlockBasic::insert`, block.cc:2276–2307):
  `ordbefore` = 2 when inserted first, else the previous op's order;
  `ordafter` = the next op's order, or `ordbefore + 0x1000000` at the end
  (saturating to `0xffffffff` on 32-bit overflow); if `ordafter -
  ordbefore <= 1` (unsigned) the block is renumbered (`setOrder`: `step =
  0xffffffff / n - 1`, orders `step, 2*step, …`), else the op gets
  `ordafter/2 + ordbefore/2` (integer halves, block.cc:2301). Inserting a
  `BRANCHIND` sets the block's `f_switch_out`. `startbasic` is **not**
  maintained by insertion (flow sets it, flow.cc:266–329;
  `funcdata_block.cc` clears it, 949).
* Queries: `getEvalType`, `getHaltType`, the flag getters, `getSlot`,
  `getRepeatSlot`, `isCseMatch`, `isCollapsible`, `isMoveable`,
  `nextOp`, `previousOp`, `target`, `getNZMaskLocal`, `compareOrder`,
  `printRaw`, `printDebug`, `getOpName`, `collapse`,
  `collapseConstantSymbol`, `getOpFromConst` (an `iop` varnode's op) —
  the full list from the class declaration; those that need `TypeOp`
  behaviour beyond the property word go to D08 and are listed in the
  status report.
* `PieceNode` (`isLeaf`, `findRoot`, `gatherPieces`) is here: it reads
  only ops and varnodes.

### 4.4 Basic blocks and covers

A basic block is a `bk-decomp-cfg` node (`NodeId`; Ghidra's block index
is `Cfg::index`, the name `b<index>` in dumps) plus, in this crate, its
op list (in `order`), the owning function and its address ranges
(`RangeList cover`: `setInitialRange`, `copyRange`, `mergeRange`). The
graph, edges, flags, dominators and the hierarchy are `bk-decomp-cfg`'s
(decomp-cfg.md 3); this crate keeps a side table `NodeId → BasicData`.

Port from `BlockBasic` (block.hh:470–531): `insert`, `removeOp`,
`setOrder`, `beginOp`/`endOp`, `firstOp`, `lastOp`, `getEntryAddr`
(block.cc:2320), `getStart`, `getStop`, `contains`, `unblockedMulti`,
`hasNoImmediateCopy`, `hasOnlyMarkers`, `isDoNothing`,
`noInterveningStatement`, `findMultiequal`, `earliestUse`,
`liftVerifyUnroll`, `printHeader`, `printRaw`, `printRawImpliedGoto`,
`encodeBody`/`decodeBody` (the ranges), and the facts:

* `complex` = `BlockBasic::isComplex` (block.cc:2417), which counts
  statements from ops and readers with the architecture's
  `max_implied_ref` (a parameter);
* `switch_out` = the block's `f_switch_out` flag;
* `ends_in_return` = `lastOp()` exists and is `RETURN`;
* `negation_changes_dataflow` = `true` for a basic block.

`block_facts(&Ssa, max_implied_ref) -> bk_decomp_cfg::BlockFacts` builds
them for every block in `Cfg` node order. `negateCondition`'s op half
(flip `boolean_flip` and `fallthru_true` on the `CBRANCH`; the edge swap
is `Cfg::swap_out_edges`) is the mutation `op_negate_condition` (4.5);
D15 applies the structurer's flips with it (decomp-cfg.md 4.5).
`flipInPlaceTest/Execute`, `getSplitPoint`, `finalTransform` are D15's.

`Cover` (cover.hh): per block index, the range of ops over which a
varnode is live; a `CoverBlock`'s start and stop are ops with the special
values "beginning" (0), "end" (1) and "input" (2), compared by
`getUIndex` (0 for the beginning, inputs and `MULTIEQUAL`s; the op's
`order` otherwise, with `INDIRECT`s placed at their target, cover.cc:29).
`addDefPoint`, `addRefPoint` (walks predecessors until the definition;
through a `MULTIEQUAL` only the matching edges), `intersect`,
`intersectByBlock`, `intersectList`, `intersect(PcodeOpSet)`, `contain`,
`containVarnodeDef`, `merge`, `rebuild`, `compareTo`, `print`.
`PcodeOpSet` is the abstract sorted op set covers are tested against;
`finalize` sorts with `compareByBlock` (block index, then `order`;
cover.cc:630) — classified for ADR-040 (`sorts.md`): ties only between an
op and itself, so the unstable sort cannot reorder anything observable.

### 4.5 The mutation interface (ADR-025 3a)

All structural change goes through methods on one type (`Ssa`, the IR of
one function), named after `Funcdata`'s. Several `Funcdata` methods also
consult state this crate does not hold; those steps go through a hook
trait implemented by D07's function state, called at exactly the point
Ghidra calls the corresponding code:

```rust
pub trait FunctionEnv {
    fn default_type(&self, size: i32) -> TypeId;                 // getBase(size, TYPE_UNKNOWN)
    fn code_type(&self) -> TypeId;                               // getTypeCode
    fn symbol_properties(&self, addr: Address, size: i32, use_point: Option<Address>)
        -> PropertiesAnswer;                                      // localmap->queryProperties (D06)
    fn after_create(&mut self, ssa: &mut Ssa, vn: VarnodeId);    // assignHigh (when highlevel_on), checkForLanedRegister
    fn wrapping_address(&self, addr: Address, size: i32) -> Address; // constructWrappingAddress when !isValidRange
    fn input_effect(&self, addr: Address, size: i32) -> EffectType;  // funcp.hasEffect (bk-cspec)
    fn cover_on(&self) -> bool;                                  // isHighOn (calcCover in setVarnodeProperties)
}
```

`PropertiesAnswer` is either an entry (whose `setSymbolProperties` the
IR applies through its annotation setters) or plain flags (applied
without `typelock`). D05's tests implement the trait with a table.

Methods and their exact semantics (read, funcdata_op.cc, funcdata_varnode.cc):

* `new_op(inputs, addr)` / `new_op_at(inputs, seq)`: `PcodeOpBank::create`.
  `new_indirect(target)`: `createIndirect` at the target's address,
  opcode `INDIRECT`, input 1 = `new_varnode_iop(target)`.
* `op_set_opcode`: `changeOpcode` (4.3).
* `op_mark_halt(op, flag)`: only on `RETURN` (`Only RETURN pcode ops can
  be marked as halt`); flag masked to `halt | badinstruction |
  unimplemented | noreturn | missing` (`Bad halt flag` when 0).
* `op_set_output(op, vn)`: no-op if already; unset the op's current
  output; if `vn` is another op's output, unset that op's output first;
  `vn = setDef(vn, op)` (may return another varnode, 4.2);
  `set_varnode_properties(vn)` (below); set the op's output.
* `op_unset_output(op)`: clear the op's output, `makeFree`, clear the
  cover.
* `op_set_input(op, vn, slot)`: no-op if already in the slot; a constant
  that already has a reader and is not `spacebase` is replaced by a new
  constant of the same size and value with its symbol copied; unset the
  old input; `addDescend` **before** writing the slot.
* `op_unset_input(op, slot)`: `eraseDescend` then clear the slot.
* `op_swap_input`, `op_set_all_input` (unset all, resize, set each),
  `op_remove_input`, `op_insert_input`.
* `op_insert(op, block, position)`: `markAlive`, `BlockBasic::insert`.
  `op_uninsert`: `markDead`, `removeOp`.
* `op_insert_before(op, follow)`: unless `op` is `INDIRECT`, step back
  over any `INDIRECT`s immediately before `follow`.
  `op_insert_after(op, prev)`: if `prev` is an `INDIRECT` whose `iop`
  input names a live op, insert after that op instead; unless `op` is
  `MULTIEQUAL`, step over `MULTIEQUAL`s after the point.
  `op_insert_begin(op, block)`: after the leading `MULTIEQUAL`s unless
  `op` is one. `op_insert_end(op, block)`: before the last op if that op
  is a flow break.
* `op_unlink`: unset output, unset every input, uninsert if in a block.
* `op_destroy`: destroy the output varnode, unset every input, and if in
  a block `markDead` and remove — not retired. `op_destroy_recursive(op)`:
  breadth-first over inputs that are written, not auto-live, have a lone
  reader, and whose def is neither a call nor an indirect source
  (funcdata_op.cc:228). `op_destroy_raw`: destroy every input and the
  output varnode, then `PcodeOpBank::destroy` (retire).
* `clone_op(op, seq)`: new op at `seq`, same opcode, `startmark |
  startbasic` copied, output and inputs cloned (`clone_varnode`).
  `new_op_before(follow, opc, in1, in2, in3)`: a new unique output of
  `in1`'s size, inserted before `follow`.
* `new_indirect_op(effect, addr, size, extra_flags)` and
  `new_indirect_creation(effect, addr, size, possible_out)` as
  funcdata_op.cc:697–744 (input from `new_varnode` or a zero constant,
  output from `new_varnode_out`, `indirect_creation` marks, inserted
  before `effect`); `mark_indirect_creation` (error `Indirect creation not
  properly formed` when input 0 is not a constant).
* `op_negate_condition(op)`: the op half of `BlockBasic::negateCondition`
  (4.4).
* Varnodes: `new_constant(size, val)` (type `default_type`, then
  `after_create`); `new_unique(size, ty)`; `new_varnode(size, addr, ty)`
  (wrapping address when the range is invalid; `after_create`;
  `symbol_properties(addr, size, none)`); `new_varnode_out(size, addr,
  op)` (`createDef`, set the op's output, `after_create`,
  `symbol_properties(addr, size, op address)`); `new_unique_out`;
  `new_varnode_iop(op)`, `new_varnode_space(space)`,
  `new_varnode_callspecs(fc)` (size 8, 4.1); `new_coderef(addr)` (size
  1, `code_type`, `annotation`); `clone_varnode(vn)` (copies only
  `annotation | externref | readonly | persist | addrtied | addrforce |
  indirect_creation | incidental_copy | volatil | mapped`);
  `destroy_varnode(vn)` (clears every reader's slot without touching the
  readers' lists, detaches the def, empties the reader list, `destroy`);
  `set_input_varnode(vn)` (an existing input overlapping it: the same
  storage returns that input, otherwise `Overlapping input varnodes`;
  `setInput`; `set_varnode_properties`; `input_effect` → `unaffected`,
  and `return_address` for a return-address effect);
  `set_varnode_properties(vn)` (if not `mapped`: `symbol_properties(addr,
  size, use point)`; compute the cover when `cover_on`);
  `total_replace(vn, new)`, `total_replace_constant(vn, val)` (markers
  get one `COPY` of the constant, after `vn`'s def or at the start of
  block 0); `clear_dead_varnodes` (in loc order: an unread input that is
  not `locked_input` becomes free; an unread free varnode is destroyed).
* Annotations: setters for every flag bit Ghidra exposes a public setter
  for (on `PcodeOp` and `Varnode`, from the class declarations),
  `update_type`, `set_consume`, `set_nzm`, `set_high`,
  `set_symbol_entry`, merge group.
* No method leaves the indexes inconsistent on error: checks first, then
  changes.

**Recorder.** The interface owns an optional `&mut dyn Recorder`. Each
method that Ghidra instruments calls `recorder.op_changing(op)` before
changing the op — Ghidra's `debugModCheck`, which `funcdata_op.cc` calls
at 12 places (`opSetOpcode`, `opUnsetOutput`, `opSetOutput`,
`opSetInput`, `opSwapInput`, `opInsert`, `opUninsert`, `opUnlink`,
`opDestroy`, `opSetAllInput`, `opRemoveInput`, `opInsertInput`) and
`funcdata_varnode.cc` once (`destroyVarnode`, for each reader) — and the
driver brackets a unit with `begin_unit(UnitId)` and `end_unit()`
(`debugActivate`, `debugModPrint`). The recorder decides what to keep:
Ghidra's trace keeps the before-text of each touched op and prints it with
the after-text at the end of the unit (D00 4.9: `DEBUG <n>: <name>`, then
per op `<seqnum>: <text or **>` and the after-text indented three
spaces); a provenance recorder keeps `(unit, op)` pairs. With no recorder
attached the cost is one branch. The crate provides the **trace
recorder**, which reproduces Ghidra's records exactly, including the
address-range filter (`debugSetRange`, `debugCheckRange`) and the rule
that a unit which touched nothing prints nothing.

**Evaluation.** At every unit boundary each live op has a defined
meaning, which this crate documents and exposes as data (the evaluator
that runs a function is D07's):

* ordinary ops: `bk_pcode::behavior` on the input values;
* `MULTIEQUAL`: the input whose slot is the index of the block in-edge
  control arrived by;
* `INDIRECT`: input 0 unless the op named by the `iop` input (a call or
  store) changes that storage, in which case the value the environment
  reports for the storage after that op; with `indirect_creation`, the
  value the environment reports;
* a **free** varnode denotes its storage (the latest value written to
  that address by an executed op), an input varnode its value at entry,
  a written varnode the value its defining op produced;
* `COPY`, `PTRADD` (`in0 + in1 * in2`), `PTRSUB` (`in0 + in1`), `PIECE`,
  `SUBPIECE`, `INSERT`, `ZPULL`, `SPULL` are ordinary; `CAST` is a copy
  although Ghidra flags it `special`. Ghidra sets `special` on 15 opcodes
  (`grep -c 'PcodeOp::special' typeop.cc`); apart from `MULTIEQUAL`,
  `INDIRECT` (above) and `CAST`, they — the branches, calls, `RETURN`,
  `LOAD`, `STORE`, `SEGMENTOP`, `NEW`, `CPOOLREF` — need the environment
  (take the exact set from the property table).

Provide `op_semantics(op) -> Semantics` classifying each op this way,
total over the 73 opcodes.

### 4.6 Per-opcode properties

One static table: opcode → property word (the `PcodeOp` flag bits the
`TypeOp` constructors pass as `opflags`: `unary`, `binary`, `special`,
`ternary`, `branch`, `call`, `returns`, `marker`, `booloutput`,
`commutative`, `coderef`, `nocollapse`, `has_callspec`, …), the name
`print raw` uses, and the `TypeOp` `addlflags` (`inherits_sign` 1,
`inherits_sign_zero` 2, `shift_op` 4, `arithmetic_op` 8, `logical_op`
0x10, `floatingpoint_op` 0x20, `boolean_reorder` 0x40; typeop.hh:41–49).
There are 73 opcodes (`CPUI_MAX` is 75; the values have gaps), each
registered once in `TypeOp::registerInstructions` (73 `inst[CPUI_…]`
lines; 74 `TypeOp…::TypeOp…` constructor definitions in typeop.cc,
counted with `grep -c '^TypeOp[A-Za-z0-9]*::TypeOp'`). Generate the table
by reading them; test it against a table the oracle dumps
(`glb->inst[opc]->getFlags()`, `getName()` and the `addlflags` for every
opcode, written with a small generator in the style of
`docs/research/decomp-wave2/build.sh`).

### 4.7 Text dumps

* `Varnode::printRaw` (varnode.cc:742): the storage form
  (`printRawNoMarkup`: register name, `u0x…`, `#0x…`, `s0x…`), `:<size>`
  when the size differs from the one the form implies, `(i)` for an input,
  `(<def seqnum>)` for a written varnode, and `(free)` when neither
  `insert` nor `constant` is set.
* `print raw` (`Funcdata::printRaw`): per block `BlockBasic::printRaw`
  (header `Basic Block <i> <start>-<stop>`, op lines `<addr>:<time
  hex>:\t<printRaw>`, implied gotos `<addr>:   \t[ goto Block_<j>:<addr>
  ]`), or the ops in `SeqNum` order when there are no blocks; the
  expression of each op by its `TypeOp::printRaw` form.
* `printVarnodeTree` (`print tree varnode`): each varnode in def order
  with `Varnode::printInfo`'s flags and `(consumed=…)`, `(internal=…)`,
  `(create=…)`. Ghidra's text carries host pointers and their order
  (plan amendment 4): **comparisons use the state dump**; the text is
  produced (without `internal=`) for people and for D09's console.
* D00's `@ops` records carry each op's `print raw` text: the loaded
  state's `print_raw` of every op must equal it.

### 4.8 State load and dump (D00's `bkstate` version 1)

Load and write, through `bk-testkit`'s `oracle::state` types, the
sections this crate holds:

* `@function`: the `K` record — next create index, `uniqbase`, next
  unique offset, next op time — so that anything created after loading
  gets the numbers Ghidra would give;
* `@spaces` (read, to resolve names and canonical keys);
* `@varnodes` (every field but `high` and the symbol entry, which are
  carried as opaque references for D14 and D06/D07), `@locorder`,
  `@deforder` (loaded as given; written by sorting with the canonical
  keys of 4.2);
* `@ops` (both trees, `main`/`alt`, `alive`/`dead`), `@oplists`;
* `@blocks`: each block's ops in order and its cover ranges (the graph
  part — flags, immediate dominator, `numdesc`, in-edges with labels —
  goes into `bk-decomp-cfg`'s `Cfg`).

Every other section (`@actions`, `@structure`, `@proto`, `@callspecs`,
`@jumptables`, `@scope`, `@heritage`, `@highs`, `@types`, `@c`, and the
`W`, `O`, `X`, `U` records of `@function`) is passed through unchanged
until the crate that owns it exists, so the round trip is byte-exact from
the first day. Pointer-valued offsets load from `op:<seqnum>`,
`call:c<k>` / `call:-` and `space:<name>`; a space constant's `nzm` is
written as its key (D00). Fields Ghidra leaves uninitialised are written
`-` by D00 and kept as "absent".

### 4.9 Units (ADR-025 item 1)

Pure data, here because the recorder names units:

* `Origin`: `Ghidra`, `Basilisk`.
* `UnitKind`: `Action`, `Rule`, `MergePass`, `StructureStep`,
  `OutputPass`.
* `Soundness`: `Exact`, or `Assumes(AssumptionId)` with a registry of
  named assumptions (`no-nan`, `readonly-memory-constant`,
  `prototype-effects`, `dead-by-consume`, …) — what the stage-equivalence
  check uses to qualify a comparison (plan 9.1, ADR-028).
* `UnitInfo { name, origin, group, kind, opcodes (rules only), soundness
  }`; names and groups are Ghidra's strings (inventory 5.2 and 6),
  interned.
* `UnitTable`: built once from the `&'static [UnitInfo]` slices each
  pass crate exports, giving `UnitId(u16)`; lookup by name; duplicate
  names of the same kind and origin are an error. The `decompile` root
  contains seven names twice — `blockstructure`, `deadcode`,
  `directwrite`, `dynamicsymbols`, `prefercomplement`,
  `structuretransform`, `unreachable` (ran, W5: `bk list actions` on
  `elseif.xml`, 243 lines): a unit is the action; its *placements*
  (position, group, constructor argument) belong to a profile, and the
  duplicated ones are addressed by position (plan amendment 2).
* A `Profile` (the arrangement of placements into Ghidra's nested groups
  and pools, and the builder that turns it into a pipeline) is D07's;
  this crate defines only the table it is built from and a consistency
  check: the Ghidra-origin units of a table can be compared with a
  checked-in list of the 161 rule names and 71 action names with their
  groups (ADR-026's counts), generated from inventory 5.2 and 6. The
  structurer's unit names are `bk-decomp-cfg`'s constants (`selectgoto`,
  `blockgoto`, …; decomp-cfg.md 5).

## 5. Design

* **Storage** (ADR-012): arenas `Vec<VarnodeData>`, `Vec<OpData>` indexed
  by `VarnodeId(u32)`, `OpId(u32)`; ids are never reused within a
  function; hot fields (flags, opcode, sizes, inputs) packed first and
  the struct sizes asserted in a test (targets: op ≤ 64 bytes with three
  inline inputs, varnode ≤ 96 bytes). Whether a field lives in the
  struct or a parallel array is private: all access is through methods.
  `VarnodeId` is not Ghidra's `create_index` (an `xref` merge consumes an
  index without a surviving varnode); the dump names varnodes by
  `create_index`, kept as a field, with a map to ids.
* **Ordered sets**: `BTreeSet` over explicit key structs (`LocKey`,
  `DefKey` with the internal keys of 4.2; `SeqNum` for the op trees)
  first; they are correct by construction and the dumps test them.
  Replace by something faster only on benchmark evidence. Reader lists: a
  small inline vector of `OpId` per varnode, order-preserving removal of
  the first match.
* **Intrusive lists** (block op list, alive/dead, per-category,
  `deadandgone`): `prev`/`next` `OpId` fields in the op and a head/tail
  per list. Removal O(1), no allocation, no dangling: a link is an index
  and liveness is a flag.
* **Borrowing.** Passes hold `&mut Ssa` and ids. Queries return copies of
  small values or short-lived references; iteration over anything that
  the body may change uses cursors (`let mut c = ssa.ops_from(seq);
  while let Some(op) = c.next(&ssa) { … ssa.op_destroy(op)?; }`).
  Stale ids are detected in debug builds by a "retired" check and are an
  error value, never undefined behaviour (ADR-020: no `unsafe`).
* **Per function, no globals.** An `Ssa` owns everything of one function
  and is `Send`; program-wide data (spaces, types, registers) is
  borrowed per call or reached through `FunctionEnv`. Join-space offsets a
  function creates go through a per-function table (plan 3 item 7).
* **Errors**: `IrError` (`thiserror`), with Ghidra's messages where Ghidra
  has one (4.2, 4.3, 4.5) and for what Ghidra assumes (slot in range, op
  alive where required, a reader present before erasing it) an error
  naming the method and the ids.
* **Modules**: `ids`, `varnode/{data, flags, query, shadow, print}`,
  `bank/{loc, def, alloc, cursor}`, `op/{data, flags, query, print,
  piece}`, `opbank/{trees, lists, cursor}`, `block/{basic, order, facts}`,
  `cover/{block, cover, opset}`, `mutate/{op, insert, varnode, annotate,
  env}`, `record/{recorder, trace}`, `semantics`, `props` (the opcode
  table), `dump/{raw, tree}`, `state/{load, write, keys}`, `unit`,
  `error`. Every file under 600 lines.
* ADR-011: arena crates (`slotmap`, `typed-arena`, `la-arena`,
  `index_vec`/`typed-index-collections`) were considered. Ids here must
  never be reused, removal keeps the slot, and the layout must stay free
  to split into parallel arrays — a plain `Vec` with a newtype index does
  all of it; evaluate `typed-index-collections` or `index_vec` for the
  indexing boilerplate and record the outcome. `smallvec` for inline
  inputs and readers. `petgraph` is not suitable for the def-use graph
  (ordered multi-edges with slots, two custom orderings) and is not used.
* **Plugin binding constraints** (ADR-037): engine-internal; rule 4
  (typed errors) and rule 8 (`Recorder` and `FunctionEnv` are object-safe
  traits) apply and hold; results reach plugins through D17, not this
  crate.

## 6. Tests

Kinds: **S** self-contained; **G** needs the spec root; **L** needs the
live reference tools (`decomp-plan.md` 4.5). Every test names the profile
whose state it uses (`ghidra` throughout). Captures come from D00's
capture driver (`bk-oracle capture`, `fixtures/decomp-oracle/`): 167
scripts, 607 decompilations (193 from the data tests, 414 from the
research corpus), byte-identical between runs; the Mac and the build host
differ only in `floatprint` (D00's report).

1. **State round trip** (S for a checked-in subset, L for all): for
   every decompilation of both corpora, dumps at the four standard points,
   found by path from `bk list actions` (D00 4.5): a start breakpoint on
   the action after `universal:start` (`constbase`), the first start of
   `oppool1`, the start of the `cleanup` pool, and `stop` — load and write
   back byte for byte. The checked-in subset is the dumps of 20 functions
   chosen to cover every opcode and every flag bit that occurs in the full
   set (selected mechanically; the list and the selection script are
   checked in), gzip-compressed.
2. **Text** (S): `print_raw` of every op of each loaded state equals the
   `@ops` text; the block-level `print raw` equals the console's captured
   `print raw` at the same point.
3. **Ordering** (S): after loading, iterating loc order, def order, both
   op trees, each block's ops, each list and each varnode's readers
   yields the dump's order; writing reproduces `@locorder`/`@deforder`;
   inserting the same varnodes and ops in shuffled order (property test)
   yields the same orders.
4. **Mutation semantics.** D00 delivered no mutation log (about 60
   non-virtual `Funcdata` methods would need hooks; D00's report), so the
   plan's replay test takes its stated fallback: (a) hand-derived unit
   tests for every method of 4.5, with the expected state written from
   the C++ (each test cites the lines it follows), run against a table
   `FunctionEnv`; (b) **re-dump tests**: wherever two consecutive standard
   dumps of a function differ only by ops and varnodes, the differences
   are re-derived by the method sequence the trace names (test 5's
   records give the units and the touched ops) — kept as a diagnostic, not
   an acceptance gate; (c) properties (test 6). D07's rule drivers replay
   whole passes later (D07, R1–R9 acceptance).
5. **Trace recorder** (S): unit tests on synthetic edit sequences against
   the record grammar of D00 4.9 and the range filter; (L) once D07 runs
   units, its runs compared with `decomp_bk_dbg`'s trace.
6. **Properties** (`proptest`, S): random sequences of valid mutations
   keep the invariants — every reader list matches the ops' inputs, each
   written varnode's `def` has it as output, set keys match fields, a free
   non-spacebase varnode has at most one reader, alive ops are in exactly
   one block list, `order` increases along each block, `alttree` holds
   only ops created by `new_indirect` whose opcode was never changed;
   dump → load → dump is the identity on any reachable state; invalid
   calls return errors and change nothing.
7. **Opcode properties** (S): the table against the oracle's dump of
   `TypeOp` flags, `addlflags` and names for the 73 opcodes;
   `op_semantics` total.
8. **Covers** (S, L): for loaded final states, the cover of a sample of
   varnodes per function printed (`printCover`) equals the console's
   `print cover varnode` output for them (captured, L; checked-in subset
   S).
9. **Block facts** (S): `block_facts` of the loaded states before each
   structuring run equal the facts D00's `bk dump blocks` writes at the
   same point (decomp-cfg.md 6.3's corpus graphs).
10. **Unit table** (S): Ghidra-origin names and groups equal the
    generated list; building with a duplicate or unknown name fails.
11. **Fuzz target** `bk_decomp_ir_state` (load arbitrary dump text; no
    panic; whatever loads writes back and reloads to the same state).
12. **Benchmarks**: load of the largest dump; create/insert/destroy of
    one million ops; a full walk of the op tree with a rule-like body
    that inserts and deletes; bytes per op and per varnode. Numbers in
    `PERF.md`, with the reference console's time to reach the same break
    point beside them.

## 7. Acceptance

1. Round trip (test 1) is byte-exact for the checked-in subset on
   Windows, macOS and Linux (S), and for all 607 decompilations at the
   four points where the reference tools are present (L); any that does
   not round-trip is listed with the first differing line.
2. Tests 2, 3, 7, 9 pass.
3. Test 4's fallback (a) covers every method of 4.5, each with the C++
   lines it follows; the D00 limitation is recorded.
4. The trace recorder reproduces the record grammar and filter (test 5,
   S part).
5. No structural field of an op or varnode can be changed except through
   the mutation interface: the data structs' fields are private to the
   crate and the public API has no other `&mut` path (reviewed, and
   enforced by the module boundary).
6. The unit table's data model exists with test 10; `Soundness` is a
   field of `UnitInfo`.
7. Size assertions and benchmarks recorded; no `unsafe`; no panic on any
   dump text (fuzz 300 s on the build host); gate green on both remote
   runs; files within the size limit; public items documented with the
   Ghidra member they correspond to.

## 8. Differences from Ghidra

- Ids instead of pointers; `iop`, `fspec` and space-constant offsets are
  ids and their varnodes are 8 bytes on every host; the bank orders among
  them use reproducible keys (4.2); no `internal=` in text.
- `eraseDescend` of an absent op and the other paths where Ghidra reads
  past a container are errors.
- The debug trace is always available (a recorder), not a build option.
- `Funcdata`'s graph part is a separate value (`Ssa`); the rest of
  `Funcdata` is in `bk-decomp-core`, reached through `FunctionEnv`.
- Units, origins and soundness have no Ghidra counterpart beyond name
  and group.

(The implementing agent appends further differences here.)

Appended by D05 (2026-11-16):

- Checks come before changes. Where Ghidra changes state and then throws
  (`markIndirectCreation` sets the op flag before it finds input 0 is not
  a constant, `funcdata_op.cc:751`; `opSetInput` unsets the old input before
  `addDescend` throws for a free varnode with a reader, `varnode.cc:336`),
  Basilisk refuses first and changes nothing. Duplicate sequence numbers
  (`newOp(inputs, seq)`), an empty slot in `opUnsetInput`, a slot out of
  range and a stale id are errors; null slots in `opUnlink`/`opDestroyRaw`
  are skipped.
- `BlockBasic::setOrder` divides by the op count (`block.cc:2707`); on an
  empty block Basilisk does nothing.
- `BlockBasic::insert` (`block.cc:2298`–`2301`) can give an op the same
  `order` as its predecessor (`ordafter/2 + ordbefore/2` loses one when
  both are odd and two apart: every op appended after order 0xfffffffd
  gets 0xfffffffd; the corpus has it, `divopt`). Basilisk keeps Ghidra's
  numbering, so orders along a block are non-decreasing, not increasing.
- `load` refuses a dump whose state breaks the IR's invariants (a written
  varnode without a def, reader lists that disagree with the ops, …;
  `Ssa::invariant_violations`); Ghidra never reads such a state.
- Join records: a version-2 dump does not carry them, so a loaded state
  prints a join varnode as `{unlinked:0x…}`; `state::install_joins` replays
  them once the dump carries Ghidra's `splitlist` (see the status report).
- Spec 6 test 6's invariant "a free non-spacebase varnode has at most one
  reader" is not one of Ghidra's: `opUnsetOutput` frees a varnode whatever
  its readers (`funcdata_op.cc:52`); only adding a reader checks it
  (`varnode.cc:330`). It is not asserted.
- Spec 6 test 8's console half cannot run: `print cover varnode <vn>` is
  unreachable in Ghidra's console because `varnode` is a prefix of
  `varnodehigh` and `IfaceStatus::expandCom` (`interface.cc:436`–`475`)
  then reads the varnode as a fourth command word ("Invalid command").
  Covers are tested against `cover.cc` by hand-derived cases instead.

## 9. Status

Done (D05, 2026-11-16) except as listed in `docs/agents/decomp-ir.md`:
the IR, the mutation interface, the state load/dump, `print raw`, covers,
block facts, the unit table, the trace recorder and the opcode table, with
the tests of section 6 (test 8 against `cover.cc` instead of the console;
the 76 corpus dumps whose ops print join varnodes are a pinned exception
until the dump carries join records). Inventory: no Ghidra test in
`docs/inventory/tests/` names this crate's classes alone; the decompiler's
data tests belong to the whole pipeline.

## 10. Open items

1. Which `PcodeOp`/`Varnode` queries need `TypeOp` behaviour or a type
   factory beyond the property word: decided per query by the implementer
   from the class declarations and listed in the status report (4.1,
   4.3).
2. The latent `alttree`/`optree` mismatch of 4.3 (`destroy` by current
   opcode): unreachable today; Basilisk removes an op from the tree it is
   in, which equals Ghidra on every reachable path.
3. Whether `FunctionEnv` should be split into a read-only and a mutable
   part once D07's `Funcdata` exists (D07 decides; the call points of 4.5
   do not change).
