# Types of operations, casts, union resolution (`decomp-typeop`)

Track `decomp-typeop` (D08 of `docs/features/decomp-plan.md`), milestone
M3, wave 3. Format: `docs/LOOP.md`, "Feature documents". Crate:
`bk-decomp-typeop` (new).

**This document is an outline, not yet a contract.** The boundary, the
dependencies and the design decisions that D07 relies on (sections 2, 3,
5) were worked out while specifying D07 and are stated with their
evidence. The behaviour (section 4) was **not read from the source**:
every item there is marked "to be specified" with the files and lines
that define it. A specification pass must complete section 4, and review
sections 6 and 7 against it, before an implementation agent starts.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`UT/` = `…/decompile/unittests/`, under `../ghidra` (commit `42db038f3c`).
**(read)** marks a statement taken from the source (file:line).

## 1. Purpose

What each p-code operation says about data types: the type an operation
gives its output and expects of its inputs, how a type moves across an
operation during propagation, which casts the output language needs, and
which field of a union an operation reads or writes. Passes and the
printer ask these questions; nothing here changes the IR except the
record of resolved union fields.

## 2. Ghidra sources

| Source | Lines | What to take |
|---|---|---|
| `CPP/typeop.hh`, `typeop.cc` | 957 + 2,762 | `TypeOp` and its per-opcode subclasses (74 constructors, 73 opcodes; `decomp-ir.md` 4.6): `getOutputLocal`, `getInputLocal`, `getOutputToken`, `getInputCast`, `propagateType`, `getOperatorName`, the `addlflags` tests, `registerInstructions` (the table), `selectJavaOperators` (115–150). Not: `push` (the printer, D16b), `printRaw` (D05), the opcode property word and boolean flip (D05's table) |
| `CPP/cast.hh`, `cast.cc` | 205 + 546 | `CastStrategy` (11 virtual methods, `cast.hh` 68–157), `CastStrategyC`, `CastStrategyJava` (overrides `castStandard` and `isZextCast`, 198–201) |
| `CPP/unionresolve.hh`, `unionresolve.cc` | 223 + 1,300 | `ResolvedUnion`, `ResolveEdge`, `ScoreUnionFields`, `ResolveCache` |
| `CPP/type.cc` | — | The methods that take a `PcodeOp`: `Datatype::findTruncation` 181, `resolveInFlow` 552, `findResolve` 564, `findCompatibleResolve` 574, `resolveTruncation` 592; `TypePointer` 1226–1260; `TypeArray` 1370–1410; `TypeStruct::findTruncation` 1803, `scoreSingleComponent` 2178, `resolveInFlow` 2214, `findResolve` 2229, `findCompatibleResolve` 2239; `TypeUnion` 2482–2600; `TypePartialUnion` 2843–2960 (`decomp-types.md` 4.8 declares them for this track) |
| `CPP/funcdata.cc` 917–1117 | 200 | The nine union-field methods of `Funcdata`, as the methods of `UnionMap` (read; 4.1) |
| `CPP/varnode.cc` 680–705 | — | `getHighTypeDefFacing`, `getHighTypeReadFacing` (they read the high variable's type and resolve it at the edge) |
| `UT/testtypes.cc` 121–214 | — | `cast_basic` 121, `cast_pointer` 137, `cast_enum` 157, `cast_compare` 165, `cast_integertoken` 204 |

## 3. Scope

**In:** the per-opcode type behaviour as a table of functions; the two
cast strategies; union and structure-field resolution in data-flow; the
union map; the access table's rows at `LOAD`, `STORE`, `PTRADD`,
`PTRSUB` (ADR-025 3e; the table's type is D07's, `decomp-core.md`
4.A.10).

**Crate owned:** `bk-decomp-typeop`. Dependencies: `bk-core`, `bk-pcode`,
`bk-decomp-types`, `bk-decomp-ir`, `bk-cspec` (a prototype's parameters:
`FuncProto`), `bk-decomp-symbols` (`CPoolRecord` for `CPOOLREF`,
`typeop.cc:2585`). **Not `bk-decomp-core`**: the crate is below it
(`docs/agents/spec-decomp-wave3.md`, plan finding 3). What Ghidra's
`TypeOp` reads from `Funcdata` and `Architecture` comes through a trait
this crate defines and D07's function state implements in its step A9:

```rust
pub trait TypeOpEnv {
    /// The call specification's prototype at a CALL or CALLIND
    /// (FuncCallSpecs::getFspecFromConst, Funcdata::getCallSpecs; typeop.cc 693–783).
    fn call_proto(&self, op: OpId) -> Option<&bk_cspec::FuncProto>;
    /// The prototype of the function the op is in (RETURN; typeop.cc 904–915).
    fn function_proto(&self) -> &bk_cspec::FuncProto;
    /// A user op's types and printed name (CALLOTHER; typeop.cc 842–868).
    fn userop_output(&self, ssa: &Ssa, op: OpId) -> Option<TypeId>;
    fn userop_input(&self, ssa: &Ssa, op: OpId, slot: usize) -> Option<TypeId>;
    fn userop_name(&self, ssa: &Ssa, op: OpId) -> Option<&str>;
    /// The type of the varnode's high variable (HighVariable::getType).
    fn high_type(&self, vn: VarnodeId) -> Option<TypeId>;
    fn default_data_space(&self) -> SpaceId;
    fn cpool_record(&self, refs: &[u64]) -> Option<&CPoolRecord>;
}
```

The union map is passed beside it (`&mut UnionMap`), not through the
trait: it is this crate's type and D07's `Funcdata` holds one.

**Not in this track:** `TypeOp::push` and everything of the printer
(D16b); `ActionSetCasts` (D16b, plan row) and `ActionInferTypes` (D11),
which call this crate; the opcode property word, names and the boolean
flip (D05's table, `decomp-ir.md` 4.6); `HighVariable::updateType` (D07,
`decomp-core.md` 4.A.11); user ops' own type answers (D07,
`decomp-core.md` 4.A.9).

Boundary functions by name: `PcodeOp::outputTypeLocal`,
`inputTypeLocal`, `getOpcode()->…` are this crate's free functions over
`(&TypeOps, &Ssa, OpId)`; `Varnode::getHighTypeReadFacing`/`DefFacing`
are this crate's (they need `high_type` and the union map);
`Varnode::updateType` and `getLocalType`'s storage part stay D05's (D05
open item 1: the implementer of D05 lists which queries it left for this
crate).

## 4. Behaviour — to be specified

Nothing below was read to the project's standard. Each item names what
defines it.

1. **The table** (`TypeOp::registerInstructions`, `typeop.cc`, before line 115):
   per opcode, the class and its constructor arguments (name, flags,
   `addlflags`, input and output metatypes for the unary, binary and
   function forms).
2. **`selectJavaOperators`** (read, 115–150): with Java operators,
   `INT_ZEXT` takes input `TYPE_UNKNOWN` and output `TYPE_INT`;
   `INT_NEGATE`, `INT_XOR`, `INT_OR`, `INT_AND`, `INT_RIGHT` take input
   and output `TYPE_INT`, and `INT_RIGHT` prints as `>>>`; without,
   `INT_ZEXT` and `INT_NEGATE` are `TYPE_UINT` in and out (134–137) and
   the rest as lines 138–150 say (not read). So the table is a value
   with a variant, chosen by the print language
   (`architecture.cc:410–433`), not a constant.
3. **Local types** (`getOutputLocal`, `getInputLocal`): the base forms
   (`TypeOp` 163–166 of the header and their bodies; `TypeOpBinary`,
   `TypeOpUnary`, `TypeOpFunc`) and each override; the ones that use the
   environment are `CALL`, `CALLIND`, `CALLOTHER`, `RETURN`, `CPOOLREF`,
   and those that build pointer types in the default data space
   (`typeop.cc` 419, 970, 1459, 1492, 1520, 2098, 2153).
4. **Tokens and casts** (`getOutputToken`, `getInputCast`): per class;
   they read high-variable types at the edge (`getHighTypeReadFacing`,
   `getHighTypeDefFacing`: 43 uses in `typeop.cc`), so they are defined
   only once high variables exist.
5. **Propagation** (`propagateType`, and the static helpers
   `propagateToPointer`, `propagateFromPointer` if present): per class.
6. **Casts** (`cast.cc`): the eleven methods of `CastStrategyC`
   (`localExtensionType`, `intPromotionType`,
   `checkIntPromotionForCompare`, `checkIntPromotionForExtension`,
   `isExtensionCastImplied`, `castStandard`, `arithmeticOutputStandard`,
   `isSubpieceCast`, `isSubpieceCastEndian`, `isSextCast`, `isZextCast`),
   the two Java overrides, the promotion size taken from the data
   organisation (`setTypeFactory`).
7. **Union resolution** (`unionresolve.cc`): `ResolvedUnion`'s three
   constructors, `ResolveEdge`'s key (the type, the op's time or an
   address, the slot — read the comparator for the exact fields and the
   encoding the dump's `U` record shows), `ScoreUnionFields` (its trial
   queue, scoring rules and limits), `ResolveCache`.
8. **The IR-bound type methods** of section 2.
9. **The union map** (read, `funcdata.cc` 917–1117): `getUnionField`
   returns the resolution of an edge only when the resolved type's size
   equals the unresolved type's; `getUnionResolution` returns it
   regardless; `setUnionField` inserts, or updates an unlocked entry
   (returning whether the entry is unlocked when the update is refused),
   and for a `MULTIEQUAL` with a real slot copies the resolution to every
   other slot holding the same varnode; `setAddressBasedUnionField`
   replaces unless locked; `updateUnionField` changes the resolved type
   of an existing entry; `forceFacingType` resolves through a plain
   pointer when the type is a relative pointer; `inheritUnionField` and
   `inheritUnionFieldPtr` copy a resolution from another edge (slot −1
   becomes 0 when the old op is a marker) and return the field number or
   −1. `ResolvedUnion::update` and the lock are item 7's.
10. **Access-table rows** (ADR-025 3e): which calls record a row; no
    Ghidra counterpart; to be designed with item 5.
11. **Order sources and undefined behaviour**: no `std::sort` in
    `typeop.cc`, `cast.cc`, `unionresolve.cc` (`grep`, this track); what
    else depends on the host is unread.

## 5. Design

* `TypeOps`: a value of 75 entries indexed by opcode (enum of behaviour
  kind plus the metatypes and symbol the Java switch changes), `Clone`,
  `Send + Sync`; built by `TypeOps::new(java: bool)`; held by D07's
  `Arch`.
* Behaviour as functions matched on the kind (no trait objects for the
  the classes): `output_local`, `input_local`, `output_token`,
  `input_cast`, `propagate_type`, `operator_name`, each taking
  `(&TypeOps, &Ssa, &mut TypeFactory, &dyn TypeOpEnv, …)`; types a query
  creates land in the function's type fork (`decomp-types.md` 4.10).
* `CastStrategy`: an enum `C | Java` with the eleven functions.
* `UnionMap`: an ordered map from `ResolveEdge` to `ResolvedUnion` with
  the nine methods; cleared by `Funcdata::clear`.
* Tests need no D07: a table-driven `TypeOpEnv` (as D05's `TableEnv`).
* Modules (each under 600 lines): `table`, `java`, `local/{base, memory,
  call, compare, arith, shift, float, piece, pointer, misc}`, `token`,
  `cast_input`, `propagate/{…}`, `cast/{c, java}`, `union/{edge, map,
  score, cache}`, `types_flow` (the `type.cc` methods), `access`, `env`,
  `error`.
* Plugin binding constraints: engine-internal; typed errors; `TypeOpEnv`
  is object-safe.

## 6. Tests (to be confirmed against section 4)

* The five `testtypes.cc` tests (`cast_basic`, `cast_pointer`,
  `cast_enum`, `cast_compare`, `cast_integertoken`; checklist line
  `unittests/testtypes.cc` of `docs/inventory/tests/decompiler-cpp.md`,
  which this track ticks). They build an architecture and decompile
  small functions in Ghidra (`testtypes.cc` 121–214 — unread: whether
  they can be ported with a table environment or need a loaded state
  decides the test's kind).
* **Oracle table** (an oracle addition, to be prototyped by the
  specification pass): a C++ generator in the form of
  `docs/research/decomp-wave3/action_oracle.cc` that, for every opcode
  and a grid of operand types (the base types of each metatype and
  size, pointers to them, an enumeration, a structure, a union, an
  array, `bool`, a code pointer), builds one op over fresh varnodes with
  those types and prints `getOutputLocal`, `getInputLocal` per slot,
  `getOutputToken`, `getInputCast` per slot, and `propagateType` for
  every (input slot, output slot) pair, in both operator variants and
  both cast strategies. Rows carry the types as their `encodeRef` text
  so that the replay needs no spec root.
* The union map against hand-derived cases; `ScoreUnionFields` against a
  table from loaded states (the `U` records of D00's dumps).

## 7. Acceptance (to be confirmed)

The five tests ported; the table replays with every row equal on all
three systems, generated on both reference builds; the `U` records of
the captured dumps round-trip through `UnionMap`; D07's step A9 compiles
against the trait.

## 8. Differences from Ghidra

- The crate sees function state through `TypeOpEnv`; the union map is a
  value of its own.
- Per-opcode behaviour is functions over a table, not a class per opcode.

## 9. Status

Specified in outline only, not implemented: sections 2, 3 and 5 are the
result of the D07 specification; section 4 is to be specified from the
source.
