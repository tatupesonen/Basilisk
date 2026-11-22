# Types of operations, casts, union resolution (`decomp-typeop`)

Track `decomp-typeop` (D08 of `docs/features/decomp-plan.md`), milestone
M3. Format: `docs/LOOP.md`, "Feature documents". Crate:
`bk-decomp-typeop` (new), below `bk-decomp-core` (ADR-060).

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`UT/` = `…/decompile/unittests/`, under `../ghidra` (commit `42db038f3c`).
Marks: **(read)** a statement taken from the source, with file and line;
**(ran, X8)** confirmed by the oracle prototype
`docs/research/decomp-wave3/typeop_oracle.cc`, run on the Mac reference
(libc++, AArch64) and on the build host's (libstdc++, x86-64 Linux) with
byte-identical output (`docs/research/decomp-wave3/runs.md`, X8).
Everything in section 4 was read line by line; a rule without **(ran)**
was read only.

## 1. Purpose

What each p-code operation says about data types: the type an operation
gives its output and expects of its inputs, how a type moves across an
operation during propagation, which casts the output language needs, and
which field of a union an operation reads or writes. Passes and the
printer ask these questions. Nothing here changes the IR; the only state
it owns is the record of resolved union fields and the table of observed
accesses.

## 2. Ghidra sources

| Source | Lines | What is taken |
|---|---|---|
| `CPP/typeop.hh`, `typeop.cc` | 957 + 2,762 | `TypeOp` and its 73 per-opcode classes: `getOutputLocal`, `getInputLocal`, `getOutputToken`, `getInputCast`, `propagateType`, `getOperatorName`, `registerInstructions` (24–109), `selectJavaOperators` (115–148), `floatSignManipulation` (154–177), `propagateToPointer` (187–199), `propagateFromPointer` (207–229), `TypeOpEqual::propagateAcrossCompare` (964–987), `TypeOpIntAdd::propagateAddIn2Out` (1241–1279) and `propagateAddPointer` (1294–1342), `TypeOpFloatInt2Float::absorbZext` (2011–2022) and `preferredZextSize` (2030–2041), the two `computeByteOffsetForComposite` (2243–2253, 2334–2346), `getBooleanFlip` (the constructors). Not: `push` (D16b), `printRaw` (D05), `opflags` and `addlflags` (D05's table), `behave` (`bk-pcode`) |
| `CPP/cast.hh`, `cast.cc` | 205 + 546 | `CastStrategy` (`setTypeFactory`, `markExplicitUnsigned`, `markExplicitLongSize`, `caresAboutCharRepresentation`), `CastStrategyC` (eleven methods), `CastStrategyJava` (`castStandard`, `isZextCast`) |
| `CPP/unionresolve.hh`, `unionresolve.cc` | 223 + 1,300 | `ResolvedUnion`, `ResolveEdge`, `ScoreUnionFields`, `ResolveCache` |
| `CPP/type.cc` | — | The methods that take a `PcodeOp`: `Datatype::findTruncation` 181, `resolveInFlow` 552, `findResolve` 564, `findCompatibleResolve` 574, `resolveTruncation` 592; `TypePointer::resolveInFlow` 1226, `findResolve` 1247, `findCompatibleResolve` 1259; `TypeArray::resolveInFlow` 1370, `findResolve` 1395, `findCompatibleResolve` 1405; `TypeStruct::findTruncation` 1803, `scoreSingleComponent` 2178, `resolveInFlow` 2214, `findResolve` 2229, `findCompatibleResolve` 2239; `TypeUnion::resolveInFlow` 2482, `findResolve` 2500, `resolveTruncation` 2510, `findTruncation` 2554, `findCompatibleResolve` 2590; `TypePartialUnion::findTruncation` 2843, `resolveInFlow` 2901, `findResolve` 2941, `findCompatibleResolve` 2951, `resolveTruncation` 2957 (`decomp-types.md` 4.8 leaves them to this track) |
| `CPP/funcdata.cc` | 917–1117 | The nine union-field methods of `Funcdata`, as the methods of `UnionMap` |
| `CPP/varnode.cc` | 658–704, and `getLocalType` | `getTypeDefFacing`, `getTypeReadFacing`, `getHighTypeDefFacing`, `getHighTypeReadFacing`, `getLocalType` |
| `UT/testtypes.cc` | 20–214 | The fixture (`castPrinted` 67–90, `longPrinted` 92–106) and `cast_basic` 121, `cast_pointer` 137, `cast_enum` 157, `cast_compare` 165, `cast_integertoken` 204 |

`typeop.cc`, `cast.cc` and `unionresolve.cc` contain no `std::sort` and no
iteration of a pointer-ordered container (4.15).

## 3. Scope

### 3.1 In

The per-opcode type behaviour as functions over a table; the two cast
strategies; union and structure-field resolution in data-flow; the union
map; the access table and its rows at `LOAD`, `STORE`, `PTRADD`, `PTRSUB`
(ADR-025 3e); the boolean-flip table; the propagation policies as units.

**Crate owned:** `bk-decomp-typeop`. Dependencies: `bk-core`, `bk-pcode`
(opcodes, `FloatFormat`), `bk-decomp-types` (D02), `bk-decomp-ir` (D05),
`bk-cspec` (D03: `FuncProto`), `bk-decomp-symbols` (D06: `CPoolRecord`).
**Not `bk-decomp-core`** (ADR-060).

### 3.2 Who owns what

| Ghidra | Owner | Where |
|---|---|---|
| `TypeOp::opflags`, `addlflags`, `name` for raw printing, `printRaw` | D05 | `decomp-ir.md` 4.6, 4.7 (`OpProps`, `RawForm`) |
| `TypeOp::behave`, `evaluateUnary` … `recoverInputUnary` | `bk-pcode` | op behaviours |
| `TypeOp::booleanFlip`, `getBooleanFlip`; `isBooleanFlipReorder` | **D08** (4.1); the reorder bit is read from D05's `addl` | misfit 1 of the track report: no document gave it an owner |
| `registerInstructions`, `selectJavaOperators`, the metatypes of `TypeOpBinary`/`Unary`/`Func` | D08 (4.1) | `TypeOps::new`, `set_language` |
| `getOutputLocal`, `getInputLocal`, `getOutputToken`, `getInputCast`, `propagateType`, `getOperatorName` of every class; the static helpers of section 2 | D08 (4.3–4.7) | |
| `PcodeOp::outputTypeLocal`, `inputTypeLocal`; `Varnode::getLocalType`, `getTypeDefFacing`, `getTypeReadFacing`, `getHighTypeDefFacing`, `getHighTypeReadFacing` | D08 (4.2) | functions over `(&Ssa, …)`; this settles D05's open item 1 for these queries |
| `Varnode::temp.dataType` (`getTempType`, `setTempType`) | D08 defines the table (`TempTypes`, 4.6); D11's `ActionInferTypes` owns the value | misfit 2 |
| `TypeOp::push` and the `PrintLanguage::op…` methods | D16b | |
| `CastStrategy` and both subclasses | D08 (4.8) | |
| Setting `Varnode::setUnsignedPrint` and `setLongPrint` after `markExplicit…` | the caller, D16b (`ActionSetCasts`), through D05's `set_unsigned_print`/`set_long_print` | D08 returns the answer (4.8.9) |
| `ResolvedUnion`, `ResolveEdge`, `ScoreUnionFields`, `ResolveCache` | D08 (4.9–4.12) | |
| `Funcdata::unionMap` and its nine methods | D08 defines `UnionMap`; D07a holds one per function, clears it in `clear` (`funcdata.cc:100`), dumps and loads its `U` records | `decomp-core.md` 3.3 |
| `Funcdata::applyUnionFacet` (`funcdata_varnode.cc:1707–1746`) | D07c, with `UnionMap`'s methods | |
| The IR-bound methods of `Datatype` and its subclasses (section 2) | D08 (4.10) | |
| `Datatype::getSubType`, `TypePointer::downChain`, `TypeFactory::getExactPiece`, `getTypePointer…`, `resizePointer`, `typeOrder`, `TypeUnion::getField`, the pure part of `TypeStruct::findTruncation` | D02 | `sub_type`, `down_chain`, `exact_piece`, `pointer`, `pointer_strip_array`, `pointer_rel`, `resize_pointer`, `partial_enum`, `type_order`, `union_field`, `struct_truncation` (all present in the merged crate) |
| `FuncCallSpecs::getFspecFromConst`, `Funcdata::getCallSpecs`, `getFuncProto`, `UserOpManage::getOp` and the user ops' `getOutputLocal`/`getInputLocal`/`getOperatorName`, `HighVariable::getType`, `ConstantPool::getRecord`, `Translate::getFloatFormat` | D07a, behind `TypeOpEnv` (3.3) | |
| `ActionInferTypes` (the propagation loop, `propagateTypeEdge`, `coreaction.cc:5471–5512`) | D11 | calls 4.6 and 4.10 |
| `ActionSetCasts` (`coreaction.cc` 2530–2940) | D16b | calls 4.4, 4.5, 4.8, 4.9 |
| `HighVariable::updateType` | D07a | `decomp-core.md` 4.A.11 |
| `AccessTable` (ADR-025 3e) | **D08 defines the type and the row rule** (4.13); D07a holds one per function; D11 rebuilds it | amends `decomp-core.md` 4.A.10, which gives the type to core: core is above this crate and D08 cannot name a type of core's |

### 3.3 `TypeOpEnv`: what the crate reads from a function and its architecture

`TypeOp` reads `Funcdata` and `Architecture` at the places below. The
crate defines the trait; `bk-decomp-core` implements it for its function
state in its step A9 (`decomp-core.md` 10); this crate ships a
table-driven implementation, `TableTypeEnv`, for its own tests.

```rust
pub trait TypeOpEnv {
    /// Funcdata::getCallSpecs(op) (funcdata.cc:481–494): the call
    /// specification of a call op, by the fspec varnode in input 0 or by
    /// search of the call-spec list. Replaces FuncCallSpecs::getFspecFromConst
    /// at typeop.cc:702 and 731, getCallSpecs at 757 and 782, at
    /// unionresolve.cc:411, 426, 751 and at type.cc:2200.
    fn call_proto(&self, ssa: &Ssa, op: OpId) -> Option<&FuncProto>;
    /// Funcdata::getFuncProto() (typeop.cc:915; unionresolve.cc:430).
    fn function_proto(&self) -> &FuncProto;
    /// UserPcodeOp::getOutputLocal / getInputLocal of the user op that
    /// input 0 of a CALLOTHER names (typeop.cc:858–859, 868–869). `None`:
    /// the user op has no answer, or the index names no user op.
    fn userop_output(&self, ssa: &Ssa, types: &mut TypeFactory, op: OpId)
        -> Result<Option<TypeId>, TypeError>;
    fn userop_input(&self, ssa: &Ssa, types: &mut TypeFactory, op: OpId, slot: usize)
        -> Result<Option<TypeId>, TypeError>;
    /// UserPcodeOp::getOperatorName(op) (typeop.cc:842–846); `false` when
    /// the index names no user op (nothing is written).
    fn userop_name(&self, ssa: &Ssa, op: OpId, out: &mut dyn fmt::Write) -> Result<bool, fmt::Error>;
    /// HighVariable::getType() of the varnode's high variable
    /// (varnode.cc:686, 700; cast.cc:87). `None`: the varnode has none.
    fn high_type(&self, vn: VarnodeId) -> Option<TypeId>;
    /// ConstantPool::getRecord(refs) (typeop.cc:2596).
    fn cpool_record(&self, refs: &[u64]) -> Option<&CPoolRecord>;
    /// Translate::getFloatFormat(size) (unionresolve.cc:997).
    fn float_format(&self, size: i32) -> Option<&FloatFormat>;
}
```

The trait is object-safe. What needs no method: the default data space
and its word size (`TypeFactory::env().data_space`, D02); a space's word
size, endianness and pointer bounds (`Ssa::spaces()`, `bk-core`); the far
and near pointer sizes and `sizeof(int)` (`DataOrganization`, D02). The
user-op methods take the type factory because a volatile read's type is
`getExactPiece` of a symbol's type (`userop.cc:128–150`,
`database.cc:137–143`), which can create a type.

`high_type` returns what `HighVariable::getType()` returns after its lazy
update; keeping it current is the implementer's (`decomp-core.md`
4.A.11). The union map and the temporary types are passed beside the
trait, not through it: they are this crate's types.

### 3.4 Not in this track

`TypeOp::push` and the printer (D16b); `ActionSetCasts` (D16b);
`ActionInferTypes` (D11); the opcode property word, the raw-print names
and forms (D05); op behaviours and evaluation (`bk-pcode`); user ops' own
type answers (D07a, `decomp-core.md` 4.A.9); `applyUnionFacet` (D07c);
the users of `ResolveCache` (`SplitDatatype`, R7).

## 4. Behaviour

Notation. An op has inputs `in0, in1, …` and maybe an output `out`. A
*slot* is `Out` (Ghidra's −1) or `In(i)`. `base(s, m)` is
`TypeFactory::getBase(s, m)`; `ptr(s, t, w)` is `getTypePointer(s, t, w)`;
`unk1` is `base(1, TYPE_UNKNOWN)`; `ws(space)` is the space's word size;
`dws` is the word size of the default data space. `gptr(t)` is
`ptr(size of t, unk1, dws)`, the "pointer to something" a spacebase
varnode propagates. Metatypes are written without `TYPE_`.

### 4.1 The table (read, `typeop.cc` 24–148 and the 73 constructors; ran, X8 rows `P`)

`registerInstructions` creates one object per opcode, 73 in all, after
the data organisation is final (`Architecture::init`,
`architecture.cc`: `restoreFromSpec` and `buildCoreTypes` come before
`buildInstructions`). Each object is one of four forms. Three of them
(`TypeOpBinary`, `TypeOpUnary`, `TypeOpFunc`) differ only in `printRaw`
(D05) and carry two metatypes; this document calls them *typed*. The
fourth (`TypeOp` itself) is *untyped*.

**Typed opcodes** (output metatype, input metatype):

| Opcodes | Out | In |
|---|---|---|
| `INT_EQUAL`, `INT_NOTEQUAL`, `INT_SLESS`, `INT_SLESSEQUAL`, `INT_SCARRY`, `INT_SBORROW` | BOOL | INT |
| `INT_LESS`, `INT_LESSEQUAL`, `INT_CARRY` | BOOL | UINT |
| `INT_SEXT`, `INT_ADD`, `INT_SUB`, `INT_2COMP`, `INT_LEFT`, `INT_SRIGHT`, `INT_MULT`, `INT_SDIV`, `INT_SREM`, `SPULL` | INT | INT |
| `INT_ZEXT`, `INT_NEGATE`, `INT_XOR`, `INT_AND`, `INT_OR`, `INT_RIGHT`, `INT_DIV`, `INT_REM` | UINT | UINT |
| `BOOL_NEGATE`, `BOOL_XOR`, `BOOL_AND`, `BOOL_OR` | BOOL | BOOL |
| `FLOAT_EQUAL`, `FLOAT_NOTEQUAL`, `FLOAT_LESS`, `FLOAT_LESSEQUAL`, `FLOAT_NAN` | BOOL | FLOAT |
| `FLOAT_ADD`, `FLOAT_DIV`, `FLOAT_MULT`, `FLOAT_SUB`, `FLOAT_NEG`, `FLOAT_ABS`, `FLOAT_SQRT`, `FLOAT_FLOAT2FLOAT`, `FLOAT_CEIL`, `FLOAT_FLOOR`, `FLOAT_ROUND` | FLOAT | FLOAT |
| `FLOAT_INT2FLOAT` | FLOAT | INT |
| `FLOAT_TRUNC` | INT | FLOAT |
| `PIECE`, `SUBPIECE` | UNKNOWN | UNKNOWN |
| `INSERT` | UNKNOWN | INT |
| `ZPULL` | UINT | INT |
| `POPCOUNT`, `LZCOUNT` | INT | UNKNOWN |

That is 55. **Untyped** (18): `COPY`, `LOAD`, `STORE`, `BRANCH`,
`CBRANCH`, `BRANCHIND`, `CALL`, `CALLIND`, `CALLOTHER`, `RETURN`,
`MULTIEQUAL`, `INDIRECT`, `CAST`, `PTRADD`, `PTRSUB`, `SEGMENTOP`,
`CPOOLREF`, `NEW`.

**The Java variant** (read, 115–148). `selectJavaOperators(true)` sets
`INT_ZEXT` to input UNKNOWN and output INT; `INT_NEGATE`, `INT_XOR`,
`INT_OR`, `INT_AND`, `INT_RIGHT` to INT in and out; and the symbol of
`INT_RIGHT` to `>>>`. `selectJavaOperators(false)` sets those six back
to UINT in and out and the symbol to `>>`, which is what the
constructors build. It is called from `PrintLanguage::adjustTypeOperators`
(`printc.cc:2424–2430`, `printjava.cc:121–127`) whenever the print
language is selected (`Architecture::setPrintLanguage`,
`architecture.cc:410–433`), so the table is a value with two variants and
the variant always equals the print language's. The cast strategy is the
print language's too (`printc.cc:136`, `printjava.cc:44–47`). Basilisk
has one switch, `Language::{C, Java}`, for both (ran: only `INT_RIGHT`'s
name differs between the variants in the 73 `P` rows).

**PIECE and SUBPIECE** read two sizes at construction (2181–2184,
2260–2263): `farPointerSize = getSizeOfAltPointer()`, and
`nearPointerSize = getSizeOfPointer()` when the former is not 0, else 0.
`TypeOps::new` reads them from the factory's data organisation.

**Boolean flip** (read, the constructors; ran, `P` rows). The
complementary opcode, for eleven opcodes: `INT_EQUAL` ↔ `INT_NOTEQUAL`,
`INT_SLESS` ↔ `INT_SLESSEQUAL`, `INT_LESS` ↔ `INT_LESSEQUAL`,
`FLOAT_EQUAL` ↔ `FLOAT_NOTEQUAL`, `FLOAT_LESS` ↔ `FLOAT_LESSEQUAL`,
`BOOL_NEGATE` → `COPY`. Every other opcode has none (`CPUI_MAX`).
`isBooleanFlipReorder` is D05's `addl` bit `boolean_reorder` (set for the
four signed and unsigned orderings and the two float orderings).

### 4.2 Shared pieces

**Default local types** (read, 263–277, 325–377). Untyped:
`output_local = base(size of out, UNKNOWN)`, `input_local(i) =
base(size of in_i, UNKNOWN)`. Typed: the same with the table's
metatypes. Ghidra dereferences a missing output; Basilisk returns
`TypeOpError::NoOutput`.

**Facing types** (read, `varnode.cc` 658–704). For a type `t` that does
not need resolution, the facing type is `t`. Otherwise it is
`find_resolve(t, op, slot)` (4.10):

* `type_def_facing(vn)`: the varnode's own type at `(def, Out)`.
* `type_read_facing(vn, op)`: the varnode's own type at
  `(op, In(op.slot_of(vn)))`.
* `high_type_def_facing(vn)`, `high_type_read_facing(vn, op)`: the same
  with `env.high_type(vn)`.

`slot_of` is `PcodeOp::getSlot`: the **first** input slot that holds the
varnode. An op that reads one varnode in two slots resolves both through
the first. Below, `T(x)` is `type_read_facing(x, op)`, `H(x)` is
`high_type_read_facing(x, op)` and `Hd(out)` is
`high_type_def_facing(out)`, with `op` the op in question.

Ghidra dereferences a null `def` (a free or input varnode whose type
needs resolution) and a null high variable. Basilisk: the unresolved type
when there is no op (`find_resolve` of 4.10 is not called), and
`TypeOpError::NoHigh(vn)` when a high type is asked of a varnode without
one.

**`local_type(vn)`** (read, `Varnode::getLocalType`). Type-locked: the
varnode's type. Otherwise `ct = output_local(def)` when written, and if
the defining op stops type propagation the result is `ct` with `blockup
= true`. Then for each reader in the varnode's reader order, with `i`
the first slot holding the varnode: `n = input_local(reader, i)`; `ct =
n` when `ct` is unset or `type_order(n, ct) < 0`. Neither written nor
read: the error `NULL local type`.

### 4.3 Local types (read; ran, X8 rows `O` and `R`)

`output_local` and `input_local` are the defaults of 4.2 except:

| Opcode | Rule | Lines |
|---|---|---|
| `CBRANCH` | in 1: `base(size of in1, BOOL)`. in 0: `ptr(size of in0, code, ws(space of in0))` | 612–622 |
| `CALL` in `i` | Default when `i = 0` or in 0 is not a call-spec varnode. Else with `p` = parameter `i − 1` of `env.call_proto(op)`: if `p` is type-locked and its type is not VOID and its size ≤ the size of in `i`: that type. Else if `p` is not type-locked and is the `this` pointer and its type is a pointer to a STRUCT: that type. Else default | 690–718 |
| `CALL` out | Default unless in 0 is a call-spec varnode, the prototype's output is locked and its type is not VOID; then that type | 720–736 |
| `CALLIND` in `i` | in 0: `ptr(size of in0, code, ws(space of the op's address))`. Others: as `CALL` with `env.call_proto(op)` (default when there is none), **without the size test** on a locked parameter | 745–774 |
| `CALLIND` out | As `CALL` out, with `env.call_proto(op)` | 776–789 |
| `CALLOTHER` | `env.userop_input` / `userop_output` when it answers, else default | 855–873 |
| `RETURN` in `i` | Default when `i = 0` or the op is in no block. Else `ct` = the output type of `env.function_proto()`; default when it is VOID or its size differs from in `i`'s; else `ct`. The output lock is not consulted | 901–922 |
| `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT` in 1 | `getBaseNoChar(size of in1, INT)` | 1536–1542, 1561–1567, 1626–1632 |
| `INDIRECT` in 1 | `ptr(size of **in0**, code, ws(space of the address of the op that in 1 names))` | 2131–2142 |
| `PTRADD`, `PTRSUB` | every input and the output: `base(size, INT)` | 2371–2381, 2447–2457 |
| `CPOOLREF` out | `refs` = the offsets of inputs 1 to n−1; no record: default; a record tagged `instance_of`: `base(1, BOOL)`; else the record's type | 2590–2602 |
| `CPOOLREF` in | `base(size, INT)` | 2604–2608 |
| `INSERT` in | slots 0 and 1: `base(size, UNKNOWN)`; others typed (INT) | 2674–2680 |
| `ZPULL`, `SPULL` in | slot 0: `base(size, UNKNOWN)`; others typed (INT) | 2701–2707, 2728–2734 |

A `CALL` whose input 0 is not a call-spec varnode is typed by default
even if the call-spec list has an entry for it (the `CALL` rule tests the
varnode, `CALLIND` searches the list). `INDIRECT` sizes the code pointer
of slot 1 by input 0; reproduced.

`CALLOTHER`: Ghidra calls the user op without a null test
(`typeop.cc:858–859`, `868–869`) and crashes when the index names none;
Basilisk uses the default (8, D-3).

### 4.4 The output token (read; ran, rows `O`)

`output_token(op)` is the type a C compiler would give the expression.
Default: `output_local(op)` (284–288). Overrides:

| Opcode | Rule | Lines |
|---|---|---|
| `COPY` | `H(in0)` | 407–411 |
| `LOAD` | `ct = H(in1)`; if `ct` is a pointer whose target has the size of `out`: the target; else `Hd(out)` | 474–487 |
| `INT_ADD`, `INT_SUB`, `INT_2COMP`, `INT_NEGATE`, `INT_XOR`, `INT_AND`, `INT_OR`, `INT_MULT` | `arithmetic_output_standard(op)` (4.8.6) | 1201–1205 and the like |
| `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT` | `H(in0)`; if that is BOOL, `base(its size, INT)` | 1544–1551, 1584–1591, 1634–1641 |
| `PIECE` | `Hd(out)` when its metatype is INT or UINT, else `base(size of out, UINT)` | 2202–2211 |
| `SUBPIECE` | `ct = H(in0)`; `f = find_truncation(ct, byte offset (4.7), size of out, op, In(1))`; when `f` exists and its type has the size of `out`: that type. Else `Hd(out)` unless it is UNKNOWN; else `base(size of out, INT)`. Slot 1 is artificial: the resolution of a truncated union is stored under the constant's slot, because slot 0 holds the resolution of the union itself | 2281–2298 |
| `PTRADD` | `H(in0)` | 2383–2387 |
| `PTRSUB` | `pt = H(in0)`. Not a pointer: the default (`base(size of out, INT)`). Else `off = addressToByte(offset of in1 as a signed 64-bit value, word size of pt)`, `r = down_chain(pt, off, allow_array_wrap = false)`; when the remaining offset is 0 and `r` exists: `r`; else `ptr(size of out, unk1, word size of pt)` | 2488–2503 |
| `SEGMENTOP` | `H(in2)` | 2553–2557 |
| `INSERT`, `ZPULL`, `SPULL` | `Hd(out)` | 2688–2692, 2715–2719, 2742–2746 |

`INT_DIV`, `INT_SDIV`, `INT_REM`, `INT_SREM`, the comparisons, the
extensions and all floating-point opcodes use the default.

### 4.5 The input cast (read; ran, rows `O`, `X`, `R` and the unit tests)

`input_cast(op, slot)` is the type input `slot` must be cast to, or
`None` when no cast is needed. `cs(req, cur, u, p)` is
`cast_standard(req, cur, care_uint_int = u, care_ptr_uint = p)` (4.8.1).

**Default** (297–305): an annotation input needs none; else `cs(
input_local(op, slot), H(in_slot), false, true)`.

| Opcode | Rule | Lines |
|---|---|---|
| `COPY` | `cs(Hd(out), H(in0), false, true)`; the slot and the annotation test are not consulted | 399–405 |
| `LOAD` | Slot other than 1: none. `req = Hd(out)`, `cur = H(in1)`, `w = ws(space named by in0)`. `cur` not a pointer: `ptr(size of in1, req, w)`. Else `cur` = its target. If `cur ≠ req`, their sizes are equal and `cur` is not STRUCT, ARRAY, SPACEBASE or UNION: none (the cast is left to the output), **unless** in 1 is implied, written and defined by a `CAST`. Then `r = cs(req, cur, false, true)`; none when `r` is none, else `ptr(size of in1, r, w)` | 442–472 |
| `STORE` | Slot 0: none. The op does special printing: none. `pt = H(in1)`, `vt = H(in2)`, `w` as for `LOAD`. `dest` = the size of `pt`'s target when `pt` is a pointer, else −1. If `dest ≠` size of `vt`: slot 1 gives `ptr(size of in1, vt, w)`, slot 2 none. Else slot 1: when in 1 is written by a `CAST`, is implied and its only reader is this op, `n = ptr(size of in1, vt, w)` is the answer if `pt ≠ n`; otherwise none. Slot 2: `cs(target of pt, vt, false, true)` | 522–558 |
| `INT_EQUAL`, `INT_NOTEQUAL` | `req = H(in0)`; `o = H(in1)`; if `type_order(o, req) < 0` then `req = o`. If `check_int_promotion_for_compare(op, slot)` (4.8.4): `req`. Else `cs(req, H(in_slot), false, false)` | 933–944, 998–1009 |
| `INT_SLESS`, `INT_SLESSEQUAL` | `req = input_local(op, slot)`; promotion for compare: `req`; else `cs(req, H(in_slot), true, true)` | 1036–1044, 1073–1081 |
| `INT_LESS`, `INT_LESSEQUAL` | the same with `cs(…, true, false)` | 1100–1108, 1125–1133 |
| `INT_ZEXT`, `INT_SEXT` | `req = input_local`; if `check_int_promotion_for_extension(op)`: `req`; else `cs(req, H(in_slot), true, false)` | 1157–1165, 1183–1191 |
| `INT_RIGHT` slot 0; `INT_DIV`, `INT_REM` every slot | `req = input_local`; `p = int_promotion_type(in_slot)`; if `p` is a promotion (not `None`) that does not include unsigned extension: `req`; else `cs(req, H(in_slot), true, true)`. `INT_RIGHT` slot 1: default | 1569–1582, 1665–1675, 1715–1725 |
| `INT_SRIGHT` slot 0; `INT_SDIV`, `INT_SREM` every slot | the same with signed extension | 1611–1624, 1685–1695, 1745–1755 |
| `FLOAT_INT2FLOAT` | None when the op absorbs a `ZEXT` (4.7). Else `care = true`, and when the input is at most 8 bytes, `care` = bit `8·size − 1` of the input's non-zero mask; `cs(input_local, H(in_slot), care, true)` | 1986–2001 |
| `PIECE`, `SUBPIECE`, `SEGMENTOP`, `CPOOLREF`, `NEW`, `INSERT`, `ZPULL`, `SPULL` | none | 2196–2200, 2275–2279, 2559–2563, hh 894, 905, 2682–2686, 2709–2713, 2736–2740 |
| `PTRADD` slot 0 | `req = T(in0)` (the varnode's own type, not the high variable's), `cur = H(in0)`. Either not a pointer: `req`. Else with the two targets: none when their aligned sizes are equal, else `req`. Other slots: default | 2389–2405 |
| `PTRSUB` slot 0 | `req = T(in0)`, `cur = H(in0)`. Equal: none. Either not a pointer: `req`. Else the two targets; when both are arrays, their elements; typedefs stripped from both; none when equal, else `req`. Other slots: default | 2459–2486 |

Every other opcode uses the default; `INT_LEFT` among them.

### 4.6 Propagation (read; ran, rows `O`)

`propagate_type(alt, op, in_slot, out_slot)` gives the type that moves
from the varnode at `in_slot`, which holds `alt`, to the varnode at
`out_slot`, or `None`. `inv` and `outv` are those varnodes. The caller
(`ActionInferTypes::propagateTypeEdge`, `coreaction.cc:5471–5512`, D11)
has already resolved `alt` in flow (4.10), refused equal slots,
annotations, a type-locked `outv`, blocked up-propagation and a boolean
onto a varnode whose non-zero mask is above 1; it compares the result
with `outv`'s temporary type. `RulePtrArith` calls it too
(`ruleaction.cc:6242`), for `PTRADD` and `PTRSUB` only.

*In ↔ out only* below means: `None` when neither slot is `Out`. *The
spacebase rule* means: when `inv` is flagged as a spacebase the result
is `gptr(alt)`, else `alt`.

| Opcode | Rule | Lines |
|---|---|---|
| `COPY` | In ↔ out only; the spacebase rule | 413–425 |
| `LOAD` | `None` when either slot is `In(0)` or `inv` is a spacebase. From `Out`: `to_pointer(alt, size of outv, ws(space named by in0))`. Else `from_pointer(alt, size of outv)` | 489–502 |
| `STORE` | `None` when either slot is `In(0)` or `inv` is a spacebase. From `In(2)`: `to_pointer(alt, size of outv, ws(…))`. Else `from_pointer(alt, size of outv)` | 560–573 |
| `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_LESSEQUAL` | `None` when either slot is `Out`. `inv` a spacebase: `gptr(alt)`. Else when `alt` is a relative pointer and `outv` is not a constant: if its parent is a STRUCT and its byte offset is ≥ 0, `ptr(size of alt, unk1, word size of alt)`; else `alt`. Else `alt` | 964–987 |
| `INT_SLESS`, `INT_SLESSEQUAL` | `None` when either slot is `Out` or `alt` is not INT; else `alt` | 1046–1052, 1083–1089 |
| `INT_ADD` | `alt` not a pointer: `None` unless it is INT or UINT, `out_slot = In(1)` and in 1 is a constant; then `alt` (an integer type moves onto the constant operand, from in 0 or from the output). `alt` a pointer: in ↔ out only; from `Out`: `None`; else `add_in2out(alt, op, in_slot)` | 1207–1227 |
| `INT_XOR`, `INT_AND` | `None` unless `alt` is an enumeration, or `alt` is FLOAT and `float_sign_manipulation(op)` is an opcode (4.7). Then the spacebase rule. Any pair of slots | 1448–1465, 1481–1498 |
| `INT_OR` | `None` unless `alt` is an enumeration; the spacebase rule. Any pair of slots | 1514–1526 |
| `MULTIEQUAL` | In ↔ out only; the spacebase rule | 2090–2104 |
| `INDIRECT` | `None` for an indirect creation, when either slot is `In(1)`, or between inputs; the spacebase rule | 2144–2159 |
| `PIECE` | With far pointers (near size ≠ 0) and `alt` a pointer: from `In(1)` to `Out`, when `inv` has the near size and `outv` the far size, `resize_pointer(alt, far)`; from `Out` to `In(1)`, when `inv` has the far size and `outv` the near size, `resize_pointer(alt, near)`; every other case `None`. Otherwise `None` unless `in_slot = Out`; then walk down: `off` = the byte offset of the input (4.7); while `alt` exists and (`off ≠ 0` or the size of `alt` ≠ the size of `outv`): `(alt, off) = sub_type(alt, off)`. The result is `alt` | 2213–2233 |
| `SUBPIECE` | With far pointers, `alt` a pointer, from `Out` to `In(0)`: `None` unless in 1 is 0, `inv` has the near size and `outv` the far size; then `resize_pointer(alt, far)`. Otherwise `None` unless from `In(0)` to `Out`. `off` = the byte offset (4.7). If `alt` is a UNION or PARTIALUNION: `f = resolve_truncation(alt, off, op, In(1))` (4.10; **this writes the union map**), `alt` = the field's type and `off` the offset within it, or `None`. Then the walk of `PIECE` | 2300–2325 |
| `PTRADD` | `None` when either slot is `In(2)`, between inputs, when `alt` is not a pointer, or from `Out`; else `add_in2out` | 2407–2420 |
| `PTRSUB` | In ↔ out only; `None` when `alt` is not a pointer or from `Out`; else `add_in2out` | 2505–2517 |
| `SEGMENTOP` | `None` when either slot is `In(0)` or `In(1)`, when `inv` is a spacebase or `alt` is not a pointer; else `resize_pointer(alt, size of outv)` | 2570–2580 |
| `NEW` | Only from `In(0)` to `Out`, and only when in 0 is written by a `CPOOLREF`: `alt` | 2640–2648 |

Every other opcode propagates nothing (319–323): `INT_SUB`, `INT_MULT`,
the shifts, divisions, extensions, the boolean and floating-point
opcodes, `CAST`, the calls, `RETURN`, the branches, `CPOOLREF`,
`INSERT`, `ZPULL`, `SPULL`, `POPCOUNT`, `LZCOUNT`.

**`to_pointer(dt, size, w)`** (187–199): if `dt` is a pointer, `dt =
base(size of dt, UNKNOWN)` (no pointer to pointer is built); if it is a
partial structure, `dt` = its component for a pointer
(`getComponentForPtr`); the result is `ptr(size, dt, w)`.

**`from_pointer(dt, size)`** (207–229): `None` unless `dt` is a pointer;
`None` when its target is variable length; the target when its size is
`size`. Otherwise only enumerations move: for a relative pointer, `r =
exact_piece(parent, byte offset, size)` when that exists and is an
enumeration; for another pointer whose target is an enumeration without
a stripped form, `partial_enum(target, 0, size)`; else `None`.

**`add_in2out(alt, op, slot)`** (1241–1279), `alt` a pointer `p`:

1. `(cmd, off) = add_pointer(op, slot, aligned size of p's target)`.
   `cmd = 2`: `None`.
2. Unless `cmd = 3`: `t = addressToByteInt(off, word size of p)`; repeat
   `p = down_chain(p, &mut t, &mut parent, &mut parent_off, allow_wrap)`
   until `p` is none or `t = 0`, where `allow_wrap` is false only for
   `PTRSUB`.
3. If a parent was found: the target is `unk1` when `p` is none, else
   `p`'s target; `p = pointer_rel(parent, target, parent_off)`.
4. `p` none: `alt` when `cmd = 0`, else `None`.
5. If the input at `slot` is a spacebase and `p`'s target is a
   SPACEBASE: `ptr(size of p, unk1, word size of p)`.
6. The result is `p`.

(The comment above the function says the output's current type is
returned to refuse an edge; the code returns null.)

**`add_pointer(op, slot, sz)`** (1294–1342) returns a command and an
offset. 0: adds the constant zero; 1: adds a constant, passed back; 2:
the pointer does not propagate; 3: the pointer propagates unchanged.

* `PTRADD`: 2 unless `slot = 0`. In 1 constant: `off = (in1 × in2)`
  masked to in 1's size; 0 when `off = 0`, else 1. Else 2 when `sz ≠ 0`
  and `in2 mod sz ≠ 0`; else 3.
* `PTRSUB`: 2 unless `slot = 0`; `off = in1`; 0 or 1 likewise.
* `INT_ADD`, with `o` the other input: `o` not a constant: when `o` is
  written by an `INT_MULT`: if the multiplier (its in 1) is a constant,
  2 when it is all ones (multiplying by −1: a pointer difference) or
  when `sz ≠ 0` and `multiplier mod sz ≠ 0`; then 3 (also when the
  multiplier is not a constant). Not written by `INT_MULT`: 3 when `sz =
  1`, else 2. `o` a constant: 2 when **`o`'s temporary type is a
  pointer**; else `off = o`, 0 or 1.
* Any other opcode: 2.

The temporary type is the propagation algorithm's working type of a
varnode (`Varnode::temp.dataType`, `varnode.hh:152–155`), set by
`ActionInferTypes` only. It is read here only for `INT_ADD`, which only
`ActionInferTypes` propagates across. Basilisk passes it as a table,
`TempTypes` (5.2); a missing entry counts as "not a pointer". Ran: with
the constant typed as an integer, `INT_ADD` of `sone *` (a structure of
two `int4`) and 4 gives `rel{8,1,4}(int4|sone)`, 1 gives
`rel{8,1,1}(xunknown1|sone)`, 8 gives `sone *`, a variable times 4 gives
`sone *` unchanged for `int4 *` and nothing for a multiplier that is not
a multiple of the target's size.

### 4.7 Names and helpers (read; ran, rows `O`)

**`operator_name(op)`**: the table's symbol, except `INT_ZEXT`,
`INT_SEXT`: the name followed by the sizes of in 0 and of `out` in
decimal (`ZEXT14`); `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`: the name
and the size of in 0; `PIECE`: `CONCAT` and the sizes of in 0 and in 1;
`SUBPIECE`: `SUB` and the sizes of in 0 and `out`; `CALLOTHER`: the user
op's name when the op is in a block and the index names a user op, else
`syscall[` + the raw print of in 0 + `]` (837–853). D05 has the same rule
for raw printing (it cannot depend on this crate); a test compares the
two on every `O` row.

**`float_sign_manipulation(op)`** (154–177): for an `INT_AND` whose in 1
is the constant `mask(size) >> 1`: `FLOAT_ABS`; for an `INT_XOR` whose
in 1 is the constant `mask ^ (mask >> 1)` (the top bit): `FLOAT_NEG`;
else none.

**`absorb_zext(op)`** (2011–2022): for a `FLOAT_INT2FLOAT`, the op
defining in 0 when in 0 is written, implied and that op is an
`INT_ZEXT`. **`preferred_zext_size(n)`** (2030–2041): 4 when `n < 4`, 8
when `n < 8`, else `n + 1`.

**Byte offsets into a composite.** `PIECE`, input `slot` (2243–2253): in
0's space big endian: 0 for slot 0, the size of in 0 for slot 1; little
endian: the size of in 1 for slot 0, 0 for slot 1. `SUBPIECE`
(2334–2346): `lsb` = in 1's offset as a 32-bit integer; big endian (in
0's space): size of in 0 − size of `out` − `lsb`; little endian: `lsb`.

### 4.8 Cast strategies (read, `cast.cc`; ran, rows `S`, `Z`, `X`, `E`, `O`)

A strategy is the language and `promote_size = sizeof(int)` of the data
organisation (`setTypeFactory`, 23–28, called from
`PrintC::initializeFromArchitecture`, `printc.cc:2414–2421`). The Java
strategy differs in 4.8.1 and 4.8.8 only.

#### 4.8.1 `cast_standard(req, cur, care_uint_int, care_ptr_uint)`

C (300–392), in this order:

1. `cur = req`: none.
2. `cur` is VOID: `req`.
3. While both are pointers: different word sizes: `req`; different
   address spaces, both set: `req`; step to the two targets, set
   `care_uint_int = true` and remember `is_ptr`.
4. Strip typedefs from both. Equal: none.
5. Either is VOID: none (no cast to or from a `void` pointer).
6. Different sizes: none when `req` is variable length, `is_ptr`, and
   both have the same variable base (`hasSameVariableBase`,
   `type.cc:147–155`: both variable length with equal unsized ids);
   else `req`.
7. By the metatype of `req`:
   * UNKNOWN, PARTIALSTRUCT, PARTIALUNION: none.
   * UINT: without `care_uint_int`, none when `cur` is UNKNOWN, INT,
     UINT, BOOL, PARTIALSTRUCT or PARTIALUNION. With it, none when `cur`
     is UINT or BOOL, or when `is_ptr` and `cur` is UNKNOWN,
     PARTIALSTRUCT or PARTIALUNION. Then, without `care_ptr_uint`, none
     when `cur` is a pointer.
   * INT: the same with INT for UINT, and no `care_ptr_uint` step.
   * CODE: when `cur` is CODE too, none if either has no prototype.
8. Otherwise `req`.

Java (471–531): 1 as above; then none when either is a pointer (object
references are cast by explicit ops); none when either is VOID; `req`
when the sizes differ; then step 7 without its `is_ptr` and
`care_ptr_uint` parts, and step 8. No typedef stripping.

#### 4.8.2 Promotion codes

`Promotion::{None (−1), Unknown (0), Unsigned (1), Signed (2), Either
(3)}`. Ghidra tests them as bit masks; "includes unsigned" is `Unsigned`
or `Either`, "includes signed" is `Signed` or `Either`, and `None & x`
is `x` (all bits set).

#### 4.8.3 `local_extension_type(vn, op)` (140–176)

`natural` by the metatype of `high_type_read_facing(vn, op)`: UINT,
BOOL, UNKNOWN, PARTIALSTRUCT, PARTIALUNION: `Unsigned`; INT: `Signed`;
anything else: the answer is `Unknown`. Then: a constant: `Either` when
its top bit is clear, else `natural`. Explicit: `natural`. Not written:
`Unknown`. Defined by an op with a boolean output: `Either`. Defined by
`CAST`, `LOAD` or a call: `natural`. Defined by `INT_AND` whose in 1 is
a constant: `Either` when that constant's top bit is clear, else
`natural`. Otherwise `Unknown`.

#### 4.8.4 `int_promotion_type(vn)` and the two checks (107–138, 178–247)

`int_promotion_type`: size ≥ `promote_size`: `None`. A constant:
`local_extension_type(vn, its only reader)`. Explicit: `None`. Not
written: `Unknown`. Else by the defining op:

* `INT_AND`: `Unsigned` when in 1 or in 0 locally includes unsigned.
* `INT_RIGHT`: `v` = local of in 0; `v` when it includes unsigned.
* `INT_SRIGHT`: `v` = local of in 0; `v` when it includes signed.
* `INT_XOR`, `INT_OR`, `INT_DIV`, `INT_REM`: `Unknown` unless both
  inputs locally include unsigned; then `Unsigned`.
* `INT_SDIV`, `INT_SREM`: the same with signed.
* `INT_NEGATE`, `INT_2COMP`: `Signed` when in 0 locally includes
  signed.
* `INT_ADD`, `INT_SUB`, `INT_LEFT`, `INT_MULT` and the cases above that
  did not answer: `Unknown`.
* Any other opcode: `None`.

A constant with no reader or several has no "only reader"; Ghidra then
passes a null op, which is used only if the constant's high type needs
resolution (a crash). Basilisk uses the unresolved type there (8, D-4).

`check_int_promotion_for_compare(op, slot)`: `a` = promotion of in
`slot`. `None`: false. `Unknown`: true. `b` = promotion of the other
input. A common extension bit: false. `b = None`: false. Else true.

`check_int_promotion_for_extension(op)`: `a` = promotion of in 0.
`None`: false. `Unknown`: true. Includes unsigned and the op is
`INT_ZEXT`: false. Includes signed and the op is `INT_SEXT`: false.
Else true.

#### 4.8.5 `is_extension_cast_implied(op, read_op)` (249–298)

False when `op`'s output is explicit, or there is no reading op. Else
with `m` = the metatype of the output's high type facing `read_op`:
`PTRADD`: true. `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_AND`,
`INT_OR`, `INT_XOR`, `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`,
`INT_LESSEQUAL`, `INT_SLESS`, `INT_SLESSEQUAL`: with `o` the other
input (`1 − slot`, the slot being the first that holds the output):
false when `o` is a constant larger than `promote_size`, or `o` is
neither a constant nor explicit, or the metatype of `o`'s facing high
type is not `m`; else true. Any other reader: false. (`INT_SDIV`,
`INT_REM` and the shifts are not in the list.)

#### 4.8.6 `arithmetic_output_standard(op)` (394–409)

`r = H(in0)`, replaced by `base(its size, INT)` when BOOL. For each
further input `i`: `t = H(in_i)`; skipped when BOOL; `r = t` when
`type_order(t, r) < 0`.

#### 4.8.7 Subpiece casts (411–441)

`is_subpiece_cast(out, in, offset)`: false unless `offset = 0`; false
unless `in` is INT, UINT, UNKNOWN, PTR, PARTIALSTRUCT or PARTIALUNION
and `out` is INT, UINT, UNKNOWN, PTR or FLOAT. For a pointer `in`: true
when `out` is a smaller pointer (far to near); else false unless `out`
is INT or UINT. Else true. `is_subpiece_cast_endian(out, in, offset,
big)`: the same with `offset` replaced by `size of in − 1 − offset` for
big endian.

#### 4.8.8 Extension casts (443–469, 533–544)

`is_sext_cast(out, in)`: `out` is UINT or INT and `in` is INT or BOOL.
`is_zext_cast(out, in)`, C: `out` is UINT or INT and `in` is UINT or
BOOL. Java: both are INT, UINT or BOOL, and `in` is a 2-byte type that
prints as a character, or 1 byte and not INT; never for 4 bytes or
more.

#### 4.8.9 Constants printed with a mark (30–105)

Ghidra's two functions answer and set a flag on the varnode. Basilisk's
only answer (3.2).

`needs_explicit_unsigned(op, slot)`: false unless the opcode inherits
its sign (`addl`); false for slot 1 of an opcode that inherits from the
first operand only; false unless the input is a constant whose facing
high type is UINT, UNKNOWN, PARTIALSTRUCT or PARTIALUNION, does not
print as a character and is not an enumeration. For an op of two inputs
that inherits from both: false when the other input's facing high type
has one of those four metatypes (it forces the sign). Then: false when
the output is explicit, or has exactly one reader whose opcode does not
inherit its sign. Else true.

`needs_explicit_long(op, slot)`: false unless the opcode is a shift,
`slot = 0`, the input is a constant larger than `promote_size` and its
high type (not facing) is UINT, INT, UNKNOWN, PARTIALSTRUCT or
PARTIALUNION. For INT with the sign bit set: negate the value in its
size; false when its top set bit is ≥ `8·promote_size − 1`. Otherwise
false when the top set bit of the value is ≥ `8·promote_size`. Else
true. (Ran through the unit test `cast_integertoken`'s seven cases, 6.1.)

`cares_about_char_representation` is false for both strategies
(`cast.hh:174`).

### 4.9 The union map (read, `unionresolve.cc` 25–129, `funcdata.cc` 917–1117)

**`ResolvedUnion`**: the resolved type, the base type (the union or
structure, pointers and partials stripped), the field number (−1: the
type itself), and a lock.

* `new(t)` (25–36): base = `t`, or its target when `t` is a pointer, or
  its parent union when a partial union; resolved = `t`; field −1.
* `with_field(t, f)` (41–75): a partial union: base = the parent union;
  `f < 0`: the stripped type; else `exact_piece(type of field f, the
  partial's offset, its size)`, or the stripped type when that is none.
  A pointer: base = the target; `f < 0`: `t`; else
  `pointer_strip_array(size of t, depend f of the target, word size)`.
  Otherwise base = `t`; `f < 0`: `t`; else depend `f` of `t`. (For a
  structure or a one-element array, depend 0 is the field or element.)
* `update(other)` (88–98): refused (false) when locked and the field
  numbers differ; false when field and resolved type are both equal;
  else takes both and returns true. The lock protects the field, not
  the resolved type.

**`ResolveEdge`**: the key `(type id, encoding, time)`, ordered in that
order (`unionresolve.hh` 212–220).

* For an op edge (103–116): time = the op's creation time; encoding =
  the slot (−1 for the output); for a pointer type, type id = the id of
  its target and encoding = slot + 0x1000; for a partial union, the id
  of the parent union; else the type's own id.
* For an address (118–129): time = **the low 32 bits of the address
  offset**; encoding = 0x2000; type id as above. The space of the
  address and the slot are not part of the key.

The type id is Ghidra's 64-bit id (`TypeEntry::id`), which is 0 for
every anonymous type. One-element arrays (which need resolution) and
pointers to anonymous types therefore share keys on one edge. Both
oddities are reproduced: the key is what the state dump's `U` record
writes and what `getUnionField` finds (8, R-1, R-2).

**The nine methods**, on `UnionMap` (an ordered map from edge to
resolution):

| Method | Behaviour | Lines |
|---|---|---|
| `get_union_field(t, op, slot)` | The entry of the edge, **only when the size of its resolved type equals the size of `t`** | 917–931 |
| `get_union_resolution(t, op, slot)` | The entry, whatever its size | 941–952 |
| `get_address_based(t, addr, slot)` | The entry of the address edge | 961–970 |
| `set_union_field(t, op, slot, r)` | Insert; if the edge exists, `update` it, and when that returns false, return whether the entry is unlocked, without the next step. Then, for a `MULTIEQUAL` and an input slot: every other slot holding the same varnode gets the entry too (insert or `update`). Returns true | 981–1006 |
| `set_address_based(t, addr, slot, r)` | Insert; an existing entry is replaced unless locked (then false) | 1017–1030 |
| `update_union_field(t, op, slot, res)` | Set the resolved type of an existing entry (field and lock kept); false when there is none | 1040–1051 |
| `force_facing_type(t, f, op, slot)` | If `t` is a relative pointer, `t = ptr(size, its target, word size)`; `set_union_field(t, op, slot, with_field(t, f))` | 1059–1071 |
| `inherit_union_field(t, op, slot, old_op, old_slot)` | When `slot` is the output and **`old_op`** is a marker, `slot = In(0)`. The entry of `(t, old_op, old_slot)`, when there is one, is set for `(t, op, slot)`; returns its field, or −1 without an entry | 1081–1093 |
| `inherit_union_field_ptr(p, op, slot, old_op, old_slot)` | The same, looking up depend 0 of the pointer `p` at the old edge and storing `with_field(p, field)` at the new one | 1103–1117 |

The map lives in the function state: empty at the start of a
decompilation, cleared by `Funcdata::clear` (`funcdata.cc:100`), filled
by `applyUnionFacet` (locked entries from union-facet symbols), by type
propagation and by `ActionSetCasts`, and carried along by the rules
that replace an op (the callers of the two `inherit` methods:
`ruleaction.cc`, `constseq.cc`, `merge.cc`, `subflow.cc`). Entries are
never removed one by one; an entry whose op was destroyed stays (its
time is never reused).

### 4.10 Resolution in flow (read, `type.cc`, lines in section 2)

Four operations on a type at an edge `(op, slot)`. A type that does not
need resolution answers with itself (`resolve_in_flow`, `find_resolve`),
−1 (`find_compatible_resolve`) or nothing (the truncations), without
touching the map.

**`find_resolve(t, op, slot)`** reads only:

* Union: `get_union_field`'s resolved type, else `t`.
* Pointer to a union: likewise. Any other pointer: `t`.
* Structure (one that needs resolution: a single field filling it):
  `get_union_field`'s type, else the type of field 0.
* Array (of one element): `get_union_field`'s type, else the element.
* Partial union: `get_union_field`'s type, else the stripped type.

**`resolve_in_flow(t, op, slot)`** resolves and records:

* Union (2482–2498): the entry of `get_union_field` if any. Else the
  address-based entry `a` of the op's address: the answer is
  `with_field(t, a.field)`'s type, **and the entry stored for the edge
  is `a` itself** (its resolved type, base and lock), not the new one.
  Else score the fields (4.11), store and return the result.
* Pointer to a union (1226–1245): the same, except that with an
  address-based entry the new `with_field(t, a.field)` is what is
  stored. Any other pointer: `t`.
* Structure, array (2214–2227, 1370–1383): the entry if any; else `f =
  score_single_component(t, op, slot)`, store `with_field(t, f)`,
  return its type.
* Partial union (2901–2939): the entry if any. Else `cur` = the
  container, `off` = the partial's offset; while `cur` exists and is
  larger than the partial: for a union, `f = resolve_truncation(cur,
  off, op, slot)` and `cur = exact_piece(type of f, offset within f,
  size)` (none without `f`), `off = 0`; (a branch for a partial-union
  container exists and cannot be reached: the container is a union;)
  anything else: none. A result that is none or of another size becomes
  the stripped type. Then `update_union_field(t, op, slot, result)` —
  which changes an entry only if `resolve_truncation` created one for
  this edge — and the result is returned.

**`score_single_component(parent, op, slot)`** (2178–2212) answers −1
(the whole) or 0 (the component). −1 when: the op is `COPY` or
`INDIRECT` and the varnode on the other side (the output for slot 0,
else in 0) is type-locked with exactly the type `parent`; the op is a
`LOAD` at `Out` or a `STORE` at `In(2)` whose in 1 is type-locked with
a facing type that is a pointer to `parent`; the op is a call with a
call specification whose locked parameter `slot − 1` (slot ≥ 1) or
locked output (slot `Out`) has the type `parent`. Else 0.

**`resolve_truncation(t, offset, op, slot)`** returns a field and the
offset within it. Union (2510–2546): `r = get_union_resolution`; when
none, the address-based entry, which is then stored for the edge. With
`r`: its field (and `offset − field offset`) when the field number is
≥ 0, else nothing. Without: for a `SUBPIECE` at the artificial slot 1,
score by `score_union_truncation_out(t, offset, op)`, store, and return
the field with offset **0**; otherwise `score_union_truncation(t,
offset, op, slot)`, store, and return the field with `offset − field
offset`; nothing when the score picks −1. Partial union (2957–2961):
the container's, at `offset + the partial's offset`. Others: nothing.

**`find_truncation(t, offset, size, op, slot)`** reads only. Structure
(1803–1817): the field containing `offset`, unless `offset − field
offset + size` exceeds the field's size; D02's `struct_truncation`.
Union (2554–2568): the field of `get_union_resolution` when ≥ 0, unless
the piece exceeds it. Partial union: the container's at `offset + the
partial's offset`. Others: nothing.

**`find_compatible_resolve(t, ct)`** gives the field of `t` that makes
it compatible with `ct`, or −1:

* Union (2590–2610): `ct` needs no resolution: the first field at
  offset 0 whose type is `ct`. Else the first field at offset 0, of
  `ct`'s size, not itself needing resolution, for which
  `find_compatible_resolve(ct, field type) ≥ 0`.
* Structure (2239–2249), array (1405–1414), with `e` = field 0's type
  or the element: 0 when `ct` needs resolution, `e` does not and
  `find_compatible_resolve(ct, e) ≥ 0`; 0 when `e = ct`; else −1.
* Pointer (1259–1265): when `ct` is a pointer, the answer of the two
  targets; else −1.
* Partial union (2951–2955): the container's.

The recursion is bounded: each call strips a pointer or moves to a
strictly smaller component.

### 4.11 Scoring union fields (read, `unionresolve.cc` 131–1230; ran, rows `U`)

Three entry points, each returning a `ResolvedUnion`:

* `score_union_fields(parent, op, slot)` (1098–1151): `parent` is a
  union, a structure or array in the single-component case, or a
  pointer to one.
* `score_union_truncation(union, offset, op, slot)` (1200–1230): a
  piece of the union at `offset`, of the varnode's size.
* `score_union_truncation_out(union, offset, op)` (1164–1189): the
  output of a `SUBPIECE` of the union.

**Scores and trials.** `scores[0]` is for the whole type and
`scores[i + 1]` for field `i`; `fields` holds the candidate type of
each. A *trial* is `(varnode, op, slot, direction, max_length, type,
score index)`: a *down* trial follows the varnode into `op` at `slot`;
an *up* trial follows it to its definition. `visited` is a set of
`(varnode, score index)`. Limits (131–133): at most **6** passes; no
further pass once more than **256** trials were counted; a pass stops
when the count passes **1,024**. The best score wins; among equal
scores the lowest index (the whole type first, then fields in order)
(1053–1066).

**Simple cases** (171–183), returning the whole type with nothing
scored: a marker op at the output slot; a pointer parent at the output
slot; a pointer parent in array arithmetic (140–164): an `INT_ADD`
whose other input is a constant ≥ the base type's size, or is written
by an `INT_MULT` by such a constant, or a `PTRADD` whose in 2 is ≥ that
size (unsigned comparisons).

**`score_union_fields`.** `w` = the pointer's word size, or 0 for a
non-pointer. The varnode `v` is `out` or the input at `slot`. Index 0:
−10 when `v`'s size differs from `parent`'s, else a trial (up for the
output slot, down otherwise). Index 0 also gets −1 when `w = 0`, or the
op is `INT_ADD`, `PTRADD`, `PTRSUB`, `STORE` or `LOAD` (prefer a field
without other evidence). For each field `i` with type `f`: for a
pointer parent, `max_length` = the size of `f` when it is an array or
smaller than the base type, else 0, and `f = pointer_strip_array(size
of parent, f, w)`; −10 when `v`'s size differs from `f`'s, else a
trial with that `max_length`. Every index marks `(v, index)` visited.
Then `run`, then the best index.

**`score_union_truncation`.** Simple cases first. Index 0 = −10. Each
field: `c = score_truncation(field type, v, offset − field offset,
index)`; a trial for `c` when it exists, and `(v, index)` visited.
`run` only when more than one trial exists. The resolved type is
`exact_piece(best field type, offset, size of v)`, or `base(size of v,
UNKNOWN)` without one.

**`score_union_truncation_out`.** `v` = the output. Index 0 = −10. A
field whose size is not `v`'s or whose offset is not `offset`: −10.
Else `new_trials_down(v, field type, index, 0)`. The collected trials
become current; `run` only for more than one; result as above.

**`run`** (1071–1088): for pass 0 to 5: stop when there are no trials
or the count exceeds 256; score every current trial in order (count
first; stop the pass past 1,024), down then up; the last pass (5)
creates no new trials; otherwise the new trials become current.

**New trials.** `new_trials_down(v, t, index, max)` (297–315): nothing
when `(v, index)` was visited. A type-locked `v` whose def-facing type
needs no resolution: add `score_locked(t, that type)` and stop. Else a
down trial for every reader of `v` in reader order, at the first slot
holding `v`. `new_trials(op, slot, t, index, max)` (323–346), `v` = the
input: nothing when visited; type-locked with a read-facing type that
needs no resolution: add `score_locked` and stop; else an up trial for
`v`, and a down trial for every reader except `(op, slot)` itself.

**`score_locked(ct, lock)`** (190–222): +5 when equal. While both are
pointers: +5 and step to the targets. Then, same metatype: +10 for
STRUCT, UNION, ARRAY, CODE, else +3. Different: −1 for INT against
UINT, else −5; and −2 more when the sizes differ.

**`score_parameter(ct, proto, i)`** (230–240): with a prototype whose
input is locked and that has parameter `i`: `score_locked(ct, its
type)`. Else −1 for ARRAY, STRUCT, UNION, CODE, else 0.
**`score_return(ct, proto)`** (246–256): with a locked output:
`score_locked(ct, output type)`; else the same −1 or 0.

**`deref_pointer(trial, v)`** (266–290) gives a type and a score. Trial
type not a pointer: −10, none. Else walk from the target down
`sub_type(·, 0)` while larger than `v`; a type of `v`'s size: +10 and
that type. Else when `max_length ≠ 0` and `v`'s size is a multiple of
the target's: −4 and `array(size of v / size of target, target)`. Else
−5, none.

**`score_truncation(ct, v, offset, index)`** (931–980): `v` does not
fit in `ct` at `offset`: −10. `ct` a union: −10 and no type, or, when
some field has exactly that offset and `v`'s size, +10 and +5 more when
the union is the one being resolved (no type is returned either way).
Otherwise +10, then walk `(ct, off) = sub_type(ct, off)` while `off ≠
0` or the size differs: an INT or UINT that still contains the piece:
+1 instead, stop; an array whose aligned element size is smaller than
`v`: −5 when `off + size of v` is not a multiple of it, else +1, stop;
running out of type: −10. The score is added to the index; the
remaining type is returned.

**A down trial** (355–717), by the reading op's opcode; `m` is the
metatype of the trial type; *agg* is ARRAY, STRUCT, UNION, CODE or
FLOAT. A result type `r` (with a `max_length`) makes new down trials on
the op's output unless this is the last pass.

| Opcode | Score and continuation |
|---|---|
| `COPY`, `MULTIEQUAL`, `INDIRECT` | 0; `r` = the trial type, `max_length` kept |
| `LOAD` | `deref_pointer(trial, out)`; `r` = its type |
| `STORE` | Slot 1: `deref_pointer(trial, in2)`; with a type and not on the last pass, `new_trials(op, 2, type, index, 0)`. Slot 2: CODE −5; else +1 and, when not the last pass and in 1's read-facing type is a pointer, `new_trials(op, 1, pointer_strip_array(its size, trial type, its word size), index, size of trial type)` |
| `CBRANCH` | BOOL +10, else −10 |
| `BRANCHIND` | PTR or agg −5, else +1 |
| `CALL`, `CALLOTHER` | Slot > 0: `score_parameter(type, env.call_proto(op), slot − 1)`; slot 0: 0 |
| `CALLIND` | Slot 0: a pointer to CODE +10, another pointer −10, else 0. Else `score_parameter` |
| `RETURN` | `score_return(type, env.function_proto())` |
| `INT_EQUAL`, `INT_NOTEQUAL` | agg −1, else +1 |
| `INT_SLESS`, `INT_SLESSEQUAL`, `INT_SCARRY`, `INT_SBORROW` | agg −5; PTR, UNKNOWN, UINT, BOOL −1; else +5 |
| `INT_LESS`, `INT_LESSEQUAL`, `INT_CARRY` | agg −5; PTR, UNKNOWN, UINT +5; INT −5; else 0 |
| `INT_ZEXT` | UINT +2; INT, BOOL +1; UNKNOWN 0; else −5 |
| `INT_SEXT` | INT +2; UINT, BOOL +1; UNKNOWN 0; else −5 |
| `INT_ADD`, `INT_SUB`, `PTRSUB` | see below |
| `INT_2COMP` | agg −5; PTR, UNKNOWN, BOOL −1; INT +5; else 0 |
| `INT_NEGATE`, `INT_XOR`, `INT_AND`, `INT_OR`, `POPCOUNT`, `LZCOUNT` | agg −5; PTR, BOOL −1; UINT, UNKNOWN +2; else 0 |
| `INT_LEFT`, `INT_RIGHT` | Slot 0: as the row above. Slot 1: agg or PTR −5, else +1 |
| `INT_SRIGHT` | Slot 0: agg −5; PTR, BOOL, UINT, UNKNOWN −1; else +2. Slot 1: as above |
| `INT_MULT` | agg −10; PTR, BOOL −2; else +5 |
| `INT_DIV`, `INT_REM` | agg −10; PTR, BOOL −2; UINT, UNKNOWN +5; else 0 |
| `INT_SDIV`, `INT_SREM` | agg −10; PTR, BOOL −2; INT +5; else 0 |
| `BOOL_NEGATE`, `BOOL_AND`, `BOOL_XOR`, `BOOL_OR` | BOOL +10; INT, UINT, UNKNOWN −1; else −10 |
| the 18 floating-point opcodes other than `FLOAT_INT2FLOAT` | FLOAT +10, else −10 |
| `FLOAT_INT2FLOAT` | agg −10; PTR −5; INT +5; else 0 |
| `PIECE` | agg −5, else 0 |
| `SUBPIECE` | `r = score_truncation(type, out, byte offset of 4.7, index)` (which adds its own score) |
| `PTRADD` | PTR: slot 0, when the aligned size of the target equals in 2: +10 and `r` = the trial type; slot 0 otherwise 0; another slot −10. agg −5; else +1 |
| `SEGMENTOP` | Slot 2: PTR +5, agg −5, else −1. Other slots: agg or PTR −2, else 0 |
| any other | −10 |

`INT_ADD`, `INT_SUB`, `PTRSUB`, down (480–543). A pointer type, with
`o` the other input (`1 − slot`): `o` constant: `off` = its value
sign-extended from its size; with `max_length ≠ 0`, an `off` outside
`0 ≤ off < max_length` scores −1 and ends; else walk `down_chain` (with
array wrap) until `off = 0`; if a pointer remains: +5, `r` = it,
`max_length` = the size of its target (0 from the walk's point of view
when the trial had none: the walk itself carries `max_length` forward
only when it was non-zero; the new value replaces it). `o` not constant:
with `max_length = 0`: +5 (indexing something that is not an array),
no `r`. Else +1, and with `el` = 1, or the multiplier when `o` is
written by an `INT_MULT` with a constant in 1 (truncated to 32 bits):
if the aligned size of the target equals `el`: +2 when `el =
max_length`, else +5 (replacing the +1); `r` = the trial type,
`max_length` kept. INT, UINT, UNKNOWN: +1, `r` = the trial type. BOOL
−3. Else −5.

**An up trial** (719–921). A varnode that is not written: a constant is
scored by `score_constant` below; nothing else happens. Else by the
defining op's opcode, with `r` continuing through `new_trials(def,
slot, r, index, max)`:

| Opcode | Score and continuation |
|---|---|
| `COPY`, `MULTIEQUAL`, `INDIRECT` | 0; `r` = the trial type through slot 0, `max_length` kept |
| `LOAD` | 0; `r = pointer_strip_array(size of in1, trial type, 1)` through slot 1, `max_length` = the size of the trial type |
| `CALL`, `CALLOTHER`, `CALLIND` | `score_return(type, env.call_proto(def))` |
| the integer comparisons, `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`, the four boolean opcodes, the four float comparisons, `FLOAT_NAN` | BOOL +10; another 1-byte type +1; else −10 |
| `INT_ADD`, `INT_SUB`, `PTRSUB` | PTR +5, and +1 more when `max_length = 0`, in 1 is a constant and the aligned size of the target equals it (as a 32-bit value); INT, UINT +5; agg −5; else +1 |
| `INT_2COMP` | agg −5; PTR, UNKNOWN, BOOL −1; INT +5; else 0 |
| `INT_NEGATE`, `INT_XOR`, `INT_AND`, `INT_OR`, `POPCOUNT`, `LZCOUNT`, `INT_LEFT`, `INT_RIGHT` | agg −5; PTR, BOOL −1; UINT, UNKNOWN +2; else 0 |
| `INT_SRIGHT` | agg −5; PTR, BOOL, UINT, UNKNOWN −1; else +2 |
| `INT_MULT` | agg −10; PTR, BOOL −2; else +5 |
| `INT_DIV`, `INT_REM` | agg −10; PTR, BOOL −2; UINT, UNKNOWN +5; else 0 |
| `INT_SDIV`, `INT_SREM` | agg −10; PTR, BOOL −2; INT +5; else 0 |
| `FLOAT_ADD`, `FLOAT_DIV`, `FLOAT_MULT`, `FLOAT_SUB`, `FLOAT_NEG`, `FLOAT_ABS`, `FLOAT_SQRT`, `FLOAT_FLOAT2FLOAT`, `FLOAT_CEIL`, `FLOAT_FLOOR`, `FLOAT_ROUND`, `FLOAT_INT2FLOAT` | FLOAT +10, else −10 |
| `FLOAT_TRUNC` | INT, UINT +2; else −2 |
| `PIECE` | FLOAT, BOOL −5; CODE, PTR −2; else 0 |
| `SUBPIECE` | INT, UINT, BOOL: +3 when in 1 is 0, else +1; else −5 |
| `PTRADD` | PTR: +10 when the aligned size of the target equals in 2, else +2; agg −5; else +1 |
| any other (`INT_ZEXT`, `INT_SEXT`, `CAST`, `NEW`, …) | −10 |

**`score_constant(trial)`** (985–1034), by the trial type: BOOL: +2
for a 1-byte value below 2, else −2. FLOAT: −1; with a format for the
size (`env.float_format`): +2 for zero, +2 for a normalised value whose
exponent is between −3 and 6; else −1 stays. INT, UINT, PTR: +2 for
zero; else `looks = value within the default data space's pointer
bounds and bit_transitions(value, size) ≥ 3` (`address.cc:1164–1180`);
PTR: +2 when `looks`, else −2; INT, UINT: +1 when `looks`, else +2.
ARRAY: 0. Else −2.

Unsigned comparisons of a 64-bit offset with a 32-bit size are done in
64 bits, as C++ converts them; the two casts to `int4` (517, 785)
truncate. Ran: 6,524 rows on `x86:LE:64`, for example a `LOAD` through
a varnode of union type `uone { int8 l; float8 d; int4 *p; int1 a[8] }`
at slot 1 scores `-11,-10,-10,-5,-10` and picks field 2.

### 4.12 The resolution cache (read, `unionresolve.cc` 1237–1298)

`ResolveCache` carries resolutions across a transform that replaces
ops: a list of `(key, base type, field)`.

* `add_resolution(key, t, op, slot)`: nothing unless `t` needs
  resolution and `get_union_resolution(t, op, slot)` has an entry; then
  append `(key, its base, its field)`.
* `resolve(key, t)`: the first record matching `(key, t)`: `t` for
  field −1, else depend `field` of `t`; without a record, `t`.
* `inherit_resolution(key, t, off, size, op, slot)`: nothing unless `t`
  needs resolution. `parent` = the parent union of a partial union, the
  target of a pointer, else `t`. For the first record matching `(key,
  parent)`: `d = exact_piece(t, off, size)`; when it exists,
  `set_union_field(d, op, slot, with_field(d, field))` and the answer
  is `d`. Ghidra then calls `vn->updateType(d)`; Basilisk returns `d`
  and the caller updates the varnode (3.2).

### 4.13 The access table (ADR-025 3e; no Ghidra counterpart)

One row per live `LOAD`, `STORE`, `PTRADD` and `PTRSUB`:

| Opcode | base | offset | size | stride | kind |
|---|---|---|---|---|---|
| `LOAD` | in 1 | 0 | size of `out` | 0 | `Read` |
| `STORE` | in 1 | 0 | size of in 2 | 0 | `Write` |
| `PTRADD` | in 0 | in 1 × in 2 masked to in 1's size when in 1 is a constant, else 0 | 0 | 0 when in 1 is a constant, else in 2 | `Address` |
| `PTRSUB` | in 0 | in 1's value | 0 | 0 | `Address` |

Offsets and strides are in the pointer's address units, as the ops hold
them. `access_row(ssa, op)` computes one row; `AccessTable::rebuild(ssa)`
replaces the table with the rows of all live ops in op order. D11 calls
`rebuild` at the end of each run of `ActionInferTypes`; D17 once more
when the function is done. The table is derived data: it never
influences the `ghidra` profile, is not dumped and takes no part in a
state comparison. The plan's acceptance (a row for each of the four
opcodes in the final state) is checked against Ghidra's final state
dump by counting ops.

### 4.14 Units (ADR-025 items 1 and 2)

* **The propagation policy of each opcode is a unit**: 73 units named
  `typeprop.<opcode>` with the lower-case p-code name (`typeprop.int_add`),
  origin `ghidra`, group `typerecovery` (the group of `infertypes`),
  soundness `Exact` (types never change values). They need a kind:
  `UnitKind::TypePolicy`, a variant D05's enum does not have (misfit 3
  of the track report). A policy is not placed in a pipeline; a profile
  *selects* it, and `TypeOps` holds the selection. The `basilisk`
  profile can replace one opcode's policy without touching the others
  (`TypeOps::with_policy`, 5.2).
* **Union scoring is a unit**: `unionscore`, same origin, group, kind
  and soundness; the three entry points of 4.11 behind one trait.
* Not units: local types, tokens, input casts and the cast strategies.
  They are the typing rules of the output language, switched by
  language. Improvements to casts are output passes (ADR-025 item 5).
  The access table is not a unit: it has no effect.

### 4.15 Order, host dependence, undefined behaviour

* No sort. The only ordered containers are the union map (key order of
  4.9; its iteration order is visible only in the dump) and `visited`,
  a `std::set` ordered by varnode **address** (`unionresolve.hh`
  134–138) that is only inserted into and tested, never iterated: no
  host dependence. The trial lists are in creation order; readers are
  visited in D05's reader order.
* The oracle is byte-identical on both reference builds for three
  architectures (563,339 rows; X8).
* Ghidra's undefined or crashing cases and what Basilisk does: section
  8, D-1 to D-6.

## 5. Design

### 5.1 Modules (each under 600 lines)

```
bk-decomp-typeop/src/
  lib.rs            what the crate is, re-exports
  error.rs          TypeOpError
  env.rs            TypeOpEnv, TableTypeEnv (tests)
  table.rs          TypeOps, OpTyping, Language, boolean_flip, the 73 rows
  cx.rs             Cx, PropCx, Slot, TempTypes
  facing.rs         facing types, local_type
  local.rs          output_local, input_local
  token.rs          output_token
  input_cast.rs     input_cast
  propagate/
    mod.rs          propagate_type, the policy trait, the unit list
    simple.rs       COPY, MULTIEQUAL, INDIRECT, the comparisons, logic, SEGMENTOP, NEW
    memory.rs       LOAD, STORE, to_pointer, from_pointer
    pointer.rs      INT_ADD, PTRADD, PTRSUB, add_in2out, add_pointer
    piece.rs        PIECE, SUBPIECE
  names.rs          operator_name, float_sign_manipulation, absorb_zext,
                    preferred_zext_size, the byte offsets
  cast/
    mod.rs          CastStrategy, the predicates of 4.8.7 to 4.8.9
    standard.rs     cast_standard (C and Java)
    promotion.rs    Promotion, 4.8.3 to 4.8.6
  union/
    edge.rs         ResolveEdge, ResolvedUnion
    map.rs          UnionMap and its nine methods
    flow.rs         find_resolve, resolve_in_flow, the truncations,
                    find_compatible_resolve, score_single_component
    score/
      mod.rs        the three entry points, run, limits, ScoreScratch
      down.rs       down trials
      up.rs         up trials, score_constant
      helpers.rs    score_locked, score_parameter, score_return,
                    deref_pointer, score_truncation
    cache.rs        ResolveCache
  access.rs         AccessTable, AccessRow, AccessKind
```

Per-opcode behaviour is a `match` on the opcode inside each query, not a
trait object per opcode: the set is closed (`LOOP.md`, enums for closed
sets) and the four queries dispatch differently.

### 5.2 Public API (sketch)

```rust
pub enum Language { C, Java }
pub enum Slot { Out, In(u16) }

#[derive(Clone)]
pub struct TypeOps { /* 75 OpTyping entries, language, near/far sizes, policies */ }
impl TypeOps {
    pub fn new(lang: Language, types: &TypeFactory) -> Self;
    pub fn language(&self) -> Language;
    pub fn set_language(&mut self, lang: Language);          // adjustTypeOperators
    pub fn typing(&self, opc: OpCode) -> Option<OpTyping>;   // Untyped | Typed { out, input }
    pub fn symbol(&self, opc: OpCode) -> &'static str;       // getName, in the variant
    pub fn cast(&self) -> CastStrategy;
    pub fn with_policy(self, opc: OpCode, policy: Arc<dyn PropagationPolicy>) -> Self;
    pub fn with_scorer(self, scorer: Arc<dyn UnionScorer>) -> Self;
}
pub const fn boolean_flip(opc: OpCode) -> Option<OpCode>;
pub static TYPEOP_UNITS: &[UnitInfo];                        // 74 entries

pub struct Cx<'a> {            // everything a read-only query needs
    pub ops: &'a TypeOps,
    pub ssa: &'a Ssa,
    pub types: &'a mut TypeFactory,   // queries create pointer and base types
    pub env: &'a dyn TypeOpEnv,
    pub unions: &'a UnionMap,
}
pub fn output_local(cx: &mut Cx, op: OpId) -> Result<TypeId>;
pub fn input_local(cx: &mut Cx, op: OpId, slot: usize) -> Result<TypeId>;
pub fn local_type(cx: &mut Cx, vn: VarnodeId) -> Result<(TypeId, bool)>;
pub fn output_token(cx: &mut Cx, op: OpId) -> Result<TypeId>;
pub fn input_cast(cx: &mut Cx, op: OpId, slot: usize) -> Result<Option<TypeId>>;
pub fn write_operator_name(cx: &Cx, op: OpId, out: &mut dyn fmt::Write) -> fmt::Result;
pub fn type_read_facing(cx: &Cx, vn: VarnodeId, op: OpId) -> TypeId;     // and the other three

pub struct TempTypes { /* Vec<TypeId> indexed by varnode, TypeId::NONE when unset */ }
pub struct PropCx<'a> {        // propagation also writes the union map
    pub ops: &'a TypeOps, pub ssa: &'a Ssa, pub types: &'a mut TypeFactory,
    pub env: &'a dyn TypeOpEnv, pub unions: &'a mut UnionMap, pub temp: &'a TempTypes,
}
pub fn propagate_type(cx: &mut PropCx, alt: TypeId, op: OpId, from: Slot, to: Slot)
    -> Result<Option<TypeId>>;
pub trait PropagationPolicy: Send + Sync {
    fn unit(&self) -> &'static UnitInfo;
    fn propagate(&self, cx: &mut PropCx, alt: TypeId, op: OpId, from: Slot, to: Slot)
        -> Result<Option<TypeId>>;
}

#[derive(Clone, Copy)]
pub struct CastStrategy { /* language, promote_size */ }
impl CastStrategy {
    pub fn cast_standard(&self, types: &TypeFactory, req: TypeId, cur: TypeId,
                         care_uint_int: bool, care_ptr_uint: bool) -> Option<TypeId>;
    pub fn local_extension_type(&self, cx: &Cx, vn: VarnodeId, op: Option<OpId>) -> Promotion;
    pub fn int_promotion_type(&self, cx: &Cx, vn: VarnodeId) -> Promotion;
    pub fn check_int_promotion_for_compare(&self, cx: &Cx, op: OpId, slot: usize) -> bool;
    pub fn check_int_promotion_for_extension(&self, cx: &Cx, op: OpId) -> bool;
    pub fn is_extension_cast_implied(&self, cx: &Cx, op: OpId, read_op: Option<OpId>) -> bool;
    pub fn arithmetic_output_standard(&self, cx: &mut Cx, op: OpId) -> Result<TypeId>;
    pub fn is_subpiece_cast(&self, types: &TypeFactory, out: TypeId, input: TypeId, offset: u32) -> bool;
    pub fn is_subpiece_cast_endian(&self, …, big_endian: bool) -> bool;
    pub fn is_sext_cast(&self, types: &TypeFactory, out: TypeId, input: TypeId) -> bool;
    pub fn is_zext_cast(&self, types: &TypeFactory, out: TypeId, input: TypeId) -> bool;
    pub fn needs_explicit_unsigned(&self, cx: &Cx, op: OpId, slot: usize) -> bool;
    pub fn needs_explicit_long(&self, cx: &Cx, op: OpId, slot: usize) -> bool;
}

pub struct ResolveEdge { /* type_id: u64, encoding: i32, time: u32; Ord in this order */ }
pub struct ResolvedUnion { /* resolve, base: TypeId; field: i32; lock: bool */ }
#[derive(Default)]
pub struct UnionMap { /* BTreeMap<ResolveEdge, ResolvedUnion>, ScoreScratch */ }
impl UnionMap { /* the nine methods of 4.9; clear; iter (dump order); insert_raw (load) */ }

pub fn find_resolve(cx: &Cx, t: TypeId, op: OpId, slot: Slot) -> TypeId;
pub fn resolve_in_flow(cx: &mut PropCx, t: TypeId, op: OpId, slot: Slot) -> Result<TypeId>;
pub fn find_truncation(cx: &Cx, t: TypeId, off: i64, size: i32, op: OpId, slot: Slot)
    -> Option<(FieldRef, i64)>;
pub fn resolve_truncation(cx: &mut PropCx, t: TypeId, off: i64, op: OpId, slot: Slot)
    -> Result<Option<(FieldRef, i64)>>;
pub fn find_compatible_resolve(types: &TypeFactory, t: TypeId, ct: TypeId) -> i32;
pub trait UnionScorer: Send + Sync { /* the three entry points of 4.11 */ }

pub struct AccessRow { pub base: VarnodeId, pub offset: u64, pub size: i32,
                       pub stride: u64, pub kind: AccessKind, pub op: OpId }
pub enum AccessKind { Read, Write, Address }
pub fn access_row(ssa: &Ssa, op: OpId) -> Option<AccessRow>;
```

`Result` is `Result<_, TypeOpError>`: `Types(#[from] TypeError)`,
`NoOutput(OpId)`, `NoHigh(VarnodeId)`, `NullLocalType(VarnodeId)` (text
`NULL local type`), `BadSlot { op, slot }`, `NotAnOp(OpId)`. A query on a
destroyed or malformed op is an error, never a panic (ADR-009).

### 5.3 Data layout, allocation, concurrency

* `TypeOps` is 75 small entries in an array indexed by the opcode's
  number, `Clone`, `Send + Sync`; part of the frozen architecture state
  (`decomp-core.md` 4.A.1). A language switch replaces six entries.
  Policy overrides are `Option<Arc<dyn …>>` per opcode: `None` runs the
  built-in match with no dynamic call, so the `ghidra` profile pays
  nothing for the hook.
* `CastStrategy` is two words, `Copy`.
* `UnionMap` belongs to one function (`Send`). Keys are 16 bytes,
  values 16 bytes; a `BTreeMap` (ordered iteration for the dump; a few
  to a few hundred entries).
* **The scoring walk is the hot path** (up to 1,024 trials per call,
  one call per unresolved edge per propagation pass). `ScoreScratch`,
  owned by the `UnionMap`, keeps the score and field vectors, the two
  trial vectors (swapped between passes) and the visited set between
  calls; a call clears and reuses them and allocates only when a
  capacity grows. A trial is 24 bytes (`VarnodeId`, `OpId`, slot,
  direction, `max_length`, `TypeId`, index). The visited set is a hash
  set of `(VarnodeId, u16)`; it is never iterated (4.15).
* The per-op queries allocate nothing themselves. `CPOOLREF` collects
  its reference offsets into a stack buffer. Types are created through
  the factory, where the common requests are a cache hit
  (`decomp-types.md` 5); the types a query creates land in the
  function's type fork (`decomp-types.md` 4.10) and are inferred types
  in ADR-025 3e's sense.
* `TempTypes` is a dense vector by varnode index, sized by
  `Ssa::varnode_bound()`.
* How the trait keeps the crate below core: every fact of function or
  architecture state is asked through `&dyn TypeOpEnv`; the crate names
  no type of `bk-decomp-core`. Tests use `TableTypeEnv` (high types by
  varnode, with "the varnode's own type" as the default; call
  prototypes by op; one function prototype; user-op answers by index;
  constant-pool records; float formats from `bk-pcode`).

### 5.4 Benchmarks (ADR-012)

`score_union_fields` on a synthetic graph that reaches the 1,024-trial
limit; `input_cast` + `output_token` over every op of a 10,000-op
function; `propagate_type` over every edge of the same. Numbers and
commands go to `PERF.md`.

### 5.5 Plugin binding constraints (ADR-037)

Engine-internal; typed errors; `TypeOpEnv`, `PropagationPolicy` and
`UnionScorer` are object-safe; ids are plain `u32` newtypes; nothing
holds a borrow across calls.

## 6. Tests and oracle

Kinds **S** (self-contained), **G** (needs the spec root), **L** (needs
the live reference tools), as in plan 4.5.

### 6.1 Ghidra's unit tests (S)

The five tests of `UT/testtypes.cc`, checklist line
`unittests/testtypes.cc` of `docs/inventory/tests/decompiler-cpp.md`
(ids `cast_basic`, `cast_pointer`, `cast_enum`, `cast_compare`,
`cast_integertoken`; D02 ported the other three; this track ticks the
line). Read, 20–214: the fixture builds `x86:LE:64:default:gcc`, a
function with high variables on, and for a unary opcode an op `out =
opc(in)` with `out` typed `t1` and `in` typed `t2`, for a binary opcode
`opc(in0: t1, in1: t2)` with a 1-byte output; `castPrinted` is
`getInputCast(op, 0, strategy) ≠ null`. `longPrinted` builds a shift of
a constant typed `t1` by a 4-byte variable and asks
`markExplicitLongSize(op, 0)`. The ops are in no block.

They port with a table environment and no loaded state: D02's test
factory for that architecture (`decomp-types.md` 6, item 1), an `Ssa`
with free ops, `TableTypeEnv` with high types equal to the varnodes'
types. One `rstest` table per Ghidra test, 11 + 11 + 3 + 10 + 7 = 42
cases, each case one assertion of the original.

### 6.2 The oracle table (S replay, L regeneration)

**Generator**: `crates/bk-decomp-typeop/tests/oracle/typeop.cc`, from
the prototype `docs/research/decomp-wave3/typeop_oracle.cc`, built by
`regen.sh` with `docs/research/decomp-wave3/build.sh`'s flags. It links
Ghidra's objects, builds an architecture from an empty `<binaryimage>`,
a function with one block and high variables on, and writes
tab-separated rows; `typeop REF ARCH [SECTIONS]`.

**The grid**: 39 types: `bool`, `char`, the signed, unsigned and
undefined integers of 1, 2, 4, 8 bytes, `wchar2`, `float4`, `float8`,
pointers to `void`, `int4`, `uint4`, `char`, `xunknown1`, `float8`,
`int4 *` and `code`, two arrays, a structure `sone { int4 a; int4 b; }`
and a pointer to it, a single-field structure, unions `uone { int8 l;
float8 d; int4 *p; int1 a[8]; }` and `utwo { int4 i; float4 f; }` with
pointers, an enumeration and a pointer to it, a typedef of `int4`, a
relative pointer into `sone`, a partial union and a partial structure.
A type prints as its name, or structurally when anonymous
(`*{8,1}(int4)`, `rel{8,1,4}(int4|sone)`), so the replay needs no spec
root.

**Sections** (row counts for `x86:LE:64:default:gcc`):

| Rows | Content | Count |
|---|---|---|
| `H`, `T` | format `bk-typeop-oracle 1`, architecture, pointer, int and far-pointer sizes; the grid | 1 + 39 |
| `P` | per opcode: names in both variants, flags, `addlflags`, boolean flip | 73 |
| `S` | `castStandard` for every pair of grid types, the four flag combinations, both strategies | 12,168 |
| `Z` | `isSextCast`, `isZextCast`, `isSubpieceCast` at offsets 0 and 1, `isSubpieceCastEndian` little and big, per pair and strategy | 3,042 |
| `O` | per variant, opcode, operand shape, operand types and output type: `getOutputLocal`, `getInputLocal` per slot, `getOutputToken`, `getInputCast` per slot, `getOperatorName`, every non-null `propagateType` edge, `markExplicitUnsigned` per constant input, `markExplicitLongSize(0)`. Shapes: plain variables; the second operand one of seven constants (typed as the first operand, and as an integer for pointers); the first operand a constant; the first operand a spacebase; for `INT_ADD` the second operand a product by a constant; the pointer of a `LOAD`/`STORE` an implied `CAST` output; `PTRADD`/`PTRSUB` with constant and variable indices and three element sizes; `SUBPIECE` at every aligned offset | 162,664 |
| `X` | integer promotion: ten small types × sixteen ways the value is produced (free, explicit, two constants, twelve defining opcodes) × fifteen readers × four shapes of the other operand: `localExtensionType`, `intPromotionType`, the compare or extension check, `getInputCast(0)` | 320 |
| `E` | `isExtensionCastImplied`: both extensions, four output types, fourteen readers, both slots, five shapes of the other operand, with and without a reading op | 2,096 |
| `R` | `CALL`/`CALLIND` with no call specification, an unlocked one and the locked `int4 f(int4 *, uint8)`; `RETURN` in a `void` and an `int4` function, in and out of a block; `CALLOTHER` for four user ops | 18 |
| `U` | `ScoreUnionFields`: the score vector, the chosen field, the resolved type and the trial count, for four parents, every slot of 65 opcodes, three shapes of the other operand, seven second-level readers; the two truncation constructors on six opcodes at every aligned offset | 6,524 |

**Runs** (X8): `x86:LE:64:default:gcc` 186,945 rows;
`x86:LE:16:Real Mode:default` (near pointer 2, far pointer 4: the only
rows where `PIECE`, `SUBPIECE` and `SEGMENTOP` resize pointers) 185,208;
`PowerPC:BE:32:default:default` (big endian) 191,186. Two runs identical
on each machine; **Mac and build host identical** for all three (sha256
prefixes `110d0ef8…`, `5df62f6d…`, `9e65aee7…`), about 25 s each.

**Replay**: the test parses the `T` rows into the factory with D02's C
parser and factory calls, builds each row's op in an `Ssa` (one block,
`TableTypeEnv`), calls the Basilisk function and compares every field.
The three tables are checked in gzip-compressed (about 0.8 MB each)
with a `.gitattributes`-safe binary extension; the table is generated
on both reference builds and the regeneration script fails if they
differ.

**What the D08 track adds to the prototype** before it relies on the
table (its known gaps, X8): (a) `U` rows through `resolveInFlow`,
`resolveTruncation`, `findResolve` and `findCompatibleResolve` with a
union map that already holds entries (locked, address-based, of another
size), printing the map after each call in the dump's `U` form; (b) the
nine map methods on scripted sequences; (c) `scoreSingleComponent` for
the single-field structure and a one-element array at `COPY`, `LOAD`,
`STORE`, a call with a locked prototype; (d) `INT2FLOAT` absorbing a
`ZEXT`; (e) pointers with an address-space attribute and a
variable-length structure in `S`; (f) second-level shapes of `U` that
vary with the first op's continuation, and a chain deep enough to hit
the 6-pass and 1,024-trial limits; (g) `ResolveCache`; (h)
`Varnode::getLocalType`. Each is a section of the same generator.

### 6.3 Union resolution on real functions (L, S subset)

The final and intermediate state dumps of the data tests that use
unions and single-field structures — `union_datatype.xml`,
`partialunion.xml`, `impliedfield.xml`, `piecestruct.xml`,
`packstructaccess.xml` — carry the map as `U` records (`@function`:
type id, op time, encoding, base type, resolved type, field, lock;
`tools/reference/README.md`, "State dumps"). Tests:

* round trip: every `U` record of D00's captures loads into `UnionMap`
  and writes back byte for byte (S for a checked-in subset, L for all);
* replay: from the dump taken at the start breakpoint of
  `ActionInferTypes`' successor at each of its runs, for every `U`
  record whose edge still exists and that is not locked, clearing the
  entry and calling `resolve_in_flow` on the edge's type gives the
  recorded field and resolved type. Entries that depend on propagation
  state the dump does not hold (the temporary types) are listed and
  skipped by name, with their count stated in the test; the full check
  is D11's state comparison after `infertypes`.

### 6.4 Other tests

* **Cross-check with D05** (S): `write_operator_name` equals D05's raw
  name for every `O` row; `boolean_flip` and the reorder bit against
  the `P` rows.
* **Properties** (`proptest`): no query panics on any op of a random
  well-formed `Ssa` with random grid types; `find_resolve` after
  `resolve_in_flow` on the same edge returns the same type;
  `set_union_field` never changes a locked entry's field;
  `cast_standard(t, t, …)` is `None`; scoring terminates within 1,024
  counted trials.
* **Access rows** (S, L): `AccessTable::rebuild` gives one row per
  live `LOAD`, `STORE`, `PTRADD`, `PTRSUB` of each captured final
  state.
* **Benchmarks**: 5.4.
* No fuzz target: the crate parses nothing.

## 7. Acceptance

1. The five unit tests ported (42 cases) and the checklist line ticked.
2. The three oracle tables replay with every row equal, on Linux, macOS
   and Windows; the tables were generated on both reference builds and
   are identical.
3. The additions (a) to (h) of 6.2 are in the generator and replay.
4. 6.3's round trip and replay pass for the five data tests.
5. `TYPEOP_UNITS` has 74 entries; a test profile that replaces the
   `INT_ADD` policy changes only `INT_ADD` rows of the replay.
6. No `unsafe`; no panic on any input (property tests); the gate green
   on the build host with and without the reference; benchmarks in
   `PERF.md`.
7. `bk-decomp-core`'s step A9 compiles against the trait (checked by
   that track).

## 8. Differences from Ghidra

Deliberate departures (ADR-001):

- The crate sees function and architecture state through `TypeOpEnv`;
  the union map, the temporary types and the access table are values
  passed in.
- Per-opcode behaviour is functions over a table, not a class per
  opcode. One `Language` value selects both the operator variant and
  the cast strategy (Ghidra switches them together).
- `markExplicitUnsigned`, `markExplicitLongSize` and
  `ResolveCache::inheritResolution` answer and leave the IR edit to the
  caller.
- The access table (ADR-025 3e) and the unit hooks (4.14) have no
  Ghidra counterpart and no effect on the `ghidra` profile.

Defined where Ghidra crashes or is undefined (ADR-024's form; each to
be recorded in `docs/GHIDRA-BUGS.md`):

- **D-1** A local type or token asked of an op without an output
  (`typeop.cc:266`): `TypeOpError::NoOutput`.
- **D-2** A high type asked of a varnode without a high variable
  (`varnode.cc:686`, `700`): `TypeOpError::NoHigh`.
- **D-3** A `CALLOTHER` whose index names no user op
  (`typeop.cc:858–859`, `868–869`: no null test, unlike 845): the
  default type.
- **D-4** A facing type asked with no op — `getTypeDefFacing` of an
  unwritten varnode (`varnode.cc:663`), `intPromotionType` of a
  constant without exactly one reader (`cast.cc:185`) — when the type
  needs resolution: the unresolved type.
- **D-5** `findResolve` and the other IR-bound type methods on an op in
  no block (`op->getParent()->getFuncdata()`, `type.cc:1230` and the
  like): Basilisk needs no block; the map is passed in.
- **D-6** `propagateAddPointer` reading a temporary type that was never
  set (`typeop.cc:1336`; `Varnode`'s constructor does not initialise
  `temp`): "not a pointer". Unreachable in Ghidra today (only
  `ActionInferTypes`, which sets every temporary type first, propagates
  across `INT_ADD`).

Reproduced on purpose (odd, deterministic; each pinned by the oracle or
by `U` records):

- **R-1** `ResolveEdge` keys a type by its 64-bit id, which is 0 for
  anonymous types: one-element arrays and pointers to anonymous types
  share an entry on one edge.
- **R-2** The address-based edge keeps the low 32 bits of the offset
  and neither the space nor the slot.
- **R-3** `TypeUnion::resolveInFlow` stores the address-based record
  itself (`type.cc:2492`) while `TypePointer::resolveInFlow` stores the
  newly built one (1237).
- **R-4** `INDIRECT`'s input 1 is typed as a code pointer of input 0's
  size (`typeop.cc:2141`).
- **R-5** `CALL` applies a size test to a locked parameter and
  `CALLIND` does not (707 against 764).
- **R-6** An op reading one varnode twice resolves it through the first
  slot (`getSlot`).
- **R-7** `set_union_field` skips the `MULTIEQUAL` copy when the update
  changed nothing.

## 9. Status

Specified; not implemented. Sections 2 to 4 were read from the source
line by line; the rules marked **(ran, X8)** are pinned by the oracle
prototype on both reference builds. Read only, not run: 4.9 (the map's
methods), 4.10, 4.12, `local_type`, and the parts of 4.11 the
prototype's shapes do not reach (6.2, the list of additions). 4.13 and
4.14 are designs.

## 10. Implementation plan

Each step ends with a green gate (`scripts/remote.sh gate`, both
forms). Needs merged: D02, D03, D05, D06.

| Step | Content | Evidence at the step's end |
|---|---|---|
| T1 | Crate, `error`, `env` with `TableTypeEnv`, `table` (`TypeOps`, both variants, `boolean_flip`), `cx`, the generator moved to `tests/oracle/` with `regen.sh`, the three tables checked in | `P` rows replay; cross-check with D05's `OpProps` |
| T2 | `facing`, `local`, `names` | `O` rows: output and input local types, operator names; `R` rows |
| T3 | `cast/standard`, the predicates of 4.8.7 and 4.8.8 | `S`, `Z` rows |
| T4 | `cast/promotion`, `token`, `input_cast`, the marks of 4.8.9 | `O` rows: tokens, input casts, marks; `X`, `E` rows; the five unit tests |
| T5 | `propagate/*` with `TempTypes`; the policy trait and `TYPEOP_UNITS` (needs `UnitKind::TypePolicy` in D05) | `O` rows: propagation; acceptance 5 |
| T6 | `union/edge`, `union/map` | generator additions (b); `U`-record round trip (6.3) |
| T7 | `union/score/*` with `ScoreScratch`; the scorer trait | `U` rows; additions (f); the scoring benchmark |
| T8 | `union/flow`, `union/cache`, `local_type` | additions (a), (c), (g), (h); 6.3's replay |
| T9 | `access`; the remaining additions (d), (e); property tests; benchmarks; status | acceptance 1 to 6 |

T3 and T6 depend only on T1; T7 on T6. After T2 the steps T3–T5 and
T6–T8 are two independent lines.

## 11. Open items

1. `UnitKind::TypePolicy` in D05 (misfit 3). Until it exists T5 keeps
   the unit list behind a `cfg`-free constant of its own type and
   registers nothing.
2. Whether `high_type` should take `&mut` access to refresh a dirty
   high variable is settled with `decomp-core.md` 4.A.11; the trait as
   written assumes core keeps high types current before it lends
   itself as an environment.
3. `AccessRow` for `PTRADD` and `PTRSUB` is this document's design; the
   consumer (the type-unification work ADR-025 leaves open) may want
   the root pointer and the accumulated offset instead. The table is
   rebuilt from the IR, so changing the rule later costs nothing.
