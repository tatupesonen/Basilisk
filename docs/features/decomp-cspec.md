# Compiler specifications and prototype models (`bk-cspec`)

Track `decomp-cspec` (D03 of `docs/features/decomp-plan.md`), milestone
M3, wave 1. Format of this document: `docs/LOOP.md`, "Feature documents".
Leaf track: it depends on no other decompiler crate.

Path abbreviations: `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/`, `UT/` =
`…/decompile/unittests/`, `P/` = `Ghidra/Processors/`, `JT/` =
`Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/program/model/lang/`,
under `../ghidra`.

## 1. Purpose

A `.cspec` file says how a compiler uses a processor: the stack pointer,
which memory is global, the data organisation, and above all the
**prototype models** — the calling conventions: which registers and stack
slots carry which parameters and return values, what a call preserves and
destroys. This crate reads the file and implements the models in both
directions: given a function's signature, assign storage to each
parameter; given the storage locations a function is seen to use, decide
which are parameters. The decompiler needs both; so does the program
model (function signatures in the database, M4), which is why the crate
is not in the decompiler's namespace and sees data types only through a
query trait.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/fspec.hh`, `CPP/fspec.cc` | `ParamEntry`, `ParamEntryRange`, `ParamList` and its five implementations, `ParamTrial`, `ParamActive`, `ParameterPieces`, `PrototypePieces`, `EffectRecord`, `ProtoModel`, `UnknownProtoModel`, `ScoreProtoModel`, `ProtoModelMerged`, `ProtoParameter`/`ParameterBasic`, `ProtoStore`/`ProtoStoreInternal`, `FuncProto`. **Authoritative.** Not `FuncCallSpecs`, `FspecSpace`, `ParameterSymbol`, `ProtoStoreSymbol` |
| `CPP/modelrules.hh`, `CPP/modelrules.cc` | All of it: `PrimitiveExtractor`, the data-type and qualifier filters, the assign actions, `ModelRule`, `HiddenReturnAction`, `ShareStackAction` |
| `CPP/architecture.cc` | `parseCompilerConfig` and the `decode*` functions it calls (`decodeProto`, `decodeDefaultProto`, `decodeProtoEval`, `decodeStackPointer`, `decodeReturnAddress`, `decodeSpacebase`, `decodeNoHighPtr`, `decodePreferSplit`, `decodeAggressiveTrim`, `decodeGlobal`, `decodeReadOnly`, `decodeFuncPtrAlign`, `decodeDeadcodeDelay`, `decodeInferPtrBounds`), `createModelAlias`, `setDefaultModel`, `addSpacebase`, `addNoHighPtr`; of `parseProcessorConfig` only what `bk-lang` does not already keep (see 4.1) |
| `CPP/pcodeinject.hh`/`.cc` (`InjectPayload`, `InjectParameter`, `PcodeInjectLibrary::decodeInject` and the name/id tables), `CPP/userop.cc` (`decodeCallOtherFixup`, `decodeSegmentOp`, `decodeJumpAssist`) | The **declarations** only: names, kinds, parameters, the uncompiled body text |
| `CPP/rangemap.hh` | The interval container `ParamEntryRange` lives in |
| `UT/testfuncproto.cc` (21), `UT/testparamstore.cc` (5) | Tests |
| `JT/AbstractProtoModelTest.java` and nine subclasses (13 tests) | Tests: tables of signature → storage for the shipped models |
| Java `ghidra.program.model.lang.{PrototypeModel, ParamListStandard, ParamEntry, …}` and `ghidra.program.model.lang.protorules.*` in `Framework/SoftwareModeling` | The Java twin of the same rules. **The C++ is authoritative**; where a Java test's expectation differs from what the C++ gives, the difference is recorded, the test asserts the C++ result and lists the Java one |
| `P/*/data/languages/*.cspec` | 107 files, 180 `<prototype>`, 6 `<resolveprototype>`, 1,558 `<pentry>`, 230 `<rule>`, 81 `<callfixup>`, 37 `<callotherfixup>` (counted) |
| `Ghidra/Framework/SoftwareModeling/data/languages/compiler_spec.rxg` | The schema; useful as a list of what may appear, not as the definition of behaviour |

## 3. Scope

**In:**
1. Reading a `.cspec` (and a `<specextensions>` document) into a
   `CompilerSpec` value.
2. Prototype models: storage assignment (`assignParameterStorage`,
   `assignMap`), trial classification (`deriveInputMap`,
   `deriveOutputMap`, `fillinMap`), every query `ParamList` and
   `ProtoModel` declare for the engine (`possibleParam`,
   `characterizeAsParam`, `getBiggestContainedParam`,
   `unjustifiedContainer`, `assumedExtension`, `getSpacebase`,
   `getRangeList`, `getMaxDelay`, `checkJoin`, `checkSplit`, `hasEffect`,
   … — take the list from the two class declarations), merged
   models and model scoring, model aliases.
3. `FuncProto` with an internal store: flags, model, parameters, effect
   list, likely-trash list, inject id, extra-pop, its XML, `setPieces`/
   `getPieces`, `updateAllTypes`, locking, comparison helpers.
4. `ParamTrial` and `ParamActive` as plain data with their operations.
5. Declarations of call fixups, callother fixups, segment ops and
   call-mechanism payloads, uncompiled.
6. ADR-025: the `FunctionSummary` type (3d) and provenance on prototype
   pieces (3f).

**Crate owned:** `bk-cspec`. Dependencies: `bk-core`, `bk-marshal`,
`bk-lang` (to find a language's `.cspec` path; nothing else of it). It
does **not** depend on `bk-decomp-types`.

**Not in this track:**
- `FuncCallSpecs` (a call site in a function's data-flow), the
  `Varnode`-facing parts of parameter recovery (`ParamActive` users in
  `coreaction.cc`, `AncestorRealistic`), symbol-backed parameter stores:
  D07.
- Compiling or running injection payloads: D18, on `bk-sleigh-snippet`.
- Creating address spaces in a live manager. `<stackpointer>` and
  `<spacebase>` are *described* here; a helper applies a `CompilerSpec`
  to a `bk_core::SpaceManager` (adds the spacebase spaces, marks
  no-high-pointer ranges, sets dead-code delays) because the tests need
  the stack space, but owning the program's manager is D07's.
- `<data_organization>` and `<enum>`: this crate keeps the element
  (position in the document) and exposes it for `bk-decomp-types` (and
  later `bk-datatypes`) to decode; it does not interpret it.
- The symbol table: `<global>` ranges are data in the `CompilerSpec`.

## 4. Behaviour

### 4.1 Reading the file
`parseCompilerConfig` walks the children of `<compiler_spec>` in document
order. Element by element (handler in parentheses):

| Element | Result in `CompilerSpec` |
|---|---|
| `<default_proto>` (`decodeDefaultProto`) | Its child `<prototype>` is decoded and becomes the default model; a second one is "More than one default prototype model" |
| `<prototype>`, `<resolveprototype>` (`decodeProto`) | A `ProtoModel` or `ProtoModelMerged`, registered by name; "Duplicate ProtoModel name: …" |
| `<modelalias name parent>` (`createModelAlias`) | The parent model under a second name. Errors: "Requesting non-existent prototype model: …", "Cannot make alias of merged model: …", "Cannot make alias of an alias: …", "Duplicate ProtoModel name: …" |
| `<eval_current_prototype>`, `<eval_called_prototype>` (`decodeProtoEval`) | The models used to evaluate the current function and called functions; each at most once; "Unknown prototype model name: …" |
| `<stackpointer register space growth reversejustify>` (`decodeStackPointer`) | The official stack: base space, register (truncated to the space's address size when the space is truncated), growth direction (`growth="negative"` or anything else = positive; default negative), reverse justification. "… element missing "space" attribute" |
| `<spacebase name register space>` (`decodeSpacebase`) | A further register-relative space |
| `<returnaddress>` (`decodeReturnAddress`) | Default return-address storage; "Multiple <returnaddress> tags in .cspec" |
| `<global>` (`decodeGlobal`) | `RangeProperties` of memory that holds global variables |
| `<readonly>`, `<nohighptr>`, `<prefersplit>`, `<aggressivetrim>`, `<funcptr align>`, `<deadcodedelay space delay>`, `<inferptrbounds>` | Read-only ranges, ranges where constants are never pointers, registers to split (`PreferSplitRecord`), the sign-extension trim flag, function-pointer alignment, per-space dead-code delay, pointer-inference bounds |
| `<data_organization>`, `<enum>` | Kept for the type system (section 3) |
| `<context_data>` | Kept as an element for the context database (three Go files have one) |
| `<callfixup>`, `<callotherfixup>`, `<segmentop>` | Declarations (4.6) |

After the elements, in this order (`parseCompilerConfig`, end): the
optional `<specextensions>` document (`prototype`, `callfixup`,
`callotherfixup`, `global`); the default model is the first model if none
was named ("No default prototype specified" if there is none); a
`__thiscall` alias of the default model is created when no model has that
name. An element this reader does not know is an **error** naming it
(Ghidra's loop would not terminate; inventory 3.1); so is a
`<specextensions>` child of another kind. Ghidra reads the
`<specextensions>` fix-ups and globals with the wrong decoder (inventory
3.1); read them from the extension document.

Registers are named in the file (3,975 `<register name=…>` and the
`piece1…` attributes of `<addr space="join">`); resolve them through
`bk_core::RegisterLookup`, which the caller supplies (from `bk-sla`/
`bk-language` when they exist; from a table built in test code before).
An unknown register is an error naming the register and the element.

The reader also needs the space manager (for `<addr>`, `<range>`,
`space=` attributes) and, for the stack-dependent defaults of 4.2, to
have applied `<stackpointer>` before any `<prototype>` is decoded:
**Ghidra's models read the stack space at decode time**
(`ProtoModel::decode` asks `glb->getStackSpace()` for the growth
direction and for the default ranges). In all 107 files `<stackpointer>`
comes before the first prototype (counted), so the order is not a
problem for the shipped files; for any other file, decode in document
order against the manager as it is at that point, as Ghidra does, so
that a prototype placed before `<stackpointer>` is decoded without a
stack — do not reorder.

Of the `.pspec`, `parseProcessorConfig` consumes `<volatile>`,
`<incidentalcopy>`, `<context_data>`, `<jumpassist>`, `<segmentop>`,
`<register_data>`, `<data_space>`, `<inferptrbounds>`; `bk-lang` already
reads the file. This track adds nothing to `bk-lang`; where the
decompiler needs one of these in a form `bk-lang` does not offer, list it
in the status report for D07.

### 4.2 `ProtoModel`
Fields: name, `extrapop` (bytes a call pops beyond the return address;
`extrapop="unknown"` is the sentinel `extrapop_unknown`), input and
output `ParamList`, `effectlist`, `likelytrash`, `internalstorage`,
`injectUponEntry`/`injectUponReturn`, `localrange`, `paramrange`,
`stackgrowsnegative`, `hasThis`, `isConstruct`, `isPrinted`, shared
actions. `ProtoModel::decode`:

* Attributes `name`, `extrapop` (required: "Missing prototype
  attributes"), `stackshift` (accepted and ignored), `strategy`,
  `hasthis`, `constructor`; any other is "Unknown prototype attribute".
  A model named `__thiscall` has `hasThis` set.
* `strategy`: empty or `standard` → `ParamListStandard` in,
  `ParamListStandardOut` out; `register` → `ParamListRegister` in,
  `ParamListRegisterOut` out; else "Unknown strategy type: …". (26
  prototypes in the corpus use `register`.)
* Children: `<input>`, `<output>`, `<unaffected>`, `<killedbycall>`,
  `<returnaddress>`, `<localrange>`, `<paramrange>`, `<sharestack>`,
  `<likelytrash>`, `<internal_storage>`, `<pcode>` (a call-mechanism
  payload; it is "upon entry" if its name contains `uponentry`, else
  "upon return"); anything else is "Unknown element in prototype".
* A `HiddenReturnAction` is always the first shared action.
* Afterwards: the architecture's default return address is added as a
  `return_address` effect when the model named none; the effect list is
  sorted by address (`EffectRecord::compareByAddress`), `likelytrash` and
  `internalstorage` sorted; without `<localrange>` or `<paramrange>` the
  defaults are computed (`defaultLocalRange`, `defaultParamRange` — both
  depend on the stack space and growth direction; port them exactly).
* The parameter range, when the input list has stack entries, comes from
  the list (`input->getRangeList`).

`ProtoModelMerged` (`<resolveprototype>`): a model that stands for a set
of named models and picks one by scoring trials (`ScoreProtoModel`,
`selectModel`); its input list is the union (`ParamListMerged`), its
effects the intersection (`intersectEffects`). `UnknownProtoModel` wraps
a model for a name that was not found.

`hasEffect(addr, size)` (lookup in the sorted effect list, with the
default `unknown_effect`), `lookupEffect`, `lookupRecord` as written.

### 4.3 `ParamEntry` and the lists
`ParamEntry::decode` (`<pentry>`): attributes `minsize`, `maxsize`,
`align` (and old-style `size`), `metatype` or `storage` (a type class:
`string2typeclass`), `extension` (`sign`, `zero`, `inttype`, `float`,
`none`; else "Bad extension attribute: …"; the attribute first clears
the zero, sign and int-type bits); child `<addr>` or `<register>`
(which may be a join). Errors: "Unknown <pentry> attribute", "ParamEntry
not fully specified", "No support for right justification in little
endian encoding", "For positive stack growth, <pentry> size must match
alignment". Derived state: `numslots`, flags (`force_left_justify`,
`reverse_stack`, `smallsize_*`, `extracheck_high`/`low`, `is_grouped`,
`overlapping`, `first_storage`, `is_stackspill`), the join record for a
multi-register entry, and overlap relations with earlier entries
(`resolveJoin`, `resolveOverlap`, `resolveFirst`). Methods to port
unchanged: `justifiedContain`, `containedBy`, `intersects`,
`getContainer`, `assumedExtension`, `getSlot`, `getAddrBySlot` (the stack
allocator: slot counting with alignment, in either growth direction),
`getSpacebase`, `isParamCheckHigh`/`Low`.

`ParamListStandard::decode` (`<input>`/`<output>`): attributes
`pointermax`, `thisbeforeretpointer`, `killedbycall`, `separatefloat`
(default true); children `<pentry>` and `<group>` first, then `<rule>`
("<pentry> and <group> elements must come before any <modelrule>").
Entries are numbered into groups and *resource sections* by type class
(`resourceStart`; with `separatefloat` float entries form their own
section). Afterwards `calcDelay`, `populateResolver` (the per-space
interval maps from address to entry), and **when `pointermax` is
positive a final rule is appended**: a size filter (`pointermax+1` and
up) with `ConvertToPointer`. With `killedbycall`, every entry's storage
is added to the model's effect list as killed by call.

Assignment (`assignMap`): for each parameter in order, the first
`ModelRule` whose filters accept it assigns it; with no matching rule the
default is `assignAddressFallback` — the first entry of the parameter's
type class with a free group (float falls back to general), else the
stack entry; a parameter that fits nowhere throws
`ParamUnassignedError`. `status` holds the next free slot per group.
Position 0 of the result is the return value; `void` is returned with an
invalid address (the tests check `res[0].addr.isInvalid()`).
`ParamListStandardOut::assignMap` adds the fall-back the header
describes: a return value too large for any output entry becomes a
hidden pointer parameter (`hiddenretparm`), and the output is that
pointer. `ParamListRegisterOut`, `ParamListRegister`, `ParamListMerged`
as written.

Trial classification (`fillinMap`, via `deriveInputMap`/
`deriveOutputMap`): given active trials (address, size), mark each as
used or not: match trials to entries, order them by group and slot
(`ParamTrial` ordering: `fixedPosition`, then entry group, then offset),
then per resource section apply the gap rules — `forceExclusionGroup`,
`forceNoUse` (a trial after an unused, unreferenced gap is dropped),
`forceInactiveChain` (a run of more than `maxchain` inactive trials
ends the parameters; `fillinMap` passes 2), `separateSections`, `markGroupNoUse`,
`markBestInactive`. Nine `testfuncproto` tests pin typical cases; the
oracle table pins the rest.

### 4.4 Model rules (`modelrules.cc`)
A `<rule>` has one data-type filter, optional qualifier filters, one
assign action and optional side effects, decoded by element name:

| Element | Class |
|---|---|
| `<datatype name …>` | `DatatypeFilter::decodeFilter` by `name`: `any` → `SizeRestrictedFilter`; `homogeneous-float-aggregate` → `HomogeneousAggregate(TYPE_FLOAT, 4, 0, 0)`; any other name is a metatype (`string2metatype`): `array` → `ArrayFilter`, else `MetaTypeFilter`. Each filter then decodes its own size attributes |
| `<varargs first>`, `<position index>`, `<datatype_at index>` + filter | `VarargsFilter`, `PositionMatchFilter`, `DatatypeMatchFilter`; several are combined by `AndFilter` |
| `<goto_stack>`, `<convert_to_ptr>`, `<join>`, `<join_per_primitive>`, `<join_dual_class>`, `<consume>`, `<hidden_return>`, `<consume_extra>`, `<extra_stack>`, `<consume_remaining>` | `GotoStack`, `ConvertToPointer`, `MultiSlotAssign`, `MultiMemberAssign`, `MultiSlotDualAssign`, `ConsumeAs`, `HiddenReturnAssign`, and as side effects `ConsumeExtra`, `ExtraStack`, `ConsumeRemaining` (read `AssignAction::decodeAction`, `decodePrecondition` and `decodeSideeffect` for which element is allowed where) |
| `<sharestack>` (child of `<prototype>`) | `ShareStackAction` |

Each action's `assignAddress` returns `success`, `fail`, `no_assignment`,
`hiddenret_ptrparam`, `hiddenret_specialreg` or
`hiddenret_specialreg_void` and edits the consumption `status`.
`PrimitiveExtractor` flattens an aggregate into its primitive members
with offsets (flags `unknown_element`, `unaligned`, `extra_space`,
`invalid`, `union_invalid`, `array_primitive`); `MultiSlotDualAssign` classifies eightbytes as general or
float the way the System V x86-64 ABI does; `MultiSlotAssign` joins
several registers (most- or least-significant first, justification);
results that span registers become **join addresses**
(`ParameterPieces::assignAddressFromPieces` → `findAddJoin`), possibly
with padding pieces or a float-extension join.

### 4.5 Types through a trait
The rules look at data types only through these questions (grep of
`modelrules.cc` and the IR-free part of `fspec.cc`): size, aligned size,
alignment, metatype, type class, array element and count, structure and
union members (offset, type), whether a structure has bitfields; and
they *create* three kinds: pointer to a type (with a size and word
size), `void`, and an unknown base of a size. Define
`trait ParamTypes` with an opaque `TypeHandle` (a `u32` newtype) and
those methods. `PrototypePieces`, `ParameterPieces` and `ProtoParameter`
hold `TypeHandle`s. `bk-decomp-types` implements the trait in a later
track; this crate ships a small implementation for its tests
(`testtypes`: primitives, arrays, structures, unions, pointers, with
alignment by a size map) and nothing in `src/` depends on it.

### 4.6 Injection and user-op declarations
`<callfixup name>` with `<target name>` children and a `<pcode>` holding
`<input>`/`<output>` parameter declarations and a `<body>` of SLEIGH
p-code text; `<callotherfixup targetop>`; `<pcode inject="uponentry|
uponreturn">` inside a prototype; `<segmentop space userop farpointer>`
with `<constresolve>` and a `<pcode>`; `<jumpassist>` (in `.pspec`).
Store each as data: kind (`CALLFIXUP`, `CALLOTHERFIXUP`,
`CALLMECHANISM`, `EXECUTABLEPCODE`), name (Ghidra derives names for
call-mechanism payloads from the model name: read `decodeInject`'s
callers), parameters (name, index, size), `paramshift`, `incidentalCopy`,
`dynamic`, the body text verbatim (note `bk-marshal`'s content rule for
CDATA and white space, ADR-011), and the source description used in
error messages. Payload ids are indices in declaration order, as in
`PcodeInjectLibrary::registerInject`, because models store them
(`injectUponEntry`). User-op names referenced by fix-ups are kept as
names; resolving them to indices needs the language (D07).

### 4.7 `FuncProto` (internal store)
The prototype of one function without a symbol table behind it: model
(by name/handle), `ProtoStoreInternal` (return value and parameters as
`ParameterBasic`: name, address, type, flags `typelock`, `namelock`,
`indirectstorage`, `hiddenretparm`, `thisptr`, …), `flags`, own
`effectlist` and `likelytrash` (differences from the model), `injectid`,
`extrapop`, `returnBytesConsumed`. Port: `setPieces`, `getPieces`,
`setModel`, `setInternal`, `updateAllTypes` (assign storage through the
model and fill the store), `setInputLock`/`setOutputLock`/
`setModelLock`, `resolveModel`, `clearUnlockedInput`/`Output`, the
`possible*Param` and `characterizeAsInputParam`-style queries that
delegate to the model when unlocked and to the store when locked,
`getBiggestContainedInputParam`, `unjustifiedInputParam`,
`assumedInputExtension`/`OutputExtension`, `isCompatible`,
`getComparableFlags`, `hasEffect` (own list then the model's),
`encode`/`decode` (`<prototype>` with `<returnsym>`, `<internallist>`,
`<unaffected>`, `<killedbycall>`, `<likelytrash>`, `<inject>`,
`<internal_storage>`…; read both functions for the exact element and
attribute set). The four methods that touch a scope or varnodes
(`setScope`, `updateInputTypes`, `updateOutputTypes`,
`updateOutputNoTypes`) are D07's.

### 4.8 ADR-025 additions
* **Provenance (3f).** `PrototypePieces`, each `ProtoParameter` and the
  `FuncProto` itself carry a `bk_core::Provenance`. It is kept beside
  Ghidra's lock flags and does not replace them: the engine's behaviour
  still follows `typelock`/`namelock` exactly, and provenance takes no
  part in any decision in this crate. It is encoded as an extra attribute
  only by basilisk's own encoder mode, never in the form compared with
  Ghidra's XML.
* **`FunctionSummary` (3d)**: a plain, serialisable value with no
  behaviour in this crate — the function's address; its prototype as
  `PrototypePieces` plus assigned storage; `returns: Always | Never |
  Unknown`; whether it ends in a tail call and to what; the stack change
  (`extrapop` as recovered); per pointer parameter a list of accesses
  (offset, size, stride, read or write); the list of callee addresses;
  and a `Provenance` and confidence for each part. A `CallSite` value
  (caller, address of the call) accompanies the trait question "does
  this call return" that D06 defines. The types live here because the
  program model stores them and must not depend on the decompiler.

## 5. Design

* `CompilerSpec`: immutable after loading, `Send + Sync`; models in a
  `Vec` addressed by `ModelId(u32)` with a name → id map (interned
  names); entries inside a list are a `Vec<ParamEntry>` addressed by
  index, never by reference (Ghidra's `list<ParamEntry>` is used for
  pointer stability only).
* Closed sets are enums: the list strategy (`Standard`, `StandardOut`,
  `Register`, `RegisterOut`, `Merged`), filters, actions, effect kinds,
  assignment results. No trait objects for Ghidra's class hierarchies.
* The per-space resolver (`ParamEntryResolver`, a `rangemap`) becomes a
  sorted `Vec` of intervals with binary search; entries do not change
  after decode.
* Assignment works on a caller-provided `&mut Vec<ParameterPieces>` and
  a small status array on the stack (`SmallVec` or fixed array by group
  count): no allocation per call beyond the output.
* Join addresses are created through the manager's `find_add_join`. A
  `CompilerSpec` is shared, so assignment takes the manager (or a
  per-function join table, `decomp-plan.md` 3.7) as an argument; it must
  not capture one.
* Errors: `CspecError` (`thiserror`) carrying the file, the element path
  and Ghidra's message; `ParamUnassigned` as its own variant since
  callers recover from it.
* Modules: `spec/{reader, elements, extensions, apply}`, `entry`,
  `list/{standard, output, register, merged, resolver, trials}`,
  `rules/{filter, qualifier, action, multislot, dualclass, extractor,
  shared}`, `model/{decode, effects, merged, score, ranges}`,
  `proto/{pieces, store, funcproto, codec}`, `inject` (declarations),
  `summary`, `types` (the trait), `error`. `fspec.cc`'s 5,928 lines and
  `modelrules.cc`'s 1,975 must not become two files.
* ADR-011: nothing on crates.io implements Ghidra's `.cspec` semantics.
  For the interval lookup, `rangemap`/`iset`-style crates are not needed
  for a static sorted vector. `smallvec` is already in the workspace's
  lock file; check before adding.

## 6. Tests

Kinds: **S** self-contained; **G** needs the spec root; **L** needs the
live reference tools (`decomp-plan.md` 4.5).

1. **Port `UT/testfuncproto.cc`** (S), all 21. The Ghidra test loads the
   `Toy:LE:32:default:default` language and adds three models in a
   `<specextensions>` document. Port it self-contained: build in test
   code a space manager with `ram`, `register`, `unique`, a stack space
   on a 4-byte stack pointer and the join space, and a `RegisterLookup`
   with the registers the tests name (`r1`–`r12` at 4 bytes and the
   2-byte low halves `r10l`, `r12l` at the low end of their parents;
   take offsets from `P/Toy/data/languages/toy.sinc` and record them in
   the test), then decode the three model definitions copied from the
   test file, and parse the prototypes with the test-side type model.
   A second version of the same test (G) loads the real Toy `.cspec`
   and `.pspec` and the registers from the reference build's `.sla`
   through whatever register source exists then; until one exists it is
   skipped with the reason. Mark `unittests/testfuncproto.cc`.
2. **Port `UT/testparamstore.cc`** (G), all 5: real `.cspec` files for
   x86-64 gcc and golang, PowerPC 64 BE, MIPS 32 BE, AArch64. Storage
   strings (`EDI`, `XMM0:4`, `stack8:10`, `join XMM0:8 RSI`, `pad:3`)
   are parsed by a ported `parseStore`. Registers: until a `.sla`-backed
   `RegisterLookup` exists, from a checked-in table of exactly the
   registers named in the tests and in those five `.cspec` files,
   dumped once from the reference build by the oracle program of item 4
   (S data, G input). Mark `unittests/testparamstore.cc`.
3. **Port the Java prototype-model tests** (G): `X64PrototypeModelTest`,
   `X64WinPrototypeModelTest`, `X64GoPrototypeModelTest`,
   `AArch64ProtoModelTest`, `MipsPrototypeModelTest`,
   `PowerPCPrototypeModelTest`, `Sparc32ProtoModelTest`,
   `Sparc64ProtoModelTest`, `VarargsStorageTest` (13 tests; their
   tables are several hundred signature → storage rows). They use C
   type names (`int`, `long`, `long double`): map them through the
   file's data organisation as `AbstractProtoModelTest` does. Mark them
   in `docs/inventory/tests/test-integrationtest.md`. A row where the
   C++ model gives a different answer from the Java expectation is kept
   as a documented exception with both values (found by item 4), not
   "fixed".
4. **Oracle tables** (G replay, L regeneration): a C++ program under
   `crates/bk-cspec/tests/oracle/` linked with the reference objects
   that, for **every** language/compiler pair whose `.cspec` is one of
   the 107 files:
   * dumps what the reader made of it: every model with its attributes,
     each input and output entry (address, sizes, alignment, class,
     group, flags, join pieces), resource sections, rules in order
     (filter, qualifiers, action, side effects, by `encode`-like text
     the oracle defines), effect list, likely trash, internal storage,
     local and parameter ranges, inject names, the default, the eval
     models, aliases; the stack and spacebase definitions; global
     ranges; and the register table restricted to registers the file
     names;
   * for every model, `assignParameterStorage` for a fixed list of about
     200 signatures (each primitive at each size, pairs and triples,
     seven to twenty parameters to exhaust registers, structures of
     mixed integer/float members of 1–64 bytes, arrays, unions, variadic
     calls, large and small return values), printing each piece's
     address, size, flags and type description, or the error;
   * for every model, `deriveInputMap` and `deriveOutputMap` for trial
     sets generated from the model's own entries (all prefixes, each
     single gap, each double gap, stack trials with holes), printing
     used/unused per trial;
   * `possibleParam`, `characterizeAsParam`,
     `getBiggestContainedParam`, `unjustifiedContainer`,
     `assumedExtension`, `hasEffect` over a grid of addresses around
     every entry.
   The Rust tests decode the same file (G) and must reproduce the dump
   and every row.
5. **Corpus** (G): all 107 files decode without error; each file's
   `<specextensions>`-style fragments in Ghidra's data tests and
   `testfuncproto` decode; counts of models, entries and rules equal the
   `grep` counts (180, 1,558, 230).
6. **Derived** (S): every decode error path with Ghidra's message;
   `FuncProto` XML round trip and equality with the oracle's encode for
   prototypes built from the 200 signatures; alias and merged-model
   behaviour; provenance survives round trips and changes no assignment
   (property test over the signatures).
7. **Properties** (`proptest`, S): for generated standard models and
   signatures, assigned storage never overlaps, respects alignment and
   size bounds, and `fillinMap` of the assigned storage marks exactly
   those trials used; decoding arbitrary XML never panics.
8. **Fuzz target** `bk_cspec_decode` in the root `fuzz/` crate.
9. **Benchmarks**: decode of the largest `.cspec`; one million storage
   assignments over the x86-64 gcc model; numbers in `PERF.md`.

## 7. Acceptance

1. The 21 `testfuncproto` tests pass on Windows, macOS and Linux with no
   external input (S).
2. The 5 `testparamstore` tests and the 13 Java-derived tests pass
   wherever the spec root is present (G), exceptions listed with both
   values.
3. Every oracle table replays with no differing row for all 107 files
   (G), apart from rows explained by a deliberate difference of section
   8. The tables were produced by Ghidra's compiled code; `regen.sh`
   reproduces them (L).
4. `src/` has no dependency on a type model: `cargo tree -p bk-cspec`
   shows neither `bk-decomp-types` nor a test-only type crate outside
   `[dev-dependencies]`.
5. `FunctionSummary`, `CallSite` and provenance exist as specified, with
   serialisation tests; they change no result of items 1–3.
6. Fuzz target 60 s without a finding; no `unsafe`; no panic on input;
   gate green; files within the size limit; public items documented with
   the Ghidra function they correspond to.

## 8. Differences from Ghidra

- Types are reached through `ParamTypes`; `PrototypePieces` names its
  model instead of pointing at it.
- An unknown `.cspec` element is an error (Ghidra: non-terminating
  loop); `<specextensions>` fix-ups and globals are read from the
  extension document (Ghidra: from the wrong decoder).
- Injection payloads are declarations here; compiling is D18.
- The file is read into an immutable `CompilerSpec`; applying it to a
  space manager is a separate step.
- `FunctionSummary` and provenance (ADR-025) have no Ghidra counterpart
  in the engine.

(The implementing agent appends further differences here.)

## 9. Status

Not started.
