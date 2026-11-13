# 02 — The decompiler (inventory)

Source of truth: Ghidra at `../ghidra`, commit `42db038f3c`, read-only.
Written so that work on milestone M3 can be planned without re-reading the
C++. The port plan built on this inventory is
`docs/features/decomp-plan.md`.

Path abbreviations, all under `../ghidra`:
`CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`UT/` = `…/decompile/unittests/`, `DT/` = `…/decompile/datatests/`,
`DOC/` = `Ghidra/Features/Decompiler/src/main/doc/`,
`REF/` = `../reference/` (the built tools, `features/reference-tools.md`).

How each statement here was established is marked where it matters:
**(ran)** — a tool or script was executed and the result seen;
**(read)** — concluded from reading the source. Section 11 lists what was
not verified. The scripts behind the generated tables are described in
`docs/agents/spec-decompiler.md`.

## 1. Size and shape

`CPP/` holds 195,348 lines in `.cc`, `.hh`, `.y` and `.l` files **(ran:
`wc -l`)**. By the Makefile's source groups (`.cc` plus `.hh`):

| Group | Lines | What it is | basilisk |
|---|---:|---|---|
| `CORE` | 12,421 | XML, marshalling, spaces, addresses, floats, raw p-code, `Translate`, opcodes, metatypes, context database | `bk-marshal`, `bk-core`, `bk-pcode` (merged); `globalcontext` is open |
| `DECCORE` | 129,004 | **The decompiler engine** (3,180 of these lines are `grammar.cc`, bison output) | milestone M3, this inventory |
| `SLEIGH` | 16,030 | SLEIGH runtime and the p-code snippet parser | `bk-sleigh` (M1, specified elsewhere) |
| `SLACOMP` | 12,217 | SLEIGH compiler | M2 |
| `GHIDRA` | 3,870 | Pipe protocol to the Ghidra JVM | replaced by a trait (section 9) |
| `SPECIAL`, `EXTRA` and headers without a `.cc` | 21,806 | Console, test runner, XML/raw/BFD architectures, call graph, BSim signatures, rule compiler, documentation headers | console and test runner are ported as test tooling; the rest as noted in section 2 |

So "port 190,000 lines" is, for the decompiler proper, **about 126,000
lines of hand-written C++ including headers and doc comments**, of which
`opbehavior`, `multiprecision`, `crc32`-style helpers and the float code
already exist in `bk-pcode`/`bk-core`.

Counts that the project documents state differently **(ran: scripts over
`CPP/*.hh` and `CPP/coreaction.cc`)**:

* **163** classes derive from `Rule` (`ruleaction.hh` 137, `subflow.hh`
  12, `bitfield.hh` 6, `double.hh` 4, `constseq.hh` 2, `condexe.hh` 1,
  `rulecompile.hh` 1). **161** are instantiated by
  `ActionDatabase::universalAction`; `RuleEquality` is declared but never
  added, and `RuleGeneric` exists only for user-compiled rules
  (`CPUI_RULECOMPILE`). ADR-004 says 167.
* **71** leaf classes derive from `Action` (`coreaction.hh` 63,
  `blockaction.hh` 7, `condexe.hh` 1), plus the containers `ActionGroup`,
  `ActionRestartGroup` and `ActionPool`. The universal action holds **80**
  leaf-action instances (nine classes appear more than once) in 6
  containers. ADR-004 says 77.
* The opcode enumeration runs to `CPUI_MAX = 75` and includes `INSERT`
  (70), `ZPULL` (71) and `SPULL` (74), which this Ghidra version's bitfield
  rules create. `bk-pcode` has them.
* 107 `.cspec` files under `Ghidra/Processors` (112 in the whole tree,
  counting `skel.cspec`, `mock.cspec` and test resources); 180
  `<prototype>` elements. `00-overview.md` says 110.

## 2. Source files

Lines are `.cc`/`.hh`. "IR" below means `Varnode`, `PcodeOp`, the blocks
and `Funcdata`.

### 2.1 `CORE` (ported, for reference)

| File | Lines | Holds |
|---|---:|---|
| `xml` | 2,510 / 403 (`xml.y` 652) | XML parser and DOM, `DocumentStorage` (named tags a whole architecture is configured from) |
| `marshal` | 1,355 / 779 | Element and attribute ids, encoders, decoders |
| `space`, `address` | 701 / 563, 1,182 / 640 | Address spaces, `Address`, `SeqNum`, `Range`, `RangeList`, bit helpers |
| `float`, `opcodes`, `opbehavior`, `multiprecision` | 692 / 102, 78 / 138, 805 / 541, 335 / 42 | Float formats, opcodes, op behaviours, 128-bit helpers |
| `pcoderaw` | 124 / 256 | `VarnodeData` (ported), `PcodeOpRaw` (not ported) |
| `translate` | 1,088 / 647 | `AddrSpaceManager`, join records (ported); `Translate`, `PcodeEmit`, `AssemblyEmit` (M1) |
| `metatype` | 154 / 57 | `type_metatype` and its names. **Not ported**; belongs to the type system |
| `globalcontext` | 618 / 334 | `ContextDatabase`, `ContextInternal`, `TrackedContext`, `ContextCache`. **Not ported**; shared by the SLEIGH runtime (context variables) and the decompiler (tracked registers) |
| `partmap.hh`, `rangemap.hh`, `error.hh`, `types.h` | 233, 465, 105 | Interval-map templates used by the context database, the symbol table and parameter lists; error classes; integer typedefs |

### 2.2 `DECCORE` — the engine

| File | Lines | Holds |
|---|---:|---|
| `architecture` | 1,564 / 400 | `Architecture`: owns everything for one program (section 3.1); reads `.pspec` and `.cspec` elements and dispatches them; `ArchitectureCapability` (registry of loaders: `xml`, `raw`, `bfd`, `ghidra`) |
| `capability` | 51 / 55 | Static-initialiser registry base class (`CapabilityPoint`). Not ported: no global state |
| `options` | 1,092 / 361 | `OptionDatabase` and 41 `ArchOption` classes — every named decompiler option (`option <name> …` in the console, `SetOptions` over the pipe) |
| `type` | 5,230 / 1,028 | `Datatype` and 16 subclasses, `TypeField`, `TypeBitField`, `TypeFactory` (section 3.5) |
| `grammar` | `grammar.y` 1,615 (`.cc` 3,180 generated) / 300 | C declaration lexer and parser (`CParse`, `parse_type`, `parse_C`, `parse_protopieces`) and the console's address/varnode/op text parsers (`parse_machaddr`, `parse_varnode`, `parse_op`) |
| `cast` | 546 / 205 | `CastStrategy`, `CastStrategyC`, `CastStrategyJava`: where casts are required, integer promotion, extension hiding |
| `typeop` | 2,762 / 957 | `TypeOp` and one subclass per opcode (63): flags, evaluation type, data-type propagation rules, input/output casts, printing hooks |
| `unionresolve` | 1,300 / 223 | `ResolvedUnion`, `ResolveEdge`, `ScoreUnionFields`, `ResolveCache`: choosing a union field per data-flow edge |
| `fspec` | 5,928 / 1,809 | Calling conventions and prototypes (section 3.7): `ParamEntry`, `ParamList*`, `ProtoModel*`, `ParamTrial`, `ParamActive`, `EffectRecord`, `ProtoParameter`, `ProtoStore*`, `FuncProto`, `FuncCallSpecs`, `FspecSpace` |
| `modelrules` | 1,975 / 681 | The `<rule>` machinery of prototype models: `DatatypeFilter`s, `QualifierFilter`s, `AssignAction`s, `ModelRule`, `PrimitiveExtractor`, side-effect actions |
| `pcodeinject` | 361 / 277 | `InjectPayload`, `InjectContext`, `ExecutablePcode`, `PcodeInjectLibrary`: call fixups, callother fixups, call-mechanism and executable p-code snippets |
| `userop` | 652 / 363 | `UserPcodeOp` kinds (unspecialised, injected, volatile read/write, segment, jump-assist, internal string, data-type), `UserOpManage` |
| `cpool` | 248 / 212 | `CPoolRecord`, `ConstantPool` (Java/Dalvik constant pool references) |
| `comment` | 406 / 255 | `Comment`, `CommentDatabase`, `CommentDatabaseInternal`, `CommentSorter` (placing comments in output blocks) |
| `stringmanage` | 484 / 97 | `StringManager`, `StringManagerUnicode`: decoding string data for display |
| `loadimage` | 115 / 230 | `LoadImage` interface (bytes at an address, symbols, sections, read-only ranges), `RawLoadImage` |
| `database` | 3,619 / 1,067 | Symbol table: `Symbol` kinds, `SymbolEntry` kinds, `Scope`, `ScopeInternal`, `Database` (section 3.6) |
| `varmap` | 1,759 / 281 | `ScopeLocal` (a function's local scope), `MapState`, `RangeHint`, `AliasChecker`, name and type recommendations: recovering the stack frame layout |
| `override` | 660 / 184 | `Override`: forced gotos, prototype, flow, dead-code-delay, indirect-call and multistage-jump overrides for one function |
| `dynamic` | 754 / 107 | `DynamicHash`: a hash naming a temporary varnode by its local data-flow, used for symbols on temporaries |
| `varnode` | 2,047 / 432 | `Varnode`, `VarnodeBank`, the two orderings (section 3.2) |
| `op` | 1,309 / 377 | `PcodeOp`, `PcodeOpBank`, `IopSpace`, `PieceNode` (section 3.3) |
| `cover` | 654 / 134 | `CoverBlock`, `Cover`, `PcodeOpSet`: where a varnode is live |
| `variable` | 1,221 / 315 | `HighVariable`, `VariableGroup`, `VariablePiece`, `HighIntersectTest` (section 3.4) |
| `block` | 3,846 / 982 | `FlowBlock`, `BlockGraph`, `BlockBasic`, the 13 structured block kinds, `BlockMap`; dominators, spanning tree, loop and irreducible-edge detection, printing dispatch |
| `funcdata`, `funcdata_op`, `funcdata_varnode`, `funcdata_block` | 1,234 / 746, 1,668, 2,334, 1,114 | `Funcdata` (section 3.4) and its 186 methods; `PcodeEmitFd`, `CloneBlockOps`, `AncestorRealistic` |
| `flow` | 1,459 / 174 | `FlowInfo`: follow control flow from the entry, lift each instruction, build ops and basic blocks, call specs, inlining, injection |
| `heritage` | 2,877 / 344 | `Heritage`: SSA construction per address space in passes (phi placement, renaming, guards for calls, stores, loads and returns), `LoadGuard`, refinement |
| `prefersplit` | 737 / 95 | `PreferSplitManager`: split designated registers before heritage |
| `merge` | 1,728 / 178 | `Merge`: merge varnodes into `HighVariable`s (required, speculative), cover intersection, marker and copy handling |
| `expression` | 803 / 238 | `PcodeOpNode`, `TraverseNode`, `BooleanMatch`, `BooleanExpressionMatch`, `TermOrder`, `AddExpression`, the bitfield expression matchers — helpers shared by rules, merge and jump tables |
| `rangeutil` | 2,605 / 410 | `CircleRange` (lines 21–1,490, IR-free except `pullBack(PcodeOp*)`), `ValueSet`, `ValueSetRead`, `Widener*`, `ValueSetSolver` (value-set analysis over the IR) |
| `emulate`, `emulateutil`, `memstate` | 462 / 551, 397 / 178, 738 / 208 | P-code emulation base, `EmulatePcodeOp`/`EmulateSnippet` (emulating existing ops, used by jump tables and injection), memory state |
| `jumptable` | 2,933 / 652 | `JumpTable`, the models (`JumpBasic`, `JumpBasic2`, `JumpBasicOverride`, `JumpAssisted`, `JumpModelTrivial`), `PathMeld`, `GuardRecord`, `EmulateFunction`, `LoadTable` |
| `action` | 1,150 / 330 | `Action`, `ActionGroup`, `ActionRestartGroup`, `Rule`, `ActionPool`, `ActionDatabase`, `ActionGroupList` (section 5) |
| `coreaction` | 6,151 / 1,114 | 63 actions and `ActionDatabase::universalAction`/`buildDefaultGroups` (section 5); `StackSolver`, `PropagationState`, `TermOrder` users |
| `ruleaction` | 11,020 / 1,605 | 137 rules (section 6) |
| `subflow` | 4,179 / 462 | `SubvariableFlow` (1,521 lines), `SplitFlow`, `SplitDatatype` (737), `SubfloatFlow`, `LaneDivide`, and 12 rules |
| `double` | 3,630 / 374 | `SplitVarnode` (1,378) and 13 "form" matchers for double-precision arithmetic, 4 rules |
| `transform` | 772 / 257 | `TransformManager`, `TransformVar`, `TransformOp`, `LanedRegister`, `LaneDescription`: build a replacement sub-graph, then apply it |
| `bitfield` | 2,418 / 268 | `BitFieldTransform`, insert and pull transforms, 6 rules |
| `constseq` | 1,027 / 145 | `ArraySequence`, `StringSequence`, `HeapSequence`, 2 rules (character-by-character copies become string copies) |
| `condexe` | 711 / 199 | `ConditionalExecution`, `ActionConditionalExe`, `RuleOrPredicate` |
| `blockaction` | 2,375 / 363 | `CollapseStructure` (868), `LoopBody`, `TraceDAG`, `FloatingEdge`, `ConditionalJoin`, 7 actions: control-flow structuring |
| `graph` | 502 / 28 | Graph dumps (data-flow, control-flow, dominator tree) for the console's `graph` commands |
| `prettyprint` | 1,279 / 1,167 | `Emit`, `EmitMarkup`, `EmitNoMarkup`, `EmitPrettyPrint` (Oppen-style line breaking), `TokenSplit`, `PendPrint` |
| `printlanguage` | 824 / 613 | `PrintLanguage`: reverse-Polish expression stack, operator tokens (`OpToken`), scopes, the per-opcode `op*` and per-block `emitBlock*` interface |
| `printc` | 3,556 / 378 | `PrintC`: the C emitter |
| `printjava` | 365 / 78 | `PrintJava` |
| `paramid` | 285 / 82 | `ParamMeasure`, `ParamIDAnalysis`: ranking of parameter candidates returned for the `paramid` root action |
| `signature` | 1,148 / 357 | BSim feature vectors (M10) |
| `crc32` | 74 / 37 | CRC table used by `DynamicHash`, symbol name hashing and signatures |

### 2.3 Console, test runner and other `EXTRA`

| File | Lines | Holds | Port |
|---|---:|---|---|
| `ifacedecomp` | 3,764 / 695 | The decompiler's console commands (section 8) | The commands data tests use, as the data-test runner |
| `interface`, `ifaceterm` | 624 / 301, 284 / 58 | Generic command-line interface, script stack, terminal handling | Minimal: a command dispatcher |
| `testfunction` | 399 / 102 | `FunctionTestCollection`, `FunctionTestProperty`: the data-test runner (section 7.2) | Yes |
| `test` | 174 / 115 | Unit-test macros and `decomp_test`'s `main` | No (Rust tests) |
| `consolemain` | 246 | `decomp`'s `main`; `load file`, `save`, `restore`, `addpath` | `basilisk decompile` |
| `sleigh_arch` | 638 / 153 | `SleighArchitecture`: finds `.ldefs`, picks language and compiler spec, loads `.sla`, `.pspec`, `.cspec`; default core types | Split between `bk-lang` (done) and the architecture track |
| `xml_arch`, `loadimage_xml` | 159 / 55, 298 / 59 | `XmlArchitecture`, `LoadImageXml`: a program as `<binaryimage>` with `<bytechunk>`s and `<symbol>`s — the form every data test uses | Yes |
| `raw_arch` | 128 / 55 | Raw-binary architecture | Later, with the CLI |
| `inject_sleigh` | 561 / 148 | `PcodeInjectLibrarySleigh`, `InjectPayloadSleigh` and friends: compile injection snippets with the SLEIGH p-code parser | With the injection track (needs `pcodeparse`) |
| `callgraph` | 468 / 128 | Call graph for the console | Later |
| `unify`, `rulecompile`, `ruleparse.y` | 1,647 / 711, 1,013 / 205, 277 | Experimental rule language (`CPUI_RULECOMPILE`, off in every build) | Not ported |
| `codedata`, `analyzesigs`, `bfd_arch`, `loadimage_bfd` | 792 / 200, 243 / 67, 175 / 56, 303 / 94 | Code/data analysis experiment, signature commands, BFD loader. Not in the reference build | Not ported (M10 for signatures) |
| `libdecomp` | 64 / 39 | `startDecompilerLibrary` | Not needed |
| `doccore.hh`, `docmain.hh` | 339, 423 | Doxygen overview pages: a written description of the pipeline and core classes. **Read these first** | — |

### 2.4 `GHIDRA`

| File | Lines | Holds |
|---|---:|---|
| `ghidra_process` | 530 / 245 | The commands the JVM sends (section 9.1) and the `main` loop |
| `ghidra_arch` | 952 / 169 | `ArchitectureGhidra`: the queries sent back to the JVM (section 9.2) |
| `ghidra_translate`, `loadimage_ghidra`, `database_ghidra`, `typegrp_ghidra`, `inject_ghidra`, `cpool_ghidra`, `comment_ghidra`, `string_ghidra`, `ghidra_context` | 178, 55, 414, 38, 236, 70, 83, 50, 45 (`.cc`) | One class per `Architecture` component, each answering from the JVM and caching |
| `signature_ghidra` | 119 / 78 | BSim commands |

## 3. Object model

Everything is reachable from one `Architecture` (per program) and one
`Funcdata` (per function). Fields are quoted from the headers **(read)**.

### 3.1 `Architecture` (`architecture.hh`)

Derives from `AddrSpaceManager`, so it *is* the space manager. Owns:

| Member | Type | Role |
|---|---|---|
| `translate` | `const Translate *` | Lifter and register names. The engine calls only `oneInstruction`, `printAssembly`, `getRegister`, `getRegisterName`, `getAllRegisters`, `getUserOpNames`, `getFloatFormat`, `setDefaultFloatFormats`, `getAlignment`, `isBigEndian`, `allowContextSet` **(ran: grep over the engine sources)** |
| `loader` | `LoadImage *` | Bytes of the program |
| `context` | `ContextDatabase *` | Context variables and tracked register values by address |
| `symboltab` | `Database *` | Scopes and symbols |
| `types` | `TypeFactory *` | All data types |
| `protoModels`, `defaultfp`, `evalfp_current`, `evalfp_called`, `defaultReturnAddr` | `map<string,ProtoModel*>`, … | Calling conventions from the `.cspec` |
| `pcodeinjectlib` | `PcodeInjectLibrary *` | Injection payloads |
| `userops` | `UserOpManage` | Meaning of each `CALLOTHER` |
| `commentdb`, `stringManager`, `cpool` | | Comments, strings, constant pool |
| `inst` | `vector<TypeOp *>` | One `TypeOp` per opcode |
| `allacts` | `ActionDatabase` | The pipeline |
| `print`, `printlist` | `PrintLanguage *` | Output language |
| `options` | `OptionDatabase *` | Named options |
| `splitrecords`, `lanerecords`, `extra_pool_rules`, `inferPtrSpaces` | | Prefer-split registers, laned registers, extra rules, spaces where constants may be pointers |
| configuration scalars | | `trim_recurse_max` 5, `max_implied_ref` 2, `max_term_duplication` 2, `max_basetype_size` 10, `max_instructions` 100,000, `max_baddata` 4, `max_jumptable_size` 1,024, `alias_block_level` 2, `infer_pointers`, `analyze_for_loops`, `readonlypropagate` (off), `nan_ignore_all` (off), `nan_ignore_compare` (on), `flowoptions`, `funcptr_align`, `split_datatype_config` (defaults from `resetDefaultsInternal`) |

Construction order, `Architecture::init` **(read)**: `buildLoader` →
`resolveArchitecture` → `buildSpecFile` → `buildContext` → `buildTypegrp`
→ `buildCommentDB` → `buildStringManager` → `buildConstantPool` →
`buildDatabase` → `restoreFromSpec` → `buildCoreTypes` →
`print->initializeFromArchitecture` → `symboltab->adjustCaches` →
`buildSymbols` → `postSpecFile` → `buildInstructions` →
`fillinReadOnlyFromLoader`. `restoreFromSpec` builds the translator, copies
its spaces, adds the `fspec`, `iop` and `join` spaces, initialises user
ops, builds the injection library, then `parseProcessorConfig` (`.pspec`),
`parseCompilerConfig` (`.cspec`) and `buildAction`.

`.cspec` elements handled by `parseCompilerConfig`: `default_proto`,
`prototype`, `resolveprototype`, `stackpointer`, `returnaddress`,
`spacebase`, `nohighptr`, `prefersplit`, `aggressivetrim`,
`data_organization`, `enum`, `global`, `segmentop`, `readonly`,
`context_data`, `eval_called_prototype`, `eval_current_prototype`,
`callfixup`, `callotherfixup`, `funcptr`, `deadcodedelay`,
`inferptrbounds`, `modelalias`; then an optional `<specextensions>`
document (`prototype`, `callfixup`, `callotherfixup`, `global`). After the
elements: `<global>` ranges are added to the global scope, a default model
is chosen (the first, if none was named), `__thiscall` is aliased to the
default model when absent, segment resolvers and prefer-split records are
initialised and `types->setupSizes()` fills in missing data-organisation
values. The element loop is a chain of `else if` with no final `else`, so
an unknown element inside `<compiler_spec>` is never consumed and the loop
would not terminate **(read)**; all 107 files use only known elements, and
basilisk reports an unknown element as an error.

A bug found by reading: in the `<specextensions>` loop the `callfixup`,
`callotherfixup` and `global` branches pass `decoder` (the already-closed
`.cspec` decoder) instead of `decoderExt`. basilisk reads the extension
document with its own decoder.

### 3.2 `Varnode` and `VarnodeBank` (`varnode.hh`)

A varnode is a storage location (address + size) *in one SSA version*.
Fields: `flags` (32 bits), `size`, `create_index` (one-up per function),
`mergegroup`, `addlflags` (16 bits), `loc` (`Address`), `def`
(`PcodeOp *`), `high` (`HighVariable *`), `mapentry` (`SymbolEntry *`),
`type` (`Datatype *`), the two iterators into the bank's sets, `descend`
(`list<PcodeOp *>`, the readers, in order of `addDescend`), `cover`
(lazily built), a temporary union (`Datatype *` during type propagation or
`ValueSet *` during value-set analysis), `consumed` and `nzm` (64-bit
masks).

`flags`: `mark`, `constant`, `annotation`, `input`, `written`, `insert`,
`implied`, `explict`, `typelock`, `namelock`, `nolocalalias`, `volatil`,
`externref`, `readonly`, `persist`, `addrtied`, `unaffected`, `spacebase`,
`indirectonly`, `directwrite`, `addrforce`, `mapped`, `indirect_creation`,
`return_address`, `coverdirty`, `precislo`, `precishi`, `indirectstorage`,
`hiddenretparm`, `incidental_copy`, `autolive_hold`, `proto_partial` — all
32 bits used. `addlflags`: `activeheritage`, `writemask`, `vacconsume`,
`lisconsume`, `symcheck_incomplete`/`symcheck_complete` (two bits),
`ptrflow`, `unsignedprint`, `longprint`, `stack_store`, `locked_input`,
`spacebase_placeholder`, `stop_uppropagation`, `has_implied_field`.

A varnode is in exactly one state: **free** (neither `input` nor
`written`; not yet in SSA form), **input** (no definition, value on entry)
or **written** (`def` set). Constants and annotations are free-standing
copies per use.

`VarnodeBank` keeps every varnode in two ordered sets:
`loc_tree` (`VarnodeCompareLocDef`: address, size, then input < written <
free, then defining `SeqNum`, or `create_index` among free ones) and
`def_tree` (`VarnodeCompareDefLoc`). The key of a varnode changes when it
becomes an input or gets a definition, so the bank removes and re-inserts
it (`xref`, `setInput`, `setDef`, `makeFree`); only the bank and `Funcdata`
may change those fields. The bank also hands out offsets in the `unique`
space (`uniqbase`, `uniqid`) and `create_index`.

Varnodes in two special spaces carry host pointers as offsets
(`funcdata_varnode.cc`: `newVarnodeIop`, `newVarnodeCallSpecs`): an `iop`
varnode's offset is a `PcodeOp *` and an `fspec` varnode's offset is a
`FuncCallSpecs *`; both are created with `size = sizeof(pointer)`.
`LOAD`/`STORE` space inputs are constants whose offset is an `AddrSpace *`.

### 3.3 `PcodeOp` and `PcodeOpBank` (`op.hh`)

Fields: `opcode` (`TypeOp *`), `flags` and `addlflags` (32 bits each),
`start` (`SeqNum`: instruction address, a unique *time* and an *order*
within the block), `parent` (`BlockBasic *`), three list iterators
(position in its block, in the alive/dead list, in the per-opcode list),
`output` (`Varnode *` or null) and `inrefs` (`vector<Varnode *>`).

`flags`: `startbasic`, `branch`, `call`, `returns`, `nocollapse`, `dead`,
`marker`, `booloutput`, `boolean_flip`, `fallthru_true`,
`indirect_source`, `coderef`, `startmark`, `mark`, `commutative`, `unary`,
`binary`, `special`, `ternary`, `return_copy`, `nonprinting`, `halt`,
`badinstruction`, `unimplemented`, `noreturn`, `missing`,
`spacebase_ptr`, `indirect_creation`, `calculated_bool`, `has_callspec`,
`ptrflow`, `indirect_store`. `addlflags`: `special_prop`, `special_print`,
`modified`, `warning`, `incidental_copy`, `is_cpool_transformed`,
`stop_type_propagation`, `hold_output`, `concat_root`,
`no_indirect_collapse`, `store_unmapped`, `immed_copy`,
`store_aliasupdate`.

`PcodeOpBank`: `optree` (`map<SeqNum, PcodeOp *>`, the iteration order of
rule pools), `alttree` (quarantined `INDIRECT`s), and intrusive lists:
`deadlist`, `alivelist`, `storelist`, `loadlist`, `returnlist`,
`useroplist`, `deadandgone` (destroyed ops kept until the function is
cleared, so stale pointers stay valid). An op is **dead** until inserted
into a block (`opInsert*`), and returns to dead when unlinked.

### 3.4 `Funcdata`, blocks, `HighVariable`

`Funcdata` (`funcdata.hh`): `flags` (16 state bits such as
`highlevel_on`, `blocks_generated`, `processing_started`,
`typerecovery_on`, `jumptablerecovery_on`, `restart_pending`,
`double_precis_on`, `normalization_on`), three creation-index watermarks
(`clean_up_index`, `high_level_index`, `cast_phase_index`),
`minLanedSize`, `size`, `glb`, `functionSymbol`, `name`, `displayName`,
`baseaddr`, `funcp` (`FuncProto`), `localmap` (`ScopeLocal *`), `qlst`
(`vector<FuncCallSpecs *>`), `jumpvec` (`vector<JumpTable *>`), `vbank`,
`obank`, `bblocks` and `sblocks` (two `BlockGraph`s: basic blocks, and the
structured hierarchy over them), `heritage`, `covermerge` (`Merge`),
`activeoutput` (`ParamActive *`), `localoverride`, `lanedMap`, `unionMap`
(`map<ResolveEdge, ResolvedUnion>`). Its methods are the only way the IR
is changed; by file **(ran: extracted from the `.cc` files)**:

* `funcdata.cc` (45): lifecycle (`clear`, `startProcessing`,
  `stopProcessing`, `startTypeRecovery`), warnings, spacebase helpers,
  call-spec list, `printRaw`, `printVarnodeTree`, `printLocalRange`,
  `encode`/`decode` of the function, jump tables, union-field bookkeeping,
  the debug trace (`debugMod*`, `debugSetRange`, …).
* `funcdata_op.cc` (52): `newOp`, `opSetOpcode`, `opSetInput`,
  `opSetOutput`, `opUnset*`, `opSwapInput`, `opInsert`/`Before`/`After`/
  `Begin`/`End`, `opUninsert`, `opUnlink`, `opDestroy`, `opDestroyRaw`,
  `opDestroyRecursive`, `opRemoveInput`, `opInsertInput`, `newIndirectOp`,
  `newIndirectCreation`, `followFlow`, `inlineFlow`, `truncatedFlow`,
  common-subexpression helpers (`cseFindInBlock`, `cseElimination`),
  `opBoolNegate`, `opFlipInPlace*`, `distributeIntMultAdd`,
  `collapseIntMultMult`, `replaceLessequal`, …
* `funcdata_varnode.cc` (59): `newConstant`, `newUnique`, `newUniqueOut`,
  `newVarnode`, `newVarnodeOut`, `newVarnodeIop`, `newVarnodeSpace`,
  `newVarnodeCallSpecs`, `newCodeRef`, `setInputVarnode`,
  `adjustInputVarnodes`, `destroyVarnode`, `totalReplace`,
  `totalReplaceConstant`, `calcNZMask`, `clearDeadVarnodes`,
  `setVarnodeProperties`, symbol linking (`linkSymbol`,
  `syncVarnodesWithSymbols`, `buildDynamicSymbol`, `attemptDynamicMapping`),
  `mapGlobals`, `assignHigh`, `setHighLevel`, ancestor checks, …
* `funcdata_block.cc` (30): `structureReset`, `removeBranch`,
  `removeUnreachableBlocks`, `removeDoNothingBlock`, `pushBranch`,
  `nodeSplit`, `nodeJoinCreateBlock`, `spliceBlockBasic`, `forceGoto`,
  jump-table installation and recovery (`recoverJumpTable`,
  `stageJumpTable`, `installJumpTable`, `switchOverJumpTables`).

**Blocks** (`block.hh`). `FlowBlock`: `parent`, `immed_dom`, `copymap`,
`intothis` and `outofthis` (`vector<BlockEdge>`; an edge is label, other
end and the index of the reverse edge; for a conditional block out-edge 0
is the false branch), `flags` (19 bits), `index` (reverse post-order),
`visitcount`, `numdesc`, `leafCount`, `structureDepth`. Edge labels:
`f_goto_edge`, `f_loop_edge`, `f_defaultswitch_edge`, `f_irreducible`,
`f_tree_edge`, `f_forward_edge`, `f_cross_edge`, `f_back_edge`,
`f_loop_exit_edge`, `f_immed_copy`. Hierarchy:

```
FlowBlock
 ├─ BlockBasic        list<PcodeOp*> op, Funcdata *data, RangeList cover
 ├─ BlockCopy         stand-in for a basic block inside the structured graph
 └─ BlockGraph        vector<FlowBlock*> list — a container of sub-blocks
     ├─ BlockGoto, BlockMultiGoto
     ├─ BlockList, BlockCondition
     ├─ BlockIf ── BlockIfElse ── BlockIfNoExit
     │        └─ BlockIfGoto
     ├─ BlockWhileDo, BlockDoWhile, BlockInfLoop
     └─ BlockSwitch
```

`BlockGraph` holds the graph algorithms: `calcForwardDominator`,
`buildDomTree`, `buildDomDepth`, `findSpanningTree`, `findIrreducible`,
`structureLoops`, `orderBlocks`, edge surgery (`addEdge`, `removeEdge`,
`switchEdge`, `moveOutEdge`, `removeBlock`, `collapseBlock`,
`spliceBlock`), and `newBlock*` constructors for each structured kind.

**`HighVariable`** (`variable.hh`): the set of varnodes that will print as
one variable: `inst` (`vector<Varnode *>`), `numMergeClasses`, `highflags`
(`flagsdirty`, `namerepdirty`, `typedirty`, `coverdirty`, `symboldirty`,
`copy_in1`, `copy_in2`, `type_finalized`, `unmerged`, `intersectdirty`,
`extendcoverdirty`), `flags` (union of the members' flags), `type`,
`nameRepresentative`, `internalCover`, `symbol`, `symboloffset`, and a
`VariablePiece` when the variable is part of a `VariableGroup` of
overlapping variables. All but `inst` and `numMergeClasses` are caches
recomputed lazily from the members (the dirty bits). `HighIntersectTest` caches
pairwise cover intersection results in a `map<HighEdge,bool>`.

### 3.5 `Datatype` and `TypeFactory` (`type.hh`, `metatype.hh`)

`Datatype`: `id` (64-bit; 0 = anonymous), `size`, `flags`, `name`,
`displayName`, `metatype`, `submeta`, `typedefImm`, `alignment`,
`alignSize`. Metatypes, with their numeric values (they index
`Datatype::base2sub`): `PARTIALUNION` 0, `PARTIALSTRUCT` 1, `PARTIALENUM`
2, `UNION` 3, `STRUCT` 4, `ENUM_INT` 5, `ENUM_UINT` 6, `ARRAY` 7, `PTRREL`
8, `PTR` 9, `FLOAT` 10, `CODE` 11, `BOOL` 12, `UINT` 13, `INT` 14,
`UNKNOWN` 15, `SPACEBASE` 16, `VOID` 17. `sub_metatype` (24 values) is the
finer ordering used by `compare`. `type_class`: `GENERAL`, `FLOAT`, `PTR`,
`HIDDENRET`, `VECTOR`, `CLASS1`–`CLASS4` (used by prototype model rules).

Subclasses: `TypeBase`, `TypeChar`, `TypeUnicode`, `TypeVoid`,
`TypePointer` (`ptrto`, `spaceid`, `truncate`, `wordsize`),
`TypePointerRel` (`parent`, `offset`, `stripped`), `TypeArray`
(`arrayof`, `arraysize`), `TypeEnum` (`map<uintb,string> namemap`),
`TypePartialEnum`, `TypeStruct` (`vector<TypeField>`,
`vector<TypeBitField>`), `TypePartialStruct`, `TypeUnion`,
`TypePartialUnion`, `TypeCode` (owns a `FuncProto *`), `TypeSpacebase`
(`spaceid`, `scopeId`, `glb`: a scope viewed as a structure).

`flags`: `coretype`, `chartype`, `enumtype`, `poweroftwo`, `utf16`,
`utf32`, `opaque_string`, `variable_length`, `has_stripped`, `is_ptrrel`,
`type_incomplete`, `needs_resolution`, `force_format` (3 bits),
`truncate_bigendian`, `pointer_to_array`, `warning_issued`,
`has_bitfields`.

`TypeFactory`: data organisation (`sizeOfInt`, `sizeOfLong`, `sizeOfChar`,
`sizeOfWChar`, `sizeOfPointer`, `sizeOfAltPointer`, `enumsize`,
`enumtype`, `alignMap`), `tree` (`set<Datatype*, DatatypeCompare>`: by
`compareDependency`, then id), `nametree` (by name, then id), caches
(`typecache[9][8]`, 10- and 16-byte floats, `type_nochar`, `charcache`),
`warnings`, `incompleteTypedef`. Types are interned: `findAdd` returns the
existing equal type.

Two orderings matter and are different: `compare(op, level)` orders types
for **propagation** (which of two candidate types wins; recursive to a
depth) and `compareDependency` orders for **identity** in the factory.
Parts of `type.cc` that reach into the IR or the symbol table **(ran: grep
by method)**: `resolveInFlow`, `findResolve`, `findTruncation`,
`resolveTruncation` and `TypeStruct::scoreSingleComponent` (union
resolution, through `Funcdata`), `TypeSpacebase` (through `Scope`), and
`TypeCode` (through `FuncProto`). Everything else is self-contained.

### 3.6 `Database`, `Scope`, `Symbol` (`database.hh`)

`Database` (`glb`, `globalscope`, `resolvemap`, `idmap`, `flagbase`,
`idByNameHash`) owns a tree of `Scope`s keyed by 64-bit id (`idmap`), a
map from address ranges to the scope that owns them (`resolvemap`, of
`ScopeMapper`), and `flagbase` (`partmap<Address,uint4>`: `readonly`,
`volatile` and similar properties by address).
`Scope` is the query interface (`queryByAddr`, `queryContainer`,
`queryFunction`, `queryExternalRefFunction`, `queryCodeLabel`,
`resolveScope`, `discoverScope`, …) with parent fallback;
`ScopeInternal` is the in-memory implementation (`nametree` sorted by
name, `maptable`: one `EntryMap` (`rangemap`) per space, `category` lists,
`dynamicentry`, `multiEntrySet`, `nextUniqueId`);
`ScopeLocal` (`varmap.hh`) is the function-local scope;
`ScopeGhidra` (`database_ghidra`) fills an internal cache by asking the
host. `Symbol` kinds: plain, `FunctionSymbol` (owns the `Funcdata`),
`EquateSymbol`, `UnionFacetSymbol`, `LabSymbol`, `ExternRefSymbol`.
`SymbolEntry` kinds: mapped to an address range with a use-point range
(`MapEntry`, `MapEntryConflict`), dynamic (`DynamicEntry`: address + hash),
unassigned.

### 3.7 Prototypes (`fspec.hh`, `modelrules.hh`)

| Class | Role |
|---|---|
| `ParamEntry` | One storage resource: address range, `minsize`/`maxsize`, alignment, type class, group(s), join record, flags (`force_left_justify`, `reverse_stack`, `smallsize_zext`/`sext`/`inttype`/`floatext`, `extracheck_high`/`low`, `is_grouped`, `overlapping`, `first_storage`, `is_stackspill`) |
| `ParamList` → `ParamListStandard` → `ParamListStandardOut` → `ParamListRegisterOut`; `ParamListRegister`; `ParamListMerged` | Ordered resources for inputs or outputs, with `ModelRule`s; assign storage for a prototype (`assignMap`), and the inverse: decide which observed *trials* are parameters (`fillinMap`) |
| `ModelRule` = `DatatypeFilter` + `QualifierFilter` + `AssignAction` (+ side effects) | The `<rule>` elements: `MetaTypeFilter`, `ArrayFilter`, `HomogeneousAggregate`; `VarargsFilter`, `PositionMatchFilter`, `DatatypeMatchFilter`, `AndFilter`; `GotoStack`, `ConvertToPointer`, `MultiSlotAssign`, `MultiMemberAssign`, `MultiSlotDualAssign`, `ConsumeAs`, `HiddenReturnAssign`, `ConsumeExtra`, `ExtraStack`, `ConsumeRemaining`; shared actions `HiddenReturnAction`, `ShareStackAction` |
| `ProtoModel`, `ProtoModelMerged`, `UnknownProtoModel` | A calling convention: input and output lists, `extrapop`, effect list (`unaffected`, `killedbycall`, `return_address`), `likelytrash`, `internalstorage`, local and parameter ranges, `injectUponEntry`/`Return`, `hasThis`, `isConstruct` |
| `EffectRecord` | Effect of a call on a storage range |
| `ParamTrial`, `ParamActive` | A candidate parameter location seen in data-flow, and the set of them for one call or return |
| `PrototypePieces`, `ParameterPieces` | Parsed prototype (model, name, types, names, first-vararg slot); one assigned parameter (address, type, flags) |
| `ProtoParameter` (`ParameterBasic`, `ParameterSymbol`), `ProtoStore` (`ProtoStoreInternal`, `ProtoStoreSymbol`) | Parameters of one prototype, stand-alone or backed by symbols in a scope |
| `FuncProto` | A function's prototype: `model`, `store`, `extrapop`, `flags` (`dotdotdot`, `voidinputlock`, `modellock`, `is_inline`, `no_return`, `paramshift_applied`, `error_inputparam`, `error_outputparam`, `custom_storage`, `is_constructor`, `is_destructor`, `has_thisptr`, `is_override`, `auto_killedbycall`), its own `effectlist` and `likelytrash`, `injectid`, `returnBytesConsumed` |
| `FuncCallSpecs` (extends `FuncProto`) | One call site: `op`, `name`, `entryaddress`, `fd`, `effective_extrapop`, `stackoffset`, `stackPlaceholderSlot`, `paramshift`, `matchCallCount`, `activeinput` and `activeoutput` (`ParamActive`), `inputConsume`, and the booleans `isinputactive`, `isoutputactive`, `isbadjumptable`, `isstackoutputlock` |

IR-free parts **(ran: grep by method)**: all of `modelrules.cc`;
in `fspec.cc` everything except `FuncCallSpecs`, `ProtoStoreSymbol`,
`ParameterSymbol` and four `FuncProto` methods (`setScope`,
`updateInputTypes`, `updateOutputTypes`, `updateOutputNoTypes`).

### 3.8 The services behind interfaces

| Interface | In-memory implementation | Asked for |
|---|---|---|
| `LoadImage` | `LoadImageXml`, `RawLoadImage` | `loadFill(buf, size, addr)`, `getArchType`, `adjustVma`, optional symbols, sections, read-only ranges |
| `ContextDatabase` | `ContextInternal` | Context variable values by address (for the lifter), tracked register values by address (`TrackedSet`), defaults |
| `CommentDatabase` | `CommentDatabaseInternal` | Comments of a function by address and kind (`user1`, `user2`, `user3`, `header`, `warning`, `warningheader`) |
| `PcodeInjectLibrary` | `PcodeInjectLibrarySleigh` | Payload by name and kind (`CALLFIXUP`, `CALLOTHERFIXUP`, `CALLMECHANISM`, `EXECUTABLEPCODE`), `inject(context, emit)` |
| `StringManager` | `StringManagerUnicode` | String bytes at an address for a character type, decoded and cached |
| `ConstantPool` | `ConstantPoolInternal` | `CPoolRecord` for a reference |
| `Translate` | `Sleigh` | Section 3.1 |
| `Scope` | `ScopeInternal` | Section 3.6 |
| `TypeFactory::findById` (virtual) | — | A type by name and id not yet in the factory |

### 3.9 The printer

`PrintLanguage` drives everything through `Emit`. Emission is a stream of
calls — `beginDocument`, `beginFunction`, `beginBlock`, `beginStatement`,
`tagOp`, `tagVariable`, `tagType`, `tagField`, `tagFuncName`, `tagComment`,
`tagLabel`, `tagCaseLabel`, `print` (syntax), `openParen`, `closeParen`,
`openGroup`, `spaces`, `startIndent`, … — each carrying the object the
token came from (the `PcodeOp`, `Varnode`, `HighVariable`, `Datatype`,
`Funcdata`). `EmitMarkup` writes those as elements and attributes
(`ELEM_SYNTAX`, `ELEM_VARIABLE`, `ELEM_OP`, `ELEM_FUNCNAME`, … with
`ATTRIB_OPREF`, `ATTRIB_VARREF`, `ATTRIB_COLOR`, …), which is what the Java
side rebuilds into `ClangToken`s; `EmitPrettyPrint` buffers tokens and
decides line breaks and indentation within `max_line_width`.
`PrintC` implements one `op<Opcode>` method per opcode and one
`emitBlock<Kind>` per block kind, pushes operands on a reverse-Polish
stack (`pushOp`, `pushAtom`) and resolves precedence and parentheses when
the stack is flushed. Expressions are *implied* varnodes printed inline;
statements are ops whose output is *explicit* (`ActionMarkExplicit`,
`ActionMarkImplied`).

## 4. Dependencies between modules

**The headers are layered; the implementation is one cycle.** With only
`#include`s in headers, the engine's modules sort into 18 layers without a
cycle (forward declarations break them). Adding each `.cc` file's includes,
48 modules collapse into a single strongly connected component **(ran:
Tarjan over the include graph)**: `action architecture bitfield block
blockaction cast comment condexe constseq coreaction cover cpool database
double dynamic emulateutil expression flow fspec funcdata heritage
jumptable merge modelrules op options override pcodeinject prefersplit
prettyprint printc printlanguage rangeutil ruleaction stringmanage subflow
transform type typeop unionresolve userop variable varmap varnode`.
Almost every one of them includes `funcdata.hh`, which includes
`architecture.hh`, which includes nearly everything.

So the order of work cannot be read off the include graph; it comes from
what each piece *calls*. Established by reading and by the per-method greps
above:

```
bk-core, bk-marshal, bk-pcode (merged)
 │
 ├─ CircleRange (rangeutil.cc 21–1490)            needs: bit helpers, OpCode
 ├─ types (type, metatype, grammar's C parser)    needs: spaces; NOT the IR, except union
 │    │                                             resolution, TypeSpacebase, TypeCode's FuncProto
 │    └─ prototype models (fspec minus FuncCallSpecs/ProtoStoreSymbol, modelrules)
 │         needs: types, spaces, registers by name, RangeList
 │    └─ compiler spec reader (architecture.cc decode*; pcodeinject and userop as data)
 │         needs: prototype models, types (data organisation), registers and user-op names
 ├─ block graph (block.cc FlowBlock/BlockGraph: edges, dominators, loops)   needs: nothing
 │    └─ structuring (blockaction.cc CollapseStructure, LoopBody, TraceDAG) needs: block graph only
 └─ IR core (varnode, op, cover, funcdata_op/_varnode low level)            needs: block graph, types (ids)
      └─ symbol table (database, varmap's ScopeLocal)   needs: IR core, types, prototypes
      └─ typeop, cast                                   needs: IR core, types, printer interface (tokens)
      └─ flow                                           needs: IR, lifter, load image, symbols, call specs, injection
      └─ heritage (+ prefersplit, the guard logic)      needs: flow output, symbols, call specs
      └─ action framework + rules                       needs: all of the above
      └─ merge, HighVariable                            needs: covers, symbols
      └─ printer                                        needs: everything
```

Two results of this that the plan uses: the block graph and the
structuring algorithm depend on nothing else (the pipe command
`StructureGraph` and the console command `structure blocks` run them on a
bare graph), and the type system, circle ranges and prototype models can
be built and tested before any IR exists.

## 5. The pipeline

### 5.1 How actions run (`action.cc`) **(read)**

* `Action::perform` applies an action; with `rule_repeatapply` it repeats
  `apply` until `count` stops increasing. `rule_onceperfunc` makes it run
  once per function (status `status_end` until `reset`);
  `rule_oneactperfunc` stops after the first time it changes something.
  `apply` returns 0 when complete and -1 for a partial completion (a
  breakpoint); the status word lets a later `perform` resume in the middle.
* `ActionGroup::apply` performs its members in order; a member returning a
  positive count adds to the group's count.
* `ActionRestartGroup` (the root, `maxrestarts` 1) re-runs the whole group
  when `Funcdata::hasRestartPending()` is set (an override was discovered,
  for example a jump table that needs a second stage or a newly found
  prototype); it calls `Architecture::clearAnalysis` and resets every
  member first, and warns "Exceeded maximum restarts with more pending"
  past the limit.
* `ActionPool::apply` walks **all live ops in `SeqNum` order**
  (`Funcdata::beginOpMain`, the `optree` map) and for each op tries the
  rules registered for its opcode (`perop[opcode]`, in the order the rules
  were added). After a rule returns non-zero, if the op is now dead the
  pool moves on; if the op's opcode changed, the rule index restarts at 0
  for the new opcode; otherwise it continues with the **next** rule (it
  does not restart at the first rule). Dead ops met during the walk are
  retired (`opDeadAndGone`). The pool as a whole has `rule_repeatapply`, so
  the walk repeats until a full pass changes nothing. Ops created by a rule
  get a new `SeqNum` time and are visited in the same pass if they sort
  after the cursor.
* Every `Action` and `Rule` has a name and a **base group**. A *root
  action* is the universal action filtered by a list of groups
  (`ActionGroupList`): `clone(grouplist)` copies only the members whose
  group is listed. `ActionDatabase::buildDefaultGroups` defines six roots:

| Root | Groups |
|---|---|
| `decompile` | base, protorecovery, protorecovery_a, deindirect, localrecovery, deadcode, typerecovery, stackptrflow, blockrecovery, stackvars, deadcontrolflow, switchnorm, cleanup, splitcopy, splitpointer, merge, dynamic, casts, analysis, fixateglobals, fixateproto, constsequence, bitfields, segment, returnsplit, nodejoin, doubleload, doubleprecis, unreachable, subvar, floatprecision, conditionalexe |
| `jumptable` | base, noproto, localrecovery, deadcode, stackptrflow, stackvars, analysis, segment, subvar, normalizebranches, conditionalexe |
| `normalize` | base, protorecovery, protorecovery_b, deindirect, localrecovery, deadcode, stackptrflow, normalanalysis, stackvars, deadcontrolflow, analysis, fixateproto, nodejoin, unreachable, subvar, floatprecision, normalizebranches, conditionalexe |
| `paramid` | base, protorecovery, protorecovery_b, deindirect, localrecovery, deadcode, typerecovery, stackptrflow, siganalysis, stackvars, deadcontrolflow, analysis, fixateproto, unreachable, subvar, floatprecision, conditionalexe |
| `register` | base, analysis, subvar |
| `firstpass` | base |

  The `jumptable` root is run on a *partial clone* of the function during
  switch recovery (`Funcdata::stageJumpTable`), so the pipeline is
  re-entrant per function. Groups can be toggled at run time
  (`toggleAction`, the `OptionToggleRule`/`OptionSetAction` options), and
  single rules disabled (`Rule::setDisable`).

### 5.2 The universal action

Generated from `ActionDatabase::universalAction` (`coreaction.cc:5861`)
**(ran)**, in order. "Container" is the group the entry is added to;
`mainloop`, `fullloop`, `stackstall` and the three pools repeat until
nothing changes. `once` = `rule_onceperfunc`. `list action` in the console
prints the same tree for the current root (243 lines for `decompile`).

| # | Container | Action (constructor arguments) | Name | Group | Flags | Source | What it does |
|---:|---|---|---|---|---|---|---|
| 1 | universal | `ActionStart` | `start` | base |  | `coreaction.hh` | Gather raw p-code for a function. |
| 2 | universal | `ActionConstbase` | `constbase` | base |  | `coreaction.cc:715` | Search for input Varnodes that have been officially provided constant values. |
| 3 | universal | `ActionNormalizeSetup` | `normalizesetup` | normalanalysis | once | `coreaction.cc:4806` | Prepare function prototypes for "normalize" simplification. |
| 4 | universal | `ActionDefaultParams` | `defaultparams` | base | once | `coreaction.cc:2437` | Find a prototype for each sub-function |
| 5 | universal | `ActionExtraPopSetup`(stackspace) | `extrapopsetup` | base | once | `coreaction.cc:1537` | Define formal link between stack-pointer values before and after sub-function calls. |
| 6 | universal | `ActionPrototypeTypes` | `prototypetypes` | protorecovery | once | `coreaction.cc:4848` | Lay down locked input and output data-type information. |
| 7 | universal | `ActionFuncLink` | `funclink` | protorecovery | once | `coreaction.cc:1709` | Prepare for data-flow analysis of function parameters |
| 8 | universal | `ActionFuncLinkOutOnly` | `funclink_outonly` | noproto | once | `coreaction.cc:1722` | Prepare for data-flow analysis of function parameters, when recovery isn't required. |
| 9 | mainloop | `ActionUnreachable` | `unreachable` | base |  | `coreaction.cc:3629` | Remove unreachable blocks |
| 10 | mainloop | `ActionVarnodeProps` | `varnodeprops` | base |  | `coreaction.cc:1379` | Transform based on Varnode properties, such as read-only and volatile |
| 11 | mainloop | `ActionHeritage` | `heritage` | base |  | `coreaction.hh` | Build Static Single Assignment (SSA) representation for function |
| 12 | mainloop | `ActionParamDouble` | `paramdouble` | protorecovery |  | `coreaction.cc:1731` | Deal with situations that look like double precision parameters |
| 13 | mainloop | `ActionSegmentize` | `segmentize` | base |  | `coreaction.cc:661` | Make sure pointers into segmented spaces have the correct form. |
| 14 | mainloop | `ActionInternalStorage` | `internalstorage` | base | once | `coreaction.cc:5333` | Check for constants getting written to the stack from internal storage registers |
| 15 | mainloop | `ActionForceGoto` | `forcegoto` | blockrecovery |  | `coreaction.cc:708` | Apply any overridden forced gotos |
| 16 | mainloop | `ActionDirectWrite`(true) | `directwrite` | protorecovery_a |  | `coreaction.cc:1451` | Mark Varnodes built out of legal parameters |
| 17 | mainloop | `ActionDirectWrite`(false) | `directwrite` | protorecovery_b |  | `coreaction.cc:1451` | Mark Varnodes built out of legal parameters |
| 18 | mainloop | `ActionActiveParam` | `activeparam` | protorecovery |  | `coreaction.cc:1861` | Determine active parameters to sub-functions |
| 19 | mainloop | `ActionReturnRecovery` | `returnrecovery` | protorecovery |  | `coreaction.cc:2021` | Determine data-flow holding the return value of the function. |
| 20 | mainloop | `ActionRestrictLocal` | `restrictlocal` | localrecovery |  | `coreaction.cc:2070` | Restrict possible range of local variables |
| 21 | mainloop | `ActionDeadCode` | `deadcode` | deadcode |  | `coreaction.cc:4164` | Dead code removal.  Eliminate dead p-code ops |
| 22 | mainloop | `ActionDynamicMapping` | `dynamicmapping` | dynamic |  | `coreaction.cc:5247` | Attach dynamically mapped symbols to Varnodes in time for data-type propagation |
| 23 | mainloop | `ActionSpacebase` | `spacebase` | base |  | `coreaction.hh` | Mark Varnode objects that hold stack-pointer values and set-up special data-type |
| 24 | mainloop | `ActionNonzeroMask` | `nonzeromask` | analysis |  | `coreaction.hh` | Calculate the non-zero mask property on all Varnode objects. |
| 25 | mainloop | `ActionInferTypes` | `infertypes` | typerecovery |  | `coreaction.cc:5773` | Infer and propagate data-types. |
| 26 | mainloop | `ActionRestructureVarnode` | `restructure_varnode` | localrecovery |  | `coreaction.cc:2400` | Create symbols that map out the local stack-frame for the function. |
| 27 | stackstall | **group/pool `oppool1`** | | | | | |
| 28 | stackstall | `ActionLaneDivide` | `lanedivide` | base |  | `coreaction.cc:620` | Find Varnodes with a vectorized lane scheme and attempt to split the lanes |
| 29 | stackstall | `ActionMultiCse` | `multicse` | analysis |  | `coreaction.cc:916` | Perform Common Sub-expression Elimination on CPUI_MULTIEQUAL ops |
| 30 | stackstall | `ActionShadowVar` | `shadowvar` | analysis |  | `coreaction.cc:929` | Check for one CPUI_MULTIEQUAL input set defining more than one Varnode |
| 31 | stackstall | `ActionDeindirect` | `deindirect` | deindirect |  | `coreaction.cc:1260` | Eliminate locally constant indirect calls |
| 32 | stackstall | `ActionStackPtrFlow`(stackspace) | `stackptrflow` | stackptrflow |  | `coreaction.cc:488` | Analyze change to the stack pointer across sub-function calls. |
| 33 | mainloop | **group/pool `stackstall`** | | | | | |
| 34 | mainloop | `ActionRedundBranch` | `redundbranch` | deadcontrolflow |  | `coreaction.cc:3719` | Get rid of redundant branches: duplicate edges between the same input and output block |
| 35 | mainloop | `ActionBlockStructure` | `blockstructure` | blockrecovery |  | `blockaction.cc:2178` | Structure control-flow using standard high-level code constructs. |
| 36 | mainloop | `ActionConstantPtr` | `constantptr` | typerecovery |  | `coreaction.cc:1207` | Check for constants, with pointer type, that correspond to global symbols |
| 37 | mainloop | **group/pool `oppool2`** | | | | | |
| 38 | mainloop | `ActionDeterminedBranch` | `determinedbranch` | unreachable |  | `coreaction.cc:3757` | Remove conditional branches if the condition is constant |
| 39 | mainloop | `ActionUnreachable` | `unreachable` | unreachable |  | `coreaction.cc:3629` | Remove unreachable blocks |
| 40 | mainloop | `ActionNodeJoin` | `nodejoin` | nodejoin |  | `blockaction.cc:2335` | Look for conditional branch expressions that have been split and rejoin them |
| 41 | mainloop | `ActionConditionalExe` | `conditionalexe` | conditionalexe |  | `condexe.cc:477` | Search for and remove various forms of redundant CBRANCH operations |
| 42 | mainloop | `ActionConditionalConst` | `condconst` | analysis |  | `coreaction.cc:4753` | Propagate conditional constants |
| 43 | fullloop | **group/pool `mainloop`** | | | | | |
| 44 | fullloop | `ActionLikelyTrash` | `likelytrash` | protorecovery |  | `coreaction.cc:2266` | Get rid of registers with trash values. |
| 45 | fullloop | `ActionDirectWrite`(true) | `directwrite` | protorecovery_a |  | `coreaction.cc:1451` | Mark Varnodes built out of legal parameters |
| 46 | fullloop | `ActionDirectWrite`(false) | `directwrite` | protorecovery_b |  | `coreaction.cc:1451` | Mark Varnodes built out of legal parameters |
| 47 | fullloop | `ActionDeadCode` | `deadcode` | deadcode |  | `coreaction.cc:4164` | Dead code removal.  Eliminate dead p-code ops |
| 48 | fullloop | `ActionDoNothing` | `donothing` | deadcontrolflow | repeat | `coreaction.cc:3638` | Remove blocks that do nothing |
| 49 | fullloop | `ActionSwitchNorm` | `switchnorm` | switchnorm |  | `coreaction.cc:4787` | Normalize jump-table construction. |
| 50 | fullloop | `ActionReturnSplit` | `returnsplit` | returnsplit |  | `blockaction.cc:2273` | Split the epilog code of the function |
| 51 | fullloop | `ActionUnjustifiedParams` | `unjustparams` | protorecovery |  | `coreaction.cc:5179` | Adjust improperly justified parameters |
| 52 | fullloop | `ActionStartTypes` | `starttypes` | typerecovery |  | `coreaction.hh` | Allow type recovery to start happening |
| 53 | fullloop | `ActionActiveReturn` | `activereturn` | protorecovery |  | `coreaction.cc:1909` | Determine which sub-functions have active output Varnodes |
| 54 | universal | **group/pool `fullloop`** | | | | | |
| 55 | universal | `ActionMappedLocalSync` | `mapped_local_sync` | localrecovery |  | `coreaction.cc:2423` | Do final synchronization of symbols in the local scope with Varnodes |
| 56 | universal | `ActionStartCleanUp` | `startcleanup` | cleanup |  | `coreaction.hh` | Start clean up after main transform phase |
| 57 | universal | **group/pool `cleanup`** | | | | | |
| 58 | universal | `ActionPreferComplement`(true) | `prefercomplement` | blockrecovery |  | `blockaction.cc:2148` | Attempt to normalize symmetric block structures. |
| 59 | universal | `ActionStructureTransform`(true) | `structuretransform` | blockrecovery |  | `blockaction.cc:2118` | Give each control-flow structure an opportunity to make a final transform |
| 60 | universal | `ActionNormalizeBranches` | `normalizebranches` | normalizebranches |  | `blockaction.cc:2125` | Flip conditional control-flow so that preferred comparison operators are used |
| 61 | universal | `ActionAssignHigh` | `assignhigh` | merge | once | `coreaction.hh` | Assign initial high-level HighVariable objects to each Varnode |
| 62 | universal | `ActionMergeRequired` | `mergerequired` | merge | once | `coreaction.hh` | Make required Varnode merges as dictated by CPUI_MULTIEQUAL, CPUI_INDIRECT, and addrtied property |
| 63 | universal | `ActionMarkExplicit` | `markexplicit` | merge | once | `coreaction.cc:3409` | Find explicit Varnodes: Varnodes that have an explicit token representing them in the output |
| 64 | universal | `ActionMarkImplied` | `markimplied` | merge | once | `coreaction.cc:3588` | Mark all the implied Varnode objects, which will have no explicit token in the output |
| 65 | universal | `ActionMergeMultiEntry` | `mergemultientry` | merge | once | `coreaction.hh` | Try to merge Varnodes specified by Symbols with multiple SymbolEntrys |
| 66 | universal | `ActionMergeCopy` | `mergecopy` | merge | once | `coreaction.hh` | Try to merge the input and output Varnodes of a CPUI_COPY op |
| 67 | universal | `ActionDominantCopy` | `dominantcopy` | merge | once | `coreaction.hh` | Replace COPYs from the same source with a single dominant COPY |
| 68 | universal | `ActionDynamicSymbols` | `dynamicsymbols` | dynamic | once | `coreaction.cc:5264` | Make final attachments of dynamically mapped symbols to Varnodes |
| 69 | universal | `ActionMarkIndirectOnly` | `markindirectonly` | merge | once | `coreaction.hh` | Mark illegal Varnode inputs used only in CPUI_INDIRECT ops |
| 70 | universal | `ActionMergeAdjacent` | `mergeadjacent` | merge | once | `coreaction.hh` | Try to merge an op's input Varnode to its output, if they are at the same storage location. |
| 71 | universal | `ActionMergeType` | `mergetype` | merge | once | `coreaction.hh` | Try to merge Varnodes of the same type (if they don't hold different values at the same time) |
| 72 | universal | `ActionHideShadow` | `hideshadow` | merge | once | `coreaction.cc:5226` | Locate shadow Varnodes and adjust them so they are hidden |
| 73 | universal | `ActionCopyMarker` | `copymarker` | merge | once | `coreaction.hh` | Mark COPY operations between Varnodes representing the object as non-printing |
| 74 | universal | `ActionLateDoNothing` | `latedonothing` | blockrecovery |  | `coreaction.cc:3692` | Remove blocks that do nothing after variable merging has occurred |
| 75 | universal | `ActionBlockStructure` | `blockstructure` | blockrecovery |  | `blockaction.cc:2178` | Structure control-flow using standard high-level code constructs. |
| 76 | universal | `ActionPreferComplement`(false) | `prefercomplement` | blockrecovery |  | `blockaction.cc:2148` | Attempt to normalize symmetric block structures. |
| 77 | universal | `ActionStructureTransform`(false) | `structuretransform` | blockrecovery |  | `blockaction.cc:2118` | Give each control-flow structure an opportunity to make a final transform |
| 78 | universal | `ActionOutputPrototype` | `outputprototype` | localrecovery | once | `coreaction.cc:5160` | Set the (already) recovered output data-type as a formal part of the prototype |
| 79 | universal | `ActionInputPrototype` | `inputprototype` | fixateproto | once | `coreaction.cc:5086` | Calculate the prototype for the function. |
| 80 | universal | `ActionMapGlobals` | `mapglobals` | fixateglobals | once | `coreaction.hh` | Create symbols for any discovered global variables in the function. |
| 81 | universal | `ActionDynamicSymbols` | `dynamicsymbols` | dynamic | once | `coreaction.cc:5264` | Make final attachments of dynamically mapped symbols to Varnodes |
| 82 | universal | `ActionNameVars` | `namevars` | merge | once | `coreaction.cc:3145` | Choose names for all high-level variables (HighVariables) |
| 83 | universal | `ActionSetCasts` | `setcasts` | casts | once | `coreaction.cc:2881` | Fill-in CPUI_CAST p-code ops as required by the casting strategy |
| 84 | universal | `ActionFinalStructure` | `finalstructure` | blockrecovery |  | `blockaction.cc:2195` | Perform final organization of the control-flow structure |
| 85 | universal | `ActionPrototypeWarnings` | `prototypewarnings` | protorecovery | once | `coreaction.cc:5281` | Add warnings for prototypes that aren't modeled properly |
| 86 | universal | `ActionStop` | `stop` | base |  | `coreaction.hh` | Do any post-processing after decompilation |

The three pools are `oppool1` (rules 1–134 of section 6, plus any
`Architecture::extra_pool_rules`), `oppool2` (rules 135–139) and `cleanup`
(rules 140–161).

Reading the order: actions 1–8 set up (lift and build blocks in
`ActionStart`, attach prototypes to calls). The **main loop** (9–42) is
heritage (one more SSA pass each time round, so later address spaces and
newly exposed stack locations enter SSA gradually — see the spaces'
`delay` and `deadcodedelay`), parameter and return recovery, dead-code
removal, type inference, local-variable restructuring, then the big rule
pool with five companion actions (`stackstall`), then control-flow
simplification and the pointer rule pool. The **full loop** (43–53) adds
the slower convergence steps (likely-trash registers, switch
normalisation, return splitting, enabling type recovery). After the loops:
cleanup rules, final block structuring, the merge sequence (61–73) that
creates `HighVariable`s, prototype fixation, naming, casts and final
structure.

## 6. Rules

Generated **(ran)** from the class declarations, `getOpList` bodies, the
`\class`/`\brief` comments and the universal action. "#" is the position in
the pipeline (the order rules are tried for one op is this order restricted
to the op's opcode). "Name" is what the console and the debug trace print.

| # | Class | Name | Pool | Group | `applyOp` at | Opcodes | Brief (Ghidra's) |
|---:|---|---|---|---|---|---|---|
| 1 | `RuleEarlyRemoval` | `earlyremoval` | oppool1 | deadcode | `ruleaction.cc`:44 | 65 opcodes | Get rid of unused PcodeOp objects where we can guarantee the output is unused |
| 2 | `RuleTermOrder` | `termorder` | oppool1 | analysis | `ruleaction.cc`:653 | 16 opcodes | Order the inputs to commutative operations |
| 3 | `RuleSelectCse` | `selectcse` | oppool1 | analysis | `ruleaction.cc`:177 | INT_SRIGHT, SUBPIECE | Look for common sub-expressions (built out of a restricted set of ops) |
| 4 | `RuleCollectTerms` | `collect_terms` | oppool1 | analysis | `ruleaction.cc`:97 | INT_ADD | Collect terms in a sum: `V * c + V * d   =>  V * (c + d)` |
| 5 | `RulePullsubMulti` | `pullsub_multi` | oppool1 | analysis | `ruleaction.cc`:872 | SUBPIECE | Pull SUBPIECE back through MULTIEQUAL |
| 6 | `RulePullsubIndirect` | `pullsub_indirect` | oppool1 | analysis | `ruleaction.cc`:954 | SUBPIECE | Pull-back SUBPIECE through INDIRECT |
| 7 | `RulePushMulti` | `push_multi` | oppool1 | nodejoin | `ruleaction.cc`:1064 | MULTIEQUAL | Simplify MULTIEQUAL operations where the branches hold the same value |
| 8 | `RuleSborrow` | `sborrow` | oppool1 | analysis | `ruleaction.cc`:3324 | INT_SBORROW | Simplify signed comparisons using INT_SBORROW |
| 9 | `RuleScarry` | `scarry` | oppool1 | analysis | `ruleaction.cc`:3393 | INT_SCARRY | Simplify signed comparisons using INT_SCARRY |
| 10 | `RuleIntLessEqual` | `intlessequal` | oppool1 | analysis | `ruleaction.cc`:601 | INT_LESSEQUAL, INT_SLESSEQUAL | Convert LESSEQUAL to LESS:  `V <= c  =>  V < (c+1)` |
| 11 | `RuleTrivialArith` | `trivialarith` | oppool1 | analysis | `ruleaction.cc`:2383 | 16 opcodes | Simplify trivial arithmetic expressions |
| 12 | `RuleTrivialBool` | `trivialbool` | oppool1 | analysis | `ruleaction.cc`:2452 | BOOL_AND, BOOL_OR, BOOL_XOR | Simplify boolean expressions when one side is constant |
| 13 | `RuleTrivialShift` | `trivialshift` | oppool1 | analysis | `ruleaction.cc`:3468 | INT_LEFT, INT_RIGHT, INT_SRIGHT | Simplify trivial shifts:  `V << 0  =>  V,  V << #64  =>  0` |
| 14 | `RuleSignShift` | `signshift` | oppool1 | analysis | `ruleaction.cc`:3498 | INT_RIGHT | Normalize sign-bit extraction:  `V >> 0x1f   =>  (V s>> 0x1f) * -1` |
| 15 | `RuleTestSign` | `testsign` | oppool1 | analysis | `ruleaction.cc`:3575 | INT_SRIGHT | Convert sign-bit test to signed comparison:  `(V s>> 0x1f) != 0   =>  V s< 0` |
| 16 | `RuleIdentityEl` | `identityel` | oppool1 | analysis | `ruleaction.cc`:3639 | BOOL_OR, BOOL_XOR, INT_ADD, INT_MULT, INT_OR, INT_XOR | Collapse operations using identity element:  `V + 0  =>  V` |
| 17 | `RuleOrMask` | `ormask` | oppool1 | analysis | `ruleaction.cc`:274 | INT_OR | Simplify INT_OR with full mask:  `V = W \| 0xffff  =>  V = W` |
| 18 | `RuleAndMask` | `andmask` | oppool1 | analysis | `ruleaction.cc`:300 | INT_AND | Collapse unnecessary INT_AND |
| 19 | `RuleOrConsume` | `orconsume` | oppool1 | analysis | `ruleaction.cc`:343 | INT_OR, INT_XOR | Simply OR with unconsumed input:  `V = A \| B  =>  V = B  if  nzm(A) & consume(V) == 0 |
| 20 | `RuleOrCollapse` | `orcollapse` | oppool1 | analysis | `ruleaction.cc`:374 | INT_OR | Collapse unnecessary INT_OR |
| 21 | `RuleAndOrLump` | `andorlump` | oppool1 | analysis | `ruleaction.cc`:403 | INT_AND, INT_OR, INT_XOR | Collapse constants in logical expressions:  `(V & c) & d  =>  V & (c & d)` |
| 22 | `RuleShiftBitops` | `shiftbitops` | oppool1 | analysis | `ruleaction.cc`:480 | INT_LEFT, INT_MULT, INT_RIGHT, SUBPIECE | Shifting away all non-zero bits of one-side of a logical/arithmetic op |
| 23 | `RuleRightShiftAnd` | `rightshiftand` | oppool1 | analysis | `ruleaction.cc`:570 | INT_RIGHT, INT_SRIGHT | Simplify INT_RIGHT and INT_SRIGHT ops where an INT_AND mask becomes unnecessary |
| 24 | `RuleNotDistribute` | `notdistribute` | oppool1 | analysis | `ruleaction.cc`:1137 | BOOL_NEGATE | Distribute BOOL_NEGATE:  `!(V && W)  =>  !V \|\| !W` |
| 25 | `RuleHighOrderAnd` | `highorderand` | oppool1 | analysis | `ruleaction.cc`:1186 | INT_AND | Simplify INT_AND when applied to aligned INT_ADD:  `(V + c) & 0xfff0  =>  V + (c & 0xfff0)` |
| 26 | `RuleAndDistribute` | `anddistribute` | oppool1 | analysis | `ruleaction.cc`:1250 | INT_AND | Distribute INT_AND through INT_OR if result is simpler |
| 27 | `RuleAndCommute` | `andcommute` | oppool1 | analysis | `ruleaction.cc`:1535 | INT_AND | Commute INT_AND with INT_LEFT and INT_RIGHT: `(V << W) & d  =>  (V & (W >> c)) << c` |
| 28 | `RuleAndPiece` | `andpiece` | oppool1 | analysis | `ruleaction.cc`:1643 | INT_AND | Convert PIECE to INT_ZEXT where appropriate: `V & concat(W,X)  =>  zext(X)` |
| 29 | `RuleAndZext` | `andzext` | oppool1 | analysis | `ruleaction.cc`:1709 | INT_AND | Convert INT_AND to INT_ZEXT where appropriate: `sext(X) & 0xffff  =>  zext(X)` |
| 30 | `RuleAndCompare` | `andcompare` | oppool1 | analysis | `ruleaction.cc`:1748 | INT_EQUAL, INT_NOTEQUAL | Simplify INT_ZEXT and SUBPIECE in masked comparison: `zext(V) & c == 0  =>  V & (c & mask) == 0` |
| 31 | `RuleDoubleSub` | `doublesub` | oppool1 | analysis | `ruleaction.cc`:1809 | SUBPIECE | Simplify chained SUBPIECE:  `sub( sub(V,c), d)  =>  sub(V, c+d)` |
| 32 | `RuleDoubleShift` | `doubleshift` | oppool1 | analysis | `ruleaction.cc`:1843 | INT_LEFT, INT_MULT, INT_RIGHT | Simplify chained shifts INT_LEFT and INT_RIGHT |
| 33 | `RuleDoubleArithShift` | `doublearithshift` | oppool1 | analysis | `ruleaction.cc`:1944 | INT_SRIGHT | Simplify two sequential INT_SRIGHT: `(x s>> c) s>> d   =>  x s>> saturate(c + d)` |
| 34 | `RuleConcatShift` | `concatshift` | oppool1 | analysis | `ruleaction.cc`:1980 | INT_RIGHT, INT_SRIGHT | Simplify INT_RIGHT canceling PIECE: `concat(V,W) >> c  =>  zext(V)` |
| 35 | `RuleLeftRight` | `leftright` | oppool1 | analysis | `ruleaction.cc`:2031 | INT_RIGHT, INT_SRIGHT | Transform canceling INT_RIGHT or INT_SRIGHT of INT_LEFT |
| 36 | `RuleShiftCompare` | `shiftcompare` | oppool1 | analysis | `ruleaction.cc`:2078 | INT_EQUAL, INT_NOTEQUAL | Transform shifts in comparisons:  `V >> c == d  =>  V == (d << c)` |
| 37 | `RuleShift2Mult` | `shift2mult` | oppool1 | analysis | `ruleaction.cc`:3677 | INT_LEFT | Convert INT_LEFT to INT_MULT:  `V << 2  =>  V * 4` |
| 38 | `RuleShiftPiece` | `shiftpiece` | oppool1 | analysis | `ruleaction.cc`:3752 | INT_ADD, INT_OR, INT_XOR | Convert "shift and add" to PIECE:  (zext(V) << 16) + zext(W)  =>  concat(V,W) |
| 39 | `RuleMultiCollapse` | `multicollapse` | oppool1 | analysis | `ruleaction.cc`:3197 | MULTIEQUAL | Collapse MULTIEQUAL whose inputs all trace to the same value |
| 40 | `RuleAliasUpdate` | `aliasupdate` | oppool1 | analysis | `ruleaction.cc`:3181 | CALL, CALLIND, CALLOTHER, STORE | Collapse INDIRECTs when there is no longer a possible alias of its output |
| 41 | `Rule2Comp2Mult` | `2comp2mult` | oppool1 | analysis | `ruleaction.cc`:3965 | INT_2COMP | Eliminate INT_2COMP:  `-V  =>  V * -1` |
| 42 | `RuleSub2Add` | `sub2add` | oppool1 | analysis | `ruleaction.cc`:4018 | INT_SUB | Eliminate INT_SUB:  `V - W  =>  V + W * -1` |
| 43 | `RuleCarryElim` | `carryelim` | oppool1 | analysis | `ruleaction.cc`:3986 | INT_CARRY | Transform INT_CARRY using a constant:  `carry(V,c)  =>  -c <= V` |
| 44 | `RuleBxor2NotEqual` | `bxor2notequal` | oppool1 | analysis | `ruleaction.cc`:259 | BOOL_XOR | Eliminate BOOL_XOR:  `V ^^ W  =>  V != W` |
| 45 | `RuleLess2Zero` | `less2zero` | oppool1 | analysis | `ruleaction.cc`:5497 | INT_LESS | Simplify INT_LESS applied to extremal constants |
| 46 | `RuleLessEqual2Zero` | `lessequal2zero` | oppool1 | analysis | `ruleaction.cc`:5545 | INT_LESSEQUAL | Simplify INT_LESSEQUAL applied to extremal constants |
| 47 | `RuleSLess2Zero` | `sless2zero` | oppool1 | analysis | `ruleaction.cc`:5637 | INT_SLESS | Simplify INT_SLESS applied to 0 or -1 |
| 48 | `RuleEqual2Zero` | `equal2zero` | oppool1 | analysis | `ruleaction.cc`:5794 | INT_EQUAL, INT_NOTEQUAL | Simplify INT_EQUAL applied to 0: `0 == V + W * -1  =>  V == W  or  0 == V + c  =>  V == -c` |
| 49 | `RuleEqual2Constant` | `equal2constant` | oppool1 | analysis | `ruleaction.cc`:5861 | INT_EQUAL, INT_NOTEQUAL | Simplify INT_EQUAL applied to arithmetic expressions |
| 50 | `RuleThreeWayCompare` | `threewaycomp` | oppool1 | analysis | `ruleaction.cc`:10149 | INT_EQUAL, INT_NOTEQUAL, INT_SLESS, INT_SLESSEQUAL | Simplify expressions involving three-way comparisons |
| 51 | `RuleXorCollapse` | `xorcollapse` | oppool1 | analysis | `ruleaction.cc`:4048 | INT_EQUAL, INT_NOTEQUAL | Eliminate INT_XOR in comparisons: `(V ^ W) == 0  =>  V == W` |
| 52 | `RuleAddMultCollapse` | `addmultcollapse` | oppool1 | analysis | `ruleaction.cc`:4091 | INT_ADD, INT_MULT | Collapse constants in an additive or multiplicative expression |
| 53 | `RuleCollapseConstants` | `collapseconstants` | oppool1 | analysis | `ruleaction.cc`:3852 | 52 opcodes | Collapse constant expressions |
| 54 | `RuleTransformCpool` | `transformcpool` | oppool1 | analysis | `ruleaction.cc`:3886 | CPOOLREF | Transform CPOOLREF operations by looking up the value in the constant pool |
| 55 | `RulePropagateCopy` | `propagatecopy` | oppool1 | analysis | `ruleaction.cc`:3923 | COPY | Propagate the input of a COPY to all the places that read the output |
| 56 | `RuleZextEliminate` | `zexteliminate` | oppool1 | analysis | `ruleaction.cc`:2508 | INT_EQUAL, INT_LESS, INT_LESSEQUAL, INT_NOTEQUAL | Eliminate INT_ZEXT in comparisons:  `zext(V) == c  =>  V == c` |
| 57 | `RuleSlessToLess` | `slesstoless` | oppool1 | analysis | `ruleaction.cc`:2561 | INT_SLESS, INT_SLESSEQUAL | Convert INT_SLESS to INT_LESS when comparing positive values |
| 58 | `RuleZextSless` | `zextsless` | oppool1 | analysis | `ruleaction.cc`:2585 | INT_SLESS, INT_SLESSEQUAL | Transform INT_ZEXT and INT_SLESS:  `zext(V) s< c  =>  V < c` |
| 59 | `RuleBitUndistribute` | `bitundistribute` | oppool1 | analysis | `ruleaction.cc`:2635 | INT_AND, INT_OR, INT_XOR | Undo distributed operations through INT_AND, INT_OR, and INT_XOR |
| 60 | `RuleBooleanUndistribute` | `booleanundistribute` | oppool1 | analysis | `ruleaction.cc`:2732 | INT_EQUAL, INT_NOTEQUAL | Undo distributed BOOL_AND through INT_NOTEQUAL |
| 61 | `RuleBooleanDedup` | `booleandedup` | oppool1 | analysis | `ruleaction.cc`:2853 | BOOL_AND, BOOL_OR | Remove duplicate clauses in boolean expressions |
| 62 | `RuleBoolZext` | `boolzext` | oppool1 | analysis | `ruleaction.cc`:3016 | INT_ZEXT | Simplify boolean expressions of the form zext(V) * -1 |
| 63 | `RuleBooleanNegate` | `booleannegate` | oppool1 | analysis | `ruleaction.cc`:2970 | INT_EQUAL, INT_NOTEQUAL | Simplify comparisons with boolean values:  `V == false  =>  !V,  V == true  =>  V` |
| 64 | `RuleLogic2Bool` | `logic2bool` | oppool1 | analysis | `ruleaction.cc`:3139 | INT_AND, INT_OR, INT_XOR | Convert logical to boolean operations:  `V & W  =>  V && W,  V \| W  => V \|\| W` |
| 65 | `RuleSubExtComm` | `subextcomm` | oppool1 | analysis | `ruleaction.cc`:4401 | SUBPIECE | Commute SUBPIECE and INT_ZEXT:  `sub(zext(V),c)  =>  zext(sub(V,c))` |
| 66 | `RuleSubCommute` | `subcommute` | oppool1 | analysis | `ruleaction.cc`:4513 | SUBPIECE | Commute SUBPIECE operations with earlier operations where possible |
| 67 | `RuleConcatCommute` | `concatcommute` | oppool1 | analysis | `ruleaction.cc`:4666 | PIECE | Commute PIECE with INT_AND, INT_OR, and INT_XOR |
| 68 | `RuleConcatZext` | `concatzext` | oppool1 | analysis | `ruleaction.cc`:4737 | PIECE | Commute PIECE with INT_ZEXT:  `concat(zext(V),W)  =>  zext(concat(V,W))` |
| 69 | `RuleZextCommute` | `zextcommute` | oppool1 | analysis | `ruleaction.cc`:4775 | INT_RIGHT | Commute INT_ZEXT with INT_RIGHT: `zext(V) >> W  =>  zext(V >> W)` |
| 70 | `RuleZextShiftZext` | `zextshiftzext` | oppool1 | analysis | `ruleaction.cc`:4808 | INT_ZEXT | Simplify multiple INT_ZEXT operations: `zext( zext(V) << c )  => zext(V) << c` |
| 71 | `RuleShiftAnd` | `shiftand` | oppool1 | analysis | `ruleaction.cc`:4856 | INT_LEFT, INT_MULT, INT_RIGHT | Eliminate any INT_AND when the bits it zeroes out are discarded by a shift |
| 72 | `RuleConcatZero` | `concatzero` | oppool1 | analysis | `ruleaction.cc`:4908 | PIECE | Simplify concatenation with zero:  `concat(V,0)  =>  zext(V) << c` |
| 73 | `RuleConcatLeftShift` | `concatleftshift` | oppool1 | analysis | `ruleaction.cc`:4936 | PIECE | Simplify concatenation of extended value: `concat(V, zext(W) << c)  =>  concat( concat(V,W), 0)` |
| 74 | `RuleSubZext` | `subzext` | oppool1 | analysis | `ruleaction.cc`:4981 | INT_ZEXT | Simplify INT_ZEXT applied to SUBPIECE expressions |
| 75 | `RuleSubCancel` | `subcancel` | oppool1 | analysis | `ruleaction.cc`:5061 | SUBPIECE | Simplify composition of SUBPIECE with INT_ZEXT, INT_SEXT, and INT_AND |
| 76 | `RuleShiftSub` | `shiftsub` | oppool1 | analysis | `ruleaction.cc`:5133 | SUBPIECE | Simplify SUBPIECE applied to INT_LEFT: `sub( V << 8*k, c)  =>  sub(V,c-k)` |
| 77 | `RuleHumptyDumpty` | `humptydumpty` | oppool1 | analysis | `ruleaction.cc`:5167 | PIECE | Simplify break and rejoin:  `concat( sub(V,c), sub(V,0) )  =>  V` |
| 78 | `RuleDumptyHump` | `dumptyhump` | oppool1 | analysis | `ruleaction.cc`:5220 | SUBPIECE | Simplify join and break apart: `sub( concat(V,W), c)  =>  sub(W,c)` |
| 79 | `RuleHumptyOr` | `humptyor` | oppool1 | analysis | `ruleaction.cc`:5274 | INT_OR | Simplify masked pieces INT_ORed together:  `(V & ff00) \| (V & 00ff)  =>  V` |
| 80 | `RuleNegateIdentity` | `negateidentity` | oppool1 | analysis | `ruleaction.cc`:442 | INT_NEGATE | Apply INT_NEGATE identities:  `V & ~V  => #0,  V \| ~V  ->  #-1` |
| 81 | `RuleSubNormal` | `subnormal` | oppool1 | analysis | `ruleaction.cc`:7685 | SUBPIECE | Pull-back SUBPIECE through INT_RIGHT and INT_SRIGHT |
| 82 | `RulePositiveDiv` | `positivediv` | oppool1 | analysis | `ruleaction.cc`:7770 | INT_SDIV, INT_SREM | Signed division of positive values is unsigned division |
| 83 | `RuleDivTermAdd` | `divtermadd` | oppool1 | analysis | `ruleaction.cc`:7801 | INT_RIGHT, INT_SRIGHT, SUBPIECE | Simplify expressions associated with optimized division expressions |
| 84 | `RuleDivTermAdd2` | `divtermadd2` | oppool1 | analysis | `ruleaction.cc`:7922 | INT_RIGHT | Simplify another expression associated with optimized division |
| 85 | `RuleDivOpt` | `divopt` | oppool1 | analysis | `ruleaction.cc`:8248 | INT_RIGHT, INT_SRIGHT, SUBPIECE | Convert INT_MULT and shift forms into INT_DIV or INT_SDIV |
| 86 | `RuleSignForm` | `signform` | oppool1 | analysis | `ruleaction.cc`:8424 | SUBPIECE | Normalize sign extraction:  `sub(sext(V),c)  =>  V s>> 31` |
| 87 | `RuleSignForm2` | `signform2` | oppool1 | analysis | `ruleaction.cc`:8459 | INT_SRIGHT | Normalize sign extraction:  `sub(sext(V) * small,c) s>> 31  =>  V s>> 31` |
| 88 | `RuleSignDiv2` | `signdiv2` | oppool1 | analysis | `ruleaction.cc`:8318 | INT_SRIGHT | Convert INT_SRIGHT form into INT_SDIV:  `(V + -1*(V s>> 31)) s>> 1  =>  V s/ 2` |
| 89 | `RuleDivChain` | `divchain` | oppool1 | analysis | `ruleaction.cc`:8372 | INT_DIV, INT_SDIV | Collapse two consecutive divisions:  `(x / c1) / c2  =>  x / (c1*c2)` |
| 90 | `RuleSignNearMult` | `signnearmult` | oppool1 | analysis | `ruleaction.cc`:8513 | INT_AND | Simplify division form: `(V + (V s>> 0x1f)>>(32-n)) & (-1<<n)  =>  (V s/ 2^n) * 2^n` |
| 91 | `RuleModOpt` | `modopt` | oppool1 | analysis | `ruleaction.cc`:8575 | INT_DIV, INT_SDIV | Simplify expressions that optimize INT_REM and INT_SREM |
| 92 | `RuleSignMod2nOpt` | `signmod2nopt` | oppool1 | analysis | `ruleaction.cc`:8637 | INT_RIGHT | Convert INT_SREM forms:  `(V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)  =>  V s% 2^n` |
| 93 | `RuleSignMod2nOpt2` | `signmod2nopt2` | oppool1 | analysis | `ruleaction.cc`:8831 | INT_MULT | Convert INT_SREM form:  `V - (Vadj & ~(2^n-1)) =>  V s% 2^n` |
| 94 | `RuleSignMod2Opt` | `signmod2opt` | oppool1 | analysis | `ruleaction.cc`:8759 | INT_AND | Convert INT_SREM form:  `(V - sign)&1 + sign  =>  V s% 2` |
| 95 | `RuleSwitchSingle` | `switchsingle` | oppool1 | analysis | `ruleaction.cc`:5354 | BRANCHIND | Convert BRANCHIND with only one computed destination to a BRANCH |
| 96 | `RuleCondNegate` | `condnegate` | oppool1 | analysis | `ruleaction.cc`:5416 | CBRANCH | Flip conditions to match structuring cues |
| 97 | `RuleBoolNegate` | `boolnegate` | oppool1 | analysis | `ruleaction.cc`:5455 | BOOL_NEGATE | Apply a set of identities involving BOOL_NEGATE |
| 98 | `RuleLessEqual` | `lessequal` | oppool1 | analysis | `ruleaction.cc`:2263 | BOOL_OR | Simplify 'less than or equal':  `V < W \|\| V == W  =>  V <= W` |
| 99 | `RuleLessNotEqual` | `lessnotequal` | oppool1 | analysis | `ruleaction.cc`:2321 | BOOL_AND | Simplify INT_LESSEQUAL && INT_NOTEQUAL:  `V <= W && V != W  =>  V < W` |
| 100 | `RuleLessOne` | `lessone` | oppool1 | analysis | `ruleaction.cc`:1315 | INT_LESS, INT_LESSEQUAL | Transform INT_LESS of 0 or 1:  `V < 1  =>  V == 0,  V <= 0  =>  V == 0` |
| 101 | `RuleRangeMeld` | `rangemeld` | oppool1 | analysis | `ruleaction.cc`:1347 | BOOL_AND, BOOL_OR | Merge range conditions of the form: `V s< c, c s< V, V == c, V != c` |
| 102 | `RuleFloatRange` | `floatrange` | oppool1 | analysis | `ruleaction.cc`:1453 | BOOL_AND, BOOL_OR | Merge range conditions of the form: `V f< c, c f< V, V f== c` etc. |
| 103 | `RulePiece2Zext` | `piece2zext` | oppool1 | analysis | `ruleaction.cc`:209 | PIECE | Concatenation with 0 becomes an extension:  `V = concat(#0,W)  =>  V = zext(W)` |
| 104 | `RulePiece2Sext` | `piece2sext` | oppool1 | analysis | `ruleaction.cc`:230 | PIECE | Concatenation with sign bits becomes an extension: `concat( V s>> #0x1f , V)  => sext(V)` |
| 105 | `RulePopcountBoolXor` | `popcountboolxor` | oppool1 | analysis | `ruleaction.cc`:10279 | POPCOUNT | Simplify boolean expressions that are combined through POPCOUNT |
| 106 | `RuleXorSwap` | `xorswap` | oppool1 | analysis | `ruleaction.cc`:10628 | INT_XOR | Simplify limited chains of XOR operations |
| 107 | `RuleLzcountShiftBool` | `lzcountshiftbool` | oppool1 | analysis | `ruleaction.cc`:10669 | LZCOUNT | Simplify equality checks that use lzcount:  `lzcount(X) >> c  =>  X == 0` if X is 2^c bits wide |
| 108 | `RuleFloatSign` | `floatsign` | oppool1 | analysis | `ruleaction.cc`:10736 | 18 opcodes | Convert floating-point sign bit manipulation into FLOAT_ABS or FLOAT_NEG |
| 109 | `RuleOrCompare` | `orcompare` | oppool1 | analysis | `ruleaction.cc`:10817 | INT_OR | Simplify INT_OR in comparisons with 0. |
| 110 | `RuleSubvarAnd` | `subvar_and` | oppool1 | subvar | `subflow.cc`:1553 | INT_AND | Perform SubVariableFlow analysis triggered by INT_AND |
| 111 | `RuleSubvarSubpiece` | `subvar_subpiece` | oppool1 | subvar | `subflow.cc`:1590 | SUBPIECE | Perform SubVariableFlow analysis triggered by SUBPIECE |
| 112 | `RuleSplitFlow` | `splitflow` | oppool1 | subvar | `subflow.cc`:2041 | SUBPIECE | Try to detect and split artificially joined Varnodes |
| 113 | `RulePtrFlow` | `ptrflow` | oppool1 | subvar | `ruleaction.cc`:9163 | 10 opcodes | Mark Varnode and PcodeOp objects that are carrying or operating on pointers |
| 114 | `RuleSubvarCompZero` | `subvar_compzero` | oppool1 | subvar | `subflow.cc`:1628 | INT_EQUAL, INT_NOTEQUAL | Perform SubvariableFlow analysis triggered by testing of a single bit |
| 115 | `RuleSubvarShift` | `subvar_shift` | oppool1 | subvar | `subflow.cc`:1680 | INT_RIGHT | Perform SubvariableFlow analysis triggered by INT_RIGHT |
| 116 | `RuleSubvarZext` | `subvar_zext` | oppool1 | subvar | `subflow.cc`:1704 | INT_ZEXT | Perform SubvariableFlow analysis triggered by INT_ZEXT |
| 117 | `RuleSubvarSext` | `subvar_sext` | oppool1 | subvar | `subflow.cc`:1723 | INT_SEXT | Perform SubvariableFlow analysis triggered by INT_SEXT |
| 118 | `RuleNegateNegate` | `negatenegate` | oppool1 | analysis | `ruleaction.cc`:9261 | INT_NEGATE | Simplify INT_NEGATE chains:  `~~V  =>  V` |
| 119 | `RuleConditionalMove` | `conditionalmove` | oppool1 | conditionalexe | `ruleaction.cc`:9393 | MULTIEQUAL | Simplify various conditional move situations |
| 120 | `RuleOrPredicate` | `orpredicate` | oppool1 | conditionalexe | `condexe.cc`:653 | INT_OR, INT_XOR | Simplify predication constructions involving the INT_OR operator |
| 121 | `RuleFuncPtrEncoding` | `funcptrencoding` | oppool1 | analysis | `ruleaction.cc`:9929 | CALLIND | Eliminate ARM/THUMB style masking of the low order bits on function pointers |
| 122 | `RuleSubfloatConvert` | `subfloat_convert` | oppool1 | floatprecision | `subflow.cc`:3517 | FLOAT_FLOAT2FLOAT | Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT |
| 123 | `RuleFloatCast` | `floatcast` | oppool1 | floatprecision | `ruleaction.cc`:9563 | FLOAT_FLOAT2FLOAT, FLOAT_TRUNC | Replace (casttosmall)(casttobig)V with identity or with single cast |
| 124 | `RuleIgnoreNan` | `ignorenan` | oppool1 | floatprecision | `ruleaction.cc`:9743 | FLOAT_NAN | Remove certain NaN operations by assuming their result is always false |
| 125 | `RuleUnsigned2Float` | `unsigned2float` | oppool1 | analysis | `ruleaction.cc`:9798 | FLOAT_INT2FLOAT | Simplify conversion:  `T = int2float((X >> 1) \| X & #1);  T + T   =>  int2float( zext(X) )` |
| 126 | `RuleInt2FloatCollapse` | `int2floatcollapse` | oppool1 | analysis | `ruleaction.cc`:9866 | FLOAT_INT2FLOAT | Collapse equivalent FLOAT_INT2FLOAT computations along converging data-flow paths |
| 127 | `RulePtraddUndo` | `ptraddundo` | oppool1 | typerecovery | `ruleaction.cc`:6808 | PTRADD | Remove PTRADD operations with mismatched data-type information |
| 128 | `RulePtrsubUndo` | `ptrsubundo` | oppool1 | typerecovery | `ruleaction.cc`:7034 | PTRSUB | Remove PTRSUB operations with mismatched data-type information |
| 129 | `RuleSegment` | `segment` | oppool1 | segment | `ruleaction.cc`:8967 | SEGMENTOP | Propagate constants through a SEGMENTOP |
| 130 | `RulePiecePathology` | `piecepathology` | oppool1 | protorecovery | `ruleaction.cc`:10581 | PIECE | Search for concatenations with unlikely things to inform return/parameter consumption calculation |
| 131 | `RuleDoubleLoad` | `doubleload` | oppool1 | doubleload | `double.cc`:3425 | PIECE | Collapse contiguous loads: `x = CONCAT44(*(ptr+4),*ptr)  =>  x = *ptr` |
| 132 | `RuleDoubleStore` | `doublestore` | oppool1 | doubleprecis | `double.cc`:3496 | STORE | Collapse contiguous stores:  `*ptr = SUB(x,0); *(ptr + 4) = SUB(x,4)  =>  *ptr = x` |
| 133 | `RuleDoubleIn` | `doublein` | oppool1 | doubleprecis | `double.cc`:3242 | SUBPIECE | Simply a double precision operation, pushing down one level, starting from a marked double precision input. |
| 134 | `RuleDoubleOut` | `doubleout` | oppool1 | doubleprecis | `double.cc`:3315 | PIECE | Simplify a double precision operation, pulling back one level, starting from inputs to a PIECE operation |
| 135 | `RulePushPtr` | `pushptr` | oppool2 | typerecovery | `ruleaction.cc`:6744 | INT_ADD | Push a Varnode with known pointer data-type to the bottom of its additive expression |
| 136 | `RuleStructOffset0` | `structoffset0` | oppool2 | typerecovery | `ruleaction.cc`:6574 | LOAD, STORE | Convert a LOAD or STORE to the first element of a structure to a PTRSUB. |
| 137 | `RulePtrArith` | `ptrarith` | oppool2 | typerecovery | `ruleaction.cc`:6535 | INT_ADD | Transform pointer arithmetic |
| 138 | `RuleLoadVarnode` | `loadvarnode` | oppool2 | stackvars | `ruleaction.cc`:4275 | LOAD | Convert LOAD operations using a constant offset to COPY |
| 139 | `RuleStoreVarnode` | `storevarnode` | oppool2 | stackvars | `ruleaction.cc`:4317 | STORE | Convert STORE operations using a constant offset to COPY |
| 140 | `RuleMultNegOne` | `multnegone` | cleanup | cleanup | `ruleaction.cc`:7067 | INT_MULT | Cleanup: Convert INT_2COMP from INT_MULT:  `V * -1  =>  -V` |
| 141 | `RuleAddUnsigned` | `addunsigned` | cleanup | cleanup | `ruleaction.cc`:7088 | INT_ADD | Cleanup:  Convert INT_ADD of constants to INT_SUB:  `V + 0xff...  =>  V - 0x00...` |
| 142 | `Rule2Comp2Sub` | `2comp2sub` | cleanup | cleanup | `ruleaction.cc`:7130 | INT_2COMP | Cleanup: Convert INT_ADD back to INT_SUB: `V + -W  ==> V - W` |
| 143 | `RuleDumptyHumpLate` | `dumptyhumplate` | cleanup | cleanup | `subflow.cc`:3025 | SUBPIECE | Simplify join and break apart based on data-types |
| 144 | `RuleSubRight` | `subright` | cleanup | cleanup | `ruleaction.cc`:7157 | SUBPIECE | Cleanup: Convert truncation to cast: `sub(V,c)  =>  sub(V>>c*8,0)` |
| 145 | `RuleFloatSignCleanup` | `floatsigncleanup` | cleanup | cleanup | `ruleaction.cc`:10792 | INT_AND, INT_XOR | Convert floating-point sign bit manipulation into FLOAT_ABS or FLOAT_NEG |
| 146 | `RuleExpandLoad` | `expandload` | cleanup | cleanup | `ruleaction.cc`:10940 | LOAD | Convert LOAD size to match pointer data-type |
| 147 | `RulePtrsubCharConstant` | `ptrsubcharconstant` | cleanup | cleanup | `ruleaction.cc`:7260 | PTRSUB | Cleanup: Set-up to print string constants |
| 148 | `RuleExtensionPush` | `extensionpush` | cleanup | cleanup | `ruleaction.cc`:7323 | INT_SEXT, INT_ZEXT | Duplicate CPUI_INT_ZEXT and CPUI_INT_SEXT operations if the result is used in multiple pointer calculations |
| 149 | `RulePieceStructure` | `piecestructure` | cleanup | cleanup | `ruleaction.cc`:7515 | INT_ZEXT, PIECE | Concatenating structure pieces gets printed as explicit write statements |
| 150 | `RuleAndStructure` | `andstructure` | cleanup | cleanup | `ruleaction.cc`:7618 | INT_AND | Convert `x & #mask => zext(sub(x,#c))` when the mask corresponds to a field access |
| 151 | `RuleSplitCopy` | `splitcopy` | cleanup | splitcopy | `subflow.cc`:2960 | COPY | Split COPY ops based on TypePartialStruct |
| 152 | `RuleSplitLoad` | `splitload` | cleanup | splitpointer | `subflow.cc`:2983 | LOAD | Split LOAD ops based on TypePartialStruct |
| 153 | `RuleSplitStore` | `splitstore` | cleanup | splitpointer | `subflow.cc`:3004 | STORE | Split STORE ops based on TypePartialStruct |
| 154 | `RuleStringCopy` | `stringcopy` | cleanup | constsequence | `constseq.cc`:977 | COPY | Replace a sequence of COPY ops moving single characters with a CALLOTHER copying a whole string |
| 155 | `RuleStringStore` | `stringstore` | cleanup | constsequence | `constseq.cc`:1009 | STORE | Replace a sequence of STORE ops moving single characters with a CALLOTHER copying a whole string |
| 156 | `RuleBitFieldStore` | `bitfield_store` | cleanup | bitfields | `bitfield.cc`:1677 | STORE | Collapse bitfield insertion ending in a CPUI_STORE |
| 157 | `RuleBitFieldOut` | `bitfield_out` | cleanup | bitfields | `bitfield.cc`:1700 | the set `BitFieldInsertTransform::allowedFinalWrites` | Collapse bitfield insertion ending in a write to a mapped Varnode |
| 158 | `RuleBitFieldLoad` | `bitfield_load` | cleanup | bitfields | `bitfield.cc`:1735 | LOAD | Collapse bitfield pulls starting with a CPUI_LOAD |
| 159 | `RuleBitFieldIn` | `bitfield_in` | cleanup | bitfields | `bitfield.cc`:1763 | 17 opcodes | Collapse bitfield pulls starting with mapped Varnodes |
| 160 | `RulePullAbsorb` | `pull_absorb` | cleanup | bitfields | `bitfield.cc`:2183 | SPULL, ZPULL | Simplify expressions explicitly using ZPULL and SPULL p-code ops |
| 161 | `RuleInsertAbsorb` | `insert_absorb` | cleanup | bitfields | `bitfield.cc`:2378 | INSERT | Simplify expressions explicitly using the INSERT p-code op |
| — | `RuleEquality` | `equality` | — | — | `ruleaction.cc`:621 | INT_EQUAL, INT_NOTEQUAL | Collapse INT_EQUAL and INT_NOTEQUAL:  `f(V,W) == f(V,W)  =>  true` |
| — | `RuleGeneric` | `?` | — | — | `rulecompile.cc`:864 | (none listed) |  |

`RulePtrFlow` registers no opcodes unless some address space is truncated
(`hasTruncations`). The source positions of the rule classes in
`ruleaction.cc` run in declaration order, not pipeline order.

### 6.1 Families, by what the rules do

The pipeline order above is fixed by Ghidra; this grouping is for
splitting the port into modules and tracks (names are the console names).

| Family | Rules |
|---|---|
| Dead code and copy propagation | `earlyremoval`, `propagatecopy`, `aliasupdate`, `multicollapse`, `pushmulti`, `pullsub_multi`, `pullsub_indirect`, `selectcse`, `negatenegate` |
| Canonical form of arithmetic | `termorder`, `collect_terms`, `sub2add`, `2comp2mult`, `shift2mult`, `addmultcollapse`, `collapseconstants`, `identityel`, `trivialarith`, `trivialshift`, `xorcollapse`, `xorswap` |
| Bit masks and logical ops | `ormask`, `andmask`, `orconsume`, `orcollapse`, `andorlump`, `negateidentity`, `shiftbitops`, `rightshiftand`, `highorderand`, `anddistribute`, `andcommute`, `andpiece`, `andzext`, `andcompare`, `bitundistribute`, `shiftand`, `humptyor`, `orcompare` |
| Shifts | `doubleshift`, `doublearithshift`, `concatshift`, `leftright`, `shiftcompare`, `shiftpiece`, `shiftsub`, `signshift` |
| Comparisons and booleans | `intlessequal`, `sborrow`, `scarry`, `carryelim`, `testsign`, `bxor2notequal`, `less2zero`, `lessequal2zero`, `sless2zero`, `equal2zero`, `equal2constant`, `threewaycomp`, `zexteliminate`, `slesstoless`, `zextsless`, `lessequal`, `lessnotequal`, `lessone`, `rangemeld`, `floatrange`, `trivialbool`, `notdistribute`, `booleanundistribute`, `booleandedup`, `boolzext`, `booleannegate`, `logic2bool`, `boolnegate`, `condnegate`, `popcountboolxor`, `lzcountshiftbool` |
| Pieces: `SUBPIECE`, `PIECE`, extensions | `piece2zext`, `piece2sext`, `doublesub`, `subextcomm`, `subcommute`, `concatcommute`, `concatzext`, `zextcommute`, `zextshiftzext`, `concatzero`, `concatleftshift`, `subzext`, `subcancel`, `humptydumpty`, `dumptyhump`, `subnormal`, `piecepathology` |
| Division and modulus recovery | `positivediv`, `divtermadd`, `divtermadd2`, `divopt`, `signform`, `signform2`, `signdiv2`, `divchain`, `signnearmult`, `modopt`, `signmod2nopt`, `signmod2nopt2`, `signmod2opt` |
| Floating point | `floatsign`, `floatcast`, `ignorenan`, `unsigned2float`, `int2floatcollapse`, `subfloat_convert` |
| Sub-variable flow (`subflow.cc`) | `subvar_and`, `subvar_subpiece`, `subvar_compzero`, `subvar_shift`, `subvar_zext`, `subvar_sext`, `splitflow` |
| Double precision (`double.cc`) | `doubleload`, `doublestore`, `doublein`, `doubleout` |
| Pointers and data types | `ptrflow`, `ptraddundo`, `ptrsubundo`, `pushptr`, `structoffset0`, `ptrarith`, `loadvarnode`, `storevarnode`, `funcptrencoding`, `segment`, `transformcpool` |
| Control flow | `switchsingle`, `conditionalmove`, `orpredicate` |
| Cleanup (output form) | `multnegone`, `addunsigned`, `2comp2sub`, `dumptyhumplate`, `subright`, `floatsigncleanup`, `expandload`, `ptrsubcharconstant`, `extensionpush`, `piecestructure`, `andstructure` |
| Splitting by data type (`subflow.cc`) | `splitcopy`, `splitload`, `splitstore` |
| Strings (`constseq.cc`) | `stringcopy`, `stringstore` |
| Bitfields (`bitfield.cc`) | `bitfield_store`, `bitfield_out`, `bitfield_load`, `bitfield_in`, `pull_absorb`, `insert_absorb` |

Rule-bearing files other than `ruleaction.cc`: `subflow.cc` (12),
`bitfield.cc` (6), `double.cc` (4), `constseq.cc` (2), `condexe.cc` (1).
The machinery behind them is much larger than the rules themselves
(`SubvariableFlow` 1,521 lines for six one-screen rules; `SplitVarnode`
and the double-precision forms 3,000 lines for four).

## 7. Tests

### 7.1 The C++ unit tests not yet ported

All four build an `Architecture` through the `xml` capability from
`<binaryimage arch="…"></binaryimage>` (no bytes), which loads the `.sla`,
`.pspec` and `.cspec` of a real language. What each *uses* of it
**(read: the whole of each file)**:

| File | Tests | Architecture | What the tests actually need |
|---|---:|---|---|
| `UT/testcirclerange.cc` | 117 | `x86:LE:64:default:gcc` | **Only `glb->inst[opcode]->getBehavior()`**, i.e. the op behaviours (`evaluateUnary`/`Binary`, `recoverInputUnary`/`Binary`) that `bk-pcode` has. Each test builds `CircleRange`s, applies one operation (intersect 8, union 8, pull-back through 14 opcodes 60, push-forward through 10 opcodes 41), and compares with a brute-force model: the set of elements pushed through the op one at a time, re-described as start/stop/step |
| `UT/testtypes.cc` | 8 | `x86:LE:64:default:gcc` | Three tests (`type_ordering`, `enum_matching`, `enum_matching2`) need the `TypeFactory` with the default core types, the C declaration parser (`parse_type`) and `Datatype::compare`/`compareDependency`/`TypeEnum::getMatches`. Five (`cast_basic`, `cast_pointer`, `cast_enum`, `cast_compare`, `cast_integertoken`) also need a `Funcdata` (`newOp`, `newUnique`, `newUniqueOut`, `newConstant`, `opSetOpcode`, `opSetInput`, `Varnode::updateType`), `TypeOp::getInputCast` and `CastStrategy::markExplicitLongSize` |
| `UT/testfuncproto.cc` | 21 | `Toy:LE:32:default:default` plus three models in a `<specextensions>` document | `ProtoModel::assignParameterStorage` on prototypes parsed by `parse_protopieces` (12 tests) and `ProtoModel::deriveInputMap` on hand-built `ParamActive` trials (9 tests). From the architecture: register names → storage (`r1`–`r12`, `r12l`, `r10l`), the stack space, the join space, core types. **No IR** |
| `UT/testparamstore.cc` | 5 | `x86:LE:64:default:gcc`, `x86:LE:64:default:golang`, `PowerPC:BE:64:default:default`, `MIPS:BE:32:default:default`, `AARCH64:LE:64:v8A:default` (as named in the tests) | `assignParameterStorage` with the **real** `.cspec` models (`__stdcall`, `abi-internal`, `__cdecl`), struct declarations through `parse_C`, storage strings such as `join XMM0:8 RSI` and `stack8:10` resolved through register names, `findAddJoin`. **No IR** |

Java tests of the same behaviour, missing from M3's list in `PLAN.md`:
`Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/program/model/lang/`
has `AbstractProtoModelTest` and nine subclasses
(`X64PrototypeModelTest`, `X64WinPrototypeModelTest`,
`X64GoPrototypeModelTest`, `AArch64ProtoModelTest`,
`MipsPrototypeModelTest`, `PowerPCPrototypeModelTest`,
`Sparc32ProtoModelTest`, `Sparc64ProtoModelTest`, `VarargsStorageTest`;
13 tests, ids in `inventory/tests/test-integrationtest.md`). They assert
signature → storage tables in the same string form as `testparamstore.cc`
(`"void func(int,longfloatpair)"` → `"void,EDI,join XMM0:8 RSI"`), against
the Java `PrototypeModel`, which reads the same `.cspec` rules. They are
by far the largest table of expected parameter storage in Ghidra.

### 7.2 Data tests (`DT/*.xml`, 93 files)

A file is `<decompilertest>` holding one `<binaryimage arch="…">` (byte
chunks by space and offset, optional `<symbol>`s), one `<script>` of
console commands (`<com>`), and `<stringmatch name min max>` elements.

How it runs (`testfunction.cc`) **(read)**:
`FunctionTestCollection::restoreXml` registers the image and builds an
`XmlArchitecture` (`init`, then `readLoaderSymbols`); `runTests` feeds the
script to a `ConsoleCommands` interface with the *bulk output* stream
(`fileoptr`, where `print C`, `print raw` and similar commands write)
redirected to a buffer. If any command fails, the whole file fails
("Execution failed"). The buffer is then split at `\n` and **each line** is
offered to each property (`FunctionTestProperty::processLine`):

* A property's text is split at newlines into one regular expression per
  line (leading blanks removed); most have one line.
* `std::regex_search` (ECMAScript grammar, unanchored) is applied to the
  output line against the current pattern line; when the last pattern line
  matches, the count goes up and matching restarts at the first pattern
  line. A failed match in the middle of a multi-line pattern restarts at
  the first line and retries that same output line against it.
* The property passes when `min <= count <= max`. So `min="0" max="0"`
  asserts absence, and counts are per matching *line*, not per occurrence.

Facts about the corpus **(ran)**: 760 properties in 93 files (the
reference run passes 758 on AArch64; the two failures are the `-NAN`
cases of ADR-021). Architectures: `x86:LE:64:default:gcc` 71,
`x86:LE:64:default:windows` 3, `MIPS:LE:32` 3, `MIPS:BE:32` 3,
`AARCH64:LE:64:v8A` 3, `PowerPC:BE:32` 2, `ARM:LE:32:v8` 2, and one each
of `x86:LE:32:default:windows`, `x86:LE:32:default:win` (as written),
`x86:LE:32:default:gcc`, `Toy:BE:32:builder.align2`, `8051:BE:16`,
`68000:BE:32:MC68020`. Commands used (count of script lines): `parse line`
232, `lo fu`/`load function` 194, `print C` 190, `decompile`/`dec` 193,
`map addr` 84, `option` 33, `map fun` 29, `map convert` 17, `override
flow` 5, `map hash` 5, `comment instr` 5, `set context` 4, `print raw` 4,
`override dest` 4, `rename` 3, `map return` 3, `set track` 2, `pointer
setting` 2, `force datatype` 2, `volatile` 2, and once each `type
varnode`, `retype`, `override proto`, `map unionfacet`, `map param`, `map
label`, `force varnode`, `fixup apply`. No pattern uses a look-around or a
back-reference (checked with `grep`), so Rust's `regex` crate can run them;
differences in escape handling between ECMAScript and `regex` syntax must
still be checked per pattern when the runner is built.

What the patterns check: almost all match lines of `print C` output (an
expression, a declaration, a statement shape, or the absence of one); four
files match `print raw` lines. They do not compare whole functions. A data
test passing therefore says less than a full-output comparison with the
reference console, which is why the plan adds one.

Every data test needs the bytes lifted to p-code, i.e. the SLEIGH runtime
for nine processor families, or p-code supplied another way.

### 7.3 Java-side tests of decompiler results

`inventory/tests/features-decompiler.md`: 15 classes, 115 tests, 12 of
them GUI. They need a program database and the UI (M5, M7). Relevant to
M3's design only through what they read from results: `DecompilerClangTest`
(39) and `DecompilerClang2Test` walk the token tree (`ClangToken`,
`ClangVariableToken`, `ClangFieldToken`, `ClangFuncNameToken`,
`ClangOpToken`, …) and map tokens to addresses, varnodes, `HighVariable`s
and `PcodeOp`s; `DecompilerHighSymbolTest`, `DecompilerEquateTest` and
`DecompilerEditDataFieldTest` rename and retype through `HighSymbol`s and
dynamic hashes; `DecompilerPspecVolatilityTest` and
`DecompilerSpecExtensionTest` exercise `<volatile>` and
`<specextensions>`; `DecompilerSwitchAnalyzerTest` reads recovered jump
tables. The Java result model lives in
`ghidra.program.model.pcode` (`HighFunction`, `HighVariable`, `HighSymbol`,
`PcodeOpAST`, `VarnodeAST`, `PcodeBlockBasic`, `JumpTable`,
`DynamicHash`, `FunctionPrototype`) and is filled from `Funcdata::encode`
output (`<function>` with `<localdb>`, `<ast>`: varnodes, blocks, ops and
block edges, `<highlist>`, `<jumptablelist>`, `<prototype>`), section 9.

## 8. What the console can show at intermediate stages

`decomp` reads commands from a script (`-i file`); **standard input must
be a pipe or terminal** (run it as `echo | decomp -i script`), otherwise it
exits with "Unknown error with input file stream" **(ran)**. All of the
following was run against `REF/bin/decomp` (the optimised build) on
`DT/elseif.xml` unless marked.

| Command | Output | Use for parity |
|---|---|---|
| `load test file <file>`; `list test commands`; `execute test command <a>-<b>` | Loads a data test's image and runs a slice of its script | Set a function up exactly as the test does, then stop short of `decompile` |
| `list action` | The current root action as a numbered tree; `!` marks once-per-function entries, `repeat` marks repeating containers | The pipeline, mechanically |
| `break start <name>` / `break action <name>` | Break before an action or rule runs / after it has made a change. Names may be qualified `group:sub:name` | Stop anywhere |
| `decompile`, then `continue` | Runs to the next break point; prints `Break at universal:fullloop:mainloop:heritage start` | Step the pipeline |
| `print raw` | Every op of every basic block in its present state: `0x001006ce:4:	CF(0x001006ce:4) = RSP(free) < #0x10` — address and time of the op, output with its defining `SeqNum` or `(i)`/`(free)`, inputs | **Primary intermediate dump.** Exact text is comparable |
| `print tree varnode` | Every varnode in definition order with type, flags (`mapped`, `tlock`, `implied`, …), `consumed` mask, `create=` index and `internal=` host address | Varnode-level comparison (drop `internal=`). `create=` exposes creation order |
| `print tree block` | The structured block hierarchy by kind and index | Structuring |
| `print actionstats` / `reset actionstats` | `<name> Tested=<n> Applied=<m>` for every action and rule | Cheap first-divergence signal: a rule applied a different number of times |
| `print C`, `print C flat`, `print C xml`, `print C types`, `print C globals` | Output, without structure, with markup, type declarations, globals | Final comparison; `print C xml` checks markup |
| `print high <name>`, `print cover high <name>`, `print cover varnode <vn>`, `print varnode <vn>`, `print inputs`, `print localrange`, `print map <scope>`, `print extrapop`, `print spaces`, `list prototypes`, `list override`, `print parammeasures` | Merging, covers, single varnodes, inputs, local stack ranges, a scope's symbols, stack adjustments, spaces, prototype models, overrides, parameter ranking | Per-subsystem checks |
| `analyze range full\|partial <varnode>` | Value-set analysis result for one varnode | `ValueSetSolver` |
| `structure blocks <infile> <outfile>` | Reads a bare control-flow graph in XML, runs `structureLoops`, `calcForwardDominator`, `CollapseStructure::collapseAll`, `orderBlocks`, writes the structured graph | **Structuring without lifting or data-flow** (read; not run here) |
| `graph dataflow\|controlflow\|dom <file>` | Graph files | Dominators |
| `disassemble`, `dump`, `count pcode` | Listing, bytes, op count | Sanity |
| `produce C <file>`, `produce prototypes` | Whole-program output; prototype recovery in leaf order | Corpus runs |
| `option <name> …` | Any `ArchOption` | Vary configuration |

Only in a build with `CPUI_DEBUG` (Makefile target `decomp_dbg`; **not
built by `scripts/build-reference.sh` today**): `trace address <lo> <hi>`,
`trace enable`/`disable`/`clear`/`list`, `trace break <n>`, `debug action
<name>`, `break jumptable`, `trace propagation`. With tracing on, every
action and rule application that modifies an op in the traced address
range is logged **(ran, scratch build)**:

```
DEBUG 0: constbase
0x001006ca:287: **
   0x001006ca:287: DF(0x001006ca:287) = #0x0:1
DEBUG 1: extrapopsetup
…
```

— a sequence number, the action or rule name, and each modified op before
(`**` for a new op) and after. One function produced 1,347 records. This
is an ordered log of the whole transformation and is the finest-grained
oracle available. The same build also checks invariants the optimised one
does not (`ActionPool::processOp` throws if a rule changes an op and
returns 0).

## 9. What the Ghidra pipe protocol asks of the host

ADR-004 replaces the pipe by a trait. The protocol shows what the trait
must offer and what a result contains.

### 9.1 Commands from the host (`ghidra_process.cc`)

| Command | Meaning |
|---|---|
| `registerProgram` | Create an `ArchitectureGhidra` from four documents: the `.pspec`, the `.cspec`, a `<sleigh>` description of the translator (spaces, big-endian flag, unique base) and `<coretypes>` |
| `deregisterProgram` | Drop it |
| `flushNative` | Clear cached symbols, types, comments and strings (the program changed) |
| `decompileAt` | Run the current root action on the function at an address; answer with a document: parameter measures (if enabled), the function (`Funcdata::encode`, with the syntax tree if enabled) and the C markup (`PrintLanguage::docFunction`, if enabled and the root is `decompile`) |
| `structureGraph` | Structure a bare control-flow graph and return it (used by the function graph view) |
| `setAction` | Choose the root action (`decompile`, `normalize`, `jumptable`, `paramid`, `register`, `firstpass`) and what to return: `tree`/`notree`, `c`/`noc`, `parammeasures`/`noparammeasures`, `jumpload`/`nojumpload` |
| `setOptions` | An `<optionslist>` document for `OptionDatabase` |
| `generateSignatures`, `debugSignatures`, `getSignatureSettings`, `setSignatureSettings` | BSim (`signature_ghidra.cc`) |

### 9.2 Queries to the host (`ghidra_arch.cc`)

| Query | Answer | Component that asks |
|---|---|---|
| `getBytes(addr, size)` | Bytes | `LoadImageGhidra` |
| `getPcode(addr)` | The p-code of one instruction (packed), or unimplemented / bad data | `GhidraTranslate` — the host lifts, not the engine |
| `getRegister(name)`, `getRegisterName(varnode)`, `getUserOpName(index)` | Register storage, name, user-op name | `GhidraTranslate` |
| `getTrackedRegisters(addr)` | Tracked register values at a function's entry | `ContextGhidra` |
| `getMappedSymbolsXML(addr)` | The symbol (variable, function, label, external reference) containing an address, or a "hole" range with its properties | `ScopeGhidra` |
| `getExternalRef(addr)` | The function an external reference resolves to | `ScopeGhidra` |
| `getNamespacePath(id)` | Parent namespaces of a scope id | `ScopeGhidra` |
| `isNameUsed(name, startId, stopId)` | Whether a name is taken between scopes | variable naming |
| `getCodeLabel(addr)` | Label at an address | printer |
| `getDataType(name, id)` | A type definition | `TypeFactoryGhidra::findById` |
| `getComments(funcaddr, kinds)` | Comments of a function | `CommentDatabaseGhidra` |
| `getStringData(addr, type, maxBytes)` | String bytes and whether truncated | `GhidraStringManager` |
| `getPcodeInject(name, kind, context)` | Injected p-code for a call fixup, callother fixup, call mechanism or executable snippet, compiled by the host | `PcodeInjectLibraryGhidra` |
| `getCPoolRef(refs)` | A constant-pool record | `ConstantPoolGhidra` |
| `isDynamicSymbolName(name)` (and the `nameFunction` default) | Naming conventions | printer |

Three things follow. The host supplies *lifted p-code and compiled
injections*; the engine never decodes bytes itself in that configuration,
so the engine's dependency on the SLEIGH runtime is one narrow interface.
Symbols and types are pulled lazily and cached per decompilation, then
flushed. And the result is three artefacts — the encoded function
(varnodes, ops, blocks, high variables, jump tables, prototype, local
symbols), the token markup, and optionally parameter measures — which is
what the Java model in section 7.3 consumes.

## 10. Where Ghidra's result depends on the host

Found while reading; each is a place where a faithful port must choose
(ADR-021: x86-64 Linux) and where Windows differs most easily.

| Where | Dependence | basilisk |
|---|---|---|
| `Datatype::hashName` (`type.cc`): `res += (uint8)nm[i]` | `char` signedness: a byte ≥ 0x80 in a type name is sign-extended on x86-64 and not on AArch64 Linux. The hash becomes the type's id | Sign-extend (x86-64) |
| `TypePointer`, `TypeArray`, `TypePointerRel`, `TypePartial*`, `TypeCode::compareDependency` | "Compare absolute pointers": the order of types in the factory's set, and so of `dependentOrder` (`print C types`), follows heap addresses | Order by creation index |
| `map` keyed by raw pointers: `TypeFactory::warnings`, `ActionNameVars::makeRec`'s `map<HighVariable*,…>`, `SubvariableFlow::varmap` (`map<Varnode*,…>`), `SubfloatFlow::maxPrecisionMap`, `StringSequence`'s `map<PcodeOp*,…>`, `EmulateFunction::varnodeMap`, `CloneBlockOps::origToClone` | Iteration order follows heap addresses wherever these maps are iterated (not merely looked up) | Keys are arena indices, so order is creation order — what Ghidra's allocator usually yields. Each such loop is checked against the reference when its module is ported |
| `iop` and `fspec` varnodes | Offset is a host pointer; size is `sizeof(void*)` (8 on 64-bit hosts) | Offset is the op's or call spec's index; size 8 |
| `LOAD`/`STORE` space constant | Offset is an `AddrSpace *` | Space index (`bk-core` already does this) |
| `print tree varnode` | Prints `internal=<address>` | Not reproduced; comparisons strip it |
| Float printing, NaN sign, float → integer | `bk-pcode`, ADR-021 | Done |
| `char` assumed signed in the code base generally | `REF` is built with `-fsigned-char`; on AArch64 Linux the data-test runner hangs without it | Rust has no such ambiguity; note it wherever a `char` is widened |
| `toupper`, `isdigit`, `isprint`, `isspace` in naming and printing (`database.cc`, `printc.cc`, `varmap.cc`, `coreaction.cc`, `type.cc`, `printlanguage.cc`) | C locale | ASCII-only functions |
| `long` | Only `LoadImage::adjustVma(long)` (32 bits on Windows) | `i64` |
| `std::regex` in the data-test runner | Library-specific corner cases of ECMAScript regex | `regex` crate; patterns checked per file |
| Unordered output | None found: the engine uses `std::map`/`set`, not hash maps | Use ordered maps or index order; never iterate a `HashMap` where order reaches output |

## 11. Not verified

* `structure blocks`, `analyze range`, `graph dom`, `produce C`,
  `print C xml` were not run; their descriptions are from reading
  `ifacedecomp.cc`.
* Whether any of the pointer-keyed maps of section 10 changes *output* on
  real inputs is not known; they are listed because their iteration order
  is formally host-dependent.
* The ECMAScript/`regex` compatibility of the 760 patterns was checked
  only for look-arounds and back-references.
* The reference tools were run on macOS AArch64 only (as in wave 1).
* The Java result model (section 7.3) is described from class names and
  `Funcdata::encode`; the Java classes were not read in detail.
* Line numbers in the generated tables are for commit `42db038f3c`.
