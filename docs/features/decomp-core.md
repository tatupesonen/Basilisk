# Decompiler core: function and architecture state, the action framework, compound operations (`decomp-core`)

Track `decomp-core` (D07 of `docs/features/decomp-plan.md`), milestone
M3, wave 3. Format: `docs/LOOP.md`, "Feature documents". Needs merged:
`decomp-ir` (D05), `decomp-symbols` (D06), `decomp-cspec` (D03),
`decomp-types` (D02), `decomp-cfg` (D04), `decomp-oracle` (D00). It
carries ADR-025's items 1 and 2 (units and profiles), 3a (recorder
attached, evaluator), 3e (the access table's type), and ADR-044's frozen
program state for everything a function owns.

The track is specified as **three crates** — `bk-decomp-core` (part A:
state), `bk-decomp-pipeline` (part B: the action framework, units,
profiles, options) and `bk-decomp-ops` (part C: compound operations on a
function) — because the plan's one crate is 16,000 lines of Ghidra and
its three parts have different users (`docs/agents/spec-decomp-wave3.md`,
"The plan compared with Ghidra's source", findings 1 and 2; proposed ADR
A there). B and C use only A's public API and not each other. If the
coordinator keeps one crate, the three become the module trees `state`,
`pipeline` and `ops` of `bk-decomp-core` with the same one-way
dependencies and the same steps.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`DT/` = `…/decompile/datatests/`, under `../ghidra` (commit `42db038f3c`);
`REF/` = the reference directory. **(read)** marks a statement taken from
the source (file:line), **(ran)** one checked against the reference build;
the runs are X1 to X7 in `docs/research/decomp-wave3/runs.md`, with the
oracle prototypes beside it. **To be specified** marks a part that was
not read to this standard: it names the files and lines that define it,
and the implementer reads them before writing (`docs/agents/RULES.md`:
the source wins).

## 1. Purpose

Everything between the IR and the passes. Part A holds what Ghidra's
`Funcdata` and `Architecture` hold beyond the IR: the configuration of a
program's decompilation, the state of one function's decompilation (flags,
prototype, call sites, jump tables, heritage, high variables, the local
scope's extra state), the answers D05's mutation methods need
(`FunctionEnv`), and the loading of Ghidra's state dumps into all of it,
so that every later pass can start from Ghidra's own state. Part B is the
machinery that runs passes: actions, rule pools, groups, break points,
statistics, the trace, the table of units, profiles and the pipeline they
build, and the options that configure a run. Part C is the library of
operations on a function that passes share.

## 2. Ghidra sources

| Source | Lines | Part | What to take |
|---|---|---|---|
| `CPP/action.hh`, `action.cc` | 330 + 1,150 | B | `Action`, `ActionGroup`, `ActionRestartGroup`, `Rule`, `ActionPool`, `ActionGroupList`, `ActionDatabase`: every member (4.B.1 to 4.B.6). **Authoritative** |
| `CPP/coreaction.cc` 5818–6149 | 330 | B | `ActionDatabase::buildDefaultGroups` and `universalAction`, as data (4.B.7) |
| `CPP/options.hh`, `options.cc` | 361 + 1,092 | B | `ArchOption` and its 39 subclasses, `OptionDatabase` (4.B.8) |
| `CPP/architecture.hh`, `architecture.cc` | 400 + 1,564 | A | The members of `Architecture`, `init` and its order, `restoreFromSpec`, `resetDefaults`, `clearAnalysis`, `setDefaultModel`, `createUnknownModel`, `getSpaceBySpacebase`, the laned-register look-ups, `setPrototype`, `setPrintLanguage`, `cacheAddrSpaceProperties`, `decodeRegisterData` (lane sizes), `SegmentedResolver`, `encode`/`restoreXml` (4.A.1, 4.A.2). The `.cspec` decoding is D03's (done), the filling of the database D06's |
| `CPP/sleigh_arch.cc` | 638 | A | **To be specified**: `SleighArchitecture` (language description look-up, `buildTranslator`, `buildSpecFile`, `encodeHeader`/`restoreXmlHeader`); `bk-lang` already reads `.ldefs`; what remains is the order of calls (4.A.2) |
| `CPP/funcdata.hh`, `funcdata.cc` | 746 + 1,234 | A | The members of `Funcdata`; constructor, `clear`, warnings, `startProcessing`, `stopProcessing`, `startTypeRecovery`, the flag accessors and index marks, spacebase helpers, the call-spec list, `fillinExtrapop`, `printLocalRange`, `encode` without the tree, `decode` (4.A.3 to 4.A.6). Not: `printRaw`, `printVarnodeTree`, the debug trace (D05); `doLiveInject`, `PcodeEmitFd` (D09); `encodeTree`, `encodeHigh` (D17); the union-field methods 917–1117 (D08, 3.3) |
| `CPP/funcdata_block.cc` | 1,114 | A, C | Block surgery and the jump-table list (A, 4.A.8); `nodeJoinCreateBlock`, `nodeSplit*`, `removeFromFlowSplit`, `CloneBlockOps` (C). Not: `stageJumpTable`, `recoverJumpTable`, `earlyJumpTableFail`, `switchOverJumpTables` (D13) |
| `CPP/funcdata_varnode.cc` | 2,334 | A, C | `setVarnodeProperties`, `assignHigh`, `checkForLanedRegister`, `setHighLevel`, `initActiveOutput` as the `FunctionEnv` implementation and state (A, 4.A.7); the rest beyond D05's part is C (4.C.2) |
| `CPP/funcdata_op.cc` 473–628, 646–668, 938–1668 | 950 | C | The compound op edits (4.C.1). 766–936 (`followFlow`, `truncatedFlow`, `inlineFlow`) is D09's |
| `CPP/fspec.hh` 1669–1790, `fspec.cc` 2123–2180, 2968–3300, 4780–5928 | 1,700 | A, C | `FuncCallSpecs` as data, `FspecSpace`, `ParameterSymbol`, `ProtoStoreSymbol` (A, 4.A.5, 4.A.6); `FuncCallSpecs`' methods (C, 4.C.4) |
| `CPP/userop.hh`, `userop.cc` | 363 + 652 | A | `UserPcodeOp` and its kinds, `UserOpManage` (4.A.9). The declarations are `bk-cspec`'s (`inject.rs`, done) |
| `CPP/pcodeinject.hh`, `pcodeinject.cc` | 277 + 361 | A | `InjectContext`, the run-time face of `InjectPayload` and `PcodeInjectLibrary` (4.A.9). `ExecutablePcode::build`/`evaluate` and the snippet emulator are D18's behind a trait |
| `CPP/expression.hh`, `expression.cc` | 238 + 803 | C | All (4.C.3) |
| `CPP/dynamic.hh`, `dynamic.cc`, `crc32.hh`, `crc32.cc` | 107 + 754 + 74 | C | `DynamicHash`, `ToOpEdge` (4.C.5) |
| `CPP/transform.hh` 95–131, `transform.cc` (`LanedRegister`) | 120 | A | `LanedRegister` and its iterator. `TransformManager`, `TransformOp`, `TransformVar`, `LaneDescription` are proposed for R7 (plan finding 8) |
| `CPP/heritage.hh` 28–140, 190–230; `jumptable.hh` 543–631; `variable.hh`, `variable.cc` (the `HighVariable` class); `merge.hh`; `varmap.hh` 190–281, `varmap.cc` 507–535 | — | A | The data members of `Heritage`, `HeritageInfo`, `LocationMap`, `LoadGuard`, `JumpTable`, `HighVariable`, `VariableGroup`, `VariablePiece`, `Merge`, `ScopeLocal`, as state structs (4.A.10); `HighVariable`'s own methods (4.A.11) |
| `CPP/ifacedecomp.cc` 890–920, 1030–1040, 1185–1230, 2500–2530, 3325–3355 | — | B | How the console drives the framework (`decompile`, `continue`, `list action`, `break`, `print actionstats`); the commands themselves are D09's |
| `tools/reference/README.md` | — | A | `bkstate` 2, `bkactions` 1, the trace |

## 3. Scope

### 3.1 In, by crate

**`bk-decomp-core` (part A).** Depends on `bk-core`, `bk-marshal`,
`bk-pcode`, `bk-lang`, `bk-cspec`, `bk-decomp-types`, `bk-decomp-cfg`,
`bk-decomp-ir`, `bk-decomp-symbols`, and from its last step
`bk-decomp-typeop` (3.3).

1. `Arch`: the program-wide configuration and services (4.A.1), its
   assembly in Ghidra's order (4.A.2), `Config` (the option-settable
   scalars) and `PrintOptions` as plain data.
2. Function records and function state: `FunctionRecord` (what survives
   `clear`), `Funcdata` (the state of one decompilation), flags, marks,
   warnings, lifecycle (4.A.3, 4.A.4).
3. Call specifications as data and the list `qlst` (4.A.5); the
   function's prototype with parameters backed by symbols (4.A.6).
4. The implementation of D05's `FunctionEnv` (4.A.7) and of D06's
   `FunctionCodec`.
5. Block surgery over D04's graph and D05's ops, `structureReset`, the
   jump-table list (4.A.8).
6. User ops and the injection library at run time (4.A.9).
7. The state structs of later tracks and their bookkeeping (4.A.10); the
   high-variable table with `HighVariable`'s own methods (4.A.11).
8. Loading and writing every `bkstate` section D05 and D06 pass through
   (4.A.12).
9. The traits later crates fill: `PcodeSource`, `ActionRunner`,
   `JumpTableRecovery`, `ExecScript`, `LocalScopeOps` (4.A.13).
10. The access table's type (ADR-025 3e) and the evaluator (3a) (4.A.14).

**`bk-decomp-pipeline` (part B).** Depends on `bk-decomp-core`,
`bk-decomp-ir`.

1. The `Action` and `Rule` traits, groups, the restart group, pools,
   break points, warnings, statistics, `print`, `printState`, specifiers
   (4.B.1 to 4.B.5).
2. Root actions: group lists, derivation, toggling, reset (4.B.6).
3. The unit table in use, `Profile`, the `ghidra` profile's arrangement
   as data, the pipeline builder (4.B.7).
4. Options (4.B.8).
5. Drivers: run to completion or to a break, the trace recorder's
   brackets, a cancellation check between unit applications (4.B.9).

**`bk-decomp-ops` (part C).** Depends on `bk-decomp-core`, `bk-decomp-ir`,
`bk-decomp-symbols`, `bk-cspec`, `bk-decomp-types`.

The compound operations of 4.C: op edits, varnode and symbol operations,
expressions, call-spec operations, dynamic hashing, cloning.

### 3.2 Not in this track

| What | Where | Why |
|---|---|---|
| Lifting and flow following (`followFlow`, `truncatedFlow`, `inlineFlow`, `doLiveInject`, `PcodeEmitFd`, `FlowInfo`), the console and the data-test runner | D09 | Plan row; D07 gives it `PcodeSource`, the flow-option bits (4.A.1) and `startProcessing`'s other steps |
| The heritage algorithm, guards' analysis, `PreferSplitManager` | D10 | Core holds `HeritageState` and its bookkeeping only (4.A.10) |
| `ScopeLocal`'s algorithms (`MapState`, `AliasChecker`, restructuring, recommendations) | D11 | Core holds `LocalScopeState` and `resetLocalWindow` (4.A.10) |
| Jump-table recovery (`stageJumpTable`, `recoverJumpTable`, `earlyJumpTableFail`, `switchOverJumpTables`, `JumpTable`'s models and methods), `EmulateFunction` | D13 | Core holds the table's data and the list operations; recovery is reached through `JumpTableRecovery` |
| `Merge`, `HighIntersectTest`, the piece groups' cover logic, the merge, marking and naming actions | D14 | Core holds the high table and `HighVariable`'s own methods (4.A.11, plan finding 7) |
| `TypeOp`, casts, union resolution, the union map and its nine methods (`funcdata.cc` 917–1117) | D08 | 3.3 |
| `universalAction` bound to real units, `paramid.*`, `encodeTree`, `encodeHigh`, the parallel driver | D17 | D07b owns the arrangement as names (plan finding 10) |
| `ExecutablePcode::build`/`evaluate`, `EmulateSnippet`, compiling payloads | D18 | Needs `bk-sleigh-snippet`; core defines `ExecScript` |
| `TransformManager` and the lane transforms | R7 (proposed) | Only `subflow.cc` uses them |
| `Statistics` (`CPUI_STATISTICS`), `ArchitectureCapability`, `capability.*`, `graph.*` | not ported | Compiled out in the reference build; static registration; console graph dumps. Listed under Differences |
| The printer and its language registry | D16b, D16c | Core holds `PrintOptions` and the language's name (ADR-048: the printer needs the tree and the options) |

### 3.3 The boundary with D08, and what D07 does only after D08 is merged

D08 (`bk-decomp-typeop`) is below core. It defines `UnionMap`,
`ResolveEdge`, `ResolvedUnion` and the nine methods Ghidra has on
`Funcdata` (`getUnionField` … `inheritUnionFieldPtr`, `funcdata.cc`
917–1117), the per-opcode `TypeOps` table with its Java variant, and a
trait `TypeOpEnv` for what its functions read from a function: the call
spec's prototype at a call op, the function's own prototype, a user op's
types and name, a high variable's type, the default data space, a
constant-pool record. Core's **last step** (11, step A9) depends on
`bk-decomp-typeop` and adds: the `TypeOps` table to `Arch` and its switch
on a print-language change (`architecture.cc:410–433`); the `UnionMap`
field of `Funcdata` (cleared by `clear`, `funcdata.cc:100`) and the `U`
records of `@function`; `impl TypeOpEnv for Funcdata`;
`applyUnionFacet` (`funcdata_varnode.cc:1707–1746`, part C). Until then
those items are absent and the `U` records pass through. If D08 is not
merged when the track reaches that step, the step is delivered as a
follow-up.

### 3.4 Ownership of the functions on a boundary

Every member of `Funcdata`, by where it goes. Lines are of the `.cc` file
named in section 2. "core" = part A, "ops" = part C.

| Members | Owner |
|---|---|
| `Funcdata` (constructor), `clear`, `warning`, `warningHeader`, `startProcessing` (its steps other than `followFlow`), `stopProcessing`, `startTypeRecovery`, every inline flag and index accessor of `funcdata.hh` 140–236, `spacebase`, `newSpacebasePtr`, `findSpacebaseInput`, `constructSpacebaseInput`, `constructConstSpacebase`, `clearCallSpecs`, `issueDatatypeWarning`, `getCallSpecs` (both), `compareCallspecs`, `sortCallSpecs`, `deleteCallSpecs`, `fillinExtrapop`, `printLocalRange`, `encode` (no tree), `decode`, `encodeJumpTable`, `decodeJumpTable` (the list; a table's own codec is D13's) | core |
| `setVarnodeProperties`, `assignHigh`, `checkForLanedRegister`, the laned-access map, `setHighLevel`, `initActiveOutput`, `clearActiveOutput` | core (`FunctionEnv`, 4.A.7) |
| `printBlockTree`, `clearBlocks`, `clearJumpTables`, `removeJumpTable`, `createReplaceVarnode`, `pushMultiequals`, `opZeroMulti`, `branchRemoveInternal`, `removeBranch`, `descendantsOutside`, `blockRemoveInternal`, `removeDoNothingBlock`, `removeUnreachableBlocks`, `pushBranch`, `linkJumpTable`, `findJumpTable`, `installJumpTable`, `installSwitchDefaults`, `structureReset`, `switchEdge`, `spliceBlockBasic` | core (4.A.8) |
| `forceGoto`, `nodeJoinCreateBlock`, `nodeSplitBlockEdge`, `nodeSplit`, `removeFromFlowSplit`, `CloneBlockOps` | ops |
| `createStackRef`, `opStackStore`, `opStackLoad`, `opBoolNegate`, `opUndoPtradd`, `getFirstReturnOp`, `findPrimaryBranch`, `listOps`, `replaceLessequal`, `distributeIntMultAdd`, `collapseIntMultMult`, `buildCopyTemp`, `opFlipInPlaceTest`, `opFlipInPlaceExecute`, `opNormalizeFlip`, `opCollapseIndirectsForCopy`, `opCollapseIndirectsForAlias`, `cseFindInBlock`, `cseElimination`, `cseEliminateList`, `moveRespectingCover` | ops (4.C.1) |
| `findHigh`, `combineInputVarnodes`, `newExtendedConstant`, `adjustInputVarnodes`, `destroyVarnodeRecursive`, `descend2Undef`, `transferVarnodeProperties`, `fillinReadOnly`, `replaceVolatile`, `checkIndirectUse`, `markIndirectOnly`, `calcNZMask`, `syncVarnodesWithSymbols`, `markIndirectAliasUpdate`, `syncVarnodesWithSymbol`, `remapVarnode`, `remapDynamicVarnode`, `remapConflictSymbol`, `detectSymbolConflicts`, `linkProtoPartial`, `linkSymbol`, `linkSymbolReference`, `findLinkedVarnode`, `findLinkedVarnodes`, `buildDynamicSymbol`, `attemptDynamicMapping`, `attemptDynamicMappingLate`, `getInternalString`, `testForReturnAddress`, `splitUses`, `findDisjointCover`, `coverVarnodes`, `applyUnionFacet`, `mapGlobals`, `prepareThisPointer`, `checkCallDoubleUse`, `onlyOpUse`, `ancestorOpUse`, `AncestorRealistic`, `spacebaseConstant` (`funcdata.cc:358`) | ops (4.C.2) |
| `followFlow`, `truncatedFlow`, `inlineFlow`, `doLiveInject`, `PcodeEmitFd` | D09 |
| `stageJumpTable`, `earlyJumpTableFail`, `recoverJumpTable`, `switchOverJumpTables` | D13 |
| `getUnionField`, `getAddressBasedUnionField`, `getUnionResolution`, `setUnionField`, `setAddressBasedUnionField`, `updateUnionField`, `forceFacingType`, `inheritUnionField`, `inheritUnionFieldPtr` | D08 (`UnionMap`) |
| `encodeTree`, `encodeHigh`, `encodeVarnode` | D17 |
| `opHeritage` (a call of `Heritage::heritage`), the unit `heritage` | D10 |
| `getMerge`, the units of the merge sequence | D14 |
| Everything `decomp-ir.md` section 2 lists | D05 |

`ActionSwitchNorm` (D13), `ActionLaneDivide` (R7) and `ActionHeritage`
(D10) are proposed to follow the code they call (plan findings 4 and 5).

## 4. Behaviour

### Part A — state (`bk-decomp-core`)

#### 4.A.1 The architecture's state (read, `architecture.hh`, `architecture.cc` 150–181, 1417–1447)

Ghidra's `Architecture` is one mutable object. Here it is four values:

* **`ArchSpec`** — fixed once assembled, `Send + Sync`, shared by `Arc`:
  the space manager (with the `fspec`, `iop` and `join` spaces inserted
  in that order after the translator's spaces, `architecture.cc:634–637`),
  the compiler spec's models and effects (`bk-cspec`), the type factory
  as loaded, user ops, the injection library, `lanerecords`,
  `splitrecords`, `inferPtrSpaces`, `min_funcsymbol_size` (1; the
  translator's alignment when that is at most 8, 639–640),
  `aggressive_ext_trim` (false), `funcptr_align` (0), the default return
  address, the architecture id, the register and user-op names, the float
  formats.
* **`Config`** — what options change; a plain `Clone` struct copied into
  each decompilation. Defaults (`resetDefaultsInternal`, 1417–1436):
  `trim_recurse_max` 5, `max_implied_ref` 2, `max_term_duplication` 2,
  `max_basetype_size` 10, `flowoptions` = `error_toomanyinstructions`,
  `max_instructions` 100,000, `max_baddata` 4, `infer_pointers` true,
  `analyze_for_loops` true, `readonlypropagate` false, `nan_ignore_all`
  false, `nan_ignore_compare` true, `alias_block_level` 2,
  `split_datatype_config` 7 (struct 1, array 2, pointer 4),
  `max_jumptable_size` 1,024. The flow-option bits are defined here with
  Ghidra's values (`flow.hh:60–74`: `ignore_outofbounds` 1,
  `ignore_unimplemented` 2, `error_outofbounds` 4, `error_unimplemented`
  8, `error_reinterpreted` 0x10, `error_toomanyinstructions` 0x20,
  `unimplemented_present` 0x80, `baddata_present` 0x100,
  `outofbounds_present` 0x200, `reinterpreted_present` 0x400,
  `toomanyinstructions_present` 0x800, `possible_unreachable` 0x1000,
  `flow_forinline` 0x2000, `record_jumploads` 0x4000), because options
  set them and D09 reads them. `nan_ignore_compare` is read by no rule
  (`grep`: only `options.cc` and the default); 4.B.8 says what `nanignore`
  really does.
* **`ModelState`** — the mutable part of the prototype models: the
  default model, `evalfp_current`, `evalfp_called`, each model's
  `extrapop` and print-in-declaration flag, and models created for
  unknown names. Options and `createUnknownModel` write it. Ghidra's
  `resetDefaults` does **not** restore it (ran, X5).
* **`PrintOptions`** — per print language: Ghidra's `PrintLanguage` and
  `PrintC` option members with their defaults (read, `printlanguage.cc`
  579–587, `printc.cc` 1644–1658, `prettyprint.hh` 103, 1092): modifier
  word 0, header comment types `header | warningheader`, instruction
  comment types `user2 | warning`, comment indent 20, namespace strategy
  minimal, C comment delimiters, indent increment 2, maximum line 100,
  `convention` true, `hide_exts` true, `inplace_ops` false, `nocasts`
  false, `NULL` false, `unplaced` false, brace styles: function
  `skip_line`, the other three `same_line`; and the name of the current
  language (`c-language`). The Java language's own defaults are **to be
  specified** from `printjava.cc` 35–60 (the option oracle shows them: X5).

Methods on these (read): `getModel`/`hasModel` (look-up by name);
`createUnknownModel(name)` — an unknown model cloned from the default,
registered under the name, not printed in declarations when the name is
`unknown` (1160–1168); `setDefaultModel(m)` — the old default becomes
printed in declarations, the new one not (323–330);
`getSpaceBySpacebase(addr, size)` — the first space, in index order, one
of whose spacebase registers equals the storage exactly, else `Unable to
find entry for spacebase register` (264–282); `getLanedRegister(addr,
size)` — binary search of `lanerecords` by whole size, the address is
not used (290–306); `getMinimumLanedRegisterSize` — the first record's
size or −1 (312–318); `nameFunction(addr)` — `func_` + the address's raw
print (550–557); `getSegmentOp(space)` (378–387); `setPrototype(pieces)`
— resolve the namespace (`Unknown namespace: <name>`), find the function
(`Unknown function name: <name>`), set its pieces (391–403).

`lanerecords` come from the `.pspec`'s `<register_data>`: for every
`<register>` with `vector_lane_sizes`, a mask of lane sizes is OR-ed
into the entry of the register's size; one record per size with a
non-zero mask, in size order (930–978). `LanedRegister::parseSizes` and
its bit mask are **to be specified** from `transform.cc` (the
`LanedRegister` methods) — read them first.

`cacheAddrSpaceProperties` (668–704): the candidate spaces are
`inferPtrSpaces` (from `<global>` ranges, D06) plus the default code and
data spaces, sorted by index (ties are the same space: stable or not is
the same), de-duplicated; dropped: a space where high pointers are
impossible, a spacebase space, the OTHER space, an overlay. If the
default data space is not first it is swapped with the first. A space
with a segment op is marked for near pointers of the op's inner size.

`SegmentedResolver::resolve(val, sz, point)` (1449–1470): when `0 <= sz
<= inner size` and the op has a resolve register and `point` is valid,
the full encoding is the segment script on (tracked value of the
register at `point`, `val`); otherwise, for larger sizes, `val` itself;
else an invalid address. It needs the script (D18, `ExecScript`).

#### 4.A.2 Assembly (read, `architecture.cc` 1392–1415, 626–647, 1173–1352)

`Architecture::init` in order: load image; resolve the language; read the
spec files; context; type factory; comment database; string manager;
constant pool; database (D06, `decomp-symbols.md` 4.18); then
`restoreFromSpec`: translator, its spaces copied, `fspec`, `iop`, `join`
inserted, user ops initialised from the translator's names
(`UserOpManage::initialize`), `min_funcsymbol_size`, the injection
library, the `.pspec` (`parseProcessorConfig`), default float formats if
none was registered, the `.cspec` (`parseCompilerConfig`, D03), the
actions (`buildAction`: extra rules, the universal action, the default
roots); then core types; the printer's initialisation from the
architecture; `adjustCaches`; default symbols (D06);
`cacheAddrSpaceProperties`; the type-operator table
(`TypeOp::registerInstructions`, D08, step A9); read-only ranges of the
image (D06).

`assemble(parts) -> Result<Arch, ArchError>` performs these in this
order from already decoded parts: a `bk_lang` language description and
`.pspec`, a `bk_cspec::CompilerSpec` (decoded against the manager as it
stands, `decomp-cspec.md` 4.1), a `PcodeSource` for names and formats, a
`LoadImage`. It calls D06's `arch::*` functions at the points 4.18 of
`decomp-symbols.md` names. Elements of `<processor_spec>` and their
handlers are listed at 1182–1234; an unknown element is `Unknown element
in <processor_spec>`. What `bk-lang` already decodes of them, and what
this crate must take from the raw element, is **to be specified** by
comparing `crates/bk-lang`'s pspec model with that list (the D03 report's
follow-up for D07: payload order through `ReadOptions::injects`, user
ops of fix-ups resolved against the language).

`encode` (`<save_state>`, 485–498): `loadersymbols`, then types,
database, context, comments, strings, the constant pool when not empty.
`restoreXml` (503–544): children `typegrp`, `db`, `context_points`,
`commentdb`, `stringmanage`, `constantpool`, `optionslist` (4.B.8 — so
the options registry is passed in), `flowoverridelist` (D06 decodes the
records, 4.17; each is delivered to the function at its address when one
exists, silently dropped otherwise, 462–464), `injectdebug`; any other
child is `XML error restoring architecture`.

`clearAnalysis(fd)`: `fd.clear()`, then remove the function's `warning`
and `warningheader` comments (335–341).

#### 4.A.3 A function: what persists and what one decompilation owns (read, `funcdata.hh` 56–101, `funcdata.cc` 34–112)

Ghidra has one `Funcdata` object per function for the life of the
program. Called functions are such objects too: a call site copies the
callee's prototype from it (`FuncCallSpecs::setFuncdata`,
`fspec.cc:4889`), options change it (`inline`, `noreturn`, `extrapop
<n> <function>`), and what a decompilation recovers for a function stays
in it for later callers. Basilisk splits it:

* **`FunctionRecord`** — program state (frozen during a decompilation,
  ADR-044; changes go to the function's overlay and are committed in
  operation order): name, display name, entry address, size, the
  function symbol, the prototype `funcp`, the function scope's id, the
  overrides (`decomp-symbols.md` 4.17), jump tables that are overrides,
  and the flag `no_code`. Kept in a table keyed by the function symbol.
* **`Funcdata`** — one decompilation: a copy of the record to work on,
  the IR (`bk_decomp_ir::Ssa`), `Cfg`s for basic blocks and the
  structured hierarchy, the flags, the three index marks,
  `minLanedSize`, `qlst`, the jump tables, `HeritageState`, the high
  table, `MergeState`, `activeoutput`, the laned-access map, the union
  map (step A9), `LocalScopeState`, the per-function overlays (types
  fork, symbol overlay, built-in user ops), and the join records it
  creates.

A function without a symbol gets the scope id `0x57AB12CD << 32 | (entry
offset & 0xffffffff)` (58–65); the function scope is created through
D06's `create_function_scope` (`decomp-symbols.md` 3.3); the prototype's
parameters are bound to that scope with the use point `entry − 1`
(`funcp.setScope(localmap, baseaddr + -1)`, 69; 4.A.6), and the local
window is reset (4.A.10). Ghidra creates the object on the first
`queryFunction`; Basilisk creates the record when the symbol is created
and the scope when the record is first used (`decomp-symbols.md` open
item 10.5: the scope oracle instantiates at creation).

Flags (`funcdata.hh:57–74`), values kept because dumps print them:
`highlevel_on` 1, `blocks_generated` 2, `blocks_unreachable` 4,
`processing_started` 8, `processing_complete` 0x10, `typerecovery_on`
0x20, `typerecovery_start` 0x40, `no_code` 0x80, `jumptablerecovery_on`
0x100, `jumptablerecovery_dont` 0x200, `restart_pending` 0x400,
`unimplemented_present` 0x800, `baddata_present` 0x1000,
`double_precis_on` 0x2000, `typerecovery_exceeded` 0x4000,
`normalization_on` 0x8000. `setJumptableRecovery(val)` is inverted on
purpose: `true` *clears* `jumptablerecovery_dont` (161).

**`clear()`** (84–112), in this order: clear exactly `highlevel_on |
blocks_generated | processing_started | typerecovery_start |
typerecovery_on | double_precis_on | restart_pending | normalization_on`;
the three index marks to 0; `minLanedSize` from the architecture; the
local scope's unlocked symbols cleared and its window reset; the active
output dropped; the prototype's unlocked output cleared (inputs go with
the scope's symbols); the union map; blocks; ops; varnodes (creation
index and unique offset restart); call specs; jump tables except
overrides, whose recovered data is cleared (`funcdata_block.cc:42–59`);
heritage; merge state. **Not cleared** (reproduced: the `F` record of a
dump shows them): `processing_complete`, `blocks_unreachable`,
`typerecovery_exceeded`, `unimplemented_present`, `baddata_present`,
`no_code`, the two jump-table recovery flags, the overrides and the
laned-access map.

**Warnings** (119–145): the text is `WARNING: ` + message, or `WARNING
(jumptable): ` + message when `jumptablerecovery_on`; `warning(txt,
addr)` adds a `warning` comment at `addr`, `warningHeader(txt)` a
`warningheader` comment at the entry, both through
`addCommentNoDuplicate` (D06 4.12) into the function's overlay.

**`startProcessing()`** (150–168): `Function processing already started`
when the flag is set; set it; a header warning `This is an inlined
function` when the prototype is inline; clear the scope's unlocked
symbols and the unlocked output; follow flow over the whole code space
(D09, through a callback argument: core does not depend on flow);
`structureReset`; sort the call specs (after the structure reset, the
order uses block indices); build the heritage info list (one
`HeritageInfo` per space, when empty, `heritage.cc:2642–2650`); apply the
dead-code delays of the overrides. **`stopProcessing()`**: set
`processing_complete`, retire the dead ops. **`startTypeRecovery()`**:
false if already started, else set `typerecovery_start`, true.
`startCastPhase`, `startCleanUp` record the bank's next creation index;
`high_level_index` is set by `setHighLevel` (4.A.7).

`fillinExtrapop()` (542–570): with no code, or a known extrapop, return
it; with no `RETURN` op return 0; else read four bytes at the first
`RETURN` op of the return list: `4`, or for a first byte `0xc2` the
16-bit little-endian immediate plus 4; store it on the prototype. It
assumes x86 (Ghidra's comment); a failed read is the image's error.

`printLocalRange`: the local scope's bounds, then each child scope's
(594–605).

#### 4.A.4 `<function>` (read, `funcdata.cc` 735–837)

`encode(id, save_tree=false, save_overrides)`: `<function>` with `id`
when non-zero, `name`, `size`, `nocode="true"` when set; the entry
address; unless `no_code`, the local scope and its children
(`encodeRecursive`); the jump-table list when not empty; the prototype;
the overrides when asked. `decode`: attributes `name` (required: `Missing
function name`), `size` (required: `Missing function size`), `id`,
`nocode`, `label` (the display name; defaults to the name); the address;
then children: `<localdb>` (`Pre-existing local scope when restoring:
<name>` if one exists; decoded as the function scope with the given id),
`<override>`, `<prototype>` (a default local scope under the global
scope is created first when none was seen), `<jumptablelist>`; with
neither `<localdb>` nor `<prototype>` a default scope is created (a
function shell); finally the local window is reset. **Ghidra's loop has
no branch for another child**: it peeks the same element for ever
(800–825) — and `encode` with the tree writes `<ast>` and `<highlist>`,
which `decode` cannot read. Basilisk returns an error naming the element
(section 8). Not run.

#### 4.A.5 Call specifications (read, `fspec.hh` 1669–1790, `funcdata.cc` 462–534)

`CallSpec` is `bk_cspec::FuncProto` plus: the call op, name, entry
address, the callee's function symbol when known, `effective_extrapop`,
`stackoffset` (`offset_unknown` = `0xBADBEEF`), `stackPlaceholderSlot`
(−1 unused), `paramshift`, `activeinput`, `activeoutput`
(`bk_cspec::ParamActive`), `inputConsume`, and the four booleans
`isinputactive`, `isoutputactive`, `isbadjumptable`,
`isstackoutputlock`. `matchCallCount` is never set in Ghidra
(GHIDRA-BUGS 31) and is not kept. Ids are `CallSpecId` (D05), in
creation order, never reused within a decompilation; `qlst` is the
current order.

* `getCallSpecs(op)`: when input 0 is in the `fspec` space, the spec it
  names; else a linear search of `qlst` for the op (481–494).
* `sortCallSpecs`: by the call op's block index, then its order in the
  block (501–517). The key is total over distinct calls, so the unstable
  sort is harmless (`sorts.md`).
* `deleteCallSpecs(op)`: remove the spec of that op from `qlst`. Ghidra
  frees it while the op's `fspec` varnode keeps the pointer (GHIDRA-BUGS
  30); here the id stays valid and names a spec marked deleted, which
  the dump writes as `call:-`.
* `FspecSpace` (2123–2180): the space's attribute encoding and
  `printRaw` (the callee's name, or its entry address) are **to be
  specified** from those lines; D05's `print raw` needs the text.

`CallSpec`'s constructor and `setFuncdata` (copying the callee's
prototype, 4889–4902), `clone`, and every analysis method are part C
(4.C.4).

#### 4.A.6 The function's prototype over symbols (`fspec.cc` 2968–3300) — to be specified

Ghidra's `FuncProto` reads its parameters through a store. A function
being decompiled uses `ProtoStoreSymbol`: a parameter is a symbol of
category `function_parameter` in the function scope with the use point
`entry − 1`; `ParameterSymbol` answers name, type, address, size and the
lock flags from the symbol (2968–3091); `setInput(i, name, pieces)`
creates or changes the symbol (3143–3209); `clearInput`, `setOutput`
(the output is a `ParameterBasic` inside the store, 3251–3267),
`encode`/`decode` (3288–3300). `bk-cspec`'s `FuncProto` has only the
internal store (`crates/bk-cspec/src/proto/funcproto.rs`: `store:
Option<ProtoStoreInternal>`, read access only). **Design decided here**:
core's `SymbolProto` wraps a `FuncProto` whose internal store mirrors
the parameter symbols; every write goes to the symbols first, and the
mirror is refreshed from the symbols before any query that reads
parameters. This needs one addition to `bk-cspec`: mutable access to the
store (`FuncProto::store_mut`). **Not read to the standard**: the exact
steps of `ProtoStoreSymbol::setInput` (symbol reuse, renaming, retyping,
attribute changes, the `index` category order) and the four `FuncProto`
methods D03 left for D07 (`setScope`, `updateInputTypes`,
`updateOutputTypes`, `updateOutputNoTypes`, `fspec.cc` 3540–3560 and
4160–4290 by name). The implementer specifies them from those lines in
the status report before step A4.

#### 4.A.7 `FunctionEnv` (D05's hooks; read, `funcdata_varnode.cc` 25–66, 312–328, 623–640)

| Hook | Answer |
|---|---|
| `default_type(size)` | the function's type fork: `getBase(size, TYPE_UNKNOWN)` |
| `code_type()` | `getTypeCode()` |
| `symbol_properties(addr, size, use_point)` | `localmap->queryProperties(addr, size, use_point, flags)` on the function scope (D06 4.6, which climbs to parent scopes): an entry with its facts, or the flags |
| `assign_high(ssa, vn)` | when `highlevel_on`: compute the cover if the varnode has one; issue a header warning for a type with a warning (`TypeFactory::findWarning`, once per text: the comment database drops duplicates); unless the varnode is an annotation, create a high variable with the varnode as its only member (4.A.11) |
| `laned_register(size, addr)` | when the architecture has a laned record of that whole size: `lanedMap[(addr, size)] = record` (the map is ordered by storage; `setLanedRegGenerated` sets `minLanedSize` to 1,000,000 so later creations skip the check) |
| `wrapping_address(addr, size)` | `constructWrappingAddress` of the space manager (`bk-core`) |
| `input_effect(addr, size)` | `funcp.hasEffect(addr, size)` |
| `cover_on()` | `highlevel_on` |

`setHighLevel()` (623–640): no-op when on; set `highlevel_on`,
`high_level_index` = the next creation index, then `assign_high` for
every varnode in loc order. `initActiveOutput()` (613–621): a fresh
`ParamActive` (not for a sub-call) whose maximum pass is the prototype's
maximum output delay, replaced by 3 when that is positive. (Ghidra never
attaches the high `assignHigh` returns here: the `HighVariable`
constructor does it, `variable.cc:220–243`, 4.A.11.)

D05's `TableEnv` and this implementation must give the same state on
every mutation test of D05 when fed the same answers (test A-3).

#### 4.A.8 Block surgery (read, `funcdata_block.cc` 27–440, 706–750, 916–960)

All operate on the basic-block `Cfg` (D04) and the ops (D05).

* `structureReset()` (723–750): clear `blocks_unreachable`; run
  `structureLoops` and `calcForwardDominator` on the basic blocks (D04's
  `Analyse::Recompute`); more than one root sets `blocks_unreachable`;
  drop every jump table whose `BRANCHIND` is dead, with the header
  warning `Recovered jumptable eliminated as dead code`; clear the
  structured hierarchy; `forceRestructure` on the heritage state
  (`maxdepth = -1`).
* `opZeroMulti(op)` (195–205): a `MULTIEQUAL` with no input gets a new
  input varnode at the output's storage, made a function input, and
  becomes `COPY`; with one input it becomes `COPY`.
* `branchRemoveInternal(bb, num)` (213–233): when the block has two
  out-edges, destroy its last op; remove one edge to the target; for the
  target's leading `MULTIEQUAL`s remove the input of that in-edge and
  `opZeroMulti`. `removeBranch` = that plus `structureReset`.
* `pushMultiequals(bb)` (105–189): for each `MULTIEQUAL` of `bb` whose
  output is read outside the one out-block's matching `MULTIEQUAL`s:
  header warning `push_multiequal on block with multiple outputs` when
  there are several out-edges; a replacement varnode (`createReplace
  Varnode`: a new unique when the output is address-tied and feeds a
  `MULTIEQUAL` at the same address in the out-block, else the same
  storage; when highs are on the replacement takes the original's place
  in its high and is marked explicit); a new `MULTIEQUAL` at the start
  of the out-block whose inputs are the original for edges from `bb`,
  the replacement otherwise; every other read of the original moves to
  the replacement, **one slot per reading op** (the loop breaks after the
  first matching slot, 178–186).
* `blockRemoveInternal(bb, unreachable)` (272–338): remove the jump
  table of a final `BRANCHIND`; when reachable, `pushMultiequals` and
  rewire the successors' `MULTIEQUAL`s (inputs of a dead `MULTIEQUAL` of
  `bb` are appended, else the dead varnode once per in-edge of `bb`);
  `removeFromFlow`; then destroy every op: for an unreachable block,
  reads of an output outside dead blocks become an undefined constant
  (`descend2Undef`, part C) with one header warning `Creating undefined
  varnodes in (possibly) reachable block`; an output still read from a
  live block is `Deleting op with descendants\\n`; a call's spec is
  deleted; finally the block is removed.
* `removeDoNothingBlock(bb)`: more than one out-edge is `Cannot delete a
  reachable block unless it has 1 out or less`; mark dead, remove,
  reset.
* `removeUnreachableBlocks(issue_warning, check_existence)` (364–411):
  with `check_existence` look for a non-entry block without an immediate
  dominator, else use the flag; collect the blocks unreachable from the
  entry; mark them dead, each with the header warning `Removing
  unreachable block (<space>,<address>)` when asked; remove all their
  out-branches, then the blocks; reset. Returns whether anything was
  removed.
* `pushBranch(bb, slot, bbnew)` (421–438): `Cannot push non-conditional
  edge` unless `bb` ends in `CBRANCH` with two out-edges; `Can only push
  branch into indirect jump` unless `bbnew` ends in `BRANCHIND`; the
  `CBRANCH` loses its condition and becomes `BRANCH`; the edge moves;
  reset.
* The jump-table list (444–494, 706–718, 42–78): `linkJumpTable(op)`
  (the table at the op's address gets the op), `findJumpTable(op)`,
  `installJumpTable(addr)` (`Cannot install jumptable if flow is already
  traced`, `Trying to install over existing jumptable`),
  `removeJumpTable` (also clears `f_switch_out` on the op's block),
  `clearJumpTables`, `installSwitchDefaults` (each table with a default
  block marks that out-edge as the default switch edge).
* `switchEdge`, `spliceBlockBasic` (916–960): **to be specified** from
  those lines.

#### 4.A.9 User ops and the injection library at run time (read, `userop.cc`, `pcodeinject.cc` 137–359)

* Kinds (`userop.hh:56–63`): unspecialized 1, injected 2, volatile read
  3, volatile write 4, segment 5, jump assist 6, string data 7, and the
  data-type op used for the copy built-ins. Built-in ids: string data
  `0x10000000`, volatile read `…01`, volatile write `…02`, `memcpy`
  `…03`, `strncpy` `…04`, `wcsncpy` `…05`.
* `initialize`: one unspecialized op per non-empty name of the
  translator, with the name's index (416–427).
* `registerOp` (514–552): a name already known with another index is
  `Conflicting indices for userop name <n>`; an index already taken by
  another name is `User op <n> has same index as <m>`; the same name at
  the same index replaces the old definition; a segment op is also
  entered by the index of its space (`Multiple segmentops defined for
  same space`).
* A call-other fix-up, a segment op and a jump assist each **replace an
  unspecialized op of that name**: `Unknown userop name in
  <callotherfixup>: <n>` / `<callotherfixup> overloads userop with
  another purpose: <n>` (85–98); `<segmentop> expecting space attribute`,
  `<segmentop> unknown userop <n>`, `Redefining userop <n>`, `Missing
  <pcode> child in <segmentop> tag`, `<pcode> child of <segmentop> tag
  must declare one <output>`, `… must declare one or two <input> tags`
  (248–314; the default name is `segment`); `Too many <case_pcode>
  tags` and the three like it, `userop: <n> is missing <addr_pcode>`,
  `… <default_pcode>`, `Unknown userop name in <jumpassist>: <n>`,
  `<jumpassist> overloads userop with another purpose: <n>` (326–377).
  `bk-cspec` holds the declarations; this crate resolves them against
  the language and reports these errors.
* `decodeVolatile` (570–602): `Missing inputop/outputop attributes in
  <volatile> element`; `read_volatile user-op registered more than once`
  (and the write form) when the built-in already exists.
* `registerBuiltin(id)` (456–508) creates on first use: string data;
  `read_volatile`, `write_volatile`; `builtin_memcpy`,
  `builtin_strncpy`, `builtin_wcsncpy` with output and first two inputs
  a pointer (to `void`, `char`, `wchar_t`: size of pointer, word size of
  the default data space) and a third input `int4`; another id is `Bad
  built-in userop id`. It runs during a decompilation and creates types,
  so it writes the function's overlay (the built-in table and the type
  fork), committed like symbols (ADR-044).
* Names and types: `VolatileOp::appendSize` — `_1`, `_2`, `_4`, `_8`,
  else `_<decimal>` (105–119); a volatile read's operator name takes the
  output's size (the bare name without an output), a write's the size of
  input 2 (bare with fewer than three inputs); their `getOutputLocal` /
  `getInputLocal(slot 2)` answer, when the op has special propagation,
  the sized type of the symbol entry at the address in input 1 found by
  `queryProperties` from the **global** scope with the op's address as
  the use point (128–172); the data-type op returns its stored types by
  slot − 1 (70–83); string data returns the output's own type (385–389).
* `SegmentOp::unify` (212–239): a `CALLOTHER` of this index with exactly
  three inputs; with a base size the bind list is (input 1, input 2),
  else (none, input 1); a constant operand is re-created at the declared
  size. `isConcatenation` (197–210) evaluates the script once on
  `(0xabab… & mask(base), 0x1234567812345678 & mask(inner))` and compares
  with `high << inner*8 | low`; the shift is undefined in C++ for an
  inner size of 8 (section 8).
* The library (`pcodeinject.cc` 220–359): four name → id maps (call
  fix-ups, call-other fix-ups, call mechanisms, scripts) with `Duplicate
  <callfixup>: <n>`, `Duplicate <callotherfixup>: <n>`, `Duplicate
  <callmechanism>: <n>`, `Duplicate <script>: <n>`; `getPayloadId(type,
  name)` (−1 when absent); the reverse names (empty when out of range).
  `bk_cspec::InjectLibrary` has the tables; this crate adds
  `InjectContext` (`pcodeinject.hh:79–95`: base address, next address,
  call address, input and output locations) and the trait a compiled
  payload implements (4.A.13).

#### 4.A.10 State of later tracks (data in core, algorithms above; ADR-026)

Each struct has exactly the members the dump lists
(`tools/reference/README.md`, "State dumps"), named after Ghidra's, with
accessors and the bookkeeping below. The owning track adds algorithms in
its own crate and may ask for members to be added.

| State | Members (dump section) | Bookkeeping in core |
|---|---|---|
| `HeritageState` (`heritage.hh`) | `pass`, `maxdepth`; per space `delay`, `deadcodedelay`, `deadremoved`, `loadGuardSearch`, `warningissued`, `hasCallPlaceholders`; `globaldisjoint` (address, size, pass); load and store guards; `loadCopyOps` (`@heritage`) | `buildInfoList`, `clear`, `forceRestructure`, `getPass`, `heritagePass(addr)`, `numHeritagePasses`, `seenDeadCode`, `setDeadCodeDelay`, `deadRemovalAllowed`, `deadRemovalAllowedSeen`, the guard lists' accessors — **to be specified** from `heritage.cc` (the functions of those names; `buildInfoList` is 2642–2650) |
| `JumpTable` (`jumptable.hh` 543–631) | the fields of the `J` and `D` records (`@jumptables`) | `isOverride`, `clear` (recovered data only), `getOpAddress`, `setIndirectOp`, `getIndirectOp`, `numEntries`, `isPartial`, `getDefaultBlock`, the label and address accessors |
| `LocalScopeState` (`varmap.hh` 190–281) | the `Z`, `N`, `D`, `Y` records of `@scope` | `resetLocalWindow` (`varmap.cc:507–535`, read): `stackGrowsNegative` from the prototype, `minParamOffset = ~0`, `maxParamOffset = 0`; unless `rangeLocked`, the scope's ranges become the union of the prototype's local range and parameter range (`Database::set_range`) |
| `MergeState` (`merge.hh`) | **to be specified** from the class's data members (the dump has no section: it is scratch between merge actions, except the proto-partial roots that `Merge::registerProtoPartialRoot` collects) | `clear` |
| `activeoutput` | the `A`/`T` records of `@proto` | `initActiveOutput`, `clearActiveOutput` |
| `AccessTable` (ADR-025 3e) | rows (base varnode, offset, size, stride, read or write, op); no Ghidra counterpart | `push`, iteration; D08 and D11 fill it |

#### 4.A.11 High variables (`variable.hh` 110–260, `variable.cc` 220–560) — partly to be specified

The table of highs is function state: D05's `HighId` names an entry.
An entry has Ghidra's members: `inst` (members in order),
`numMergeClasses`, `highflags` (`flagsdirty` 1, `namerepdirty` 2,
`typedirty` 4, `coverdirty` 8, `symboldirty` 0x10, `copy_in1` 0x20,
`copy_in2` 0x40, `type_finalized` 0x80, `unmerged` 0x100,
`intersectdirty` 0x200, `extendcoverdirty` 0x400; read, `variable.hh`
120–130), `flags`, `type`, `nameRepresentative`, `internalCover`,
`symbol`, `symboloffset`, `piece`. The dump's `@highs` section defines
what must round-trip.

Read: `flagsDirty` sets `flagsdirty | namerepdirty`; `typeDirty` sets
`typedirty`; `symbolDirty` sets `symboldirty`; `coverDirty` sets
`coverdirty` and marks the piece group's extended covers dirty
(`variable.hh` 165–168, 276–281); `compareName` (the order of preference
for the name representative, `variable.cc` 455–487: name lock, then
unaffected, persistent, input, address-tied, proto-partial, not in the
unique space, written, earlier defining op).

**D05's high events** (the misfit in the track report): before any read
of a high, and after each mutation call it makes, the function state
drains the events D05 recorded and applies them in order: `FlagsDirty`,
`CoverDirty`, `TypeDirty`, `SymbolDirty` as above; `SetSymbol(vn)` =
`HighVariable::setSymbol`; `SetSymbolReference` likewise; `Removed(vn)`
= `HighVariable::remove`, deleting a high left without members.

**To be specified** from `variable.cc` before step A8: the constructor
(220–243), `setSymbol` (245–283), `setSymbolReference` (285–300),
`updateFlags`, `updateCover`, `updateType` (354–450), `getType`,
`getSymbol`, `getNameRepresentative` (the rest of 489–515), `remove`
(517–540), `merge` and the remaining members. `HighIntersectTest`, the
merge of two highs as an operation of `Merge`, and `VariableGroup`'s
cover combination stay D14's; whether `VariablePiece`'s data can be
split from its algorithms is the first thing to read.

#### 4.A.12 State dumps (`bkstate` 2)

Load into the structures above, and write back byte for byte, the
sections D05 and D06 pass through: `@function` (`F`: name, display name,
entry, size, flags, the three marks, `minLanedSize`; `W` comments; `O`
overrides; `X` laned-access entries; `U` union map at step A9),
`@actions` (into a pipeline's status, 4.B.9 — loaded by part B),
`@structure` (into the structured `Cfg`, D04's reader), `@proto`,
`@callspecs`, `@jumptables`, `@heritage`, `@highs`, `@types` (each type
decoded into the function's type fork in table order; a `t<n>` reference
resolves through the table). `@c` passes through. A field Ghidra leaves
unset (`-`) stays absent. After loading, the state must be one from
which Ghidra's next action could run: the round trip (test A-1) checks
the fields, the pass tracks check the meaning.

#### 4.A.13 Traits other crates fill

```rust
/// The eleven Translate methods the engine calls (inventory 3.1), plus the
/// instruction length flow needs.  Implemented by bk-sleigh and by
/// bk-testkit's RecordedPcode.
pub trait PcodeSource: Send + Sync {
    fn one_instruction(&self, sink: &mut dyn PcodeSink, addr: Address) -> Result<i32, LiftError>;
    fn instruction_length(&self, addr: Address) -> Result<i32, LiftError>;
    fn print_assembly(&self, out: &mut dyn AssemblySink, addr: Address) -> Result<i32, LiftError>;
    fn register(&self, name: &str) -> Option<VarnodeData>;
    fn register_name(&self, space: SpaceId, offset: u64, size: i32) -> Option<&str>;
    fn all_registers(&self) -> &[(VarnodeData, Box<str>)];
    fn user_op_names(&self) -> &[Box<str>];
    fn float_format(&self, size: i32) -> Option<&FloatFormat>;
    fn alignment(&self) -> i32;
    fn is_big_endian(&self) -> bool;
    fn unique_start(&self, layer: UniqueLayer) -> u64;
    fn allow_context_set(&self, val: bool);   // interior flag of the decoder's context cache
}
/// Runs a root action on a function (plan section 2): the jump-table
/// recovery of D13 runs the `jumptable` root on a partial clone.
pub trait ActionRunner { fn run_root(&self, root: &str, fd: &mut Funcdata) -> Result<(), DecompError>; }
/// Recovery of the table of one BRANCHIND (D13); D09 calls it during flow.
pub trait JumpTableRecovery {
    fn recover(&self, fd: &mut Funcdata, op: OpId, flow: &dyn FlowFacts, runner: &dyn ActionRunner)
        -> Result<(Option<JumpTableId>, RecoveryMode), DecompError>;
}
/// A compiled executable payload (segment, jump-assist scripts); D18.
pub trait ExecScript: Send + Sync { fn evaluate(&self, inputs: &[u64]) -> Result<u64, DecompError>; }
```

`RecoveryMode` has Ghidra's values (`success`, `fail_normal`,
`fail_thunk`, `fail_return`, `fail_callother`). `FlowFacts` is what
`stageJumpTable` asks of the flow object (`doesJumpRecord`, and a clone
of the flow up to the op: D09 and D13 settle its methods; **to be
specified** with D09's spec). Without a recovery object every `BRANCHIND`
fails with `fail_normal`, which is how D09 is accepted before D13.

Where Ghidra's run is not re-entrant by accident, Basilisk's is by
construction: `stageJumpTable` switches the architecture's *current
root* to `jumptable`, resets and performs that shared instance, and
switches back (`funcdata_block.cc:518–531`). A pipeline here is an
object owned by one decompilation (4.B.9); the `jumptable` pipeline is
built for it on first use, with every rule enabled, as Ghidra's separate
instance has (plan finding 14).

#### 4.A.14 The evaluator (ADR-025 3a) — to be specified

D05 gives each op a meaning (`decomp-ir.md` 4.5, "Evaluation"). The
evaluator that runs a whole function against an environment (memory, the
effect of calls and of the ops `INDIRECT` names, the values of inputs)
and reports observable effects is owed by this track (plan section 8).
It was not designed in this specification pass. What it must fix before
D19 uses it: the environment trait; the order of effects; what is
compared (calls with targets, stores outside the frame, the returned
storage, plan 9.1 item 2); how `Soundness::Assumes` units qualify a
comparison. It is step C6 and blocks nothing else.

### Part B — the pipeline (`bk-decomp-pipeline`)

#### 4.B.1 An action's state machine (read, `action.cc` 27–37, 100–125, 298–362)

Flags: `rule_repeatapply` 4, `rule_onceperfunc` 8, `rule_oneactperfunc`
16, `rule_debug` 32, `rule_warnings_on` 64, `rule_warnings_given` 128.
Status: `start` 1, `breakstarthit` 2, `repeat` 4, `mid` 8, `end` 16,
`actionbreak` 32. Break points: `break_start` 1, `tmpbreak_start` 2,
`break_action` 4, `tmpbreak_action` 8. A new action has status `start`,
no break points, counts 0. `count` and `lcount` are not initialised by
the constructor (GHIDRA-BUGS 31); here they start at 0.

`perform(fd)` returns the number of changes, or −1 for a stop:

```
loop:
  match status:
    start:          count = 0
                    if a start break point is set: clear the temporary one;
                        status = breakstarthit; return -1
                    count_tests += 1
                    lcount = count;  RUN
    breakstarthit,
    repeat:         lcount = count;  RUN
    mid:            RUN                          (lcount is kept)
    end:            return 0
    actionbreak:    (nothing: the action finished last time)
  RUN:  recorder.begin_unit;  res = apply(fd);  recorder.end_unit(name)
        if res < 0:  status = mid; return res
        if lcount < count:
            warn once (4.B.4); count_apply += 1
            if an action break point is set: clear the temporary one;
                status = actionbreak; return -1
  status = repeat
  if not (lcount < count and rule_repeatapply): leave the loop
if rule_onceperfunc or rule_oneactperfunc:
    status = end if (count > 0 or rule_onceperfunc) else start
else:
    status = start
return count
```

Consequences, each pinned by the oracle table (test B-1): `Tested`
counts entries through `start` only, so a repeat pass does not count and
an action resumed after its own start break is **never counted for that
run**; after an action break the loop condition is evaluated with the
counts of the interrupted pass, so a repeating action goes on repeating;
an `end` action answers 0 until reset; `rule_oneactperfunc` ends only
once something changed.

`reset(fd)`: status `start`, `rule_warnings_given` cleared.
`resetStats()`: both counters 0. Seven of Ghidra's leaf actions override
`reset` **without calling the base** (`coreaction.hh` 77, 99, 133, 198,
646, 872, 1003: `starttypes` sets `typerecovery_on`, `normalizesetup`
sets `normalization_on`, five clear a counter of their own), so their
status is not reset. For six that is invisible (their flags are 0 and
the status is `start` after every perform). For `normalizesetup`
(`rule_onceperfunc`) it is not: it applies once per root instance, not
once per function (ran, X7). The `ghidra` profile reproduces this: a
unit's `reset` hook says whether the framework's part runs
(`ResetKind::Full | OwnOnly`), and the seven are `OwnOnly`. `reset` may
change the function (the two flag setters; `RuleDoubleIn::reset` sets
`double_precis_on`, `double.cc:3181`; `RuleSubvarSext::reset` reads
`aggressive_ext_trim`, `subflow.cc:1736`).

#### 4.B.2 Groups (read, `action.cc` 376–527)

A group's own group name is empty. `apply`: unless the status is `mid`,
start at the first member; for each member from the current one:
`res = member.perform(fd)`; `res > 0`: add it to the group's count, and
if the **group's** action break point is set (clearing a temporary one),
advance to the next member and return −1; `res < 0`: return −1 (the
current member stays current); after the last member return 0. `reset`
and `resetStats` do the base's work, then every member's.
`clearBreakPoints` clears every member's, then its own.

A group stopped by its own action break after its **last** member has no
current member. Ghidra's `printState` then dereferences `list.end()`
(444–454) and the console crashes at `Break at …` (ran, X3). Basilisk
prints the group's name and `:` and nothing after it (section 8).

#### 4.B.3 The restart group (read, `action.cc` 529–582)

Members: `maxrestarts`, `curstart`. `reset`: `curstart = 0`, then the
group's reset. `curstart` is not initialised before the first reset; the
console always resets first; here it starts at 0. `apply`:

```
if curstart == -1: return 0                       (already completed)
loop:
    res = group apply;  if res != 0: return res
    if not fd.restart_pending:  curstart = -1; return 0
    if fd.jumptablerecovery_on: return 0           (no restart inside recovery; curstart is kept)
    curstart += 1
    if curstart > maxrestarts:
        fd.warningHeader("Exceeded maximum restarts with more pending"); curstart = -1; return 0
    clearAnalysis(fd)                              (4.A.2: clears restart_pending)
    reset every member (not this group); status = start
```

Because the status is then `start`, the next group apply begins again at
the first member. The universal root is such a group with
`rule_onceperfunc` and `maxrestarts` 1.

#### 4.B.4 Rules and pools (read, `action.cc` 622–960)

Rule flags: `type_disable` 1, `rule_debug` 2, `warnings_on` 4,
`warnings_given` 8. A rule has a name, a group, break points (only the
action kinds are ever tested), counters, and the list of opcodes it
applies to (`getOpList`). `addRule` appends the rule to the pool's list
and to the per-opcode list of each opcode it names, in call order; a
rule that names an opcode twice is entered twice and is tried twice
(seen in the oracle: `COPY,COPY`).

`ActionPool::apply`: unless the status is `mid`, the cursor is the first
op of the main op tree (all ops, dead ones included, in `SeqNum` order)
and the rule index 0; then `processOp` on the cursor's op until the
cursor is at the end (return 0) or it returns −1.

`processOp(op)`:

```
if op is dead:  advance the cursor; retire the op (opDeadAndGone); rule index = 0; return 0
opc = op.code
while rule index < len(perop[opc]):
    rule = perop[opc][rule index];  rule index += 1
    if rule is disabled: continue
    recorder.begin_unit;  rule.count_tests += 1;  res = rule.applyOp(op, fd);  recorder.end_unit(rule name)
    if res > 0:
        rule.count_apply += 1;  pool.count += res;  warn once
        if the rule's action break point is set: clear the temporary one; return -1
        if op is dead: break
        if opc != op.code:  opc = op.code; rule index = 0
advance the cursor; rule index = 0; return 0
```

* The cursor is advanced **before** a dead op is retired and after the
  rules of a live one, so an op a rule created with a later sequence
  number is visited in the same pass, and the walk is a key cursor in
  Rust (`plan` 3 item 4).
* After a rule changes the opcode, the rules of the new opcode are tried
  from the first; otherwise the *next* rule is tried, not the first.
* A stop at a rule's break point returns before the dead and opcode
  checks. On the next `processOp` the opcode is read afresh but the rule
  index is **not** reset: a break point on a rule that changes the
  opcode changes which rules are tried next. Reproduced (the oracle
  table has such rows); section 8.
* In Ghidra's debug build a rule that changes the opcode and returns 0
  is `ERROR: Rule <name> changed op without returning result of 1!`; the
  optimised build goes on with the old opcode's list. Basilisk reports
  the error in debug builds and behaves as the optimised build
  otherwise.
* The pool's own flags and break points are handled by `perform` like
  any action's; with `rule_repeatapply` the whole walk repeats until a
  pass changes nothing.

#### 4.B.5 Listing, state, statistics, warnings, specifiers (read, `action.cc` 41–48, 93–97, 132–164, 171–289, 428–504, 741–800)

* **`print(num, depth)`**: an action's line is the number right-aligned
  in 4 columns (decimal, padded with spaces), ` repeat ` or eight
  blanks, `!` for `rule_onceperfunc` else a blank, `S` when a start
  break point is set else a blank, `A` for an action break point else a
  blank, `depth*5+2` blanks, the name; it takes one number. A group
  prints its line and a line end, then each member at `depth+1` followed
  by a line end, with `  <-- ` after the member that is current. A pool
  prints its line and a line end, then per rule: the number in 4
  columns, `D` when disabled else a blank, `A` for an action break point
  else a blank, `(depth+1)*5+2` blanks, the name, a line end. So a pool
  inside a group is followed by an empty line. The `ghidra` profile's
  listing must equal `docs/research/decomp-wave3/list-actions.txt`
  line for line (243, 157, 179, 183, 140, 16 lines for the six roots;
  ran, X1). `list action` in Ghidra's console prints into a stream whose
  fill character earlier commands may have changed (GHIDRA-BUGS, smaller
  observations); the listing here always pads with blanks, as `bk list
  actions` does.
* **`printState`**: the name, then ` start` for the statuses `start`,
  `breakstarthit`, `repeat`; `:` for `mid`; ` end` for `end`; nothing
  for `actionbreak`. A group in `mid` appends its current member's
  state; a pool in `mid` appends a blank and the cursor op's sequence
  number.
* **`printStatistics`**: `<name> Tested=<n> Applied=<m>` per action, and
  per rule after its pool, in listing order.
* **Warnings**: when `warnings_on` is set and `warnings_given` is not,
  the first application sets the latter and prints `Applied action
  <name>` or `Applied rule <name>` through the architecture's warning
  sink; `reset` clears `warnings_given`.
* **Specifiers** (`break`, `option warning`, `option togglerule`): the
  text is split at the first `:` into a token and the rest.
  `getSubAction` on a leaf or pool: itself if its name equals the whole
  text. On a group: if the token is the group's name and there is no
  rest, the group; if the token is the group's name, search with the
  rest; otherwise search with the **whole** text; the search asks every
  member and succeeds only if exactly one answers. `getSubRule` is the
  same for groups (a group name with no rest matches no rule); a pool
  whose name is the token searches its rules for a name equal to the
  rest, any other pool for a name equal to the whole text; exactly one
  match is required. So a name that occurs twice below a group cannot be
  addressed (GHIDRA-BUGS, smaller observations; D00 4.1); Basilisk adds
  addressing by position (`Pipeline::node_at(position)`), which is what
  the oracle's `bk break` uses. `setBreakPoint` tries the action form
  first, then the rule form; `setWarning` likewise; `disableRule` /
  `enableRule` use the rule form.

#### 4.B.6 Root actions (read, `action.cc` 962–1148; `coreaction.cc` 5818–5857)

A root is the universal tree filtered by a set of group names: `clone`
keeps a leaf or a rule whose group is in the set, as a **fresh instance**
(flags as constructed, enabled, no break points, counters 0;
`coreaction.hh:37–40`, `ruleaction.hh:88–91`); a group or pool is kept
with its flags and name when at least one member is, else it is absent.

* The six default group lists are those of `buildDefaultGroups`
  (5818–5857; the option oracle's `I` rows list them): `decompile` (32
  groups), `jumptable` (11), `normalize` (18), `paramid` (17),
  `register` (3), `firstpass` (1).
* `setCurrent(name)`: **first** the current name becomes `name`, then
  the root is derived: an already derived root of that name is reused,
  else the group list must exist (`Action group does not exist: <name>`)
  and the universal tree is cloned. A failed `setCurrent` therefore
  leaves the new name with the old action (ran, X5: `root=<name>` while
  `act` is unchanged). Reproduced; section 8.
* `toggleAction(root, group, on)`: add or remove the group in the root's
  list (creating an empty list for an unknown root name), clone the
  universal tree again, replace the root's instance, and make it current
  if the root's name is the current name. **Everything set on the old
  instance is lost**: disabled rules, break points, warnings, statistics
  (ran, X2).
* `setGroup`, `cloneGroup(old, new)` (`Action group does not exist`),
  `addToGroup`, `removeFromGroup` change lists only and mark the lists
  as not default.
* `resetDefaults()`: drop every derived root, rebuild the default lists
  if they were changed, make `decompile` current (derived afresh).
* A root whose list matches nothing is **null**. Ghidra then crashes in
  `list action`, `option warning`, `option nanignore` and `decompile`
  (ran, X2: exit 139); `option togglerule` reports `Missing current
  action`. Basilisk reports `Missing current action` in all of them.

#### 4.B.7 Units, profiles, the pipeline builder (ADR-025 items 1 and 2)

* **Units.** A pass crate exports its units as values: D05's `UnitInfo`
  (name, origin, groups, kind, opcodes, soundness) and a constructor
  `fn(&BuildCx, group: &str, arg: UnitArg) -> Box<dyn Action>` or `->
  Box<dyn Rule>`. `UnitArg` covers the constructor arguments Ghidra's
  placements differ by: none; a boolean (`directwrite` true/false,
  `prefercomplement` and `structuretransform` true/false); the stack
  space (`extrapopsetup`, `stackptrflow`); the architecture
  (`ptrflow`).
* **A profile** is data: a tree of placements —
  `Group { name, flags, restart: Option<max>, members }`,
  `Pool { name, flags, rules: [(unit name, group)] , extra_rules: bool }`,
  `Leaf { unit name, group, arg }` — and the root group lists. The
  **`ghidra` profile** is `universalAction` (`coreaction.cc` 5861–6149)
  written out as that tree: the restart group `universal`
  (`rule_onceperfunc`, 1 restart) with 8 leading leaves, `fullloop`
  (repeat) holding `mainloop` (repeat) holding 18 leaves, `stackstall`
  (repeat: `oppool1` with 134 rules and the architecture's extra rules
  appended, then 5 leaves), 3 leaves, `oppool2` (5 rules), 5 leaves;
  then 10 leaves of `fullloop`; then 2 leaves, the pool `cleanup` (22
  rules), and 29 trailing leaves. The names, groups, flags and order are
  the table of inventory 5.2 and section 6 of the inventory; the
  generated listing is checked against X1's capture, which is the
  authority.
* **The builder** resolves each placement's unit by name in the unit
  table: a missing unit, or two units of one name, kind and origin, is
  an error naming it. For work before all units exist the builder takes
  a policy: `Missing::Error` (the `ghidra` profile in release) or
  `Missing::Placeholder` — a unit that fails with "unit `<name>` is not
  implemented" when applied. Listing, specifiers, group filtering and
  the oracle tables need no real unit; the pass tracks register theirs.
* **`basilisk`-origin units** enter only through another profile. Test
  profiles (test B-6): one adds a `basilisk` unit after `deadcode`, one
  replaces `earlyremoval`; the `ghidra` profile's listing and trace are
  unchanged by their existence.
* One switch per unit: the registry of 4.B.8 has, besides Ghidra's
  options, `unit <name> on|off` for a `basilisk`-origin unit (off in the
  `ghidra` profile by construction). Ghidra's own per-rule switch is
  `togglerule`.

#### 4.B.8 Options (read, `options.cc`; ran, X2, X5)

`OptionDatabase::set(name, p1, p2, p3)` looks the name up among 38
registered options (`options.cc:98–135`): an unknown name, and the
declared but unregistered `hideextensions` (GHIDRA-BUGS 41) and
`structalign` (an element id without a class), is `Unknown option`
(a parse error). `decode` reads `<optionslist>`: each child is an option;
its parameters are `<param1>`, `<param2>`, `<param3>` in that order, or
the element's own content as the first parameter when it has no
children (165–190). The console passes up to three blank-separated
words (`Too many option parameters`).

Outcomes are a returned text or one of Ghidra's three error classes
(`ParseError`, `RecovError`, `LowlevelError`), which the console and the
host report differently; the option oracle's rows give class and text
for 30,350 commands (test B-3), and that table is the definition.
`onOrOff`: empty → on, `on`, `off`, else `Must specify toggle value,
on/off`.

**Numbers** are read with the base detected from the prefix (`0x`, `0`).
An empty parameter leaves the variable at its initial value; text that
is not a number gives 0; digits followed by other text give the digits'
value — but for `12abc` (the tail being hexadecimal digits) the libc++
build fails and gives 0 while libstdc++ gives 12 (ran, X5: 49 rows, one
cause). Basilisk follows the x86-64 Linux build (ADR-021): the longest
prefix that is a number in the detected base.

| Option | Parameters and effect (returned text) |
|---|---|
| `extrapop` | p1 `unknown` or a number (initial −300: `Bad extrapop adjustment parameter`, reached only by an empty p1 or `-300`); with p2 the named function's prototype (`Unknown function name: <p2>`; `ExtraPop set for function <p2>`), else the default model and both evaluation models when set (`Global extrapop set`) |
| `readonly` | empty: `Read-only option must be set "on" or "off"`; sets `readonlypropagate` |
| `defaultprototype` | `Unknown prototype model :<p1>` (low-level); `setDefaultModel` |
| `inferconstptr`, `analyzeforloops` | toggles (`Recovery of for-loops is <p1>` echoes p1 as given, also when empty) |
| `inline`, `noreturn` | p1 a function name (`Unknown function name: <p1>`); the value is true unless p2 is given and is not the word `true` |
| `warning` | p1 an action or rule specifier (`No action/rule specified`; `Bad action/rule specifier: <p1>`), p2 a toggle (default on) |
| `nullprinting`, `inplaceops`, `conventionprinting`, `nocastprinting` | toggles of the C printer's options; another language answers with a text and changes nothing (the texts are in the table) |
| `maxlinewidth` | initial −1 (`Must specify integer linewidth`, reached only by an empty p1); a value below 20 or above 10,000 is `Bad maximum line size` (low-level, `prettyprint.cc:1259–1262`) |
| `indentincrement`, `commentindent` | initial −1 (`Must specify integer increment` / `… comment indent`) |
| `commentstyle` | `c` or a text starting `/*`; `cplusplus` or starting `//`; else `Unknown comment style. Use "c" or "cplusplus"` |
| `commentheader`, `commentinstruction` | p1 a comment type (`user1`, `user2`, `user3`, `header`, `warning`, `warningheader`; else `Unknown comment type: <p1>`), p2 a toggle: set or clear the bit |
| `integerformat` | a text starting `hex`, `dec` or `best`; else `Unknown integer format option: <p1>` |
| `braceformat` | p1 the category (`function`, `ifelse`, `loop`, `switch`; `Unknown brace format category: <p1>`), p2 the style (`same`, `next`, `skip`; `Unknown brace style: <p2>`) — the style is checked first; the comment in the source has the parameters reversed (ran, X2) |
| `setaction` | `Must specify preexisting action`; with p2: copy p1's group list to p2 and make p2 current; else make p1 current (4.B.6) |
| `currentaction` | `Must specify subaction, on/off`; three parameters: make p1 current, then toggle group p2 in it by p3; two: toggle group p1 in the current root by p2 |
| `allowcontextset` | the lifter's flag (`PcodeSource::allow_context_set`) |
| `ignoreunimplemented`, `errorunimplemented`, `errorreinterpreted`, `errortoomanyinstructions`, `jumpload` | set or clear one flow-option bit |
| `baddatacount` | empty: `0xffffffff`; else a number (initial `0xdeadbeef`: `Bad baddatacount parameter`, unreachable but for that value) |
| `protoeval` | `Must specify prototype model`; `default` or a model name (`Unknown prototype model: <p1>`); sets `evalfp_current` |
| `setlanguage` | selects or creates the print language (`Unknown print language: <p1>`); a new language takes the old one's output stream and markup setting; then the type operators are adjusted for the language (step A9) |
| `jumptablemax` | a number, 0 is `Must specify integer maximum` |
| `togglerule` | `Must specify rule path`, `Must specify on/off`, `Missing current action`; `Successfully disabled rule` / `Failed to disable rule` (and the enable forms): on the current root's instance only |
| `aliasblock` | `none` 0, `struct` 1, `array` 2, `all` 3 (`Must specify alias block level`, `Unknown alias block level: <p1>`); `Alias block level unchanged` when equal |
| `maxinstruction` | `Must specify number of instructions`; negative: `Bad maxinstruction parameter` |
| `namespacestrategy` | `minimal`, `all`, `none`; else `Must specify a valid strategy` |
| `splitdatatype` | up to three of `struct`, `array`, `pointer` (`Unknown data-type split option: <v>`); then, on the **current** root: with neither struct nor array, groups `splitcopy` and `splitpointer` off; else `splitcopy` on and `splitpointer` as the pointer bit — two `toggleAction`s, so the root is derived again twice |
| `nanignore` | `none`, `compare`, `all` (`Unknown nanignore option: <p1>`); sets the two flags, then disables the rule `ignorenan` on the current root when both are off, else enables it |

`nanignore none` is therefore undone by any later option that derives
the root again (`splitdatatype`, `currentaction`, `setaction` to a new
root), and never reaches the other roots (ran, X2). The `ghidra` profile
reproduces it, because the order of options is part of a test's script;
section 8.

`Arch`-level `resetDefaults` (1440–1447): `Config` to its defaults, the
roots as in 4.B.6, every created print language's options to its
defaults. It leaves `ModelState`, function properties, the selected
language, the Java operator table and `allowcontextset` as they are
(ran, X5).

#### 4.B.9 Pipelines and drivers

A `Pipeline` is one root instance with its status: built from a profile
and a root's group list, owned by one decompilation, `Send`. The
program-wide **`PipelineConfig`** (`Clone`, frozen during decompilation)
holds the profile's name, the group lists, the current root's name, and
what Ghidra keeps on the current root's instance between functions: the
disabled rules, warnings, break points, and the statistics. Since
Ghidra's root instance is shared by all functions, three things carry
over from one function to the next there: the statistics (merged back
after a decompilation, in commit order), the `status` of `OwnOnly`-reset
units (4.B.1: `normalizesetup`), and break points. The console and the
data-test runner (D09) keep one pipeline per root across functions,
which is exactly Ghidra; the parallel driver (D17) builds one per
function from the config and must say what it does with `normalizesetup`
(open item 3).

* `Pipeline::reset(fd)`, `perform(fd) -> Stop { Done(count) | Break }`,
  `print_state`, `list`, `statistics`, `set_break(position | specifier,
  kind)`: 4.B.1 to 4.B.5.
* The driver brackets every unit application with the recorder
  (`begin_unit`, `end_unit`; `debugActivate`, `debugModPrint`), so D05's
  trace recorder reproduces `decomp_bk_dbg`'s trace once units exist.
  The trace's own break (`trace break <n>`: the status becomes
  `actionbreak` when the record count reaches `n`, `action.cc` 335–340,
  841–846) is offered through the recorder's return value.
* Between unit applications the driver checks a cancellation flag and a
  budget (plugin binding constraints: a monitor type that is not in a UI
  crate); a cancelled run returns `DecompError::Cancelled` and leaves the
  program state untouched (plan 3 item 9). No Ghidra counterpart.
* `@actions` of a dump loads into a pipeline: per line the status,
  counts and flags, and where a group or pool stands mid-way (`child:<i>`,
  `op:<seqnum>/<rule index>`, `restart:<curstart>`), so that a loaded
  state can be continued (test B-5).
* `impl ActionRunner` for the decompilation's set of pipelines.

### Part C — compound operations (`bk-decomp-ops`)

Functions over `&mut Funcdata`. Each is ported from the lines named,
with a unit test per function that cites them (as D05's test 4a). The
one-line descriptions are Ghidra's own (`funcdata.hh`); **the bodies
were not read to the standard of parts A and B** unless a row says
"read". The implementer reads each before porting and lists what it
found different from the description.

#### 4.C.1 Op edits (`funcdata_op.cc`)

| Function | Lines | Used by | What |
|---|---|---|---|
| `createStackRef`, `opStackLoad`, `opStackStore` | 473–572 | D11, call specs | Build `sp + off` (and a `LOAD`/`STORE` through it) before or after an op |
| `opBoolNegate` | 574–591 | rules | Insert `BOOL_NEGATE` of a varnode |
| `opUndoPtradd` | 593–628 | rules, D16b | Turn `PTRADD` back into `INT_ADD` (with a multiply unless the element size is 1) |
| `getFirstReturnOp` | 646–668 | D11, D12, D16b | A `RETURN` that is not a halt |
| `findPrimaryBranch`, `listOps` | 938–995 | overrides (D09) | The op of an instruction that is the branch, call or return; `listOps` walks the main tree and the quarantined `INDIRECT`s |
| `replaceLessequal` | 997–1039 | rules | `a <= c` to `a < c+1` when no overflow |
| `distributeIntMultAdd`, `collapseIntMultMult` | 1041–1127 | rules | Coefficient distribution and collapse |
| `buildCopyTemp` | 1129–1190 | R7 | Copy a varnode into a unique before a point |
| `opFlipInPlaceTest`, `opFlipInPlaceExecute`, `opNormalizeFlip` | 1192–1320 | D15, rules | Negate a condition in place; they use the opcode's boolean flip (`bk-pcode`/D05's table, no D08 dependency) |
| `opCollapseIndirectsForCopy`, `opCollapseIndirectsForAlias` | 1322–1490 | rules | Convert `INDIRECT`s around a `COPY`; drop them where no alias exists (reads the store guards) |
| `cseFindInBlock`, `cseElimination`, `cseEliminateList` | 1492–1623 | D11, rules | Common sub-expression elimination; the list form uses a **stable** sort by hash (1593), kept stable |
| `moveRespectingCover` | 1625–1668 | D15 | Move an op past another if covers allow (uses highs) |

#### 4.C.2 Varnode and symbol operations (`funcdata_varnode.cc`, `funcdata.cc:358–460`)

The members listed for "ops" in 3.4, lines as in the function list of
`docs/research/decomp-wave3/plan_graph.txt` ("Members of the D07
files"). Groups: input adjustment (`combineInputVarnodes` 395,
`adjustInputVarnodes` 508, `newExtendedConstant` 476); read-only and
volatile memory (`fillinReadOnly` 663, `replaceVolatile` 745);
`calcNZMask` 884; symbol synchronisation (`syncVarnodesWithSymbols` 969
to `linkSymbolReference` 1262, `findLinkedVarnode(s)` 1287, `mapGlobals`
1748, `prepareThisPointer` 1818); dynamic symbols (`buildDynamicSymbol`
1355, `attemptDynamicMapping(Late)` 1384); parameter-trial ancestry
(`checkCallDoubleUse` 1851, `onlyOpUse` 1900, `ancestorOpUse` 2012,
`AncestorRealistic` 2092–2334); `spacebaseConstant` (`funcdata.cc`
358–460, read: the `PTRSUB` of a marked zero constant and the offset,
with an `INT_ADD` for an offset inside the symbol and a `ZEXT` or
`SUBPIECE` when the pointer size differs from the constant's; a `COPY`
is rewritten in place). The symbol-linking members that only the merge
and naming actions call (`linkSymbol`, `linkSymbolReference`,
`linkProtoPartial`, `findLinkedVarnodes`, `attemptDynamicMappingLate`,
`detectSymbolConflicts`) may move to D14 if the coordinator prefers;
they are here because the plan gives the file to D07.

#### 4.C.3 Expressions (`expression.cc`)

`PcodeOpNode`, `TraverseNode` (flags `actionalt` 1, `indirect` 2,
`indirectalt` 4, `lsb_truncated` 8, and its static tests),
`BooleanMatch` (`same` 1, `complementary` 2, `uncorrelated`; `evaluate`
to a depth), `BooleanExpressionMatch` (`maxDepth`), `AdditiveEdge`,
`TermOrder`, `AddExpression`, `BitFieldExpression` and its three
subclasses. Read: `TermOrder::collect` (236–278) and the order
(`additiveCompare`: a term is before another when `Varnode::termOrder`
is −1 — a non-constant before a constant, then by storage address, a
multiplied term ordered by its multiplicand, `varnode.cc:1154–1174`).
The sort (292) is unstable in Ghidra and ties are common (two versions
of one register): **Basilisk sorts stably** (ADR-040). Both C++
libraries use insertion sort for the short lists that occur, and the
captures of both builds agree on all 607 decompilations (D00's report),
so no table row distinguishes the rule today; unverified for lists long
enough to leave insertion sort.

#### 4.C.4 Call-spec operations (`fspec.cc` 4780–5928)

The methods of `FuncCallSpecs` named in the scan's user table: creation
from a call op and `setFuncdata` (D09's flow uses them), `clone`,
`deindirect`, `forceSet`, `insertPcode` (needs D09's live injection:
through a callback), the stack placeholder (`createPlaceholder`,
`resolveSpacebaseRelative`, `abortSpacebaseRelative`), input recovery
(`initActiveInput`, `checkInputJoin`, `doInputJoin`,
`checkInputTrialUse`, `finalInputCheck`, `buildInputFromTrials`),
output recovery (`checkOutputTrialUse`, `buildOutputFromTrials`),
`lateRestriction` and the `transferLocked*` family, `commitNewInputs`,
`commitNewOutputs`, `paramshiftModifyStart`/`Stop`, `hasEffectTranslate`,
`getInputBytesConsumed`/`set…`, `countMatchingCalls` (no caller in
Ghidra: not ported). `compareByEntryAddress` and its sort (5906) belong
to `countMatchingCalls`. `checkInputTrialUse` takes D11's `AliasChecker`
as a trait argument.

#### 4.C.5 Dynamic hashing (`dynamic.cc`, `crc32.cc`)

`DynamicHash`: the four hash methods, `uniqueHash` (both forms),
`findVarnode`, `findOp`, `gatherFirstLevelVars`, and the field
extractors of a hash. Read: the edge order (`ToOpEdge::operator<`,
68–79: the op's instruction address, then its `order`, then the slot)
and the edge hash (93–103: slot, the opcode through `transtable`, then
the address offset byte by byte, low byte first, for the address size);
opcodes that translate to 0 are skipped along the data-flow (106–150).
`order` is local to a block, so two ops of one instruction in different
blocks can tie; the sort (148) is unstable in Ghidra: **Basilisk sorts
stably**, keeping reader-list order (ADR-040); unverified whether a tie
is reachable. `transtable` and the layout of the 64-bit hash are **to be
specified** from 24–63 and the extractor functions.

#### 4.C.6 Cloning and node splitting (`funcdata_block.cc` 760–914, 970–1114)

`forceGoto`, `nodeJoinCreateBlock`, `nodeSplitBlockEdge`, `nodeSplit`,
`removeFromFlowSplit`, `CloneBlockOps`: **to be specified** from those
lines.

## 5. Design

### 5.1 Crates and modules (every file under 600 lines)

* `bk-decomp-core`: `arch/{spec, config, models, print_options, assemble,
  lanes, segments, codec}`, `userops/{kinds, manage, builtin}`, `inject`,
  `function/{record, table, flags, lifecycle, warnings, codec, spacebase}`,
  `callspec/{data, list}`, `proto/{symbol_store, parameter}`,
  `env` (`FunctionEnv`), `blocks/{remove, multiequal, branch, reset,
  jumplist}`, `state/{heritage, jumptable, local, merge, access}`,
  `high/{table, flags, events, update, symbol}`, `dump/{function, proto,
  callspecs, jumptables, heritage, highs, types}`, `traits`, `overlay`,
  `error`; from step A9 `typeop_env`, `unionfacet`.
* `bk-decomp-pipeline`: `action` (traits), `status` (the state machine),
  `group`, `restart`, `pool`, `print`, `specifier`, `roots`, `unit`
  (constructors over D05's table), `profile/{model, ghidra, builder}`,
  `options/{registry, numbers, arch, print, actions, table}`, `pipeline`,
  `driver`, `dump` (`@actions`), `error`.
* `bk-decomp-ops`: `op/{stack, negate, ptradd, compare, mult, flip,
  indirect, cse, movecover}`, `varnode/{inputs, readonly, volatile,
  nzmask, sync, link, dynamic, globals, thisptr, undef}`, `ancestor`,
  `expr/{node, boolean, terms, add, bitfield}`, `callspec/{create, stack,
  inputs, outputs, locked, commit}`, `dynhash/{crc, edge, hash, find}`,
  `clone`, `error`.

### 5.2 Public API (sketch)

```rust
// bk-decomp-core
pub struct Arch { pub spec: Arc<ArchSpec>, pub config: Config, pub models: ModelState, pub print: PrintOptions,
                  pub program: Arc<ProgramState> /* D06: database, image, comments, cpool, context */,
                  pub functions: FunctionTable }
pub fn assemble(parts: ArchParts<'_>) -> Result<Arch, ArchError>;
pub struct Funcdata { /* 4.A.3; fields private */ }
impl Funcdata {
    pub fn begin(arch: &Arch, function: SymbolId) -> Result<Self, DecompError>;   // copy of the record, overlays, forks
    pub fn finish(self) -> FunctionOutcome;      // the record's changes and the overlays, for commit (ADR-044)
    pub fn ssa(&self) -> &Ssa;   pub fn ssa_env(&mut self) -> (&mut Ssa, &mut dyn FunctionEnv);
    pub fn flags(&self) -> FuncFlags;            // and the setters of funcdata.hh
    pub fn clear(&mut self) -> Result<(), DecompError>;
    pub fn warning(&mut self, text: &str, at: Address);   pub fn warning_header(&mut self, text: &str);
    pub fn start_processing(&mut self, follow_flow: &mut dyn FnMut(&mut Funcdata) -> Result<(), DecompError>) -> Result<(), DecompError>;
    pub fn call_specs(&self) -> &[CallSpecId];   pub fn call_spec(&self, id: CallSpecId) -> &CallSpec;
    pub fn call_spec_of(&self, op: OpId) -> Option<CallSpecId>;
    pub fn structure_reset(&mut self) -> Result<(), DecompError>;
    pub fn remove_unreachable_blocks(&mut self, warn: bool, check: bool) -> Result<bool, DecompError>;
    pub fn heritage(&self) -> &HeritageState;    pub fn heritage_mut(&mut self) -> &mut HeritageState;  // likewise the other states
    pub fn high(&mut self, id: HighId) -> HighRef<'_>;    // drains D05's events first
    pub fn load_dump(arch: &Arch, dump: &oracle::state::Dump) -> Result<Self, DumpError>;
    pub fn write_dump(&self, into: &mut oracle::state::Dump) -> Result<(), DumpError>;
}
// bk-decomp-pipeline
pub trait Action: Send {
    fn apply(&mut self, fd: &mut Funcdata, cx: &mut RunCx<'_>) -> Result<u32, DecompError>;   // the number of changes
    fn reset(&mut self, fd: &mut Funcdata) -> ResetKind { ResetKind::Full }
}
pub trait Rule: Send {
    fn apply_op(&mut self, op: OpId, fd: &mut Funcdata, cx: &mut RunCx<'_>) -> Result<u32, DecompError>;
    fn reset(&mut self, fd: &mut Funcdata) {}
}
pub struct Profile; pub struct PipelineConfig; pub struct Pipeline;
impl Pipeline {
    pub fn build(profile: &Profile, root: &str, cfg: &PipelineConfig, units: &UnitTable, cx: &BuildCx) -> Result<Self, BuildError>;
    pub fn reset(&mut self, fd: &mut Funcdata);
    pub fn perform(&mut self, fd: &mut Funcdata, run: &mut RunCx<'_>) -> Result<Stop, DecompError>;
    pub fn list(&self) -> String;   pub fn state(&self) -> String;   pub fn statistics(&self) -> String;
}
pub struct Options;  impl Options { pub fn set(&self, target: &mut OptionTarget<'_>, name: &str, p: [&str; 3]) -> Result<String, OptionError>; }
```

A leaf returns its number of changes instead of adding to a shared
`count`; no leaf of Ghidra's returns anything but 0 from `apply`
(`grep` of `coreaction.cc`, `blockaction.cc`, `condexe.cc`: the only
`return -1` are in helper functions), so "partial completion" exists
only for groups and pools and is the framework's.

### 5.3 Data layout, allocation, concurrency

* A pipeline is a flat arena of nodes (`Vec<Node>`; a group's members
  are a range of child ids), statuses and counters in parallel arrays;
  a pool's per-opcode rule lists are `SmallVec<[u16; 8]>` indices into
  its rules, indexed by opcode. No allocation while running: the walk
  holds a `SeqNum` key; the recorder is an `Option<&mut dyn Recorder>`.
* `ArchSpec`, `Config`, `ModelState`, `PrintOptions`, `PipelineConfig`,
  `Profile`, the unit table and the function table are `Send + Sync`
  and immutable while functions are decompiled (ADR-044). A `Funcdata`
  and a `Pipeline` are `Send`, owned by one worker. Units are `Send`;
  per-function unit state (the counters the seven `reset` overrides
  clear) lives in the unit instance.
* What a decompilation changes outside itself goes into its outcome and
  is committed in operation order: the function record (the recovered
  prototype, jump-table overrides), the symbol overlay (D06), the type
  fork (D02), built-in user ops, comments, statistics. The console and
  the data-test runner commit after every function, which is Ghidra's
  sequential behaviour: a later caller sees the prototype an earlier
  decompilation left in the callee's record.
* Options change `Config`, `ModelState`, `PrintOptions`,
  `PipelineConfig` and function records, between decompilations only.
* Errors: `DecompError` (`thiserror`) carrying Ghidra's message where
  Ghidra has one, the unit in force and the function; `ArchError`,
  `OptionError { class: Parse | Recov | LowLevel, text }`,
  `BuildError`, `DumpError`. No panics: every id is checked, every
  cursor re-validated after a unit ran.
* ADR-011: nothing on crates.io implements this framework; `smallvec`
  and `bitflags` are in the workspace. A generic pass manager (`salsa`,
  `egg`'s runner) would not reproduce Ghidra's order, which is the
  behaviour.

### 5.4 ADR-025's hooks

Items 1 and 2: 4.B.7. 3a: the recorder brackets (4.B.9), the evaluator
(4.A.14, open). 3d: `Funcdata::finish` returns what D17 builds the
`FunctionSummary` from (the prototype, `noreturn`, the call list); the
host's `call_returns` is asked by D09. 3e: `AccessTable` (4.A.10); the
type fork per function. 3f: a function record's prototype keeps
`bk-cspec`'s provenance; warnings are `Analysis`.

### 5.5 Plugin binding constraints (ADR-037)

Rule 2: the frozen values are `Send + Sync + 'static`. Rule 4: the error
enums map to exception classes; `OptionError` keeps Ghidra's class.
Rule 6: `list`, `state`, `statistics` return owned strings. Rule 8:
`Action`, `Rule`, `PcodeSource`, `ActionRunner`, `JumpTableRecovery`,
`ExecScript` are object-safe. Cancellation and progress: the driver's
monitor (4.B.9). The others concern the program model.

## 6. Tests

Kinds **S**, **G**, **L** as in plan 4.5. Checklist ids: Ghidra has no
unit test for these modules (`docs/inventory/tests/decompiler-cpp.md`:
the C++ unit tests are circle ranges, float emulation, prototypes,
marshal, multi-precision, parameter stores, types); this track marks no
line. The 93 data tests are D17's.

**Part A**

* A-1 **State round trip** (S subset, L all): every `bkstate` section
  loads and writes back byte for byte for D00's captures (607
  decompilations, five points each); with D05 and D06 the whole dump.
* A-2 **Assembly** (G): for the 93 data tests' architectures, the
  spaces, models, default model, `min_funcsymbol_size`, lane records,
  `inferPtrSpaces`, user ops (index, name, kind) and payload ids equal a
  table from Ghidra — **an oracle addition**: `arch_oracle.cc`, a
  prototype in the form of `docs/research/decomp-wave2/image_oracle.cc`,
  rows `A` (id, min function symbol size, flags), `S` per space, `M`
  per model (name, extrapop, printed, strategy), `U` per user op, `J`
  per payload (id, kind, name), `L` per lane record, `P` per inferable
  space, one file per data test in byte order of names. To be written by
  the track (step A2); not prototyped here.
* A-3 **`FunctionEnv`** (S): D05's mutation tests run against this
  implementation with the table's answers supplied through a scripted
  scope and prototype, giving the same states.
* A-4 **Lifecycle** (S): `clear` leaves exactly the flags of 4.A.3;
  warnings' texts in and out of jump-table recovery; `startProcessing`
  twice; `fillinExtrapop` on `c2 08 00` and on `c3`; `<function>` encode
  and decode with each child, the shell form, the errors, an unknown
  child.
* A-5 **Block surgery** (S, L): unit tests per function of 4.A.8 from
  the lines; from Ghidra's dumps, wherever two consecutive standard
  dumps differ by removed blocks (the trace names `unreachable`,
  `donothing`, `deadcode`), applying the function gives the next dump's
  blocks, ops and call specs — a diagnostic until D12's actions exist.
* A-6 **User ops** (S, G): every error text of 4.A.9; the built-ins'
  types; G: the user-op table of A-2.
* A-7 **Highs** (S, L): the events of 4.A.11 against hand-derived
  states; `@highs` round trip at the `stop` point for all captures.
* A-8 Properties (`proptest`): dump → load → dump is the identity on
  any loaded state; a refused call changes nothing.
* Fuzz: `bk_decomp_core_state` (any dump text: no panic, and what loads
  writes back), `bk_decomp_core_function` (`<function>`).

**Part B**

* B-1 **The action table** (S replay, L regeneration): the generator
  `crates/bk-decomp-pipeline/tests/oracle/action.cc` (from
  `docs/research/decomp-wave3/action_oracle.cc`, built by `regen.sh`
  with `build.sh`'s flags) run as `action REF DT/elseif.xml 0x1006ca 1
  2000`: 136,527 rows, identical on both reference builds (X4). The
  replay builds each tree from the `N` rows with scripted units, an
  `Ssa` holding the `F` rows' ops alive in one block, applies the `B`
  and `J` rows, and requires every `L`, `S`, `K`, `C`, `P`, `W`, `E`, `Z`
  row to be equal, the 6 `!case` rows included. The table is checked in
  gzip-compressed under both library names; the test requires them
  identical. The `<past-the-end>` state (125 rows) is what Basilisk
  prints there by definition.
* B-2 **Listings** (S): the `ghidra` profile's six listings equal the
  checked-in `list-actions` capture; with `togglerule`, break points and
  a toggled group, equal further captures taken with `bk list actions`
  (the track adds them: `D`, `S`, `A` marks; the 242-line root of X2).
* B-3 **The option table** (G replay, L regeneration): `option.cc`
  (from `option_oracle.cc`), `option REF DT/elseif.xml 0x1006ca 1 3000`:
  74,055 rows on each build. The replay assembles the architecture of
  `elseif.xml` from the spec root, applies every command and requires
  class, text and changed keys to be equal, the `R` and `U` rows too.
  Rows where the two builds differ are recognised by cause and counted
  (ADR-040's form): one cause, `hex-letter tail after decimal digits`,
  49 rows; Basilisk equals the libstdc++ table everywhere. Keys the
  crate cannot have before step A9 (`typeops`) are compared from then
  on. The 4 `skip` classes aside, a command Ghidra cannot survive (a
  null root) is absent from the table and tested by hand (4.B.6).
* B-4 **Statistics and trace** (S, L): once a pass track registers
  units, `print actionstats` and the `decomp_bk_dbg` trace of its runs;
  here: the framework's part on scripted units (the bracket order, a
  unit that touched nothing prints nothing).
* B-5 **`@actions`** (S, L): every captured dump's section loads into a
  pipeline and writes back equal; for a dump taken at a break point,
  `print_state` equals the path the capture driver recorded.
* B-6 **Profiles** (S): a missing unit and a duplicate fail the build
  with the name; the two test profiles of 4.B.7; the six default group
  lists; a root with no member is an error value.
* B-7 **Specifiers** (S): the `S` rows of B-1, and the names that occur
  twice in the `decompile` root resolve by position only.
* Fuzz: `bk_decomp_pipeline_options` (`<optionslist>` documents).

**Part C**

* C-1 Unit tests per function, each citing its lines (S).
* C-2 **Dynamic hashes** (S, L): for every `M` record with `hash:0x…`
  in the captured `@scope` sections (42 dumps with dynamic entries, D00's
  report), `findVarnode` on the loaded state returns the varnode whose
  symbol entry is that record, and `uniqueHash` of that varnode gives
  the hash.
* C-3 **Compound operations by replay** (L, later): accepted with the
  rule and action tracks that call them, from Ghidra's dumps and trace;
  listed here so that the tracks know the functions carry no acceptance
  of their own beyond C-1.
* C-4 `TermOrder` (S): ties keep input order; the orders of the
  `termorder` records in the captured traces (352 applications in the
  data tests) once R1 runs.

**Benchmarks** (`PERF.md`): a pool walk over one million ops with 134
scripted rules of which 1 % apply; `perform` overhead per leaf; loading
the largest captured dump into a `Funcdata`; `assemble` for x86-64 gcc
against the reference console's `load test file` time.

## 7. Acceptance

1. Part A: A-1 byte-exact on the checked-in subset on Windows, macOS and
   Linux, and on all captures where the reference is present; A-2 equal
   for the 93 data tests; A-3, A-4, A-6, A-7, A-8 pass; A-5's unit
   tests pass.
2. Part B: B-1 with every row equal on all three systems; B-2 equal for
   the six roots; B-3 with every row equal or recognised and counted;
   B-5, B-6, B-7 pass.
3. Part C: C-1 for every function of 4.C; C-2 on the checked-in subset;
   every "to be specified" item of this document is either specified in
   the status report with its lines or listed under Gaps.
4. The unit table's `ghidra` names and groups equal D05's checked-in
   list; the `ghidra` profile has the 161 rules, the 80 leaf placements
   and the 7 groups and pools of `universalAction`, each once.
5. No `unsafe`; no panic on any dump, `<function>` or `<optionslist>`
   text (fuzz 300 s each on the build host); both remote gate runs
   green; files within the size limit; public items documented with the
   Ghidra member they correspond to.

## 8. Differences from Ghidra

- `Architecture` is four values, `Funcdata` is a record plus the state
  of one decompilation, and a pipeline belongs to one decompilation;
  committing after every function reproduces Ghidra's single shared
  objects (4.A.1, 4.A.3, 4.B.9).
- Leaves return their change count; partial completion is the
  framework's.
- Defined where Ghidra is undefined or crashes: `count`, `lcount` and
  `curstart` start at 0; a group stopped after its last member prints
  its name and `:` (Ghidra dereferences the end iterator, X3); a null
  root is `Missing current action` everywhere (X2); `<function>` with an
  unknown child is an error (Ghidra loops for ever, by reading);
  `SegmentOp::isConcatenation` with an 8-byte inner size computes the
  shift as 0 bits kept (`userop.cc:204`, undefined in C++).
- Host dependence removed: numeric option parameters are read as the
  libstdc++ build reads them (X5); `TermOrder` and `DynamicHash` sort
  stably (ADR-040).
- **Reproduced on purpose** (the `ghidra` profile, each pinned by a
  table or a capture): `Tested` is not counted after a start break; a
  rule break point followed by an opcode change continues with the old
  rule index; a failed `setaction` keeps the new name; re-deriving a
  root forgets disabled rules, so `nanignore none` is undone by a later
  `splitdatatype` or `currentaction` and never reaches the `jumptable`
  root; `normalizesetup` applies once per root instance (X7);
  `resetDefaults` leaves models, function properties and the print
  language; `clear` leaves six flags; `braceformat` takes the category
  first.
- Not ported: `Statistics`, `ArchitectureCapability`, `capability.*`,
  `graph.*`, `countMatchingCalls`, the unregistered `hideextensions`.
- Additions without a Ghidra counterpart: addressing a node by
  position; `Missing::Placeholder` units; the cancellation check;
  `basilisk`-origin units and their switch.

(The implementing agent appends further differences here.)

## 9. Status

Specified, not implemented. Parts A and B are specified from the source
except the items marked "to be specified"; part C is a list of
functions with their lines and users, to be read by the implementer.

## 10. Implementation plan

Each step ends with both remote gate runs green and a commit. Steps A1
to A8 are part A; B and C steps need A1 to A5 merged or on the same
branch and are independent of each other.

| Step | Content | Gate evidence |
|---|---|---|
| A1 | Crate skeleton; `Config`, `PrintOptions`, `ModelState` with defaults; flags; error types; the traits of 4.A.13 | unit tests of defaults against the option table's `I` rows |
| A2 | `ArchSpec`, `assemble`, lane records, `cacheAddrSpaceProperties`, user ops and the library at run time; the `arch` oracle | A-2, A-6 |
| A3 | `FunctionRecord`, the function table, `Funcdata` with flags, marks, warnings, `clear`, `startProcessing` without flow, the overlays and `finish` | A-4 (lifecycle part) |
| A4 | Call specs as data and the list; `SymbolProto` (4.A.6, after its specification); `<function>` codec and D06's `FunctionCodec` | A-4 (codec part) |
| A5 | `FunctionEnv` implementation; state structs of 4.A.10 with their bookkeeping; dump load and write of `@function`, `@proto`, `@callspecs`, `@jumptables`, `@heritage`, `@types` | A-1 without highs, A-3 |
| A6 | Block surgery, `structureReset`, the jump-table list | A-5 |
| A7 | The spacebase helpers, `fillinExtrapop`, `printLocalRange`, `setPrototype`, `<save_state>` | unit tests |
| A8 | The high table, D05's events, `@highs` | A-7, A-1 complete |
| A9 | After D08: `TypeOps` in `Arch`, the union map field, `TypeOpEnv`, `U` records | A-1 with `U`, B-3's `typeops` key |
| B1 | Traits, the state machine, groups, restart group, pool; scripted units for tests | B-1 |
| B2 | Listing, state, statistics, warnings, specifiers, positions | B-1 (`L`, `S` rows), B-7 |
| B3 | Roots, `PipelineConfig`, profiles, the `ghidra` arrangement, the builder with placeholders | B-2, B-6 |
| B4 | Options | B-3 |
| B5 | `Pipeline`, the driver, recorder brackets, cancellation, `@actions`, `ActionRunner` | B-4, B-5 |
| C1 | Expressions, `TermOrder` | C-1, C-4 |
| C2 | Op edits of 4.C.1 | C-1 |
| C3 | Dynamic hashing | C-2 |
| C4 | Varnode and symbol operations of 4.C.2, ancestry | C-1 |
| C5 | Call-spec operations; cloning and node splitting | C-1 |
| C6 | The evaluator, after its specification (4.A.14) | its own tests |

## 11. Open items

1. **Three crates or one** (proposed ADR A in the track report).
2. **`bk-cspec` needs `FuncProto::store_mut`** (or a store trait) for
   4.A.6; a change to a merged crate, for the coordinator.
3. **`normalizesetup` in the parallel driver**: once per root instance
   is Ghidra's sequential behaviour; D17 decides whether a per-function
   pipeline applies it every time (a difference only in the `normalize`
   root).
4. **Where the symbol-linking operations live** (4.C.2): ops or D14.
5. **The evaluator** (4.A.14) and `FlowFacts` (4.A.13) are unspecified.
6. **The parts marked "to be specified"**: 4.A.1 (Java printer
   defaults, `LanedRegister`), 4.A.2 (`sleigh_arch.cc`, what `bk-lang`
   already decodes), 4.A.5 (`FspecSpace`), 4.A.6 (the symbol-backed
   store), 4.A.8 (`switchEdge`, `spliceBlockBasic`), 4.A.10
   (`HeritageState`'s bookkeeping, `MergeState`), 4.A.11 (`HighVariable`'s
   methods), 4.A.13 (`FlowFacts`), 4.A.14 (the evaluator), 4.C.5 (the
   hash layout), 4.C.6, and the bodies of every function of part C.
