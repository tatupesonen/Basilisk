# Track `spec-decomp-wave3` — status report

Specification track for D07 (`decomp-core`, crate `bk-decomp-core`) and
D08 (`decomp-typeop`, crate `bk-decomp-typeop`) of
`docs/features/decomp-plan.md`. Writes no shipping code. **In progress.**

## State

- [x] Rules, direction, loop, ADRs (to ADR-048, read from local `master`),
      plan with amendments 11 and 12, the neighbouring specs (D00 to D06),
      the wave-2 report, the inventory, the printer spike's report.
- [x] D07 source reading, to the standard, of: `action.hh`, `action.cc`
      (all), `options.cc` (all), `coreaction.cc` 5818–6149,
      `architecture.cc` 134–704 and 1139–1472, `funcdata.hh` (all),
      `funcdata.cc` (all), `funcdata_block.cc` 27–750, `userop.cc` (all),
      `pcodeinject.cc` 100–361, the `Varnode` members that touch
      `HighVariable`, `FuncCallSpecs`' declaration, parts of
      `funcdata_varnode.cc` (25–66, 312–328, 613–640), `dynamic.cc`
      60–150, `expression.cc` 236–292.
- [ ] **Not read to the standard** (marked "to be specified" in the
      spec, with lines): the bodies of `funcdata_op.cc` 473–1668 and of
      `funcdata_varnode.cc` beyond the lines above, `fspec.cc`'s
      `FuncCallSpecs`, `ProtoStoreSymbol` and `FspecSpace`,
      `expression.cc` and `dynamic.cc` beyond the lines above,
      `transform.*`, `variable.cc`, `heritage.cc`'s bookkeeping
      functions, `sleigh_arch.cc`, `funcdata_block.cc` 760–1114.
- [x] D07 runs against the reference consoles (X1 to X7) and two oracle
      prototypes run on both reference builds.
- [x] `docs/features/decomp-core.md` (all nine sections, an
      implementation plan, open items; 15 "to be specified" marks).
- [ ] D08: **not specified.** `docs/features/decomp-typeop.md` is an
      outline: its boundary, dependencies and design come from the D07
      work and are stated with evidence; its behaviour section lists what
      to read and where, and says so at the top. `typeop.cc`, `cast.cc`
      and `unionresolve.cc` were not read; no D08 oracle was prototyped.
- [x] The plan compared with the source (14 findings; what was not
      checked is listed).
- [x] This report.

## Misfits with D05 and D06 found so far (told early)

1. **D05 never tells the owner of high variables that a varnode changed.**
   In Ghidra every `Varnode` setter forwards to its `HighVariable`
   (read, `CPP/varnode.cc`): `setFlags`/`clearFlags` call
   `high->flagsDirty()` and, when the bits include `coverdirty`,
   `high->coverDirty()` (371–393; `setDef` 421–436 and `addDescend`/
   `eraseDescend` reach them with `coverdirty` on every structural edit);
   `updateType` (both forms) and `copySymbol` call `high->typeDirty()`
   (487–537); `setSymbolProperties`, `setSymbolEntry`, `copySymbol` call
   `high->setSymbol(this)` (441–471, 536); `setSymbolReference` calls
   `high->setSymbolReference` (478–484); `clearSymbolLinks` walks the
   high's instances and calls `symbolDirty()` (397–415); the destructor
   calls `high->remove(this)` and deletes an unattached high (645–651).
   `coverDirty` also marks the piece group (`variable.hh` 276–281).
   `decomp-ir.md` 4.1 and 4.5 list the setters and `set_high`, and the
   implementation (`crates/bk-decomp-ir/src/mutate/annotate.rs` on branch
   `decomp-ir`: `varnode_set_flags`, `update_type`, `set_symbol_entry`,
   `copy_symbol`) changes the varnode only. `FunctionEnv` has
   `assign_high` and nothing else for highs. The high table is D07 state
   with D14's algorithms, so D05 cannot do the work itself, but it is the
   only place that sees every change. Without a channel the dirty bits of
   `@highs` (`highflags`) cannot be reproduced from `assignhigh` onwards
   (D14, D15, `setcasts`, the printer's builder).
   **What must change in D05**: every `Ssa` method that corresponds to one
   of the `Varnode` members above records an event for the varnode's high,
   in call order, when the varnode has one: `FlagsDirty`, `CoverDirty`,
   `TypeDirty`, `SymbolDirty`, `SetSymbol(vn)`, `SetSymbolReference(vn,
   entry, offset)`, `Removed(vn)`. Either a queue the `Ssa` owns (`fn
   take_high_events(&mut self) -> impl Iterator<Item = HighEvent>`,
   allocation only when highs exist) or a method on `FunctionEnv` called at
   those points; the queue needs no signature change. D07's function state
   drains it before any read of a high (D07 spec, 4.A.9). Nothing in
   D05's acceptance changes: loading a dump calls no setter, and no event
   is produced for a varnode without a high.
2. **A doubt about a recorded Ghidra defect** (D06's defect 16,
   `docs/GHIDRA-BUGS.md` "Smaller observations", `decomp-symbols.md` 4.17
   and 4.21 row 16: "`Architecture::decodeFlowOverride`
   (`architecture.cc:475–476`) closes its element twice"). Read again
   (`architecture.cc` 452–481): line 465 closes the `<flow>` child, line
   475 the `<calldest>` child, line 480 the list; each opened element is
   closed once. What the loop does get wrong is an unknown child: it is
   opened at 457 and never closed, so the `closeElement(elemId)` at 480
   fails. D06's "closes once" behaviour is unaffected; the bug entry
   should be reworded. Not run.
3. **`bk-cspec` (D03, merged) has no way to back a prototype's
   parameters by symbols.** `FuncProto` holds `store:
   Option<ProtoStoreInternal>` with read access only
   (`crates/bk-cspec/src/proto/funcproto.rs`); Ghidra's function being
   decompiled uses `ProtoStoreSymbol` (`fspec.cc` 3128–3300). D07's design
   (`decomp-core.md` 4.A.6) mirrors the symbols into the internal store
   and needs `FuncProto::store_mut` (one accessor); the alternative is a
   store trait in `bk-cspec`. Either is a change to a merged crate.
4. **D05's unit data and D07** fit: `UnitInfo` already lists several
   groups per name on the branch (`unit/ghidra.rs`), which the placements
   of `unreachable`, `deadcode`, `directwrite` need. D07 needs from D05,
   besides finding 1: a key cursor over the main op tree that survives
   insertion and retirement (the pool walk), `op_dead_and_gone`, and the
   recorder's unit brackets; the coordinator says ranged cursors are
   being added. Not checked against the branch after its review fixes.


## The plan compared with Ghidra's source

Method: the source read for D07 (below), and `docs/research/decomp-wave3/
plan_graph.py` — a text scan that cuts every `.cc` file into member
definitions, gives each to a track by the plan's table, and counts the
class names and uniquely named member functions each uses
(`plan_graph.txt`: sizes, the track matrix, the names behind each pair, the
users of each D07 member). A scan is evidence of a use, not proof of its
absence; rows marked **read** were checked in the source. `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/`.

### Findings

| # | Plan says | Source says (file, line) | What should change |
|---|---|---|---|
| 1 | D07 is L, 10,000 lines | The files of the row, with what D05, D09 and D13 take removed and `FuncCallSpecs` added, are 16,239 lines by the plan's own measure (`.cc` + `.hh`, comments included; `plan_graph.txt`, "Lines per track"). The plan's rule is "tracks above L are split" | Split D07 (finding 2) |
| 2 | D07 → D11 is one link of the critical path | Three parts of D07 have different users (`plan_graph.txt`, "Users of the members…"): (a) function and architecture state, block surgery, call-spec list, dump loading — used by every later track; (b) the action framework, units, profiles, options (`action.*`, `options.*`) — used by every track that defines units, calls nothing of (c); (c) the compound operations (`funcdata_op.cc` 473–628 and 938–1668, `funcdata_varnode.cc` beyond D05's part, `expression.*`, `dynamic.*`, `FuncCallSpecs`' methods, `AncestorRealistic`) — each used by one or two tracks (D11, D12, the rule families). (b) and (c) do not call each other (**read**: `action.cc`, `options.cc` use no member of (c)) | Three tracks and three crates: D07a `bk-decomp-core` (state), D07b `bk-decomp-pipeline`, D07c `bk-decomp-ops`; D07b, D07c, D08 and D10 can run in parallel after D07a. The spec is written this way (proposed ADR A) |
| 3 | D08 "needs merged: D05"; the crate tree of section 2 draws `bk-decomp-typeop` above `bk-decomp-core` | Both directions exist in the source. Core uses typeop: `Architecture::inst` and `TypeOp::registerInstructions` (`architecture.cc:614`), `adjustTypeOperators` on a language switch (`architecture.cc:416`, 431), `ResolveEdge`/`ResolvedUnion` in `Funcdata::unionMap` (`funcdata.cc:917–1117`). Typeop uses core: `FuncCallSpecs` and `getCallSpecs` (`typeop.cc:693–783`), the function's prototype (915), user ops (842–868), the union map through `Datatype::resolveInFlow` | D08 stays below core and needs D05, D02, D03, D06 (not D07): it defines the union map and an environment trait (`TypeOpEnv`) for call specs, prototype, user ops and high types; core depends on typeop and implements the trait in its last step. The plan's drawing is the wrong way round; its table is right |
| 4 | D10 needs D07; D13 owns "the value-set half of `rangeutil.cc`" and needs D01, D09, D10 | `Heritage` uses the value-set solver for load guards (`heritage.cc:740–898`: `ValueSetSolver`, `ValueSetRead`, `WidenerNone`, `WidenerFull`, **read**). D10 needs it, and D13 needs D10: a cycle | The value-set half (`rangeutil.cc` 1491–2605, `rangeutil.hh` 103–330) becomes its own small track before D10 and D13 (needs D01, D04, D05), or part of D10 |
| 5 | D12 needs D11 | `ActionSwitchNorm` calls `JumpTable::matchModel` and `recoverLabels` (`coreaction.cc:4787–4800`, scan: `D12 -> D13`); `ActionLaneDivide` constructs `LaneDivide` of `subflow.hh` (`coreaction.cc:610`, **read**) | The unit `switchnorm` goes to D13; `lanedivide` goes to R7 or D12 gains "needs R7". D12 and D13 are in the same wave today |
| 6 | D14 needs D11 | `merge.cc` and `variable.cc` use nothing of `coreaction.cc`; of `varmap.*` only `ActionNameVars` and `ActionMapGlobals` need `ScopeLocal`'s name recommendations (scan: `D14 -> D11: ScopeLocal 3, recoverNameRecommendationsForSymbols 1`) | With state loading the merge sequence can be built after D07 and D08 without D11; only the naming action waits for `varmap`. Not read line by line: unverified beyond the scan |
| 7 | Critical path D02 → D05 → D07 → D11 → D14 → D16b → D17 | D07 → D11: needed (state, framework, compound operations). D11 → D14: not needed for the merge passes (finding 6). D14 → D16b: `printc.cc` reads `HighVariable`'s lazily computed type, name representative and symbol; if those cache updates (`variable.cc`, the `HighVariable` methods, about 870 lines) are in core with the high table, D16b needs D07, D08 and the loaded structure, not D14's merge code. D07a itself cannot be shortened: every later track needs the state | Proposed: `HighVariable`'s own methods move to D07a (the D05 misfit above needs the high table there anyway); D14 keeps `Merge`, `HighIntersectTest`, the piece groups' cover logic and the actions. Then the only chain the source forces is D05 → D07a → {everything} → D17 |
| 8 | `transform.*` is D07's | `TransformManager`, `TransformOp`, `TransformVar`, `LaneDescription` are used only by `subflow.cc` (scan: R7 and D07 itself); `LanedRegister` is architecture data used by `Funcdata`, D11 and D12 | `transform.*` minus `LanedRegister` moves to R7 |
| 9 | `emulateutil.*` is D13's; `emulate.*`, `memstate.*`, `crc32.*`, `graph.*`, `capability.*` are in no row | `ExecutablePcode::build` and `evaluate` (`pcodeinject.cc:146–206`, D07's row) use `EmulateSnippet` of `emulateutil.hh`, which derives from `Emulate` (`emulate.hh`); `SegmentOp::execute` (`userop.cc:241`) and the jump-assist scripts run through it. `dynamic.cc` uses `crc_update` (`crc32.hh`) | `EmulateSnippet` and the `Emulate` base go with the track that makes payloads executable (D18), behind a trait core defines (`ExecScript`); `EmulateFunction` stays D13's; `crc32` goes with `dynamic.*` (D07c); `memstate` is `bk-emu`'s (M6); `graph.*` (data-flow graph dumps for the console) and `capability.*` (static registration) are not ported, to be listed as such |
| 10 | D07 owns "the unit table and profiles"; D17 owns "`universalAction`, `buildDefaultGroups`" | D07's own acceptance (`list action` for six roots) needs the whole arrangement and the six group lists (`coreaction.cc:5818–6149`) | D07b owns the arrangement and the group lists as data; D17 owns binding the names to the units and `paramid.*` |
| 11 | D09 is M, 5,000; D11 L 8,000 and D12 M 6,000 | D09's own files are 2,596 lines (`flow.*`, `xml_arch`, `testfunction`, the flow methods), about 5,000 with the console commands of `ifacedecomp.cc` the data tests use: plausible. `coreaction.*`, `varmap.*` and `condexe.*` are 10,300 lines in all; less the merge, marking and naming actions, `ActionSetCasts` and `universalAction`, D11 and D12 together are about 8,700, not 14,000 | D11 and D12 could be one L track, or two M tracks |
| 12 | `Funcdata::encode` is D17's | `<function>` inside `<mapsym>` is needed by D06's `FunctionCodec` hook as soon as a saved state is read (`funcdata.cc:735–837`) | D07a owns `encode` without the tree and `decode`; D17 owns `encodeTree`, `encodeHigh` and the result encoding |
| 13 | D09 "needs D07"; D13 "needs D09" | Flow calls `Funcdata::recoverJumpTable` in the middle of following flow (`flow.cc:1441`), which runs the `jumptable` root on a partial clone (`funcdata_block.cc:509–566`) | Consistent with the plan given two traits in core: `ActionRunner` (plan section 2) and a jump-table recovery hook that D13 fills; D09 is accepted without switch recovery until then. Stated in the D07 spec |
| 14 | The rule-subset oracle: "the reference console with exactly the rules Basilisk has ported enabled (`option togglerule`)" | `togglerule` changes the current root's instance only (`options.cc:902–930`). Any later `option currentaction`, `splitdatatype` or `setaction` derives the root again with every rule enabled (ran, X2), and the `jumptable` root used for switch recovery is a separate instance that never sees the toggles (`funcdata_block.cc:518–531`, **read**) | Capture scripts give every `togglerule` after the last root-changing option; a rule family's comparison on functions with switches has all rules in the jump-table root on both sides. To be told to the R tracks and D19 |

### Not checked

- The rule families' internal split (R1 to R6 over `ruleaction.cc`) was
  not checked rule by rule; the scan treats them as one.
- D15, D16b, D16c, D17, D18: only through the scan's rows; no file of
  theirs was read for this comparison.
- The size figures are line counts with comments, as the plan's are.
- `sleigh_arch.cc` (638 lines: language discovery, `buildTranslator`,
  `buildSpecFile`, `restoreXml`) is in no row. D06 took `buildSymbols`;
  the rest is `bk-lang`'s and D07a's assembly. Not read beyond that.

## What each document covers

**`docs/features/decomp-core.md` (D07; 1,580 lines).** Three crates:
`bk-decomp-core` (state), `bk-decomp-pipeline` (framework),
`bk-decomp-ops` (compound operations). Scope by crate; what is not in the
track and where it goes; the D08 boundary; a table giving every member of
`Funcdata` an owner. Behaviour, part A: the architecture as four values
with every default; assembly order; function record against the state of
one decompilation; flags, `clear` (exactly which flags), warnings,
`startProcessing`; `<function>`; call specs as data; `FunctionEnv`;
block surgery; user ops and the injection library at run time with every
error text; the state structs of later tracks; high variables and D05's
events; dump sections; the traits later crates fill. Part B: `perform`
as a state machine; groups; the restart group; pools (`processOp`
exactly); listing, state, statistics, warnings, specifiers; root
actions; units, profiles, the builder; all 38 options with texts and
quirks; pipelines and drivers. Part C: the compound operations as tables
of functions, lines and users. Design, tests (two oracle tables with
measured sizes, one oracle to add), acceptance, differences,
implementation plan in 20 steps, open items.

**`docs/features/decomp-typeop.md` (D08; outline).** See State.

## What was run, and where

`docs/research/decomp-wave3/runs.md`, X1 to X7.

- Mac only: the six root listings (X1); the option quirks in the console
  (X2); the `printState` crash in Ghidra's own console (X3);
  `normalizesetup` (X7).
- Mac and build host, each twice: `action_oracle` (136,527 rows,
  identical everywhere) and `option_oracle` (74,055 rows; 49 rows differ
  between the builds, one cause).
- `plan_graph.py` on the reference source copy (identical to the Ghidra
  tree for the six files compared with `cmp`).
- No gate run: documentation-only branch. Every push succeeded.

## Proposed ADRs (unnumbered)

**A. D07 is three crates; a pipeline belongs to one decompilation.**
`bk-decomp-core` holds state, `bk-decomp-pipeline` the action framework,
units, profiles and options, `bk-decomp-ops` the compound operations;
pipeline and ops depend on core and not on each other. The architecture's
action database becomes a frozen `PipelineConfig` plus one `Pipeline` per
decompilation (the `jumptable` pipeline built on first use); the console
and the data-test runner keep one pipeline per root across functions,
which is Ghidra's shared instance.

**B. `bk-decomp-typeop` is below `bk-decomp-core`.** It owns the
type-operator table, the cast strategies, union resolution and the union
map, and reads function state through a trait (`TypeOpEnv`) that core
implements; core depends on it. Amends the crate drawing of
`decomp-plan.md` section 2.

**C. A function is a record in program state and the state of one
decompilation.** What Ghidra keeps in a `Funcdata` across decompilations
(prototype, overrides, override jump tables, `no_code`) is a
`FunctionRecord`, frozen while functions are decompiled; a decompilation
works on a copy and returns its changes, with the symbol overlay, the
type fork, built-in user ops, comments and statistics, to be committed in
operation order (extends ADR-044 to these).

**D. The table of high variables and `HighVariable`'s own methods are
core's; `Merge` and the intersection tests stay D14's.** D05 records an
event for every varnode change Ghidra forwards to a high variable; core
applies them before a high is read. Amends the D14 row.

**E. Where Ghidra's action framework and options are undefined, crash or
depend on the host, Basilisk defines them; where they are merely odd, the
`ghidra` profile reproduces them** (ADR-024's form). Defined: a null root
action is an error; a group stopped after its last member prints its
name; `<function>` with an unknown child is an error; numeric option
parameters are read as the libstdc++ build reads them; `TermOrder` and
`DynamicHash` sort stably (ADR-040). Reproduced, each pinned by a table
or capture: the items of `decomp-core.md` section 8, "Reproduced on
purpose".

## Proposed amendments to `decomp-plan.md`

The "What should change" column of the findings table above, findings 1
to 14. In short: split D07 in three (1, 2); D08 below core, needing D05,
D02, D03, D06 (3); the value-set solver before D10 (4); `switchnorm` to
D13 and `lanedivide` to R7 (5); D14 without D11 except naming (6, 7);
`transform.*` to R7 (8); `EmulateSnippet` and the `Emulate` base to D18,
`crc32` with `dynamic.*`, the unassigned modules listed (9); the
arrangement and group lists to D07b (10); sizes (11); `<function>` to
D07a (12); the two traits that let D09 precede D13 (13); the rule-subset
oracle's limits (14).

## Defects found in Ghidra (for `docs/GHIDRA-BUGS.md`)

Paths under `CPP/`. Confirmed = reproduced against the reference build.

1. **Crash**: `ActionGroup::printState` (`action.cc:444–454`)
   dereferences `state` when it is `list.end()`, which
   `ActionGroup::apply` leaves after an action breakpoint on a group
   fires behind its last member (517–519). Confirmed in Ghidra's own
   console: `condmulti.xml`, `break action mainloop`, `decompile`,
   `continue` six times, exit 139 (X3).
2. **Crash**: a root action with no member is a null pointer
   (`ActionGroup::clone`, `action.cc:391–406`;
   `ActionDatabase::toggleAction`, 1024–1041) that `list action`,
   `option warning`, `option nanignore` and `decompile` dereference.
   Confirmed: `option setaction firstpass`, `option currentaction
   firstpass base off`, `list action`, exit 139 (X2). `option
   togglerule` alone checks (`options.cc:911–913`).
3. **Host dependence**: numeric option parameters are read with
   `istream >>` and the base taken from the text (`options.cc` 223–225,
   476–479, 493–496, 511–514, 803–805, 865–868, 974–976). `12abc` is 12
   with libstdc++ and a failure (0) with libc++: 49 of 74,055 oracle rows
   differ between the two reference builds. Confirmed (X5).
4. **`option nanignore none` is undone by later options.** The setting
   is only a disabled-rule flag on the current root's instance
   (`options.cc:1080–1086`); `nan_ignore_compare` is read by no rule
   (`ruleaction.cc:9746` reads `nan_ignore_all` only). Any option that
   derives the root again (`splitdatatype`, `currentaction`) builds every
   rule enabled (`action.cc:1024–1041`, `Rule::clone`), and the
   `jumptable` root never gets the flag. Confirmed by listing (X2);
   output not compared. `option togglerule` is lost the same way.
5. **`ActionNormalizeSetup::reset` (`coreaction.hh:646`) does not call
   `Action::reset`**, so the action applies once per root instance, not
   once per function. Confirmed: three decompilations under the
   `normalize` root, `normalizesetup Tested=1` (X7). Six other overrides
   (`coreaction.hh` 77, 99, 133, 198, 872, 1003) skip the base too; with
   flags 0 only their "warning given" bit is affected (by reading).
6. `ActionDatabase::setCurrent` (`action.cc:1012–1013`) stores the new
   name before deriving the action; when the group list does not exist
   the name stays changed with the old action. Confirmed (X5: 16,000
   rows of the form `root=<name>` after `Action group does not exist`).
7. **Hang**: `Funcdata::decode` (`funcdata.cc:800–825`) has no branch
   for an unknown child of `<function>` and peeks it for ever; `encode`
   with the tree writes `<ast>` and `<highlist>`, which it cannot read
   back. Read; not run.
8. `ActionPool::processOp` (`action.cc:839–851`): a rule's action
   breakpoint returns before the check for a changed opcode, and on
   resumption the rule index is not reset, so a breakpoint changes which
   rules are tried. Read; the action oracle contains such rows, none was
   isolated.
9. `Action::perform` (`action.cc:305–313`): `count_tests` is incremented
   only on the path through `status_start`, so an action stopped at its
   own start breakpoint is not counted. Read; in the oracle's `E` rows.
10. Option numbers: text that is not a number reads as 0 (C++11), so the
    sentinels are unreachable: `option extrapop abc` sets extrapop 0,
    `baddatacount abc` and `maxinstruction abc` set 0, `maxlinewidth abc`
    reports the printer's `Bad maximum line size` instead of `Must
    specify integer linewidth`. Confirmed (X2).
11. `OptionBraceFormat`'s comment (`options.cc:588–597`) gives the
    parameters in the opposite order to the code (category first).
    Confirmed (X2).
12. `SegmentOp::isConcatenation` (`userop.cc:204`) shifts by
    `innerinsize * 8` bits, undefined for an inner size of 8. Read.
13. Correction of an existing entry: see Misfits, item 2.
14. Smaller: `Architecture::resetDefaults` leaves a model's extrapop,
    the default and evaluation models, function properties, the print
    language and `allowcontextset` changed (X5, `U` rows); the `jumptable`
    root is a separate instance, so its statistics are not in `print
    actionstats` of the current root (by reading).

## Open questions for the owner

1. Three crates and three tracks for D07 (ADR A), or one?
2. D08 needs its own specification pass (the outline exists). Who writes
   it, and before or after D07a starts?
3. Should the `ghidra` profile reproduce defects 4 and 5 (the spec says
   yes: option order is part of a script; the parallel driver's handling
   of `normalizesetup` is open)?

## What the implementation tracks should be told beyond the documents

- **D07**: start from the two prototypes (they build with `build.sh`);
  the action table is the definition of the framework, the option table
  of the options. Write the scripted units of the action oracle first.
  Specify each "to be specified" item from its lines in the status
  report before the step that needs it. The `arch` oracle (test A-2) is
  not prototyped.
- **D05**: the high events (Misfits 1).
- **R tracks, D19**: plan finding 14.
- **D09**: `startProcessing` takes flow as a callback; flow options are
  core's bits; without a `JumpTableRecovery` every `BRANCHIND` fails
  normally.

## Not done, plainly

D08's behaviour was not read or specified and has no oracle prototype.
Part C of D07 lists functions with lines and users but their bodies were
not read. The evaluator (ADR-025 3a) and `FlowFacts` are unspecified. No
`arch` oracle. X1 to X3 and X7 ran on the Mac only. The plan comparison
rests on a text scan except where a row says "read".

## Commits

`git log --oneline master..spec-decomp-wave3`.

## State at stop

- `decomp-core.md`: all nine sections, the implementation plan and open
  items are present. Complete and verified against the source: section 3
  (scope, ownership table), 4.A.1 to 4.A.5, 4.A.7 to 4.A.9, 4.A.12,
  4.A.13, and all of part B (4.B.1 to 4.B.9), with the runs X1 to X7.
  Drafts with "to be specified" marks and line ranges: 4.A.6, 4.A.10,
  4.A.11, 4.A.14 and all of part C (function lists, bodies unread).
  Nothing is missing as a section.
- `decomp-typeop.md`: started as an outline only. Boundary, dependencies
  and design are stated; the behaviour section is a list of what to read.
- Plan against the source: 14 findings in the table above (D07 is 16,000
  lines and splits in three; D08 sits below core; D10 needs the value-set
  solver; D12 needs D13 and R7 code; D14 does not need D11 for merging).
- Next agent, first: specify D08's section 4 from `typeop.cc`, `cast.cc`,
  `unionresolve.cc` and prototype its oracle table; then the "to be
  specified" items of `decomp-core.md` in the order of its steps.
