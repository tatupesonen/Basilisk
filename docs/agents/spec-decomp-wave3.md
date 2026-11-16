# Track `spec-decomp-wave3` — status report

Specification track for D07 (`decomp-core`, crate `bk-decomp-core`) and
D08 (`decomp-typeop`, crate `bk-decomp-typeop`) of
`docs/features/decomp-plan.md`. Writes no shipping code. **In progress.**

## State

- [x] Rules, direction, loop, ADRs (to ADR-048), plan with amendments 11
      and 12, the neighbouring specs (D00 to D06), the wave-2 report, the
      inventory read.
- [ ] D07 source reading (`action.*`, `options.*`, `funcdata*.*`,
      `architecture.*`, `expression.*`, `transform.*`, `FuncCallSpecs`,
      `userop.*`, `pcodeinject.*`, `dynamic.*`).
- [ ] D07 runs against the reference consoles.
- [ ] `docs/features/decomp-core.md`.
- [ ] D08 source reading (`typeop.*`, `cast.*`, `unionresolve.*`, the
      IR-bound methods of `type.cc`).
- [ ] D08 runs and oracle prototype.
- [ ] `docs/features/decomp-typeop.md`.
- [ ] This report, final form.

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

## Next

Continue the D07 source reading; the plan comparison below grows with it.
