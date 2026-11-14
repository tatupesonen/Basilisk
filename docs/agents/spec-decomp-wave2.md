# Track `spec-decomp-wave2` — status report

Specification track for D06 (`decomp-symbols`, new document) and the
revision of D05 (`decomp-ir`) of `docs/features/decomp-plan.md`. Writes no
shipping code. **Done.**

## State

- [x] Rules, plan (with its amendments), ADRs, D00/D04 specs, the wave-1
      report and the existing crates' APIs read.
- [x] D06 source reading (`database.*`, `rangemap.hh`, `partmap.hh`,
      `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*.*`,
      `globalcontext.*`, `override.*`, the `ghidra_*` host classes, the
      filling code in `architecture.cc`, `sleigh_arch.cc`, `xml_arch.cc`,
      `funcdata.cc` 34–80, `varmap.*` for `ScopeLocal`).
- [x] Three oracle prototypes written and run on both reference builds
      (W2–W4).
- [x] `docs/features/decomp-symbols.md` (1,600 lines).
- [x] D05 source check (`varnode.*`, `op.*`, `cover.*`, `BlockBasic`,
      `funcdata_op.cc`, `funcdata_varnode.cc`, `funcdata_block.cc`
      classified) and `docs/features/decomp-ir.md` revised.
- [x] This report.

## What each document covers

**`docs/features/decomp-symbols.md` (D06, `bk-decomp-symbols`).** Scope
class by class and method by method, with what goes to D07 (`Funcdata`
creation, `<function>`, `updateType`), D11 (`ScopeLocal` and what D06
leaves open for it: function scopes, an extension slot, the calls it
needs, wrapper attributes, default names from varnode facts), D16b
(`CommentSorter`), D09/D07 (applying overrides), `bk-sleigh` (the context
store, ADR-026). Behaviour with file:line: flags and categories; the
entry map (`rangemap`) exactly — fragments, subsorts, C++ multiset
insertion order with hints (libc++ and libstdc++ agree), insert, unzip,
erase, zip, every look-up, the record-list placement rule; the property
map; entries and `Scope::addMap`'s six steps (the use-limit "kludge",
join pieces); symbols (ids, dedup, categories, kinds, depth cache);
every query and the `stack*` walks; scopes, hashed ids, resolution,
ownership and the resolve map; name building; mutations and what each
invalidates; multi-entry and use-point rules; every XML element;
comments; strings; constant pool; load images (`<binaryimage>`, the hex
digit rule, `pad()`, `loadFill`, raw images); context names and
`<context_points>`; overrides; what the architecture puts in and in which
order; the host trait (every Ghidra query, when it is asked, what is
cached); order sources; 18 defects. Design: crate and dependencies,
arenas and typed ids, `EntryMap` layout, ADR-011 evaluation of interval
crates, API sketch, the `ProgramHost` trait with the 3d methods and 3f
provenance, the cache layer, what it supplies to `bk-decomp-types` and
`bk-cspec`, errors, concurrency with per-function overlays and commit,
performance, plugin constraints. Tests: unit tests per behaviour table,
three oracle tables (scope 205,104 rows, context 85,713, image 8,435)
with their generators, the `print map` comparison, `@scope` loading, the
`DecompilerPspecVolatilityTest` property part, properties, seven fuzz
targets, benchmarks. Acceptance, differences, open items.

**`docs/features/decomp-ir.md` (D05, revised).** Corrections folded in,
every Ghidra statement re-checked, aligned with D00 (keys, sections, dump
points by path, no mutation log) and D04 (`Cfg`, `NodeId`,
`BlockFacts`); the environment-dependent steps of `Funcdata`'s mutation
methods moved behind a `FunctionEnv` trait; open items instead of "to
verify". Changes listed below.

## What was run, and where

`docs/research/decomp-wave2/runs.md` (W1–W6), scripts beside it.

- Mac (`../reference`, Apple clang 17, libc++): `print map`/`dump` on
  `elseif.xml` (W1); `image_oracle` on all 93 data tests (W2);
  `scope_oracle` seed 1, 2,000 cases (W3, with lldb on two crashes);
  `context_oracle` seed 1, 2,000 cases (W4); `bk list actions` (W5).
- Build host (`scripts/remote.sh run`, g++ 14.2, libstdc++): the same three
  oracles, each twice. Results: every table byte-identical between runs
  on each host and between the hosts (the image table after ordering by
  file, since the shells expand `*.xml` differently). The first scope and
  context runs differed only through bugs of the generators (random draws
  inside function arguments, evaluated in different orders by clang and
  g++; an uninitialised offset printed), fixed and re-run.
- Counts by `grep` (W6).
- No gate run: documentation-only branch.

## Statements of the old `decomp-ir.md` found wrong

1. 4.1/4.2: `iop`/`fspec` offsets as ids "tested against Ghidra's dumps"
   — Ghidra's bank order among them follows heap addresses; Basilisk
   orders by internal keys and writes D00's canonical keys (correction of
   2026-11-14, folded in, with the `fspec` re-sorting subtlety: D00's key
   is the `qlst` position at writing time).
2. 4.1: missing the rule that *any* free non-`spacebase` varnode may have
   at most one reader (`addDescend` throws, varnode.cc:330); 4.5 stated it
   for constants only.
3. 4.2: `def` order given only as "read the comparator" — now exact; `xref`
   deletes the duplicate and consumes its `create_index` (so `VarnodeId`
   cannot equal `create_index`, contrary to 4.8's "loading reproduces
   them" taken literally).
4. 4.3: "`alttree` … if nothing in this track's scope touches it, defer"
   — every `INDIRECT` the engine creates goes through `newIndirect` →
   `createIndirect` → `alttree`; `changeOpcode` moves ops out of it.
5. 4.3: "`BlockBasic::insert` … maintains `startbasic` on the first op" —
   it does not (flow sets it, `funcdata_block.cc` clears it); it sets
   `f_switch_out` for a `BRANCHIND`.
6. 4.3: the order scheme left to verify — now specified (block.cc:2276–2307,
   2700–2713).
7. 4.5: the varnode creation methods and `opSetOutput` were assigned to
   D05 whole, but they call `localmap->queryProperties` (D06),
   `assignHigh` (D14), `checkForLanedRegister`,
   `constructWrappingAddress`, `funcp.hasEffect` (D07/`bk-cspec`): not
   implementable in a crate below D06/D07 → `FunctionEnv`.
8. 4.5: `op_set_opcode` "re-derives the property flags (read for the
   mask)" — the mask is 14 named bits (op.cc:299); and it also moves an
   `INDIRECT` from `alttree` to `optree`.
9. 4.5: missing semantics of `opInsertBefore/After/Begin/End` (skipping
   `INDIRECT`s and `MULTIEQUAL`s), `opDestroyRecursive`, `cloneOp`,
   `newOpBefore`, `newIndirect`, `opMarkHalt`'s checks.
10. 4.5: `debugModCheck` "at twelve places in `funcdata_op.cc`" — right,
    but a thirteenth is in `destroyVarnode` (funcdata_varnode.cc:295).
11. 4.5: evaluation called `CAST` ordinary and listed `special` ops
    incompletely — `special` is on 15 opcodes, including `CAST`,
    `MULTIEQUAL`, `INDIRECT`, `BRANCH`, `CBRANCH`.
12. 4.6: "the 63 constructors in `typeop.cc`" — 73 opcodes, 74
    constructors.
13. 4.4: "`isComplex` and the last-op facts" — the structurer takes four
    facts (`complex`, `switch_out`, `ends_in_return`,
    `negation_changes_dataflow`).
14. 4.7/6 item 2: "`print tree varnode` … equal (`internal=` stripped)" —
    not achievable (plan amendment 4); replaced by the op texts in
    `@ops` and block-level `print raw`.
15. 4.9: "the universal action contains nine actions more than once" —
    seven names occur twice in the `decompile` root (ran, W5).
16. 6 item 1: "after `ActionStart`" (folded correction) — points found by
    path from `bk list actions`.
17. 6 item 4: mutation replay from a D00 call log — D00 delivered no log;
    the fallback is now the test.
18. 2: `mapentry: Option<SymbolEntryId>` — the entry belongs to D06's
    arena (`EntryId`), referenced opaquely here.

## Where the plan is wrong or cannot work as written

1. **D06 row, `globalcontext.*`**: ADR-026 puts the context store in
   `bk-sleigh`, which exists and ports `ContextInternal`; D06 adds the
   named-variable registry and the `<context_points>` codec over it, so
   `bk-decomp-symbols` depends on `bk-sleigh` — against plan 2's rule
   that only the top crates do (proposed ADR A).
2. **D06 acceptance, "`<binaryimage>` loading … with `print map`-equivalent
   output equal to the console's (G)"**: `print map` prints only the
   global scope's symbols (default symbols and loader functions), not the
   image; the console's `dump` aborts at the first unmapped byte. The
   evidence is the image table (chunks after pad, read-only ranges,
   properties, probes; G replay) plus `print map` itself (L).
3. **Plan 8, 3d, D06's acceptance** ("a test host that answers 'does not
   return' changes flow exactly as `override flow … callreturn`") needs
   flow following — it belongs to D09.
4. **Plan 3 item 7, per-function overlays**: Ghidra's console is
   sequential, and a decompilation adds global symbols (`DAT_…`) that the
   next one sees; overlays need a commit in operation order to reproduce
   L5 on data tests with several functions (proposed ADR B).
5. **D05 row, "the low-level halves of `funcdata_op.cc` and
   `funcdata_varnode.cc`"**: the halves call symbol, prototype and high
   state (item 7 above); D05 needs the hook trait (proposed ADR D).
6. **D05 evidence, "mutations recorded from Ghidra's trace"**: the trace
   records touched ops, not calls; D00 found a call log impractical.
7. **D06 "owns no C++ unit test; later owns `DecompilerPspecVolatilityTest`
   (M5)"**: the property part of that test is portable now (S); only the
   whole-decompilation part waits.

## What the state-dump format lacks

For **D06** (rebuilding a function scope exactly from `@scope`):

1. The scope's Ghidra id and its next symbol id. Proposed: two fields
   added to `@scope`'s `Z` record, `ghidra_id` (hex) and
   `next_unique_id` (hex).
2. The order of each space's entry map, which depends on insertion
   history and cannot be recomputed from the entries: the record list and
   the fragment multiset. Proposed: per space with entries, `R
   <space> <entry refs in record-list order>` and per fragment, in
   multiset order, `F <space> <first> <last> <entry ref>`, an entry ref
   being `s<symbol id>:<position in mapentry>`.
3. The dynamic entry list's order. Proposed: `Q <entry refs in list
   order>`.

For **D05**: nothing found missing (both op trees, all lists, the
counters, block op orders and ranges are present).

## Open items

From the two documents' last sections: the shared varnode/symbol flag
type; `bk_sleigh::context` as its own crate; the 3d flow comparison
moving to D09; state dump format 2 for `@scope`; the lazy instantiation
of function scopes (`queryFunction`) against D07's creation point; which
IR queries need `TypeOp` or a type factory; the latent `alttree`
mismatch; splitting `FunctionEnv`.

## Proposed ADRs (unnumbered)

**A. The decompiler's symbol crate uses `bk-sleigh`'s context store; the
store moves to its own crate.** `bk-decomp-symbols` adds names and XML to
`bk_sleigh::ContextDb` instead of porting `ContextInternal` again. To
keep the decompiler's lower crates free of translator code, the
`context` module of `bk-sleigh` (with its `partmap`) becomes a small crate
(`bk-context`) that `bk-sleigh` re-exports.

**B. Decompiler program state is frozen during a decompilation; each
function writes into an overlay committed in operation order.** Global
scope additions, host replies, string and constant-pool caches and
property changes made while decompiling one function go into its
overlay, with ids continuing from the frozen counters. The console and
the data-test runner commit after every function (Ghidra's sequential
behaviour); the parallel driver's commit policy is D17's and must be
deterministic.

**C. Where Ghidra's in-memory codecs are undefined or contradict
themselves, Basilisk defines them.** Hex content is read as the
signed-`char` x86-64 build reads it and always terminates;
`CPoolRecord` byte data is written as hex (what the decoder reads); a
default `<context_pointset>` sets all its variables; a symbol entry past
the end of its space is rejected before anything changes. Each is listed
under "Differences from Ghidra" (ADR-024's form).

**D. The IR crate delegates the environment steps of `Funcdata`'s
mutation methods through a trait.** `bk-decomp-ir` implements the
structural part of each method and calls `FunctionEnv` (default types,
symbol properties, high and laned-register registration, wrapping
addresses, prototype effects) at the points Ghidra does; D07's function
state implements it.

## Defects found in Ghidra (for `docs/GHIDRA-BUGS.md`)

Paths under `CPP/`. Confirmed = reproduced against the reference build.

1. **Crash**: `Scope::addMapSym` with `ScopeInternal::addMapInternal`
   (database.cc:2000, 2010–2015, 1727–1730): an entry running past the end
   of its space is appended to the symbol before the throw; the handler's
   `removeSymbol` erases it through an indeterminate iterator. Confirmed:
   SIGSEGV in `rangemap::erase` (lldb), W3. Basilisk checks first.
2. **Crash**: `FuncProto::encode` (fspec.cc:4569) on a prototype without
   a model, reached by `ScopeInternal::encode` of an instantiated function
   that never got a prototype. Confirmed: SIGSEGV, W3. For D07.
3. **Use after free**: `Scope::addUnassigned` (database.cc:1294–1297).
   Read.
4. `Symbol::getMapEntryPosition` (database.cc:395) tests the argument's
   size instead of each entry's: a piece gets position 0. Read; D00's
   dump writes this number. Basilisk reproduces.
5. **Null dereference**: `ScopeInternal::clearCategory`,
   `clearUnlockedCategory` (database.cc:2175, 2226) on empty category
   slots. Read.
6. `Symbol::getResolutionDepth` (database.cc:422–424): the cache is never
   invalidated by renames. Read; reproduced.
7. **Hang with unsigned `char`**: the hex loops of `LoadImageXml::open`
   (loadimage_xml.cc:115–135) and `StringManager::decode`
   (stringmanage.cc:246–266) stop only on a non-positive `char`; at the
   end of text `(char)EOF` is 255 where `char` is unsigned (Linux
   AArch64). Read; the hang itself was observed by the reference-tools
   track (PROGRESS 2026-11-12, the reason for `-fsigned-char`), now with
   its cause. No validation of hex digits either.
8. `CPoolRecord::encode` (cpool.cc:67) writes bytes as characters, not
   hex; Ghidra cannot read its own encoding. Read.
9. `ConstantPool::putRecord` (cpool.cc:160) leaves `flags`, `value`,
   `byteDataLen` uninitialised. Read.
10. `CheapSorter(refs)` (cpool.hh:182) reads `refs[0]` of a possibly empty
    list. Read.
11. `CPoolRecord::decode` (cpool.cc:141–145): fewer hex tokens than
    `length` leave bytes indeterminate. Read.
12. `ContextInternal::decodeContext` (globalcontext.cc:355–358) zeroes the
    whole default before every `<set>` of a default pointset. Read.
13. `ArchitectureGhidra::buildSymbols` (ghidra_arch.cc:405–429) resolves
    `next` from the last *volatile* symbol. Read.
14. `RawLoadImage::open` (loadimage.cc:60) opens the file in text mode
    (CR LF translation on Windows). Read.
15. `LoadImageXml::adjustVma` (loadimage_xml.cc:284) truncates the offset
    to `int4`. Read.
16. `Architecture::decodeFlowOverride` (architecture.cc:475–476) closes
    the element twice. Read.
17. `CommentDatabaseInternal::addComment` (comment.cc:182–193): past
    65,535 comments at one address the key exists, the comment is dropped
    and leaked. Read.
18. `StringManagerUnicode::getStringData` (stringmanage.cc:466–468) can
    read past a 32-byte chunk when `maximumChars` is not a multiple of the
    character size (unreachable with 2048). Read.
19. Latent: `PcodeOpBank::destroy` (op.cc:1052–1056) erases from the tree
    chosen by the op's *current* opcode, so an `INDIRECT` living in
    `optree` would leave a stale entry; no path creates one today. Read.

## What the implementation tracks should be told beyond their documents

- **D06**: start from the three prototypes in `docs/research/decomp-wave2/`
  (they build with `build.sh`); draw random numbers one per statement
  (argument evaluation order differs between clang and g++); never print
  an invalid `Address`'s offset; keep the generator's crash workarounds
  (hide an instantiated function's `Funcdata` when encoding; keep entries
  clear of the end of a space). `EntryMap` is the core: write it and its
  property test first. `bk-sleigh`'s `context::partmap` is private; the
  property map needs its own small one. The D02 `Spacebase` constructor
  D06 needs must be requested from the coordinator (D02's crate).
- **D05**: D00 and D04 are on `master` now; read `bk-testkit`'s
  `oracle::state` and `bk-decomp-cfg`'s `Cfg`/`BlockFacts` before
  designing; `FunctionEnv` is the boundary to D07 — implement a table
  version for tests; the dump's `create_index` is not your arena index.
- **D07** (later): `FuncProto::encode` crashes without a model (defect 2):
  guard it; create function scopes through D06's `create_function_scope`
  with the symbol's id.
- **D09** (later): the 3d flow comparison and the data tests' `map …`,
  `set context`, `set track`, `volatile`, `readonly`, `comment instr`
  commands run over D06's API; commit the overlay after every
  `decompile`.

## Commits

```
docs(decomp-ir): revision against the source, D00 and D04; corrections folded in
docs(spec-decomp-wave2): status after D06
docs(decomp-symbols): tests, acceptance, differences, open items
docs(decomp-symbols): design
docs(decomp-symbols): behaviour
docs(decomp-symbols): purpose, sources, scope
docs(spec-decomp-wave2): runs W1-W4 for D06
docs(spec-decomp-wave2): context oracle never prints an invalid address's offset
docs(spec-decomp-wave2): context oracle prototype
docs(spec-decomp-wave2): scope oracle sequences its random draws
docs(spec-decomp-wave2): scope oracle avoids wrapping addresses (Ghidra crash recorded)
docs(spec-decomp-wave2): scope oracle prototype, notes before pause
docs(spec-decomp-wave2): image and context oracle prototype
docs(spec-decomp-wave2): status report skeleton
```
(plus the final commit of this report; `git log --oneline master..HEAD`
lists them.)
