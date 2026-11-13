# Decompiler port plan (milestone M3)

Not a feature spec: this is the plan that the decompiler's feature specs
hang from — the crate split, the tracks and their order, what gates each,
and how parity with Ghidra is measured while the port is incomplete. Facts
about Ghidra are in `docs/inventory/02-decompiler.md` ("the inventory");
section numbers below marked *inv.* refer to it. ADR-025 (profiles, and six
properties the port has from its first version) binds this plan; section 8
says which track builds each property and how its acceptance shows it.
Decisions here that need the coordinator's confirmation, and two places
where Ghidra's code does not fit ADR-025 as worded, are in section 9.

Path abbreviations: `CPP/`, `UT/`, `DT/`, `REF/` as in the inventory.

## 1. What is being ported

The decompiler engine is the Makefile's `DECCORE` group: 129,000 lines of
`.cc` and `.hh`, about 126,000 hand-written (inv. 1). Its implementation
files form one dependency cycle of 48 modules (inv. 4); the order of work
below comes from what each part calls, not from the include graph.

Three facts shape the plan:

1. **Three parts need nothing of the IR**: circle ranges, the type system,
   and the prototype models with the `.cspec` reader. A fourth, the block
   graph with control-flow structuring, needs only itself. Their Ghidra
   unit tests need no lifted p-code (inv. 7.1). They can start now.
2. **Everything else is a pipeline**, and a pass can only be compared with
   Ghidra if it starts from the state Ghidra's pass started from. Either
   every earlier pass is already exact, or Ghidra's state is *loaded*.
   Section 4 makes the second possible, which is what lets the middle of
   the pipeline be built in parallel.
3. **Lifted p-code is needed from the first pipeline step** (`ActionStart`
   lifts instructions), and the SLEIGH runtime does not exist yet. The
   engine therefore takes p-code through a small trait, and until
   `bk-sleigh` lands the tests feed it p-code recorded from Ghidra's own
   lifter (section 4.4). The pipe protocol already works this way (inv.
   9.2: the host lifts).

## 2. Crate split

ADR-013: a component that can be used or tested alone is its own crate;
ADR-015: tracks own disjoint crates. The split keeps **state** (data
structures) in low crates and **passes** (algorithms over the state) in
crates above them, so that passes can be written in parallel and so that a
change of IR representation is confined to two crates.

```
bk-decomp                    pipeline assembly in Ghidra's order, root actions, options,
  │                          public API (decompile → tokens + function result), parallel driver
  ├── bk-decomp-print        output tree → tokens: Emit, markup, pretty printer (stage 2)
  ├── bk-decomp-out          typed output tree, its builder (PrintC's decisions) and
  │                          output passes (stage 1; ADR-025 3c)
  ├── bk-decomp-merge        HighVariable construction, covers intersection, naming, casts
  ├── bk-decomp-jumptable    switch recovery, value-set solver
  ├── bk-decomp-struct       structuring actions that touch ops (for-loops, switches, conditions)
  ├── bk-decomp-actions      the actions of coreaction.cc and condexe
  ├── bk-decomp-rules-*      rule families, one crate per family (section 6, tracks R1–R9)
  ├── bk-decomp-heritage     SSA construction, prefer-split
  ├── bk-decomp-flow         control-flow following, call specs at lift time, inlining, injection
  │
  ├── bk-decomp-typeop       TypeOp per opcode, cast strategy, union resolution
  ├── bk-decomp-core         Funcdata (function state), Architecture (program state),
  │                          the action/rule framework and its trace
  ├── bk-decomp-symbols      Scope/Symbol/Database, comments, strings, constant pool,
  │                          load image, context, overrides; the host trait (ADR-004)
  ├── bk-decomp-ir           varnodes, ops, basic blocks, covers in arenas; state load/dump
  │
  ├── bk-decomp-cfg          block graph, dominators, loops, structuring (CollapseStructure)
  ├── bk-cspec               .cspec reader, prototype models, parameter assignment
  ├── bk-decomp-types        Datatype, TypeFactory, data organisation, C declaration parser
  └── bk-decomp-range        CircleRange
        (all on bk-core, bk-marshal, bk-pcode; bk-cspec and the top also on bk-lang;
         the top on bk-sleigh and bk-sleigh-snippet when they exist — ADR-023)
```

Notes on the split:

* `PLAN.md` names two crates (`bk-decomp`, `bk-decomp-print`). This plan
  replaces that with the tree above; `PLAN.md`'s crate map needs the
  update (section 9).
* **`bk-cspec` is not decompiler-specific.** The program model (M4) needs
  calling conventions and data organisation too, with its own richer type
  model, as Ghidra's Java side does (`PrototypeModel` and `ParamList*`
  exist in both languages and read the same file). So `bk-cspec` sees
  types only through a small query trait (size, alignment, metatype,
  fields, element type; "pointer to", "void", "unknown of size") and
  depends on neither type model. This also removes the dependency between
  the types track and the prototype track.
* **`Funcdata` is plain state in `bk-decomp-core`; passes are functions in
  other crates** taking `&mut Funcdata`. Ghidra's `Heritage`, `Merge` and
  `JumpTable` objects become state structs in core with their algorithms
  in `bk-decomp-heritage`, `-merge`, `-jumptable`.
* **The pipeline re-enters itself**: jump-table recovery runs the
  `jumptable` root action on a partial clone of the function, from inside
  flow following (inv. 5.1). Lower crates receive the pipeline as a trait
  object (`&dyn ActionRunner`), implemented in `bk-decomp`.
* **Rule families are separate crates** so that several agents can port
  rules at once without sharing files. Each exports its rules as values
  (name, group, opcode list, apply function); `bk-decomp` places them in
  Ghidra's order by name and fails to build its table if a name is
  missing or duplicated.
* `ruleaction.cc` (11,020 lines) becomes six crates of 6–40 one-rule
  modules each; no Rust file approaches the size limit.

## 3. Design constraints shared by all tracks

These hold across specs so that tracks written apart fit together. They
include what ADR-025 requires of the port from its first version.

1. **Arenas and typed indices** (ADR-012): `VarnodeId`, `OpId`, `BlockId`,
   `TypeId`, `SymbolId`, `HighId`, `CallSpecId` are `u32` newtypes. No
   `Rc<RefCell<…>>`, no `unsafe` (ADR-020).
2. **The IR's representation is private to `bk-decomp-ir`.** Passes use an
   API that mirrors `Funcdata`'s mutation methods (inv. 3.4) and read
   through accessor methods and iterators; no pass touches arena storage,
   and hot fields may move between array-of-structs and struct-of-arrays
   without touching passes.
3. **Ghidra's orderings are part of the behaviour**, because rule
   application order depends on them: ops are visited in `SeqNum` order,
   varnodes are kept in the two orders of `VarnodeBank`, readers of a
   varnode in insertion order, creation indices count up in Ghidra's
   order (inv. 3.2, 3.3, 5.1). These are specified, tested against
   Ghidra's dumps, and not "an implementation detail".
4. **Mutation during iteration is expressed with cursors, not borrowed
   iterators.** A walk holds a key (a `SeqNum`, an index) and asks the
   container for the successor after each step, so the body may insert
   and destroy freely. Destroyed ops and varnodes keep their slot until
   the function is cleared (Ghidra's `deadandgone`), so a stale id never
   aliases a new object; debug builds check liveness on access.
5. **Units and profiles** (ADR-025 items 1 and 2). Every rule, action,
   merge pass, structuring step and output pass is a *unit*: a value with
   Ghidra's name, an origin (`ghidra` or `basilisk`), a base group and,
   for rules, an opcode list. Units are registered in one table; a
   *profile* names the units and their arrangement, and the pipeline is
   built from the table by a profile. The `ghidra` profile is
   `universalAction` exactly (inv. 5.2) and is the target of every
   differential test in this plan; Ghidra's units are never edited to
   improve them. Ghidra's *root actions* (`decompile`, `jumptable`,
   `normalize`, `paramid`, `register`, `firstpass`; inv. 5.1) are group
   filters applied to a profile's pipeline, so the two are independent.
   Every decompiler test names its profile; snapshots are per profile.
6. **Provenance is never dropped.** An op keeps the address and sequence
   number of the instruction it came from through every transformation;
   output-tree nodes and tokens carry the `OpId`/`VarnodeId`/`HighId`/
   `TypeId` they print (as Ghidra's markup does, inv. 3.9); names and
   types carry where they came from (ADR-025 3f: user, debug information,
   import, library signature, analysis, model). The optional record of
   unit applications (ADR-025 3a) links an op to the unit that produced
   it.
7. **Per-function work is independent and deterministic.** Program-wide
   state (`Architecture`: spaces, models, base types, symbols) is
   immutable and `Send + Sync` during decompilation; whatever a function
   creates (types, join records, symbols, scopes) goes into a
   per-function overlay with its own id range (the `bk-core` report's
   note on join offsets). Results do not depend on scheduling.
8. **No host dependence** (ADR-021, ADR-022): the cases of inv. 10 are
   resolved as that table says; nothing iterates a hash map where order
   can reach output; no behaviour differs between Windows, macOS and
   Linux.
9. **Typed errors, no panics** (ADR-009). Ghidra throws `LowlevelError` in
   about a thousand places; each becomes an error value with Ghidra's
   message where a test or a user sees it. A function that fails to
   decompile yields an error result and leaves the program state intact.
10. **The host is a trait** (ADR-004): the queries of inv. 9.2, minus
    those the engine can answer itself once `bk-sleigh` exists, **plus**
    what ADR-025 3d and 3f add: function summaries of callees, "does the
    call at this site return", and provenance on every name and type that
    crosses it, in both directions. In-memory implementations (for data
    tests) live in `bk-decomp-symbols`.

## 4. How parity is measured

"The output matches" is checked last and says least about *where* a
difference arose. The port is measured at six levels; a track's acceptance
names the levels it must pass.

| Level | Compared with Ghidra | Tool | Catches |
|---|---|---|---|
| L0 | Unit behaviour: Ghidra's C++ unit tests, ported | `cargo test` | A wrong component |
| L1 | **Oracle tables**: a C++ program linked against the reference objects evaluates the component on many inputs; the table is checked in and replayed | `cargo test` (replay); regeneration needs `REF/` | Behaviour no unit test pins — the method that found the `INT_SEXT` difference in `bk-pcode` |
| L2 | **State after a pass**, starting from Ghidra's state before it | state dumps (4.2) | A wrong pass, in isolation |
| L3 | **The trace**: every rule and action application in order, with the ops it changed | debug console (4.1) | The first wrong rule application, by name |
| L4 | Data tests: Ghidra's 760 pattern checks in 93 files | data-test runner | Regressions in what Ghidra's authors chose to pin |
| L5 | **Whole output**: `print C` text of every function of a corpus, equal to the reference console's | captured output | Everything else, including printing |

### 4.1 What the reference console gives (all verified by running it)

* `list action`, `break start|action <name>`, `continue`, `print raw`,
  `print tree varnode`, `print tree block`, `print actionstats` work in
  the optimised console `REF/bin/decomp` (inv. 8).
* A console built with `CPUI_DEBUG` adds the **trace**: one numbered
  record per rule or action application that modified an op, with each
  modified op before and after (inv. 8). `REF/` does not contain this
  build yet.
* `option togglerule <rule> off` disables one rule and `option
  currentaction <root> <group> off` a group, in the reference console.
  **So Ghidra can be run with exactly the rules basilisk has ported so
  far**, and compared at L2, L3 and L5 in that configuration. A rule
  family is accepted against Ghidra-with-only-those-rules, not against
  hand-written expectations and not only when the whole pipeline exists.

### 4.2 State dumps and state loading (the oracle track, `D00`)

The console's own dumps omit most flags and all side state, and Ghidra
cannot reload a function's syntax tree. To compare and to *inject* state,
the project adds one C++ file to the reference build:

* `tools/reference/consoleext_bk.cc`, copied into the build's source copy
  (the Makefile compiles every `.cc` there into the console) and compiled
  with `-fno-access-control` so it can read private members without
  patching Ghidra. It registers console commands (as `ifacedecomp.cc`'s
  `IfaceDecompCapability` does), chiefly `bk dump state <file>`: the
  **complete** state of the current function in a line-oriented text
  format defined by basilisk — every varnode (creation index, address,
  size, both flag words, defining op, readers in order, type reference,
  `consumed`, `nzm`, symbol entry, merge group), every op (sequence
  number, order, opcode, both flag words, inputs, output, parent block),
  blocks and edges with labels, the function's flags and watermarks, call
  specs with their trials, jump tables, the local scope's symbols, the
  heritage state per address space, and the types referred to. Host
  pointers never appear; objects are named by creation index or sequence
  number.
* The debug console (`decomp_dbg`) is built into `REF/bin` next to the
  optimised one, with this extension, so that break points, the trace and
  state dumps can be combined: dump before a pass, `continue`, dump after.

`bk-decomp-ir` (and, for their parts, `-symbols` and `-core`) load this
format into their own structures and write it back. Three uses:

1. **Round trip** — load Ghidra's dump, dump it again, compare bytes. This
   proves the Rust state can represent everything Ghidra's has, with the
   same orders. It is the acceptance test of the IR track and needs no
   pass to exist.
2. **Pass isolation (L2)** — load the dump taken before pass P, run
   basilisk's P, compare with the dump taken after Ghidra's P. Heritage,
   each action, each rule pool run and the merge sequence can each be
   developed and accepted this way, in any order.
3. **Divergence reports** — when a full run differs, the two dumps at the
   last agreeing break point are the bug report.

The dump format is basilisk's, versioned, and documented in
`tools/reference/README.md`; captured dumps are gzip-compressed fixtures.
Because the format describes Ghidra's state, not basilisk's layout, it
does not constrain the IR design (section 8).

### 4.3 Corpus

* **Data tests**: 93 files, about 190 decompiled functions.
* **Rule coverage of that corpus is uneven** (measured with `print
  actionstats` summed over all 93 files): 32,788 rule applications, of
  which `earlyremoval` (12,757) and `propagatecopy` (7,846) are 63 %;
  124 of 161 rules apply at least once; **37 never apply and 54 more
  apply in at most two files** (table in section 10). The data tests
  alone cannot accept those rules.
* **The research corpus** (`docs/research/decompiler-quality/`: 74
  fragments in the data tests' `<binaryimage>` form with their console
  scripts and the reference output, 0.5 MB) is the second corpus and the
  one ADR-025's scorecard starts from. Measured the same way, it makes
  five of those 37 rules apply (`rightshiftand`, `highorderand`,
  `andcommute`, `bxor2notequal`, `subright`); **32 rules apply in neither
  corpus**.
* **Extended corpus** (track `D19`): further fragments in the same form,
  built the research corpus's way (`tools/run.py`, `elf2frag.py`), chosen
  so that every rule applies at least 20 times in the reference console.
  Selection is by `print actionstats`, mechanical. Rules that no compiled
  code can be found for (`segment` needs a segmented address space,
  `transformcpool` a constant pool) are listed with the reason.
* Corpus results are **captured** (trace, dumps at chosen break points,
  `print C`) into checked-in compressed fixtures where they are small, and
  regenerated on demand where they are large (the fixture then holds
  hashes and the first lines, and the test needs `REF/`).

### 4.4 P-code before the SLEIGH runtime exists

The engine takes instructions through a trait (working name
`PcodeSource`: lift one instruction at an address into a p-code sink,
report its length and fall-through; register and user-op names; float
formats — the eleven `Translate` methods the engine calls, inv. 3.1).
Implementations: `bk-sleigh` when it lands; before that, **recorded
p-code**. A recording is made inside the reference console by a proxy
`Translate` (in `consoleext_bk.cc`) that forwards to Ghidra's SLEIGH
engine and logs every `oneInstruction` call the decompiler makes — so
context changes, delay slots and inlined callees are exactly what Ghidra
saw — and is replayed by a `RecordedPcode` source in `bk-testkit`. The
recording for the data tests is a checked-in fixture; when `bk-sleigh`
arrives, the same recordings become one of *its* differential tests.

### 4.5 Where checks can run (ADR-022)

Every acceptance check is one of three kinds, stated per track in section
6:

* **S — self-contained.** Runs on Windows, macOS and Linux with nothing
  but the repository: ported unit tests whose inputs are built in test
  code, and replays of checked-in oracle tables, dumps, traces and
  recordings.
* **G — needs the spec root** (`BASILISK_GHIDRA_DIR`): reads Ghidra's
  `.cspec`, `.pspec`, `.ldefs`, `.sla` or data-test files, which are not
  copied into the repository (ADR-002). Platform-independent; skips with a
  printed reason when the tree is absent.
* **L — needs the live reference tools** (`REF/`, Unix-built): regenerates
  captures and runs comparisons too large to check in. Skips elsewhere.

A track's acceptance must not rest on L alone: whatever proves it right is
captured and replayed (S, or G when the input is a Ghidra spec file).

### 4.6 Gate and nightly (ADR-025 item 4)

The split of `docs/research/decompiler-quality.md` 5.3 applies to every
track's tests: the **gate** runs only kind S and G checks — replays of
checked-in tables, dumps, traces and recordings, `insta` snapshots of the
`ghidra` profile's output against the checked-in reference output, and the
bounded stage-equivalence check (lifted p-code against the final IR on a
fixed seed and a per-function budget) once D07 exists; **nightly** runs
kind L: regeneration of every capture from the reference tools with a
drift report, the unbounded comparisons, the compiler matrix. Scorecard:
`docs/QUALITY.md`, three columns (Ghidra reference, `ghidra` profile,
default profile).

A detail of the console that script replay must reproduce (found by the
research, by running it): `load function` follows flow immediately, so a
flow override given after it takes effect only on a second `decompile`.
The data-test runner (D09) executes commands in the script's order with
the same side effects, and does not "tidy" a script.

### 4.7 Reporting

`docs/PARITY.md` gets a decompiler table maintained from test output, per
corpus function: trace prefix agreed / trace length, break points whose
dumps agree, data-test checks passed, output equal. M3 is done when all
760 data-test checks pass (the two `-NAN` checks as ADR-021 says), L5
holds on the data-test corpus, and L3 holds on the extended corpus except
for documented differences.

## 5. Tracks

Size is hand-written C++ lines of the Ghidra code the track ports (`.cc` +
`.hh`, measured; inv. 2), as a guide to effort: **S** under 3,000, **M**
3,000–7,000, **L** 7,000–10,000. Tracks above L are split. The last
column names the ADR-025 properties the track must build in (3a–3f; "units"
= items 1 and 2); section 8 says how each is shown. **Leaf** tracks need
no other decompiler crate.

| Id | Track | Crates owned | Ghidra code | Size | Needs merged | ADR-025 |
|---|---|---|---|---|---|---|
| D00 | `decomp-oracle` | `tools/reference/consoleext_bk.cc`, additions to `scripts/build-reference.sh` and `bk-testkit` (`decomp_dbg` wrapper, dump/trace/recording parsers) | — (tooling, C++ and Rust) | S | — (leaf) | — |
| D01 | `decomp-range` | `bk-decomp-range` | `rangeutil.cc` 21–1,490 | S (1,500) | — (leaf) | — |
| D02 | `decomp-types` | `bk-decomp-types` | `type.*` minus IR-bound methods, `metatype.*`, the C parser of `grammar.y` | L (7,500) | — (leaf) | 3e (inferred category), 3f (type provenance) |
| D03 | `decomp-cspec` | `bk-cspec` | `fspec.*` minus `FuncCallSpecs` and symbol-backed stores, `modelrules.*`, the `.cspec` decoding of `architecture.cc`, payload/user-op declarations of `pcodeinject`/`userop` | L (8,500) | — (leaf) | 3d (the `FunctionSummary` type), 3f (prototype provenance) |
| D04 | `decomp-cfg` | `bk-decomp-cfg` | `block.*` (graph, the structured kinds), `blockaction.cc` (`CollapseStructure`, `LoopBody`, `TraceDAG`, `FloatingEdge`) | M (6,500) | — (leaf) | 3b; units (goto selection as a replaceable step) |
| D05 | `decomp-ir` | `bk-decomp-ir` | `varnode.*`, `op.*`, `cover.*`, `BlockBasic`, the low-level halves of `funcdata_op.cc` and `funcdata_varnode.cc`, dumps and state load | L (8,000) | D00, D02, D04 | **3a**; the unit table's data model |
| D06 | `decomp-symbols` | `bk-decomp-symbols` | `database.*`, `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage.*`, `loadimage_xml.*`, `globalcontext.*`, `override.*`, `partmap`/`rangemap` | L (9,000) | D02, D03 | **3d** (summaries through the program trait, call-site "returns?"), **3f** |
| D07 | `decomp-core` | `bk-decomp-core` | `funcdata.cc` and the rest of the `funcdata_*` files, `architecture.*` (assembly, not decoding), `options.*`, `action.*` (framework, trace, statistics), `expression.*`, `transform.*`, `FuncCallSpecs`, `userop.*`, `pcodeinject.*` (run time), `dynamic.*` | L (10,000) | D03, D05, D06 | **units and profiles**; 3a (recorder attached; evaluator); 3e (the access table's type) |
| D08 | `decomp-typeop` | `bk-decomp-typeop` | `typeop.*`, `cast.*`, `unionresolve.*`, the IR-bound methods of `type.cc` | M (7,000) | D05 | units (propagation policy per opcode is a unit); 3e (fills the access table at pointer ops) |
| D09 | `decomp-flow` | `bk-decomp-flow`, the data-test runner crate `bk-decomp-datatest` | `flow.*`, flow methods of `Funcdata`, `xml_arch`, `testfunction`, the console commands data tests use | M (5,000) | D07 | 3d (asks the trait whether a call returns, with the call site) |
| D10 | `decomp-heritage` | `bk-decomp-heritage` | `heritage.*`, `prefersplit.*` | M (4,000) | D07 | 3a (each pass ends evaluable) |
| D11 | `decomp-actions-a` | `bk-decomp-actions` (first half) | `coreaction.cc`: set-up and main-loop actions up to `restructure_varnode`, dead code, non-zero mask, `varmap.*` | L (8,000) | D07, D08 | units; 3e (`ActionInferTypes` fills the access table) |
| D12 | `decomp-actions-b` | `bk-decomp-actions` (second half; started after D11 merges) | The stack-stall actions, branch and block clean-up, `condexe.*`, conditional constants, likely trash, switch normalisation, return split, prototype fixation | M (6,000) | D11 | units |
| R1 | `rules-basic` | `bk-decomp-rules-basic` | Families "dead code and copy propagation", "canonical form of arithmetic" (inv. 6.1): 21 rules | S | D07, D08 | units |
| R2 | `rules-bits` | `bk-decomp-rules-bits` | "Bit masks and logical ops", "shifts": 26 rules | S | D07, D08 | units |
| R3 | `rules-compare` | `bk-decomp-rules-compare` | "Comparisons and booleans": 31 rules | M | D07, D08 | units |
| R4 | `rules-piece` | `bk-decomp-rules-piece` | "Pieces", "cleanup" (without `dumptyhumplate`, which is in `subflow.cc`): 27 rules | M | D07, D08 | units |
| R5 | `rules-divide` | `bk-decomp-rules-divide` | "Division and modulus recovery", "floating point" (without `subfloat_convert`): 18 rules | S | D07, D08 | units |
| R6 | `rules-pointer` | `bk-decomp-rules-pointer` | "Pointers and data types", "control flow" (without `orpredicate`): 13 rules | M | D07, D08, D06 | units |
| R7 | `rules-subflow` | `bk-decomp-rules-subflow` | `subflow.*`: 12 rules, `SubvariableFlow`, `SplitFlow`, `SplitDatatype`, `SubfloatFlow`, `LaneDivide` | M (4,600) | D07, D08 | units |
| R8 | `rules-double` | `bk-decomp-rules-double` | `double.*`: 4 rules | M (4,000) | D07, D08 | units |
| R9 | `rules-bitfield` | `bk-decomp-rules-bitfield` | `bitfield.*`, `constseq.*`: 8 rules | M (3,900) | D07, D08 | units |
| D13 | `decomp-jumptable` | `bk-decomp-jumptable` | `jumptable.*`, `emulateutil.*`, the value-set half of `rangeutil.cc`, jump-table methods of `Funcdata` | L (7,500) | D01, D09, D10 | 3a (shares the evaluator) |
| D14 | `decomp-merge` | `bk-decomp-merge` | `merge.*`, `variable.*`, the merge, marking and naming actions | M (6,000) | D11 | units (each merge pass); a high variable records the passes that formed it |
| D15 | `decomp-struct` | `bk-decomp-struct` | `blockaction.cc` actions, the op-touching methods of the structured blocks (`BlockWhileDo` for-loops, `BlockSwitch`, condition negation) | S | D04, D07 | 3b (applies the structurer's result to the IR), units |
| D16a | `decomp-out-spike` | none (a report and a throw-away prototype) | `printc.*`, `printlanguage.*` read against the 93 data tests | S | D00 | **3c's condition** |
| D16b | `decomp-out` | `bk-decomp-out` | `printlanguage.*` (the reverse-Polish machinery as a tree builder), `printc.*` and `printjava.*` (what is pushed and when), `CommentSorter`, `ActionSetCasts` | L (7,500) | D14, D15, D16a | **3c**; units (output passes) |
| D16c | `decomp-print` | `bk-decomp-print` | `prettyprint.*`, the `Emit` family, markup encoding | S (2,500) | D16a | 3c (stage 2), 3f (a token can show the provenance of its name or type) |
| D17 | `decomp-driver` | `bk-decomp`, `basilisk decompile` | `universalAction`, `buildDefaultGroups`, `paramid.*`, the result encoding (`Funcdata::encode`), parallel driver, benchmarks | M | all | **profiles** (`ghidra`, `basilisk`), **3d** (summary as an output), item 4 (scorecard, gate) |
| D18 | `decomp-inject` | `bk-decomp-inject` | `inject_sleigh.*` on top of `bk-sleigh-snippet` | S | `bk-sleigh-snippet` | — |
| D19 | `decomp-corpus` | `bk-decomp-corpus` (dev-only) | — (corpus runner, extended corpus, counters, stage-equivalence harness, parity and quality tables) | M | D00; grows with D07, D09 | item 4 |

Not in M3: `signature.*` (BSim, M10), `callgraph.*`, `raw_arch.*` (with
the CLI and loaders), `codedata`, `rulecompile`/`unify` (never built).

### 5.1 Waves

A wave's tracks do not depend on each other's unmerged code (ADR-015). The
project runs about four agents at once in total, so a wave here is an
*ordering*, not a head count: its tracks can be taken in any order or
together as slots allow.

| Wave | Tracks | Why here |
|---|---|---|
| **1 — now** | D01, D02, D03, D00, D04 | Leaf tracks: no IR, no lifter. D00 is tooling that every later track's acceptance uses |
| 2 | D05, D06, D16a | D05 needs D00, D02, D04; D06 needs D02, D03; the spike needs only D00's final-state dumps and decides how D16b is built |
| 3 | D07, D08, D16c | The function and program state, the unit table and profiles, op typing. D08 may run with D07 because it needs only D05; D16c needs only the tree format the spike fixed |
| 4 | D09, D10, D11, R1–R9, D19 | With state loading (4.2) these do not wait for each other: each is accepted from Ghidra's state before its pass. Rule tracks are taken in the order R1, R4, R6, R3, R2, R7, R5, R8, R9 (by how often their rules apply in the corpora, section 10) |
| 5 | D12, D13, D14 | Need D11's or D09/D10's merged code |
| 6 | D15, D16b | Structuring with the IR; the output tree |
| 7 | D17, then D18 when `bk-sleigh-snippet` exists | Assembly, whole-output parity, the scorecard, performance |

The critical path is D02 → D05 → D07 → D11 → D14 → D16b → D17: seven
tracks. Without state loading it would be every track in pipeline order.

### 5.2 What can start now

**D01, D02, D03, D00 and D04**, today, in any combination. They port
self-contained Ghidra behaviour whose representation is private to their
crate; ADR-025 asks of them only additive things (a provenance field, an
inferred-type category, a summary type, a pure structurer), which their
specs include. Specs: `features/decomp-range.md`,
`features/decomp-types.md`, `features/decomp-cspec.md`; D00 and D04 are
specified in sections 4.2 and 6 to the level needed to brief an agent and
get their own feature documents when started.

**D05** no longer waits for a design decision — the research is done and
ADR-025 settles what the IR must offer — but it needs D00, D02 and D04
merged. Its spec is `features/decomp-ir.md`.

## 6. Acceptance per track

For each track: the Ghidra tests it owns (ids as in
`docs/inventory/tests/`), and the evidence, with its kind (S/G/L, section
4.5). "Table" = an L1 oracle table produced by a C++ program kept under
the crate's `tests/oracle/` with a `regen.sh`, as `bk-pcode` does.

**D00 `decomp-oracle`.** No Ghidra tests. Accepted when: (1)
`scripts/build-reference.sh` also produces `REF/bin/decomp_dbg` with the
extension, on macOS and in the Linux container, incrementally, and the
stamp records it; (2) `bk dump state` after `decompile` on every data
test's functions produces a dump that a checker script confirms is
complete — every varnode and op reachable from the console's own `print
raw` and `print tree varnode` output appears with the same sequence
numbers and creation indices (L); (3) the proxy translator's recording
replays inside the reference console to the same `print raw` after
`ActionStart` (L); (4) `bk-testkit` parses dumps, traces
(`DEBUG n: name` records) and recordings into typed structures, with unit
tests on checked-in samples (S); (5) the dump format is documented and
versioned. It must also add an x86-64 Linux container target, so that
ADR-021's reference host finally exists.

**D01 `decomp-range`.** Owns `unittests/testcirclerange.cc` (117). Evidence:
the 117 tests ported with `bk-pcode`'s behaviours in place of
`glb->inst[]` (S); a table of every `CircleRange` operation over
exhaustive 1-byte domains and sampled wider ones, evaluated by Ghidra's
compiled class (S replay, L regeneration). Details in its spec.

**D02 `decomp-types`.** Owns `type_ordering`, `enum_matching`,
`enum_matching2` of `unittests/testtypes.cc`; the other five move to D08.
Evidence: those three ported (S); tables from Ghidra's compiled
`TypeFactory` — pairwise `compare` and `compareDependency` over a few
hundred types, layout (size, alignment, field offsets, bitfields) of
parsed declarations under several data organisations, `getMatches` for
enumerations, `hashName`, encode output (S replay); data organisation of
all 107 `.cspec` files (G). Details in its spec.

**D03 `decomp-cspec`.** Owns `unittests/testfuncproto.cc` (21),
`unittests/testparamstore.cc` (5) and the nine Java classes
`ghidra.program.model.lang.{X64,X64Win,X64Go,AArch64,Mips,PowerPC,Sparc32,Sparc64}…ProtoModelTest`
and `VarargsStorageTest` (13 tests, `test-integrationtest.md`). Evidence:
`testfuncproto` ported against a Toy-like architecture built in test code
(S); `testparamstore` and the Java tables against the real `.cspec` files
(G); all 107 files decode, with a table of what Ghidra's reader made of
each — models, their entries and rules, effects, ranges — dumped by an
oracle program (G replay, L regeneration); storage assignment for a fixed
set of signatures under every model of every file, from Ghidra (G replay).
Details in its spec.

**D04 `decomp-cfg`.** Owns no unit test (Ghidra has none for blocks).
Evidence: a table from `BlockGraph` in Ghidra's compiled code over
generated graphs (several thousand: random, reducible and irreducible,
with self-loops and multiple edges, up to 64 nodes; plus the control-flow
graphs of every data-test function, exported with `bk dump state`):
dominators, reverse post-order indices, spanning-tree edge labels,
irreducible edges, loop bodies (S replay); **the structured result** of
each graph from the console command `structure blocks`, i.e. the full
block hierarchy (S replay, L regeneration); property tests (every node
appears once in the hierarchy; edges preserved; structuring a copy
leaves the input untouched and gives an equal result — ADR-025 3b). What
Ghidra's rules read from or do to basic blocks (statement complexity,
last-op kind; condition negation) enters as per-block input facts and
leaves as a list of condition flips in the result (section 9.1); with
neutral facts this is exactly how `structure blocks` runs on a bare
graph. The result carries a measure (gotos, depth).

**D05 `decomp-ir`.** Owns no unit test alone. Evidence: **round trip** of
Ghidra's state dumps for every data-test function at four break points
(after `ActionStart`, after the first heritage pass, at the start of the
cleanup pool, at the end) — load, dump, byte-equal (S replay of a
checked-in subset, L for all); `print raw` and `print tree varnode` text
generated from loaded state equal to the console's (S); every mutation
method checked by loading a dump, applying a scripted sequence of
mutations recorded from Ghidra's trace, and comparing with the next dump
(S); invariants as property tests; benchmarks. Draft spec:
`features/decomp-ir.md`.

**D06 `decomp-symbols`.** Owns no C++ unit test; later owns
`DecompilerPspecVolatilityTest` and `DecompilerSpecExtensionTest` behaviour
(M5). Evidence: scope queries (`queryByAddr`, `queryContainer`,
`queryFunction`, name resolution, use-point restrictions, conflicting
entries) against a table from Ghidra's `ScopeInternal` over generated
symbol sets (S replay); `<binaryimage>` loading of all 93 data tests with
`print map`-equivalent output equal to the console's (G); context and
tracked-register lookups against a table from `ContextInternal` (S).

**D07 `decomp-core`.** Evidence: state dumps including function flags,
call specs and options round-trip (S); the action framework reproduces
Ghidra's control flow — a table of `perform` results for synthetic action
trees with scripted change counts, break points and restarts, from
Ghidra's `Action` classes (S replay); `list action` output for all six
root actions equal to the console's (S); every option of
`OptionDatabase` sets what Ghidra sets (table of resulting configuration,
S).

**D08 `decomp-typeop`.** Owns `cast_basic`, `cast_pointer`, `cast_enum`,
`cast_compare`, `cast_integertoken` of `testtypes.cc`. Evidence: those
five ported (S); a table of `getInputCast`/`getOutputToken`/
`getInputLocal`/`propagateType` for every opcode over a grid of operand
types, from Ghidra (S replay).

**D09 `decomp-flow`.** Evidence: for every function of every data test,
state after `ActionStart` equal to Ghidra's dump, from recorded p-code (S
for a subset, G+L for all); bad-data, unimplemented-instruction,
too-many-instructions, inline and override cases from the data tests that
exercise them (`inline.xml`, `inlinetarget.xml`, `overridedest.xml`,
`skipnext2.xml`, `injectoverride.xml`). The data-test runner executes
scripts up to the commands implemented so far and reports the rest as
"not yet", never as passed.

**D10 `decomp-heritage`.** Evidence (L2): from Ghidra's dump before each
heritage pass, the dump after it, for every pass of every data-test
function (S subset, L all).

**D11, D12 `decomp-actions`.** Evidence (L2), per action: from Ghidra's
dump at `break start <action>`, the state at the next break point equal
to Ghidra's, for every occurrence in the corpus; plus the trace records
of that action (L3).

**R1–R9 (rule families).** Evidence, per family: (L2+L3) with the
reference console configured to enable only the base set (R1) plus the
family's rules — every other rule switched off with `option togglerule` —
load Ghidra's state at each start of each rule pool, run basilisk's pool
with the same rules, and require the same trace records in the same order
and the same state at the pool's end, over the data-test corpus and the
extended corpus (S subset, L all); every rule of the family applies at
least 20 times in the accepted runs, or the gap is listed; no rule is
accepted on hand-written expectations alone. R1 is accepted with only its
own rules enabled.

**D13 `decomp-jumptable`.** Owns no unit test. Evidence: the switch data
tests (`switchhide`, `switchind`, `switchloop`, `switchmask`,
`switchmulti`, `switchreturn`, `ifswitch`, `stackreturn`); recovered
tables (addresses, labels, default) equal to Ghidra's dump for every
`BRANCHIND` in both corpora; value-set results against `analyze range`
(L).

**D14 `decomp-merge`.** Evidence (L2): dumps across the merge sequence
(`assignhigh` … `copymarker`), including high-variable membership and
names, equal to Ghidra's.

**D15 `decomp-struct`.** Evidence: from Ghidra's dump before each
structuring action, the state after it and `print tree block` equal to
Ghidra's (S subset, L all); the flips and goto edges D04 returned are
applied and the resulting op flags equal Ghidra's.

**D16a `decomp-out-spike`.** A report answering ADR-025 3c with evidence
from all 93 data tests (section 8.1); no crate.

**D16b `decomp-out`, D16c `decomp-print`.** Evidence: from Ghidra's final
state dump (so output is accepted independently of the pipeline), the
tree built by D16b printed by D16c equals `print C` and `print C xml` of
the console token for token, for every function of both corpora (S
subset as `insta` snapshots, L all); D16c alone: printing the trees
logged from the reference console by D16a's instrumentation gives the
console's text; the pretty printer against a table of token streams and
line widths from Ghidra's `EmitPrettyPrint` (S); every token resolves to
an op or varnode and an address wherever Ghidra's markup has one.

**D17 `decomp-driver`.** Owns the 93 data tests
(`inventory/tests/decompiler-cpp.md`). Evidence: all 760 checks (L4, G);
whole output equal on both corpora with nothing loaded from Ghidra (L5);
identical results for 1 and N threads; per-function time against the
reference console (`PERF.md`); the `ghidra` profile is `universalAction`
and the `basilisk` profile exists and equals it until an improvement is
accepted; each decompilation returns a `FunctionSummary`; `insta`
snapshots of the `ghidra` profile for both corpora in the gate
(ADR-025 item 4).

## 7. Things other tracks and the coordinator must provide

* **The reference build** gains `decomp_dbg`, the console extension and an
  x86-64 Linux container target (D00). Until then, L2/L3 evidence cannot
  be produced, which is why D00 is in wave 1.
* **`bk-sleigh`** (ADR-023; language model in `bk-sla`, registers and
  flow types in `bk-language`) is needed for running the engine on bytes
  that were never recorded. The interface it must satisfy is the
  `PcodeSource` trait of D07; the SLEIGH tracks should be told its eleven
  methods (inv. 3.1) and that context changes made by instructions must be
  visible to later lifts within one function.
* **`bk-sleigh-snippet`** (ADR-023) compiles `.cspec` call fixups and
  `<pcode>` bodies and is needed by D18; 108 `<body>` elements exist in
  the 107 files. Until then `bk-cspec` keeps payloads as uncompiled text,
  and the data tests that need injection (`injectoverride.xml` and any
  that call a fixed-up function) stay open.
* **`globalcontext`** (`ContextDatabase`) is in D06 here; the SLEIGH
  runtime needs the context-variable half of it earlier. Whichever track
  lands first owns it; the other adopts it. To be settled between the two
  specs (section 9).

## 8. ADR-025 in this plan

The research is finished and ADR-025 records what it requires. None of it
changes Ghidra-profile output; all of it is cheap only if built in from
the first version. Per property: who builds it, and what in that track's
acceptance shows it is there.

| ADR-025 | Built by | What is built | How acceptance shows it |
|---|---|---|---|
| Items 1, 2 — units, origins, profiles | D05 (data model), D07 (table, profiles, driver), every pass track (its units), D17 (the two profiles) | `UnitId`, `UnitInfo { name, origin, group, kind, soundness }`; a `UnitTable` each pass crate contributes to; `Profile` = an arrangement of units by name; the pipeline builder; one switch per unit in the option registry | D07: `list action` text generated from the `ghidra` profile equals the console's for all six root actions; building a profile fails on an unknown or duplicate unit name; a test profile that adds a `basilisk`-origin unit and one that replaces a Ghidra unit, with the `ghidra` profile's traces unchanged. Every pass track: its units appear in the table with Ghidra's names and groups (checked against inv. 5.2 and 6 mechanically) |
| 3a — evaluable IR, one mutation interface, recorder | D05 (interface, recorder hook, op semantics table), D07 (evaluator over a function with an environment; recorder → trace), D10 and every pass (leave the IR evaluable) | All structural edits through the `Funcdata`-shaped API of `bk-decomp-ir`; a `Recorder` trait called on every edit with the unit in force; an evaluator giving `MULTIEQUAL` (by predecessor edge) and `INDIRECT` (through the environment's effect of the named op) a meaning, with free varnodes read by storage | D05: the recorder's output for a scripted edit sequence equals Ghidra's debug trace records for the same edits (the trace *is* a recorder of this kind); the round trip of state dumps proves nothing bypasses the interface (a field changed outside it would not be dumped as Ghidra's). D07 and D19: the bounded stage-equivalence check runs in the gate on both corpora |
| 3b — structurer on a copy, returning a hierarchy and a measure | D04 (structurer), D15 (applies results to the IR) | `structure(graph, block facts, options) -> Structured { hierarchy, condition flips, goto edges, measure { gotos, depth, … } }`, a pure function of its inputs; the block graph is cheap to copy | D04: structuring a graph twice, or a copy of it, gives equal results and leaves the input untouched (property test); results equal `structure blocks` from the reference console; the measure's goto count equals the number of `goto` edges Ghidra marks |
| 3c — typed output tree | D16a (spike), D16b (tree and builder), D16c (printing) | See section 8.1 | D16a's report; then D16b/c: token-for-token equality with `print C` and `print C xml` from Ghidra's final state |
| 3d — function summaries | D03 (the `FunctionSummary` type), D06 (trait methods: summary of a callee; "does the call at this site return"), D09 (asks at call sites during flow), D17 (produces a summary per decompiled function) | Plain data in `bk-cspec`; two trait methods with defaults that answer what Ghidra's engine knows (the callee's prototype and its `no_return` flag; flow overrides at the site) | D06: with the default implementation every data test behaves as before; a test host that answers "does not return" for one call site changes flow exactly as the console's `override flow <addr> callreturn` does (compared with the console). D17: the summary's parameters and return agree with the function's recovered prototype in the reference output |
| 3e — inferred types, table of observed accesses | D02 (category), D07 (the table's type, owned by the function state), D08 and D11 (fill it during propagation) | Types created during a function's decompilation live in a per-function overlay and are marked inferred; `AccessTable` rows (base varnode, offset, size, stride, read/write, op) | D02: an overlay type never changes the identity or order of base types, and dropping the overlay restores the factory (tests). D08/D11: for each `LOAD`, `STORE`, `PTRADD` and `PTRSUB` in the final state of a corpus function there is a row, checked against Ghidra's final state dump |
| 3f — provenance on names and types | D02 (types), D03 (prototype pieces), D06 (symbols; across the trait in both directions), D16c (visible on tokens) | One `Provenance` enum (user, debug information, import, library signature, analysis, model, default) carried as an attribute that takes no part in comparison or identity | D02/D03/D06: round trip through the trait preserves it; changing only the provenance of an input never changes `ghidra`-profile output (property test over the data tests) |
| Item 4 — scorecard, gate | D19 (runner, counters, equivalence harness), D17 (the `ghidra`-profile snapshots) | Section 4.6 | `docs/QUALITY.md` with its command |

### 8.1 The printer in two stages

ADR-025 3c is conditional on a spike. Planned so that no printer code is
written before the question is answered:

1. **D16a, the spike** (wave 2; needs only D00's dumps and the reference
   console). Question: can `PrintC`'s output for the 93 data tests be
   reproduced token for token from a tree that is built first and printed
   afterwards? Method: instrument the reference console through
   `consoleext_bk.cc` to log, for every function of every data test and of
   the research corpus, (i) the sequence of `PrintLanguage` pushes
   (`pushOp`, `pushAtom`, `pushVn*`, with the `OpToken`, the op, the
   varnode, the modifier word in force) and block emissions, and (ii) the
   resulting `Emit` call sequence; then show with a small prototype that
   (ii) is a function of a tree built from (i) alone, or list the places
   where it is not. Ghidra's printer already holds an implicit tree —
   `ReversePolish { tok, visited, paren, op, id, id2 }` nodes over `Atom {
   name, type, highlight, op, vn | fd | ct }` leaves, driven by 51
   `OpToken`s and 16 modifier flags (`printlanguage.hh`, `printc.hh`) —
   so the expected answer is yes. What the spike must look at
   specifically, because these are where emission and tree building are
   interleaved in `printc.cc`: prefix tokens emitted when an operator is
   pushed, before its operands exist; parenthesis decisions taken at push
   time from the enclosing token; modifier flags that change how the same
   node prints (`force_hex`, `print_load_value`, `comma_separate`,
   `negatetoken`, `hide_thisparam`, `pending_brace`, …); `PendPrint`
   (braces that are emitted only if something follows); comments placed
   by `CommentSorter` between statements; declarations and type
   printing, which use the same stack; string and character constants
   fetched from the string manager during printing; the `flat` and
   `no_branch`/`only_branch` modes used when a block is printed inside a
   condition. Output: a report with the answer, the node kinds, and the
   list of facts each node must carry. Accepted by the coordinator, who
   then confirms or revises 3c.
2. **D16b, the tree** (`bk-decomp-out`): node types (statements, blocks,
   expressions, declarations, comments) each referring to ops, varnodes,
   high variables, types and addresses; the builder, which is `PrintC`'s
   decision logic emitting nodes instead of tokens; the unit interface
   for output passes (none in the `ghidra` profile).
3. **D16c, the emitter** (`bk-decomp-print`): tree → `Emit` calls →
   markup or text, with Ghidra's pretty printer. It can be written as
   soon as the spike has fixed the node kinds, from logged trees, without
   waiting for the builder.

If the spike's answer is no, D16b builds from the structured block
hierarchy directly, as `PrintC` does, D16c stays as planned, and output
passes are defined over the hierarchy; the plan's track list does not
change, only D16b's design.

### 8.2 What remains exposed to later decisions

* **Rule application order equal to Ghidra's** is fixed for the `ghidra`
  profile and is what the trace compares. A `basilisk`-profile driver
  with another strategy can run the same units but cannot be accepted by
  trace equality; it is accepted by the scorecard and the
  stage-equivalence check (ADR-025 item 5).
* **Rules as hand-written matchers** over the mutation interface, as in
  Ghidra. ADR-025 does not ask for a pattern language; if one is wanted
  later it adds units, it does not replace these.
* **Cross-function type unification** is explicitly undecided in ADR-025;
  D02's overlay and D07's access table are the hooks it would use.
* **Per-function overlays** for types and join records (3.7).

## 9. For the coordinator

### 9.1 Where Ghidra's code does not fit ADR-025 as worded

1. **3b: Ghidra's structurer already works on a copy, but it edits the
   original while doing so.** `ActionBlockStructure::apply` builds the
   structured graph with `graph.buildCopy(data.getBasicBlocks())` and
   runs `CollapseStructure` on it (`blockaction.cc`). Ten call sites in
   `CollapseStructure`'s rules call `negateCondition(true)` on a block of
   the copy; `BlockCopy::negateCondition` forwards to the original
   (`copy->negateCondition(true)`, `block.hh:557`), and
   `BlockBasic::negateCondition` flips `boolean_flip` and `fallthru_true`
   on the block's real `CBRANCH` and swaps the real block's out-edges
   (`block.cc`). The rules also *read* the IR through the copy:
   `isComplex` counts statements from ops, readers and
   `max_implied_ref`. So "run it on a copy and throw the result away"
   is not side-effect free in Ghidra. **Proposed reading, used in this
   plan:** the structurer takes per-block facts as input (two-way
   branch, complexity, last-op kind) and returns the condition flips and
   goto edges as part of its result; D15 applies them to the IR when a
   result is adopted. For the `ghidra` profile this is the same final
   state provided no rule of `CollapseStructure` reads back a flag it
   flipped on the original — true by my reading (the rules consult the
   copy's own edge order, which the flip also swaps), and checked by D04's
   and D15's acceptance against the console. If the ADR means this, its
   wording can stay with "and the edits it wants made to the blocks".
2. **3a: "evaluated at every stage" holds at unit boundaries and under
   stated assumptions, not absolutely.** (i) Inside a unit the graph is
   transiently inconsistent (heritage mid-pass, `TransformManager`
   between building and applying); the property is "after every unit".
   (ii) Until a space is heritaged its varnodes are *free*: they denote
   storage, not a value, so the evaluator needs a machine state beside
   the SSA values — defined in `features/decomp-ir.md`, but it means the
   IR at early stages is evaluated as an emulator would, which is the
   lifted p-code's own semantics. (iii) Ghidra marks some ops `special`
   (`CALL*`, `LOAD`, `STORE`, `BRANCHIND`, `RETURN`, `INDIRECT`,
   `SEGMENTOP`, `CPOOLREF`, `NEW`); they are evaluable only against an
   environment. (iv) **Several Ghidra units change the function's
   meaning on purpose**, under assumptions: `ignorenan` (no NaN reaches a
   comparison; option `nanignore`), dead-code removal driven by the
   prototype model's effect lists and `ActionLikelyTrash`, read-only
   memory treated as constant (`option readonly`), parameter and return
   recovery deciding which registers are observable, `funcptrencoding`.
   A stage-equivalence check of lifted p-code against final IR therefore
   has to compare *observable* effects (calls and their targets, stores
   outside the frame, the recovered return storage) and has to know
   which assumption-making units fired. **Proposed addition:** each unit
   declares `soundness`: `Exact`, or `Assumes(<name>)`; the recorder
   reports which fired; the equivalence check qualifies or skips
   accordingly. This is one field in the unit table and is in the IR
   spec. Without it the gate's equivalence check would fail on correct
   ports of Ghidra's rules.
3. **3c**: nothing found by reading that makes it unworkable; the
   interleavings to examine are listed in 8.1. The conclusion belongs to
   the spike.
4. **3e/3f**: workable only if category and provenance stay out of type
   identity and ordering. `TypeFactory` interns by `compareDependency`;
   if an inferred `int4 *` were a different type from a user's `int4 *`,
   propagation would choose differently and the `ghidra` profile's output
   would change. The specs make both attributes of the *entry*, not of
   the type's identity.

### 9.2 To confirm

1. **Crate tree of section 2** in place of `bk-decomp` +
   `bk-decomp-print` (update `PLAN.md`'s map). Proposed ADR: "The
   decompiler is split into state crates and pass crates; `Funcdata` is
   data; passes are functions."
2. **State dumps through a console extension compiled with
   `-fno-access-control`** (D00), and the debug console in `REF/`.
   Proposed ADR: "The decompiler's intermediate state is compared with
   and loaded from Ghidra's through a basilisk-defined dump format." It
   adds C++ to `tools/reference/` and one file to the reference build's
   copy — no change to `../ghidra`.
3. **Rule families accepted in rule-subset configurations** (section 6):
   "the reference console with only rules X enabled" becomes an accepted
   oracle beside the default configuration. It is still the `ghidra`
   profile in ADR-025's sense — same units, fewer enabled.
4. **`bk-cspec` outside the decompiler namespace, seeing types through a
   query trait**, shared with the program model; it also holds
   `FunctionSummary`.
5. **`Provenance` in `bk-core`.** D02, D03 and D06 all carry it and D02
   and D03 run in the same wave, so it must exist before they start: one
   enum (`Default`, `Analysis`, `Model`, `Imported`, `LibrarySignature`,
   `DebugInfo`, `User`, ordered by trust as Ghidra's `SourceType` is) with
   a doc comment. Requested as a coordinator commit to `bk-core`; the
   specs name `bk_core::Provenance`.
6. **Corrections to project documents**: 163 rule classes (161 in the
   pipeline) and 71 action classes (80 instances), not 167 and 77
   (ADR-004, ADR-013, `00-overview.md`, the research's D1); 107 `.cspec`
   files, not 110; `PLAN.md`'s M3 list omits the nine Java
   prototype-model test classes and the oracle tooling, and attributes
   all eight `testtypes` tests to the type system (five need the IR and
   `TypeOp`).
7. **Who owns `globalcontext`** (section 7).
8. **Recorded p-code as the interim lifter** (4.4), and its hand-over to
   the SLEIGH tracks as a differential test.
9. **Coverage**: 32 rules apply in neither the data tests nor the
   research corpus (section 10). D19 extends the corpus; until then
   those rules can be ported but not accepted.

## 10. Rule coverage of the corpora (measured)

Applications of each rule summed over all 93 data tests in the reference
console (`print actionstats`), with the number of files in which the rule
applied at least once. Command in `docs/agents/spec-decompiler.md`.

`earlyremoval` 12757 (93), `propagatecopy` 7846 (93), `addmultcollapse`
1385 (68), `collapseconstants` 1060 (88), `andmask` 980 (62), `piece2zext`
838 (59), `subzext` 778 (58), `sub2add` 754 (83), `identityel` 716 (78),
`loadvarnode` 675 (74), `storevarnode` 662 (77), `subvar_zext` 573 (53),
`ptrarith` 453 (50), `termorder` 352 (49), `collect_terms` 318 (53),
`subextcomm` 233 (31), `aliasupdate` 225 (47), `dumptyhump` 200 (33),
`equal2zero` 145 (40), `boolnegate` 143 (41), `shiftbitops` 116 (10),
`subcommute` 105 (21), `divopt` 104 (6), `selectcse` 98 (26), `condnegate`
96 (41), `subnormal` 81 (8), `subcancel` 76 (15), `modopt` 65 (4),
`intlessequal` 57 (25), `multicollapse` 56 (16), `sborrow` 49 (26),
`shift2mult` 47 (12), `trivialarith` 45 (19), `zextshiftzext` 40 (8),
`subvar_subpiece` 34 (20), `splitcopy` 33 (2), `doubleshift` 32 (1),
`divtermadd2` 32 (1), `lessequal` 26 (15), `divtermadd` 21 (2),
`bitfield_load` 21 (2), `structoffset0` 19 (8), `doublesub` 18 (6),
`rangemeld` 18 (10), `humptydumpty` 17 (11), `pushptr` 17 (7),
`splitstore` 16 (3), `piecestructure` 14 (6), `notdistribute` 13 (7),
`logic2bool` 13 (6), `shiftpiece` 12 (4), `stringcopy` 12 (1),
`pull_absorb` 12 (2), `xorcollapse` 10 (7), `signform` 10 (5), `andpiece`
9 (5), `pullsub_multi` 8 (5), `pullsub_indirect` 8 (3), `signshift` 8 (5),
`booleannegate` 8 (5), `addunsigned` 8 (4), `bitfield_in` 8 (2),
`trivialshift` 7 (3), `shiftsub` 7 (5), `stringstore` 7 (1),
`bitfield_store` 7 (2), `shiftcompare` 6 (2), `concatzero` 6 (3),
`subvar_and` 6 (4), `subvar_sext` 6 (1), `ignorenan` 6 (4), `doublein` 6
(3), `booleandedup` 5 (4), `concatzext` 5 (3), `floatrange` 5 (4),
`conditionalmove` 5 (3), `subfloat_convert` 5 (3), `ptraddundo` 5 (1),
`bitfield_out` 5 (2), `andzext` 4 (1), `zextcommute` 4 (3), `divchain` 4
(2), `signmod2nopt` 4 (1), `orcompare` 4 (2), `subvar_compzero` 4 (3),
`doubleout` 4 (2), `dumptyhumplate` 4 (1), `insert_absorb` 4 (2),
`trivialbool` 3 (2), `anddistribute` 3 (2), `andcompare` 3 (3),
`doublearithshift` 3 (2), `zexteliminate` 3 (3), `piece2sext` 3 (2),
`multnegone` 3 (3), `expandload` 3 (2), `testsign` 2 (2), `ormask` 2 (1),
`orconsume` 2 (2), `andorlump` 2 (1), `2comp2mult` 2 (1), `equal2constant`
2 (2), `concatcommute` 2 (2), `signmod2nopt2` 2 (1), `signmod2opt` 2 (1),
`funcptrencoding` 2 (1), `unsigned2float` 2 (1), `int2floatcollapse` 2
(1), `doubleload` 2 (1), `2comp2sub` 2 (2), `ptrsubcharconstant` 2 (1),
`splitload` 2 (1), `push_multi` 1 (1), `orcollapse` 1 (1), `sless2zero` 1
(1), `bitundistribute` 1 (1), `booleanundistribute` 1 (1), `shiftand` 1
(1), `signdiv2` 1 (1), `lessnotequal` 1 (1), `lessone` 1 (1),
`lzcountshiftbool` 1 (1), `floatsign` 1 (1), `subvar_shift` 1 (1).

The research corpus (74 fragments, the same measurement; two `a07_switch`
scripts printed no statistics and are not counted) adds applications of
`rightshiftand` 2, `highorderand` 2, `andcommute` 6, `bxor2notequal` 2 and
`subright` 20.

Never applied by any data test (37; the 32 without the five above apply in
neither corpus): `scarry`, `rightshiftand`,
`highorderand`, `andcommute`, `concatshift`, `leftright`, `carryelim`,
`bxor2notequal`, `less2zero`, `lessequal2zero`, `threewaycomp`,
`transformcpool`, `slesstoless`, `zextsless`, `boolzext`,
`concatleftshift`, `humptyor`, `negateidentity`, `positivediv`,
`signform2`, `signnearmult`, `switchsingle`, `popcountboolxor`, `xorswap`,
`splitflow`, `ptrflow`, `negatenegate`, `orpredicate`, `floatcast`,
`ptrsubundo`, `segment`, `piecepathology`, `doublestore`, `subright`,
`floatsigncleanup`, `extensionpush`, `andstructure`.
