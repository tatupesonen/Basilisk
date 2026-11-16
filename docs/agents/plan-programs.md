# Track `plan-programs` — report

Planning track (Fable 5.2), worktree `basilisk-wt/plan-programs`, branch
`plan-programs`, 2026-11-16. Documents only; no product code, no gate
run (the gate checks nothing this branch adds). The track was asked to
converge early (usage); what that left undone is under "Gaps".

## Built

| File | What it is | State |
|---|---|---|
| `docs/features/program-plan.md` | The port plan for M4 and M5 in the shape of `decomp-plan.md` | M4 usable for briefing specification agents; M5 a track table; "to be planned" items marked |
| `docs/research/plan-programs/roadmap-check.md` | M4 to M10 against Ghidra's source: coverage, dependencies, what is missing, what can be pulled forward, where the order of work is wrong, a proposed order, a size estimate | Complete for what was measured; M9 not re-checked |
| `docs/research/plan-programs/*.py`, `*.sh`, outputs, `README.md` | Twelve measurement scripts with their output and commands | Complete |

## What was read and measured

* Read: `DIRECTION.md`, `RULES.md`, `LOOP.md`, `PLAN.md`, `PARITY.md`,
  `inventory/00-overview.md`, `decomp-plan.md` (sections 1 to 9.2),
  `plugin-binding-constraints.md`, the host-trait and overlay sections of
  `decomp-symbols.md`, `decomp-oracle.md` 4.13, `testbed.md`'s headless
  section, `ui-shell`'s `ProgramSource` (in `bk-ui`'s source), the
  `sleigh-language` draft's head; ADR-001 to 015, 020 to 022, 025 to
  028, 035 to 037, 043 to 048. `PERF.md` only for its budgets table.
* The paused work: `../store-spike` (the study so far, both notes
  files, the harness's interface and run script, and the uncommitted
  results of an aborted run under its build directory) and `../spec-pe`
  (status file and the size of its five fact sheets; the fact sheets
  themselves were not read).
* Measured over Ghidra's tree (commands in
  `docs/research/plan-programs/README.md`): every module's size by
  language and source set and its `build.gradle` dependencies; package
  sizes of `SoftwareModeling`, `DB` and `Base`; the import graph between
  91 package groups, resolved per class, with its cycles; every loader,
  relocation handler, ELF extension, exporter, analyzer, file system and
  command class; analyzers' type, priority and imports; processors' Java
  by kind; which classes of `Project` and `DB` the program model
  imports; the test checklist by package.
* Read in Ghidra's source for behaviour (cited where used):
  `Disassembler.java` (the program-free mode), `ProgramDB.java`
  (managers, version), `Table.java` (key allocation), `AddressMapDB.java`
  (key layout), `AnalysisPriority.java`, `AutoAnalysisManager.java`
  (task lists, events, one-time analysis), `AnalysisScheduler.java`
  (option names), `Loader.java`, `LoaderTier.java`, `AnalyzeHeadless.java`
  (options), `AbstractProgramLoader.java` and `HeadlessAnalyzer.java`
  (transactions), `ProcessorEmulatorTestAdapter.java` (test binaries),
  the root `build.gradle` (`BIN_REPO`), a `.gdt` file's first bytes.

## Verified and not verified

Verified by measurement or by reading the cited lines: every figure
marked measured; the five facts of `roadmap-check.md` section 1.

Not verified (each is marked where it appears):

* Nothing was run through Ghidra. The dump script, headless script
  compilation with the JDK alone, run times, determinism at
  `-max-cpu 1`, and that a one-time analysis with the other analyzers
  off runs only that analyzer.
* The crate order memory → references → symbols → code units →
  functions rests on import counts, not on method bodies.
* That `LoadTarget` stays small for the ELF loader.
* Default enablement of analyzers is a floor: the script sees a literal
  `setDefaultEnablement(true)` only; analyzers that override
  `getDefaultEnablement` are not counted.
* The storage numbers are from an aborted run on a loaded Mac.
* Which cross toolchains the build host can install.
* Every estimate of Rust lines; the user-interface and M8 ratios are
  guesses and say so.
* The closure of what the program model needs from `Framework/Project`
  (only direct imports were measured).

## Proposed ADRs (the coordinator numbers them; next free is ADR-049)

A. **The program side is area crates and one assembling crate.** Area
   crates (`bk-memory`, `bk-refs`, `bk-symbols`, `bk-datatypes`,
   `bk-listing`, `bk-functions`) own their tables and the rules inside
   one area; effects that cross areas are written once in `bk-program`,
   at the points of Ghidra's manager protocol. Replaces `bk-program`,
   `bk-datatypes`, `bk-store`, `bk-loader*` in the crate map with the
   tree of `program-plan.md` section 2 (adds `bk-addr`, `bk-task`,
   `bk-cmd`, `bk-reloc-*`, `bk-cparser`, `bk-ghidra-db`, `bk-export`,
   `bk-ui-program`, `bk-decomp-host`).
B. **ADR-003's decision is split**: the table interface of `bk-store` is
   fixed now; the engine is chosen by the finished spike, which adds a
   memory-first candidate. No track waits for the engine.
C. **One logical change log** is undo, change set and event source;
   readers use snapshots; a snapshot is ADR-044's frozen state. Undo
   survives save; bulk-step undo is open until the spike.
D. **Ids are never reused**; variables have their own identity.
E. **Parity of the Java side is measured at six levels (P0 to P5) with a
   Basilisk-defined program dump**, written by a Ghidra script on the
   build host and by Basilisk; dumps can be loaded, so analyzers are
   accepted from Ghidra's state; analyzer-subset runs of Ghidra are an
   accepted oracle (the counterpart of ADR-027).
F. **Ghidra's packed databases are read, read-only**, for the shipped
   data-type archives and Function ID databases. Narrows ADR-003. Needs
   the owner.
G. **ADR-002 extended**: data files of `Ghidra/Features/*/data` are read
   in place like processor data and never copied.
H. **Loaders are written against a `LoadTarget` trait** with a recording
   implementation; format parsers hold no program-side code.
I. **Analysis improvements live in profiles** (ADR-025 applied to
   analysis); the `ghidra` profile is the oracle's target.
J. **The corpus is built by the project** (compiler-built samples,
   Ghidra's p-code test sources per processor, damaged files, named
   system binaries), recorded in a manifest; `LOOP.md`'s sentence about
   Ghidra's test resources applies only to the three source directories
   that exist.

## Proposed changes to `PLAN.md`

* Crate map: the program rows as in ADR proposal A.
* M4: add the corpus, the program builder, the domain-object layer
  (transactions, undo, events, options), external locations, program
  trees, source map, function tags, the read-only database reader, the
  file-open part of the file-system layer; move the binary, hex and XML
  exporters in from M6; move "editing commands with undo/redo" from M7
  to M4/M5 (M7 binds them to actions).
* M5: name block models, symbolic propagation, the byte-search engine;
  say that default analysis includes two decompiler analyzers and
  several analyzers `PARITY.md` has under M6, and that M5's oracle runs
  with those off until they land.
* M6: the emulator needs `sleigh-language`, not M2; its tests need M4
  and built binaries; the JIT (45,439 of the module's 71,882 lines)
  needs a decision; DWARF and PDB are a reader (now) and an applier
  (after M4); `GhidraGo` belongs to M8.
* M8: say it is a design over `bk-store`, not a port of the page-delta
  versioning.
* M9 or its own item: RTTI class recovery (28,042 lines of scripts).
* M10: name `Debugger-importers`, `Debugger-dap`, `Debugger-jpda`, the
  `drgn` and `x64dbg` agents, `FunctionGraphDecompilerExtension`,
  `GhidraBuild`'s items, the launch scripts' counterparts.
* Order of work: `sleigh-language` is a chain track, started now; the
  programs chain is four lines (data types, store and memory, parsers
  and relocation tables, disassembler core); the storage engine does not
  block specification; the corpus is a first step beside `ref-headless`.

## Proposed changes to `PARITY.md`

* Add rows: `Features/FunctionGraphDecompilerExtension` (M7);
  `Debug/Debugger-importers`, `Debugger-dap`, `Debugger-jpda`,
  `AnnotationValidator` (not applicable: a Java annotation processor),
  agents by name; `Extensions/SampleTablePlugin`, `sample`,
  `bundle_examples`; `GhidraBuild/*`; `Ghidra/RuntimeScripts`.
* Split "Base: loaders, opinions, importer" by loader, and "Base:
  commands" away from `bk-program`.
* The Framework rows for the program model: one per area crate.
* `Emulation`: note the JIT.

## Defects and oddities found in Ghidra (for `docs/GHIDRA-BUGS.md`; read, not reproduced)

1. **Record keys are reused after undo.** `db.Table.getKey()`
   (`Ghidra/Framework/DB/src/main/java/db/Table.java:605–611`) returns
   the stored maximum key plus one, and the maximum is part of the
   state undo restores; the symbol table takes its ids from it
   (`…/program/database/symbol/SymbolDatabaseAdapterV6.java:114`). After
   "create symbol, undo, create another symbol" the second symbol has
   the first one's id. Whether a stale `Symbol` object then silently
   refreshes to the other symbol was not traced. Reproduction to run
   later: a script that keeps a `Symbol`, undoes its creation, creates
   another and reads the first. Basilisk: ids are never reused.
2. **`Features/Sarif` depends on a debugger module.** Its build file
   names `Debugger-isf` and 43 of its 120 files import it (the ISF
   data-type writers). Not a behavioural defect; a layering one that a
   port must not copy.
3. **`SystemEmulation` depends on `Debugger`** for one class
   (`DebuggerStaticMappingContext`). As 2.

Nothing here was confirmed by running Ghidra.

## Gaps (asked for and not done, or done only in part)

* **M5 is a table**, as the coordinator allowed; the analyzers are
  grouped by family, not ordered by what reads what.
* **Three M4 tracks are marked "to split"** (built-in data types,
  composites, the data-type manager; also symbols) because per-class
  sizes were not measured; **the read-only database reader, the
  relocation oracle tables, the file-system layer and
  `SM/program/util`** are marked "to be planned".
* The `LoadTarget` method list and the cross-area rule table of
  `bk-program` are named, not written.
* The spike's fact sheets for PE were not read; the PE track is planned
  from sizes only.
* `docs/features/plugin-api.md`, `ui-shell.md`, `bin-elf.md`, `lang.md`
  and `PERF.md` were read in part, not whole.
* The dependency scripts see imports only.
* No helper agents were started; nothing was built or run except the
  Python and shell scripts in the research directory.

## Follow-ups for the coordinator

* Copy `../store-spike/tools/store-spike/target/results/*.tsv` to a
  committed place: they are the only storage measurements and sit in a
  build directory.
* `../spec-macho` and `../spec-program-model` are empty worktrees on
  `master`'s commit; this plan supersedes the second's purpose.
* The checklist's GUI flag is set by a test's base class; program-model
  specifications should classify tests by content.

## Open questions for the owner

1. May Basilisk read Ghidra's packed databases read-only (`.gdt`,
   `.fidb`)? Default analysis parity depends on it.
2. May system binaries and MSVC-built samples be used on the build host
   without being committed?
3. Is a C storage engine acceptable if the finished spike favours it?
4. What replaces the JIT emulator: nothing (interpreter only), or a
   Rust design of its own later?
5. Which `GhidraBuild` items are out of scope (Eclipse plug-ins, IDA
   export plug-ins)?
6. More slots for the programs side: it can use six to ten.

## Commits

    62137bc docs(plan-programs): track report
    a719fc3 docs(plan-programs): the programs port plan for M4 and M5
    557df22 docs(plan-programs): roadmap check, counts corrected after re-measuring
    7a2b600 docs(plan-programs): the roadmap M4 to M10 checked against Ghidra's source
    5197ef7 docs(plan-programs): measurement scripts over Ghidra's source and their output
    de3e796 docs(plan-programs): track start
    (and the commit that adds this list)
