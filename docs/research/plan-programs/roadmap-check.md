# The roadmap compared with Ghidra's source (M4 to M10)

Track `plan-programs`, 2026-11-16. `docs/PLAN.md` lists milestones M4 to
M10 and an "Order of work". This document checks both against Ghidra's
source at the pinned commit `42db038f3c`: what code each milestone item
covers, what that code depends on, whether its place in the order is
right, what the roadmap does not name, and what could start earlier.

**How to read the figures.** Every figure marked *measured* comes from a
script in this directory; `README.md` lists the commands. Lines are
physical lines of `src/main/java` unless stated. Dependencies are Java
imports resolved per class (`pkgdeps.py`); they are a floor, because a
use that needs no import is not seen. Nothing was run through Ghidra: no
JDK is set up for this track. Statements about behaviour were read in the
source and cite the file. *Estimated* figures give their method.
*Unverified* marks what was not checked.

Path abbreviations: `SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`,
`BASE/` = `Ghidra/Features/Base/src/main/java/ghidra/`.

## 1. Five facts that change the roadmap

1. **Ghidra's source tree holds no test binaries.** `Ghidra/Test/TestResources`
   contains three directories of C sources and no `data/` directory
   (measured: `find` over the tree for executables, objects and saved
   programs finds only 15 data-type archives, two GNU disassembler files
   and six DMG libraries). The binaries Ghidra's tests name live in a
   separate repository, `ghidra.bin` (`build.gradle:59`,
   `BIN_REPO = ../ghidra.bin`), which is not public. `LOOP.md`'s rule
   "test binaries taken from Ghidra's test resources are referenced in
   place" therefore applies to nothing for loaders and analysis. The same
   holds for the 126 processor emulator tests: their binaries are looked
   up under `data/pcodetests` of a module or of `TestResources`
   (`BASE/test/processors/support/ProcessorEmulatorTestAdapter.java:74–96,171`)
   and are absent; only their C sources ship
   (`Ghidra/Extensions/SleighDevTools/pcodetest/c_src`, 6,483 lines).
   What Ghidra's tests do use is a builder: 449 test files use
   `ProgramBuilder`, 120 `ToyProgramBuilder`, 57
   `ClassicSampleX86ProgramBuilder`; 17 use `env.getProgram(…)` and 6
   `getTestDataFile` (measured, `grep -rlF` over the test source sets).
   **Consequence:** the corpus for M4 and M5 is built by the project, and
   the program-model tests need a `ProgramBuilder` equivalent before they
   can be ported.
2. **Loaders are almost untested in Ghidra.** `ghidra.app.util.opinion`,
   the importer and its plugins have 10 test classes with 54 tests; the
   exporters and the XML program format have none (measured,
   `tests-m4-m5.txt`). Parity of loaders can only come from the
   `ref-headless` oracle. `PLAN.md` says this; the count shows how
   completely it is true.
3. **Data-type archives and Function ID databases are Ghidra databases.**
   The 15 shipped `.gdt` archives (21.6 MB; `Ghidra/Features/Base/data/typeinfo/`,
   one in `Features/Rust`) start with a Java serialisation header and
   hold a ZIP of a Ghidra buffer file (`xxd`: `aced 0005 … PK 03 04`;
   `Ghidra/Framework/FileSystem/…/store/db/PackedDatabase.java`). The
   analyzer that applies them, `ApplyDataArchiveAnalyzer`, is on by
   default (`analyzers.tsv`), and what it applies (library function
   signatures) changes decompiler output. Function ID's `.fidb` files are
   the same format (`FunctionID` imports `db.*` in 8 files;
   `gradle/support/fetchDependencies.gradle:121–175` fetches them).
   ADR-003 says Basilisk does not read Ghidra's packed-database format.
   **Default analysis cannot reach parity without reading it.** A
   read-only reader is needed (proposed ADR, section 6).
4. **Default analysis runs the decompiler.** `DecompilerSwitchAnalyzer`
   and `DecompilerCallConventionAnalyzer` set default enablement to true
   (`Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/analysis/DecompilerSwitchAnalyzer.java:70`,
   `DecompilerCallConventionAnalyzer.java:63`). Whole-analysis parity
   needs M3 finished. Everything else in M5 does not: Ghidra enables
   analyzers one by one through program options named
   `Analyzers.<name>` (`BASE/app/plugin/core/analysis/AnalysisScheduler.java:152`),
   so Ghidra can be run with exactly the analyzers Basilisk has, as the
   decompiler plan runs the console with a subset of rules.
5. **In Java the layers the plan relies on do not exist.** The 41 package
   groups of `SoftwareModeling` form one import cycle of 321,000 lines,
   and the 50 groups of `Features/Base` another of 689,000 lines
   (measured, `deps-scc.txt`): model interfaces import the database
   implementation (`model` → `program.database` in 56 files), format
   parsers import the data-type model (156 of the 230 PE files, 90 of the
   134 Mach-O files), loaders import the user interface. Between modules
   the graph is a clean chain (Utility → Generic → DB → … → Project →
   SoftwareModeling → Emulation → Base). So, as with the decompiler's
   48-module cycle, the order of work comes from what each part calls,
   and each track's specification has to say where it cuts.

## 2. Milestone by milestone

Sizes are Java main lines, measured (`modules.tsv`, `packages-*.tsv`,
`deps-groups.tsv`). "Needs" is what the code imports, by number of
importing files where it matters.

### M4 — Program model, storage, loaders

| Plan item | Ghidra code | Size | Needs, by the source | Place in the order |
|---|---|---:|---|---|
| `ref-headless` | — (tooling: a Ghidra script, a build of Ghidra on the build host) | — | A JDK 21 and Gradle; `analyzeHeadless` (`BASE/app/util/headless/`, 4,222 lines; options read from `AnalyzeHeadless.java`) | Right: first. It also needs a corpus (fact 1), which the plan does not say |
| Storage spike, `bk-store` | `Ghidra/Framework/DB` (replaced, ADR-003) | 31,606 | Generic only. The program database uses 33 of its 97 classes (`uses-db-by-program.tsv`): tables, records, fields, schemas, iterators, the handle | Right, but it does not block the model's specification: see section 5 |
| `bk-program` | `SM/program/model/{address,mem,listing,symbol,reloc,sourcemap,scalar,util}` and `SM/program/database/*` without `data` | model 36,923; database 79,456 (of which schema adapters for old versions, not applicable: 15,810 in all of `database`) | `Framework/DB` (299 file imports), **`Framework/Project` (249)**, Generic, `model.lang` and `model.data` | Right. The plan's list omits what the source has: external locations (`database/external`, 1,390), program trees (`database/module`, 3,453), source-file map (`database/sourcemap` 2,158), function tags, user data (`ProgramUserDataDB`), options stored in the program, overlay spaces, the change set |
| — (not in the plan) | The domain-object slice of `Framework/Project`: `DomainObjectAdapterDB`, the transaction managers, change records and events, `Lock`, `OpenMode`, `VersionException` | 25 classes, 4,784 lines imported directly (`uses-project-by-program.tsv`); the closure is larger, not measured | DB, Generic | **Missing from M4.** `PLAN.md` puts all of `Project` in M8. Transactions, undo, events and the program's options are defined there, not in `SoftwareModeling` |
| `bk-datatypes` | `SM/program/model/data` (251 files), `SM/program/database/data` (92 files), `dtarchive` (both sides), the C parser (`BASE/app/util/cparser`, 2,073 + a 6,230-line JavaCC grammar) | 40,011 + 28,845 + 3,709 + 8,303 | `model.mem` (75 files: every data type reads values through `MemBuffer`), `model.lang`, `Framework/Docking` (94 files: settings definitions and a few Swing types; 15 files, 2,539 lines import Swing or docking directly) | Right, and it is the largest single part of M4. The 61 test classes with 982 tests make it the best-tested part too |
| `bk-loader` + ELF, PE, Mach-O, raw, Intel hex | `BASE/app/util/opinion` (72 files), `importer` (19), the formats' program-side code (data-type layouts and markup inside `format.*`) | opinion 28,250; importer 3,147; `format.pe` 32,463; `format.macho` 18,530; `format.elf` 11,284 | model (193 file imports), `program.database` (30, mostly `mem`), **`Framework/Project` (20: domain folders and files)**, **`formats.gfilesystem` (9; and 11 of the 31 byte-provider files)**, `analysis.core` (2), demangler (1) | Right. Two cuts to make: the file-system layer (`FSRL`, `FileSystemService`; `PLAN.md` has all of it in M10) and project folders (M8) |
| Relocation handlers per processor | `Ghidra/Processors/*/src/main/java`: 22 ELF handlers, 5 Mach-O, 6 COFF, 13 ELF extensions (`extension-classes.tsv`) | ELF 11,769 (with type enums and contexts); Mach-O 911; COFF 1,249; extensions 3,465 (`processors-java.tsv`) | The ELF loader (`ElfProgramBuilder`, 3,821 lines), memory, symbols | Right. They are independent of each other: 20 processor modules |
| `basilisk import` | `BASE/app/util/importer/AutoImporter.java` (829), `ProgramLoader.java` (704) | 1,533 | Loaders, the store | Right |
| — (not in the plan) | A program builder for tests: `BASE/program/database/ProgramBuilder.java` and the sample builders (`BASE/test`, 11,554 lines with the test environment) | about 3,000 of it is builders (estimated from file names; not measured exactly) | The program model | **Missing.** 449 test files depend on it (fact 1) |

### M5 — Disassembly and auto-analysis

| Plan item | Ghidra code | Size | Needs, by the source | Place in the order |
|---|---|---:|---|---|
| Flow-following disassembler | `SM/program/disassemble` (6 files) | 3,669 | `model.lang`, `model.mem`, `model.listing`, `program.util` (context), `database.register` (1 file). **It has a mode with no program**: `Disassembler.getDisassembler(Language, AddressFactory, …)` (`Disassembler.java:171`) and `pseudoDisassembleBlock(MemBuffer, RegisterValue, int)` (`:778`) return instruction blocks from bytes; a program is consulted at six `program == null` checks and instructions are stored through one call, `listing.addInstructions(instructionSet, false)` (`:639`) | **Can start before M4**: it needs `sleigh-language` and a byte source. Storing its result is M4's code manager (`CodeManager.addInstructions`, `SM/program/database/code/CodeManager.java:408`) |
| Auto-analysis manager | `BASE/app/plugin/core/analysis/AutoAnalysisManager.java` (1,801), `AnalysisScheduler`, `AnalysisTaskList`, `BASE/app/services/{Analyzer,AbstractAnalyzer,AnalysisPriority,AnalyzerType}` | about 2,900 | Commands (`Framework/Project`'s `BackgroundCommand`), program events, options | Right. Small; the weight is in the analyzers |
| Analyzers | 133 concrete classes in 30 modules (`analyzers.tsv`): `Features/Base` 45 (13,698 lines), `FileFormats` 33 (5,569), `Processors/*` 31 (10,625), `BytePatterns` 5, `MicrosoftCodeAnalyzer` 5, `Decompiler` 3, and others | 36,582 for the analyzer classes alone | What they call is larger than they are: commands (`app.cmd`, 126 files, 19,083), **block models** (`SM/program/model/block`, 6,789), **symbolic propagation** (`BASE/program/util/SymbolicPropogator.java` 3,047 + `VarnodeContext.java` 2,159; at least 17 analyzers use it), byte-pattern search (`BASE/util/bytesearch`, 4,590), the demangler framework (5,664), GCC exception tables (`BASE/app/plugin/exceptionhandlers`, 6,751), `util.state` (4,741) | Right, with three parts the plan does not name (bold) that are tracks of their own |
| Decompiler wired to the program | `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler` (9,292), `app/cmd/function` (1,141), the three analyzers (966), `SM/program/model/pcode` (the result model: `HighFunction`, `HighSymbol`, …; 18,039) | about 29,000 | The program model (399 file imports), M3 | Right. Two of its analyzers are on by default (fact 4) |
| `basilisk analyze` | `BASE/app/util/headless` | 4,222 | Importer, analysis, scripts (3 files: pre- and post-scripts are M9) | Right |

### M6 — Headless core complete

| Plan item | Ghidra code | Size | Needs, by the source | Place in the order |
|---|---|---:|---|---|
| Exporters | 11 concrete classes (`extension-classes.tsv`), `BASE/app/util/xml` | 2,069 + 6,792; the C exporter (631) is in `Decompiler` | Program model; **`Sarif` needs `Debug/Debugger-isf`** (43 of its 120 files import it; 17 classes, 1,469 lines) | Binary, Intel hex, ASCII and XML export need only M4 and **can move to M4**: an XML export is also a second channel for comparing with Ghidra (section 5) |
| DWARF | `BASE/app/util/bin/format/dwarf` (131 files) | 23,223 | Parser and applier are one package: it imports data types (25 files), listing (24), `program.database` (10), `model.pcode` (7), analysis | Split it: the reader needs only `bk-bin` and can start now; the applier needs M4 |
| PDB | `Ghidra/Features/PDB` | 91,637 main, 80,708 test: reader `…/bin/format/pdb2` 59,816; applier `pdbapplicator` 21,370 + `classtype` 3,000; symbol server 5,583 | Reader: `bk-bin` and `MicrosoftDmang` (5 files). Applier: model, commands (14), analysis (10) | As DWARF |
| Demanglers | `MicrosoftDmang` 16,436 (17,088 lines of tests, 1,711 tests), `MicrosoftDemangler` 2,308, `GnuDemangler` 3,869 + `GPL/DemanglerGnu` 33,926 lines of C, framework `BASE/app/util/demangler` 5,664; **also `Rust` (2,966) and `Swift` (10,905), which the plan lists under "Swift, Rust, …" only in `PARITY.md`** | — | `MicrosoftDmang` imports nothing but `Utility` (4 files): fully independent. The framework and the analyzers need the model and commands | The parsers can start now (the plan says so). The demangler *analyzers* are on by default and belong to M5's default analysis, not M6 |
| Function ID | `Ghidra/Features/FunctionID` | 9,633 | **Ghidra's database format** (fact 3), the program model, hashing over instructions | After the read-only database reader. The databases themselves are fetched, not in the tree |
| Emulator | `Ghidra/Framework/Emulation` (478 files) | 71,882, of which **the JIT (`ghidra.pcode.emu.jit.*`) is 45,439**: it compiles p-code to JVM bytecode | `model.pcode` (221 file imports), `model.address` (112), `model.lang` (97), the Java SLEIGH classes (34), `model.listing` (22), `model.mem` (20). **Not** the database, `Framework/DB`, `Project` or `Base` | The plan says it "needs only M1 and M2". It needs M1 **with `sleigh-language`** (registers, instruction prototypes, p-code objects), and nothing of M2. The JIT cannot be ported as it is; what replaces it is a decision (section 6) |
| Processor emulator tests (126 classes) | `Ghidra/Processors/*/src/test.processors`; harness `BASE/test/processors/support` (5,342) | — | **A loaded program** (the harness imports the test binary with the ELF loader), **test binaries that are not in the tree** (fact 1), cross compilers for each processor | Cannot run before M4's ELF loader. Needs a toolchain track on the build host; its output doubles as the per-processor corpus for loaders and relocations |
| Assembler | `SM/app/plugin/assembler` (117 files) | 17,728; `WildcardAssembler` 1,870 | The Java SLEIGH classes (59 files), `model.lang`, `model.listing` (11) | Needs `sleigh-language`; otherwise independent, as the plan says |
| (in `PARITY.md` under M6) `MicrosoftCodeAnalyzer`, `Objective-C`, `Swift`, `Rust`, `GhidraGo`, Go (`format.golang`, 16,718), `SystemEmulation`, `Sarif` | — | 9,977; 6,925; 10,905; 2,966; 1,324; 16,718; 9,194; 13,673 | `Objective-C` imports the decompiler (1 file) and has an analyzer on by default; `SystemEmulation`'s build file depends on `Debugger` (one class used); `GhidraGo` is a URL handler for projects (needs `Project`), not the Go language | `PLAN.md`'s M6 list names none of these; `PARITY.md` does. `GhidraGo` belongs with M8 |

### M7 — User interface

| Plan item | Ghidra code | Size | Note |
|---|---|---:|---|
| Shell | `Framework/Docking` 157,152, `Gui` 26,179, `Help` 11,267, `Project`'s tool framework (`plugintool`, 11,486) | — | Replaced (ADR-008) |
| Views | `BASE/app/plugin/core` (71 packages, 241,246 lines without analysis), `BASE/app/util/viewer` (32,867), `ByteViewer`, `FunctionGraph`, the graph modules, `Framework/Graph` (28,644), `Decompiler`'s panel (`plugin.core.decompile` 12,368 + `component` 6,099), `DecompilerDependent` (15,586) | — | The plan names about 14 of the 71 `plugin.core` packages. Not named, among the larger: composite editor (17,464), instruction search (7,232), terminal (7,965), program-tree view (8,831), strings and encoded strings (9,690), equates (3,293), register values (2,035), checksums, overview bars, call tree, colorizer, printing, clipboard |
| "Editing commands with undo/redo" | `BASE/app/cmd` (126 files, 19,083) | — | **Misplaced.** Commands are what loaders and analyzers call (`opinion`, `analysis.core`, `demangler`, PDB all import `app.cmd`); they are M4 and M5 work. What is M7 is binding them to actions |
| Program diff | `BASE/program/util/ProgramDiff*.java`, `ProgramMerge*.java` (about 12,000 lines, headless), `Features/ProgramDiff` (6,021, the view) | — | The engine is headless and can serve the oracle's comparison (section 5) |

### M8 — Projects and collaboration

`Framework/Project` 80,984, `FileSystem` 21,794, `GhidraServer` 10,416,
`BASE/app/merge` 39,763 (65 test classes, 1,167 tests). `GhidraServer`
imports only `FileSystem`, `DB`, `Generic` and `Utility`. The versioned
file layer stores **page-level deltas of Ghidra's database** (notes of
the paused storage study, verified there). Since Basilisk's store is its
own (ADR-003), M8 is not a port of this code but a design on top of
`bk-store`; the plan should say so. Also in M8 by the source: old-language
translation (`SM/program/util/LanguageTranslator*.java`; 48 `.trans` and
`.lang` files under `Ghidra/Processors`), and `GhidraGo`.

### M9 — Plugin API

Not re-checked here; `features/plugin-api.md` is its plan. Two facts from
this measurement: Ghidra bundles 331 Java and 25 Python scripts; and
**28,042 lines of them are one feature**, RTTI class recovery
(`Ghidra/Features/Decompiler/ghidra_scripts/classrecovery`, 17 files),
which no milestone names and which is too large to treat as "a bundled
script".

### M10 — Remaining modules

| Area | Size (measured) | Note |
|---|---:|---|
| `Ghidra/Debug` | 217,653 Java main + 23,251 Python (agents) | `Framework-TraceModeling` (69,835) is built on `Framework/DB` (58 file imports) and `Emulation` (24): a second database-backed model. `Debugger-importers`, `Debugger-dap`, `Debugger-jpda`, `AnnotationValidator` and the `drgn` and `x64dbg` agents are not named in `PARITY.md` |
| `VersionTracking` (+BSim link) | 57,488 | Sessions are Ghidra databases (`fw.DB` in 25 files) |
| `BSim` (+visualiser, Elastic) | 49,627 | Needs the decompiler's signatures (`signature.*`, not in M3) and a database server |
| `FileFormats` | 79,066 | 667 files; 52 file systems; 33 analyzers; its loaders (`DexLoader`, `ApkLoader`, dump files, dyld cache extraction) |
| Other loaders in `Base` | COFF 4,194 + loader 844; OMF 5,250; NE 2,783; MZ 618; PEF 3,284; SOM 3,868; XCOFF 1,166; a.out 1,084; and `DefLoader`, `MapLoader`, `DbgLoader`, `GdtLoader`, `GzfLoader`, `XmlLoader`, Motorola hex, OMF-51, DYLD cache | COFF is needed by PE work earlier: `PeLoader` shares the debug-symbol loader (`AbstractPeDebugLoader`) and MSVC objects are COFF |
| `Extensions` | 27,237 | `Jython` and the OSGi bundle host (`BASE/app/plugin/core/osgi`, 5,147) are replaced by ADR-014; `SampleTablePlugin`, `sample`, `bundle_examples` are examples |
| Processors' other Java | 44,716 in all; analyzers 10,625; emulate-state modifiers 3,332; p-code injection 1,258; `JVM` 11,619 and `Dalvik` 573 (class-file and DEX support) | Analyzers are M5 by the source (several are on by default for their processor) |

## 3. What the roadmap does not name at all

Checked with `roadmap-coverage.py` (module names against `PARITY.md` and
`PLAN.md`) and by reading the package tables.

| Not named | Where | Size | Proposed home |
|---|---|---:|---|
| The domain-object layer (transactions, undo, events, options) | `Framework/Project/…/framework/{data,model}`, `Framework/Generic/…/framework/options` | about 5,000 used directly | M4 (`bk-program`) |
| A program builder for tests | `BASE/program/database/ProgramBuilder.java`, sample builders | — | M4, first: `bk-testkit` |
| A corpus of binaries | — | — | M4, with `ref-headless` |
| Read-only reader of Ghidra's packed databases (`.gdt`, `.fidb`) | `Framework/DB` (the read path), `SM/program/database/data` adapters | — | M4/M5 (proposed ADR) |
| `Ghidra/Features/*/data` and `Ghidra/Processors/*/data` files other than language specs: no-return name lists, `functionTags.xml`, the string model (`stringngrams`), syscall tables, Windows ordinal tables (`data/symbols`), parser profiles, pattern files, Rich-header products | `Ghidra/Features/Base/data` and others | — | ADR-002 covers processor data only; extend it: read in place, never copied |
| Block models | `SM/program/model/block` | 6,789 | M5 |
| Symbolic propagation | `BASE/program/util/{SymbolicPropogator,VarnodeContext}.java` | 5,206 | M5 |
| Memory and byte-pattern search engines | `BASE/features/base/memsearch` (8,142), `BASE/util/bytesearch` (4,590) | 12,732 | M5 (analyzers use `bytesearch`); the views are M7 |
| The file-system layer used by import (`FSRL`, `FileSystemService`, nested containers) | `BASE/formats/gfilesystem` | 9,252 | The core in M4; back ends stay in M10 |
| Source-file map, program trees, external manager, function tags, user data | `SM/program/database/{sourcemap,module,external}`, … | about 8,000 | M4 |
| `model.correlate`, `model.gclass` | `SM/program/model/` | 1,603; 680 | M10 (function hashing: Version Tracking, FID), M5/M9 (class recovery) |
| RTTI class recovery | `Features/Decompiler/ghidra_scripts/classrecovery` | 28,042 | After M5; its own track |
| `FunctionGraphDecompilerExtension` | `Ghidra/Features/` | 2,010 | M7 |
| `Debugger-importers`, `Debugger-dap`, `Debugger-jpda`, `AnnotationValidator`, agents `drgn` and `x64dbg` | `Ghidra/Debug/` | 1,139; 1,432; 7,554; 1,289; 2,449; 3,243 (Python) | M10; `AnnotationValidator` is a Java annotation processor: not applicable |
| `GhidraBuild`: Eclipse plug-ins (`GhidraDev`, the SLEIGH editor), the IDA export plug-ins, the extension skeleton, launch support | `GhidraBuild/` | not measured | Decide per item: the skeleton maps to a plugin template (M9); the SLEIGH editor to an editor integration; IDA export and `GhidraDev` are candidates for "out of scope", which needs the owner |
| Launch scripts and support tools (`analyzeHeadless`, `sleigh`, `bsim`, server administration, …) | `Ghidra/RuntimeScripts` | — | Sub-commands of the one binary, with the milestone of each |
| The help content | 252 HTML files, 78,045 lines under `src/main/help` | — | The documentation site (ADR-030) is the counterpart; nothing checks coverage against these files yet |
| The JIT emulator | `Framework/Emulation/…/pcode/emu/jit` | 45,439 | Decision needed (section 6) |
| The checklist's GUI flag | `docs/inventory/tests/` | — | Many program-database tests are flagged GUI because of their base class (for example 4 of 5 classes of `program.database.symbol`), not because they drive a window. M4 specifications must classify them by what they check |

## 4. Where `PLAN.md`'s "Order of work" is wrong or incomplete

1. **"The emulator and the assembler … need only M1 and M2."** Both need
   the Java-side language model (`sleigh-language`, M1's open item):
   `Emulation` imports `model.lang` in 97 files and the Java SLEIGH
   classes in 34; the assembler imports the Java SLEIGH classes in 59 of
   its 117 files. Neither needs M2. The emulator's *tests* need M4 and
   binaries that have to be built (fact 1).
2. **`sleigh-language` is listed as filler ("usable to fill a slot at any
   time").** By the source it is on the critical path: the disassembler,
   the code manager (instructions are stored as a prototype id,
   `SM/program/database/code/InstDBAdapter.java:38`), register values,
   the emulator and the assembler all start from it. It should be the
   next track started, not a spare one.
3. **The programs chain is drawn as one line** ("`bk-store`,
   `bk-program`, `bk-datatypes` → loaders → disassembly and analysis").
   By the source it is at least four lines that meet late: (a) data
   types, which need only memory reads through a small trait; (b) the
   address map, memory and the store; (c) the format parsers and the
   relocation tables, which need only bytes; (d) the disassembler core,
   which needs only `sleigh-language`. The long pole is narrower than the
   plan says and the width is greater (the plan in
   `docs/features/program-plan.md` shows it).
4. **"`ref-headless` and the storage decision → program-model plan and
   specs."** The storage decision does not have to come before the
   model's specification or even its first implementation, if the model
   is written against a table interface (the paused spike already drives
   five engines through one; `../store-spike/tools/store-spike/src/engine.rs`).
   What must come first is `ref-headless` **and the corpus**.
5. **"Editing commands with undo/redo" in M7.** Commands are M4/M5
   (section 2). Undo is a property of the program model and store (M4).
6. **"DWARF and PDB parsers (format parsing needs only `bk-bin`)"** is
   right for the readers, but in Ghidra the DWARF reader and applier are
   one package and PDB's applier is 24,000 lines; the specifications must
   cut there. The appliers are M4-dependent and are where the analysis
   value is.
7. **Demangler analyzers, FID's analyzer, the data-archive analyzer,
   `MicrosoftCodeAnalyzer`, the Objective-C, Swift, Rust and Go
   analyzers are on by default.** "Whole-binary differential tests
   against Ghidra headless" (M5's last item) cannot pass while they are
   in M6. Either M5's oracle runs with them off in Ghidra (possible:
   fact 4), or they move into M5. The plan should say which; this
   document proposes the first, with the comparison tightened as each
   lands.
8. **"About 2.4 million of Ghidra's 3.1 million lines"** are the Java
   side: measured, Java main is 2,348,155 lines and Java tests and
   screenshot generators 694,118. Of the main lines about 570,000 are
   Swing and its framework or replaced utilities (`Docking`, `Gui`,
   `Help`, `Generic`, `Utility`, the view packages of `Base`), so the
   figure overstates what is ported; section 5 has the estimate.

## 5. What can be pulled forward, because it needs only what exists

| Work | Needs | Why now |
|---|---|---|
| `sleigh-language` | M1 (on `master`) | Fact above: it gates four chains |
| The disassembler core (flow following into instruction blocks, context along paths, delay slots, conflicts inside a block) | `sleigh-language`, `bk-bin` | `Disassembler` has a program-free mode (section 2). It can be compared with Ghidra's own on raw bytes before any program model exists, and gives `basilisk disasm` on an ELF file through `bk-elf` alone |
| Data types (the in-memory model: built-ins, composites with packing and bit fields, enums, typedefs, function definitions, data organisation, conflict handling) | `bk-core`, `bk-cspec`'s data organisation; memory through a trait | 251 + 92 files; 61 test classes with 982 tests, none needing a binary |
| The C parser | Data types | Three test classes; the grammar is self-contained |
| PE, Mach-O and COFF parsers | `bk-bin` | The paused `spec-pe` track has five fact sheets (2,373 lines) and a crate experiment |
| DWARF and PDB *readers*, the Microsoft demangler, the GNU demangler | `bk-bin` only (`MicrosoftDmang` imports nothing else) | 1,711 + 212 tests wait for them |
| Relocation *tables* (type numbers, names, the arithmetic of each type as a pure function of symbol value, addend, address and bytes) | `bk-elf` | 22 ELF handlers are mostly such tables; applying them needs memory (M4) |
| A read-only reader for Ghidra's packed databases | `bk-bin` | Fact 3; it also lets tests read Ghidra's own `.gdt` content as a data-type corpus |
| `ref-headless` and the corpus | The build host | Blocks every acceptance |
| The address model of the program side (`AddressSet`, ranges, the factory, overlay and segmented spaces) | `bk-core` | 12 test classes with 141 tests; everything in M4 uses it |
| Binary, Intel hex and XML exporters | M4's first tracks | They are small (2,069 + 6,792 lines), and an XML export that Ghidra's `XmlLoader` can read is a second, independent comparison channel: Basilisk's program imported into Ghidra |
| The headless program comparison (`ProgramDiff`'s categories) | The dump readers | It defines "equal programs" category by category (`BASE/program/util/ProgramDiffFilter.java`); the oracle's comparison should use the same categories |
| Monitor type out of `bk-ui` | — | Binding constraint 7; every M4 crate needs it on day one |

## 6. Proposed corrected order

| Step | `PLAN.md` says | The source says | Proposed |
|---|---|---|---|
| 1 | `ref-headless` and the storage decision first | Both are leaves; the corpus is missing | `ref-headless` **with the corpus and the toolchains**, the storage spike finished in parallel; neither blocks specification |
| 2 | `sleigh-language` when a slot is free | Gates disassembly, code units, register values, emulator, assembler | Start it now, as a chain track |
| 3 | Program-model plan and specs | The model is one import cycle; it must be cut by what calls what | Specify in this order: addresses and the store interface; memory; data types (parallel); symbols and namespaces; code units; references; functions |
| 4 | `bk-store`, `bk-program`, `bk-datatypes`, then loaders | Data types, parsers, relocation tables and the disassembler core need none of the others | Run them beside the store and model chain |
| 5 | Loaders after the model | Loaders need memory, symbols, references, data, functions, relocations, external locations, properties, and commands (disassemble, create function, apply data) | Raw and hex loaders after memory; ELF after symbols, relocations and data types; PE and Mach-O after ELF's shared machinery |
| 6 | M5: disassembler, manager, analyzers, decompiler wiring | The disassembler core is early; analyzers need commands, block models, symbolic propagation; two default analyzers need M3 | Commands with the model (M4); the manager and the non-decompiler analyzers as soon as loaders import; whole-analysis parity after M3 |
| 7 | M6 after M5: exporters, DWARF, PDB, demanglers, FID, emulator, assembler | Exporters need only M4; readers and demanglers need only `bk-bin`; emulator and assembler need `sleigh-language`; emulator tests need M4 and built binaries | Readers and demanglers now (filler); exporters at the end of M4; appliers and default-on analyzers with M5; emulator and assembler any time after `sleigh-language` |
| 8 | M7 on real programs after M5 | `ProgramSource` needs memory blocks, listing rows, functions, symbols, references, strings, search, comments, edits (`crates/bk-ui/src/model/source.rs:96–145`) | A first adapter after the loaders, on an imported but unanalysed program; it grows with M5. The interface does not have to wait for analysis |
| 9 | M8 projects | A redesign over `bk-store`, not a port | Decide the versioning model when `bk-store`'s format is fixed, so the format can carry it |
| 10 | M10 the rest | Trace modelling, Version Tracking and BSim are database-backed models of their own | Unchanged, but each needs its own plan |

Decisions this order needs (proposed ADRs are in the track report):
reading Ghidra's packed databases read-only; `Features/*/data` read in
place like processor data; what replaces the JIT emulator; which
`GhidraBuild` items are out of scope.

## 7. Size per milestone, in Rust lines (an estimate)

**Method.** (1) Take the Java main lines each milestone covers
(measured, tables above). (2) Remove what is not ported by decision:
schema adapters for old versions (15,810), Swing code, the JIT's
bytecode generation. (3) Multiply by a ratio of Rust product lines to
ported source lines. The ratio is measured on the crates that have a
Ghidra counterpart of known size (`rust-sizes.tsv` against the track
sizes of `decomp-plan.md` and the package tables): `bk-decomp-range`
1.19, `bk-decomp-types` 1.14, `bk-cspec` 1.24, `bk-decomp-cfg` 1.19
(all four against C++), `bk-elf` 0.76 (10,224 against Java's 13,378,
with relocation classes and data-type layouts not ported), `bk-bin` 0.67
(3,519 against 5,262). Java is more verbose than C++ per unit of
behaviour (each file carries a 15-line licence header; accessors and
Javadoc), so **0.8** is used for Java, with a range of 0.6 to 1.0.
(4) Tests: 0.42 of product lines, the workspace's own ratio (56,303
test lines to 134,338 product lines). For the user interface no ratio
exists (`bk-ui` is 14,520 lines against demo data); 0.4 is a guess.

Every figure below is an **estimate**; the range is what the ratio's
range gives, not a confidence interval.

| Milestone | Java lines covered (measured parts, summed) | Rust product, estimated | With tests |
|---|---:|---:|---:|
| M4 | about 300,000: model without `lang` and `pcode` 78,000; database without old adapters 90,000; `program.util` and utilities 19,000; domain-object slice 5,000; loaders and importer 31,000; program-side code of PE, Mach-O, ELF 54,000 (upper bound: part is parsing); relocation handlers and extensions 17,000; C parser 8,000 | 240,000 (180,000–300,000), plus `bk-store` and the oracle tooling, about 15,000 (a guess) | 360,000 |
| M5 | about 160,000: disassembler 4,000; commands 19,000; manager 3,000; analyzers 37,000; block models 7,000; symbolic propagation and `util.state` 10,000; byte search 5,000; byte patterns without their views 7,000; exception tables 7,000; demangler framework 6,000; decompiler interface and result model 29,000; headless 4,000; processors' analyzers are in the 37,000; the rest of `Base`'s `program.util` and `app.util` about 20,000 | 130,000 (95,000–160,000) | 180,000 |
| M6 | about 270,000: PDB 92,000; DWARF 23,000; Go 17,000; demanglers 23,000 Java + 34,000 C; FID 10,000; emulator without the JIT 26,000; assembler 20,000; exporters and XML 9,000; `MicrosoftCodeAnalyzer`, Objective-C, Swift, Rust 31,000; `SystemEmulation` 9,000; Sarif 14,000 | 215,000 (160,000–270,000) | 305,000 |
| M7 | about 480,000 of views and their framework in `Base`, `Decompiler`, `DecompilerDependent`, `ByteViewer`, the graph modules, `ProgramDiff`, `CodeCompare`; the docking framework itself is replaced | 190,000 (a guess at 0.4) | 230,000 |
| M8 | 153,000 (`Project`, `FileSystem`, `GhidraServer`, merge), mostly redesigned | 60,000 (a guess) | 85,000 |
| M9 | — (`features/plugin-api.md`) | not estimated here | — |
| M10 | about 510,000: Debug 218,000 + 23,000 Python; Version Tracking 57,000; BSim 50,000; `FileFormats` 79,000; remaining loaders and formats 30,000; processors' other Java 20,000; extensions 27,000 | 330,000 (0.65: much of it is views) | 430,000 |
| **M4 to M10** | about 1,870,000 | **about 1,170,000** | **about 1,600,000** |

`master` holds about 190,000 lines today. `PLAN.md`'s "eight to ten
times that" for the full port is consistent with this estimate (8.4
times, tests included, before M3's remainder and M9). M4 alone is larger
than everything written so far.
