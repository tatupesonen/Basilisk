# 00 — Ghidra source map (overview inventory)

Source of truth: the Ghidra tree at `../ghidra`, commit `42db038f3c`
(2026-11-10), read-only. This document maps the whole tree so later
inventories and feature specs can point into it. Line counts are lines of
Java (main and test source) unless stated, rounded. Area inventories
(`01-…`, `02-…`) are written by the coordinator when their milestone is
planned (`LOOP.md`); the test checklist is `tests/`.

## 1. Top level

| Path | What it is |
|---|---|
| `Ghidra/Framework/` | Libraries everything else builds on: utilities, storage, program model, SLEIGH, emulation, the Swing docking framework, projects |
| `Ghidra/Features/` | The application: loaders, analyzers, the decompiler, UI plugins, and the larger tools (PDB, Version Tracking, BSim, …) |
| `Ghidra/Processors/` | One module per processor family: SLEIGH specs and other language data (`data/`), plus Java for relocations, analyzers and loader extensions |
| `Ghidra/Debug/` | The debugger: trace model, UI, agents for gdb/lldb/dbgeng/…, taint analysis |
| `Ghidra/Extensions/` | Optional extensions: Jython, BSim Elastic, machine learning, Lisa, SleighDevTools (the p-code test framework), samples |
| `Ghidra/Test/` | Cross-module integration tests (`IntegrationTest`, `DebuggerIntegrationTest`) and `TestResources` (test binaries and programs) |
| `Ghidra/RuntimeScripts/`, `Configurations/` | Launch scripts and the release configuration |
| `GPL/` | GPL-licensed helpers: GNU demangler and disassembler wrappers, DMG. Not ported from source (ADR-010) |
| `GhidraBuild/`, `GhidraDocs/`, `gradle/` | Build infrastructure and documentation |

A Ghidra module is a directory with `src/main/java`, optional
`src/test/java` (unit tests), `src/test.slow/java` (integration tests),
`src/test.processors/java` (p-code emulator tests), `src/screen/java`
(help screenshot generators), `data/` and `ghidra_scripts/`.

## 2. Framework

| Module | Lines | Contents | basilisk |
|---|---:|---|---|
| `SoftwareModeling` | 358,000 | **Program model** (`ghidra.program.model.*`, 124,000: address, memory, listing, symbol, data types, language, p-code) and its **database implementation** (`ghidra.program.database.*`, 108,000). **SLEIGH runtime** in Java (`ghidra.app.plugin.processors.sleigh`, 16,000) and the **SLEIGH compiler** in Java (`ghidra.pcodeCPort`, 19,000, a port of the C++; grammar in `src/main/antlr`, 4,200 lines of ANTLR). **Assembler** (`ghidra.app.plugin.assembler`, 18,000). P-code utilities, float formats and op behaviours (`ghidra.pcode`). Disassembler (`ghidra.program.disassemble`) | `bk-core`, `bk-pcode`, `bk-sleigh*`, `bk-lang`, `bk-program`, `bk-datatypes`, `bk-store`, `bk-disasm`, `bk-asm` |
| `DB` | 45,000 | Ghidra's own storage engine: buffer files, B-tree tables with long/fixed/variable keys, indexes, chained buffers, transactions, versioned buffer files | `bk-store` (own design, ADR-003) |
| `Emulation` | 78,000 | P-code emulator (`ghidra.pcode.emu`, `exec`), the older `emulate` package, user-op libraries, the p-code JIT | `bk-emu` |
| `Generic` | 94,000 | Utilities: collections, tasks and monitors, options, XML helpers, class discovery, timers, text | Mostly replaced by Rust std and crates; the rest lands where it is used |
| `Utility` | 13,000 | Module and application layout, launchers, logging bootstrap | Replaced |
| `Project` | 87,000 | Projects, domain objects and files, tools and plugins framework, options, remote repository client | `bk-project` (M8) |
| `FileSystem` | 25,000 | Local and versioned file-system layer for projects, item storage | `bk-project` (M8) |
| `Docking` | 184,000 | Swing docking windows, actions, tables, trees, dialogs, theming | Replaced by egui; behaviour that users see is reproduced in `bk-ui` |
| `Gui`, `Help` | 42,000 | Theme engine, help system | `bk-ui` |
| `Graph` | 40,000 | Graph algorithms and the visual graph framework | `bk-graph` (algorithms), `bk-ui` |
| `Pty` | 10,000 | Pseudo-terminals for the debugger | `bk-debug-*` (M10) |

## 3. The decompiler and SLEIGH in C++

`Ghidra/Features/Decompiler/src/decompile/cpp` — 190,000 lines in one flat
directory. The Makefile groups the sources; the same groups guide the
crate split.

| Group | Files (main ones, lines) | What it is |
|---|---|---|
| `CORE` | `xml` (2,500), `marshal` (1,400), `space` (700), `float` (700), `address` (1,200), `pcoderaw`, `translate` (1,100), `opcodes`, `globalcontext` (600) | Encoding, address spaces, addresses, raw p-code, the `Translate` interface, the context database |
| `SLEIGH` | `sleigh` (800), `sleighbase` (400), `slghsymbol` (2,500), `slghpattern` (1,000), `slghpatexpress` (1,700), `semantics` (1,100), `context` (300), `slaformat` (260), `pcodeparse` (3,300), `pcodecompile` (950), `filemanage` | SLEIGH runtime: `.sla` loading, decision trees, instruction decoding, p-code templates; the p-code snippet parser used for injection |
| `SLACOMP` | `slgh_compile` (4,100), `slghparse` (bison output of `slghparse.y`), `slghscan` (flex output of `slghscan.l`, includes the preprocessor) | SLEIGH compiler |
| `DECCORE` | `ruleaction` (11,000), `coreaction` (6,200), `fspec` (5,900), `type` (5,200), `subflow` (4,200), `block` (3,800), `double` (3,600), `database` (3,600), `printc` (3,600), `jumptable` (2,900), `heritage` (2,900), `typeop` (2,800), `rangeutil` (2,600), `bitfield` (2,400), `blockaction` (2,400), `funcdata*` (5,800), `varnode` (2,000), `modelrules` (2,000), `varmap` (1,800), `merge` (1,700), `architecture` (1,600), `flow` (1,500), `op`, `unionresolve`, `prettyprint`, `variable`, `action`, `options`, `constseq`, `transform`, `dynamic`, `cover`, `cast`, `cpool`, `userop`, `stringmanage`, `pcodeinject`, `paramid`, `comment`, `override`, `loadimage*`, `capability`, `graph` | The decompiler engine |
| `GHIDRA` | `ghidra_arch`, `ghidra_process`, `ghidra_translate`, `ghidra_context`, `loadimage_ghidra`, `typegrp_ghidra`, `database_ghidra`, `inject_ghidra`, `cpool_ghidra`, `comment_ghidra`, `string_ghidra`, `signature_ghidra` | The pipe protocol to the Ghidra JVM (`RegisterProgram`, `DecompileAt`, `StructureGraph`, `SetAction`, `SetOptions`, …). Replaced by an in-process trait (ADR-004) |
| `EXTRA` / console | `ifacedecomp` (3,800), `interface`, `ifaceterm`, `consolemain`, `testfunction`, `codedata`, `callgraph`, `raw_arch`, `xml_arch`, `sleigh_arch`, `libdecomp`, `unify`, `rulecompile`, `signature` (BSim features), `analyzesigs` | The standalone console (`decomp`), its test runner (`decomp_test`: runs `datatests/*.xml` and `unittests/*.cc`), BSim signature generation |

Tests beside it: `../unittests` (7 files, 205 `TEST` cases: circle ranges
117, float emulation 31, function prototypes 21, marshalling 18, types 8,
multiprecision 5, parameter store 5) and `../datatests` (93 XML files, each
a self-contained program fragment with a script and expected-output
regular expressions).

Where Java and C++ both implement something (SLEIGH runtime and compiler,
p-code op behaviour, float formats, address spaces), **the C++ is
authoritative for the decompiler and SLEIGH tracks and the Java for the
program-model tracks**; the feature spec says which, and tests from both
sides are ported.

The Java side of the decompiler (`Features/Decompiler/src/main/java`,
70,000 lines) is the process wrapper (`DecompInterface`,
`DecompileProcess`, `DecompileCallback`), the result model (`ClangToken*`,
`HighFunction` lives in SoftwareModeling), and the decompiler UI panel.

## 4. Features

| Module | Lines | Contents | Milestone |
|---|---:|---|---|
| `Base` | 1,057,000 | Binary formats (`app.util.bin.format`: PE 32,000, DWARF 23,000, Mach-O 19,000, Go 17,000, ELF 13,000, OMF, COFF, SOM, PEF, NE, XCOFF, a.out, MZ); byte providers and `BinaryReader`; loaders and opinions (`app.util.opinion`, 28,000: ELF, PE, Mach-O, dyld cache, COFF, MS COFF, OMF, OMF-51, NE, MZ, COM, PEF, SOM, a.out, raw, Intel hex, Motorola hex, XML, GZF, GDT, DEF, MAP, DBG); importer; commands (`app.cmd`, 19,000); analyzers (`app.plugin.core.analysis` and others, about 120 analyzers); the 87 plugin packages under `app.plugin.core` (code browser, listing fields, symbol tree and table, data type manager, composite editor, memory map, search, scripting, bookmarks, references, function editor, …); program merge (40,000); scripting (`GhidraScript`, `FlatProgramAPI`); headless analyzer; exporters; XML and C parsers; demangler framework | M4–M7 |
| `Decompiler` | 70,000 + C++ | See section 3 | M3, M5 |
| `DecompilerDependent` | 18,000 | Analyzers and features that call the decompiler | M5 |
| `PDB` | 175,000 | PDB/MSF reader, type and symbol records, applier | M6 |
| `MicrosoftDmang`, `MicrosoftDemangler` | 37,000 | Microsoft C++ name demangler and its analyzer (1,711 tests) | M6 (parser in wave 2) |
| `GnuDemangler` | 8,700 | Parser for GNU demangler output and its analyzer | M6 |
| `MicrosoftCodeAnalyzer` | 16,000 | RTTI, exception-handling structures, MSVC patterns | M6 |
| `FileFormats` | 82,000 | File-system browser back ends: Android, iOS, archives, firmware images, crash dumps | M10 |
| `VersionTracking`, `VersionTrackingBSim` | 88,000 | Correlators, match tables, markup migration | M10 |
| `BSim`, `BSimFeatureVisualizer` | 53,000 | Function similarity database and search | M10 |
| `FunctionID` | 14,000 | Function ID databases and matching | M6 |
| `BytePatterns` | 15,000 | Function-start pattern mining and matching | M5 |
| `ProgramDiff`, `CodeCompare` | 21,000 | Program diff and side-by-side comparison | M7 |
| `FunctionGraph`, `GraphServices`, `GraphFunctionCalls`, `ProgramGraph`, `DataGraph` | 48,000 | Graph views | M7 |
| `ByteViewer` | 15,000 | Hex view and editors | M7 |
| `SystemEmulation` | 13,000 | System-call emulation libraries | M6 |
| `Sarif` | 16,000 | SARIF import and export | M6 |
| `Swift`, `Rust`, `Objective-C`, `GhidraGo` | 24,000 | Language-specific demangling, metadata and analysis | M6 |
| `WildcardAssembler` | 3,300 | Assembler with wildcards | M6 |
| `GhidraServer` | 11,000 | Multi-user repository server | M8 |
| `PyGhidra` | 2,300 | CPython integration | M9 |
| `Recognizers`, `SourceCodeLookup`, `DebugUtils` | 2,300 | Small helpers | as reached |

## 5. Processors

39 modules under `Ghidra/Processors`, 150 `.slaspec` files, 110 `.cspec`
files, 310,000 lines of SLEIGH. Each `data/languages` directory holds:

| File | Purpose |
|---|---|
| `*.ldefs` | Language definitions: id (`x86:LE:64:default`), endianness, size, variant, version, `.sla` and `.pspec` names, compiler specs, external tool names |
| `*.slaspec`, `*.sinc` | SLEIGH source and includes |
| `*.sla` | Compiled SLEIGH (built by Ghidra's build; not in the source tree) |
| `*.pspec` | Processor spec: program counter, context defaults, tracked registers, register groups and vector lanes, default symbols and memory blocks, properties |
| `*.cspec` | Compiler spec: data organisation, stack pointer, calling conventions (prototype models), call fixups, injections |
| `*.opinion` | Which language and compiler a loader should pick for a given machine type and flags |
| `*.dwarf`, `*.gdis`, `*.register.info` | DWARF register mapping and other per-tool data |

`data/patterns` holds function-start patterns; `data/manuals` the manual
indexes. Processor Java code (59,000 lines) holds ELF/COFF/Mach-O
relocation handlers, processor-specific analyzers, loader extensions and
emulator state modifiers; `src/test.processors` holds the p-code emulator
tests (126 classes) that run compiled test binaries from the
SleighDevTools p-code test suite.

## 6. Debugger

`Ghidra/Debug` (270,000 lines): `Framework-TraceModeling` (trace database),
`Debugger` (UI and services), `Debugger-api`, `Debugger-rmi-trace` (the
remote-method protocol to back ends), agents for gdb, lldb, dbgeng, drgn,
x64dbg, JPDA and DAP, `Debugger-isf`, `TaintAnalysis`, `ProposedUtils`.
Milestone M10.

## 7. Tests

`tests/README.md` lists the totals by module. Kinds:

| Kind | Where | Count | Port as |
|---|---|---:|---|
| Unit | `src/test/java` | 9,849 `@Test` | Rust unit tests |
| Slow / integration | `src/test.slow/java` | 8,836 | Rust integration tests; GUI ones as `egui_kittest` |
| Screenshot generators | `src/screen/java` | 538 | `egui_kittest` snapshot tests of the same views |
| Processor emulator tests | `src/test.processors/java` | 126 classes | Emulator runs of the same p-code test binaries (M6) |
| Decompiler C++ unit tests | `decompile/unittests` | 205 | Rust unit tests |
| Decompiler data tests | `decompile/datatests` | 93 | Data-test runner in `bk-decomp` |

801 of the 1,706 JUnit classes drive the Swing GUI (ADR-006).
