# basilisk ↔ Ghidra parity matrix

Status of every Ghidra module against basilisk. Updated by the coordinator
whenever a branch merges. Module contents are described in
`inventory/00-overview.md`; test status per class is in `inventory/tests/`.

Last updated: 2026-11-13 (`bk-ui` merged on demo data; `bk-binutils-sys` and `bk-gnu-disasm` merged; SLEIGH tracks specified, `sla` in progress). M0 complete 2026-11-12.

**Status legend**
- **Done**: implemented, its Ghidra tests marked, on `master`.
- **Partial**: some of it exists; the Notes say what is missing.
- **In progress**: a track is working on it now.
- **Missing**: nothing on `master` yet.
- **Replaced**: basilisk provides the function by different means, by
  decision; Notes name the ADR.
- **Out of scope**: excluded by an owner decision (`DIRECTION.md`). None so far.

## Framework

| Ghidra module | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| SoftwareModeling: address, p-code model, float formats, op behaviour | `bk-core`, `bk-pcode` | M0 | Partial | `bk-pcode` and `bk-core` done for the decompiler/SLEIGH side (C++ model). Java's program-model address API and its 11 test classes wait for M4 |
| SoftwareModeling: language definitions (`.ldefs`, `.pspec`, opinions) | `bk-lang` | M0 | Partial | Readers, registry and opinion queries done. `.cspec` arrives with the decompiler (M3); old-language translators M8; `SleighLanguageProviderTest` partly ported (rest needs M2) |
| SoftwareModeling: SLEIGH runtime | `bk-sla`, `bk-sleigh` | M1 | In progress | Specified (ADR-023, ADR-024; `features/sla.md`, `sleigh-decode.md`, `sleigh-pcode.md`). Track `sla` running; nothing on `master` yet. |
| SoftwareModeling: SLEIGH compiler | `bk-sleigh-syntax`, `bk-sleigh-compiler` | M0, M2 | Partial | Front end done: preprocessor, lexer, parser, checked against Ghidra's compiled output for all 150 specs. Semantic analysis and `.sla` output are M2 |
| SoftwareModeling: program model and database | `bk-program`, `bk-datatypes`, `bk-store` | M4 | Missing | |
| SoftwareModeling: disassembler | `bk-disasm` | M5 | Missing | |
| SoftwareModeling: assembler | `bk-asm` | M6 | Missing | |
| DB | `bk-store` | M4 | Missing | Own format (ADR-003) |
| Emulation | `bk-emu` | M6 | Missing | |
| Generic, Utility | — | — | Replaced | Rust std and crates; parts land where used. Tests ported or marked N/A per class (ADR-006) |
| Project, FileSystem | `bk-project` | M8 | Missing | |
| Docking, Gui, Help | `bk-ui` | M7 | Partial | Replaced by egui (ADR-008). On `master` against demo data: design system, menus, tool bar, key bindings from one action registry, docking with native pop-out windows, layout persistence. Help is missing. No Ghidra GUI tests ported yet. |
| Graph | `bk-graph`, `bk-ui` | M5, M7 | Missing | |
| Pty | `bk-debug-*` | M10 | Missing | |

## Decompiler (C++)

| Ghidra part | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| CORE (xml, marshal, space, address, translate, opcodes, float) | `bk-core`, `bk-marshal`, `bk-pcode` | M0 | Partial | Done except `Translate`/`PcodeEmit`, `PcodeOpRaw` and the context database (M1) |
| SLEIGH runtime | `bk-sla`, `bk-sleigh` | M1 | In progress | Specified (ADR-023, ADR-024; `features/sla.md`, `sleigh-decode.md`, `sleigh-pcode.md`). Track `sla` running; nothing on `master` yet. |
| SLEIGH compiler | `bk-sleigh-compiler` | M2 | Missing | |
| Decompiler engine (DECCORE) | `bk-decomp`, `bk-decomp-print` | M3 | Missing | |
| Ghidra pipe protocol (GHIDRA) | trait in `bk-decomp` | M5 | Replaced | In process (ADR-004) |
| Console and test runner | `basilisk decompile`, data-test runner | M3 | Missing | |
| BSim signatures | `bk-bsim` | M10 | Missing | |
| C++ unit tests (205), data tests (93) | — | M0–M3 | Missing | Float and marshal tests in wave 1 |

## Features

| Ghidra module | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| Base: byte providers, `BinaryReader` | `bk-bin` | M0 | Done | Ghidra's reader and provider tests ported. `MemoryByteProvider` needs program memory (M4) |
| Base: ELF format | `bk-elf` | M0 | Partial | Parser done (tolerant; checked against `object` and lld). Not ported: GNU build attributes, data-type layouts. The ELF loader and relocation handlers are M4 |
| Base: PE, Mach-O, COFF, OMF, NE, MZ, PEF, SOM, XCOFF, a.out formats | `bk-pe`, `bk-macho`, … | M4, M10 | Missing | PE and Mach-O planned for wave 2 |
| Base: DWARF, Go | `bk-dwarf`, `bk-golang` | M6 | Missing | |
| Base: loaders, opinions, importer | `bk-loader*` | M4 | Missing | |
| Base: commands | `bk-program` (operations) | M4–M5 | Missing | |
| Base: analyzers | `bk-analysis`, `bk-analyzers-*` | M5 | Missing | |
| Base: headless analyzer | `bk-headless`, `basilisk analyze` | M5 | Missing | |
| Base: exporters, XML, C parser | `bk-export`, `bk-datatypes` | M6 | Missing | |
| Base: scripting | `bk-plugin` | M9 | Missing | Python through PyO3 (ADR-014) |
| Base: UI plugins (87 packages) | `bk-ui` | M7 | Partial | Against demo data only (`features/ui-shell.md`, `features/ui-design.md`): Listing, Decompiler view, Functions, Defined Strings, References, Search, Symbol Tree, Program Trees, Console, Go To, rename/label/comment dialogs. Missing: Data Type Manager, Function Graph, Bookmarks, Memory Map, byte viewer, everything needing a real program. |
| Base: program merge | `bk-project` | M8 | Missing | |
| Decompiler (Java): interface, result model, UI | `bk-decomp`, `bk-ui` | M5, M7 | Missing | |
| DecompilerDependent | `bk-analyzers-*` | M5 | Missing | |
| PDB | `bk-pdb` | M6 | Missing | |
| MicrosoftDmang, MicrosoftDemangler | `bk-demangle-ms` | M6 | Missing | Parser planned for wave 2 |
| GnuDemangler | `bk-demangle-gnu` | M6 | Missing | The analyzer and result model, calling the ported libiberty demangler directly (ADR-018) |
| MicrosoftCodeAnalyzer | `bk-analyzers-msvc` | M6 | Missing | |
| FunctionID | `bk-fid` | M6 | Missing | |
| BytePatterns | `bk-analyzers-*` | M5 | Missing | |
| SystemEmulation | `bk-emu` | M6 | Missing | |
| Sarif | `bk-export` | M6 | Missing | |
| Swift, Rust, Objective-C, GhidraGo | `bk-analyzers-*` | M6 | Missing | |
| WildcardAssembler | `bk-asm` | M6 | Missing | |
| ProgramDiff, CodeCompare | `bk-ui`, `bk-program` | M7 | Missing | |
| FunctionGraph, GraphServices, GraphFunctionCalls, ProgramGraph, DataGraph | `bk-ui` | M7 | Missing | |
| ByteViewer | `bk-ui` | M7 | Missing | |
| GhidraServer | `bk-server` | M8 | Missing | |
| PyGhidra | `bk-plugin` | M9 | Missing | The same PyO3 bindings as an importable module (ADR-014) |
| FileFormats | `bk-fs-*` | M10 | Missing | |
| VersionTracking, VersionTrackingBSim | `bk-vt` | M10 | Missing | |
| BSim, BSimFeatureVisualizer | `bk-bsim` | M10 | Missing | |
| Recognizers, SourceCodeLookup, DebugUtils | as reached | M10 | Missing | |

## Processors

| Ghidra part | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| Language data for 39 processor modules | read in place | M0–M2 | Reused | ADR-002 |
| Relocation handlers | `bk-loader-*` | M4 | Missing | |
| Processor analyzers and extensions | `bk-analyzers-*` | M5, M10 | Missing | |
| Emulator tests (126 classes) | `bk-emu` tests | M6 | Missing | |

## Debug, Extensions

| Ghidra module | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| Framework-TraceModeling, Debugger, Debugger-api, Debugger-rmi-trace, agents, ISF, TaintAnalysis, ProposedUtils | `bk-debug-*` | M10 | Missing | |
| Extensions (Jython, BSimElastic, MachineLearning, Lisa, SymbolicSummaryZ3, samples) | — | M10 | Missing | Decide per extension when reached |
| Extensions/SleighDevTools (p-code test framework) | `bk-testkit`, `bk-emu` tests | M6 | Missing | `bk-testkit` exists (oracle wrappers); the p-code test framework itself is M6 |

## Ghidra's GPL modules (ADR-018)

Ported like any other code, as ordinary crates called directly.

| Ghidra module | basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| GPL/DemanglerGnu (libiberty demangler, versions 2.24 and 2.41) | `bk-demangle-gnu` | M6 | Missing | |
| GPL/GnuDisassembler (`gdis` over binutils) | `bk-binutils-sys`, `bk-gnu-disasm` | M10 | Partial | On `master`: binutils 2.41 built from source (ADR-019), safe API, `.gdis` configuration, all 65 of Ghidra's `gnu` names resolve. Missing: the listing field (M7) and the block script (M9) that use it; `bk-lang`'s external names are not wired to it yet. Windows verified under Wine only. |
| GPL/DMG (DMG/HFS+ reader) | `bk-fs-dmg` | M10 | Missing | |
