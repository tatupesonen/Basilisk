# Basilisk ↔ Ghidra parity matrix

Status of every Ghidra module against Basilisk. Updated by the coordinator
whenever a branch merges. Module contents are described in
`inventory/00-overview.md`; test status per class is in `inventory/tests/`.

Last updated: 2026-11-15 (`bk-decomp-cfg` merged). 2026-11-14: (`bk-decomp-range` merged; M2 complete: `bk-sleigh-snippet` merged, after `bk-sleigh-compiler` part 2 and `basilisk sleigh compile`; `bk-sleigh` part 2 — p-code generation and `basilisk disasm` — and `bk-cspec` merged; earlier the same day `bk-sla`, `bk-decomp-types`, `bk-sleigh` part 1 and `bk-sleigh-compiler` part 1; CI green on Linux, macOS and Windows). 2026-11-13: (`bk-ui` merged on demo data; `bk-binutils-sys` and `bk-gnu-disasm` merged; SLEIGH tracks specified, `sla` in progress). M0 complete 2026-11-12.

**Status legend**
- **Done**: implemented, its Ghidra tests marked, on `master`.
- **Partial**: some of it exists; the Notes say what is missing.
- **In progress**: a track is working on it now.
- **Missing**: nothing on `master` yet.
- **Replaced**: Basilisk provides the function by different means, by
  decision; Notes name the ADR.
- **Out of scope**: excluded by an owner decision (`DIRECTION.md`). None so far.

## Framework

| Ghidra module | Basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| SoftwareModeling: address, p-code model, float formats, op behaviour | `bk-core`, `bk-pcode` | M0 | Partial | `bk-pcode` and `bk-core` done for the decompiler/SLEIGH side (C++ model). Java's program-model address API and its 11 test classes wait for M4 |
| SoftwareModeling: language definitions (`.ldefs`, `.pspec`, opinions) | `bk-lang` | M0 | Partial | Readers, registry and opinion queries done. `.cspec` arrives with the decompiler (M3); old-language translators M8; `SleighLanguageProviderTest` partly ported (rest needs M2) |
| SoftwareModeling: SLEIGH runtime | `bk-sla`, `bk-sleigh` | M1 | Partial | On `master`: `bk-sla` (the compiled-language model, validating reader, byte-exact writers; all 150 reference `.sla` round-trip) and `bk-sleigh` (language loading, context database, instruction decoding, disassembly text, p-code generation with delay slots, crossbuild and user ops, `Translate`, and the command `basilisk disasm`: every record kind equals `pcodedump` over 175 language configurations, apart from counted cases where Ghidra reads stale memory or its two-entry parse cache; 37 instructions that crash `pcodedump` lift; single-threaded at or above Ghidra's C++ engine on both x86-64 Linux (decode 1.11×, decode + p-code level at 1.00×) and the M1 (1.32×, 1.38×), 6.7–7.9× at 8 threads, no allocation per instruction). Missing: the Java-side language services (`sleigh-language`). |
| SoftwareModeling: SLEIGH compiler | `bk-sleigh-syntax`, `bk-sleigh-compiler` | M0, M2 | Partial | Done: preprocessor, lexer, parser, semantic analysis, pattern resolution, decision trees and `.sla` output; all 150 specifications compile to the same bytes as Ghidra's compiler; the p-code snippets of every shipped `.cspec` and `.pspec` compile to Ghidra's templates (`bk-sleigh-snippet`) |
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

| Ghidra part | Basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| CORE (xml, marshal, space, address, translate, opcodes, float) | `bk-core`, `bk-marshal`, `bk-pcode` | M0 | Partial | Done except `Translate`/`PcodeEmit`, `PcodeOpRaw` and the context database (M1) |
| SLEIGH runtime | `bk-sla`, `bk-sleigh` | M1 | Partial | On `master`: `bk-sla` (the compiled-language model, validating reader, byte-exact writers; all 150 reference `.sla` round-trip) and `bk-sleigh` (language loading, context database, instruction decoding, disassembly text, p-code generation with delay slots, crossbuild and user ops, `Translate`, and the command `basilisk disasm`: every record kind equals `pcodedump` over 175 language configurations, apart from counted cases where Ghidra reads stale memory or its two-entry parse cache; 37 instructions that crash `pcodedump` lift; as fast as Ghidra's engine or faster, no allocation per instruction). Missing: the Java-side language services (`sleigh-language`); 8-thread scaling of 6× not yet shown on an idle machine. |
| SLEIGH compiler | `bk-sleigh-compiler` | M2 | Partial | Complete on `master`: all 150 specifications compile to `.sla` files byte-identical to those of Ghidra's compiler (the XML form and the warnings too), with no tolerated difference; `basilisk sleigh compile` with Ghidra's C++ and Java options; 117 diagnostic cases agree with Ghidra's compiler; about 2.9× faster than it over all 150. P-code snippets (`bk-sleigh-snippet`): all 137 snippet elements of the shipped compiler and processor specifications (588 compilations over 116 languages) equal Ghidra's templates, as do 236 hand-written cases and 200,000 generated ones with no tolerated difference (bit ranges wrap at 32 bits as Ghidra's do). Missing: a compile cannot be cancelled or report progress yet. |
| Decompiler engine (DECCORE) | `bk-decomp-*`, `bk-cspec` (ADR-026) | M3 | Partial | Planned in 31 tracks (`features/decomp-plan.md`). On `master`: `bk-decomp-range` (D01: `CircleRange`, the value ranges under jump-table recovery and value-set analysis; all 117 Ghidra tests ported; every row of oracle tables from both reference builds matched, undefined arithmetic defined by ADR-041), `bk-decomp-types` (D02: types, factory, orderings, XML, C declaration parser) and `bk-cspec` (D03: every shipped `.cspec` read, parameter lists, prototype models, storage assignment and `FuncProto`; every oracle row replayed against Ghidra built with libc++ and with libstdc++ — two tables of 152,046 rows, which agree except in 119 rows where Ghidra's unstable sorts make its own answer depend on the C++ library; there Basilisk sorts stably, ADR-040, each such row recognised by cause and counted). Also on `master`: `bk-decomp-cfg` (D04: the block graph, its analyses, the structured-block hierarchy and the control-flow structurer; 4,000 generated graphs structure byte-identically to Ghidra's `structure blocks` on both reference builds; the comparison against real functions waits for the oracle tooling, D00). Everything else is missing: IR, symbols, flow, heritage, rules, actions, merging, structuring, printing. |
| Ghidra pipe protocol (GHIDRA) | trait in `bk-decomp` | M5 | Replaced | In process (ADR-004) |
| Console and test runner | `basilisk decompile`, data-test runner | M3 | Missing | |
| BSim signatures | `bk-bsim` | M10 | Missing | |
| C++ unit tests (205), data tests (93) | — | M0–M3 | Missing | Float and marshal tests in wave 1 |

## Features

| Ghidra module | Basilisk | Milestone | Status | Notes |
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

| Ghidra part | Basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| Language data for 39 processor modules | read in place | M0–M2 | Reused | ADR-002 |
| Relocation handlers | `bk-loader-*` | M4 | Missing | |
| Processor analyzers and extensions | `bk-analyzers-*` | M5, M10 | Missing | |
| Emulator tests (126 classes) | `bk-emu` tests | M6 | Missing | |

## Debug, Extensions

| Ghidra module | Basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| Framework-TraceModeling, Debugger, Debugger-api, Debugger-rmi-trace, agents, ISF, TaintAnalysis, ProposedUtils | `bk-debug-*` | M10 | Missing | |
| Extensions (Jython, BSimElastic, MachineLearning, Lisa, SymbolicSummaryZ3, samples) | — | M10 | Missing | Decide per extension when reached |
| Extensions/SleighDevTools (p-code test framework) | `bk-testkit`, `bk-emu` tests | M6 | Missing | `bk-testkit` exists (oracle wrappers); the p-code test framework itself is M6 |

## Ghidra's GPL modules (ADR-018)

Ported like any other code, as ordinary crates called directly.

| Ghidra module | Basilisk | Milestone | Status | Notes |
|---|---|---|---|---|
| GPL/DemanglerGnu (libiberty demangler, versions 2.24 and 2.41) | `bk-demangle-gnu` | M6 | Missing | |
| GPL/GnuDisassembler (`gdis` over binutils) | `bk-binutils-sys`, `bk-gnu-disasm` | M10 | Partial | On `master`: binutils 2.41 built from source (ADR-019), safe API, `.gdis` configuration, all 65 of Ghidra's `gnu` names resolve. Missing: the listing field (M7) and the block script (M9) that use it; `bk-lang`'s external names are not wired to it yet. Windows verified under Wine only. |
| GPL/DMG (DMG/HFS+ reader) | `bk-fs-dmg` | M10 | Missing | |
