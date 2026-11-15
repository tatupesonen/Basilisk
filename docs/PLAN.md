# Basilisk — plan

Basilisk is a Rust reimplementation of Ghidra, aiming for full parity and
then better. The owner's decisions are in `DIRECTION.md`; architecture
decisions in `DECISIONS.md`; how work proceeds in `LOOP.md`; what Ghidra
contains in `inventory/`; per-feature specs in `features/`; status against
Ghidra in `PARITY.md`.

## Goals

1. **Parity.** Everything Ghidra does, module by module, headless core
   first. Ghidra's processor specifications work unchanged (ADR-002).
2. **Better where it can be.** Not a one-to-one port: improve on Ghidra
   when the result is better, and document each difference (ADR-001).
3. **Speed.** Language load, disassembly and decompilation at least as fast
   as Ghidra's; analysis parallel where it is safe; a UI that never blocks
   (ADR-012).
4. **Trustworthy.** Panic-free on hostile binaries (ADR-009), every Ghidra
   test ported (ADR-006), output checked against Ghidra itself (ADR-007).

## What is being reimplemented

Ghidra at commit `42db038f3c` is about 2.9 million lines of Java, 190,000
lines of C++ (the decompiler and the SLEIGH compiler) and 310,000 lines of
SLEIGH specification that Basilisk reuses. `inventory/00-overview.md` maps
every module. The largest parts:

| Ghidra part | Size | What it is |
|---|---:|---|
| `Features/Base` | 1,057,000 lines Java | Loaders and binary formats, analyzers, commands, the listing and most UI plugins, scripting, headless mode |
| `Framework/SoftwareModeling` | 358,000 | Program model and its database implementation, SLEIGH runtime and compiler (Java), assembler, p-code model |
| Decompiler C++ | 190,000 lines C++ | Decompiler engine, SLEIGH compiler and runtime (C++) |
| `Framework/Docking`, `Gui`, `Help` | 227,000 | Swing docking framework — replaced by egui, not ported |
| `Features/PDB` | 175,000 | PDB parser and applier |
| `Debug/*` | 270,000 | Debugger, trace database, agents |
| `Framework/Generic`, `Utility`, `Project`, `DB`, `FileSystem` | 265,000 | Utilities, project and storage layers |
| `Framework/Emulation` | 78,000 | P-code emulator, JIT |
| `Features/VersionTracking`, `BSim`, `FunctionID`, `ProgramDiff` | 160,000 | Cross-program analysis |
| `Processors/*` | 59,000 lines Java + specs | Per-processor relocation handlers, analyzers, extensions |

## Architecture

Planned crates (those marked ● exist or are in the current wave):

```
 basilisk ● (bin: CLI now; GUI from M7)
   ├── bk-ui (egui)                          bk-plugin, bk-plugin-ui, basilisk-py (Python plugins; extension module, ADR-035)
   ├── bk-headless (import → analyse → export pipeline)
   │
   ├── analysis        bk-analysis (auto-analysis manager, analyzer trait)
   │                   bk-analyzers-* (function start, references, switch tables, data, strings, …)
   │                   bk-disasm (flow-following disassembler)      bk-fid   bk-demangle-gnu  bk-demangle-ms
   │
   ├── decompiler      bk-decomp (pipeline, API, parallel driver)   bk-decomp-out, bk-decomp-print (two-stage printer)
   │                   passes: bk-decomp-{flow,heritage,actions,jumptable,merge,struct,typeop}, bk-decomp-rules-* (nine families)
   │                   state: bk-decomp-core, -symbols, -ir, -cfg, -types, -range   bk-cspec (.cspec, prototype models)   (ADR-026)
   │
   ├── program         bk-program (memory, listing, symbols, references, functions, …)
   │                   bk-datatypes (types, archives, C parser)     bk-store (program database, ADR-003)
   │
   ├── import          bk-loader (opinions, loader trait, import)   bk-loader-elf, -pe, -macho, -raw, …
   │                   bk-elf ●  bk-pe  bk-macho  bk-coff  bk-dwarf  bk-pdb  …   (pure format parsers)
   │                   bk-bin ● (byte providers, binary reader)
   │
   ├── language        bk-sleigh (runtime: decode, disassemble, lift)   bk-sleigh-compiler (.slaspec → .sla)
   │                   bk-sla ● (compiled-language model, reader, writer; ADR-023)   bk-sleigh-snippet (p-code snippets)
   │                   bk-language (registers, flow and operand types, overrides; later wave)
   │                   bk-sleigh-syntax ● (preprocessor, lexer, parser)  bk-lang ● (.ldefs, .pspec, .opinion, registry)
   │                   bk-emu (p-code emulator)   bk-asm (assembler)
   │
   └── foundation      bk-pcode ● (opcodes, op behaviour, float formats)
                       bk-marshal ● (encoder/decoder: XML and packed)   bk-core ● (address spaces, addresses, varnodes)
                       bk-testkit ● (fixtures, reference-tool oracles; dev only)
```

Dependency rules: arrows point down only. Format parsers (`bk-elf`, …)
depend only on `bk-bin`; they know nothing about programs. `bk-sleigh*`
know nothing about programs. `bk-decomp` depends on the language and
foundation layers and reaches the program through a trait (ADR-004), so it
can be tested standalone on Ghidra's data tests. Nothing below `bk-ui`
depends on it. `bk-testkit` is a dev-dependency only. Basilisk ships as
a single binary; Ghidra's GPL modules are ported as ordinary crates
(ADR-018).

Crates are split further as components grow (ADR-013); this map is updated
in the same commit that adds or splits a crate.

### Data flow (headless core)

1. **Import** (`bk-loader` over the format crates): pick a loader and a
   language/compiler pair through the `.opinion` files, map sections into
   program memory, apply relocations, create symbols and entry points.
2. **Language** (`bk-lang`, `bk-sleigh`): load the `.sla` for the language
   (compiling the `.slaspec` with `bk-sleigh-compiler` when needed), then
   decode instructions and lift them to p-code on demand.
3. **Analysis** (`bk-analysis`): the auto-analysis manager schedules
   analyzers by priority over changed address sets, as Ghidra does;
   disassembly follows flow, functions and references are created.
4. **Decompile** (`bk-decomp`): per function, in parallel; results are C
   text plus token markup tied back to addresses and varnodes.
5. **Store** (`bk-store`): everything above writes through transactions.

## Milestones

A milestone is finished when its features are implemented, the Ghidra tests
for them are marked in `inventory/tests/`, the feature docs describe what
was built, and the gate is green. The first unchecked task in the earliest
unfinished milestone is the next work unless `PROGRESS.md` says otherwise.
Each milestone is planned in detail (inventory, feature specs, tracks) when
it is reached; later milestones are intentionally coarse.

### M0 — Foundations (wave 1, complete 2026-11-12)
- [x] Workspace, lints, gate, CI, licence, docs skeleton, test checklist
- [x] `bk-core` + `bk-marshal`: address spaces, addresses, varnode data, XML and packed encode/decode (`features/core-marshal.md`)
- [x] `bk-pcode`: opcodes, op behaviours, float formats, multiprecision (`features/pcode.md`)
- [x] `bk-sleigh-syntax`: SLEIGH preprocessor, lexer, parser; parses all 150 `.slaspec` files (`features/sleigh-syntax.md`)
- [x] `bk-lang`: `.ldefs`, `.pspec`, `.opinion`, language registry (`features/lang.md`)
- [x] `bk-bin` + `bk-elf`: byte providers, binary reader, ELF parser (`features/bin-elf.md`)
- [x] `bk-testkit` + reference tools: build Ghidra's `sleigh` and `decomp`, compile every `.sla`, oracle wrappers (`features/reference-tools.md`)

### M1 — SLEIGH runtime
Tracks and order: ADR-023. Undefined behaviour in Ghidra's engine: ADR-024.
- [x] `sla` — `bk-sla`: the compiled-language model, validating reader, byte-exact writers; all 150 reference files round-trip (`features/sla.md`)
- [x] `sleigh-decode` — `bk-sleigh`: loading, context database, instruction decoding, operand printing; `I`/`E`/`T` records equal to `pcodedump` for every language (`features/sleigh-decode.md`)
- [x] `sleigh-pcode` — `bk-sleigh`: p-code generation (templates, handles, delay slots, crossbuild, user ops), `Translate`, `basilisk disasm`; every record equal to `pcodedump`, the 20-operand exception aside (`features/sleigh-pcode.md`)
- [x] Benchmarks: language load time, decode and lift throughput at or above the reference (`PERF.md`): load 20 ms against 32; single-threaded decode 1.11× and decode + p-code 1.00× the g++ reference on x86-64 Linux, 1.32× and 1.38× on the M1; 6.7–7.9× at 8 threads. A clear margin for decode + p-code on x86-64 is a queued follow-up (compiled templates)
- [ ] `sleigh-language` — `bk-sleigh`, `bk-language`: registers as a model, flow and operand types, overrides, compile on demand (`features/sleigh-language.md`, a draft; later wave)

### M2 — SLEIGH compiler
- [x] `sleigh-compiler-front` — `bk-sleigh-compiler`: semantic analysis over `bk-sleigh-syntax` (symbols, tokens, constructors, macros, `with` blocks), p-code template compilation; symbols, print pieces, context changes and templates equal to Ghidra's for all 150 specifications (`features/sleigh-compiler-front.md`)
- [x] `sleigh-compiler-back` — `bk-sleigh-compiler`: pattern resolution, decision-tree construction, consistency checks, `basilisk sleigh compile`; all 150 specifications compile to the same inflated bytes as Ghidra's C++ compiler; `SleighCompileRegressionTest` ported as that equality (`features/sleigh-compiler-back.md`)
- [x] `sleigh-snippet` — `bk-sleigh-snippet`: p-code snippets of `.cspec`/`.pspec` (137 elements in 49 files; 588 compilations over 116 languages) compile to Ghidra's template with no difference; reference tool `snippetdump`; `PcodeParserTest` ported (`features/sleigh-snippet.md`)
- [ ] Compiler diagnostics equal to the C++ compiler's, one case per message (in `sleigh-compiler-front`/`-back`)

### M3 — Decompiler core, standalone
Runs on Ghidra's `<decompilertest>` data tests (bytes + language + script),
with no program database. Crates: ADR-026. How parity is measured: ADR-027.
What the port carries for later improvements: ADR-025, ADR-028. The 31
tracks, their order, sizes and acceptance are in `features/decomp-plan.md`;
this list follows its waves.
- [x] Wave 1 (leaf tracks; **all five tracks done**: D01, D02, D03 on 2026-11-14, D00 and D04 on 2026-11-15 — `features/decomp-oracle.md`, `features/decomp-cfg.md`, ADR-042; one follow-up in progress, the state dump's `@scope` section, format version 2): D01 `bk-decomp-range` (117 `testcirclerange` tests; `features/decomp-range.md`) · D02 `bk-decomp-types` (3 of the 8 `testtypes` tests, the other five need the IR and move to D08; `features/decomp-types.md`) · D03 `bk-cspec` (21 `testfuncproto`, 5 `testparamstore`, nine Java prototype-model classes; `features/decomp-cspec.md`) · D00 oracle tooling (state dumps, debug console, recorded p-code; `features/decomp-oracle.md`) · D04 `bk-decomp-cfg` block graph and structuring (`features/decomp-cfg.md`)
- [ ] Wave 2: D05 `bk-decomp-ir` (`features/decomp-ir.md`, revised 2026-11-15; ADR-046) · D06 `bk-decomp-symbols` and the host trait (`features/decomp-symbols.md`; ADR-043, 044, 045; **in progress**) · D16a printer spike
- [ ] Wave 3: D07 core (function state, units, profiles, drivers) · D08 typeop and casts · D16c emitter
- [ ] Wave 4: D09 flow and the data-test runner · D10 heritage · D11 actions A · R1–R9 rule families · D19 corpus extension (32 rules apply in no corpus yet)
- [ ] Wave 5: D12 actions B · D13 jump tables · D14 merge
- [ ] Wave 6: D15 structuring on the IR · D16b output tree
- [ ] Wave 7: D17 driver · D18 injection (needs `bk-sleigh-snippet`)
- [ ] All 93 data tests pass; differential runs against reference `decomp`
- [ ] `basilisk decompile` on a data-test file; per-function benchmark against Ghidra

### M4 — Program model, storage, loaders
- [ ] Storage engine spike and decision (ADR-003), then `bk-store`
- [ ] `bk-program`: memory blocks, address map, code units, symbols and namespaces, references, functions and variables, equates, comments, bookmarks, properties, relocations, register values
- [ ] `bk-datatypes`: built-in types, composites, archives, data organisation from `.cspec`
- [ ] `bk-loader` + ELF, PE, Mach-O, raw binary, Intel hex; relocation handlers per processor
- [ ] `basilisk import`

### M5 — Disassembly and auto-analysis
- [ ] Flow-following disassembler, instruction prototypes, context propagation
- [ ] Auto-analysis manager and scheduling
- [ ] Analyzers in Ghidra's priority order: entry points, function starts (pattern files), references, switch tables, stack, data and strings, no-return, call-fixups, demanglers, format-specific analyzers
- [ ] Decompiler wired to the program (parameter ID, switch analysis, decompiler-dependent analyzers)
- [ ] `basilisk analyze` (headless: import, analyse, export); whole-binary differential tests against Ghidra headless

### M6 — Headless core complete
- [ ] Exporters (C, XML/SARIF, binary, hex), import/export round trips
- [ ] DWARF, PDB, GNU and Microsoft demanglers (the GNU one ported from libiberty, ADR-018), Function ID
- [ ] Emulator (`bk-emu`) and the processor emulator tests (126 classes)
- [ ] Assembler (`bk-asm`)

### M7 — egui UI
- [ ] Shell: docking, pop-out windows, actions and key bindings, task and progress, options
- [ ] Listing, decompiler view with cross-highlighting, byte viewer, symbol tree and table, data type manager, function graph, references, search, bookmarks, memory map
- [ ] Editing commands with undo/redo; program diff

### M8 — Projects and collaboration
- [ ] Projects, versioned programs, multi-user server, merge

### M9 — Plugin API (ADR-014, ADR-035, ADR-036, ADR-037)
Python hosts Basilisk through an extension module (`basilisk-py`); the
tracks and their acceptance are in `features/plugin-api.md`. The work is
spread over the milestones its parts depend on rather than left to the end.
- [ ] P0 reference fixtures · P1 host and packaging (`python -m basilisk`, wheels on three systems, the binary's hand-over) · P3 the flat scripting layer — can start now
- [ ] P2 program-model bindings · P4a loaders — after M4
- [ ] P4b analyzers and exporters — after M5/M6 · P5 decompiler bindings and proposers — after the decompiler is wired to a program
- [ ] P6 interface hooks (`bk-plugin-ui`) — after `bk-ui`'s action registry and view kinds accept run-time entries
- [ ] P7 ports of Ghidra's bundled scripts (28 % port once the program model is bound, 53 % with decompiler, data-type and analysis bindings); importable module in PyGhidra's role

### M10 — Remaining modules
- [ ] Debugger and trace model, Version Tracking, BSim, file-system browser and container formats, remaining loaders and processors' Java extensions, everything left in `PARITY.md`
- [ ] Ghidra's remaining GPL modules: DMG; the GNU disassembler over binutils built from source (`bk-binutils-sys`, `bk-gnu-disasm`, ADR-019)

## Working in waves

Per ADR-015 each wave has one spec and one agent per track, with disjoint
crate ownership. Wave 1 was the six M0 tracks (complete). Wave 2 is being
specified by research agents (see `PROGRESS.md`, `## Now`): the SLEIGH
runtime and compiler (M1, M2), the decompiler port plan and its first
tracks (M3), PE and Mach-O parsers and the program model (M4), with a
storage-engine study deciding ADR-003. The UI (M7) and the GNU
disassembler (M10) were started early at the owner's request.
