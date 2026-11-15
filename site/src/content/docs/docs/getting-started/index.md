---
title: Introduction
description: What Basilisk is, what it can do today, and what it is for.
sidebar:
  order: 1
---

Basilisk is a reverse-engineering suite: it takes a compiled program, recovers its instructions, functions,
data and control flow, and turns machine code back into readable C. It does this by reimplementing
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) in Rust, and it reads Ghidra's processor
specifications — the SLEIGH files that describe each instruction set — unchanged.

## Goals

- **Parity.** Everything Ghidra does, module by module, the headless core first.
- **Better where it can be.** Behaviour from Ghidra, structure from Rust; each deliberate difference is
  documented.
- **Speed.** Language load, disassembly and decompilation at least as fast as Ghidra's; analysis in parallel
  where it is safe; an interface that never blocks.
- **Trustworthy.** No crashes on hostile binaries, Ghidra's own tests ported, output checked against Ghidra.

## What exists today

:::note[Today]
- **Disassembly and p-code for every processor Ghidra ships.** `basilisk disasm` decodes bytes with any of
  Ghidra's 150 SLEIGH languages and prints each instruction with its p-code. The output equals that of
  Ghidra's own engine, record for record.
- **The SLEIGH compiler.** `basilisk sleigh compile` turns a `.slaspec` into a `.sla` file with the same
  content as the one Ghidra's compiler writes, for all 150 specifications.
- **The desktop interface**, running on a built-in demo program: the Listing, the Decompiler view, the
  Symbol Tree and Program Trees, the Functions, Defined Strings and References tables, the Console, search,
  Go To and the command palette, rename and comment dialogs, docking and pop-out windows, dark and light
  themes.
- **Foundations**: Ghidra's language definitions (`.ldefs`, `.pspec`, `.opinion`) and compiler
  specifications (`.cspec`), an ELF parser, the p-code model and its floating-point formats, and the GNU
  disassembler from binutils.
- **The first parts of the decompiler**: its type system, value ranges, calling-convention models and
  control-flow structuring, each checked against Ghidra's decompiler.
:::

:::caution[Not yet]
Opening a real binary, analysis, decompiling a function and Python scripting. The
[roadmap](/roadmap/) lists the milestone for each; the [status matrix](/status/) tracks every Ghidra module.
:::

## Where Basilisk stands on the road to Ghidra

| Milestone | What it brings | State |
|---|---|---|
| M0 | Foundations: p-code model, language files, SLEIGH parser, ELF parser | Done |
| M1 | SLEIGH runtime: decoding and p-code for every language | Done, one later item open |
| M2 | SLEIGH compiler | Done, diagnostics parity open |
| M3 | The decompiler, standalone | In progress |
| M4 | Program database, loaders (ELF, PE, Mach-O, raw) | Planned |
| M5 | Flow-following disassembly and auto-analysis | Planned |
| M6 | Exporters, DWARF and PDB, demanglers, the emulator, the assembler | Planned |
| M7 | The full interface on real programs | Shell and core views exist on demo data |
| M8 | Projects, versioned programs, the multi-user server | Planned |
| M9 | Python scripting and plugins | Designed |
| M10 | The debugger, Version Tracking, BSim, the remaining formats | Planned |

The [roadmap](/roadmap/) has every task of every milestone.

## Next

1. [Build and run Basilisk](/docs/getting-started/build/) from source.
2. [Disassemble your first bytes](/docs/getting-started/first-disassembly/).
3. If you know Ghidra: [coming from Ghidra](/docs/getting-started/coming-from-ghidra/).
