---
title: Introduction
description: What basilisk is, what it can do today, and what it is for.
sidebar:
  order: 1
---

basilisk is a reverse-engineering suite: it takes a compiled program, recovers its instructions, functions,
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
- The **desktop interface**, running on a built-in demo program: the Listing, the Decompiler view, the
  Symbol Tree and Program Trees, the Functions, Defined Strings and References tables, the Console, search,
  Go To and the command palette, rename and comment dialogs, docking and pop-out windows, dark and light
  themes.
- Reading Ghidra's language definitions (`.ldefs`, `.pspec`, `.opinion`), parsing all 150 SLEIGH
  specifications, and reading and writing compiled SLEIGH (`.sla`) files byte for byte.
- An ELF parser, the p-code model and its floating-point formats, and the GNU disassembler from binutils.
:::

:::caution[Not yet]
Opening a real binary, disassembly with SLEIGH, analysis, the decompiler and Python scripting. The
[roadmap](/roadmap/) lists the milestone for each; the [status matrix](/status/) tracks every Ghidra module.
:::

## Next

[Build and run basilisk](/docs/getting-started/build/) from source.
