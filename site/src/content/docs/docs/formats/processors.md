---
title: Processors
description: Every processor Ghidra describes in SLEIGH works in Basilisk — the 39 processor modules, their languages and how a language id is read.
sidebar:
  order: 2
---

Basilisk has no processor support of its own to write or maintain. It reads the processor descriptions
Ghidra ships, unchanged, so the list of processors is Ghidra's list.

:::note[Today]
For all 150 SLEIGH specifications in Ghidra's 39 processor modules:
- the specification **compiles** to the same content as with Ghidra's compiler
  ([`basilisk sleigh compile`](/docs/cli/sleigh-compile/));
- instructions **decode** and **lift to p-code** with the same result as Ghidra's engine
  ([`basilisk disasm`](/docs/cli/disasm/)).

The compiler specifications (`.cspec`: calling conventions, stack layout, data sizes) are read for all of
them too; the decompiler will use them.
:::

## Language ids

A language is named by four parts separated by colons, exactly as in Ghidra:

```text
x86:LE:64:default
 │   │  │   └── variant
 │   │  └────── address size in bits
 │   └───────── byte order: LE little-endian, BE big-endian
 └───────────── processor
```

Several ids can share one SLEIGH specification and differ only in their processor specification or
defaults; that is why there are more ids (193) than specifications (150).

## The modules

Counts are for the Ghidra commit Basilisk is developed against.

| Module | Language ids | Specifications | An id from it |
|---|---|---|---|
| 6502 | 2 | 2 | `6502:LE:16:default` |
| 68000 | 5 | 5 | `68000:BE:32:default` |
| 8048 | 1 | 1 | `8048:LE:16:default` |
| 8051 | 5 | 5 | `8051:BE:16:default` |
| 8085 | 1 | 1 | `8085:LE:16:default` |
| AARCH64 | 5 | 3 | `AARCH64:LE:64:v8A` |
| ARM | 22 | 16 | `ARM:LE:32:v8` |
| Atmel (AVR, AVR32) | 5 | 5 | `avr32:BE:32:default` |
| BPF | 1 | 1 | `BPF:LE:32:default` |
| CP1600 | 1 | 1 | `CP1600:BE:16:default` |
| CR16 | 1 | 2 | `CR16C:LE:16:default` |
| Dalvik | 13 | 11 | `Dalvik:LE:32:default` |
| DATA | 2 | 2 | `DATA:LE:64:default` |
| eBPF | 2 | 2 | `eBPF:BE:64:default` |
| HCS08 | 6 | 3 | `HC05:BE:16:default` |
| HCS12 | 4 | 3 | `HC-12:BE:16:default` |
| Hexagon | 1 | 1 | `Hexagon:LE:32:default` |
| JVM | 1 | 1 | `JVM:BE:32:default` |
| Loongarch | 4 | 4 | `Loongarch:LE:32:ilp32f` |
| M16C | 2 | 2 | `M16C/60:LE:16:default` |
| M8C | 1 | 1 | `M8C:BE:16:default` |
| MC6800 | 3 | 3 | `6809:BE:16:default` |
| MCS96 | 1 | 1 | `MCS96:LE:16:default` |
| MIPS | 22 | 6 | `MIPS:BE:32:default` |
| NDS32 | 2 | 2 | `NDS32:BE:32:default` |
| PA-RISC | 1 | 1 | `pa-risc:BE:32:default` |
| PIC | 13 | 13 | `PIC-24E:LE:24:default` |
| PowerPC | 23 | 18 | `PowerPC:BE:32:default` |
| RISCV | 3 | 3 | `RISCV:LE:64:default` |
| Sparc | 2 | 2 | `sparc:BE:32:default` |
| SuperH | 3 | 3 | `SuperH:BE:32:SH-2A` |
| SuperH4 | 2 | 2 | `SuperH4:BE:32:default` |
| TI_MSP430 | 2 | 2 | `TI_MSP430:LE:16:default` |
| Toy (Ghidra's test languages) | 13 | 13 | `Toy:BE:32:default` |
| tricore | 4 | 1 | `tricore:LE:32:default` |
| V850 | 2 | 2 | `V850:LE:32:default` |
| x86 | 6 | 2 | `x86:LE:64:default` |
| Xtensa | 2 | 2 | `Xtensa:LE:32:default` |
| Z80 | 4 | 2 | `z80:LE:16:default` |

The ids of a module are in its `.ldefs` file, under
`Ghidra/Processors/<module>/data/languages/`.

## Your own processor

Because the files are read as they are, a SLEIGH specification written for Ghidra works in Basilisk: put the
module's directory beside the others under `Ghidra/Processors/`, compile it with
[`basilisk sleigh compile`](/docs/cli/sleigh-compile/), and its ids are available to
[`basilisk disasm`](/docs/cli/disasm/).

## What each file is for

| File | What it holds | Read by Basilisk |
|---|---|---|
| `.slaspec`, `.sinc` | The instruction set in SLEIGH: encodings, display, p-code | Yes; compiled |
| `.sla` | The compiled form of a `.slaspec` | Yes; also written, byte for byte |
| `.ldefs` | The module's languages: ids, descriptions, which files belong to each | Yes |
| `.pspec` | Processor details: the program counter, default context, register groups, default symbols | Yes |
| `.cspec` | A compiler's conventions: calling conventions, stack, data sizes, p-code snippets | Yes |
| `.opinion` | Which language and compiler a loader should pick for a file | Yes |
| `.dwarf`, `.gdis`, patterns, manuals' indexes | Debug-register maps, external disassembler setup, function-start patterns | With the features that use them (M5, M6) |

## Planned

| What | Milestone |
|---|---|
| Registers as a model, instruction flow and operand types, per-instruction overrides | M1, later item |
| Choosing a language for a file from the `.opinion` files during import | M4 |
| Relocation handlers per processor | M4 |
| Function-start patterns and per-processor analyzers | M5 |
| Processor emulation tests | M6 |
