---
title: Formats and processors
description: The binary formats and processor languages Basilisk reads — today and planned.
sidebar:
  order: 1
  label: Overview
---

## Processors

Basilisk does not rewrite Ghidra's processor descriptions. It reads Ghidra's language files **unchanged**:
the SLEIGH specifications (`.slaspec`, `.sinc`) that describe each instruction set, and the language
definitions (`.ldefs`), processor specifications (`.pspec`) and loader opinions (`.opinion`) around them.

:::note[Today]
- All 150 SLEIGH specifications in Ghidra's 39 processor modules parse.
- All 150 compiled `.sla` files that Ghidra's compiler produces are read and written back byte for byte.
- `.ldefs`, `.pspec` and `.opinion` files are read into a language registry.
:::

Decoding instructions with these languages is milestone M1; compiling `.slaspec` files to `.sla` is M2.

## Binary formats

| Format | Today | Planned |
|---|---|---|
| ELF | Parser | Loader and relocations (M4) |
| PE, Mach-O | — | Parsers and loaders (M4) |
| Raw binary, Intel hex | — | Loaders (M4) |
| COFF, OMF, NE, MZ, PEF, SOM, XCOFF, a.out | — | M4–M10 |
| DWARF, PDB | — | M6 |

Parsers of untrusted input are fuzzed and never panic on malformed files.
