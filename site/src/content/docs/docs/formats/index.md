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
definitions (`.ldefs`), processor specifications (`.pspec`), compiler specifications (`.cspec`) and loader
opinions (`.opinion`) around them.

:::note[Today]
- All 150 SLEIGH specifications in Ghidra's 39 processor modules compile, to the same content as with
  Ghidra's compiler.
- Instructions decode and lift to p-code for every one of them, with the same result as Ghidra's engine.
- `.ldefs`, `.pspec`, `.cspec` and `.opinion` files are read into a language registry.
:::

The list of modules and how to name a language is on [Processors](/docs/formats/processors/).

## Binary formats

:::caution[Not yet]
Basilisk cannot load an executable yet. The ELF parser exists as a library; loaders arrive with the program
database in milestone M4. Until then [`basilisk sleigh decode`](/docs/cli/sleigh-decode/) works on raw code bytes.
:::

| Format | Today | Planned |
|---|---|---|
| ELF | Parser | Loader and relocations (M4) |
| PE, Mach-O | — | Parsers and loaders (M4) |
| Raw binary, Intel hex | — | Loaders (M4) |
| COFF, OMF, NE, MZ, PEF, SOM, XCOFF, a.out | — | M4–M10 |
| DWARF, PDB | — | M6 |

### The ELF parser

The parser reads everything Ghidra's ELF loader uses: headers, sections and segments, symbol tables,
relocations, dynamic information, notes and version tables, for 32-bit and 64-bit files in either byte
order. It is tolerant in the way Ghidra's is: a damaged table is reported and the rest of the file is still
read.

### Hostile input

Programs that are reverse-engineered are often built to break tools. Every parser of untrusted input in
Basilisk is fuzzed, and none may panic, overflow or allocate without bound on a malformed file; a bad file
gives an error, not a crash. See [how results are checked](/docs/internals/verification/).
