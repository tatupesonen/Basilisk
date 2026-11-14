---
title: How it works
description: basilisk's architecture — the headless data flow, the crate map, SLEIGH, p-code, the decompiler pipeline and the program database.
sidebar:
  order: 1
---

basilisk is a workspace of focused Rust crates. Dependencies point one way: format parsers know nothing about
programs, the SLEIGH crates know nothing about programs, and nothing below the interface depends on it. It
ships as a single binary.

## The headless data flow

```mermaid title="From a binary file to decompiled C (docs/PLAN.md, Data flow)"
flowchart LR
  file[/Binary file/] --> import[Import<br/>loaders, formats]
  import --> lang[Language<br/>decode, lift]
  lang --> analysis[Analysis<br/>auto-analysis]
  analysis --> decomp[Decompile<br/>in parallel]
  import --> store[(Program<br/>database)]
  analysis --> store
  decomp --> store
```

1. **Import** picks a loader and a language through Ghidra's `.opinion` files, maps sections into program
   memory, applies relocations and creates symbols and entry points.
2. **Language** loads the compiled SLEIGH (`.sla`) for the processor, compiling the `.slaspec` when needed,
   then decodes instructions and lifts them to p-code on demand.
3. **Analysis** schedules analyzers by priority over the addresses that changed: disassembly follows flow,
   and functions and references are created.
4. **Decompile** runs per function, in parallel; the result is C text plus tokens tied back to addresses.
5. **Store**: everything above writes to the program database through transactions.

## The crate map

Crates with a solid green border exist today; dashed ones are planned. Dependencies point down only.

```mermaid title="basilisk's crates by layer; each layer depends only on the layers below it (docs/PLAN.md, Architecture)"
block-beta
  columns 6
  l1["APPLICATION"] basilisk["basilisk"] ui["bk-ui"] plugin["bk-plugin"] headless["bk-headless"] space
  l2["ANALYSIS"] analysis["bk-analysis"] analyzers["bk-analyzers-*"] disasm["bk-disasm"] space:2
  l3["DECOMPILER"] decomp["bk-decomp"] passes["bk-decomp-*"] cspec["bk-cspec"] space:2
  l4["PROGRAM"] program["bk-program"] datatypes["bk-datatypes"] store["bk-store"] space:2
  l5["IMPORT"] loader["bk-loader"] elf["bk-elf"] pe["bk-pe, bk-macho"] bin["bk-bin"] space
  l6["LANGUAGE"] sleigh["bk-sleigh"] sleighc["bk-sleigh-compiler"] sla["bk-sla"] syntax["bk-sleigh-syntax"] lang["bk-lang"]
  l7["FOUNDATION"] pcode["bk-pcode"] marshal["bk-marshal"] corec["bk-core"] space:2
  class l1,l2,l3,l4,l5,l6,l7 layer
  class basilisk,ui,elf,bin,sla,syntax,lang,pcode,marshal,corec done
  class plugin,headless,analysis,analyzers,disasm,decomp,passes,cspec,program,datatypes,store,loader,pe,sleigh,sleighc planned
```

## SLEIGH

SLEIGH is Ghidra's language for describing instruction sets: how bytes decode into instructions, how they
print, and what each one does as p-code. basilisk reads Ghidra's SLEIGH specifications unchanged; it parses
all 150 of them today and reads and writes the compiled `.sla` form byte for byte. Decoding (milestone M1)
and the compiler (M2) come next.

## P-code

P-code is a small, processor-independent set of operations — copy, load, store, arithmetic, branches,
calls — over varnodes (an address space, an offset and a size). Every instruction lifts to a short p-code
sequence, and everything after the language layer, the emulator and the decompiler included, works on
p-code alone. basilisk's p-code model, opcodes and floating-point formats exist today.

## The decompiler pipeline

See [The decompiler](/docs/decompiler/): p-code is built into a control-flow graph, put into SSA form,
simplified by rules, given types and variables, and structured into C. Planned for milestone M3.

## The program database

Everything basilisk learns about a binary — memory, code units, symbols, references, functions, types,
comments — lives in a program database written through transactions with undo. Its storage engine is being
chosen by experiment (ADR-003); the program model is milestone M4.
