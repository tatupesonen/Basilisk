---
title: How it works
description: Basilisk's architecture — the headless data flow, the crate map, SLEIGH, p-code, the decompiler pipeline and the program database.
sidebar:
  order: 1
  label: Overview
---

Basilisk is a workspace of focused Rust crates. Dependencies point one way: format parsers know nothing about
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
   then decodes instructions and lifts them to p-code on demand. *This step exists today.*
3. **Analysis** schedules analyzers by priority over the addresses that changed: disassembly follows flow,
   and functions and references are created.
4. **Decompile** runs per function, in parallel; the result is C text plus tokens tied back to addresses.
5. **Store**: everything above writes to the program database through transactions.

## The crate map

Crates with a solid green border exist today; dashed ones are planned; the decompiler's crates, marked in
ember, are being written now (four of them exist). Dependencies point down only.

```mermaid title="Basilisk's crates by layer; each layer depends only on the layers below it (docs/PLAN.md, Architecture)"
block-beta
  columns 6
  l1["APPLICATION"] basilisk["Basilisk"] ui["bk-ui"] plugin["bk-plugin"] headless["bk-headless"] space
  l2["ANALYSIS"] analysis["bk-analysis"] analyzers["bk-analyzers-*"] disasm["bk-disasm"] space:2
  l3["DECOMPILER"] decomp["bk-decomp"] passes["bk-decomp-*"] cspec["bk-cspec"] space:2
  l4["PROGRAM"] program["bk-program"] datatypes["bk-datatypes"] store["bk-store"] space:2
  l5["IMPORT"] loader["bk-loader"] elf["bk-elf"] pe["bk-pe, bk-macho"] bin["bk-bin"] space
  l6["LANGUAGE"] sleigh["bk-sleigh"] sleighc["bk-sleigh-compiler"] sla["bk-sla"] syntax["bk-sleigh-syntax"] lang["bk-lang"]
  l7["FOUNDATION"] pcode["bk-pcode"] marshal["bk-marshal"] corec["bk-core"] space:2
  class l1,l2,l3,l4,l5,l6,l7 layer
  class basilisk,ui,elf,bin,sla,syntax,lang,pcode,marshal,corec,sleigh,sleighc,cspec done
  class passes here
  class plugin,headless,analysis,analyzers,disasm,decomp,program,datatypes,store,loader,pe planned
```

## SLEIGH

SLEIGH is Ghidra's language for describing instruction sets: how bytes decode into instructions, how they
print, and what each one does as p-code. Basilisk reads Ghidra's SLEIGH specifications unchanged. Both the
compiler and the runtime exist today and equal Ghidra's for all 150 specifications. More:
[SLEIGH](/docs/internals/sleigh/).

## P-code

P-code is a small, processor-independent set of operations — copy, load, store, arithmetic, branches,
calls — over varnodes (an address space, an offset and a size). Every instruction lifts to a short p-code
sequence, and everything after the language layer, the emulator and the decompiler included, works on
p-code alone. More: [P-code](/docs/internals/pcode/).

## The decompiler pipeline

See [The decompiler](/docs/decompiler/): p-code is built into a control-flow graph, put into SSA form,
simplified by rules, given types and variables, and structured into C. It is being ported now (milestone
M3).

## The program database

Everything Basilisk learns about a binary — memory, code units, symbols, references, functions, types,
comments — lives in a program database written through transactions with undo. Its storage engine is being
chosen by experiment (ADR-003); the program model is milestone M4.

## How it is checked

Each part is run against Ghidra on the same input and the outputs are compared. More:
[How results are checked](/docs/internals/verification/).
