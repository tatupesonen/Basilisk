---
title: The decompiler
description: basilisk's decompiler, a port of Ghidra's C++ decompiler — planned for milestone M3.
sidebar:
  order: 1
  label: Overview
---

:::caution[Planned]
The decompiler is milestone M3. Its port plan is written and its first crates are being built; it does not
decompile anything yet. The Decompiler view in the interface shows demo output today.
:::

basilisk's decompiler is a port of Ghidra's C++ decompiler, written as a set of Rust crates. It runs in the
same process as the rest of basilisk (Ghidra runs its decompiler as a separate process), and it decompiles
functions in parallel.

## The pipeline

The decompiler works on p-code, the processor-independent operations SLEIGH produces for each instruction.

```mermaid title="From instructions to C: the decompiler's stages, all planned"
block-beta
  columns 7
  bytes["Machine<br/>code"] space lift["P-code<br/>from SLEIGH"] space flow["Control<br/>flow"] space ssa["SSA form<br/>heritage"]
  space:7
  c["C and<br/>tokens"] space struct["Structure<br/>loops, if"] space types["Types and<br/>variables"] space rules["Simplify<br/>rules"]
  bytes --> lift
  lift --> flow
  flow --> ssa
  ssa --> rules
  rules --> types
  types --> struct
  struct --> c
  class bytes,lift,flow,ssa,rules,types,struct,c planned
```

## How it is checked

First, the decompiler runs standalone on Ghidra's 93 decompiler data tests (bytes, a language and a script,
with no program database), and its output is compared with Ghidra's own decompiler on the same input. Then
it is wired to the program model for analysis and the interface.
