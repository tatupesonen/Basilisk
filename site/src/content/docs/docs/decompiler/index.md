---
title: The decompiler
description: Basilisk's decompiler, a port of Ghidra's C++ decompiler — planned for milestone M3.
sidebar:
  order: 1
  label: Overview
---

:::caution[Being ported]
The decompiler is milestone M3 and is being ported now. It does not decompile anything yet; the Decompiler
view in the interface shows demo output today.
:::

Basilisk's decompiler is a port of Ghidra's C++ decompiler, written as a set of Rust crates. It runs in the
same process as the rest of Basilisk (Ghidra runs its decompiler as a separate process), and it decompiles
functions in parallel.

## What exists today

| Part | Crate | State |
|---|---|---|
| The type system and the C declaration parser | `bk-decomp-types` | Done |
| Value ranges (strided intervals) | `bk-decomp-range` | Done |
| Compiler specifications and calling-convention models | `bk-cspec` | Done |
| The block graph, its analyses and control-flow structuring | `bk-decomp-cfg` | Done; structures all of the reference's test functions as Ghidra does |
| The reference: Ghidra's decompiler with state dumps at every stage | test tooling | Done |
| Varnodes, operations and the function's data flow | `bk-decomp-ir` | In progress |
| Symbols and scopes | `bk-decomp-symbols` | In progress |
| Flow, SSA construction, the simplification rules, type recovery, variable merging, output | — | Planned, in that order |

## The pipeline

The decompiler works on p-code, the processor-independent operations SLEIGH produces for each instruction.

```mermaid title="From instructions to C: the decompiler's stages. Lifting exists; the rest is being ported"
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
  class bytes,lift done
  class flow,ssa,rules,types,struct,c planned
```

## The stages

1. **Lift.** SLEIGH turns each instruction into [p-code](/docs/internals/pcode/).
2. **Control flow.** The p-code is followed from the function's entry into basic blocks and a graph;
   indirect jumps are resolved into switch tables.
3. **SSA form.** Every value gets one definition, so that the flow of data is explicit. Ghidra calls this
   *heritage*.
4. **Simplify.** Well over a hundred rewrite rules run until nothing changes: constants fold, flag
   computations collapse into comparisons, stack arithmetic becomes variables.
5. **Types and variables.** Types flow from known signatures and from how values are used; values that
   are the same variable in the source are merged.
6. **Structure.** The graph of blocks becomes `if`, `while`, `switch` and, where nothing else fits, `goto`.
7. **Print.** The result is emitted as C, with every token tied back to the operation and address it came
   from, which is what makes the Decompiler view clickable.

## How it is checked

The decompiler is the part of Ghidra where "the same answer" is hardest to show, so it is checked stage by
stage. Ghidra's decompiler is built with extra commands that dump its internal state at chosen points; each
Basilisk pass is loaded with Ghidra's state before that pass and must produce Ghidra's state after it. The
final acceptance is Ghidra's 93 decompiler data tests (bytes, a language and a script, with no program
database) and a larger corpus, with output equal to Ghidra's. See
[How results are checked](/docs/internals/verification/).

## Improvements

Parity comes first: the default output is Ghidra's. Improvements to the output are designed as separate,
named profiles that you choose, so that a difference from Ghidra is always one you asked for.
