---
title: P-code
description: P-code, the processor-independent operations every instruction lifts to — varnodes, address spaces and the families of operations.
sidebar:
  order: 3
---

P-code is the language everything above the processor layer speaks. Every instruction of every processor
is translated ("lifted") into a short sequence of p-code operations, and analysis, emulation and the
decompiler work on those alone. That is how one decompiler serves 39 processor families.

Basilisk's p-code is Ghidra's: the same operations with the same meaning, down to the result of every
arithmetic corner case.

## Varnodes

P-code has one kind of operand, the **varnode**: a run of bytes somewhere.

```text
(register,0x0,4)      4 bytes at offset 0 of the register space
(ram,0x401000,8)      8 bytes of memory at address 0x401000
(const,0x1,4)         the constant 1, 4 bytes wide
(unique,0x58300,4)    a temporary inside one instruction
```

A varnode is an **address space**, an **offset** and a **size**. It has no type and no name. That
`(register,0x0,4)` is called `EAX` is something the language adds for display.

| Space | Holds |
|---|---|
| `ram` (the name varies by processor) | The program's memory |
| `register` | The processor's registers, laid out by the language |
| `const` | Constants: the offset is the value |
| `unique` | Temporaries that live within one instruction |

Some processors have more: separate code and data memories, for example.

## Operations

An operation has an opcode, input varnodes and at most one output. An example, x86's `ADD EAX,0x1`, in
part:

```text
(register,0x200,1,CF) = INT_CARRY (register,0x0,4,EAX), (const,0x1,4)
(register,0x0,4,EAX)  = INT_ADD   (register,0x0,4,EAX), (const,0x1,4)
(register,0x206,1,ZF) = INT_EQUAL (register,0x0,4,EAX), (const,0x0,4)
```

Nothing is implicit. Flags are ordinary one-byte varnodes, computed by ordinary operations.

| Family | Operations |
|---|---|
| Moving data | `COPY`, `LOAD`, `STORE` |
| Integer arithmetic | `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_SDIV`, `INT_REM`, `INT_SREM`, `INT_NEGATE`, `INT_2COMP` |
| Bits and shifts | `INT_AND`, `INT_OR`, `INT_XOR`, `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT`, `POPCOUNT`, `LZCOUNT` |
| Comparison | `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_SLESS`, `INT_LESSEQUAL`, `INT_SLESSEQUAL`, `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW` |
| Changing size | `INT_ZEXT`, `INT_SEXT`, `SUBPIECE`, `PIECE` |
| Booleans | `BOOL_AND`, `BOOL_OR`, `BOOL_XOR`, `BOOL_NEGATE` |
| Floating point | `FLOAT_ADD`, `FLOAT_SUB`, `FLOAT_MULT`, `FLOAT_DIV`, `FLOAT_NEG`, `FLOAT_ABS`, `FLOAT_SQRT`, comparisons, conversions, rounding |
| Control flow | `BRANCH`, `CBRANCH`, `BRANCHIND`, `CALL`, `CALLIND`, `RETURN` |
| Escape | `CALLOTHER`: an operation the specification names but does not define, such as a system call or a vector instruction |

The decompiler adds a few of its own while it works (`MULTIEQUAL` and `INDIRECT` for SSA form, `PTRADD`,
`PTRSUB` and `CAST` for types); instructions never lift to those.

## Two properties worth knowing

**Sizes are explicit.** Every varnode has a size, and every operation has rules for the sizes of its
inputs and output. A 32-bit add of 64-bit registers does not exist: the specification must extract, add and
extend, and each step is visible.

**Addresses of p-code.** One instruction lifts to several operations, so an operation is identified by the
instruction's address and its index within the instruction. A branch whose target is a constant is a jump
*within* the instruction's own p-code; that is how a specification writes loops and conditions, as in
x86's `REP` prefixes.

## In Basilisk

| Crate | Part |
|---|---|
| `bk-core` | Address spaces, addresses, ranges and varnode data |
| `bk-pcode` | The opcodes, the arithmetic of every operation, and the floating-point formats |

The arithmetic matters for parity. When the decompiler folds constants, or an emulator runs, the result of
`INT_SDIV` on the most negative number, or of a float-to-integer conversion that overflows, must be what
Ghidra computes. `bk-pcode` is tested against tables generated from Ghidra's own implementation for every
operation and size.

See p-code for your own bytes with [`basilisk disasm`](/docs/cli/disasm/).
