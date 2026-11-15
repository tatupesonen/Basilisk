---
title: Your first disassembly
description: Compile a processor language with Basilisk, disassemble a few bytes, and read the p-code they lift to.
sidebar:
  order: 3
---

This page takes about five minutes. You compile one of Ghidra's processor languages with Basilisk, decode a
small x86-64 function, and read its p-code. It uses only what exists today.

You need a [built `basilisk`](/docs/getting-started/build/) and
[Ghidra's language files](/docs/getting-started/build/#ghidras-language-files) with `BASILISK_GHIDRA_DIR`
pointing at them.

## 1. Compile the language

A SLEIGH specification (`.slaspec`) describes an instruction set as text. Before it can decode anything it
is compiled into a `.sla` file. If you cloned Ghidra's source, that file does not exist yet; make it:

```sh
basilisk sleigh compile "$BASILISK_GHIDRA_DIR/Ghidra/Processors/x86/data/languages/x86-64.slaspec"
```

This takes a fraction of a second and writes `x86-64.sla` beside the specification. The warnings it prints
are the ones Ghidra's own compiler prints for this file. The result has the same content as the file
Ghidra's compiler produces.

To compile every language of every processor in one go, give the directory:

```sh
basilisk sleigh compile -a "$BASILISK_GHIDRA_DIR/Ghidra/Processors"
```

If you point `BASILISK_GHIDRA_DIR` at an installed Ghidra release instead, skip this step: a release ships
the `.sla` files.

## 2. Disassemble

Here is a tiny function as bytes: `55 48 89 e5 8b 45 fc 83 c0 01 5d c3`. Decode it as x86-64, loaded at
address `0x401000`:

```sh
basilisk disasm --language x86:LE:64:default --base 0x401000 \
  --hex 554889e58b45fc83c0015dc3 --format text --no-pcode
```

```text
0x401000  55                       PUSH RBP
0x401001  48 89 e5                 MOV RBP,RSP
0x401004  8b 45 fc                 MOV EAX,dword ptr [RBP + -0x4]
0x401007  83 c0 01                 ADD EAX,0x1
0x40100a  5d                       POP RBP
0x40100b  c3                       RET
```

The text is Ghidra's: the same mnemonics, operand order and number formatting you see in Ghidra's Listing.

`--language` takes a Ghidra language id: processor, endianness, size and variant. Other examples are
`AARCH64:LE:64:v8A`, `ARM:LE:32:v8`, `MIPS:BE:32:default` and `RISCV:LE:64:default`. Each needs its `.sla`
compiled as in step 1. See [Processors](/docs/formats/processors/).

## 3. Read the p-code

Leave out `--no-pcode` and every instruction is followed by its p-code: what the instruction does, written
in a small set of operations that is the same for every processor.

```sh
basilisk disasm --language x86:LE:64:default --base 0x401000 --hex 83c001 --format text
```

```text
0x401000  83 c0 01                 ADD EAX,0x1
    (register,0x200,1,CF) = INT_CARRY (register,0x0,4,EAX), (const,0x1,4)
    (register,0x20b,1,OF) = INT_SCARRY (register,0x0,4,EAX), (const,0x1,4)
    (register,0x0,4,EAX) = INT_ADD (register,0x0,4,EAX), (const,0x1,4)
    (register,0x0,8,RAX) = INT_ZEXT (register,0x0,4,EAX)
    (register,0x207,1,SF) = INT_SLESS (register,0x0,4,EAX), (const,0x0,4)
    (register,0x206,1,ZF) = INT_EQUAL (register,0x0,4,EAX), (const,0x0,4)
    (unique,0x58300,4) = INT_AND (register,0x0,4,EAX), (const,0xff,4)
    (unique,0x58400,1) = POPCOUNT (unique,0x58300,4)
    (unique,0x58500,1) = INT_AND (unique,0x58400,1), (const,0x1,1)
    (register,0x202,1,PF) = INT_EQUAL (unique,0x58500,1), (const,0x0,1)
```

One `ADD` becomes ten operations, because p-code spells out everything the processor does:

- The first two lines compute the carry and overflow flags from the values *before* the addition.
- The third line is the addition itself.
- The fourth clears the upper half of `RAX`, as x86-64 does when a 32-bit register is written.
- The rest set the sign, zero and parity flags from the result.

Each value in parentheses is a **varnode**: an address space, an offset in it, and a size in bytes.
`(register,0x0,4,EAX)` is four bytes at offset 0 of the register space, which the language calls `EAX`.
`(const,0x1,4)` is the constant 1. `(unique,…)` is a temporary that lives only inside this instruction.

This is what the rest of Basilisk works on. The decompiler never looks at x86 or ARM instructions; it reads
p-code, which is why one decompiler serves every processor. More in [P-code](/docs/internals/pcode/).

## 4. Decode a file

Without `--hex`, `disasm` reads a file, or standard input:

```sh
basilisk disasm --language x86:LE:64:default --base 0x1000 --format text code.bin
```

It decodes the bytes one instruction after another from the first byte (a *linear sweep*). It does not
know about file formats: give it raw code, not an ELF or PE file. Loading executables and following the
flow of control arrive with the [loaders](/docs/formats/) (M4) and [analysis](/docs/analysis/) (M5).

## Next

- [`basilisk disasm`](/docs/cli/disasm/): every option, the machine-readable output, context variables.
- [How SLEIGH decodes an instruction](/docs/internals/sleigh/).
