---
title: basilisk sleigh decode
description: Decode raw bytes with any of Ghidra's SLEIGH languages and print every instruction with its p-code.
sidebar:
  order: 2
  label: sleigh decode
---

`basilisk sleigh decode` decodes raw bytes with a SLEIGH language and prints each instruction with the p-code it
lifts to. It works for every language Ghidra ships. Its output equals the output of Ghidra's own SLEIGH
engine on the same bytes, record for record; that equality is tested for all 150 languages.

```text
basilisk sleigh decode --language <id> [options] [--hex HEXBYTES | <file> | -]
```

New here? [Your first disassembly](/docs/getting-started/first-disassembly/) walks through it.

:::note[What it is and is not]
`sleigh decode` drives the instruction decoder over raw code as a **linear sweep**: it decodes at the base
address, moves on by the instruction's length, and repeats. It is not Basilisk's disassembler. Ghidra's
disassembler follows the flow of control from entry points; Basilisk's port of it arrives with milestone M5,
after the loaders (M4), and the name `basilisk disasm` is kept for it.
:::

## Options

| Option | Meaning |
|---|---|
| `--language <id>` | The language id, for example `x86:LE:64:default`. Required. See [Processors](/docs/formats/processors/) |
| `--root <dir>` | A Ghidra tree, or any directory with the same layout, that holds the language files. Default: `$BASILISK_GHIDRA_DIR` |
| `--sla-dir <dir>` | A directory with the same layout as the root that holds the compiled `.sla` files, for when the root has none (a read-only source tree, say) |
| `--base <addr>` | The address of the first byte. Default 0; write `0x…` for hexadecimal |
| `--context NAME=VALUE` | Set a context variable over the whole code space. Repeatable |
| `--hex HEXBYTES` | Decode these bytes instead of a file |
| `--format pcodedump\|text` | The record format (default) or a listing for reading |
| `--no-pcode` | Leave out the p-code |
| `--quiet` | Decode and lift everything, print only the first and last record |
| `--timing` | Print load and decode times on standard error |
| `-h`, `--help` | Print the help |

Input comes from `--hex`, from the named file, or from standard input when neither is given (or the file is
`-`).

## Context variables

Some processors decode the same bytes differently depending on a mode. SLEIGH calls these modes *context
variables*. The processor specification sets their defaults; `--context` overrides them.

The best-known one is ARM's Thumb mode:

```sh
basilisk sleigh decode --language ARM:LE:32:v8 --hex 01207047 --context TMode=1 --format text --no-pcode
```

```text
0x0  01 20                    movs r0,#0x1
0x2  70 47                    bx lr
```

Without `--context TMode=1` the same four bytes decode as one 32-bit ARM instruction. Context that an
instruction itself changes takes effect for the instructions after it, as in Ghidra's engine.

## The listing format

`--format text` prints one line per instruction (address, bytes, mnemonic and operands) with the p-code
indented below it:

```text
0x401000  55                       PUSH RBP
    (unique,0x4f900,8) = COPY (register,0x28,8,RBP)
    (register,0x20,8,RSP) = INT_SUB (register,0x20,8,RSP), (const,0x8,8)
    STORE (const,0x3,8,ram), (register,0x20,8,RSP), (unique,0x4f900,8)
```

Bytes that are not an instruction print as `??` with the reason, and decoding resumes at the next byte.

## The record format

The default format is for programs. It is the format of `pcodedump`, the small reference tool the project
builds from Ghidra's C++ engine, so that the two outputs can be compared byte for byte. It is versioned;
the version is the first field of the first line.

Lines are tab-separated; the first field is a one-letter tag.

| Record | Fields after the tag | Meaning |
|---|---|---|
| `H` | version, language id, code space, base address, byte count | The first line |
| `I` | address, length, flow length, bytes, mnemonic, operand text | One instruction |
| `P` | opcode, output varnode or `-`, input varnodes… | One p-code operation of the instruction above |
| `U` | kind, message | The instruction above decodes but has no p-code: `unimplemented`, `bad-data` or `error` |
| `E` | address, length, bytes, kind, message | These bytes are not an instruction: `bad-data`, `truncated` or `error` |
| `T` | number of instructions, number of `E` and `U` records | The last line. If it is missing, the output was cut short |

```text
H	1	x86:LE:64:default	ram	0x0	3
I	0x0	1	1	55	PUSH	RBP
P	COPY	(unique,0x4f900,8)	(register,0x28,8,RBP)
P	INT_SUB	(register,0x20,8,RSP)	(register,0x20,8,RSP)	(const,0x8,8)
P	STORE	-	(const,0x3,8,ram)	(register,0x20,8,RSP)	(unique,0x4f900,8)
I	0x1	1	1	c3	RET	
P	LOAD	(register,0x288,8,RIP)	(const,0x3,8,ram)	(register,0x20,8,RSP)
P	INT_ADD	(register,0x20,8,RSP)	(register,0x20,8,RSP)	(const,0x8,8)
P	RETURN	-	(register,0x288,8,RIP)
E	0x2	1	ff	truncated	instruction extends past the end of the input
T	2	1
```

A varnode is `(space,0xOFFSET,SIZE)`, with the register's name as a fourth field when the location is
exactly a register. The first input of `LOAD` and `STORE` names the address space that is read or written:
`(const,0x3,8,ram)`.

Numbers written `0x…` are lower-case hexadecimal; the others are decimal. In text fields a backslash, tab,
line feed and carriage return are written `\\`, `\t`, `\n` and `\r`.

### Delay slots

On processors with delay slots (MIPS, SPARC, SuperH and others), the instruction after a branch runs before
the branch takes effect. The p-code of the branch therefore includes the p-code of the instruction after
it, and the *flow length* field says how many bytes that covers:

```text
I	0x0	4	8	0c000100	jal	0x400
P	COPY	(register,0x7c,4,ra)	(const,0x8,4)
P	COPY	(register,0x10,4,a0)	(const,0x1,4)
P	CALL	-	(ram,0x400,4)
I	0x4	4	4	24040001	li	a0, 0x1
P	COPY	(register,0x10,4,a0)	(const,0x1,4)
```

The `jal` is 4 bytes long but its p-code accounts for 8: the `li` in its delay slot is the second `COPY`.
Because the sweep moves on by length, the `li` then also appears as an instruction of its own.

## Speed

`--quiet --timing` measures without the cost of printing:

```sh
basilisk sleigh decode --language x86:LE:64:default --quiet --timing code.bin
```

```text
timing	load_seconds=0.030192	decode_seconds=0.183622	instructions=332522	ops=2639511	errors=52672	bytes=1000000
```

That run decoded a megabyte of random bytes — the worst case, since many of them are not instructions —
and lifted 332,522 instructions to 2.6 million p-code operations in 0.18 seconds on one core of a laptop.
Loading the x86-64 language took 30 ms. The project's budget is to be at least as fast as Ghidra's C++
engine at each of these; the measurements are in `docs/PERF.md` in the repository.

## Exit status

| Status | Meaning |
|---|---|
| 0 | The sweep ran. Bytes that did not decode are in the output, not in the status |
| 1 | The language was not found or could not be loaded (for example, its `.sla` is not compiled) |
| 2 | A bad command line |

## Differences from Ghidra

Three, all in places where Ghidra's C++ engine has no defined result. They are recorded as a decision in
the repository (ADR-024):

- **Instructions with more than 20 operands.** Ghidra's C++ engine cannot decode them and reports "SLEIGH
  parser out of state space"; two PowerPC AltiVec instructions are affected. Basilisk decodes them.
- **Instruction bytes past the sixteenth** read as zero.
- **An instruction that both refers to the address after the next instruction and changes the context of
  the next one** is decoded from the context as it stands, without Ghidra's cache. Among Ghidra's languages
  only the `Toy` test language has such an instruction.
