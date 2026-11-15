---
title: basilisk sleigh compile
description: Compile a SLEIGH specification into a .sla file with the same content as Ghidra's compiler produces.
sidebar:
  order: 3
  label: sleigh compile
---

`basilisk sleigh compile` is Basilisk's SLEIGH compiler. It turns a processor specification written in
SLEIGH (`.slaspec`, with the `.sinc` files it includes) into the compiled `.sla` file that decoding uses.
It takes the options of Ghidra's `sleigh` command and prints the same warnings.

```text
basilisk sleigh compile [options...] <infile.slaspec> [<outfile.sla>]
basilisk sleigh compile [options...] -a [<directory>]
```

:::note[How exact it is]
For all 150 specifications Ghidra ships, the output has the same content as the file Ghidra's C++ compiler
writes: after decompression the two are equal byte for byte. No differences are tolerated in that test.
:::

## Compiling one specification

```sh
basilisk sleigh compile x86-64.slaspec
```

writes `x86-64.sla` beside the input. Name a second file to write somewhere else. An input named without
`.slaspec` gets it appended.

The x86-64 specification, one of the largest, compiles in about a quarter of a second.

## Compiling a directory

```sh
basilisk sleigh compile -a "$BASILISK_GHIDRA_DIR/Ghidra/Processors"
```

compiles every `.slaspec` under the directory, each beside itself, and continues after a failure. Without a
directory it uses the current one. All 150 of Ghidra's specifications compile in under five seconds on a
laptop; the last line reports the count:

```text
150 languages successfully compiled
```

## Options

| Option | Meaning |
|---|---|
| `-a [dir]` | Compile every `.slaspec` under the directory |
| `-y` | Write the `.sla` in the XML debug format instead of the compressed binary form |
| `-u` | Print a warning for each unnecessary p-code operation |
| `-l` | Report pattern conflicts |
| `-n` | Print a warning for each constructor that does nothing (a NOP) |
| `-t` | Print a warning for each temporary that is written and never read |
| `-e` | Require the `local` keyword for temporaries |
| `-c` | Print a warning for each constructor with colliding operands |
| `-f` | Print a warning for each unused token field |
| `-s` | Treat register names as case sensitive |
| `-DNAME=VALUE` | Define the preprocessor macro `NAME` |
| `-dMODULE` | Define `MODULE` as that processor module's directory under `$BASILISK_GHIDRA_DIR` |
| `-i <file>` | Read options from a file, one per line; lines starting with `#` are comments |
| `-x` | Accepted and ignored (it turns on parser debugging in Ghidra) |

Without `-u`, `-n`, `-t` and the like, the compiler prints one summary line per kind of warning and says
which option lists the cases:

```text
WARN  390 NOP constructors found
WARN  Use -n switch to list each individually
```

## Errors

An error names the file and line, and no output file is written:

```text
tiny.slaspec:9 - ERROR tiny.slaspec:9: in table "instruction" constructor starting at line 9
tiny.slaspec:9 - ERROR tiny.slaspec:9:    Main section: Could not resolve at least 1 variable size
No output produced
```

The messages are Ghidra's. The output file is written through a temporary file, so a failed or interrupted
compilation never leaves a partial `.sla` behind.

## Exit status

These are the statuses of Ghidra's compiler, so that build scripts written for it keep working.

| Status | Meaning |
|---|---|
| 0 | Success |
| 2 | The compilation failed |
| 1 | A bad command line |

## Differences from Ghidra

- **The same output on every machine.** The output of Ghidra's own C++ compiler depends on how it was
  built: builds for 64-bit ARM differ from builds for x86-64 in 14 of the 150 files, because of how
  floating-point arithmetic is contracted when the compiler chooses between decision-tree fields. Basilisk
  produces the x86-64 Linux result on every machine.
- **Errors carry the location of the mistake.** Ghidra reports some errors at the end of the file, where
  its lexer happens to be when a late pass runs.
- **Both of Ghidra's command lines.** Ghidra has a C++ and a Java SLEIGH compiler with slightly different
  options; Basilisk accepts the options of both.
- **A file that starts with a byte-order mark** is accepted. Both of Ghidra's compilers reject it with a
  syntax error.

Making every diagnostic equal to Ghidra's, one test case per message, is still open work in milestone M2.

## See also

- [How SLEIGH decodes an instruction](/docs/internals/sleigh/).
- [`basilisk disasm`](/docs/cli/disasm/) uses the compiled files.
