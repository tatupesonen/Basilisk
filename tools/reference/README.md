# Reference tools

basilisk is measured against Ghidra itself (ADR-007). This directory holds
what is ours in that arrangement; Ghidra's own tools are built from its
source by `scripts/build-reference.sh` and never checked in. Nothing here
ships in the product (ADR-005). Specification:
`docs/features/reference-tools.md`.

| File | What it is |
|---|---|
| `pcodedump.cc` | A small C++ program linked against Ghidra's SLEIGH engine that prints disassembly and p-code in the format below |
| `patches/` | Patches the build script applies to its **copy** of Ghidra's source |
| `measure.sh` | Measures the reference tools for the baseline in `docs/PERF.md` |

## Building

```
scripts/build-reference.sh [--force] [--jobs N]
```

Reads the Ghidra tree (`BASILISK_GHIDRA_DIR`, default `../ghidra`) and
writes only below the reference directory (`BASILISK_REFERENCE_DIR`,
default `../reference`):

```
reference/
  src/{cpp,zlib,unittests}   the copy of Ghidra's sources the build runs in
  bin/sleigh                 Ghidra's SLEIGH compiler        (sleigh_opt)
  bin/decomp                 Ghidra's decompiler console     (decomp_opt)
  bin/decomp_test            Ghidra's test runner            (decomp_test_dbg)
  bin/pcodedump              the oracle in this directory
  Ghidra/Processors/<Module>/data/languages/
                             a copy of each language directory with a
                             compiled .sla beside every .slaspec
  logs/                      make.log, one log and time per .slaspec,
                             unittests.log, datatests.log
  .state/                    input fingerprints that make reruns incremental
  STAMP                      Ghidra commit, tool versions, the test baseline,
                             and the sha256 and size of every tool and .sla
```

It needs a C++11 compiler (`g++` or `CXX`), a C compiler, `make`, `patch`
and `sha256sum` or `shasum` — nothing beyond a stock developer machine, no
`sudo`. `bison` and `flex` are **not** needed: Ghidra checks its generated
parsers in, and the script keeps `make` from regenerating them (macOS ships
bison 2.3, which is too old for the grammars).

Each step records a fingerprint of its inputs and is skipped when nothing
changed, so a second run does no work; a new Ghidra commit, an edited patch
or `pcodedump.cc`, or a deleted output rebuilds what depends on it.

### How the build differs from Ghidra's Makefile

The source is Ghidra's; these `make` variables are overridden on the command
line:

| Variable | Value | Why |
|---|---|---|
| `ARCH_TYPE` | empty | The Makefile forces `-arch x86_64` on macOS and `-m32` on Linux hosts that are not x86-64; we build for the host |
| `ADDITIONAL_FLAGS` | `-w -DLOCAL_ZLIB -fsigned-char` | No warnings from Ghidra's code; use the bundled `zlib/` as Ghidra's Gradle build does (`buildNatives.gradle`), instead of a system zlib; `char` signed, as Ghidra's code assumes (on Linux aarch64, where it is unsigned, `decomp_test` otherwise spins on every data test). Drops the Makefile's `-mmacosx-version-min=10.6` |
| `LNK` | `../zlib/libz.a` | The bundled zlib, compiled with `-DNO_GZIP` as in the Gradle build |
| `BFDLIB` | empty | No GNU BFD (not on a stock machine, and GPL) |
| `EXTRA` | the Makefile's expression minus `analyzesigs bfd_arch codedata loadimage_bfd` | The Makefile compiles every `*.cc` into the console; these four include the BFD load image. The console and the test runner lose the `codedata` and signature-analysis commands, which no data test uses |

### Patches

| Patch | Why |
|---|---|
| `0001-opbehavior-int-min-macro.patch` | `opbehavior.cc` declares local constants named `INT_MIN`. With Apple clang 17 `<limits.h>` reaches the file through the standard headers and `INT_MIN` is a macro there, so the unmodified file does not compile. The patch adds `#undef INT_MIN` after the includes; behaviour is unchanged |

### How the languages are compiled

As Ghidra's Gradle build does it (`gradle/processorProject.gradle`, task
`sleighCompile`): each `.slaspec` is compiled with the
`sleighCompileOptions` listed in its module's `build.gradle` and
`-DBaseDir=<root>`, where `%%Module%%` in an option stands for that
module's path below the root. At the pinned Ghidra commit the options are
only `-l` (and `-t` for Hexagon), no module defines a preprocessor macro and
no specification includes a file from another module; the script handles
both for when that changes.

## `pcodedump`

```
pcodedump <root> <language-id> <base-address> [options] < bytes
```

* `<root>` — a directory with Ghidra's layout that holds compiled `.sla`
  files: the reference directory.
* `<language-id>` — for example `x86:LE:64:default`. The `.ldefs` that
  defines it names the `.sla` and `.pspec`; both are resolved beside that
  `.ldefs`.
* `<base-address>` — byte offset of the first input byte in the language's
  default code space, decimal or `0x` hexadecimal.
* `--context NAME=VALUE` — set a context variable over the whole code
  space, overriding the processor specification (`--context TMode=1` decodes
  ARM bytes as Thumb). Repeatable.
* `--hex HEXBYTES` — take the bytes from the argument instead of standard
  input.
* `--quiet` — decode and lift everything but print only the `H` and `T`
  records (for timing).
* `--timing` — print load and decode times on standard error.

Before decoding it does what Ghidra's `SleighArchitecture` does: applies
the language's `<truncate_space>` entries and the `<context_data>` of the
processor specification. It then decodes the bytes as a **linear sweep**:
disassemble at the current address, lift, advance by the instruction's
length. Context changes an instruction commits (`globalset`) take effect
for later instructions, as in Ghidra's engine. Bytes past the end of the
input read as zero.

Exit status: 0 when the sweep ran (decode errors are in the output, not the
status), 1 when the language cannot be found or loaded, 2 for a bad command
line.

### Output format, version 1

The format is a contract: `insta` snapshots of it are checked in (for
example `crates/bk-testkit/tests/snapshots/`) and
`bk_testkit::tools::parse_dump` reads it. A change bumps the version in the
`H` record, here, in `pcodedump.cc` and in the parser together.

The output is lines of tab-separated fields; the first field is a
one-letter record tag. Numbers written `0x…` are lower-case hexadecimal
without padding; other numbers are decimal. In text fields (mnemonic,
operand text, messages) a backslash, tab, line feed and carriage return are
written `\\`, `\t`, `\n`, `\r`.

| Record | Fields after the tag | Meaning |
|---|---|---|
| `H` | version, language id, code space name, base address (`0x`), byte count | First line |
| `I` | address (`0x`), length, flow length, bytes (hex pairs), mnemonic, operand text | One instruction. The sweep advances by *length*. *Flow length* is the number of bytes the instruction's p-code accounts for: larger than *length* when delay-slot instructions are folded into it, equal otherwise. The operand text may be empty |
| `P` | opcode name, output varnode or `-`, input varnodes… | One p-code op of the preceding `I`, in order |
| `U` | kind, message | The preceding `I` disassembles but did not lift; it has no `P` records. Kind is `unimplemented` (semantics marked `unimpl`), `bad-data` (bytes its p-code needs, such as a delay slot, do not decode) or `error` |
| `E` | address (`0x`), length, bytes, kind, message | The bytes here are not an instruction. Kind is `bad-data` (length 1; decoding resumes at the next byte), `truncated` (an instruction that needs bytes past the end of the input; covers the rest of the input and is the last record) or `error` (length 1) |
| `T` | number of `I` records, number of `E` plus `U` records | Last line; its absence means the output was cut short |

A varnode is `(space,0xOFFSET,SIZE)` or `(space,0xOFFSET,SIZE,NAME)`:

* `space` is the address space's name (`register`, `ram`, `unique`,
  `const`, …), `OFFSET` the byte offset in it (the value, for a constant),
  `SIZE` the size in bytes.
* `NAME` is present when a register is exactly that location (same space,
  offset and size).
* The first input of `LOAD` and `STORE` is a constant that identifies an
  address space. Ghidra's engine holds a host pointer there; the dump prints
  the space's index in the language's space table as the offset and the
  space's name as `NAME`: `(const,0x3,8,ram)`.

Example (`push rbp; ret`, then a byte that is not an instruction):

```
H	1	x86:LE:64:default	ram	0x1000	3
I	0x1000	1	1	55	PUSH	RBP
P	COPY	(unique,0x4f900,8)	(register,0x28,8,RBP)
P	INT_SUB	(register,0x20,8,RSP)	(register,0x20,8,RSP)	(const,0x8,8)
P	STORE	-	(const,0x3,8,ram)	(register,0x20,8,RSP)	(unique,0x4f900,8)
I	0x1001	1	1	c3	RET	
P	LOAD	(register,0x288,8,RIP)	(const,0x3,8,ram)	(register,0x20,8,RSP)
P	INT_ADD	(register,0x20,8,RSP)	(register,0x20,8,RSP)	(const,0x8,8)
P	RETURN	-	(register,0x288,8,RIP)
E	0x1002	1	06	bad-data	r0x00001002: Unable to resolve constructor
T	2	1
```

Things to know when comparing against it:

* Offsets are byte offsets, as Ghidra's C++ stores them, also in spaces
  whose addressable unit is larger than a byte.
* A delay-slot instruction appears twice: inside the p-code of the branch
  before it (whose flow length covers it) and as an instruction of its own,
  because the sweep advances by length.
* Offsets in the `unique` space are the engine's temporaries. They are
  stable for a given `.sla`, but a different compiler may number them
  differently; compare them up to renaming if that is the case.
* Only the processor specification's context is applied, not a compiler
  specification's (three Go `.cspec` files carry `<context_data>`).

## Measuring

`tools/reference/measure.sh` prints the numbers recorded under "Reference
tools" in `docs/PERF.md`: time to compile every language, `.sla` sizes,
language load time and decode throughput of `pcodedump` on x86-64 code, and
the time of the decompiler's tests.
