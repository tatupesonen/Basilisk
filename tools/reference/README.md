# Reference tools

Basilisk is measured against Ghidra itself (ADR-007). This directory holds
what is ours in that arrangement; Ghidra's own tools are built from its
source by `scripts/build-reference.sh` and never checked in. Nothing here
ships in the product (ADR-005). Specification:
`docs/features/reference-tools.md`.

| File | What it is |
|---|---|
| `pcodedump.cc` | A small C++ program linked against Ghidra's SLEIGH engine that prints disassembly and p-code in the format below |
| `snippetdump.cc` | Compiles p-code snippets (the `<pcode>` bodies of `.cspec`/`.pspec` files) with Ghidra's `PcodeSnippet` and prints the templates; format under "`snippetdump`" |
| `consoleext/` | Basilisk's console extension (the `bk …` commands, ADR-042), linked into `decomp_bk` and `decomp_bk_dbg`; commands and formats under "The console extension" |
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
  bin/snippetdump            the p-code snippet oracle in this directory
  bin/decomp_dbg             Ghidra's CPUI_DEBUG console      (decomp_dbg)
  bin/decomp_bk              decomp_opt's objects + consoleext/
  bin/decomp_bk_dbg          decomp_dbg's objects + consoleext/
  src/consoleext/{opt,dbg}/  the extension's objects
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

Step `[1b/5]` adds the three debugging consoles without touching what step
1 built: `make decomp_dbg` in the same source copy with the same overrides
(only `com_dbg/` objects and `decomp_dbg` are made), then the extension's
sources compiled **outside** the Makefile — with the flags the Makefile
gives `com_opt/` and `com_dbg/` objects (read from make itself through
`consoleext/vars.mk`), plus `-fno-access-control` and `-I src/cpp` — and
linked with exactly the objects of `decomp_opt` and `decomp_dbg`. The
extension registers its commands through a static `IfaceCapability`, so
linking its objects is all it takes; Ghidra's files are compiled without
the flag and `bin/decomp` stays Ghidra's, byte for byte. `decomp_dbg` and
the extension have their own fingerprints (`.state/decomp_dbg.fp`,
`.state/consoleext.fp`): an edited extension source recompiles the
extension and relinks only the two `_bk` consoles. `STAMP` lists all eight
tools and `console_extension: <sha256 of the extension's sources>`.

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

## `snippetdump`

```
snippetdump <root> <language-id> < records
```

Loads the language as `pcodedump` does (resolving the `.sla` beside the
`.ldefs`), applies the language's `<truncate_space>` entries, and compiles
each input record with Ghidra's `PcodeSnippet` exactly as
`PcodeInjectLibrarySleigh::parseInject` does: parameters added in record
order with their indices, the unique base set, `parseStream`, and on
success the carried base updated. Exit status: 0 when every record was
read, 1 when the language cannot be loaded, 2 for a bad command line, 3 for
a malformed record.

### Record format, version 1

Lines of tab-separated fields. Text fields are escaped: backslash, tab,
line feed, carriage return and NUL are written `\\`, `\t`, `\n`, `\r`,
`\0`.

Input, one line per snippet:

| Fields | Meaning |
|---|---|
| `S`, source, base, body, then `index:name` per parameter | *source* is a label echoed back; *base* is `continue` (use the carried base and advance it, as for call fix-ups and injections), `0x…` (set the carried base to this value first; the library starts at `unique_base + 0x200`), or `fixed:0x…` (use this base and leave the carried one alone, as for executable p-code at 0x2000); *body* is the snippet text |

Output:

| Record | Fields after the tag | Meaning |
|---|---|---|
| `H` | version, language id, `unique_base` (`0x`), initial carried base (`0x`) | First line |
| `O` | source, base used, base after, error count (0 or 1: whether any error was reported), first error, template XML | Compiled (possibly with errors Ghidra ignores). The XML is `ConstructTpl::encode(-1)` through `XmlEncode` with formatting |
| `F` | source, base used, `rejected` or `exception`, message | Not compiled. `rejected`: `parseStream` returned false; the message is `getErrorMessage()`, the first error. `exception`: a `LowlevelError` escaped (`SleighError` from `PcodeCompile`); the message is its text |
| `T` | number of `O`, number of `F` | Last line |

## The console extension (`consoleext/`, `decomp_bk`, `decomp_bk_dbg`)

Basilisk's commands for measuring the decompiler port
(`docs/features/decomp-oracle.md`, ADR-042). They exist only in
`bin/decomp_bk` and `bin/decomp_bk_dbg`; every Ghidra command works there as
in `bin/decomp`. Run them like the console itself:

```
echo | LC_ALL=C SLEIGHHOME=<reference> <reference>/bin/decomp_bk -i SCRIPT
```

Errors are the console's own (`Execution error: <message>`, the script
stops). Files are written atomically (`<file>.part`, then renamed). Paths
cannot contain white space (the console has no quoting). The commands that
read graph files need an architecture only for an opcode table; `load test
file <datatests>/elseif.xml` is the conventional set-up.

| Command | Effect |
|---|---|
| `bk version` | `bk console extension (<format versions>)` |
| `bk list actions` | the current root's actions and rules, format `bkactions 1` (below), to the bulk stream |
| `bk break start <n>` | start breakpoint on the action at position `n` of `bk list actions` (a rule has none: Ghidra checks only a rule's action breakpoint, `ActionPool::processOp`) |
| `bk break action <n>` | action breakpoint on the action or rule at position `n` |
| `bk break clear` | clears every breakpoint of the current root |
| `bk dump blocks <file>` | the current function's basic blocks as a graph file, with their real facts |
| `bk dump structure <file>` | the current function's structured hierarchy (`P` and `S` records; leaves are `L<position of the basic block in the block list>`) |
| `bk cfg analyze <graph> <out>` | Ghidra's analyses on a graph file: format `bkcfg 1` |
| `bk structure <graph> <out> [bare\|asgiven] [finish] [trace] [xml <file>]` | Ghidra's structurer on a graph file: format `bkstruct 1` |
| `bk dump state <file>` | the complete state of the current function: format `bkstate 1` |
| `bk capture structure <prefix>` | decompiles the current function, stopping at every `blockstructure` start, the action after each and the action after `finalstructure`; writes `<prefix>.<k>.blocks.bkg` at each start whose structure is empty (structuring run *k*), `<prefix>.<k>.structure.bks` at the next action, `<prefix>.final.{structure.bks,state}` and `<prefix>.end.{structure.bks,state}` |
| `bk pcode record <file>` | from now on, records every answer of Ghidra's lifter (format `pcoderec 1`); give it after `load test file`/`load file` and before the first `load function` |
| `bk pcode replay <file>` | from now on, answers `oneInstruction` and `instructionLength` from a recording, by address |
| `bk pcode stop` | ends recording (writes the file) or replay |
| `bk trace stream` | points the debug stream, where the `OPACTION_DEBUG` trace goes, at the bulk output (`decomp_bk_dbg` only; `load test file` already does it) |

Positions are what `list action` prints; give them by path from `bk list
actions` (`ActionList::position_of` in `bk-testkit`), never as numbers
written into a script, so that a change in Ghidra's action list cannot shift
a test silently. Breakpoints by position reach the actions whose names
occur more than once (`blockstructure` at 0168 and 0231, …), which Ghidra's
`break start <name>` cannot.

### Conventions of every format

One record per line, fields separated by one tab, LF line ends, a header
naming the format and its version, a final `T` record. Decimal numbers
have no sign (unless negative) and no leading zeros; hexadecimal numbers
are `0x` and lower-case digits without leading zeros (`0x0`). A list field
is comma-separated, `-` when empty. A text field escapes `\`, tab, LF, CR
and NUL as `\\`, `\t`, `\n`, `\r`, `\0`. An address is `<space>:0x<offset>`.
Each number has one spelling, so a parsed file written back is the same
bytes; `bk-testkit`'s readers (`bk_testkit::oracle`) enforce that. A change
to a format bumps its version here, in the extension and in the reader
together.

### Graph files, `bkgraph` version 1

The input of `bk cfg analyze` and `bk structure`, the output of `bk dump
blocks`.

```
H	bkgraph	1	<node count>
N	<id>	<index>	<flags hex>	<facts>	<idom id or ->	<numdesc>
I	<id>	<src>:<src out-slot>:<label hex>,…     (in-edges in order; - if none)
A	<id>	<start address>	<stop address>      (optional; basic blocks only)
T
```

Per node, in Ghidra's list order, an `N`, an `I` and optionally an `A`
record; ids are `0..n-1` in that order. `flags` are `FlowBlock::flags`,
labels `FlowBlock::edge_flags`. Out-edge order is given by the slot
numbers: every out-slot of every node must be named by exactly one in-edge
(Ghidra's XML reader would leave a slot uninitialised). `<facts>` is a
subset of `csrn` in that order, or `-`: `c` too complex to be a condition
(`isComplex`), `s` switch out (`f_switch_out`, also set in the flags), `r`
ends in `RETURN`, `n` negating the condition changes data-flow
(`docs/features/decomp-cfg.md` 4.1). A node cannot have both `s` and `r`.
`index`, `idom` and `numdesc` are used only by `asgiven` mode. `bk dump
blocks` writes `c` from `BlockBasic::isComplex`, `s` from the flags, `r`
from the last op, and always `n`. Ghidra's plain blocks (what `structure
blocks` builds from XML) have the facts `c`.

The structurer runs on **fact blocks**: plain `FlowBlock`s of the extension
whose `isComplex` returns `c`, whose `negateCondition` logs the flip, swaps
the block's own edges and returns `n`, and whose `lastOp` is null or, for
`r`, a `PcodeOp` with opcode `RETURN` and no parent (read only by
`compareFinalOrder`).

### Analysis dumps, `bkcfg` version 1 (`bk cfg analyze`)

The graph is copied (`buildCopy`), and on the copy `structureLoops`,
`calcForwardDominator`, `clearVisitCount` and a `CollapseStructure`'s
`orderLoopBodies` run.

```
H	bkcfg	1	ok|error	<message or ->
O	<input ids in list order after the analysis>
N	<id>	<index>	<idom id or ->	<numdesc>	<dominator depth>     (list order)
I	<id>	<src>:<src out-slot>:<label hex>,…                   (list order)
R	<root ids in rootlist order>
L	<head>	<depth>	<exit or ->	<uniquecount>	<tails>	<top>bottom,…	<container head or ->
T
```

One `L` record per `LoopBody` in Ghidra's list order (deepest first). On a
`LowlevelError` the header says `error` with Ghidra's message and only `T`
follows.

### Structure dumps, `bkstruct` version 1 (`bk structure`, `bk dump structure`)

`bk structure` builds fact blocks, copies them (`buildCopy`); in `bare`
mode (the default) runs `structureLoops` and `calcForwardDominator` on the
copy, as `structure blocks` does, while `asgiven` takes index, dominator,
descendant count and labels from the file, as `ActionBlockStructure` takes
them from the function; then collapses; with `finish` runs `orderBlocks`,
`scopeBreak(-1,-1)`, `markUnstructured`, `markLabelBumpUp(false)`
(`ActionFinalStructure` without `finalizePrinting`). The collapse runs
twice, on two copies: once by the extension's copy of
`CollapseStructure::collapseAll`/`collapseInternal`/`collapseConditions`,
which calls Ghidra's own rule methods in Ghidra's order and logs them, and
once by Ghidra's unmodified `collapseAll`; unless both give the same flips,
change count and hierarchy the command writes `error` with `trace replica
differs`. `xml <file>` also writes the result with Ghidra's encoder
(`BlockGraph::encode`, what `structure blocks` writes).

```
H	bkstruct	1	ok|error	<message or ->
G	<source>	<out-slot>	<target>	<cause>         (each new goto mark)
F	<leaf>                                          (each condition flip)
C	<data-flow change count>
S	<node>	<kind>	<index>	<flags hex>	<depth>	<leaf count>	<parent or ->	<components>	<kind data>	<in-edges>	<out-edges>
P	<top-level nodes in list order>
R	<seq>	<rule>	<node>                            (with trace)
T
```

* Node names: leaves (`BlockCopy`) are `L<input id>` (`bk dump
  structure`: `L<position of the basic block>`); structured nodes are
  `S<n>`, numbered in pre-order of the final hierarchy (top-level list
  order, components in order). `G`, `F` and `R` records name nodes as they
  are at the end (nodes are never freed).
* One `S` record per node, leaves included, in that pre-order. Kinds are
  Ghidra's with `if` and `ifnoexit` as their own names (`typeToName` writes
  `properif` and `ifelse`): `copy`, `goto`, `multigoto`, `list`,
  `condition`, `if`, `ifelse`, `ifnoexit`, `ifgoto`, `whiledo`, `dowhile`,
  `infloop`, `switch`. Depth is `getStructureDepth()`, leaf count
  `getBasicCount()`.
* Kind data: `goto` and `ifgoto` `<target or ->,<goto type hex>`;
  `multigoto` `<targets>,…,default` or `…,-`; `condition` the stored opcode
  name (`INT_OR`, `BOOL_AND`, `BOOL_OR`); `whiledo` `overflow` or `-`;
  `switch` per case in `caseblocks` order
  `<node>:<outindex>:<chain>:<gototype hex>:<isexit 0|1>:<isdefault 0|1>`;
  every other kind `-`.
* Edges: `<node>:<reverse index>:<label hex>`, in order.
* `G`: after `selectGoto` (cause `selected` when it returned a block,
  `clipped` when `clipExtraRoots` marked edges), after a `ruleBlockSwitch`
  that matched without building (`switchskip`) and after `ruleCaseFallthru`
  (`fallthru`), the level is scanned in list order and out-slot order for
  `f_goto_edge` labels that were not there before; one record per new mark.
* `F`: the fact blocks' `negateCondition` calls, in order.
* `R` (`trace`): one per rule application in the collapse: running number,
  rule (`blockgoto`, `blockcat`, `blockor`, `blockproperif`, `blockifelse`,
  `blockwhiledo`, `blockdowhile`, `blockinfloop`, `blockswitch`,
  `blockifnoexit`, `casefallthru`), the node it was applied to.
* `bk dump structure` writes only `H`, `S`, `P` and `T`.

### Action lists, `bkactions` version 1 (`bk list actions`)

```
H	bkactions	1	<root name>	<line count>
<line as list action prints it>	<full path>
T
```

The line is rendered as `Action::print` and `ActionPool::print` render it
(position `setw(4)`, ` repeat ` or eight blanks, `!` once per function, `S`
and `A` breakpoint flags, `depth*5+2` blanks, the name; rules: position,
`D` when disabled, `A`, blanks, name) in a fresh stream — `list action`
itself prints into the console's stream, whose fill and base earlier
commands may have changed — without `list action`'s blank separator lines
and `<--` state marker. The path joins the names from the root with `:`
(`universal:fullloop:mainloop:blockstructure`); a line's position is its
index.

### State dumps, `bkstate` version 2 (`bk dump state`)

Everything that defines where Ghidra's pipeline stands for the current
function, every object named by a reproducible key, never a host pointer:
varnodes `v<create index, hex>`, ops by sequence number
`<address>:0x<time>` (`-:0x…` when the op has no address), basic blocks
`b<index>`, call specs `c<position in qlst>`, jump tables `j<position>`,
high variables `h<n>` (numbered by their smallest member's create index),
symbols `s<symbol id, hex>`, data types `t<n>` (position in `@types`, in
order of first reference). The three kinds of host pointer Ghidra keeps in
varnode offsets are written by key: an `iop` varnode's offset as
`op:<seqnum>`, an `fspec` varnode's as `call:c<k>` (`call:-` when the call
spec is no longer in `qlst`: Ghidra deleted it and the varnode keeps the
dangling pointer), a `LOAD`/`STORE` space constant (a constant of pointer
size equal to an `AddrSpace *`) as `space:<name>`; such a constant's `nzm`
is its key too. The varnode bank orders are written with those keys in
place of the pointers (op time, call-spec position — the largest key for a
dead one —, space index); Ghidra's own order among those varnodes follows
heap addresses.

```
BKSTATE	2	<ghidra commit>	<architecture id>
@<section>	<record count>          (18 sections, in this order, each present)
…
END	<number of lines before END>
```

| Section | Records (fields after the tag) |
|---|---|
| `@function` | `F` name, display name, entry, size, flags, clean_up_index, high_level_index, cast_phase_index, minLanedSize · `K` next create index, uniqbase, next unique offset, next op time · `W` per comment of the function (warnings included): type, address, uniq, text · `O` the local overrides as `Override::encode` writes them, when any · `X` per `lanedMap` entry: storage, size, whole size, lane-size mask · `U` per `unionMap` entry: type id, op time, encoding, base type, resolved type, field, lock |
| `@actions` | per line of `list action`, in order: `A` position, path, status, count, lcount (`-` until Ghidra sets them), count_tests, count_apply, flags, breakpoint, state (`restart:<curstart>`, `child:<i>` and `op:<seqnum>/<rule index>` where a group or pool stands mid-way) · `R` position, path, flags, count_tests, count_apply, breakpoint |
| `@spaces` | `P` index, name, type, shortcut (or `-`), word size, address size, flags, delay, dead-code delay |
| `@varnodes` | `V` per varnode, by create index: id, space, offset, size, flags, addlflags, mergegroup, def, readers (in `descend` order), type, consumed, nzm, high, symbol entry (`s<id>:<position in mapentry>`) |
| `@locorder`, `@deforder` | one `O` record: every varnode, in the bank's order with canonical keys |
| `@ops` | `O` per op (`optree` and `alttree`), by sequence number: seqnum, order, opcode, flags, addlflags, output, inputs, parent block, `alive`/`dead`, `main`/`alt`, the op as `print raw` prints it |
| `@oplists` | `L` per list of `PcodeOpBank` (`alive`, `dead`, `store`, `load`, `return`, `userop`): the ops in list order |
| `@blocks` | `B` per basic block in list order: block, position, flags, immediate dominator, numdesc, cover ranges (`<space>:0x<first>-0x<last>`), ops in block order · `E` per in-edge of that block: source, out-slot, label |
| `@structure` | the `S` and `P` records of a structure dump (leaves `L<position of the basic block>`), when the hierarchy is not empty |
| `@proto` | the function's prototype: `M` model (or `-`), extrapop (`-` without a model: Ghidra leaves it uninitialised until `setModel`), flags, injectid, returnBytesConsumed · `Q` per parameter: `in`/`out`, position, name, storage, size, type, flags (`t` type lock, `n` name lock, `z` size lock, `h` this, `i` indirect storage, `r` hidden return, `u` name undefined) · `X` per effect: type, address, size · `Y` per likely-trash location: address, size · `A` per `ParamActive` (`activeoutput`): direction, slotbase, stackplaceholder, numpasses, maxpass, isfullychecked, needsfinalcheck, recoversubcall, joinMostSigFirst · `T` per trial of it: address, size, flags, model entry (`<space>:0x<base>:<size>`), slot, offset, fixedPosition |
| `@callspecs` | per call spec in `qlst` order: `C` call, op, name, entry, effective_extrapop, stackoffset, stackPlaceholderSlot, paramshift, isinputactive, isoutputactive, isbadjumptable, isstackoutputlock, inputConsume; then its prototype records (`M`, `Q`, `X`, `Y`) and, when active, `A`/`T` for `activeinput` and `activeoutput` |
| `@jumptables` | `J` per table: table, BRANCHIND, opaddress, addresstable, block2addr (`<out-edge position>:<address index>`), labels, defaultBlock, lastBlock, switchVarConsume, recoverCount, displayFormat, partialTable, collectloads, defaultIsFolded, model kind, original model kind, isOverride · `D` per load table: address, size, entries |
| `@scope` | `Z` the local scope: name, stack space, stackGrowsNegative, rangeLocked, overlapProblems, openParamRefs, minParamOffset, maxParamOffset, owned ranges · `N` name recommendations · `D` dynamic recommendations · `Y` type recommendations · `S` per symbol, by id: id, name, display name, type, flags, dispflags, category, catindex, nameDedup, kind, wholeCount · `M` per map entry of it: storage (address, `hash:0x…` or `-`), size, offset, use-limit ranges, extraflags, properties · `G` per symbol of another scope that the function's records name: id, name, scope, storage |
| `@scope`, version 2 | after the `G` records, when there is a local scope: `I` the scope's Ghidra id (`uniqueId`), next symbol counter (`nextUniqueId`), display name, parent's id (or `-`), children's ids in id order · `C` per category vector, in category order: its slots in `catindex` order (`s<id>`, `null` for an empty slot) · `E` `multiEntrySet` in its order · `R` per record of each space's entry map, spaces in index order, records in record-list order: space, entry ref, first, last, the subsort computed at insertion (use index, use offset) · `F` per fragment, same spaces, in multiset order: space, first, last, entry ref · `Q` the dynamic entry list in order. An entry ref is `s<symbol id>:<index of the entry in the symbol's mapentry>` (the real index, not `Symbol::getMapEntryPosition`, which gives 0 for every piece). |
| `@heritage` | `Z` pass, maxdepth · `I` per heritaged space: space, delay, deadcodedelay, deadremoved, loadGuardSearch, warningissued, hasCallPlaceholders · `M` per `globaldisjoint` range: address, size, pass · `L` per load and store guard: `load`/`store`, op, space, pointerBase, minimum, maximum, step, analysis state · `C` loadCopyOps |
| `@highs` | `H` per high variable: high, members (`inst` order), numMergeClasses, highflags, flags, type, name representative, symbol, symbol offset, piece (`<first high of the group>:<offset>:<size>:<group size>:<group symbol offset>`) |
| `@types` | `T` per referenced type: name in the dump, Ghidra's id, metatype, size, name, `Datatype::encode` on one line |
| `@c` | `C` per line of `print C`, when the function is finished (`processing_complete` set and the root action not stopped mid-way: the flag survives `Funcdata::clear`) |

Version 1 (D00's first format) is version 2 without `@scope`'s `I`, `C`,
`E`, `R`, `F`, `Q` records; `bk-testkit` reads both and writes back the
version it read. Only the function's local scope is dumped; symbols of
other scopes are named by `G` references.

Left out, deliberately: host addresses; caches Ghidra rebuilds from the
state (covers, `HighVariable`'s cached properties beyond what `highflags`
says is valid, intersection caches); scratch valid inside one algorithm
(`Varnode::temp`, visit counts, marks); the architecture (spaces are
listed, models, types and global symbols referred to by name and id);
the partial `Funcdata` copies of jump-table recovery; the printer's state;
fields Ghidra never sets (`FuncCallSpecs::matchCallCount`); `Heritage`'s
per-pass work arrays (`domchild`, `augment`, `flags`, `depth`, `merge`),
rebuilt by every pass.

### Recorded p-code, `pcoderec` version 1 (`bk pcode record`)

The proxy translator that replaces `Architecture::translate` shares the
original's spaces and copies its endianness, alignment, unique base and
float formats; it forwards every method and, while recording, logs every
`oneInstruction` and `instructionLength` call in call order (repeats
included: flow is followed again by every `decompile`, by inlining and by
jump-table recovery).

```
H	pcoderec	1	<language id>	<compiler spec id>
X	<address>                              (addresses whose records differ)
I	<address>	<length>	<op count>     (oneInstruction returned; its P records follow)
P	<op address>	<opcode>	<output or ->	<inputs…>
U	<address>	unimplemented|baddata|error	<length or ->	<message>
L	<address>	<length>                     (instructionLength)
T	<I count>	<U count>	<L count>
```

Varnodes are written as `pcodedump` writes them: `(space,0xOFFSET,SIZE)`,
or `(space,0xOFFSET,SIZE,NAME)` when a register is exactly that location; a
`LOAD`/`STORE` space constant is `(const,0x<space index>,<size>,<space
name>)`. Replay answers by address — an `I` record replays its ops, a `U`
record rethrows `UnimplError` (with its length), `BadDataError` or
`LowlevelError` with the message — and refuses a recording with `X`
records (`context-dependent records at <address>`); an address that is not
in the recording is an error (`pcode replay: no record for <address>`).

### The trace (`decomp_dbg`, `decomp_bk_dbg`)

Ghidra's own `OPACTION_DEBUG` output (`Funcdata::debugModPrint`), with
`trace address` (no argument: the whole function) and `trace enable`
before `decompile`:

```
DEBUG <count>: <action or rule name>
<seqnum>: <op before, or ** when it was dead or had no block>
   <seqnum>: <op after, or **>
…
<empty line>
```

The records are written into the console's output, between its other
lines; `bk_testkit::oracle::Trace::extract` picks them out. The trace does
not cover the partial functions of jump-table recovery.

### The capture driver (`bk-oracle`)

`cargo run -p bk-testkit --bin bk-oracle -- capture <datatests|research|all>
<out>` runs, for every data test (in the data-test directory, as `load test
file <name>.xml` and the test's commands) and every research fragment (in
`docs/research/decompiler-quality`, its script as it is), four console
runs: `decomp_bk` with state dumps at the four standard points (the action
after `start`, the first start of `oppool1`, the start of `cleanup`,
`stop`; positions by path from `bk list actions`) and at the end, with
`print raw` at the first point and `print raw` and `print tree varnode` at
the end, recording the p-code; `decomp_bk` replaying that recording;
`decomp_bk_dbg` with the trace; `decomp_bk` with `bk capture structure`.
It also runs the plain script with `print raw`, `print tree varnode` and
`print tree block` after each decompilation through `decomp` and
`decomp_dbg`. It checks that every end dump is complete against the
console's own listings (`decomp-oracle.md` 6.2), that the replay gives the
same `print raw` (6.3) and that `decomp_dbg` prints what `decomp` prints,
host pointers aside (6.6); it runs everything twice and requires the two
captures to be byte-identical (6.5). `bk-oracle compare` classifies the
differences between two builds' captures by named cause, `bk-oracle check`
reports drift against `fixtures/decomp-oracle/`.

## The printer log (`patches-instr/`, `decomp_instr`)

The instrumented console of track D16a (`docs/research/decomp-out-spike/`)
logs what `PrintC` decides and what it asks its `Emit` object to do. It is
separate from the reference consoles: the reference directory and its
binaries are never touched.

* `patches-instr/0001-printer-hooks.patch` adds hooks to a **copy** of
  `prettyprint.*`, `printlanguage.*` and `printc.cc`, plus `bkinstr.hh`. A
  hook does nothing while its global pointer is null, which is the default,
  so the console is Ghidra's unless logging is switched on. The pushes are
  not virtual (`printlanguage.hh:292-296`), hence a patch rather than an
  `Emit` subclass. `patches-instr/source/make-patch.sh` regenerates the
  patch from the Ghidra tree (`BASILISK_GHIDRA_DIR`) and reproduces it byte
  for byte; each edit asserts that its anchor occurs exactly once.
* `patches-instr/bk_printlog.cc` is the logger, linked only into this
  console and compiled with `-fno-access-control` to read the printer's
  private state.
* `patches-instr/build-instr.sh [--jobs N] OUT` copies the decompiler
  sources from the Ghidra tree to `OUT/src`, applies `patches/*.patch` and
  then `patches-instr/*.patch`, and builds `OUT/bin/decomp_instr` with
  `build-reference.sh`'s compiler flags. Reruns are incremental. `OUT` must
  be outside the Ghidra tree and the reference directory (the script
  refuses otherwise).

Run it like `decomp` (`SLEIGHHOME` set to the reference directory), with
`BK_PRINTLOG=<prefix>` in the environment. Every document the printer
produces (`docFunction`, `docAllGlobals`, `docSingleGlobal`,
`docTypeDefinitions`: `print C`, `print C xml`, `print C flat`, `print
language <lang>`, `print C globals`, `print C types`) is appended to three
files. Without `BK_PRINTLOG` its output is byte-identical to `decomp`'s
(checked on 1,014 runs on each machine by the spike's `run_corpus.py`).

The formats follow the conventions above, with these keys: an op is
`<space>:0x<offset>:0x<time>/<OPNAME>` (its `SeqNum` and opcode), a varnode
`v<create index hex>`, a block `<type>:<index>` (types `basic`, `graph`,
`copy`, `goto`, `list`, `condition`, `if`, `ifelse`, `ifnoexit`, `ifgoto`,
`whiledo`, `dowhile`, `switch`, `infloop`; the logger names them itself
because `FlowBlock::typeToName` writes `ifelse` for `ifnoexit`,
`block.cc:696`), a symbol `s<id hex>:<name>`, a data-type `t<id
hex>:<display name>`, a function `f:<name>`; `-` is a null pointer. Each
file holds one `F` ... `/F` block per document; documents are numbered from
1 in each file.

### `<prefix>.tree`, `bkprinttree` version 1

What the printer decided. It is the only input of the spike's tree builder.

```
H	bkprinttree	1
F	<n>	<function name, or <docAllGlobals> etc.>
O	<language>	<mods hex>	<brace func>	<brace ifelse>	<brace loop>	<brace switch>	<comment start>	<comment end>	<line comment indent>	<instr comment types hex>	<header comment types hex>	<unplaced 0|1>	<nocasts 0|1>	<markup 0|1>
>	<event>	<mods hex>	<facts…>        (entry to a structural method)
<	<event>[	!]                         (its exit; ! if left by an exception)
P	<token>	<print1>	<print2>	<op>         (pushOp)
A	<tag>	<highlight>	<text>	<op>	<second>	<offset>   (pushAtom)
V	<varnode>	<op>	<mods hex>              (pushVn*; informative)
M	<pushMod|popMod|setMod|unsetMod>	<mods hex>    (informative)
M	<pushScope|popScope>	<scope name>     (informative)
/F	<n>	<ok|error>
T	<document count>
```

`P` and `A` records are logged after the push has been placed on the RPN
stack (after the inner `recurse()`), so they come in pre-order of the
expression tree and each token takes as many children as its `stage`
(the token table of `printc.cc:23-77` and `printjava.cc:21`). `<token>` is
the `OpToken`'s member name in `PrintC` (or `instanceof`); `print1` and
`print2` are its printed strings, which differ between languages
(`adjustTypeOperators`). In an `A` record `<tag>` is the `Atom` type
(`syntax`, `vartoken`, `functoken`, `optoken`, `typetoken`, `fieldtoken`,
`bitfieldtoken`, `casetoken`, `blanktoken`), `<highlight>` the
`syntax_highlight` number, `<text>` the final text (names, constants and
strings already formatted), and only the fields `emitAtom` reads for that
tag are filled (`printlanguage.cc:376-407`): `<op>` for every tag but
`syntax`, `typetoken` and `blanktoken`; `<second>` the varnode, function,
data-type or case value; `<offset>` the field offset. `V` and `M` records
are not needed to print; they are there to check the tree.

The facts of each `>` record, in order (the names are those of `PrintC`'s
methods; `printc.cc` lines):

| Event | Facts |
|-------|-------|
| `docFunction` (2784) | name, entry address |
| `lineComment` (`printlanguage.cc:593`) | indent (−1 is the configured one), comment type hex, address, text |
| `functionDeclaration` (2720) | display name, function, calling-convention name and unknown flag (`-` `-` when not printed) |
| `symbolScope` (233) | symbol, scope separator, the scope names printed (comma list) |
| `prototypeOutput` (2275) | the return varnode `beginReturnType` gets |
| `prototypeInputs` (2303) | parameter count, `...` flag, per parameter `hidden`, `symbol` or `type` |
| `scopeVarDecls` (2665) | scope name, category |
| `varDeclStatement`, `varDecl` (2644-2663) | symbol |
| `blockBasic` (2821) | block, last op, out count, fall-through-is-true, out blocks |
| `blockGraph`, `blockCopy`, `blockGoto`, `blockLs`, `blockCondition`, `blockIf`, `forLoop`, `blockWhileDo`, `blockDoWhile`, `blockInfLoop`, `blockSwitch` (2889-3508) | block, keyword op (last op of component 0 for if and the loops), components; then per kind: goto (`gotoPrints`, target, goto type), list (per pair: next is the flow successor), condition (opcode), if (kind, goto target, goto type), for/while (initialise op, iterate op, overflow syntax), switch (case count; per case block:goto type:exit:default) |
| `switchCase` (3281) | case index, first op of the case block, default flag, the default's label value or the label count |
| `label` (3319) | block, label text, address |
| `labelStatement`, `anyLabelStatement` (3353-3381) | block, label bumped up, jump target, unstructured target |
| `gotoStatement` (2385) | source block, its last op, target block, goto type hex |
| `statement`, `expression`, `inplaceOp`, `constructor`, `bitFieldStore`, `bitFieldExpression`, `commentGroup`, `opBranch`, `opCbranch`, `opBranchind` | op, input count, output varnode |
| `opReturn` (773) | op, input count, halt type hex |
| `commentBlockTree` (3402) | block |
| `commentFuncHeader`, `localVarDecls` | function |
| `globalVarDeclsRecursive` (2751) | scope name |
| `typeDefinition` (2451) | data-type |
| `structDefinition` (2201) | display name, field count |
| `enumDefinition` (2234) | display name, size, value count, value names (one field each) |

### `<prefix>.emit`, `bkprintemit` version 1

Every call `PrintLanguage` made on its `Emit` object, outermost calls only
(an `Emit` method calling another, such as `openBraceIndent` calling
`tagLine`, is one record), as `<method>` and its arguments in declaration
order: strings escaped, highlight as a number, pointers as keys, spaces as
`<count>	<bump>`. A call with a result ends in `	=	<result>`
(`beginFunction`, `beginBlock`, `openParen`, `openGroup`, `startIndent`,
`startComment`, `openBraceIndent`, `hasPendingPrint`, …). `setPendingPrint`
and `hasPendingPrint` carry no argument: the `PendPrint` is a stack object
whose address is reused.

### `<prefix>.diag`, `bkprintdiag` version 1

`D	<n>	<message>` for every place where emission and tree building
interleave: a structural method entered, or an `Emit` call made outside
the RPN machinery, while the RPN stack is not empty or varnodes are
pending. The final `S	direct	<n>	interleaved	<n>	outside	<n>` counts
the direct calls, the interleaved ones (0 on the whole corpus) and calls
made outside any document.

## Measuring

`tools/reference/measure.sh` prints the numbers recorded under "Reference
tools" in `docs/PERF.md`: time to compile every language, `.sla` sizes,
language load time and decode throughput of `pcodedump` on x86-64 code, and
the time of the decompiler's tests.
