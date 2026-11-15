# Decompiler oracle: state dumps, traces, recorded p-code (`decomp-oracle`)

Track `decomp-oracle` (D00 of `docs/features/decomp-plan.md`), milestone
M3, wave 1. Format of this document: `docs/LOOP.md`, "Feature documents".
Tooling only: C++ built into the reference build, the reference build
script, and parsers and wrappers in `bk-testkit`. Every later decompiler
track's acceptance (plan sections 4 and 6) is measured with what this
track delivers; D04 (`docs/features/decomp-cfg.md`) uses sections 4.6
and 4.7 from its start.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`DT/` = `…/decompile/datatests/`, under `../ghidra` (commit `42db038f3c`);
`REF/` = the reference directory (`../reference` on the Mac,
`$BASILISK_REFERENCE_DIR` on the build host). **(read)** marks a
statement from reading the source, **(ran)** one checked by running the
reference build; the runs are R1–R9 in
`docs/research/decomp-wave1/runs.md`, with their scripts beside it.

## 1. Purpose

Ghidra's decompiler is measured at six levels (plan 4, ADR-027). The
middle ones need things the reference console does not give: the
**complete** state of a function at any point of the pipeline, in a form
both implementations can write and compare byte for byte; the **trace**
of every rule and action application; the **p-code** Ghidra's lifter
produced, so that the port can run before its own SLEIGH runtime is
wired in; and the control-flow structurer on arbitrary graphs. This track
builds those into the reference build, documents their formats as
contracts, and gives Rust tests typed access to them.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/ifacedecomp.hh/.cc`, `CPP/interface.hh/.cc`, `CPP/consolemain.cc` | How console commands are registered (`IfaceCapability`, `registerCom`), parsed and run; the existing commands (4.1) |
| `CPP/action.hh/.cc` | `Action::perform`, `print`, `printState`, `printStatistics`, `setBreakPoint`, `getSubAction`/`getSubRule`, the status machine (4.1, 4.10) |
| `CPP/funcdata.hh`, `funcdata.cc` 207–223, 576–588, 1118–1232 | `printRaw`, `printVarnodeTree`, the `OPACTION_DEBUG` trace (`debugModCheck`, `debugModPrint`, `debugSetRange`, `debugCheckRange`) |
| `CPP/varnode.hh/.cc`, `CPP/op.hh/.cc` | Every field and flag of `Varnode`, `VarnodeBank`, `PcodeOp`, `PcodeOpBank`; `printRaw`, `printInfo`, `printDebug`; the bank orders (varnode.cc:34–79) |
| `CPP/block.hh/.cc` | Blocks, edges, the structured hierarchy (with D04) |
| `CPP/fspec.hh` (`FuncProto` 1368, `FuncCallSpecs` 1669, `ParamActive` 290, `ParamTrial` 213), `CPP/jumptable.hh` 543, `CPP/heritage.hh` 123–260, `CPP/variable.hh` 112, `CPP/database.hh` 118–520, `CPP/varmap.hh` 221 | The side state the dump carries (4.4) |
| `CPP/translate.hh` 94–380, `CPP/flow.cc` | `Translate`, `PcodeEmit`; where the engine lifts (4.8) |
| `CPP/blockaction.hh/.cc` | `CollapseStructure` and friends, run on fact-carrying graphs (4.6, 4.7) |
| `CPP/testfunction.cc` | How the data-test runner feeds commands (newlines become spaces, testfunction.cc:119) |
| `CPP/Makefile` | Targets `decomp_opt`, `decomp_dbg`; `CPUI_DEBUG` turns on `OPACTION_DEBUG`, `PRETTY_DEBUG`, `TYPEPROP_DEBUG` (types.h:88–97) |

## 3. Scope

**In:**

1. **Reference build additions** (`scripts/build-reference.sh`, section
   4.2): `REF/bin/decomp_dbg` (Ghidra's own `CPUI_DEBUG` console,
   unmodified), and two consoles with Basilisk's extension,
   `REF/bin/decomp_bk` (optimised) and `REF/bin/decomp_bk_dbg`
   (`CPUI_DEBUG`), linked from the same objects as `decomp`/`decomp_dbg`
   plus the extension. `bin/decomp` stays byte-identical to what the
   script builds today.
2. **The console extension** (`tools/reference/consoleext/`, 4.10): the
   commands of section 4.10 — state dumps, positional breakpoints, the
   block graph and structurer commands D04 needs, p-code recording and
   replay, trace control.
3. **Formats** (contracts, versioned, documented in
   `tools/reference/README.md`): state dump (4.4), graph file (4.6),
   analysis and structure dumps (4.6, 4.7), trace (4.9), p-code
   recording (4.8), action list (4.1).
4. **`bk-testkit`** (5.3): wrappers for `decomp_dbg`, `decomp_bk`,
   `decomp_bk_dbg`; typed parsers and writers for every format; the
   capture driver that produces the fixtures of section 6; the
   host-difference helpers of 4.11.
5. **Determinism and host dependence** of every oracle output (4.11).
6. The two **optional logs** of plan 6 item (6), if practical (4.12).

**Not in this track:** any decompiler crate (the parsers produce plain
data; loading a dump into Basilisk's IR is D05's, D06's and D07's);
Ghidra headless (M5; 4.13 records what a later track needs); the extended
corpus (D19); the data-test runner (D09); the parity tables in
`PARITY.md` (D19 fills them from test output, 4.15).

**Owned:** `tools/reference/consoleext/` (new), `tools/reference/README.md`
(new sections), `tools/reference/patches/` (only for 4.12),
`scripts/build-reference.sh` (additions), in `crates/bk-testkit` the new
modules of 5.3 and one line per new tool in `paths.rs`'s `Tool` enum,
`fuzz/` entries for the parsers, `fixtures/decomp-oracle/` (new).

## 4. Behaviour

### 4.1 The reference console as it is (ran)

Invocation: `echo | SLEIGHHOME=REF REF/bin/decomp -i SCRIPT`. Standard
input must be a pipe or a terminal (inventory 8); without `SLEIGHHOME`
(or `-s`) the console finds no language (`No sleigh specification for
x86:LE:64:default`, R1). Each script line is echoed after the prompt
`init> `; lines run through `execute test command` are echoed after
`test> `. A failing command prints `Execution error: <message>` and the
console stops (`Aborting process`, exit status 1 when it is in error;
R7). Commands write either to the bulk stream (`print …`, `list action`)
or to the status stream; both are standard output in the console.

| Command | Output shape (exact examples in runs.md) |
|---|---|
| `load test file <DT/x.xml>` | `<path> test successfully loaded: <description>`; builds the architecture and image of a data test without running its script |
| `list test commands`, `execute test command <a>[-<b>]` | ` 1: map fun r0x1006ca testElseIf` …; runs commands a..b (1-based) with the test's side effects |
| `load function <name>` / `lo fu` | `Function testElseIf: 0x001006ca`; **follows flow immediately** (plan 4.6) |
| `decompile` | `Decompiling <name>`, then `Decompilation complete` or `Break at <state>`; `Clearing old decompilation` first if already started |
| `continue` | resumes: `Break at <state>` or `Decompilation complete`; errors `Decompilation has not been started` / `is already complete` |
| `break start <spec>` / `break action <spec>` | silent; `Bad action/rule specifier: <spec>` |
| `list action` | the current root as a numbered tree, 243 lines for `decompile`: `0000        !    universal`; fields per `Action::print`: number (4 digits, zero-filled), ` repeat ` or 8 blanks, `!` once-per-function, `S`/`A` breakpoint flags, `depth*5+2` blanks, name; rule pools list their rules below them |
| `print raw` | per basic block `Basic Block <i> <start>-<stop>` then op lines `<addr>:<time hex>:\t<printRaw>`, implied gotos as `<addr>:   \t[ goto Block_<j>:<addr> ]` (R5) |
| `print tree varnode` | one line per varnode in **def order**: `<type> = <printRaw> [tied] [mapped] [persistent] [tlock] [nlock] [base] [unaff] [implied] [addrforce] [readonly] (consumed=0x…) (internal=0x<host address>) (create=0x…)` (`Varnode::printInfo`, varnode.cc:282) |
| `print tree block` | the structured hierarchy (decomp-cfg.md 4.10); nothing before structuring |
| `print actionstats`, `reset actionstats` | `<name> Tested=<n> Applied=<m>` per action and rule |
| `option togglerule <rule> off`, `option currentaction <root> <group> off` | disable one rule / a group (plan 4.1) |
| `structure blocks <in> <out>` | bare-graph structuring in Ghidra's XML (decomp-cfg.md 4.10, 6.2); needs an architecture loaded first |
| `print C` | the decompiled function |

**Breakpoint names cannot reach every action (ran, R7).** A specifier is
matched against the action tree by `ActionGroup::getSubAction`
(action.cc:456) and `getSubRule` (481, 777): a qualified prefix is
consumed only by the group that bears it, every sub-group is searched
with the unconsumed specifier, and more than one match returns null.
`blockstructure` (positions 0168 in `mainloop` and 0231 at the top
level), `prefercomplement`, `structuretransform`, `dynamicsymbols`,
`deadcode`, `unreachable`, `directwrite` and every other name that occurs
twice therefore cannot be stopped at in the top-level instance, by any
spelling. D00 adds positional breakpoints (`bk break`, 4.10). The plan's
"dump at `break start blockstructure`" is done with them.

**The debug console** (`make decomp_dbg`, ran on the build host, R8,
R9): built with `CPUI_DEBUG` and `-g` (no optimisation); 7.7 s with 20
jobs; on all 93 data tests its output equals the optimised console's
(pointer lines aside, 4.11). It adds `trace address [<lo> [<hi>]
[<uqlo> <uqhi>]]`, `trace enable|disable|clear|list`, `trace break <n>`,
`debug action <name>`, `break jumptable` (ifacedecomp.cc:151–163). With
`trace address` (no argument: whole function) and `trace enable`, a
`decompile` writes the trace of 4.9 to the debug stream (1,347 records
for `elseif.xml`, identical in two runs). The trace does **not** cover the
partial functions of jump-table recovery (their `Funcdata` has its own,
disabled, debug state).

### 4.2 The build

`scripts/build-reference.sh` gains, after step [1/5]:

* `make decomp_dbg` with the same overrides as the other targets (one
  `make` invocation for all targets keeps it incremental), copied to
  `REF/bin/decomp_dbg`.
* The extension's sources (`tools/reference/consoleext/*.cc`, `*.hh`) are
  compiled **outside the Makefile**, twice: once with the Makefile's
  `com_opt` flags (`$(OPT_CXXFLAGS) $(ADDITIONAL_FLAGS) -D__TERMINAL__`)
  and once with `com_dbg`'s (`$(DBG_CXXFLAGS) $(ADDITIONAL_FLAGS)
  -DCPUI_DEBUG -D__TERMINAL__`), each adding `-fno-access-control` and
  `-I REF/src/cpp`. `decomp_bk` = the link line of `decomp_opt`
  (Makefile:235–236: `$(CXX) $(OPT_CXXFLAGS) $(ARCH_TYPE) -o …
  $(COMMANDLINE_OPT_OBJS) $(BFDLIB) $(LNK)`, i.e. the `com_opt/*.o` of
  `COMMANDLINE_NAMES` and the bundled zlib) plus the extension's
  optimised objects; `decomp_bk_dbg` likewise from `decomp_dbg`'s line
  (232–233) and `com_dbg`. The script takes the object list from `make
  -n` or from `COMMANDLINE_NAMES` evaluated with the same `EXTRA`, not
  from a directory listing.
  The extension registers its commands from a static `IfaceCapability`
  object, as `IfaceDecompCapability` does (ifacedecomp.cc:26), so linking
  its object file is enough. **Why not the plan's "copy into the source
  copy so the Makefile compiles it"**: the Makefile has no per-file flags,
  and `-fno-access-control` must not touch Ghidra's own files (it can
  change SFINAE results in templates); a file in the source copy would
  also enter `decomp`, `decomp_test` and `libdecomp`, so the reference
  console would no longer be Ghidra's.
* Fingerprints: the extension's sources join the tools fingerprint of a
  new step `[1b/5] console extension`; changing them relinks the two
  `_bk` consoles only.
* `STAMP` lists the four consoles' sha256 and size (`== tools:` block) and
  a line `console_extension: <sha256 of the concatenated sources>`.
* README's "Building" section and output tree list the new binaries.

**The x86-64 Linux reference** (plan 6 D00 asked for "an x86-64 Linux
container target"): since the `remote-build` track the build host builds
`REF` natively with this same script (`docs/agents/remote-build.md`,
"Reference tools"; Debian g++ 14.2, libstdc++), so no container target
is needed. D00 rebuilds the host's reference with the new script
(`scripts/remote.sh setup`, which runs `build-reference.sh` into the
host's reference directory) and records both STAMPs in its report.

### 4.3 Identity: what names an object in every format

Ghidra's objects are named by values a port can reproduce, never by host
pointers:

| Object | Name in dumps | Reproducible by Basilisk? |
|---|---|---|
| Varnode | `v<create index, hex>` (`Varnode::create_index`, one-up per function, varnode.hh:138) | Yes: creation order is behaviour (plan 3.3) |
| PcodeOp | `<address>:<time hex>` — `SeqNum` `pc` and `uniq` (address.hh:125–127), as `print raw` prints it; `order` is a separate field | Yes (`time` is one-up per function, never reused) |
| Basic block | `b<index>` (`FlowBlock::index`, reverse post-order after `structureReset`) | Yes (D04) |
| Structured node | decomp-cfg/D00 4.7: `L<leaf>` / `S<n>` | Yes |
| Call spec | `c<position in Funcdata::qlst>` at dump time | Yes (`sortCallSpecs` is total, funcdata.cc:501) |
| Jump table | `j<position in jumpvec>` | Yes |
| High variable | `h<n>`, numbered by the smallest member create index | Yes |
| Symbol | `s<symbolId, hex>` (`Symbol::symbolId`) | Yes for function-local symbols created in Ghidra's order |
| Data type | `t<n>`: position in the dump's type table (4.4.10) | The table holds Ghidra's encoding; `n` is local to the dump |
| Address space | its name (`ram`, `register`, `unique`, `const`, `stack`, `join`, `iop`, `fspec`, …) | Yes |

**Pointer-valued offsets.** Ghidra stores host pointers in three kinds of
varnode offset: an `iop`-space varnode holds a `PcodeOp *` (op.cc:46), an
`fspec`-space varnode a `FuncCallSpecs *` (fspec.cc:2155), and the first
input of `LOAD`/`STORE` a constant holding an `AddrSpace *`. The dump
writes them as `op:<seqnum>`, `call:c<k>` and `space:<name>` (a constant
is recognised as a space constant when its offset equals the address of
one of the architecture's spaces and its size is `sizeof(void *)`,
exactly as `pcodedump` does). Their **size** is printed as Ghidra has it
(8 on both reference hosts).

**The bank orders are not reproducible as Ghidra has them (ran, R5).**
`VarnodeBank`'s loc and def trees compare by `Address` (varnode.cc:39,
73), i.e. by these pointer values, so the relative order of `iop`,
`fspec` and space-constant varnodes follows heap addresses: two runs of
the same binary print `print tree varnode` in different orders (43 of 93
data tests differ between runs on the Mac, only in such lines). The dump
therefore writes both orders **with the canonical keys substituted**:
the extension sorts the varnodes with Ghidra's two comparators in which
the offset of a pointer-valued varnode is replaced by its key (`op` →
the op's `time`, `call` → `k`, `space` → the space's index). This is the
order D05 must reproduce; Ghidra's own order differs from it only among
those varnodes.

### 4.4 The state dump (`bk dump state <file>`), format version 1

Ghidra's own encodings are not enough for this: `Varnode::encode` writes
six of the 32 flag bits (`addrtied`, `grp`, `input`, `persists`,
`unaff`, `volatile`) and `PcodeOp::encode` the opcode, seqnum and operand
references only (read: varnode.cc, op.cc), and `print tree varnode`
prints ten flags and a host address. Hence a format of Basilisk's.
Line-oriented UTF-8 text, fields separated by one tab, records in a
fixed section order; every line is `<tag>\t<fields…>`. Numbers are
lower-case hexadecimal with `0x` where Ghidra prints them that way
(offsets, flags, masks, `create`, `time`) and decimal otherwise (sizes,
indices, counts). Text fields escape `\`, tab, LF, CR, NUL as `\\`, `\t`,
`\n`, `\r`, `\0`. A list field is a comma-separated sequence, `-` when
empty. An address is `<space>:0x<offset>` (`ram:0x1006ca`). Sections
start with `@<name>\t<count>` and are present even when empty. Grammar:

```
dump     = "BKSTATE" TAB "1" TAB ghidra-commit TAB arch-id NL
           "@function" ... "@actions" ... "@spaces" ... "@varnodes" ...
           "@locorder" ... "@deforder" ... "@ops" ... "@oplists" ...
           "@blocks" ... "@structure" ... "@proto" ... "@callspecs" ...
           "@jumptables" ... "@scope" ... "@heritage" ... "@highs" ...
           "@types" ... "@c" ...
           "END" TAB line-count NL
```

`END` carries the number of lines before it, so a truncated dump is
detected. The sections and their records (field order is the order
listed):

1. **`@function`** — one `F` record: name, display name, entry address,
   `size`, `flags` (hex, funcdata.hh:57–74), `clean_up_index`,
   `high_level_index`, `cast_phase_index`, `minLanedSize`; and one `K`
   record of the counters that decide what is created next:
   `vbank.create_index` (next varnode), `vbank.uniqbase`, `vbank.uniqid`
   (next `unique` offset), `obank.uniqid` (next op time). Plus `W`
   records: the function's warning comments and header warnings, in
   order.
2. **`@actions`** — where the pipeline stands: `A` per action or rule in
   `list action` order: position, full path (`universal:fullloop:…`),
   `status`, `count`, `count_tests`, `count_apply`, flags, breakpoint
   word; for pools, each rule's disabled flag and counts. A loader (D07)
   resumes the pipeline from this.
3. **`@spaces`** — `P` per architecture space: index, name, type,
   shortcut, word size, address size, flags. Lets the dump be read
   without the architecture.
4. **`@varnodes`** — `V` per live varnode in **create-index order**:
   `v<create>`, space, offset (canonical, 4.3), size, `flags` (32 bits,
   varnode.hh:79–115), `addlflags` (16 bits, 118–133), `mergegroup`, def
   (`<seqnum>` or `-`), readers (seqnums **in `descend` order**), type
   (`t<n>` or `-`), `consumed`, `nzm`, high (`h<n>` or `-`), symbol entry
   (`s<id>:<entry position>` or `-`). Left out: `cover` (a cache rebuilt
   from def and readers, `coverdirty`), `temp` (a per-algorithm scratch
   union, varnode.hh:152–155), `internal` (host address).
5. **`@locorder`**, **`@deforder`** — one `O` record each: every varnode's
   name in the bank order of 4.3.
6. **`@ops`** — `O` per op in `SeqNum` order (`obank.optree`, all ops not
   yet destroyed, dead ones included): seqnum, `order`, opcode name,
   `flags` (op.hh:72–106), `addlflags` (108–121), output (`v…` or `-`),
   inputs (`v…`, in slot order), parent block (`b<i>` or `-`),
   `alive`/`dead`.
7. **`@oplists`** — `L` records, one per list of `PcodeOpBank` whose
   order passes iterate: `alive`, `dead`, `store`, `load`, `return`,
   `userop`: the seqnums in list order.
8. **`@blocks`** — the basic-block graph `bblocks` in list order, one `B`
   per block: `b<i>`, flags, `immed_dom` (`b<j>` or `-`), the cover
   ranges (`RangeList`: `<space>:<first>-<last>` items), its ops in block
   order; and `E` records for its in-edges in order: `b<src>`,
   source out-slot, label (hex). (This is the graph file of 4.6 plus ops
   and ranges.)
9. **`@structure`** — the structured hierarchy `sblocks` when non-empty:
   the records of 4.7 without the header.
10. **`@proto`** and **`@callspecs`** — the function's `FuncProto` and, per
    `qlst` position, `C`: `c<k>`, the call op's seqnum, name, entry
    address, `effective_extrapop`, `stackoffset`, `paramshift`,
    `matchCallCount`, the flags `isinputactive`, `isoutputactive`,
    `isbadjumptable`, `isstackoutputlock`; followed by its prototype
    (model name, `extrapop`, prototype flags, input and output parameter
    pieces with storage, type and flags, effect list, likely-trash list)
    and, when active, its `ParamActive` (`activeinput`, `activeoutput`:
    `slotbase`, `stackplaceholder`, `numpasses`, `maxpass`,
    `recoversubcall`, `joinMostSigFirst`, and per trial: address, size,
    flags, entry index, slot, offset, fixed position).
11. **`@jumptables`** — `J` per table: `j<k>`, the `BRANCHIND`'s seqnum,
    the recovered addresses in order, the target block of each
    (`b<i>`, as `getIndexByBlock` maps them), the labels, the default index, the
    model kind, `lastBlock`, `maxtablesize`, `maxaddsub`, `maxleftright`,
    `maxext`, `partialTable`, `collectloads`, `switchVarConsume`,
    `defaultIsFolded` and the override if any (jumptable.hh:543–631; take
    the full member list from the class).
12. **`@scope`** — the local scope (`localmap`): its flags
    (`stackGrowsNegative`, `rangeLocked`, `overlapProblems`), the
    name/type recommendations, the address ranges it owns; `S` per symbol
    in `symbolId` order: id, name, display name, type, `flags`,
    `dispflags`, category, `catindex`, `nameDedup`, then `M` per map
    entry: address, size, offset, use-limit ranges, `extraflags`. Global
    symbols that local data refers to are written as `G` references (id,
    name, address), not expanded.
13. **`@heritage`** — `pass`, `maxdepth` and per heritaged space
    (`HeritageInfo`, heritage.hh:123–141): space, `delay`,
    `deadcodedelay`, `deadremoved`, `loadGuardSearch`, `warningissued`,
    `hasCallPlaceholders`; the `globaldisjoint` and `disjoint` location
    maps (address, size, pass); the load and store guards (op seqnum,
    space, range, step, analysis state); `loadCopyOps`.
14. **`@highs`** — when high variables exist: `H` per high: `h<n>`,
    members (`v…` in `inst` order), `numMergeClasses`, `highflags`, union
    flags, type, name representative, symbol and offset, piece group.
15. **`@types`** — `T` per data type referenced by any earlier record, in
    first-reference order: `t<n>`, Ghidra's type id (hex), metatype,
    size, name, and its `Datatype::encode` XML on one line (escaped).
16. **`@c`** — when the function is fully decompiled (`processing_complete`):
    the text of `print C`, one `C` record per line.

**What a dump deliberately leaves out, and why:** host addresses
(`internal=`, pointer offsets — replaced, 4.3); caches Ghidra recomputes
from the state (covers, `HighVariable`'s dirty-bit caches, `Cover`
objects, `HighIntersectTest`'s pair cache); scratch that is only valid
inside one algorithm (`Varnode::temp`, `visitcount`, marks, the
`modified` op flag of the debug trace); the program-wide `Architecture`
(spaces are listed; models, types and global symbols are referenced by
name and id); the partial `Funcdata` clones of jump-table recovery
(transient); the printer's state.

**State loading.** The plan needs loading only on the Rust side (D05,
D06, D07 load dumps into their own structures; plan 4.2). Nothing loads a
dump back into Ghidra. What a dump can restore: everything listed above
that is not a cache — varnodes with their ids, flags, def/use and both
orders; ops with seqnums, order, flags, lists; blocks; the structure;
prototypes and call specs with trials; jump tables; the local scope;
heritage's per-space state and guards; highs; the action status. What it
cannot: (a) Ghidra's pointer-dependent bank order (4.3) — Basilisk's
canonical order is restored instead; (b) the architecture (the loader
needs the same language, compiler spec and image, which the test names);
(c) caches, which the loader recomputes and which D05's round trip checks
indirectly by re-dumping; (d) `Varnode::temp` and other scratch, which no
pass reads across a unit boundary (read: `setTempType` and `setValueSet`
are set and consumed inside `ActionInferTypes` and `ValueSetSolver`).

### 4.5 Taking dumps: break points

A dump is taken at a break point: `bk break start <n>` (4.10) on the
action or rule at position `n` of `list action`, then `decompile` and
`continue` as usual, with `bk dump state <file>` at each stop. For the
plan's four standard points (D05 test 1): after `ActionStart` = break
start at the action following `start` (position 0002, `constbase`); the
first start of `oppool1`; the start of the `cleanup` pool (0192); `stop`
(0242) — positions as `list action` prints them for the `decompile` root
(R7). The capture driver resolves positions by path from `bk list
actions`, never by hard-coded numbers.

### 4.6 Graph files and `bk cfg` (for D04)

**Graph file, version 1** (input of `bk cfg analyze` and `bk structure`,
output of `bk dump blocks`):

```
H	bkgraph	1	<node count>
N	<id>	<index>	<flags hex>	<facts>	<idom id or ->	<numdesc>
I	<id>	<src>:<src out-slot>:<label hex>,…   (in-edges of <id>, in order; - if none)
A	<id>	<start address>	<stop address>      (optional; basic blocks only)
T
```

`N` records appear in Ghidra's list order and ids are `0..n-1` in that
order. Out-edge order is given by the slot numbers: every out-slot of
every node must occur exactly once (else the extension rejects the file;
Ghidra's own XML reader would leave a slot uninitialised,
decomp-cfg.md 4.10). `<facts>` is a set of letters — `c` complex, `s`
switch out, `r` ends in `RETURN`, `n` negation changes data-flow — or `-`
(decomp-cfg.md 4.1). `index` and `idom` are used only by `asgiven` mode;
`bare` mode recomputes them.

**`bk cfg analyze <graph> <out>`**: builds the graph from fact blocks
(4.10), copies it (`buildCopy`), runs `structureLoops` and
`calcForwardDominator` on the copy, then `orderLoopBodies` of a
`CollapseStructure` over it (after `clearVisitCount`, as `collapseAll`
does), and writes:

```
H	bkcfg	1	ok|error	<message or ->
O	<ids in list order after the analysis>
N	<id>	<index>	<idom or ->	<numdesc>	<dom depth>
I	<id>	<src>:<slot>:<label hex>,…
R	<root ids, rootlist order>
L	<head>	<depth>	<exit or ->	<uniquecount>	<tails, in order>	<exit edges top>bottom, in order>	<immed container head or ->
T
```

### 4.7 `bk structure` and the structure dump (for D04)

**`bk structure <graph> <out> [bare|asgiven] [finish] [trace] [xml
<file>]`**: builds
fact blocks, `buildCopy`; in `bare` mode `structureLoops` and
`calcForwardDominator` on the copy (as `structure blocks`); then the
collapse; with `finish`, `orderBlocks`, `scopeBreak(-1,-1)`,
`markUnstructured`, `markLabelBumpUp(false)` (`ActionFinalStructure`
without `finalizePrinting`, which needs ops and jump tables). The
collapse is run by the extension's copy of `CollapseStructure::collapseAll`
and `collapseInternal` (blockaction.cc:1776–1904), calling Ghidra's own
(private) rule methods, `selectGoto` and `collapseConditions` in Ghidra's
order, so that it can log; the extension also runs Ghidra's unmodified
`collapseAll` on a second copy and fails the command (`error`, message
`trace replica differs`) unless both give the same dump. With `xml
<file>` it also writes the result with Ghidra's own encoder
(`BlockGraph::encode`, as `structure blocks` does), for test 6.4.
Output:

```
H	bkstruct	1	ok|error	<message or ->
G	<source>	<out-slot>	<target>	<cause>                (each new goto edge)
F	<leaf>                                                    (each flip event)
C	<dataflow change count>
S	<node>	<kind>	<index>	<flags hex>	<depth>	<leaf count>	<parent or ->	<components>	<kind data>	<in-edges>	<out-edges>
P	<top-level nodes in list order>
R	<seq>	<rule>	<node>                                    (trace only)
T
```

* Nodes: leaves are `L<input id>`; structured nodes are `S<n>`, numbered
  in pre-order of the final hierarchy (top-level list order, components
  in order). Records referring to nodes during the run (`G`, `F`, `R`)
  are resolved to these names after the run (nodes are never freed).
* Kinds (Ghidra's kinds, but `ifnoexit` kept distinct from `ifelse`,
  unlike `typeToName`): `copy`, `goto`, `multigoto`, `list`, `condition`,
  `if`, `ifelse`, `ifnoexit`, `ifgoto`, `whiledo`, `dowhile`, `infloop`,
  `switch`. Kind data: `goto` target node and goto type (hex); `ifgoto`
  the same; `multigoto` targets and `default`/`-`; `condition` the stored
  opcode name (`INT_OR`, `BOOL_AND`, `BOOL_OR`; decomp-cfg.md 4.4);
  `whiledo` `overflow`/`-`; `switch` per case
  `<node>:<outindex>:<chain>:<gototype>:<isexit>:<isdefault>` in
  `caseblocks` order; others `-`.
* Edges: `<node>:<rev>:<label hex>` lists, in order; a structured node
  keeps edges to its siblings, components keep their internal edges.
* `G` records: after `selectGoto` (cause `selected` when it returned a
  block, `clipped` when it returned null after `clipExtraRoots`), after a
  `ruleBlockSwitch` that applied without building (`switchskip`) and after
  `ruleCaseFallthru` (`fallthru`), the extension scans the current level
  in list order and out-slot order for goto labels that were not there
  before; one record per new edge, in that scan order.
* `F` records come from the fact block's `negateCondition` override, in
  call order.
* `R` records (`trace`): one per rule application in `collapseInternal`
  and `collapseConditions`: running number, rule name (`blockgoto`,
  `blockcat`, `blockor`, `blockproperif`, `blockifelse`, `blockwhiledo`,
  `blockdowhile`, `blockinfloop`, `blockswitch`, `blockifnoexit`,
  `casefallthru`), the node it was applied to (name of the node that
  was `bl`).
* On a `LowlevelError` the header says `error` with Ghidra's message
  (`Could not finish collapsing block structure`, …) and no other record
  but `T` follows.

**Fact blocks**: a `FlowBlock` subclass of the extension that overrides
`isComplex` (the `c` fact), `negateCondition` (logs the flip, swaps its
edges as `FlowBlock::negateCondition(true)` does, returns the `n` fact),
`lastOp` (null, or for an `r` node a `PcodeOp` built once per command
with `glb->inst[CPUI_RETURN]` as its opcode and no parent — read only by
`compareFinalOrder`), and `getType` (`t_basic`). A node with both `r`
and `s` is rejected (`getJumptable` would follow the fake op's null
parent).

**`bk dump blocks <file>`** writes the current function's `bblocks` as a
graph file with the real facts (`c` = `BlockBasic::isComplex`, `s` =
`f_switch_out`, `r` = last op `RETURN`, `n` always), labels, indices,
dominators and `A` records. **`bk dump structure <file>`** writes its
`sblocks` in the structure-dump format (`P` and `S` records only; leaves
are `L<basic block index>`).

### 4.8 Recorded p-code (`bk pcode record|replay <file>`)

The engine reaches the lifter only through `Architecture::translate`
(`const Translate *`); the calls it makes after initialisation are
`oneInstruction`, `instructionLength`, `printAssembly`, `getRegister`,
`getRegisterName`, `getExactRegisterName`, `getAllRegisters`,
`getUserOpNames`, `getFloatFormat`, `getAlignment`, `isBigEndian`,
`getUniqueStart`, `getDefaultCodeSpace` and `allowContextSet` (read:
`grep "translate->" CPP/*.cc`). `bk pcode record <file>` replaces
`conf->translate` by a proxy `Translate` that copies the original's
spaces (`copySpaces`), endianness, alignment, unique base and float
formats, forwards every virtual method, and for `oneInstruction` wraps the
caller's `PcodeEmit` in a recording emitter that forwards each `dump` and
logs it. It must be given **after** `load test file`/`load file` and
**before** the first `load function` (which lifts at once, plan 4.6).
`bk pcode stop` restores the original translator and closes the file.

**Recording format, version 1** (tab-separated; varnodes written as in
`pcodedump`'s `P` records: `(space,0xOFFSET,SIZE[,NAME])`, with the
`LOAD`/`STORE` space constant written `(const,0x<space index>,8,<space
name>)`):

```
H	pcoderec	1	<language id>	<compiler spec id>
I	<address>	<length>	<op count>          (oneInstruction returned)
P	<op address>	<opcode>	<output or ->	<inputs…>   (one per PcodeEmit::dump, in order)
U	<address>	unimplemented|baddata|error	<length or ->	<message>   (oneInstruction threw)
L	<address>	<length>                     (instructionLength)
T	<I count>	<U count>	<L count>
```

Every call is recorded in call order, repeats included (flow is
followed again on each `decompile`, by inlining and by jump-table
recovery). `bk pcode replay <file>` installs a proxy that answers
`oneInstruction` and `instructionLength` from the recording **by
address**, rethrowing recorded errors with their message and length,
and forwards everything else to the real translator; an address that is
not in the recording is an error (`pcode replay: no record for
<address>`). Before answering it checks that every record of one address
is identical; if not, replay refuses the file (`context-dependent
records at <address>`) — the recording is still valid as a log, and its
`H` record is followed by an `X <address>` record per such address so
that `RecordedPcode` (5.3) can report it. **Acceptance check (plan 6
D00 (3))**: for every data test, a run with `bk pcode record`, then a
fresh run with `bk pcode replay` of that file, each stopped with `bk
break start` at the action after `start`, give byte-identical `print
raw`.

### 4.9 The trace

Produced by `decomp_dbg` or `decomp_bk_dbg` with `trace address` and
`trace enable` before `decompile` (4.1); the extension's `bk trace
stream` points the architecture's debug stream at the bulk output for
scripts that do not start with `load test file`. Grammar of one record
(`Funcdata::debugModPrint`, funcdata.cc:1147, R9):

```
record = "DEBUG " count ": " name NL ( before NL "   " after NL )+ NL
before = seqnum ": " ( "**" | rawop )
after  = seqnum ": " ( "**" | rawop )
```

`count` is decimal from 0; `name` is the action or rule name; `rawop` is
`PcodeOp::printRaw`; an op that was dead or had no block prints `**`. A
unit that changed no op in range prints nothing. The parser (5.3)
returns `TraceRecord { count, name, ops: Vec<(seqnum, before, after)> }`
and keeps the raw text of each op for comparison with D05's recorder.

### 4.10 The console extension's commands

All commands start with `bk`; errors are `IfaceExecutionError`s with the
message given, so the console aborts a script on them like on its own
commands. Files are written atomically (to `<file>.part`, then renamed).

| Command | Effect |
|---|---|
| `bk version` | prints `bk console extension <format versions>` |
| `bk list actions` | the current root as `list action` prints it, each line followed by a tab and the action's full path; rule-pool lines likewise with `pool:rule` |
| `bk break start <n>` / `bk break action <n>` | set the start / action breakpoint on the action or rule at position `n` of `list action` (walking `ActionGroup::list` and `ActionPool`'s rule list in print order); `bk break clear` clears all |
| `bk dump state <file>` | 4.4 |
| `bk dump blocks <file>`, `bk dump structure <file>` | 4.7 |
| `bk cfg analyze <graph> <out>` | 4.6 |
| `bk structure <graph> <out> [bare\|asgiven] [finish] [trace]` | 4.7 |
| `bk pcode record <file>`, `bk pcode replay <file>`, `bk pcode stop` | 4.8 |
| `bk trace stream` | debug stream → bulk output (only in `decomp_bk_dbg`) |
| `bk log mutations <file>`, `bk log printer <file>` | 4.12, only if delivered |

`bk cfg` and `bk structure` need a loaded architecture, as `structure
blocks` does, but only for `glb->inst[CPUI_RETURN]` (the fact block's
fake op); `load test file DT/elseif.xml` is the conventional set-up.

### 4.11 Determinism and host dependence

**Requirement**: every oracle output this track defines is byte-identical
across repeated runs of the same binary, and is generated on both
reference builds — macOS arm64 (Apple clang 17, libc++) and x86-64 Linux
(g++ 14.2, libstdc++). Where the two differ, the difference is recognised
by cause and counted, in ADR-040's form: the replay test requires every
row where the builds agree to equal Basilisk, and classifies every row
where they disagree into a named cause with a checked-in count, so a new
cause or a moved count fails the test (worked examples:
`crates/bk-cspec/tests/oracle_common/host.rs` and the `bk-decomp-range`
oracle on branch `decomp-range`).

What was measured (R3–R6, R8, R9):

* `structure blocks` on 3,000 random graphs: identical between runs and
  between the two hosts.
* The 93 data tests with `print C`, `print raw`, `print tree varnode`,
  `print tree block`: between runs of one binary on one host the only
  differences are **host pointers and the order they impose** (4.3); Mac
  against host, after removing those, the only difference is
  `floatprint.xml`'s `NAN` against `-NAN` (ADR-021).
* `decomp_dbg` equals `decomp` on the same host; its trace is identical
  between runs.

Sources of order the extension must make defined, and how:

| Source | Where | Defined by |
|---|---|---|
| Varnode bank orders over pointer-valued offsets | varnode.cc:39, 73; op.cc:46; fspec.cc:2155 | canonical keys (4.3) |
| Printing of pointer-valued offsets | `print tree varnode`; `Varnode::printRaw` | `op:`, `call:`, `space:` names (4.3) |
| `orderBlocks` ties among blocks ending in `RETURN` | block.hh:448, block.cc:718 | not changed in Ghidra; counted as a cause by D04's replay (decomp-cfg.md 4.9) |
| `std::sort` ties elsewhere (effect lists, trials, …) | listed in `docs/research/decomp-wave1/sorts.md` | not changed in Ghidra; each consuming track handles them per ADR-040 |
| Pointer-keyed containers that are iterated | none on a dump path (sorts.md) | — |
| File-system order (`readdir`) | language discovery (`FileManage::matchListDir`, filemanage.cc:177–203) | the capture driver loads data tests by explicit path and sorts every directory listing it makes byte-wise |
| Paths and locale in output | the console echoes the data-test path; the build host's `perl` prints locale warnings on standard error | the driver passes paths relative to a fixed root, sets `LC_ALL=C`, and separates standard error from the captured output |

### 4.12 Optional logs (plan 6 D00 (6))

Two logs for later tracks, each behind a command, **if practical**:

* **Mutation log** (`bk log mutations`, for D05 test 4): every call of
  the `Funcdata` methods of `docs/features/decomp-ir.md` 4.5 with its
  arguments (ids per 4.3) and results. These methods are not virtual, so
  logging needs hooks in Ghidra's source: a patch adding, at the top of
  each method, `if (bk_hook) bk_hook->…(…)` with a null global pointer by
  default.
* **Printer log** (`bk log printer`, for D16a): every `PrintLanguage`
  push (`pushOp`, `pushAtom`, `pushVn*`, with the `OpToken`, op, varnode,
  modifier word) and every `Emit` call. `Emit` is virtual (an `Emit`
  subclass that logs and forwards needs no patch); the pushes need hooks
  as above.

Hook patches must not change the reference consoles: they live in
`tools/reference/patches-instr/` (not `patches/`), and the script builds
them into a **separate** source copy `REF/src-instr/` and binary
`REF/bin/decomp_bk_instr` (with the extension), only when the
`--instrumented` flag is given. If this proves impractical (the hooks
would have to go into templates, inline methods or many call sites), D00
says so in its report and the two consumers use their stated fall-backs
(D05: decomp-ir.md 6 item 4; D16a: Emit-only logging).

### 4.13 Ghidra headless (later track, M5)

Not delivered by D00: no M3 track needs it. What the later track
(`ghidra-headless`) needs, from `docs/agents/testbed.md` ("Ghidra
headless on the host") and Ghidra's build files: a JDK 21
(`openjdk-21-jdk-headless` or an Eclipse Temurin container, no root);
Gradle through Ghidra's wrapper (`./gradlew -I
gradle/support/fetchDependencies.gradle init`, then `./gradlew
buildGhidra`), about 150 MB of Gradle download into `~/.gradle` and about
10 GB of disk for a build of a **copy** of the pinned tree (the host's
tree is read-only); the result is a distribution zip under `build/dist/`,
run as `support/analyzeHeadless <project dir> <name> -import <binary>
-postScript <export script>`. The export script would dump, per
function, the program model's view (name, entry, body ranges, signature,
calling convention, references) and the decompiler's output through
`DecompInterface` with the same options as the console. Every output
would follow 4.11's rules. D00's only obligation: keep `bk-testkit`'s
tool enumeration open for a `GhidraHeadless` entry (5.3).

### 4.14 Corpus, where checks run, gate and nightly

* **Corpora** (plan 4.3): the 93 data tests (193 `decompile` commands,
  ran: `grep -o "<com>[^<]*</com>" DT/*.xml`); the research corpus (74
  fragments, 209 functions, each script decompiling every function
  twice: 430 `decompile` lines). The capture driver (5.3) runs the
  data-test scripts as `FunctionTestCollection` does (CDATA unwrapped,
  newlines to spaces) and the research scripts as they are.
* **Kinds** (plan 4.5): the parsers' unit tests and every replay of a
  checked-in capture are **S**; anything that reads Ghidra's data-test
  files is **G**; regenerating captures is **L**.
* **Gate**: the S and G tests of this track and of its consumers.
  **Nightly** (`tools/testbed/nightly.sh`, through `scripts/remote.sh
  nightly`): one new item, `oracle`, that rebuilds the host's reference
  if the script changed, regenerates every capture of section 6 twice,
  requires the two to be identical, and diffs them against the checked-in
  fixtures; the drift report lists every fixture that changed, by file.
  D00 adds the item to the rotation (it needs about one minute: R5's
  full data-test run takes 13 s with `decomp_dbg`).

### 4.15 Reporting

The capture driver writes a summary per corpus function (functions,
dumps taken, trace length, recording size, any error). `PARITY.md`'s
decompiler table (plan 4.7) is D19's; D00 provides the per-function
counts it will be built from in `fixtures/decomp-oracle/summary.txt`.

## 5. Design

### 5.1 The extension (C++)

`tools/reference/consoleext/`: `bk_capability.cc` (registration, `bk
version`, `bk list actions`, `bk break`), `bk_ids.cc/.hh` (naming and
canonical keys, 4.3), `bk_state.cc` (4.4), `bk_cfg.cc` (4.6, 4.7, fact
blocks, the collapse replica), `bk_pcode.cc` (4.8), `bk_io.cc/.hh`
(escaping, atomic files). C++11 like Ghidra; each file under 1,000 lines;
no change to any Ghidra file; private members reached through
`-fno-access-control` only. Every command catches `LowlevelError` and
reports it in its output or as an `IfaceExecutionError`, never crashes on
a malformed input file (it is fed generated files).

### 5.2 Formats

Versioned by the number after the format name in each header. A change
bumps the version in the header, in `tools/reference/README.md`, in the
extension and in the parser together, as `pcodedump`'s format does.

### 5.3 `bk-testkit`

* `tools/decomp.rs` gains `DecompVariant { Opt, Dbg, Bk, BkDbg }` (or
  four `Tool` entries: `DecompDbg`, `DecompBk`, `DecompBkDbg`, with
  `GhidraHeadless` reserved), the same `run_script` interface, and
  helpers `dump_state_at`, `trace`, `record_pcode`.
* `oracle/` (new): `state.rs` (dump → `StateDump` with one typed struct
  per section; writer back to text, byte-identical for any parsed dump),
  `graph.rs` (graph files, both directions), `cfgdump.rs` (analysis
  dumps), `structure.rs` (structure dumps), `trace.rs`, `pcoderec.rs`
  (`Recording` and `RecordedPcode`: a by-address lookup returning ops,
  length or the recorded error, refusing context-dependent addresses),
  `actions.rs` (`bk list actions` → positions and paths), `host.rs`
  (library detection for file names `*.libcxx.*`/`*.libstdcxx.*`, and a
  generic "agree / differ by named cause" replay helper in ADR-040's
  form).
* All parsers: `thiserror` errors with line numbers, no panics on any
  input (ADR-009), a `proptest` "never panics" and "write ∘ parse =
  identity" test, and a fuzz target each (`fuzz/fuzz_targets/
  bk_testkit_state.rs`, `_graph.rs`, `_structure.rs`, `_trace.rs`,
  `_pcoderec.rs`).
* Capture driver: `crates/bk-testkit/src/bin/bk-oracle.rs` (`cargo run
  -p bk-testkit --bin bk-oracle -- capture <corpus> <out>`), Unix only
  (the reference tools are), writes `fixtures/decomp-oracle/` (gzip
  files and `summary.txt`), runs each capture twice and refuses
  differing results.

### 5.4 Plugin binding constraints

Test tooling; not on the plugin surface. No rule applies.

## 6. Tests

1. **Parsers (S)**: unit tests on checked-in samples of every format
   (`crates/bk-testkit/tests/data/oracle/`: one state dump of a small
   data-test function at each of the four standard points, a graph file,
   analysis and structure dumps with and without trace, a trace of
   `elseif.xml`, a recording of `elseif.xml`), round trip, the property
   tests and fuzz targets of 5.3.
2. **Dump completeness checker (L; plan 6 D00 (2))**: for every
   `decompile` of every data test, `bk dump state` at the end and the
   console's own `print raw` and `print tree varnode` at the same stop;
   the checker requires every op of `print raw` to appear in `@ops` with
   the same seqnum and printed form, every varnode of `print tree
   varnode` to appear in `@varnodes` with the same create index, flags
   rendering and consumed mask, `@deforder` to equal the console's order
   once pointer lines are re-sorted by canonical key, and the dump to
   parse. Counts of functions, ops and varnodes go to `summary.txt`.
3. **Replay of recorded p-code (L; plan 6 D00 (3))**: 4.8's check, for
   every data test.
4. **Structurer commands (L)**: the generator of R3 (rewritten as test
   support that writes each graph both as Ghidra XML and as a graph file
   with neutral facts) feeds `structure blocks` and `bk structure … bare
   xml <file>`; the two XML outputs are byte-identical for all 3,000
   graphs (fact blocks with neutral facts behave as Ghidra's plain
   blocks), and the trace replica agrees with `collapseAll` on every
   graph (4.7). D04's tables come from these commands.
5. **Determinism (L)**: every capture of this section generated twice
   per host and on both hosts, with the results of 4.11 (equal, or
   differing only by counted causes).
6. **`decomp_dbg` equals `decomp` (L)**: R8 repeated on both hosts on
   the full data-test run.
7. **Build (L)**: `build-reference.sh` twice in a row does no work the
   second time; touching an extension source relinks only `decomp_bk*`;
   `bin/decomp`'s sha256 is unchanged by the track.

## 7. Acceptance

From plan 6, made concrete:

1. `scripts/build-reference.sh` produces `REF/bin/decomp_dbg`,
   `decomp_bk` and `decomp_bk_dbg` on the Mac and on the build host,
   incrementally, with `bin/decomp` unchanged, and `STAMP` records them
   and the extension's hash.
2. The completeness checker (6.2) passes for every `decompile` of all 93
   data tests on both hosts; `summary.txt` gives the counts.
3. The recording replay (6.3) gives identical `print raw` after `start`
   for every data test.
4. `bk-testkit` parses dumps, graph files, analysis and structure dumps,
   traces and recordings into typed structures, with unit tests on
   checked-in samples (S) and the property tests and fuzz targets (300 s
   each on the build host without finding).
5. Every format is documented in `tools/reference/README.md` with its
   version.
6. The two optional logs exist behind their commands, or the report
   says which cannot be done and why (4.12).
7. 6.4–6.7 pass; every capture is byte-identical between runs and the
   two hosts' captures agree except for causes named and counted.
8. The nightly `oracle` item exists and has run once.
9. Gate green on both remote gate runs.

## 8. Differences from Ghidra

- The dumps name pointer-valued offsets by canonical keys and write the
  varnode bank orders with those keys substituted (4.3); Ghidra's own
  order among those varnodes depends on heap addresses.
- Positional breakpoints reach actions whose names Ghidra's specifier
  syntax cannot (4.1, 4.10).
- The extension is linked into separate consoles; Ghidra's `decomp` is
  untouched (4.2).

(The implementing agent appends further differences here.)

Appended by the implementation (track `decomp-oracle`):

- `bk dump state` writes, besides 4.4's fields, the op's `print raw` text
  (`@ops`), `alttree` ops (`main`/`alt`), the action state of groups and
  pools stopped mid-way, `lanedMap`, `unionMap`, the local overrides, the
  function's own output trials (`Funcdata::activeoutput`), and jump tables'
  `recoverCount`, `displayFormat`, `block2addr`, load tables and original
  model; it leaves out what Ghidra never initialises or never sets:
  `Action::count`/`lcount` before the action first ran (`-`),
  `FuncProto::extrapop` without a model (`-`) and
  `FuncCallSpecs::matchCallCount` (always). An `fspec` varnode whose call
  spec Ghidra deleted (`deleteCallSpecs`) is written `call:-`, never
  dereferenced. A space constant's `nzm` is written as its key.
- `@c` is written when the function is finished and the root action is not
  stopped mid-way: `processing_complete` survives `Funcdata::clear`, so on
  a second decompilation of the same function it is set at every stop.
- `bk list actions` renders the lines in a fresh stream: `list action`
  pads the position with whatever fill the console's stream was left with
  (spaces in a fresh console).
- `bk break start` on a rule is an error: Ghidra checks only a rule's
  action breakpoint (`ActionPool::processOp`), so it would never stop.
- Fact blocks keep `FlowBlock`'s type `t_plain`: nothing in the structurer
  reads the copied block's type, and `t_basic` would invite a cast to
  `BlockBasic`.
- `bk capture structure` (not in 4.10) runs one decompilation and writes
  every structuring run's graph and structure: the mainloop's
  `blockstructure` runs an unknown number of times, which a static
  console script with `bk break` and `continue` cannot follow. It installs
  the switch defaults before writing a run's blocks, as
  `ActionBlockStructure` does next; plain `bk dump blocks` writes the
  labels as they are at the stop.
- The capture driver runs the consoles in the corpus directory with
  relative paths, so no output names where the corpus is.

Appended by track `decomp-oracle-v2` (format `bkstate 2`):

- `@scope` carries, for the function's local scope, what an exact rebuild
  of its `ScopeInternal` needs and the symbol and entry records do not
  give: the scope's ids and children (`I`), the category slots with empty
  ones (`C`), `multiEntrySet` (`E`), each space's entry-map record list with
  the subsort each record got at insertion (`R`) and its fragment multiset
  (`F`), and the dynamic entry list (`Q`). The record list and fragment
  order depend on insertion history (`rangemap.hh`); the subsort is
  computed once at insertion from the symbol's `addrtied` flag and the
  entry's use limit, which can change afterwards; `multiEntrySet`
  membership is decided when `wholeCount` reaches 2 and is not revisited.
  The name-tree order (name, dedup) and the child order (id) follow from
  what is written and are not repeated. Only the local scope is dumped;
  other scopes' symbols stay `G` references.
- Entry refs use the entry's real index in the symbol's `mapentry`, not
  `Symbol::getMapEntryPosition` (which returns 0 for every piece,
  database.cc:395) — in version 1 as well.

## 9. Status

Implemented (track `decomp-oracle`, report `docs/agents/decomp-oracle.md`):

- `scripts/build-reference.sh` step `[1b/5]`: `bin/decomp_dbg`,
  `bin/decomp_bk`, `bin/decomp_bk_dbg`; own fingerprints; `STAMP` lists
  them and `console_extension`. Both shared reference directories rebuilt:
  only files added and `STAMP` rewritten; `bin/decomp` byte-identical.
- The extension (`tools/reference/consoleext/`, 11 files): every command of
  4.10 and `bk capture structure`; the optional logs of 4.12 are not
  delivered (section 10, item 2).
- Formats `bkstate`, `bkgraph`, `bkcfg`, `bkstruct`, `bkactions`,
  `pcoderec` version 1 and the trace, in `tools/reference/README.md`.
- `bk-testkit`: `oracle::{graph, cfgdump, structure, actions, state, trace,
  pcoderec}` (typed readers, byte-identical writers, property tests, five
  fuzz targets), `oracle::{generate, host, capture}`, the `bk-oracle`
  driver, three new `Tool`s and consoles.
- Captures of the data tests and the research corpus on both builds: 167
  scripts (2 research fragments skipped: they fail in `decomp` too), 607
  decompilations, 11,005 ops and 18,134 varnodes checked complete, 74,836
  trace records, 767 structuring runs (each reproduced exactly by `bk
  structure … asgiven`), every recording replayed to the same `print raw`,
  `decomp_dbg` = `decomp`; two runs identical on each build; the builds
  differ in 5 of 8,536 files, all `floatprint`, by NaN sign (48 lines) and
  its bank-order consequence (8). Fixtures: `fixtures/decomp-oracle/`.
- Nightly item `oracle` (`tools/testbed/oracle.sh`).
- `bkstate 2` (track `decomp-oracle-v2`): the `@scope` records above;
  `bk-testkit` reads versions 1 and 2 and writes back the version it read.
  Over the 3,642 captured dumps (both builds, identical apart from the
  known NaN causes): 2,983 category records, no empty slot, no symbol in
  a multi-entry set, 42 dumps with dynamic entries, 7,750 entry-map
  records and 8,242 fragments; every record list equals the
  `(last, subsort)` order, which the format does not assume.

## 10. Open items

1. Whether every field of `JumpTable`, `LoadGuard` and `ParamTrial`
   listed in 4.4 is enough for D13, D10 and D07: the sections are
   specified by "every data member of the class" and the implementer
   lists the members it found; a consumer that needs more amends the
   format (version 2).
2. Whether the hook patches of 4.12 are practical.
3. How often `orderBlocks` ties occur in the corpora (decomp-cfg.md 10.1):
   the capture of D04's corpus graphs reports it.
4. Whether any pass iterates a varnode bank range over `iop`, `fspec` or
   space constants in a way that reaches output (4.3): if so it is a
   host dependence of Ghidra's output itself, to be found by the tracks
   that port those passes; none was found in the data tests (R5, R6).

Settled by the implementation:

1. The field lists are those of the classes at commit `42db038f3c`
   (`tools/reference/README.md`, "State dumps"). 4.4's `maxtablesize`,
   `maxaddsub`, `maxleftright`, `maxext` are not `JumpTable` state (the last
   three are `static constexpr`, the first a parameter of recovery), and
   `Heritage` has no `disjoint` member (it is local to `heritage()`). A
   jump-table model is written by kind only; `JumpBasic`'s recovered
   internals (`jrange`, `pathMeld`, normalised and switch varnodes) are not
   in v1 — D13 amends the format if it needs them.
2. The hook patches are not delivered. The mutation log needs a call at the
   top of about 60 `Funcdata` methods, several of them inline in
   `funcdata.hh`, kept in step with Ghidra in a second source copy and a
   third console build; the printer's pushes likewise need hooks in
   `PrintLanguage`'s non-virtual push methods. An `Emit`-only log is not
   transparent at the `PrintLanguage`→`Emit` boundary either: `Emit` keeps
   non-virtual state that callers set directly (`setPendingPrint`,
   `setIndentIncrement`, the paren and indent levels), which a forwarding
   wrapper would not share; it is transparent below `EmitPrettyPrint`
   (wrapping its `lowlevel`), if D16a wants the post-layout stream. D05 and
   D16a use their stated fall-backs.
3. `orderBlocks` ties: none. In all 607 decompilations the top level of the
   final structure is a single node, so `orderBlocks` sorts nothing
   (`list.size() != 1`).
4. No sign of it: captures on two builds with different allocators and
   heap layouts, and two runs on each, agree in every output (C, `print
   raw`, dumps, traces) apart from the NaN sign — 607 decompilations.

Settled by track `decomp-oracle-v2`:

5. State dump format 2 for an exact rebuild of a function scope
   (`decomp-symbols.md` 6.4): delivered as `bkstate 2`. Left out on
   purpose: whether a space has an empty entry map (Ghidra creates one on
   first use and keeps it when emptied; queries answer the same as with
   none), `Scope::owner` (a cache link, null for local scopes), and the
   database's resolve map (it holds no function scopes).
