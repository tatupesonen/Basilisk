# SLEIGH runtime, part 1: language loading, context, decoding, disassembly text (`bk-sleigh`)

Track `sleigh-decode`, milestone M1. Starts when `sla` (`features/sla.md`)
is merged. Format of this document: `docs/LOOP.md`. Background this spec
relies on and does not repeat: `docs/inventory/01-sleigh.md` sections 1
and 3–8a. Part 2 (`features/sleigh-pcode.md`) adds p-code generation to
the same crate afterwards.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`
under `../ghidra`; `REF` = `../reference`.

## 1. Purpose

Load a compiled language and decode machine instructions with it: which
constructors match, how long the instruction is, what its operands
resolve to, how it prints, and what it does to the decoding context.
This is the hot path under the disassembler, the emulator and the
decompiler, and the language data it produces is shared by every thread.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/sleigh.cc`, `sleigh.hh` | `Sleigh::initialize`, `resolve`, `resolveHandles`, `instructionLength`, `printAssembly`, the role of `DisassemblyCache` |
| `CPP/sleighbase.cc` | `buildXrefs`, `getRegister`, `getRegisterName`, `getExactRegisterName`, `getAllRegisters`, `getUserOpNames` |
| `CPP/context.cc`, `context.hh` | `ParserContext`, `ParserWalker`, `ConstructState`, `FixedHandle`, byte and bit access, `addCommit`, `applyCommits`, `setOutOfBandState`, `calcCurrentLength`, the limits |
| `CPP/slghsymbol.cc` | `resolve`, `getFixedHandle`, `print`, `checkTableFill` of every symbol kind; `Constructor::print*`, `applyContext`; `DecisionNode::resolve`; `ContextOp::apply`, `ContextCommit::apply` |
| `CPP/slghpatexpress.cc` | `getValue` of every expression; `getInstructionBytes`, `getContextBytes` |
| `CPP/slghpattern.cc` | `PatternBlock::isInstructionMatch`, `isContextMatch`; the three disjoint patterns' `isMatch` |
| `CPP/semantics.cc` | `HandleTpl::fix`, `ConstTpl::fix`, `fixSpace`, `fillinSpace`, `fillinOffset` (handle resolution only) |
| `CPP/globalcontext.cc`, `globalcontext.hh`, `partmap.hh` | `ContextBitRange`, `ContextDatabase`, `ContextInternal`, `ContextCache`, `TrackedContext` |
| `CPP/translate.hh` | The `Translate` interface, `UnimplError`, `BadDataError`, `AssemblyEmit`, `UniqueLayout` |
| `tools/reference/pcodedump.cc` (Basilisk) | What the oracle does around the engine: language set-up, the sweep, the record format |

C++ is authoritative (it is what the oracle and the decompiler run). The
Java runtime's additional services are `features/sleigh-language.md`.

## 3. Scope

**In.** Crate **`bk-sleigh`** (new, owned by this track): `Language`
(the loaded language: model, spaces, registers, user ops, context
variables, defaults from `.ldefs`/`.pspec`); the context database;
`Decoder` (parse an instruction: constructors, lengths, handles, pending
context commits; apply commits); disassembly text; the errors; the
differential test harness against `pcodedump`; benchmarks.

**Not in.** P-code generation and the `Translate` trait's
`one_instruction` (`sleigh-pcode`); the `basilisk disasm` command
(`sleigh-pcode`); flow types, operand objects, register groups, p-code
overrides, compiling a missing `.sla` (`sleigh-language`); following flow
across instructions (`bk-disasm`, M5); the file format (`bk-sla`).

Dependencies: `bk-sla`, `bk-core`, `bk-marshal`, `bk-pcode`, `bk-lang`
(registry, `.ldefs`, `.pspec`); dev: `bk-testkit`, `bk-elf`/`bk-bin` (text
sections of fixture binaries), `proptest`, `insta`, `dhat`.

## 4. Behaviour

Inventory sections 3–7 describe Ghidra's behaviour and are normative
unless this section says otherwise. This section fixes what is Basilisk's
own: the units of the API, the defined results where the C++ is
undefined, and the errors.

### 4.1 Loading a language
`Language::from_sla(Arc<Sla>)` builds, once:

* the `SpaceManager` (`bk_sla`'s `build_spaces`), with the language's
  register table installed as its `RegisterLookup`;
* the register table from every global varnode symbol: lookup by name,
  by exact `(space, offset, size)`, and "containing register" with
  exactly the search of `SleighBase::getRegisterName` (inventory section
  3 — including that it only looks back over entries with the first
  candidate's offset). Two symbols with the same location fail the load
  ("Duplicate register pairs", naming both);
* the user-op name table by index (gaps are absent);
* the context variables: name → bit range, from each context symbol's
  field, in global-scope name order; the context size in words;
* per value-map, name and varnode-list symbol, whether its table is
  completely filled (`checkTableFill`);
* per constructor, the flow-through operand (only print piece is one
  operand), and whether its main template asks for a delay slot;
* the default float formats (`bk_pcode::FloatFormats::DEFAULT`).

`Language::load(&LanguageRegistry, &LanguageId)` finds the `.sla` through
`registry.sla_file(id)`, reads it with `bk_sla`, then applies what the
other language files say, as `pcodedump` and Ghidra's `SleighArchitecture`
do: each `<truncate_space>` of the `.ldefs` entry (`SpaceManager`
truncation), and the `.pspec`'s `<context_data>` (4.3). A missing `.sla`
is an error that names the expected path. The `.sla`'s endianness is not
compared with the `.ldefs`'s here (Java does; `sleigh-language`).

`Language` is immutable, `Send + Sync`, and shared as `Arc<Language>`.

### 4.2 Context database
`ContextDb` is a port of `ContextInternal` with the semantics of inventory
section 4.2: default words; split points ordered by (space index,
offset); a value and an explicitly-set mask per split point;
`set_change_point` (flowing), `set_region`, by word/mask or by variable
name; `get(addr)` returning the words and the offset range over which
they are constant; tracked sets with `tracked_value`. It is plain data
(`Clone`), independent of any language once created with a context size.

The decoder reads context through a small trait so that the program
model's own store (M5) can stand in for `ContextDb`:

```
trait ContextSource { fn context_at(&self, addr: Address, out: &mut [u32]) -> OffsetRange; }
trait ContextSink   { fn set_change_point(&mut self, addr, word, mask, value);
                      fn set_region(&mut self, first: Address, end: Option<Address>, word, mask, value); }
```

### 4.3 Defaults from the `.pspec`
`Language::initial_context() -> ContextDb`: a fresh database of the
language's context size, with each `<context_set>` applied as a region set
over its range and each `<tracked_set>` stored for its range
(`ContextInternal::decodeFromSpec`). Names and ranges come unresolved
from `bk_lang::ProcessorSpec`; resolve them through `pspec::AddressResolver`
on the language's spaces, replaying `ProcessorSpec::sections` in order. An
unknown context variable is a load error ("Non-existent context variable:
X"). `<set val>` is decimal or `0x` hex as `bk-lang` decodes it.

### 4.4 Decoding
`Decoder` is a per-thread worker over an `Arc<Language>`. It owns every
buffer it needs and reuses them; **after warm-up, decoding allocates
nothing**. Bytes come from a `ByteSource` (monomorphised, not `dyn`):
`fn load(&self, addr: Address, buf: &mut [u8; 16])`, the counterpart of
`LoadImage::loadFill`; an implementation over `(base, &[u8])` that reads
zeros outside the slice is provided (what `pcodedump` does).

`decode(addr, &bytes, &context) -> Result<&Parse, DecodeError>` performs
"resolve" of inventory section 5 and returns the parse: the tree of
constructor nodes (constructor, offset, length), the instruction length,
the delay-slot byte count, and the pending commits. It does not touch
the context store.

`resolve_handles(&mut parse)` performs "resolve handles" (needed before
p-code, and by callers who want operand values).

`apply_commits(&parse, &mut sink)` performs `applyCommits` (inventory
section 4.4).

`prepare(addr, …)` is the sequence the engine runs before generating
p-code (`Sleigh::oneInstruction` steps 1–3, inventory section 7.1), and
what the differential harness must run after each instruction so the
context evolves as the oracle's does: alignment check; decode; resolve
handles; apply commits; then, while delay-slot bytes remain, decode the
next instruction, resolve its handles, apply its commits. It yields the
flow length (length including delay slots) and leaves the main and
delay-slot parses available to part 2.

Defined results where the C++ is undefined (inventory section 8):

| Case | Basilisk |
|---|---|
| Reading instruction bytes | The buffer is 16 bytes. A read whose first byte index is ≥ 16 is `BadData` "Instruction is using more than 16 bytes" (as C++). Bytes of a read that starts below 16 and runs past it are zero |
| `<<`, `>>` | Count taken modulo 64; `>>` arithmetic (ADR-021; Java agrees) |
| `/` | Divisor 0 is `BadData` "Division by zero in pattern expression" (Java throws; C++ undefined); `i64::MIN / -1` wraps |
| `+ - *`, unary `-` | Wrapping |
| More than 20 operands in a constructor | Decoded normally. Ghidra's C++ fails ("SLEIGH parser out of state space"; [run] `vadduhm`, PowerPC AltiVec, 27 operands) |
| Nesting | More than 30 nested constructors is `Limit` "SLEIGH exceeded maximum parse depth" (as C++); more than 4,096 nodes in one instruction is `Limit` |
| `operand_exp` recursion | Bounded by the loader's cycle check (`bk-sla`) and a depth limit of 64 |
| `inst_next2` | Decodes the next instruction with the context the store holds for it *now*; the look-ahead is not cached across calls (inventory section 5.2 describes the one situation where Ghidra's cache would answer differently) |
| A parse cached in Ghidra although context changed | Never reused: the decoder may keep the last parse to serve `disassemble` followed by `prepare` at the same address, keyed by address, byte-source identity and a change counter of the context store |

### 4.5 Disassembly text
`mnemonic(&parse, out)` and `body(&parse, out)` append to caller-owned
`String`s exactly what `Constructor::printMnemonic` and `printBody` write
(inventory section 6): the flow-through recursion, the split at the first
white-space piece, operands printed in full, numbers as `0x…`/`-0x…` in
lower-case hex of the 64-bit value, register names from the symbol.
Formatting uses no locale and no floating point.

### 4.6 Errors
`DecodeError` (`thiserror`), each carrying the address and printing
Ghidra's text so that the oracle's `E` records can be compared verbatim:

| Variant | Text | Ghidra |
|---|---|---|
| `BadData::NoConstructor` | `<addr>: Unable to resolve constructor` | `BadDataError` |
| `BadData::NoTableEntry(kind)` | `<addr>: No corresponding entry in valuetable` / `nametable` / `varnode list` | `BadDataError` |
| `BadData::TooLong` | `Instruction is using more than 16 bytes` | `BadDataError` |
| `BadData::DivisionByZero` | see 4.4 | — |
| `Limit(..)` | as in 4.4 | `LowlevelError` |
| `Next2Unavailable` | `inst_next2 not available in this context` | `LowlevelError` |
| `Unaligned` (from `prepare`) | `Instruction address not aligned: <addr>` | `UnimplError`, length 0 |

`<addr>` is the space's shortcut character followed by the raw address
(`bk_core`'s `print_raw`): `r0x00001002`.

### 4.7 Platforms (ADR-022)
No file access beyond `bk-sla`'s and `bk-lang`'s; nothing
platform-specific. Tests that need `REF` or the Ghidra tree skip without
them (so they skip on Windows CI, where the reference tools are not
built); everything else — unit tests on hand-built `Sla` fixtures, the
context database tests, the snapshot tests of 6.4 — runs on all three
systems.

## 5. Design

* Modules: `language/{load, registers, userops, context_vars, setup}`,
  `context/{db, partmap, tracked}`, `decode/{bytes, tree, resolve,
  decision, pattern, expr, handles, commit}`, `print`, `error`,
  `translate` (the trait, completed in part 2).
* **The parse** is a `Vec` of nodes reused between instructions. When a
  constructor is chosen, its operands' nodes are allocated as one
  contiguous run (`first_child + i`), so a node is `{constructor, parent,
  first_child, offset, length, handle}` with no per-node allocation.
  `FixedHandle` is `Copy` (space, size, optional pointer space + offset +
  size, temporary space + offset).
* **Decision walk**: a loop over `bk_sla` decision nodes — read the field
  with one or two unaligned loads from the 16-byte buffer (kept as two
  big-endian `u64`s, or a `u128`), index the child run. Leaf: test pairs
  in order with word compares. No recursion, no virtual calls.
* **Expressions**: an iterative or shallow-recursive evaluator over the
  `Expr` arena; token-field reads are a shift and mask of the buffered
  bytes.
* **Symbols** dispatch on the `bk_sla` kind enum (`match`), not on trait
  objects.
* **Sizes** asserted in tests: parse node ≤ 64 bytes; `FixedHandle` ≤ 40.
* **Threads**: one `Arc<Language>`, one `Decoder` per thread. A test
  decodes the same stream on 8 threads and requires identical output.
* **What part 2 and later tracks get from this track**: `Language`
  (spaces, `RegisterLookup`, user-op names, float formats, alignment,
  `uniqbase`, `uniqmask`, `maxdelay`, `numsections`, context variables,
  `initial_context`), `ContextDb` and the two traits, `Decoder` with
  `decode`/`resolve_handles`/`apply_commits`/`prepare`, `Parse` (tree
  walk, handles, constructor ids, commits), the text functions, and
  `trait Translate` with `instruction_length` and `print_assembly`
  implemented by a `(Language, ContextDb, ByteSource)` bundle.

## 6. Tests

### 6.1 Ghidra tests to port
Checklist files under `docs/inventory/tests/`. The Java tests of the
SLEIGH runtime mostly need a `Program`; those that need only a language
are listed in `features/sleigh-language.md` (they use Java-only API:
`Register`, `RegisterValue`, volatility). For this track:

* `decompiler-cpp.md` — the 93 data tests load a language through the C++
  `Sleigh` and so depend on this track, but they test the decompiler and
  are ported by `bk-decomp` (M3). Not marked here.
* No C++ unit test targets the SLEIGH runtime.

So this track's independent check is the differential one, as planned in
`PLAN.md` M1.

### 6.2 Differential test against `pcodedump` — every language
For each of the 150 `.slaspec`-derived `.sla` files that an `.ldefs` names
(all language ids of the registry; ids sharing one `.sla` and `.pspec` are
run once), compare record by record with `REF/bin/pcodedump` (format:
`tools/reference/README.md`). In this track the `I` records (address,
length, **flow length**, bytes, mnemonic, operand text), the `E` records
(address, length, bytes, kind, message) and the `T` record are compared;
`P` and `U` records are ignored until part 2. Basilisk's side of the
sweep mirrors the oracle's exactly: at each position `decode` + text,
then `prepare` (so commits and delay-slot parses happen in the same
order), advance by length; a failed decode is an `E` of length 1; an
instruction longer than the remaining input is `truncated` and ends the
sweep; `--context` is a region set over the whole default code space.

**Where the bytes come from** (all deterministic; seeds fixed in the test):

1. *Directed samples.* For every pair at every leaf of the root decision
   tree: 8 samples of 16 random bytes with the pair's instruction mask
   and value imposed at its offset. When the pair has a context block,
   the sample belongs to the context configuration obtained by turning the
   block's mask and value into values of the named context variables
   (unconstrained bits 0); otherwise to the `.pspec` default. Samples of
   one configuration are packed into one stream using the length
   Basilisk decodes for each (a delay-slot instruction is followed by a
   second directed sample), and the stream is given to the oracle with
   that configuration as `--context` options. Packing by Basilisk's own
   length cannot hide an error: a wrong length desynchronises the two
   sweeps and the records differ. To raise coverage of sub-tables, half
   of the samples additionally impose the pattern of a randomly chosen
   leaf pair of each sub-table operand at that operand's offset (when
   compatible with the bits already fixed).
   A stream is cut (a new oracle invocation starts) after a sample whose
   parse committed context, so commits do not colour all later samples;
   at most 200 invocations per language, after which streams are not cut.
2. *Random sweep.* 64 kB of random bytes per language under the default
   context: error paths, resynchronisation, commits in sequence.
3. *Real code.* The text sections of the ELF fixtures `bk-elf`'s tests
   use (and of Ghidra's test binaries where the tree has them), each
   under its language's default context: realistic sequences, delay slots
   and mode switches (`--context TMode=1` for Thumb objects).

**How coverage is judged.** The harness counts, per language, the
constructors selected in any node of any parse that the oracle confirmed
as an `I` record, and writes a table (language, constructors, exercised,
root pairs targeted, root pairs confirmed) as an `insta` snapshot.
Required: every root-table leaf pair targeted; at least 99 % of root pairs
confirmed across all languages and at least 95 % in each; at least 90 %
of all constructors exercised in each language. A language below a
threshold fails the test unless its uncovered constructors are listed in a
checked-in exceptions file with the cause for each group (for example
"needs a context value no named variable can express"); the coordinator
reviews that file at merge.

**Tolerated differences**, each recognised mechanically by the harness
and counted in the snapshot (zero is expected for 2–3):

1. *More than 20 operands.* Oracle: `E … error  SLEIGH parser out of
   state space`; Basilisk: an instruction whose parse has a constructor
   with more than 20 operands. The harness then resynchronises at the
   next address both sides have a record for. Directed samples for such
   root constructors are kept out of the oracle streams and covered by
   6.4.
2. An instruction that reads a byte index ≥ 16 (oracle reads past its
   buffer).
3. An instruction that both evaluates `inst_next2` and commits context
   that changes the next instruction's decode.

Anything else is a failure. The full run is long (hundreds of oracle
processes); it is a normal test that skips without `REF`, and a reduced
form (directed samples, 1 per pair, 12 languages named in the test: x86,
x86-64, ARM v8 LE, AARCH64, MIPS32 BE, PowerPC 32 BE, SPARC, 68000, AVR8,
RISC-V 64, Hexagon, Toy BE) runs in the gate.

### 6.3 Tests derived from the source
Unit tests on `Sla` fixtures built with `SlaBuilder`: each symbol kind as
an operand; each expression operator with boundary values (shift counts
0, 63, 64, −1; division by zero; `i64::MIN`); token fields big- and
little-endian, signed and unsigned, crossing byte boundaries, at offsets
that reach byte 15 and 16; context fields across a word boundary;
operand offsets relative to the constructor and to another operand;
length calculation with operands longer than the constructor;
`operand_exp` evaluated before its operand is parsed (context change);
value-map, name and varnode-list tables with unusable entries and the
"filled" shortcut; flow-through printing; the 30-level depth limit; the
register lookup quirk of 4.1; the context database: every operation of
4.2 including a flowing set stopping at an earlier explicit set, region
sets, defaults, tracked values in both endiannesses; commit application
for an operand address, `inst_next`, a constant-valued address in a
word-addressed space, `noflow`, and wrap-around at the top of the space.

### 6.4 Snapshots (run everywhere, no oracle needed)
`insta` snapshots, taken from `pcodedump` output once and checked in
(they are small): the directed samples of the Toy languages, and 200
instructions each of x86-64, ARM/Thumb with a mode switch, MIPS with
delay slots. Plus Basilisk-only snapshots of the PowerPC AltiVec
instructions Ghidra's C++ cannot decode.

### 6.5 Property and fuzz
`proptest`: arbitrary bytes and context words never panic in `decode`,
`prepare`, text; decoding is deterministic; `decode` never reports a
length of 0 or above the 16-byte limit plus operand overhang allowed by
the model. Fuzz target `bk_sleigh_decode` in the shared `fuzz/` crate:
input = a language selector byte (over the fixture languages embedded as
`Sla` built in the harness, and the reference `.sla` files when present)
followed by bytes and context; runs `decode`, text and `prepare`.
A second target `bk_sleigh_hostile_sla` feeds `bk_sla`-fuzzed models that
passed validation into the decoder with fixed bytes: a valid model must
never make the decoder panic or loop. 60 s each without a finding.

### 6.6 Benchmarks (`#[ignore]` release tests; numbers in `PERF.md`)
On the x86-64 code sample `tools/reference/measure.sh` builds (or the
4-file variant described in `docs/agents/spec-sleigh.md`), same context
settings as the oracle, best of 5, with the reference figure re-measured
in the same session:

| Benchmark | Reference (inventory 8a, loaded machine) | Required |
|---|---|---|
| `Language::load` x86-64 (`.sla` + `.ldefs` + `.pspec`) | 41–48 ms | no slower than the reference in the same session; at most 40 ms |
| decode only | 2.87 M instructions/s | at least the reference in the same session |
| decode + text | 1.24 M/s | at least the reference in the same session |
| allocations per instruction in steady state | — | 0, asserted with `dhat` over 100,000 instructions |
| 8 threads sharing one `Language` | — | throughput scales at least 6× on the 8-core machine; recorded |

## 7. Acceptance

1. The differential test of 6.2 passes for every language, with the
   coverage thresholds met or excepted in the checked-in file, and the
   tolerated-difference counts in the snapshot.
2. The tests of 6.3–6.5 pass; no panic on any input; both fuzz targets
   run 60 s clean.
3. The benchmarks of 6.6 meet their figures; results in `PERF.md`.
4. `Language` and `ContextDb` are `Send + Sync` (asserted); sizes of 5
   asserted.
5. Gate green on macOS; `cargo check --target x86_64-pc-windows-msvc`
   passes; the oracle-free tests pass on all three systems in CI.

## 8. Differences from Ghidra

* Defined results for the undefined cases of 4.4 (bytes past 15, shifts,
  division by zero, more than 20 operands, bounded recursion).
* No address-keyed parse cache: a parse is never reused after the
  context changed.
* The context is reached through traits; `ContextCache`'s range cache is
  an implementation detail of `ContextDb` lookups, not a separate object.
* Errors are typed values carrying Ghidra's messages.
* Space-id constants are space indices, not host pointers.

(The implementing track appends.)

Appended by the `sleigh-decode` track:

* **Errors are one flat enum** (`DecodeError`) with `class()` giving
  Ghidra's exception class (`BadData`, `Unimplemented`, `Lowlevel`, which
  is also `pcodedump`'s record kind), instead of nested `BadData::…`
  variants. Each prints Ghidra's text and carries the address.
* **A node whose constructor exports nothing has the constant-0 handle.**
  Ghidra's node keeps whatever its reused state held.
* **Operand values evaluated "out of band" where Ghidra's walker is left
  uninitialised** (the named constructor is not above the current node,
  or a nested reference from the stand-in node names another constructor)
  are evaluated at the current position. The documented quirk that a
  constructor-relative operand is placed from the stand-in node's offset is
  kept.
* **`inst_next` in an expression evaluated while the instruction is being
  resolved** (before its length is known) is the instruction's own address;
  Ghidra reads the stale value its reused parser state holds.
* **Context words past the end of the array read as zero**, in decision
  nodes, context patterns and context fields (Ghidra reads past the array);
  a context operation shift of 32 or more is taken modulo 32 (x86-64).
* **A completely filled table indexed by a negative field value** (a signed
  field) is `NoTableEntry` when the operand is printed or its handle
  resolved; Ghidra indexes outside its table. A varnode-list entry that is
  unusable at print time is `NoTableEntry` (Ghidra dereferences null).
* **`inst_next2`** is computed when the parse is decoded if an operand
  prints or resolves through it, and before handles are resolved if an
  export or a commit uses it, by decoding the next instruction with the
  context the store holds then; if that look-ahead fails, a use reports
  `Next2Unavailable` (Ghidra reports the look-ahead's own error). Only Toy
  uses `inst_next2`, and only in p-code.
* **Ghidra's operand limit is available as an option**:
  `Decoder::set_operand_limit(Some(20))` fails as Ghidra's C++ does ("SLEIGH
  parser out of state space"). The differential harness uses it so both
  sweeps stay in step; Basilisk's own decoding of those constructors is
  checked separately (6.4 and the harness's `over-20` count).
* **`prepare` bounds the delay-slot loop** to 16 instructions and stops at a
  zero-length instruction (Ghidra's loop would not end).
* `ContextDb::change_point` and `region` combine the value with a bitwise
  OR without masking it, as Ghidra does; the by-variable forms mask.
* **The coverage snapshot of `every_language` holds only what every host
  gives** (track `sleigh-perf-linux`, 2026-11-14). Where `pcodedump` reads
  a stale handle (ADR-038) it prints a record on one host and crashes on
  another (ARM v8-m little-endian: 145 unset-handle records and 5 crashes
  on macOS, 146 and 4 on x86-64 Linux), so the snapshot row has
  `unset-or-crash` (their sum) where it had the unset-handle count and
  `oracle-crashes`; the run prints both counts and a summary, and the
  threshold assertions run before the snapshot. Not a difference in
  decoding, only in what the test asserts.

## 9. Status

Done (track `sleigh-decode`, 2026-11-14). Crate `crates/bk-sleigh`: `Language`
(`from_sla`, `load`, `truncate_space`, `apply_processor_spec`, registers,
user ops, context variables, `initial_context`), `ContextDb` with the
`ContextSource`/`ContextSink` traits, `Decoder` (`decode`,
`resolve_handles`, `apply_commits`, `prepare`, `disassemble`,
`set_operand_limit`), `Parse` (nodes, handles, commits), text
(`Language::mnemonic`, `body`), `Translate`/`Translator`, errors.

Acceptance, as measured (details in `docs/agents/sleigh-decode.md`):

1. The differential test passes for every language `pcodedump` can run (175
   distinct `.sla`/`.pspec` pairs): no record differs; 419,098 of 421,932
   root pairs confirmed (99.33 %), every language at or above 95 % of its
   pairs and 90 % of its constructors except the two `DATA` languages,
   which are in the exceptions file (`tests/data/coverage-exceptions.txt`);
   tolerated differences: 3 (more than 20 operands), 1 (bytes past 16), 0;
   36 oracle crashes (a Ghidra bug, below) split out. The coverage table is
   the snapshot `tests/snapshots/differential__coverage_table.snap`.
2. Tests of 6.3–6.5 pass; both fuzz targets ran 60 s clean.
3. Benchmarks met except the 8-thread scaling (4.78× on a machine loaded by
   other work); `docs/PERF.md`.
4. `Language` and `ContextDb` are `Send + Sync`, sizes asserted.
5. Gate green on macOS; Windows checked with `cargo clippy --target
   x86_64-pc-windows-msvc` and the oracle-free tests run under Wine; Linux
   rests on CI.

Departures from this spec, with reasons, are in the track report: streams
are cut on demand (when a sample no longer decodes to its target after
earlier commits) with a cap of 1,000 invocations instead of after every
commit with a cap of 200; the `T` record's error count is compared without
`U` records (part 2); recordings of real languages need Ghidra's `.sla`
and are skipped in CI, where the self-contained `bkfix` fixture's
recording runs instead.

**Performance on x86-64 Linux** (track `sleigh-perf-linux`, 2026-11-14):
decode only is now 11 % ahead of the g++-built reference on an AMD Zen 4
virtual machine (it was 14 % behind) and 32 % ahead on the M1 Pro;
decode + text 50 % and 95 % ahead. `docs/PERF.md` has the numbers,
`docs/agents/sleigh-perf-linux.md` the changes. `Node::handle` moved to
`Parse::handle(n)`.
