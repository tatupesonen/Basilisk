# SLEIGH runtime, part 2: p-code generation, `Translate`, `basilisk sleigh decode` (`bk-sleigh`)

Track `sleigh-pcode`, milestone M1. Starts when `sleigh-decode`
(`features/sleigh-decode.md`) is merged; same crate, so the two never run
together. Format of this document: `docs/LOOP.md`. Background this spec
relies on and does not repeat: `docs/inventory/01-sleigh.md` sections 1.7,
7, 8 and 8a.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`
under `../ghidra`; `REF` = `../reference`.

## 1. Purpose

Turn a decoded instruction into p-code: walk the constructors' templates,
fill in operand handles, add the loads and stores that dynamic operands
need, weave in delay-slot and cross-built instructions, resolve labels to
relative branches, and hand the operations to an emitter. With this the
crate offers the whole of Ghidra's `Translate` interface, which is what
the decompiler, the emulator and the disassembler stand on. The track
also delivers the `basilisk sleigh decode` command and completes the differential
test of M1.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/sleigh.cc`, `sleigh.hh` | `Sleigh::oneInstruction`; `SleighBuilder` (`dump`, `generateLocation`, `generatePointer`, `generatePointerAdd`, `appendBuild`, `buildEmpty`, `delaySlot`, `appendCrossBuild`, `setLabel`, `setUniqueOffset`); `PcodeCacher` (`addLabel`, `addLabelRef`, `resolveRelatives`, `emit`, the 4,096-varnode bound) |
| `CPP/semantics.cc`, `semantics.hh` | `PcodeBuilder::build`; `ConstTpl::fix`/`fixSpace`; `VarnodeTpl::isDynamic`, `isRelative`; the directive opcodes |
| `CPP/translate.hh` | `Translate`, `PcodeEmit`, `UnimplError`, `UniqueLayout` |
| `CPP/inject_sleigh.cc` | `InjectPayloadSleigh::inject`, `setupParameters` — how a free-standing template is built with fixed parameter handles |
| `tools/reference/pcodedump.cc` (basilisk) | The oracle and its output format, which `basilisk sleigh decode` reproduces |

C++ is authoritative. Java's `PcodeEmit` additionally applies flow
overrides, fall-through overrides and `CALLOTHER` fix-ups; those are
`features/sleigh-language.md`.

## 3. Scope

**In.** In crate **`bk-sleigh`** (owned by this track while it runs): the
p-code builder; the emitter interface; `Translate::one_instruction`;
building p-code from a free-standing template with given parameter
handles (the mechanism injection needs); `basilisk sleigh decode` in the
`basilisk` binary crate (one new subcommand module; the only file outside
`bk-sleigh` this track touches besides the shared files every track
appends to); the full differential test; throughput benchmarks.

**Not in.** Compiling p-code snippets from text (`sleigh-snippet`);
choosing and applying injections, call fix-ups, flow overrides
(`sleigh-language`, the decompiler); an owned p-code op type with sequence
numbers (`PcodeOpRaw`) and the emulator (M6); printing p-code in Ghidra's
listing syntax (`PcodeFormatter`, `sleigh-language`).

## 4. Behaviour

Inventory section 7 is normative for the algorithm: order of events
(7.1), building a template with `BUILD`/`DELAY_SLOT`/`LABEL`/`CROSSBUILD`
(7.2), one op with dynamic inputs and outputs (7.3), resolving varnode
templates and constants (7.4), relative branches (7.5), delay slots and
crossbuild (7.6). What follows fixes basilisk's side.

### 4.1 `lift`
`Decoder::lift(addr, &bytes, &mut context, &mut emitter) -> Result<u32,
LiftError>` is `Sleigh::oneInstruction`: `prepare` (part 1 — alignment,
decode, handles, commits, delay-slot parses), build the root
constructor's main template into the decoder's op buffer, resolve
relative branches, then pass every op to the emitter in order. It returns
the flow length. Nothing reaches the emitter unless the whole instruction
built without error.

### 4.2 The emitter
```
trait PcodeEmit { fn op(&mut self, addr: Address, opcode: OpCode,
                        output: Option<VarnodeData>, inputs: &[VarnodeData]); }
```
`inputs` borrows the decoder's buffer for the duration of the call. An
emitter that collects into its own arena, one that counts, and one that
writes `pcodedump` `P` records are provided. Opcodes passed are never
directives.

### 4.3 Varnodes
* Space-id constants (`LOAD`/`STORE` input 0; `const_curspace` or
  `const_spaceid` used as a value): a constant-space varnode whose offset
  is the **space index** and whose size is 8, built with
  `bk_core`'s `Address::const_from_space` convention
  (`docs/agents/core-marshal.md`). `pcodedump` prints exactly this
  (`(const,0x3,8,ram)`).
* Unique-space offsets: template offset OR
  `(address offset & uniqmask) << 8`, where the address is that of the
  instruction whose template is being built (the delay-slot or
  cross-built instruction while inside one).
* The effective-address temporary of a truncated dynamic operand is
  `uniqbase + 0x100` (`UniqueLayout::RUNTIME_BITRANGE_EA`), in the unique
  space, **without** the `uniqmask` bits (the C++ assigns the offset
  directly).
* `Language` exposes the layout constants: `unique_start(layout)` =
  `uniqbase + layout` for `RUNTIME_BOOLEAN_INVERT` 0,
  `RUNTIME_RETURN_LOCATION` 0x80, `RUNTIME_BITRANGE_EA` 0x100, `INJECT`
  0x200, and the fixed `ANALYSIS` 0x10000000.

### 4.4 Errors
`LiftError` wraps part 1's `DecodeError` and adds:

| Variant | Text | Ghidra |
|---|---|---|
| `Unimplemented { flow_length }` | `Instruction not implemented in pcode:\n <addr>: <mnemonic>  <body>` — of the instruction being built when a constructor without a template was reached | `UnimplError` |
| `Unaligned` | `Instruction address not aligned: <addr>`, flow length 0 | `UnimplError` |
| `MissingLabel` | `Reference to non-existant sleigh label` | `LowlevelError` |
| `CrossBuildInSection` | `CROSSBUILD directive within a named section` | `LowlevelError` |
| `CrossBuildTarget` | `Could not obtain cached crossbuild instruction` — the target address does not decode | `LowlevelError` |
| `DelaySlot` | a delay-slot instruction does not decode: the underlying `DecodeError`, reported as the oracle does (`U bad-data …`) | `BadDataError` from the nested parse |
| `TooManyVarnodes` | `Maximum parameters exceeded for a single p-code op` — one op with more than 4,096 varnodes | `LowlevelError` |
| `Limit` | more than 65,536 ops or 64 nested delay/crossbuild levels in one instruction | none (unbounded in C++) |

`CROSSBUILD` in Ghidra requires the target to be in the parse cache
already; basilisk decodes the target on demand (with the context the
store holds for it) and resolves its handles, which gives the same result
whenever Ghidra's precondition held.

### 4.5 Free-standing templates (for injection)
`Decoder::build_template(template: TemplateRef, ctx: &InjectContext, &mut
emitter)`: `InjectContext` gives the instruction address (`inst_start`),
the next address (`inst_next`), the call or reference address
(`inst_dest`/`inst_ref`), and a list of `(operand index, VarnodeData)`
parameters. As `InjectPayloadSleigh::inject` does: a one-node parse whose
operand handles are the parameters as static handles (space, offset,
size); `uniqmask` treated as 0; `DELAY_SLOT` and `CROSSBUILD` are errors;
relative branches resolved; ops emitted at the instruction address.
`const_flowref`/`const_flowdest` and their sizes resolve from the
call address. This is the only place those constants are legal.

### 4.6 `Translate`
The trait gathers what the decompiler asks of a language
(`CPP/translate.hh`); a bundle of `Arc<Language>`, a context store and a
byte source implements it:

`instruction_length(addr)`, `print_assembly(addr, &mut emit)`,
`one_instruction(addr, &mut emit)`; `register(name)`,
`register_name(space, offset, size)`, `exact_register_name`,
`all_registers()` (ordered by space, offset, size), `user_op_names()`,
`spaces() -> &SpaceManager`, `float_format(size)`, `alignment()`,
`is_big_endian()`, `unique_base()`, `unique_start(layout)`,
`set_context_default(name, value)`, `allow_context_set(bool)` (when
false, commits are not applied — `ContextCache::allowSet`).

### 4.7 `basilisk sleigh decode`
```
basilisk sleigh decode --language <id> [--root <ghidra-or-reference-dir>] [--base <addr>]
                [--context NAME=VALUE]... [--hex HEXBYTES | <file> | -]
                [--format pcodedump|text] [--no-pcode] [--quiet] [--timing]
```
A linear sweep over raw bytes, exactly `pcodedump`'s (zero fill past the
end, `E` on failure and resume at the next byte, `truncated` at the end).
`--format pcodedump` (the default) writes format version 1 of
`tools/reference/README.md` **byte for byte as the oracle does**, so the
two outputs can be compared with `cmp`; `text` is a human listing
(address, bytes, mnemonic, operands, indented p-code in the same varnode
notation). Language files are found through `bk_lang`'s registry under
`--root` (default: `BASILISK_GHIDRA_DIR`); exit status 0 when the sweep
ran, 1 when the language cannot be loaded, 2 for a bad command line.
Output uses `\n` on every platform; input is read in binary mode.

### 4.8 Platforms (ADR-022)
As part 1. The command works on Windows paths and reads standard input
in binary mode there. No timing- or locale-dependent formatting
(`--timing` writes to standard error only).

## 5. Design

* Modules added: `pcode/{build, op, location, labels, delay, crossbuild,
  inject}`, `emit`, `translate` (completed); in the binary crate
  `cmd/disasm`.
* **Op buffer**: two reusable `Vec`s in the decoder — ops `(opcode,
  output slot, input range)` and varnodes — cleared per instruction;
  label positions and label references in two more. **No allocation per
  instruction or per op in steady state.**
* **Builder** is a loop with an explicit stack of (template, position,
  node, label base, unique bits) for `BUILD`, delay slots and crossbuild;
  recursion depth is bounded by part 1's parse depth plus the nesting
  limit of 4.4.
* **Template access** through `bk_sla`'s `TemplateRef`, so file templates
  and owned snippet templates share the code.
* `VarnodeData` is `bk_core`'s (16 bytes).
* The decoder keeps the parses of the current instruction, its delay-slot
  instructions and at most one cross-build target alive together.

**What later tracks get**: `PcodeEmit`, `lift`, `build_template` and
`InjectContext`, `trait Translate`, the `pcodedump`-format writer (reused
by tests of the compiler: compile with basilisk, decode with basilisk,
compare with the oracle), `basilisk sleigh decode`.

## 6. Tests

### 6.1 Ghidra tests to port
None can be ported with this track alone: `PcodeEmitContextTest` (16) and
`PcodeEmitContextCrossBuildTest` (11) in
`docs/inventory/tests/test-integrationtest.md` test p-code emission but
through a `Program` and Java's override machinery
(`features/sleigh-language.md` lists them); the C++ data tests belong to
`bk-decomp`. The independent check is 6.2.

### 6.2 Differential test against `pcodedump` — every language, every record
Part 1's harness (byte sources, context configurations, coverage table,
resynchronisation) with the comparison extended to **all** records: `P`
(opcode, output, inputs — space name, offset, size, register name) and
`U` (kind, message). With `basilisk sleigh decode --format pcodedump` this is a
byte comparison of the two tools' outputs per stream, except at the
tolerated differences:

1. Part 1's three (more than 20 operands; bytes past 15; `inst_next2`
   with a commit).
2. None is expected in p-code. In particular unique-space offsets are
   compared exactly, not up to renaming — the `.sla` is the same file on
   both sides.

Coverage is additionally judged on templates: the snapshot table gains
"constructors whose main template was built" and "op templates built" per
language; required at least 90 % of constructors with a template in each
language, or an entry in the exceptions file. Hexagon (crossbuild, named
sections, `uniqmask`), the 26 languages with `maxdelay`, and Toy
(`inst_next2`) must each show their feature exercised: the table has a
column per feature (delay slots built, crossbuilds built, named sections
built, relative branches resolved, dynamic loads, dynamic stores,
truncated dynamic operands) and a zero in a column for a language whose
`.sla` contains the construct fails the test.

The gate runs the reduced form (part 1's twelve languages); the full run
is the merge check.

### 6.3 Tests derived from the source
On `Sla` fixtures built with `SlaBuilder`: each directive; nested `BUILD`
in main and named sections including implied builds through a constructor
without that section; labels in nested constructors (label bases), a
backward and a forward relative branch, sizes 1–8 of the branch constant;
dynamic input, dynamic output, both in one op, with and without
offset-plus, with a constant pointer (static after all); offset-plus on a
constant handle (shift) and on a register handle (add); constants in the
constant space masked to size; unique offsets with and without
`uniqmask`; delay slot of one and of two instructions, a delay-slot
instruction that does not decode, commits made by the delay-slot
instruction; crossbuild to a section present and absent; an unimplemented
constructor at the root and nested (message names the right
instruction); every error of 4.4; `build_template` with inputs and an
output, `inst_dest`, a relative branch.

### 6.4 Snapshots
The part-1 snapshot streams with their p-code, from `pcodedump` output
checked in once; they run everywhere without the oracle.

### 6.5 Property and fuzz
The part-1 targets extended to `lift`; additionally `proptest`: for
arbitrary bytes, every relative branch emitted lands inside the
instruction's own op list or one past its end, every varnode has a size
the op allows being non-zero, and `lift` after `disassemble` gives the
same instruction length. Fuzz target `bk_sleigh_lift` (bytes and context
on the fixture languages). 60 s without a finding.

### 6.6 Benchmarks (`#[ignore]` release tests; numbers in `PERF.md`)
Same input and method as part 1, reference re-measured in the same
session.

| Benchmark | Reference (`PERF.md`; inventory 8a) | Required |
|---|---|---|
| decode + lift, counting emitter | 1.5 M instructions/s, 6.1 M ops/s | at least the reference in the same session |
| decode + text + lift | 0.84 M/s | at least the reference in the same session |
| `basilisk sleigh decode --quiet` end to end on the 778 kB sample | `pcodedump --quiet`: 0.14 s after a 41–48 ms load | no slower in total |
| `basilisk sleigh decode` with the full listing to a null device | `pcodedump`: 0.65 s | no slower |
| allocations per instruction in steady state | — | 0, asserted with `dhat` |

## 7. Acceptance

1. The differential test of 6.2 passes for every language with the
   coverage and feature columns satisfied.
2. `basilisk sleigh decode --format pcodedump` output equals `pcodedump`'s for
   the 6.2 streams outside the tolerated differences; the command's help
   text and exit statuses are tested.
3. Tests of 6.3–6.5 pass; fuzz target 60 s clean; no panic on any input.
4. Benchmarks of 6.6 meet their figures; `PERF.md` updated; the M1 lines
   of the plan can be ticked.
5. Gate green on macOS; `cargo check --target x86_64-pc-windows-msvc`
   passes; oracle-free tests pass on all three systems in CI.

## 8. Differences from Ghidra

* Space-id constants are space indices with size 8, on every host.
* A cross-build target is decoded on demand instead of being required in
  a cache.
* Bounds on ops and nesting per instruction (4.4).
* The emitter borrows; no per-op heap objects.

(The implementing track appends.)

Appended by the `sleigh-pcode` track:

* **An instruction without p-code inside a delay slot or a crossbuild** is an
  ordinary `Unimplemented` error with the flow length, naming the innermost
  instruction (its own address and text). Ghidra's `delaySlot` and
  `appendCrossBuild` leave the builder on a dead walker when the nested
  build throws, and `oneInstruction`'s handler then crashes
  (`docs/research/pcodedump-crashes.md`). In basilisk the walker is a value
  scoped to the nested build.
* **The handle of a subtable operand whose constructor exports nothing**
  reads as the constant 0 of size 0 (part 1's unset-handle rule). Ghidra
  reads an uninitialised `FixedHandle`: stale data from an earlier parse in
  a reused parse slot (different p-code: AARCH64 `bfdot`, MIPS `mfhc0`, …),
  or a null space in a fresh one, which crashes `pcodedump` (the five
  ARM v8-m crashes of the decode harness: `vpt…` with `itmode=1`). The
  builder reports `BuildFeature::UnsetHandle` so tools can flag it.
* **No parse cache** (ADR-024): delay-slot instructions are taken from the
  run `prepare` decoded; a delay slot of a delay-slot instruction beyond
  that run is `DelaySlotMissing` ("Could not obtain cached delay slot
  instruction", an error the spec's table did not list), which is what
  `pcodedump`'s sweep gives. Ghidra's 2-entry cache can hand the builder a
  parse that a later lookup overwrote (Toy `harvard_rev`: a delay slot using
  `inst_next2` evicts the branch's own parse); basilisk builds the right
  instruction.
* **`inst_next2` whose instruction does not decode**: the next instruction's
  decode error is kept and raised when a template needs `inst_next2`, as
  Ghidra's `getN2addr` throws it (instead of "inst_next2 not available").
* **A crossbuild target decoded on demand has no `inst_next2`** (only Toy
  uses `inst_next2`, only Hexagon crossbuild).
* **`Decoder::lift_decoded`** lifts the instruction the last `decode`
  produced without decoding it again — the effect Ghidra's parse cache has
  between `printAssembly` and `oneInstruction`, without the cache.
* **Bounds**: 65,536 ops, 512 recursion levels of `BUILD`/delay/crossbuild,
  16 instructions per `DELAY_SLOT` (Ghidra loops forever on a zero-length
  delay-slot instruction), 8 crossbuild targets decoded on demand alive at
  once.
* **`BUILD` in a free-standing template** is a no-op (no operand is a
  subtable); Ghidra dereferences a null constructor.
* **Label numbers are 32 bits, as in Ghidra's C++ engine** (track
  `sleigh-perf-linux`, 2026-11-14): `setLabel` hands the sum of the
  `LABEL` constant and the label base to `PcodeCacher::addLabel(uint4)`,
  and `resolveRelatives` reads `uint4 id = ptr->offset`, so a label number
  2³² + n means label n; Basilisk now does the same
  (`pcode::build::label_number`). The Java engine (`PcodeEmit.setLabel`,
  `PcodeEmitObjects/Packed.resolveRelatives`) casts to a signed `int`: it
  agrees below 2³¹ and throws for numbers in [2³¹, 2³²) after the
  truncation, where the C++ grows its label vector towards 16 GiB. Both
  fail there; Basilisk keeps its bound and returns `MissingLabel`
  ("Reference to non-existant sleigh label") for any truncated number at
  or above `MAX_OPS` (65,536), with no allocation. Tests:
  `pcode_units::label_numbers_are_32_bits`.

## 9. Status

Built by track `sleigh-pcode` (2026-11-14; report `docs/agents/sleigh-pcode.md`).

* **`bk-sleigh`**: `emit` (`PcodeEmit`; `PcodeCollector`, `PcodeCounter`,
  `PcodeRecords`, `write_record`, `write_varnode`), `pcode` (`Decoder::lift`,
  `lift_observed`, `lift_decoded`, `build_template`,
  `build_template_observed`, `InjectContext`, `BuildObserver`,
  `BuildFeature`, `LiftError`, `LiftLimit`; modules `buffer`, `location`,
  `build`, `nested`, `error`), `dump` (`pcodedump`'s sweep and record
  writer, `SweepObserver`). The spec's module names `op`, `labels`,
  `delay`, `crossbuild`, `inject` became `build` (ops, labels, `BUILD`),
  `nested` (delay slots and crossbuild), `buffer` and `pcode/mod.rs`
  (injection).
* **`basilisk sleigh decode`** (`crates/basilisk/src/cmd/disasm.rs`), plus
  `--sla-dir` for a root without compiled files.
* **Differential test**: every record (`I`, `E`, `P`, `U`, `T`) equal to
  `pcodedump`'s for all 175 language pairs; template and feature coverage in
  the snapshot table; three new tolerated kinds, each explained by the
  harness's model of Ghidra (see Differences): unset handles, crossbuild
  targets Ghidra's cache would not hold, parses Ghidra's cache clobbered.
* **`Translate`** completed (`one_instruction`, registers, user ops, spaces,
  float formats, alignment, endianness, unique layout, `set_context_default`,
  `allow_context_set`); `UniqueLayout` and `Language::unique_start`.
  `print_assembly` keeps part 1's two-string form instead of an emitter.
* **Not met**: 8-thread scaling below 6× (report, Gaps).

**Performance on x86-64 Linux** (track `sleigh-perf-linux`, 2026-11-14;
report `docs/agents/sleigh-perf-linux.md`, numbers in `docs/PERF.md`): on
an AMD Zen 4 virtual machine decode + lift is level with the g++-built
reference (median ratio 0.99–1.00 over 11 back-to-back rounds), decode is
11 % ahead and decode + text + lift 18 % ahead; on the M1 Pro decode +
lift is 38 % ahead. The output is unchanged (every differential test
byte-equal to `pcodedump`). The decoder now keeps its own layout of the
decision trees, context changes, exports and leaf expressions
(`language/decide.rs`, `language/tables.rs`), the inner decode functions
fail with a two-byte `decode::fault::Fault`, handles live beside the nodes
(`Parse::handle`; `Node::handle` is gone), and build walks share one
`Consts` per instruction.
