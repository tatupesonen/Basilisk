# SLEIGH runtime, part 3: the language services Java adds (`bk-sleigh`, `bk-language`)

Track `sleigh-language`, after milestone M1's `sleigh-pcode`; needed by M4
(program model: registers) and M5 (flow-following disassembler). Format
of this document: `docs/LOOP.md`.

**State of this spec: draft.** Sections marked **[verified]** were read in
the Java source at the lines cited. Sections marked **[to verify]** name
the Java code that defines the behaviour but were not read line by line;
the coordinator (or a research pass) completes them before the track
starts. Nothing here blocks M1 or M2.

Path abbreviations: `SM/` =
`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`, `SL/` =
`SM/app/plugin/processors/sleigh/`, under `../ghidra`.

## 1. Purpose

Ghidra's C++ engine knows a language as spaces, name ↔ varnode maps and
`Translate`. Its Java side knows more, and the program model, the
disassembler and the listing need that: registers as objects with
parents, bit ranges, groups and flags; values of registers with masks;
the flow type, fall-through and operand classification of an instruction
derived from its p-code templates; p-code emission under per-instruction
overrides; and getting a usable `.sla` when it is missing or stale. C++
has no counterpart, so Java is the specification.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `SL/SleighLanguage.java` | Loading (`decode`, `parseSpaces`), `.pspec` handling (`read`), `loadRegisters`, context register construction, `parse`, `getManualEntry`, `isVolatile`, default symbols |
| `SL/SleighLanguageFile.java`, `SleighLanguageProvider.java`, `ModuleDefinitionsMap.java` | Locating files, staleness, compile-on-demand under a lock |
| `SL/SleighInstructionPrototype.java`, `ConstructState.java`, `ParserWalker.java`, `SleighParserContext.java`, `Constructor.java` | Flow types, fall-through, delay-slot depth, operand types and objects, separators, mnemonic |
| `SL/PcodeEmit.java`, `PcodeEmitObjects.java`, `PcodeEmitPacked.java` | Emission with overrides |
| `SM/program/model/lang/` (`Register`, `RegisterBuilder`, `RegisterManager`, `RegisterValue`, `PcodeOverride`, `InstructionPrototype`, `OperandType`, `InstructionContext`) | The model types |
| `SM/program/model/symbol/` (`FlowType`, `RefType`), `SM/program/model/listing/FlowOverride.java` | Flow vocabulary |

## 3. Scope

**In.** In **`bk-sleigh`**: modules `register` (register model built from
a `Language` and its `.pspec`), `prototype` (instruction information
derived from a `Parse`), `override` (the override interface and its
application during emission). New crate **`bk-language`**: the language
service — find a language in the `bk_lang` registry, make sure its `.sla`
exists and is current (compiling with `bk-sleigh-compiler` when not),
load it once and share it.

**Not in.** Instructions stored in a program, references, the
disassembler's flow following and context propagation
(`DisassemblerContextImpl`, `ProgramContext`): M4/M5. The assembler.
`.cspec`. P-code text formatting for the listing (`PcodeFormatter`): with
the listing.

## 4. Behaviour

### 4.1 Language loading beyond part 1 [verified: `SleighLanguage.java` 123–206, 470–498, 846–1001]
* A language's `.slaspec` must exist even when a `.sla` does (146–148).
* Endianness: the load fails if the `.sla`'s endianness differs from the
  `.ldefs`'s **and** the instruction endianness equals the `.ldefs`'s
  (879–885) — the escape is for languages whose instructions and data
  differ in endianness.
* Spaces: `space` with `delay > 0` is a RAM-type space, with `delay == 0`
  a register-type space; `space_other` must be present; `<truncate_space>`
  applies only to RAM-type spaces, must be positive and strictly smaller
  than the original size, and an entry that matches no space is an error
  (958–994). A space named by the `.pspec`'s `<segmented_address>` becomes
  a segmented space (964–975).
* `parse` (the entry to decoding) rejects an address not aligned to
  `align` (381–386) and a delay-slot instruction that itself has delay
  slots (`NestedDelaySlotException`).

### 4.2 Registers [verified: `SleighLanguage.java` 1009–1086, `RegisterBuilder.java` 47–162, `RegisterManager.java` 96–135]
* Every varnode symbol in a register-type or RAM-type space is a
  register (RAM-type: the space is flagged as having mapped registers).
* Every context symbol is a bit-field register at its context varnode's
  address: `leastSigBit = varnode bits − endbit − 1`, `bitLength = endbit
  − startbit + 1`, always big-endian, flag `TYPE_CONTEXT`, plus
  `TYPE_DOES_NOT_FOLLOW_FLOW` for `noflow` fields. A varnode-list symbol
  over a context field is registered the same way.
* Adding a register with the same address, least significant bit and bit
  length as an existing one makes it an alias. Names are also findable in
  all-lower and all-upper case.
* Parents and children are computed by ascending bit size; a base
  register is one without a parent. The context base register is the base
  register carrying `TYPE_CONTEXT` (the flag propagates to parents); none
  → "no context".
* `.pspec` `<register_data>`: `rename`, `alias`, `group`, `hidden`,
  `volatile`, `vector_lane_sizes` (656–711); `<programcounter>` sets
  `TYPE_PC`.
* `RegisterValue` (value and mask, both as wide as the base register;
  assignment, combination, extraction of a child's value; left-justified
  bytes for context registers) [to verify: `RegisterValue.java`; pinned
  by `RegisterValueTest` and `RegisterValueContextTest`].

### 4.3 `.pspec` beyond `<context_data>` [verified: `SleighLanguage.java` 554–834]
`<context_set>` requires a context register and `<tracked_set>` a
non-context one ("Bad register name" otherwise); a value that does not
parse is silently 0 (599–610). `<volatile>` ranges (a `<register>` child
is rejected in Java although the decompiler reads it); `<default_symbols>`
with `address="next"` and a three-valued `volatile`;
`<default_memory_blocks>`; `<data_space>`; `<jumpassist>` and `<segmentop>`
create injection payloads (compiled by `bk-sleigh-snippet`); unknown
elements are logged, not fatal (829–834). `isVolatile(addr)` combines the
ranges with per-symbol overrides [to verify the precedence; pinned by
`SleighLanguageVolatilityTest`].

### 4.4 Instruction information [verified: `SleighInstructionPrototype.java` 130–141, 201–393, 443–636, 725–737, 884–886, 1002–1038, 1335–1352]
* **Flow** is computed from the templates of the whole constructor tree
  (`walkTemplates`): each `BRANCH`, `CBRANCH`, `BRANCHIND`, `CALL`,
  `CALLIND`, `RETURN` contributes flags; `BRANCH` to `inst_next` is
  "branch to end", to `inst_start` or a label "no fall-through" only,
  otherwise "jump out, no fall-through"; `CBRANCH` likewise without
  "no fall-through"; any `inst_next2` input sets "has next2".
  `flowListToFlowType` combines the records and `convertFlowFlags` maps a
  flag set to a `FlowType` through a fixed table (332–393; unlisted sets
  are `INVALID`). With crossbuilds the flow is computed per instance.
* **Fall-through offset** = length plus delay-slot instructions until the
  delay byte count is covered; on any failure, the plain length (574–598).
  Delay-slot depth is 1 when the byte count is 1 without parsing (470–472).
* **Operands shown** are those of the "mnemonic constructor": follow the
  flow-through operand down from the root. **Operand type** (503–558):
  invalid handle → dynamic; static in a register space → register;
  constant → scalar; flagged `code` → address|code; RAM → address|data;
  else dynamic; plus *indirect* when the mnemonic constructor's own
  `CALLIND`/`BRANCHIND` goes through that operand.
* **Mnemonic**: as part 1, prefixed with `_` when the instruction is
  being shown in a delay slot; "UNKNOWN" on failure. Separators between
  operands come from the literal print pieces
  (`Constructor.printSeparator`) [to verify: `Constructor.java` — the
  exact rule for which literal belongs to which operand, and
  `getOpObjects`].
* A prototype is shared by all instructions with the same constructor
  tree (hash of the root state, +0xFABFAB in a delay slot; equality trusts
  the hash, 421–427, 1425–1428). basilisk need not share prototypes this
  way, but must not let two different trees be confused.

### 4.5 Emission under overrides [verified: `PcodeEmit.java` 76–121, 183–260, 770–894; to verify: 259–410]
`PcodeOverride` supplies, per instruction: a flow override (`BRANCH`,
`CALL`, `CALL_RETURN`, `RETURN`), a fall-through override address,
overriding references (call, jump, `CALLOTHER`→call, `CALLOTHER`→jump),
the primary call reference, and whether a destination has a call fix-up.

* Flow override, applied to the first qualifying op only: `BRANCH` turns
  `CALL` into `BRANCH` and `CALLIND`/`RETURN` into `BRANCHIND`; `CALL`
  turns `BRANCH` (not to a label or `inst_start`/`inst_next`/`inst_next2`)
  into `CALL`, and `BRANCHIND`/`RETURN` into `CALLIND`; `CALL_RETURN` does
  the same and appends `RETURN` of constant 0; `RETURN` and the `CBRANCH`
  cases: [to verify, 259–410].
* `checkOverrides`, per emitted op, in this order: `CALLIND` + an
  unconditional call-override reference → `CALL` to it; `CALLOTHER` + a
  `CALLOTHER` call or jump override → `CALL`/`BRANCH` to it; `CALL`
  without a call fix-up + a primary call reference that differs from the
  destination (or an overriding reference) → `CALL` to it; fall-through
  override: a `BRANCH`/`CBRANCH` whose destination is the default
  fall-through address is redirected; `BRANCH`/`CBRANCH` to an address +
  an unconditional jump override → `BRANCH` to it. Each kind applies once
  per instruction.
* After the last op, a fall-through override appends `BRANCH` to it
  (`resolveFinalFallthrough`), except inside a delay slot.
* Java resolves constants in the constant space with a mask for sizes up
  to 8, as C++; a failed emission yields a single `UNIMPLEMENTED` op
  rather than an error (1002–1038).

### 4.6 The language service (`bk-language`) [verified: `SleighLanguageFile.java` 124–189, 315–429, 498–505]
* A `.sla` needs compiling when it is missing, when its header version is
  not 4, or when it is older than its `.slaspec` or any file that includes
  (a preprocessor scan for the newest timestamp; a scan failure forces
  compilation).
* Compile options come from the module's `data/sleighArgs.txt` (release)
  or `build/tmp/sleighArgs.txt` (development), else defaults; `BaseDir` is
  always defined as the installation root with a trailing separator.
* The output is written to `<name>.sla.<pid>.tmp` and renamed over the
  target (delete-then-rename as a fallback).
* Compilation happens under a cross-process lock on the language; when the
  lock cannot be taken (read-only installation) the existing `.sla` is
  used as it is. `SleighLanguageProviderTest` pins the lock behaviour.
* **Platforms (ADR-022):** timestamps, atomic replace and the lock file
  must work on Windows, macOS and Linux — use `std::fs` and a lock crate
  that passes ADR-011 (candidates: `fs4`, `fd-lock`; check Windows
  semantics for replacing a file another process has open). Read-only
  detection must not rely on Unix permission bits.

## 5. Design (outline)

`Register`s live in one arena inside `RegisterTable` (typed `RegisterId`;
parent, children range, base, bit range, flags, group, lane sizes, aliases);
`RegisterValue` owns two small byte buffers. Instruction information is
computed on demand from a `Parse` plus the language, with per-constructor
flow summaries precomputed at load so the common case (no crossbuild) is
a table lookup — this is the disassembler's hot path, so it gets the
same no-allocation rule and a benchmark. Overrides are a trait the
emitter consults (`None` costs nothing). `bk-language` holds a
`LanguageService` with a concurrent map of loaded `Arc<Language>`.

## 6. Tests to port

From `docs/inventory/tests/` (checklist lines quoted):

| Checklist line | Needs | When |
|---|---|---|
| `framework-softwaremodeling.md`: `ghidra.program.model.lang.RegisterManagerTest` (unit, 3 tests) | register model only | this track |
| `test-integrationtest.md`: `ghidra.program.model.lang.RegisterValueTest` (slow, 4 tests) | x86 32-bit language, no program | this track |
| `test-integrationtest.md`: `ghidra.program.model.lang.RegisterValueContextTest` (slow, 4 tests) | same, context base register | this track |
| `framework-softwaremodeling.md`: `ghidra.app.plugin.processors.sleigh.SleighLanguageVolatilityTest` (unit, 5 tests) | avr8 language, temporary `.pspec`/`.ldefs` | this track |
| `framework-softwaremodeling.md`: `ghidra.app.plugin.processors.sleigh.SleighLanguageProviderTest` (slow, 4 tests) | compiler, lock, child processes | this track (after M2); two cases are Unix-permission tests — port the behaviour, state the Windows equivalent |
| `framework-softwaremodeling.md`: `ghidra.program.model.pcode.VarnodeTest` (unit, 2 tests) | address spaces only | belongs with `bk-core`'s varnode type; port here if still open |
| `test-integrationtest.md`: `ghidra.program.model.lang.VectorRegisterPspecTest` (6 tests) | six languages; uses `ProgramBuilder` only to obtain them | this track, loading the languages directly |
| `test-integrationtest.md`: `PcodeEmitContextTest` (16), `PcodeEmitContextCrossBuildTest` (11) | a `Program` with references and overrides (Toy, Hexagon) | M5; the override logic itself gets derived tests here |
| `framework-softwaremodeling.md`: `ghidra.program.model.lang.InstructionSetTest` (unit, 4 tests) | instruction blocks | `bk-disasm` (M5) |

[to verify] Whether Ghidra has tests of flow types and operand types that
need no program (none was found by class name:
`SleighInstructionPrototype`, `ParserWalker`, `ContextCache`,
`ConstructState` have no test classes in the inventory).

**Differential check (this track must add it):** Ghidra's C++ tools do
not expose flow or operand types, so the oracle is full Ghidra
(`GHIDRA_INSTALL_DIR`, ADR-007): a headless script dumps, for the
directed samples of `sleigh-decode` §6.2 in a handful of languages,
each instruction's flow type, fall-through, operand types and operand
representation; basilisk must agree. Without an installation the test
skips; a checked-in snapshot of that dump keeps CI meaningful.

## 7. Acceptance (to be finalised with the [to verify] items)

1. The tests of the table marked "this track" are ported and marked.
2. The differential dump agrees for every sampled instruction.
3. Register tables for all languages build without error and are
   snapshot-tested for x86-64, ARM, AARCH64, MIPS, PowerPC.
4. Compile-on-demand works on the three systems; two processes asking for
   the same stale language produce one valid `.sla` (ported
   "thundering herd" test).
5. Flow information per instruction costs no allocation; benchmark
   recorded.

## 8. Differences from Ghidra

(To be written by the track.) Known in advance: emission failure is a
typed error, with the single `UNIMPLEMENTED` op available as a
convenience for listings.

## 9. Status

Draft specification; not started.
