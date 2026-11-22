# Track `spec-decomp-typeop` — status report

Specification track. Finishes wave 3 of the decompiler specifications:
(1) D08 `decomp-typeop` (`docs/features/decomp-typeop.md`, crate
`bk-decomp-typeop`), (2) the parts of D07 (`docs/features/decomp-core.md`)
that the previous track left "to be specified". Writes no product code.
**Stopped on the coordinator's instruction (the machine was shut down)
right after the first full draft of the D08 document was written. Task 2
was not started.**

## State and how to continue

### Task 1 — `docs/features/decomp-typeop.md` (D08)

All sections are present (1 to 11: the nine of `LOOP.md`, an
implementation plan, open items). The text was written in one pass and
**was not re-read after writing**: the next agent should proof-read it
once against the notes below before the coordinator reviews it.

- **Complete, read line by line from the source, and pinned by the
  oracle prototype on both reference builds**: 4.1 (the table, the Java
  variant, boolean flip), 4.3 (local types), 4.4 (output token), 4.5
  (input cast), 4.6 (propagation), 4.7 (names and helpers), 4.8 (cast
  strategies), 4.11 (union scoring, as far as the prototype's shapes
  reach).
- **Complete, read line by line, not run** (read-only): 4.2
  (`local_type`, the facing types), 4.9 (the union map and its nine
  methods), 4.10 (resolution in flow: the `type.cc` methods), 4.12
  (`ResolveCache`); the deeper parts of 4.11 (limits of 6 passes and
  1,024 trials, second-level continuation).
- **Designs of this track, no Ghidra counterpart**: 3.3 (`TypeOpEnv`),
  4.13 (access table: derived from the IR by `rebuild`), 4.14 (units:
  73 `typeprop.<opcode>` and `unionscore`), section 5 (modules, API,
  layout), 6 (tests), 7, 10 (nine steps T1 to T9).
- **Known weak spot to check first**: in 4.11, the paragraph on
  `INT_ADD`/`INT_SUB`/`PTRSUB` down trials has a muddled parenthesis
  about `max_length`. The source (`unionresolve.cc:480–543`) says: with
  a constant other operand, if the trial's `maxLength ≠ 0` and the
  offset is outside `0 ≤ off < maxLength`, score −1 and stop; otherwise
  walk `downChain` until the offset is 0; if a pointer remains, score
  +5, continue with it and `maxLength = size of its target`. Rewrite
  the parenthesis to say just that.
- Not verified: the row counts quoted in 6.2 are the prototype's (X8);
  the statement "about 0.8 MB each" is the measured gzip size.

### The oracle prototype

`docs/research/decomp-wave3/typeop_oracle.cc` (committed; throw-away).
It builds with `sh docs/research/decomp-wave3/build.sh REF
docs/research/decomp-wave3/typeop_oracle.cc OUT`. Scratch build and
outputs: `target/typeop-oracle/` in this worktree (not committed).
Result (`runs.md`, X8): 186,945 rows for `x86:LE:64:default:gcc`,
185,208 for `x86:LE:16:Real Mode:default`, 191,186 for
`PowerPC:BE:32:default:default`; two runs identical on the Mac; **also
run on the build host through `scripts/remote.sh run`, twice each: all
three outputs byte-identical to the Mac's** (sha256 prefixes
`110d0ef8f9e6ce31`, `5df62f6d0a448bd4`, `9e65aee73ddf2b02`).
`runs.md` X8 still ends with "Not run on the build host in this track
unless a later entry says so": **that line is out of date and must be
replaced by the result above.** Gaps of the prototype are listed in X8
and in the spec's 6.2 (additions (a) to (h)).

### Task 2 — `docs/features/decomp-core.md` (D07 open parts)

**Not started.** Nothing of 4.A.6, 4.A.10, 4.A.11, 4.A.14 or part C was
read or written. One amendment follows from Task 1 and is not yet made
in that file: 4.A.10's `AccessTable` row should say the type is D08's
(core is above typeop) and core holds one per function.

### What the next agent does first

1. Proof-read `decomp-typeop.md` (fix the 4.11 paragraph; check the
   cross-references 6.2/6.3/8 against section 4).
2. Fix the last line of `runs.md` X8 (build-host result).
3. Complete the lists below in this report if anything is added.
4. Start Task 2 in the order 4.A.6 (`fspec.cc` 2968–3300,
   `ProtoStoreSymbol`; say exactly what `bk-cspec` must change), 4.A.10,
   4.A.11 (`variable.cc` 220–560), 4.A.14, part C.

## Misfits (each needs a decision or a change elsewhere)

1. **Nobody owns `TypeOp::getBooleanFlip`.** D05's `OpProps` has no
   complementary opcode; users are D07c, R3, D16b. Eleven opcodes have
   one (`typeop.cc` 930, 995, 1023, 1060, 1097, 1122, 1763, 1796, 1815,
   1834, 1853). Proposed and specified: D08 owns `boolean_flip(opc)`;
   no change to D05.
2. **`Varnode::getTempType` has no home.** `typeop.cc:1336` reads it;
   D05 has no such field. Proposed and specified: D08 defines
   `TempTypes`, owned by D11's `ActionInferTypes` and passed to
   `propagate_type`. No change to D05.
3. **D05's `UnitKind` has no kind for a propagation policy**
   (`Action`, `Rule`, `MergePass`, `StructureStep`, `OutputPass`).
   The plan makes each opcode's propagation policy a unit. Needed:
   `UnitKind::TypePolicy` in `bk-decomp-ir` (one variant).
4. **`AccessTable`'s type cannot be core's** (`decomp-core.md` 4.A.10):
   D08 fills it and is below core. Specified: D08 defines `AccessTable`
   and `AccessRow`; core holds one per function.
5. `TypeOpEnv` differs from the outline's sketch: the user-op methods
   take `&mut TypeFactory` (a volatile read's type is `getExactPiece`,
   `database.cc:137–143`); `default_data_space` is dropped (D02's
   `TypeEnv::data_space` has it); `float_format` is added
   (`unionresolve.cc:997`); `userop_name` writes into a `fmt::Write`.
   Core's step A9 implements this form.

## Proposed ADRs (letters; the coordinator numbers them)

**A. D08 owns the boolean-flip table and the temporary-type table;
D08 defines the access table.** Misfits 1, 2, 4.

**B. Where Ghidra's type-operator code crashes or reads unset memory,
Basilisk defines the result; where it is only odd, the `ghidra` profile
reproduces it** (ADR-063's form). Defined: D-1 to D-6 of the spec's
section 8. Reproduced: R-1 to R-7 there.

**C. The union map's key is Ghidra's**: `(64-bit type id, encoding,
op time or low 32 bits of an address)`, including its collisions,
because the state dump's `U` records and every lookup depend on it.

**D. A propagation policy is a unit that a profile selects, not one it
places** (`typeprop.<opcode>`, `unionscore`; `UnitKind::TypePolicy`).

## Proposed amendments to `decomp-plan.md`

- Section 8, row 3e: the access table's type is D08's, held by core;
  it is rebuilt from the IR at the end of each `ActionInferTypes` run
  (D11) rather than filled incrementally.
- D08's row: needs D02, D03, D05, D06 (already in section 13); owns
  `getBooleanFlip`, `Varnode::getLocalType` and the four facing-type
  methods of `Varnode`.

## Defects found in Ghidra (all by reading; none reproduced by a run)

Paths under `CPP/`.

1. `TypeOpCallother::getInputLocal`/`getOutputLocal`
   (`typeop.cc:858–859`, `868–869`) call the user op without a null
   test; `getOperatorName` (845) tests. A `CALLOTHER` with an
   unregistered index crashes during type propagation.
2. `ResolveEdge` (`unionresolve.cc:103–129`): the address-based form
   stores `addr.getOffset()` in a 32-bit `uintm` and ignores the space
   and the slot; anonymous types (id 0) share keys.
3. `TypeUnion::resolveInFlow` (`type.cc:2489–2493`) builds a new
   `ResolvedUnion` from the address-based record but stores the old
   record (`*res`) for the edge; `TypePointer::resolveInFlow` (1237)
   stores the new one.
4. `Varnode::getTypeDefFacing`/`getHighTypeDefFacing`
   (`varnode.cc:663`, `689`) pass a null `def` to `findResolve` for an
   unwritten varnode whose type needs resolution;
   `CastStrategyC::intPromotionType` (`cast.cc:185`) passes
   `loneDescend()`, which is null for a constant without exactly one
   reader.
5. `Varnode`'s constructor does not initialise `temp`
   (`varnode.cc`, the constructor); `propagateAddPointer`
   (`typeop.cc:1336`) reads it. Unreachable today.
6. `TypeOpIndirect::getInputLocal` (`typeop.cc:2141`) sizes the code
   pointer of input 1 by input 0.
7. `TypeOpCall::getInputLocal` tests the parameter's size (707),
   `TypeOpCallind::getInputLocal` does not (764).
8. `TypeOpIntAdd::propagateAddIn2Out`'s comment (1229–1240) says the
   output's current type is returned to refuse an edge; the code
   returns null.
9. `get_opname` (`opcodes.cc`) names `MULTIEQUAL`, `INDIRECT`, `PTRADD`,
   `PTRSUB` by their SLEIGH aliases `BUILD`, `DELAY_SLOT`, `LABEL`,
   `CROSSBUILD` (seen in the oracle's first output).

## Open questions for the owner

1. Should the `ghidra` profile reproduce the union map's key collisions
   (ADR C says yes)?
2. Is "selected, not placed" acceptable for policy units (ADR D), or
   should propagation policies not be units at all?

## What was run, and where

`runs.md` X8 (plus the build-host result stated above). No gate run:
documents and a prototype source outside the workspace.

## Not done, plainly

Task 2 entirely. The `arch` oracle (test A-2 of `decomp-core.md`). A
proof-read of the D08 document. No union-resolution run on real
functions (6.3 is a specification). The prototype does not exercise the
union map's methods, `resolveInFlow`, `ResolveCache` or `getLocalType`.

## Commits

`git log --oneline master..spec-decomp-typeop`.
