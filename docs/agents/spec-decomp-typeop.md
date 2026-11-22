# Track `spec-decomp-typeop` — status report

Specification track. Finishes wave 3 of the decompiler specifications:
(1) D08 `decomp-typeop` (`docs/features/decomp-typeop.md`, crate
`bk-decomp-typeop`), (2) the parts of D07 (`docs/features/decomp-core.md`)
that the previous track left "to be specified". Writes no product code.
**In progress.**

## State and how to continue

Kept current in every commit.

- [x] Read: RULES, LOOP, DIRECTION, the ADRs named in the brief, the plan
      with sections 11 to 13, the wave-3 report, the D08 outline, D02's
      and D05's boundary sections, the merged `bk-decomp-types` and
      `bk-cspec` APIs, D05's API on branch `decomp-ir`.
- [x] Read to the standard (every line): `typeop.cc`, `typeop.hh`,
      `cast.cc`, `cast.hh`, `unionresolve.cc`, `unionresolve.hh`, the
      IR-bound methods of `type.cc` (lines in the spec, section 2),
      `funcdata.cc` 917–1117, `varnode.cc` 658–704, `testtypes.cc`
      20–214, `coreaction.cc` 5470–5510 (the one caller of
      `propagateType` in type inference), `architecture.cc` 410–433 and
      612–616.
- [ ] `docs/features/decomp-typeop.md`: **being written** (the outline of
      the previous track is still what is on the branch).
- [ ] The D08 oracle prototype (`typeop_oracle.cc`): not started.
- [ ] Task 2 (D07's open parts): not started.

Next, in order: write D08 sections 1 to 5; prototype the oracle and run
it; write sections 6 to 10; then Task 2 in the order 4.A.6, 4.A.10,
4.A.11, 4.A.14, part C.

## Misfits found so far (told early)

1. **Nobody owns `TypeOp::getBooleanFlip`.** The D08 outline gives the
   "boolean flip" to D05's table; D05's `OpProps` (branch `decomp-ir`,
   `crates/bk-decomp-ir/src/props.rs`) has `flags`, `addl`, `name`,
   `form` and no complementary opcode. Users are D07c
   (`funcdata_op.cc:1264`, `1306`; `expression.cc:206`), R3
   (`ruleaction.cc:5472`) and D16b (`printc.cc:2476`). The table is ten
   opcode pairs set in the `TypeOp` constructors (`typeop.cc` 930, 995,
   1023, 1060, 1097, 1122, 1763, 1796, 1815, 1834, 1853). **Proposed:
   D08 owns it** (`boolean_flip(opc) -> Option<OpCode>`, a constant
   function, with `isBooleanFlipReorder` read from D05's `addl` bit).
   No change to D05.
2. **`Varnode::getTempType` has no home.** `typeop.cc:1336`
   (`TypeOpIntAdd::propagateAddPointer`) reads the temporary type of the
   other operand of an `INT_ADD`. It is a member of `Varnode`
   (`varnode.hh:152–155`, a union shared with the value-set pointer),
   written only by `ActionInferTypes` (`coreaction.cc` 5432, 5507, 5649,
   5764). D05 has no such field. **Proposed: D08 defines `TempTypes`**, a
   dense table from `VarnodeId` to `TypeId` that the caller of
   `propagate_type` owns (D11's `ActionInferTypes`) and passes in. No
   change to D05.

## Proposed ADRs, plan amendments, Ghidra defects, open questions

Collected at the end of Task 1 (below, when written).

## Commits

`git log --oneline master..spec-decomp-typeop`.
