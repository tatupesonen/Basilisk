# Circle ranges (`bk-decomp-range`)

Track `decomp-range` (D01 of `docs/features/decomp-plan.md`), milestone
M3, wave 1. Format of this document: `docs/LOOP.md`, "Feature documents".
Leaf track: it depends on no other decompiler crate and on no pending
design decision.

Path abbreviations: `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/`, `UT/` =
`…/decompile/unittests/`, under `../ghidra`.

## 1. Purpose

A `CircleRange` is a set of integers modulo 2ⁿ described as a half-open
interval `[left, right)` on the circle with a step: the values a variable
may take. The decompiler pulls such ranges back through operations (from a
branch condition to the variable it constrains) and pushes them forward
(from inputs to an output). Jump-table recovery, value-set analysis, the
range-merging rules and heritage's guard logic are built on it. This track
ports the class and nothing above it.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/rangeutil.hh`, class `CircleRange` (lines 49–106) and the inline `operator==` and `encodeRangeOverlaps` at the end | The interface and the overlap classification |
| `CPP/rangeutil.cc` lines 21–1,490 | Every `CircleRange` method. **Authoritative** |
| `UT/testcirclerange.cc` | 117 tests and the brute-force model they compare against |
| `CPP/address.cc` (`calc_mask`, `sign_extend`, `count_leading_zeros`, `leastsigbit_set`, `mostsigbit_set`, `bit_transitions`) | Already in `bk_core::bits` |
| `CPP/opbehavior.cc` | Already in `bk_pcode::behavior` (the tests use it as the model) |

There is no Java twin of this class.

## 3. Scope

**In:** `CircleRange` with every method of the header **except**
`pullBack(PcodeOp *, Varnode **, bool)`: construction (empty, explicit
bounds with size and step, boolean, single value), `setRange` (two
forms), `setFull`, `isEmpty`, `isFull`, `isSingle`, `getMin`, `getMax`,
`getEnd`, `getMask`, `getSize`, `getStep`, `getMaxInfo`, equality,
`getNext`, `contains` (range and value), `intersect`, `setNZMask`,
`circleUnion`, `minimalContainer`, `invert`, `setStride`,
`pullBackUnary`, `pullBackBinary`, `pushForwardUnary`,
`pushForwardBinary`, `pushForwardTrinary`, `widen`, `translate2Op`,
`printRaw`; and the private helpers they use (`normalize`, `complement`,
`convertToBoolean`, `newStride`, `newDomain`, `encodeRangeOverlaps` with
the `arrange` table).

**Crate owned:** `bk-decomp-range`. Dependencies: `bk-core` (bit helpers)
and `bk-pcode` (`OpCode`; the op behaviours as a dev-dependency for the
test model).

**Not in this track:** `CircleRange::pullBack(PcodeOp*, …)` — the 70-line
wrapper that reads operand sizes and the constant from an op and then
calls `pullBackUnary`/`pullBackBinary`; it arrives with the IR (D13).
`ValueSet`, `ValueSetRead`, `Partition`, `Widener*`, `ValueSetSolver` (the
rest of `rangeutil.cc`): D13.

## 4. Behaviour

Port `rangeutil.cc` 21–1,490 exactly. The points below are where a port
goes wrong; they are from reading the source and each is pinned by the
oracle table of section 6.

### 4.1 Representation
Five fields: `left`, `right` (64-bit), `mask` (2ⁿ−1 for a size of n/8
bytes, from `calc_mask(size)`), `isempty`, and `step` (a signed 32-bit
count; always a power of two in practice, and the low bits of `left` and
`right` agree modulo `step`). The set is `left, left+step, …` up to but
not including `right`, modulo `mask+1`. `left == right` (non-empty) means
**every** value congruent to `left` modulo `step` — the full set when
`step` is 1.

* The default constructor makes an **empty** range and leaves the other
  fields unset in C++. In Rust they are zero (with `step` 1); no method
  may behave differently for an empty range because of them. Where Ghidra
  reads those fields of an empty range the result in C++ is undefined;
  record each such place under "Differences from Ghidra".
* `CircleRange(lft, rgt, size, step)` masks both bounds and does **not**
  normalise or validate; `CircleRange(val, size)` does **not** mask
  `val`; `CircleRange(bool)` uses a mask of `0xff` (size 1) whatever the
  caller's varnode size.
* `normalize` only touches full sets (`left == right`): it reduces `left`
  to `left % step` (0 when `step` is 1). Equality compares the four fields
  after the `isempty` check, so two descriptions of the same set that are
  not normalised compare unequal — keep that; callers rely on the methods
  normalising where Ghidra does.
* `getSize` returns the number of elements, except for a full 8-byte set,
  where the count does not fit and Ghidra returns `mask` (or
  `mask/step + 1`) — "we lie by one". Keep the lie.
* `getMaxInfo`, `getMax`, `getNext`, `isSingle` as written; `getNext`
  wraps with the mask and reports whether the end was reached.

### 4.2 Set operations
* `intersect` and `circleUnion` return 0 when the result is valid and 2
  when it would be two pieces; Ghidra's comments state that the receiver
  is not modified when the result is not 0 — check that claim against the
  oracle table rather than trusting it. Both classify the relative position of the two intervals
  with `encodeRangeOverlaps` — six comparisons packed into an index into
  the 64-character string `arrange` — and switch on the letter `a`–`g`.
  Copy the string exactly:
  `gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda`.
* Steps: `intersect` handles different steps by refining to the larger
  step when one stride is a subset of the other (`newStride`) and fails
  otherwise; `circleUnion` requires equal steps except for the
  single-element special cases. `minimalContainer(op2, maxStep)` always
  produces a range containing both (possibly more than the union, with as
  few added values as it can; two single values a power of two apart, at
  most `maxStep`, give a stepped range) and returns **true when the
  container is everything**.
* `contains(range)` has the documented gap ("Missing one case where
  op2.step > this->step…"): reproduce the result the code gives, not the
  mathematically complete one.
* `invert` sets the step to 1, complements the set and returns the
  original step. `setNZMask(nzmask, size)` sets the range to the values
  whose non-zero bits lie within a mask (step from the trailing zero
  bits, `left` 0, `right` just past the mask) and returns false, leaving
  the range unmodified, when the value is not usable as a mask.
* `setStride(newStep, rem)`, `widen(op2, leftIsStable)` and
  `translate2Op` (turn a range into `x < c`, `c <= x`, `x == c`, `x != c`
  and friends: returns 0 with an opcode, constant and slot, or 2 when the
  range is not one comparison) as written.

### 4.3 Pull-back and push-forward
* `pullBackUnary(opc, inSize, outSize)`: the set of inputs whose image
  under a unary op lies in the range, for exactly `BOOL_NEGATE`, `COPY`,
  `INT_2COMP`, `INT_NEGATE`, `INT_ZEXT`, `INT_SEXT`; false when the pre-image is not one circle range or the op is not
  handled. The extension cases change the mask to the input size and must
  handle ranges that cross the sign boundary.
* `pullBackBinary(opc, val, slot, inSize, outSize)`: same, for an op whose
  other operand is the constant `val` in the other slot, for exactly
  `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_LESSEQUAL`, `INT_SLESS`,
  `INT_SLESSEQUAL`, `INT_CARRY` (the comparisons start from the boolean
  form of the range, `convertToBoolean`), `INT_ADD`, `INT_SUB` (the slot
  matters), `INT_RIGHT`, `INT_SRIGHT`.
* Push-forward — the image of ranges under an op, over-approximated to
  one circle range, false when nothing useful can be said.
  `pushForwardUnary` handles exactly `CAST`, `COPY`, `INT_ZEXT`,
  `INT_SEXT`, `INT_2COMP`, `INT_NEGATE`, `BOOL_NEGATE`, `FLOAT_NAN`;
  `pushForwardBinary(…, maxStep)` handles `PTRSUB`, `INT_ADD`,
  `INT_MULT`, `INT_LEFT`, `SUBPIECE`, `INT_RIGHT`, `INT_SRIGHT`, the six
  integer comparisons, `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`,
  `BOOL_XOR`, `BOOL_AND`, `BOOL_OR` and the four float comparisons;
  `pushForwardTrinary` handles only `PTRADD`, as `in1 + in2 * in3` through
  the binary cases. Multiplication and left shift introduce steps bounded
  by `maxStep`; `SUBPIECE` and the extensions change the domain
  (`newDomain`).
* All arithmetic is on `u64` with explicit masking; several places shift
  by a computed amount that can reach 64, or negate `step`. C++ leaves
  those undefined or implementation-defined; the oracle table records
  what the x86-64 build does, and the Rust code computes that value
  explicitly (wrapping operations, `checked_shl` with the Ghidra result
  for the out-of-range case). List each under "Differences" only if the
  two reference hosts disagree.

### 4.4 Text
`printRaw`: `(empty)`; `(full)` or `(full,<step>)`; `[<hex left>]` for a
single value; otherwise `[<hex left>,<hex right>)` with `,<step>` (decimal)
before the parenthesis when the step is not 1. Hex without `0x`, lower
case. Offer it as `Display`.

## 5. Design

* One `Copy` struct, `CircleRange { left: u64, right: u64, mask: u64,
  step: u32 or i32, empty: bool }`; assert `size_of` ≤ 32 bytes in a test.
  Methods mutate in place where Ghidra's do and return a small result
  enum instead of `0`/`2`/`bool` where the integer has distinct meanings
  (`intersect`, `circleUnion`, `translate2Op`); keep a doc comment naming
  the Ghidra method and its return code on each.
* No allocation anywhere; every method is `O(1)` apart from the bounded
  loops Ghidra has. Inputs are untrusted in the sense of ADR-009: sizes
  outside 1–8, steps of 0 or negative, shift amounts ≥ 64 must not panic
  or divide by zero; return the "cannot represent" result.
* Modules: `range` (representation, queries, text), `setops`
  (`contains`, `intersect`, `circleUnion`, `minimalContainer`, `invert`,
  `setNZMask`, strides), `pull` (pull-back), `push` (push-forward),
  `compare` (`translate2Op`, `convertToBoolean`). Each well under 600
  lines.
* ADR-011: no existing crate implements wrapped (circular) strided
  intervals with these exact approximations; interval crates
  (`intervallum`, `ranges`, `iset`) model linear intervals. Written here
  because the approximations *are* the behaviour.

## 6. Tests

Kinds per `decomp-plan.md` 4.5: **S** runs everywhere from the
repository; **L** needs the live reference tools.

1. **Port `UT/testcirclerange.cc`** (S): all 117 cases, table-driven
   (`rstest`), with the test file's brute-force model ported as a test
   helper — enumerate the range's elements, push each through
   `bk_pcode::behavior::evaluate_unary`/`evaluate_binary` or pull back
   with `recover_input_unary`/`recover_input_binary` (an evaluation error
   means "not in range"), then re-describe the element set as
   start/stop/step with the helper `getStartStopStep` exactly as the C++
   test does. The Ghidra test builds an `Architecture` only to reach the
   op behaviours; nothing else of it is needed. Mark
   `unittests/testcirclerange.cc` in
   `docs/inventory/tests/decompiler-cpp.md`.
2. **Oracle table** (S replay, L regeneration): a C++ program under
   `crates/bk-decomp-range/tests/oracle/`, compiled against
   `rangeutil.cc`'s object from the reference build as `bk-pcode`'s oracle
   is, that prints one line per case with the inputs and the complete
   result (return value and all five fields, plus `printRaw`):
   * every method that takes one range, over **all** 1-byte ranges with
     steps 1, 2, 4 and 8 whose bounds are aligned to the step (about
     12,000 ranges), and for `pullBackUnary`/`pushForwardUnary` every
     handled opcode and each input/output size pair from {1, 2, 4, 8};
   * every method that takes two ranges, over all pairs of a 300-range
     sample of that set and a further 200,000 pseudo-random pairs at
     sizes 2, 4 and 8 (fixed seed; include full, empty, single-value,
     wrapping and sign-crossing ranges on purpose);
   * `pullBackBinary` for every handled opcode, both slots, constants
     {0, 1, 2, 7, 8, 0x7f, 0x80, 0xff, and the size's analogues};
   * `translate2Op`, `setNZMask`, `getSize`, `getMaxInfo`, `setStride`,
     `widen`, `minimalContainer` over the single-range set.
   The table is gzip-compressed and checked in with its `regen.sh`; the
   Rust test replays every row. Rows that depend on undefined behaviour
   in C++ (shifts ≥ 64, uninitialised fields of an empty range) are
   detected by running the oracle under UndefinedBehaviorSanitizer once
   and are marked in the table rather than silently accepted.
3. **Soundness properties** (`proptest`, S): for random ranges at 1 and 2
   bytes, checked by enumeration — a successful `intersect`/`circleUnion`
   equals the set operation; a successful push-forward contains the image
   of every element; a successful pull-back contains exactly the
   pre-image where Ghidra's is exact and at least the pre-image otherwise
   (the oracle table tells which); `contains(x)` agrees with enumeration;
   `Display` round-trips through a test parser. Never panics for any
   field values, including invalid ones.
4. **Benchmark** (`#[ignore]`): `intersect`, `pullBackBinary`,
   `pushForwardBinary` in nanoseconds per call; numbers in `PERF.md`.

## 7. Acceptance

1. The 117 ported tests pass on Windows, macOS and Linux (S).
2. The oracle table replays with no differing row, except rows marked as
   undefined behaviour in C++, each listed in section 8 with the value
   Basilisk returns and why (S). The table was generated by Ghidra's
   compiled code, not by the Rust implementation; `regen.sh` reproduces
   it on a machine with `../reference` (L), and the regenerated table is
   identical on the macOS and Linux reference builds or the differing
   rows are listed.
3. The property tests pass with at least 4,096 cases each.
4. No allocation, no `unsafe`, no panic on any input; gate green; files
   within the size limit; public items documented with the Ghidra method
   they correspond to.

## 8. Differences from Ghidra

- `pullBack(PcodeOp*, …)` is not here (section 3).
- An empty range has defined (zero) fields.
- Return codes are enums.

(The implementing agent appends further differences here.)

- `translate2Op` returns four codes, not two: 0 (a comparison), 1 (every
  input: the range is full), 2 (not one comparison), 3 (no input: the range
  is empty); `Translated` has a variant for each.
- **Undefined behaviour in the C++, defined here as both reference builds
  compute it** (ADR-024 form; every row of the oracle that hits one is marked
  ` #ub=…` and agrees with Basilisk; counts in
  `crates/bk-decomp-range/tests/data/README.md`):
  shift counts of 64 or more, or negative, are taken modulo 64
  (`pullBackBinary` `INT_RIGHT`/`INT_SRIGHT`, rangeutil.cc:949, 961–962,
  975, 989–990; `pushForwardBinary` `SUBPIECE`, `INT_RIGHT`, `INT_SRIGHT`,
  1288–1293, 1308–1313, 1334–1335; `sign_extend` asked to narrow,
  address.cc:1003, and `sign_extend(intb, bit)`, address.hh:605); the
  `int4` step shift of `setNZMask` (696) is taken modulo 32; signed
  overflow wraps (`valRight + 1`, 1331); and `SUBPIECE` with an offset of
  2^28 or more, where `(int4)in2.left * 8` overflows (1283), keeps the step
  only for offset 0 (both compilers test `sa == 0` as "offset is 0") but
  shifts by the wrapped product.
- **The two reference hosts disagree on one kind, and Basilisk follows
  x86-64**: `pushForwardBinary` `INT_LEFT` with a shift amount of 64 or
  more (rangeutil.cc:1269–1270). g++ on x86-64 shifts modulo 64; Apple
  clang on AArch64 vectorises the two shifts into one `USHL`, which reads
  the amount's low byte as a signed count (64–127 give 0, 128–255 shift
  right). 834 rows of the checked-in macOS table (5,185 of the extended
  set) differ for this reason, each recognised and counted
  (`tests/common/host.rs`).
- **Where Ghidra crashes or hangs, Basilisk returns a defined result**:
  a step of 0 (no valid range has one; the C++ divides by it, a crash on
  x86-64) divides as AArch64 does, `x / 0 = 0` and `x % 0 = x`;
  `INT_LEFT` push-forward with a step bound above 2^30 doubles the `int4`
  step past overflow to 0 and Ghidra's `normalize` then divides by it
  (SIGFPE on x86-64); Basilisk wraps the doubling the same way and the
  division gives the value; `INT_MULT` push-forward with a constant whose
  low 32 bits are 0 and a step bound above 2^30 makes Ghidra's doubling
  loop run forever; Basilisk returns `false`. The oracle stays below these
  bounds; `tests/edge_cases.rs` pins Basilisk's results.
- **Uninitialised fields of an empty range**: `getMax`, `getMaxInfo`,
  `setStride`, `minimalContainer` and `widen` read the bounds of an empty
  range without looking at `isempty`; in Ghidra the answer then depends on
  whatever memory the default constructor left. Basilisk's empty range has
  bounds 0, mask 0 and step 1, and the methods compute with those (2,777
  oracle rows, marked ` #uninit`, found with valgrind).
- **Kept as Ghidra has them** (not differences; the soundness properties of
  `tests/properties.rs` exclude each by name and `tests/edge_cases.rs` pins
  several): `contains` of a full stepped range ignores phase;
  `intersect` never compares phases of equal-step operands, and its
  `newStride` misreads ranges that wrap or round past the top; `INT_SUB`
  pull-back with the variable in slot 1 does not reverse the bounds;
  `INT_RIGHT` and `INT_SRIGHT` push-forwards of wrapping ranges are one
  value short; a comparison pull-back of a range holding both outcomes
  gives `[0,2)` instead of everything; `minimalContainer` of a full range
  returns the other range, and leaves `right - step + 1` unmasked;
  `getMaxInfo` ignores the step and the sign bit, so `INT_MULT` and
  `INT_LEFT` push-forwards can miss a wrap; `SUBPIECE` of a full stepped
  range loses its phase. Reported under Follow-ups in
  `docs/agents/decomp-range.md`.

## 9. Status

Implemented (track `decomp-range`, 2026-11-14): `crates/bk-decomp-range`,
every method of section 3, no allocation, no `unsafe`, no panic on any
field values. Tests: the 117 cases of `testcirclerange.cc`; the oracle
tables of both reference hosts (152,913 rows each, replayed in full) and
the live regeneration with the extended case set (592,213 rows) where the
reference exists; 11 soundness and robustness properties at 4,096 cases;
edge cases, a no-allocation test, a fuzz target `bk_decomp_range_ops`,
and the benchmark of 6.4 (`docs/PERF.md`). Deviations from section 6.2,
for table size: the checked-in table samples 100 of the 1-byte ranges for
the pair set and 10,000 random pairs (the extended set, regenerated and
replayed live, has the 300-range sample and 200,000 pairs); the 1-byte
set of section 6.2 has 87,040 ranges, not "about 12,000".
