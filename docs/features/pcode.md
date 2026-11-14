# P-code operations, behaviours and float formats (`bk-pcode`)

Track `pcode`, wave 1, milestone M0. Format of this document:
`docs/LOOP.md`, "Feature documents".

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`UT/` = `Ghidra/Features/Decompiler/src/decompile/unittests/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/`,
`SMT/` = `Ghidra/Framework/SoftwareModeling/src/test/java/`, all under
`../ghidra`.

## 1. Purpose

P-code is the intermediate language every Ghidra processor is lifted to.
`bk-pcode` defines its operation codes and the exact arithmetic of each
operation — integer, boolean and floating point, at every operand size —
which the decompiler uses for constant folding and the emulator for
execution.

## 2. Ghidra sources

| Source | What to take from it |
|---|---|
| `CPP/opcodes.hh`, `CPP/opcodes.cc` | The `OpCode` enumeration (`CPUI_COPY` = 1 … `CPUI_MAX` = 75), the name table, `get_opname`, `get_opcode`, `get_booleanflip` |
| `SM/ghidra/program/model/pcode/PcodeOp.java` | The Java opcode constants and mnemonics; check they agree with the C++ and note any op present on one side only |
| `CPP/opbehavior.hh`, `CPP/opbehavior.cc` | `OpBehavior` and one subclass per op: `evaluateUnary`, `evaluateBinary`, `evaluateTernary`, `recoverInputUnary`, `recoverInputBinary`, `registerInstructions`. **Authoritative for sizes up to 8 bytes** |
| `SM/ghidra/pcode/opbehavior/*.java` | The Java behaviours, which also work on `BigInteger` for operands wider than 8 bytes. **Authoritative for wide operands** |
| `CPP/float.hh`, `CPP/float.cc` | `FloatFormat`: decoding and encoding of IEEE-style formats into host doubles, classification, `opEqual` … `opRound`, conversions, `printDecimal`. Authoritative for the decompiler |
| `SM/ghidra/pcode/floatformat/` (`FloatFormat`, `BigFloat`, `FloatFormatFactory`, `FloatKind`) | Arbitrary-precision float emulation with correct rounding for every format size (2, 4, 8, 10, 12, 16 bytes), used by the emulator and for display |
| `CPP/multiprecision.hh`, `CPP/multiprecision.cc` | 128-bit helpers (`mult64to128`, `unsignedSubtract128`, `unsignedCompare128`, `power2Divide`, `udiv128`, …) |
| `SM/ghidra/pcode/utils/Utils.java` | Size masks, sign extension, byte order helpers used by the behaviours |
| `UT/testfloatemu.cc` (31 tests), `UT/testmultiprec.cc` (5 tests) | C++ tests |
| `SMT/ghidra/pcode/floatformat/` (`FloatFormatTest` 58, `BigFloatTest` 26), `SMT/ghidra/pcode/opbehavior/` (about 46 classes) | Java tests |

*Corrections from the track's reading of Ghidra's source (2026-11-12),
which override the text below where they differ: there are 73 operations,
not 74 (slot 45 is unused); `get_opcode` is a map lookup and the boolean
flips come from `typeop.cc`, not `opcodes.cc`; the Java op behaviours and
their tests live in `Ghidra/Framework/Emulation` (checklist file
`docs/inventory/tests/framework-emulation.md`); the C++ `FloatFormat` has
only the 4- and 8-byte formats, so sizes 2, 10, 16 and 32 are defined by
the Java alone; `multiprecision.cc`'s function names differ from those
listed here.*

## 3. Scope

**In:** opcodes; op behaviours for all sizes; float formats; multiprecision
helpers. **Crate owned:** `bk-pcode`. It has **no dependency on other
`bk-*` crates** (the `core-marshal` track is writing `bk-core` and
`bk-marshal` in the same wave; do not depend on them).

**Not in this track:** `PcodeOpRaw`, varnodes, p-code emission and the
`Translate` interface (wave 2, M1); user-defined ops (`userop.cc`);
the emulator; `RangeUtil`/`CircleRange` (M3).

## 4. Behaviour

### 4.1 Opcodes
An enum with Ghidra's numeric values (they appear in `.sla` files and in
encoded p-code, so they are fixed), every mnemonic exactly as Ghidra
prints it, lookup by name (Ghidra's `get_opcode` does a binary search over
a sorted name table and has specific results for unknown names — match
them), and `get_booleanflip` (the complementary comparison and whether the
operands must be swapped). Expose op classification that Ghidra spreads
across `OpBehavior` and `TypeOp` only as far as `OpBehavior` has it
(`isunary`, `isspecial`).

### 4.2 Op behaviours
For each op: evaluation on operands of a given input and output size, and
"recover input" (solving for one input given the output and the other
input) where Ghidra implements it. Results must equal Ghidra's bit for
bit, including the cases that are easy to get wrong:

- masking to the output size before and after; sign extension by size;
- `INT_LEFT`/`INT_RIGHT`/`INT_SRIGHT` with shift amounts greater than or
  equal to the bit width;
- `INT_DIV`, `INT_SDIV`, `INT_REM`, `INT_SREM` by zero (Ghidra raises an
  evaluation error — return an error value, do not panic) and signed
  overflow (`MIN / -1`);
- `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`; `INT_ZEXT`, `INT_SEXT`;
  `SUBPIECE` and `PIECE`; `POPCOUNT`, `LZCOUNT`; `BOOL_*`;
- float ops through the float format for the operand size, including NaN
  and infinity handling, `FLOAT_NAN`, `TRUNC`, `CEIL`, `FLOOR`, `ROUND`,
  `INT2FLOAT`, `FLOAT2FLOAT`, `SQRT`, comparison of NaNs;
- special ops (`LOAD`, `STORE`, `BRANCH`, `CALL`, `MULTIEQUAL`, `INDIRECT`,
  `CPOOLREF`, `NEW`, …) have no arithmetic: evaluating them is the error
  Ghidra raises.

Two operand widths: a fast path on `u64` for sizes up to 8 bytes (the
decompiler's path; results equal the C++), and a wide path for larger
operands such as vector registers (results equal the Java `BigInteger`
behaviours). Choose the wide representation deliberately — `u128` covers
16 bytes without allocation; anything wider needs limbs — and document the
choice. Where the C++ and Java disagree for sizes up to 8 bytes, follow
the C++ and record the disagreement under "Differences from Ghidra".

Float evaluation needs the format for a size. Ghidra reaches it through
`Translate::getFloatFormat`; here it is a small table type
(`FloatFormats`: size → format) passed in by the caller, with the standard
IEEE set available as a constant.

### 4.3 Float formats
Two levels, as in Ghidra:

- **Host-double emulation** (`CPP/float.cc`): decode an encoded value of
  the format into a host `f64` plus a class (normalised, denormalised,
  zero, infinity, NaN), encode back with the format's rounding, and the
  op implementations on encodings. Must match the C++ exactly, including
  its handling of the x87 80-bit format's explicit integer bit (`j` bit
  conventions) and of formats wider than a double (precision loss rules).
- **Exact emulation** (`BigFloat`/`FloatFormat` in Java): arbitrary
  precision with round-to-nearest-even for every supported size, exact
  decimal formatting (`toDecimalString`, the shortest-representation
  rules), `toBigInteger`/`toBinaryString`, min/max/NaN/infinity
  constructors. Must match the Java results, which the 84 Java tests pin
  down.

Decide whether one implementation can serve both with identical results;
if not, keep both and explain why in the feature doc.

### 4.4 Multiprecision
The 128-bit helpers behave as in `multiprecision.cc`. Rust has `u128`, so
most of them reduce to native operations: keep the API the decompiler
needs (callers arrive in M3: `ruleaction.cc`'s division-optimisation
rules) but implement it natively, and port the five tests against it.

## 5. Design

- `OpCode`: `#[repr(u8)]` enum, `Copy`, with `const` tables for names and
  flips; conversion from the numeric value is checked (`TryFrom<u8>`).
- Behaviours are **functions selected by `match` on `OpCode`**, not a
  table of trait objects: `evaluate_unary(op, size_out, size_in, a)`,
  `evaluate_binary(op, size_out, size_in, a, b)`, the `recover_input_*`
  pair, and wide-operand equivalents. This is on the decompiler's
  constant-folding hot path: no allocation, no dynamic dispatch.
- Errors: a small `EvalError` enum (division by zero, op has no
  evaluation, unsupported size, no float format for size).
- Modules: `opcode`, `behavior/{integer, boolean, float, special, wide}`,
  `float/{format, host, exact, decimal}`, `multiprecision`, `mask`
  (size masks and sign extension). Keep every file small.
- Evaluate `num-bigint` (or similar) for the exact float path and wide
  integers under ADR-011; a dependency-free limb implementation is
  acceptable if it is simpler and faster for the sizes involved.

## 6. Tests

- **Port** `UT/testfloatemu.cc` (31) and `UT/testmultiprec.cc` (5); mark
  them in `docs/inventory/tests/decompiler-cpp.md`.
- **Port** `ghidra.pcode.floatformat.FloatFormatTest` (58) and
  `BigFloatTest` (26), and every `ghidra.pcode.opbehavior.OpBehavior*Test`
  class (each has a `long` case and a `BigInteger` case); mark them in
  `docs/inventory/tests/framework-softwaremodeling.md`. The op-behaviour
  classes are near-identical: make them table-driven.
- **Derived tests:** opcode numeric values and names against the tables
  in `opcodes.cc`/`PcodeOp.java`; `get_booleanflip` for every comparison;
  every edge case listed in 4.2; `recover_input_*` inverts `evaluate_*`.
- **Property tests:** integer ops at sizes 1, 2, 4, 8 agree with Rust's
  wrapping arithmetic on the native types; the wide path agrees with the
  `u64` path for sizes up to 8; float ops at sizes 4 and 8 agree with
  native `f32`/`f64` (bit patterns, with NaN payload rules stated);
  encode/decode round-trips for every format.
- **Benchmarks:** `evaluate_binary` over a mix of ops (should be within a
  small factor of native arithmetic); float encode/decode; numbers in
  `PERF.md`.

## 7. Acceptance

1. All listed C++ and Java tests pass in ported form and are marked.
2. Opcode values and mnemonics equal Ghidra's for all 74 ops.
3. No panics for any operand values or sizes (property tests cover
   sizes 0 through 64 bytes for the entry points that take a size).
4. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- Behaviours are matched functions over an enum, not a class per op.
- Multiprecision helpers use native `u128`.

(The implementing agent appends further differences here, including any
C++/Java disagreements found.)

Appended by the `pcode` track (first agent, revised by the second; see `docs/agents/pcode.md` for
the reasoning behind each and for what Ghidra's source says):

**Structure**

- The wide path's operand is `Wide`, a fixed 512-bit unsigned integer
  (`primitive-types`' `U512`), not an arbitrary-precision integer: `Copy`,
  no allocation, covers the 64-byte `ZMM` registers. Sizes above 64 bytes
  are `EvalError::UnsupportedSize`. Java's `BigInteger` has no limit.
- The wide path returns the result cut to `size_out` bytes. Java returns
  an untruncated, possibly negative `BigInteger` and the emulator truncates
  it when storing.
- The exact float level uses `num-bigint` for significands and a small
  `Decimal` type that reproduces the parts of Java's `BigDecimal` Ghidra's
  output is defined by (canonical `toString`, `MathContext` rounding,
  the `String` constructor); `BigFloat` operations return new values
  instead of mutating.
- Two float implementations are kept (host level = C++ `float.cc`, exact
  level = Java `BigFloat`), because they do not give identical results:
  see the next two groups.
- `PTRADD` (ternary) and `PTRSUB` (binary) are evaluated as `typeop.cc`
  wires them (`OpBehaviorPtradd`/`OpBehaviorPtrsub`); the emulator's
  `registerInstructions` leaves them unimplemented, as does the wide path.
- There is no `behavior/boolean.rs`: the four boolean operations are
  one-line arms of the dispatch `match`.

**Where Ghidra's result is undefined or host-dependent (u64 path)**

Reviewed by the second `pcode` agent against Ghidra's source, Ghidra's own
data tests and a differential run of Ghidra's compiled C++
(`tests/cpp_oracle.rs`, 87,176 cases; see `docs/agents/pcode.md`).

- A NaN *created* by an operation (`inf - inf`, `0/0`, `0 * inf`,
  `sqrt(-1)`) is the **negative** quiet NaN, x86-64's default NaN. Ghidra
  takes the host FPU's: negative on x86-64, positive on AArch64. Ghidra's
  data test `floatprint.xml` folds `0.0f / 0.0f` and expects `-NAN`, so the
  x86-64 result is the tested one (the reference build on AArch64 fails that
  test). A NaN *propagated* from a single NaN input keeps that input's sign
  (both hosts agree). (Changed from the first agent's positive NaN.)
- With **two NaN inputs**, `FLOAT_ADD` and `FLOAT_MULT` give the quiet NaN
  with the sign of the *second* input, `FLOAT_SUB` and `FLOAT_DIV` that of
  the *first*: what Ghidra compiled by GCC gives on x86-64 (SSE2 returns
  the first source operand, and GCC puts `val2` there for the commutative
  operations). AArch64 takes the first input's for all four. basilisk
  computes the sign explicitly, never from the host's arithmetic. Seen in
  the x86-64 oracle table (48 rows; `x86-oracle` track, 2026-11-14).
- `FLOAT_TRUNC` of a NaN, an infinity or a value outside `i64` saturates
  (NaN gives 0). The C++ cast is undefined: x86-64 gives `i64::MIN`,
  AArch64 saturates. Java's `(long)` cast saturates and
  `FloatFormatTest.testOpTruncLongInt` and `OpBehaviorFloatTruncTest` pin
  that, so basilisk saturates; this is the one place it does not follow
  x86-64, and a differential test against a reference `decomp` built on
  x86-64 will see the difference for out-of-range constants. In the x86-64
  oracle table these are 58 rows (`cpp_oracle.rs`, class
  `TruncSaturates`): x86-64 gives `i64::MIN` cut to the output size, so 0
  at sizes below 8 for a positive overflow, where basilisk gives all ones.
- A value that rounds up from the largest subnormal to the smallest normal
  encodes as the smallest normal. The C++ shifts by -1 there ("TODO handle
  round to normal case") and returns a signed zero on both hosts (seen in
  the differential run). Java is correct. Kept: a fixed rounding bug in a
  case no Ghidra test pins.
- `INT_SEXT` with `size_out < size_in`, or a size of 0: the C++ shifts by a
  negative amount or by 64; both hosts take the count modulo 64, and
  basilisk now does the same, reproducing Ghidra's compiled result bit for
  bit. (The first agent returned the input unchanged; the differential run
  found it.)
- Shift counts outside `0..64` that the C++ reaches only with a size of 0
  or above 8 (undefined behaviour) are taken modulo 64, which is what Java
  defines and what x86-64/AArch64 produce.
- `recover_input_binary` of `INT_LEFT`/`INT_RIGHT`/`INT_SRIGHT` by 0 at 8
  bytes: the C++ shifts by 64, which both hosts take as 0, so it reports
  every non-zero output as "not in range" (seen on AArch64 in the
  differential run). basilisk returns the output, the correct input. Kept
  as a deliberate fix: the decompiler's only caller is jump-table
  recovery (`jumptable.cc`), where Ghidra simply fails on such a shift.
- The oracle table (`tests/data/opbehavior_cpp.txt.gz`) is x86-64 Linux's
  (2026-11-14). Against it, `tests/cpp_oracle.rs` accepts exactly three
  classes of difference, each counted and each required to still occur:
  out-of-range `FLOAT_TRUNC` (58 rows), the subnormal rounding to the
  smallest normal (3 rows) and `recover_input_binary` of a shift by 0
  (10 rows, below). `tests/host_independence.rs` pins the host-dependent
  cases as literal bits so every CI host checks the same values.
- `FLOAT_CEIL`, `FLOAT_FLOOR` and `FLOAT_ROUND` use the `libm` crate, not
  the C library (`round()` is wrong on MinGW for 0.49999999999999994).
- `printDecimal` prints non-finite values as `inf`, `-inf`, `nan`, `-nan`
  (the C++ prints what the C library prints). It reproduces libstdc++'s
  stream extraction, which stores the largest finite value on overflow
  (`testfloatemu.cc` pins `1.79769313486232e+308` for `DBL_MAX`); with
  libc++ (macOS) Ghidra prints 17 digits there and fails its own test.

**C++/Java disagreements for sizes up to 8 bytes (the C++ wins)**

- `INT_DIV` by zero: the C++ throws; Java returns 0. basilisk:
  `DivideByZero`, on the wide path too (Java's `BigInteger` overload also
  returns 0, while its `INT_SDIV`/`INT_REM`/`INT_SREM` throw).
- `FLOAT_ROUND`: the C++ uses `round()` (halfway cases away from zero);
  Java uses `floor(x + 0.5)`. The u64 path follows the C++; the wide path
  follows Java, whose tests pin `round(-2.5) = -2`.
- `PIECE`: the C++ shifts the high piece by `(size_out - size_in) * 8`;
  Java shifts by `size_in * 8`, which is wrong when the two pieces differ
  in size. Both paths use the C++ formula.
- `SUBPIECE` with an offset of 8 or more: 0 in the C++; Java's `long`
  overload shifts by the offset modulo 8.
- `INT_LEFT`/`INT_RIGHT`/`INT_SRIGHT` compare the shift amount with
  `8 * size_out` in the C++ and `8 * size_in` in Java; `INT_RIGHT` masks
  before shifting in the C++ and after in Java; `INT_LESS`/`INT_LESSEQUAL`
  mask their inputs in Java and not in the C++. These agree on clean inputs
  with equal sizes.
- Opcode names: `get_opname` (C++) calls `MULTIEQUAL`, `INDIRECT`,
  `PTRADD`, `PTRSUB` by their SLEIGH template names `BUILD`, `DELAY_SLOT`,
  `LABEL`, `CROSSBUILD`; `PcodeOp.getMnemonic` (Java) uses the operation
  names and accepts both when parsing. Both are available (`name`,
  `mnemonic`).
- The C++ `FloatFormat` exists for 4 and 8 bytes only; Java has 2, 4, 8,
  10, 16 and 32.

**Java bugs fixed on the wide/exact path (not pinned by a Java test)**

- Float comparisons are IEEE: a NaN is unordered and `+0 == -0`. Java's
  `BigInteger` overloads compare `BigFloat` representations and use
  `compareTo`'s total order, so there `+0 == -0` is false, `-0 < +0` is
  true and `x < NaN` is true.
- Narrowing into the x87 format: a rounding carry bumps the exponent.
  Java tests the carry against the wrong bit for a format with an explicit
  integer bit and loses the value (the result decodes as zero).

**Java behaviour kept on the wide/exact path although questionable**

- A NaN result is always the positive quiet NaN (also for `FLOAT_NEG` and
  `FLOAT_ABS`). (This differs from the u64 path's x86-64 rule; Java's
  `BigFloat` has no NaN sign, so it is defined behaviour there.)
- `FLOAT_TRUNC` of an infinity gives the largest or smallest integer of
  the *float's* size, then cut to the output size.
- `INT2FLOAT` into the 2-, 10-, 16- and 32-byte formats truncates an
  integer wider than the significand instead of rounding; decimal text is
  converted to those formats by converting the digits and the power of ten
  separately and multiplying or dividing (not always the nearest value).
- The x87 format has no subnormals (they encode as zero), and its infinity
  is recognised only when the whole 64-bit fraction field, integer bit
  included, is zero — so a real x87 infinity (`0x7fff 8000…`) decodes as a
  NaN.
- `toDecimalString` appends `.0` to scientific notation without a decimal
  point (`1E+10.0`).

## 9. Status

Complete (2026-11-12). The library (`crates/bk-pcode/src`) covers sections
4.1 to 4.4. Every listed Ghidra test is ported and marked: `testfloatemu.cc`
(31), `testmultiprec.cc` (5), `BigFloatTest` (26), `FloatFormatTest` (58)
and the 40 `OpBehavior*Test` classes (82 methods). Derived tests, a
differential test against Ghidra's compiled C++ behaviours, property tests
(native arithmetic, wide = u64, float ops against native `f32`/`f64`, round
trips, never panics) and benchmarks (`docs/PERF.md`) are in place. Gaps and
the detailed report: `docs/agents/pcode.md`.
