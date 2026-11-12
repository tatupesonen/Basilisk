# Track `pcode` — handover

Crate `bk-pcode`: p-code opcodes, op behaviours, float formats,
multiprecision. Spec: `docs/features/pcode.md`.

This is a **handover written mid-track** (the owner changed the plan; the
first agent stopped at a checkpoint). The library is written and passes its
tests; the test-porting, property-test, benchmark and gate work of the spec
is partly done. Read "Remaining" for what to do next, in order.

Branch `pcode`, worktree `/Users/tatu/slop/basilisk-wt/pcode`. `master` has
**not** been merged in (its lint configuration is stricter now; merging it
is the next agent's first step).

Wording used below: **ran** = I executed it and saw the result;
**read** = concluded from reading Ghidra's source, not executed.

## Done

All of `crates/bk-pcode/src` (about 5,000 lines with unit tests):

| Module | Spec section | State |
|---|---|---|
| `opcode.rs` — `OpCode` (`#[repr(u8)]`, Ghidra's values), `name()` (C++ `get_opname`), `mnemonic()` (Java `PcodeOp.getMnemonic`), `from_name`, `from_mnemonic`, `TryFrom<u8>`, `boolean_flip()`, `is_unary()`, `is_special()` | 4.1 | complete |
| `error.rs` — `EvalError` (`DivideByZero`, `RemainderByZero`, `Unimplemented{op, arity}`, `NoFloatFormat`, `UnsupportedSize`, `CannotRecover`, `OutOfRange`), Ghidra's messages | 5 | complete |
| `mask.rs` — `calc_mask`, `signbit_negative`, `uintb_negate`, `sign_extend` (3-arg), `sign_extend_bit`, `zero_extend_bit`, `byte_swap` | 5 | complete for what the behaviours need; the other `address.cc` helpers (`leastsigbit_set`, `coveringmask`, `bit_transitions`, …) are not here |
| `wide.rs` — `Wide`, a 512-bit unsigned integer over `primitive_types::U512` | 4.2 | complete |
| `behavior/mod.rs` — `evaluate_unary`, `evaluate_binary`, `evaluate_ternary` on `u64` (one `match`, no allocation) | 4.2 | complete |
| `behavior/{integer,special,float}.rs` — the op bodies for the u64 path | 4.2 | complete |
| `behavior/recover.rs` — `recover_input_unary`, `recover_input_binary` | 4.2 | complete |
| `behavior/wide.rs` — `wide::evaluate_unary`, `wide::evaluate_binary` on `Wide` | 4.2 | complete (no ternary, no recover: Java has neither) |
| `float/format.rs` — `FloatFormat` (sizes 2, 4, 8, 10, 16, 32), `FloatClass`, `FloatFormats` table (`DEFAULT` = 4 and 8, `IEEE` = all six, `NONE`) | 4.2, 4.3 | complete |
| `float/host.rs` — host level: the C++ `float.cc` on `u64` encodings through `f64` | 4.3 | complete |
| `float/bigfloat.rs`, `float/arith.rs` — `BigFloat` (Java `BigFloat`) | 4.3 | complete |
| `float/encode.rs`, `float/exact_ops.rs` — exact level of `FloatFormat`: decode/encode, from int/decimal/string/native, `op_*_exact` on `Wide` encodings | 4.3 | complete |
| `float/decimal.rs` — `Decimal` (the subset of Java `BigDecimal` Ghidra uses) | 4.3 | complete |
| `float/display.rs` — `print_decimal` (C++ `printDecimal`), `to_decimal_string` (Java), `round_decimal` | 4.3 | complete |
| `float/convert.rs` — correctly rounded big-integer → `f64`/`f32` | 4.3 | complete |
| `multiprecision.rs` — `udiv128`, `add128`, `subtract128`, `leftshift128`, `uless128`, `ulessequal128`, `set_u128` on `u128`, plus `from_words`/`to_words` | 4.4 | complete |
| `lib.rs` — crate docs, re-exports, a doctest | — | complete |

Tests written by the first agent (all pass, see "Verified"):

- unit tests next to the code in every module (69);
- `tests/cpp_floatemu.rs` — port of `unittests/testfloatemu.cc`, 31 tests;
- `multiprecision.rs` `tests` module — port of `unittests/testmultiprec.cc`,
  5 tests, plus one extra;
- `tests/java_bigfloat.rs` — port of `BigFloatTest`, 26 tests (plus one that
  checks the reimplemented `java.util.Random` against known JDK values);
- `tests/behavior.rs` — 20 derived tests: every edge case of spec 4.2,
  operations without arithmetic, which interface each op has,
  `recover_input_*` inverting `evaluate_*`, the wide path at 16–64 bytes,
  wide float ops on the 10-, 16- and 32-byte formats.

Tests written by two helper subagents (see "In flight" for their state):
`tests/java_opbehavior_*.rs` and `tests/java_floatformat_*.rs`.

Docs: `docs/features/pcode.md` sections 8 (differences) and 9 (status)
filled in; `docs/inventory/tests/decompiler-cpp.md` marks
`testfloatemu.cc` and `testmultiprec.cc`;
`docs/inventory/tests/framework-softwaremodeling.md` marks `BigFloatTest`.

## Verified

Ran, on this machine (macOS, AArch64), last at the handover commit:

| Command | Result |
|---|---|
| `CARGO_BUILD_JOBS=2 cargo test -p bk-pcode` | **247 passed, 0 failed, 0 ignored** across 12 test binaries (breakdown under "Final state at handover") |
| `cargo clippy -p bk-pcode --all-targets --quiet -- -D warnings` | clean **at commit `f349f56`** (library and its unit tests). **Not re-run** after the `tests/*.rs` files were added, so the integration tests have not been through clippy. |
| `cargo fmt -p bk-pcode` | run on everything committed |
| `scripts/gate.sh` | **not run** |

Not verified by anything other than their own unit tests: nothing is
"written but untested" in `src`, but these have thin coverage — see
"Remaining" items 3 and 4:

- `to_decimal_string` with `compact` on the 10/16/32-byte formats (only
  binary64 cases are tested by me; `FloatFormatTest` covers more);
- `big_float_from_decimal` for the non-4/8 formats (a handful of cases);
- the exact level at 80/128/256 bits is tested on exactly representable
  values plus `1/3` and `sqrt(2)` in binary128 and `1/3` in x87 (expected
  encodings written from known constants). Its algorithms are the same code
  that `BigFloatTest` checks at 24 and 53 bits against native arithmetic on
  117×117 operand pairs per operation;
- no test on an x86-64 host: the NaN-sign and `TRUNC` choices are designed
  to be host-independent, and the ported C++ tests compute their expected
  NaN encodings by basilisk's rule rather than from the host, but that has
  only been run on AArch64.


## Remaining

In the order I would do it:

1. **Merge `master`**, fix what its stricter lints report.
2. **Finish and check the Java test ports** (state in "In flight"):
   `OpBehavior*Test` — 40 classes, 82 `@Test` methods — and
   `FloatFormatTest` — 58 methods. Check the subagent-written files against
   the Java (they assert basilisk's behaviour where it deliberately differs;
   each such row should carry a `// Java: …` comment and correspond to a
   difference listed in the spec, section 8). Run clippy on them.
3. **Mark the checklist**: `FloatFormatTest` in
   `docs/inventory/tests/framework-softwaremodeling.md`; the 40
   `OpBehavior*Test` classes in
   **`docs/inventory/tests/framework-emulation.md`** (lines 24–63) — the
   spec says they are in `SoftwareModeling`, but they live in
   `Ghidra/Framework/Emulation`.
4. **Property tests** (`tests/properties.rs`, `proptest` is already a
   dev-dependency; none written yet). The plan:
   - integer ops at sizes 1, 2, 4, 8 against Rust's wrapping arithmetic on
     `u8`/`u16`/`u32`/`u64` and the signed types;
   - the wide path equals the u64 path for sizes ≤ 8 — for **integer** ops,
     clean inputs and `size_in == size_out` where the op expects it. Do not
     include `PTRSUB` (wide: unimplemented) or `FLOAT_ROUND` and NaN-sign
     cases (the two float levels differ by design);
   - host float ops at 4 and 8 bytes against native `f32`/`f64` bit
     patterns, with the NaN rule (sign of the first NaN input, else
     positive); exact-level ops at 4 and 8 bytes against native too;
   - round trips: `encoding(host_float(x)) == x` for non-NaN encodings of
     the 2-, 4- and 8-byte formats; `encode_big_float(decode_big_float(x))
     == x` for every format (x87: only encodings with the integer bit set
     and a non-zero, non-maximal exponent, plus zero);
   - `recover_input_*` inverts `evaluate_*` on random values;
   - **no panics**: every `OpCode`, sizes 0..=64 and a few huge ones, any
     operand values, for `evaluate_unary/binary/ternary`, `recover_input_*`
     and `wide::evaluate_*` with `FloatFormats::IEEE` (acceptance 3);
   - `Wide` add/sub/mul/div/shift against `num-bigint` at 16–64 bytes;
   - `Decimal::to_f64` against `str::parse::<f64>`; `to_decimal_string(x,
     compact)` parses back to `x` for binary64.
5. **Benchmarks** (none written): `evaluate_binary` over a mix of ops
   against native arithmetic; float encode/decode (`encoding`,
   `host_float`); the wide path. As `#[ignore]` release tests printing
   ns/op, numbers into `docs/PERF.md` under `bk-pcode`.
6. **File sizes**: `tests/behavior.rs` is 963 lines (under the gate's 1,000
   but far over the 600 guideline) — split it (integer / float / recover /
   wide). `src/float/encode.rs` (655) and `src/float/host.rs` (613) are just
   over 600 because of their test modules.
7. **Gate**: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`.
8. Rewrite this file as the final status report (`docs/agents/RULES.md`).

Optional, if time: `rustc_apfloat` as a dev-only differential oracle for
the exact level at binary128 and x87 (see "Crates").

## In flight

**Java test ports by two helper subagents.** When the stop order came, two
subagents I had started were porting `OpBehavior*Test` (40 classes) and
`FloatFormatTest` (58 methods) into `crates/bk-pcode/tests/`. I told them
to stop at a clean point and report; both did, between files, so nothing
is half-written. What they finished and what is left is under "Final state
at handover" below. Their brief, so the next agent can judge their
output:

- Java `long` overloads are ported against the u64 path / host level
  (C++ semantics); Java `BigInteger` overloads against the wide path /
  exact level.
- Many Java `BigInteger` tests pass a meaningless `sizeout` (for example
  `OP.evaluateBinary(1, 16, a, b)`) and compare 16 bytes; because basilisk
  truncates to `size_out`, the port passes the compared size as `size_out`.
- Where a Java expectation conflicts with a documented difference, the
  port asserts basilisk's value with a `// Java: …` comment. A mismatch
  that no documented difference explains was to be isolated in a separate
  `#[ignore = "mismatch under investigation: …"]` test asserting the Java
  value, never papered over.

**Property tests and benchmarks**: designed (above), not started.

**Tried and dropped**: `Wide` was first written over the `bnum` crate
(`U512`); it worked, but `bnum` has 30 reverse dependencies, so under the
owner's "prefer the industry-standard crate" rule it was replaced by
`primitive-types` before anything depended on it. Nothing else was tried
and abandoned.

## What Ghidra's source says that the spec does not

Spec corrections:

- **There are 73 operations, not 74.** Values 1..=74 with slot 45 unused
  (`"UNUSED1"` in the C++ name table); 0 is `BLANK`/`UNIMPLEMENTED`, 75 is
  the end marker. This Ghidra has `INSERT` (70), `ZPULL` (71), `SPULL`
  (74) — no `EXTRACT`.
- **`get_opcode` is a `std::map` lookup, not a binary search**, and returns
  0 for an unknown name (and 45 for `"UNUSED1"`). `get_booleanflip` does
  not exist in `opcodes.cc` at this commit: the flip is `TypeOp`'s
  `booleanFlip` field and `boolean_reorder` flag (`typeop.cc`), mirrored by
  `pcodeCPort/opcodes/OpCode.java` (`getOpCodeFlip`, `getBooleanFlip`).
- **The Java op behaviours and their 40 tests are in
  `Ghidra/Framework/Emulation`**, not `SoftwareModeling`; the checklist is
  `docs/inventory/tests/framework-emulation.md`.
- **The C++ `FloatFormat` only constructs the 4- and 8-byte formats**
  (other sizes leave its fields uninitialised); `jbitimplied` is always
  true there, and `Translate::setDefaultFloatFormats` registers exactly 4
  and 8. There is no x87 handling in the C++ to match. The 2-, 10-, 16-
  and 32-byte formats are Java only (no 12-byte format anywhere).
- **`multiprecision.cc` has** `leftshift128`, `uless128`, `ulessequal128`,
  `udiv128`, `add128`, `subtract128`, `set_u128` — not the `mult64to128`,
  `unsignedSubtract128`, `unsignedCompare128`, `power2Divide` the spec
  names.
- **Java's `long` float overloads also go through host doubles**
  (`decodeHostFloat`, `getEncoding(double)`), like the C++. Only the
  `BigInteger` overloads use `BigFloat`. So for sizes ≤ 8 there are two
  host-double implementations (C++ and Java) and one exact one.
- Two wirings of behaviours exist in the C++: `registerInstructions`
  (emulator; `PTRADD`/`PTRSUB` unimplemented) and the `TypeOp`
  constructors (decompiler; `OpBehaviorPtradd` ternary, `OpBehaviorPtrsub`
  binary). basilisk follows `TypeOp`.

C++/Java disagreements and bugs found (each is in the spec, section 8,
with what basilisk does):

- `INT_DIV` by zero: C++ throws, Java returns 0 (both overloads).
- `FLOAT_ROUND`: C++ `round()`, Java `floor(x + 0.5)` (both overloads; the
  Java tests pin `round(-2.5) == -2`). Java's version also has the
  classic `0.49999999999999994 → 1` error, since the sum is rounded.
- `PIECE`: Java shifts by `size_in * 8` (the high piece's size); the C++
  by `(size_out - size_in) * 8` (the low piece's size). Java is wrong for
  unequal pieces.
- `SUBPIECE`, shifts, `INT_LESS`: see the spec.
- `float.cc` `getEncoding`/`convertEncoding`: a subnormal that rounds up
  to the smallest normal reaches `signif >> (-exp)` with `exp == 1`, a
  shift by -1 (read; the source says "TODO handle round to normal case").
  With the shift count taken modulo 64 the result is zero.
- Java `FloatFormat.getEncoding(BigFloat)`: after rounding, the carry test
  is `leadBit(fraction) > frac_size`, but for the x87 format the lead bit
  is at `frac_size - 1`, so a carry is missed and the fraction's bit 64
  is OR-ed into the exponent field (read).
- Java `BigInteger` float comparisons use `BigFloat.equals` and
  `compareTo` (read): `+0 == -0` false, `x < NaN` true.
- Java `BigFloat.round` adds 0.5 with rounding, then floors.
- Java `getBigFloat(BigInteger)` truncates for sizes other than 4 and 8
  and leaves small integers unnormalised (`scale = fracbits - 1`).
- Java decodes an x87 encoding with exponent 0x7fff and fraction
  `0x8000000000000000` (the real x87 infinity) as a NaN, and gives the x87
  format no subnormals (read).
- `IntSright::recoverInputBinary` only accepts an output whose top
  `sa + 1` bits are all ones, so it cannot recover a shift of a
  non-negative value; and the recovered values of the three shifts are not
  masked. Kept as is.
- `OpBehaviorLzcount` (C++) computes `count_leading_zeros(in1) -
  8*(sizeof(uintb) - sizein)` in unsigned arithmetic: garbage if `in1` has
  bits above its size. Reproduced exactly.

Easy to get wrong:

- `BigFloat`'s `fracbits` *includes* the integer bit (24, 53, 64, 113,
  237), and the value is `unscaled * 2^(scale - fracbits + 1)` — the Java
  class comment says `2^(scale - fracbits)`, the code disagrees with it.
- `BigFloat` values may be unnormalised (from `getBigFloat(BigInteger)`);
  `add0`/`sub0` return early on the scale difference alone, so the Java
  algorithms have to be followed step by step, not replaced by a textbook
  implementation.
- `BigFloat.equals` ignores the sign and payload of NaNs but distinguishes
  quiet from signalling; `decodeBigFloat(long)` produces signalling NaNs,
  `decodeBigFloat(BigInteger)` never does.
- `printDecimal` relies on C++ stream extraction storing the largest
  finite value on overflow: that is why `DBL_MAX` prints as
  `1.79769313486232e+308` (15 digits), which the C++ test pins.
- Java `BigDecimal.toString` switches to scientific notation when the
  scale is negative or the adjusted exponent is below -6, and
  `toDecimalString` then appends `.0` to a text with no decimal point —
  from reading the code this yields forms like `1E+10.0`; I did not
  observe an input that produces one (a `BigFloat`'s decimal expansion
  rounded to the display precision always kept a decimal point in what I
  ran).
- The sign of a created NaN and out-of-range `TRUNC` are host-dependent in
  Ghidra (see spec section 8); the ported C++ tests therefore cannot
  compare NaN results with native arithmetic.

## Decisions and crate evaluations

Design decisions (all in the spec, section 8): two float levels kept
separate; `Wide` fixed at 512 bits; wide results truncated to `size_out`;
host-independent NaN signs and `TRUNC`; Java comparison and x87-carry bugs
fixed on the exact path; the Java quirks that tests pin, or that are
defined behaviour, kept. The fixes were chosen where Ghidra's result is an
accident (undefined behaviour or lost values) and no Ghidra test pins it;
if strict parity with Ghidra's emulator is wanted instead, the two places
to change are `float/exact_ops.rs` (`compare_exact`) and the carry test in
`float/encode.rs` (`encode_big_float`).

Crates (figures from the crates.io API on 2026-11-12: total downloads /
recent downloads / reverse dependencies / last release):

| Crate | Decision | Figures | Reason |
|---|---|---|---|
| `num-bigint` 0.4.8 | **adopted** (exact float level, `Decimal`) | 741M / 211M / 2,599 / 2026-07-05 | The standard arbitrary-precision integer. 0.4.8 pinned rather than 0.5.1 (same date): the 0.4 line has far more use (0.4.8 alone 103M downloads vs 23M) and its API is the one I know; bumping is the coordinator's call. |
| `primitive-types` 0.14.0 (`U512`, built on `uint`) | **adopted** for `Wide` | 71M / 13M / 275 / 2025-09-19 (`uint`: 83M / 16M / 175 / 2026-10-02) | Fixed-width, `Copy`, no allocation: the emulator's wide path must not allocate per op. Most reverse dependencies of the candidates. Used with `default-features = false, features = ["std"]`. Its panicking APIs (`bit`, `from_little_endian`, division) are guarded in `wide.rs`. |
| `libm` 0.2.16 | **adopted** (`ldexp`) | 587M / 169M / 1,452 / 2026-01-24 | `std` has no `ldexp`; the C++ `createFloat` uses it. |
| `thiserror` | adopted (workspace) | — | error enums |
| `crypto-bigint` 0.7.11 | rejected for `Wide` | 343M / 95M / 197 / 2026-11-08 | More downloads than `primitive-types`, but it is built for constant-time cryptography: its default operations are deliberately slower and division needs `NonZero`/`_vartime` variants. Fails the performance requirement for an emulator hot path. |
| `bnum` 0.14.4 | tried, **replaced** | 23M / 10M / 30 / 2026-03-24 | Fits technically, but niche (30 reverse dependencies). |
| `ruint` 1.21.1 | rejected | 35M / 9M / 126 / 2026-10-23 | Fewer dependents than `primitive-types`; no advantage here. |
| `bigdecimal` 0.4.11 | rejected | 145M / 38M / (not checked) / 2026-09-28 | Ghidra's decimal output is defined by Java `BigDecimal`'s `toString`, `MathContext` rounding and `String` constructor; `bigdecimal` formats and parses by its own rules, so only its storage (a `BigInt` and a scale) would be reused. `Decimal` is about 200 lines on `num-bigint`. |
| `rustc_apfloat` 0.2.3 | rejected as the implementation; possible dev-only oracle | 7M / 2M / (not checked) / 2025-06-11 | Correct IEEE arithmetic for half/single/double/x87/quad, but Ghidra's `BigFloat` is not that: unnormalised values, no x87 subnormals, a 32-byte format, truncating int→float, `floor(x + 0.5)`, and 84 Java tests that pin its representation (`toBinaryString`, `scale`, `isNormal`). |
| `ryu` | not used | — | `printDecimal` is not shortest-representation printing: it searches precisions from the format's minimum and reads the text back; `std`'s exact formatting and correctly rounded parsing do it. |

Hand-written although crates exist nearby, with the reason: `Decimal`
(above); `round_to_f64` in `float/convert.rs` (correctly rounded big
integer → float with a sticky bit and subnormal handling — `num-bigint`'s
`to_f64` has no sticky-bit input, which the decimal → binary conversion
needs).

## Follow-ups for the next wave

- `bk-pcode` depends on no other `bk-*` crate. Sizes are plain `u32` byte
  counts; if `bk-core` defines a size newtype, the entry points are the
  place to adopt it.
- The emulator needs a decision on x87 infinities and subnormals (Java's
  decoding is kept; real x87 infinities decode as NaN).
- The decompiler's printing of float constants should call
  `FloatFormat::print_decimal` after handling NaN and infinity itself, as
  `printc.cc` does.
- Proposed ADR: "NaN signs and out-of-range float→int conversions are
  host-independent in basilisk" (recording the choice made here), since it
  affects differential tests against a reference `decomp` built on x86-64.

## Final state at handover

`CARGO_BUILD_JOBS=2 cargo test -p bk-pcode`, run by me after both helper
subagents had stopped: every binary `ok`, 247 tests, none ignored.

| Test binary | Tests | Ports | Written by |
|---|---:|---|---|
| unit tests in `src` | 69 | includes `testmultiprec.cc` (5) | first agent |
| doctest (`lib.rs`) | 1 | — | first agent |
| `tests/cpp_floatemu.rs` | 31 | `testfloatemu.cc`, all 31 | first agent |
| `tests/java_bigfloat.rs` | 27 | `BigFloatTest`, all 26 (+1 RNG check) | first agent |
| `tests/behavior.rs` | 20 | derived | first agent |
| `tests/java_opbehavior_int_arith.rs` | 20 | `OpBehavior{Int2Comp,IntAdd,IntAnd,IntCarry,IntDiv,IntMult,IntNegate,IntOr,IntRem}Test` | subagent |
| `tests/java_opbehavior_int_shift_cmp.rs` | 14 | `OpBehavior{IntLeft,IntRight,IntSRight,IntLess,IntLessEqual,IntSLess,IntSLessEqual}Test` | subagent |
| `tests/java_opbehavior_bool_misc.rs` | 12 | `OpBehavior{BoolAnd,BoolNegate,BoolOr,BoolXor,Lzcount,Popcount}Test` | subagent |
| `tests/java_floatformat_encoding.rs` | 11 | `FloatFormatTest`: the encoding, below-minimum-subnormal, max/min value and midpoint-rounding methods | subagent |
| `tests/java_floatformat_roundtrip.rs` | 6 | `FloatFormatTest`: `testGetHostFloat*`, `testBigFloat*FormatRandom`, `testBigFloatTo{Double,Float}Encoding` | subagent |
| `tests/java_floatformat_ops_long.rs` | 18 | `FloatFormatTest`: the 18 `testOp…Long…` methods | subagent |
| `tests/java_floatformat_ops_big.rs` | 18 | `FloatFormatTest`: the 18 `testOp…BigInteger…` methods | subagent |

**Ported Ghidra tests**

- `unittests/testfloatemu.cc`: 31 of 31. Marked.
- `unittests/testmultiprec.cc`: 5 of 5. Marked.
- `BigFloatTest`: 26 of 26. Marked.
- `OpBehavior*Test`: **22 of 40 classes** (46 of 82 methods). **Not
  ported: the 18 `OpBehaviorFloat*Test` classes** — `Abs`, `Add`, `Ceil`,
  `Div`, `Equal`, `Float2Float`, `Floor`, `Int2Float`, `LessEqual`, `Less`,
  `Mult`, `Nan`, `Neg`, `NotEqual`, `Round`, `Sqrt`, `Sub`, `Trunc`. Not
  marked in the inventory (mark the 22 only after checking them).
- `FloatFormatTest`: **53 of 58 methods**. **Not ported:**
  `testValueOfBigInteger`, `testValueOfBigDecimal`,
  `testValueOfDecimalString`, `testDoubleDecodeWithToString`,
  `testFloatDecodeWithToString`. Not marked.

**What the subagents reported** (I ran their tests; I have **not** read
their test files line by line against the Java — that review is item 2 of
"Remaining"):

- No Java expectation failed for a reason outside the documented
  differences; no test is `#[ignore]`d.
- Rows that assert basilisk's value instead of Java's, each with a
  `// Java: …` comment: three `INT_DIV`-by-zero rows (`int_div_*` in
  `java_opbehavior_int_arith.rs`; Java expects 0, basilisk
  `DivideByZero`), and `op_round(-2.5)` in `test_op_round_long`
  (`java_floatformat_ops_long.rs`; Java -2.0, basilisk -3.0). The exact
  level's `test_op_round_big_integer` keeps Java's -2.0 and passes.
- The Java classes `OpBehaviorIntSLessTest` and
  `OpBehaviorIntSLessEqualTest` are swapped in Ghidra: each tests the
  other's operation. The port keeps the Java class name in the test name
  and tests the operation the Java class really tests.
- `OpBehaviorIntMultTest.testEvaluateBinaryLong` has two
  `assertEquals(long, long, 4|8)` calls that resolve to JUnit's
  delta comparison (a typo for a byte size); the port asserts the exact
  values.
- Wide-path sizes: Java rows written `(sizeout=1, sizein=16)` and compared
  at 16 bytes are ported as `(16, 16)`; a few `(8, 8)` rows with 16-byte
  operands likewise. Each test says so in a comment.
- The integer tables were generated from the Java with a one-off script
  and then hand-edited; row counts equal the Java `assertEquals` counts.
- Their notes for the unported float classes (from reading the Java, not
  run): `FloatRound` long expects -2.0 for -2.5 (basilisk: -3.0, the
  documented difference); `FloatAbs`/`FloatCeil`/`FloatDiv` long first
  cases call `FF8.op…` directly; `FloatInt2Float` long passes `-2` as an
  unclean 64-bit pattern with `size_in` 4 and checks the upper 32 result
  bits are zero; `FloatSqrt` compares decimal text (`Double.toString`
  prefix, and `FF8.round(result).toString()` →
  `round_decimal(..).to_string()`); `FloatTrunc` BigInteger compares
  against negative `BigInteger`s (compare two's complement at 8 bytes).
- For the five unported `FloatFormatTest` methods: `BigDecimal.valueOf(d)`
  inputs must be carried as Java `Double.toString` literals
  (`2.123456789`, `2.1234567890123457`, `2.1234567890123457E123`,
  `2.1234567890123458E-123`, `1.7976931348623157E308`, `4.9E-324` — taken
  from shortest-repr digits, not from running Java);
  `doTestValueOfBigDecimal` compares two private binary renderings, for
  which comparing `encode_big_float(&bf)` with the native double's bits is
  the equivalent.

**Known lint failure**: `cargo clippy -p bk-pcode --all-targets -- -D
warnings` (run by both subagents after `tests/behavior.rs` was added)
fails at `crates/bk-pcode/tests/behavior.rs:326` — "using decimal literal
for bitwise operation" (`10_000_000_000u64 & 0xffff_ffff`). Not fixed.
The subagents report their own seven files clean under clippy; I did not
re-run it.

**File sizes** over the 600-line guideline (all under the gate's 1,000):
`tests/behavior.rs` 963, `tests/java_opbehavior_int_arith.rs` 675,
`src/float/encode.rs` 655, `src/float/host.rs` 613.

**Not done at all**: property tests, benchmarks (`docs/PERF.md` untouched),
the full gate, the merge of `master`.
