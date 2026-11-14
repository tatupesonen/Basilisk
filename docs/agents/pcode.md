# Track `pcode` — final status report

Crate `bk-pcode`: p-code opcodes, the arithmetic of every p-code
operation at every operand size, float formats, multiprecision helpers.
Spec: `docs/features/pcode.md`. Branch `pcode`, worktree
`/Users/tatu/slop/basilisk-wt/pcode`. Two agents worked on it: the first
wrote the library and part of the tests and stopped at a checkpoint; the
second (this report) merged `master`, reviewed the work against Ghidra, and
finished the track.

Wording: **ran** = executed and the result seen; **read** = concluded from
reading source, not executed.

## Built

`crates/bk-pcode` (no dependency on other `bk-*` crates):

| Module | What | Ghidra |
|---|---|---|
| `opcode` | `OpCode` (`#[repr(u8)]`, Ghidra's values, 73 operations), `name()` (C++ `get_opname`), `mnemonic()` (Java), `from_name`, `from_mnemonic`, `TryFrom<u8>`, `boolean_flip()`, `is_unary()`, `is_special()` | `opcodes.cc`, `PcodeOp.java`, `typeop.cc` flips |
| `error` | `EvalError` with Ghidra's messages | — |
| `mask` | `calc_mask`, `sign_extend`, `sign_extend_bit`, `zero_extend_bit`, `uintb_negate`, `byte_swap`, … | `address.cc`, `Utils.java` |
| `behavior` | `evaluate_unary/binary/ternary`, `recover_input_unary/binary` on `u64` (one `match`, no allocation) | `opbehavior.cc` |
| `behavior::wide` | `evaluate_unary/binary` on `Wide` (≤ 64 bytes) | Java `BigInteger` behaviours |
| `wide` | `Wide`, 512-bit unsigned on `primitive_types::U512` | — |
| `float` | `FloatFormat` (2, 4, 8, 10, 16, 32 bytes), `FloatFormats` table; host level (`float.cc` through `f64`); exact level (`BigFloat`, `Decimal`, decimal text) | `float.cc`, `FloatFormat.java`, `BigFloat.java` |
| `multiprecision` | the `multiprecision.cc` helpers on `u128` | `multiprecision.cc` |

API notes for the next tracks are under "Follow-ups".

## Tests

`CARGO_BUILD_JOBS=2 cargo test -p bk-pcode` (ran): **336 passed, 0
failed, 4 ignored** (the benchmarks).

| Kind | Binary | Tests |
|---|---|---:|
| unit (next to the code) | `src/**` | 69 |
| doctest | `lib.rs` | 1 |
| ported C++ | `cpp_floatemu.rs` (`testfloatemu.cc`) | 31 |
| ported C++ | `multiprecision.rs` `tests` (`testmultiprec.cc`, in the 69 unit tests) | 5 (+1) |
| ported Java | `java_bigfloat.rs` (`BigFloatTest`) | 27 |
| ported Java | `java_floatformat_{encoding,roundtrip,ops_long,ops_big,valueof}.rs` (`FloatFormatTest`) | 58 |
| ported Java | `java_opbehavior_{int_arith,int_shift_cmp,bool_misc}.rs` (22 classes) | 46 |
| ported Java | `java_opbehavior_float_{arith,cmp,conv}.rs` (18 classes) | 36 |
| differential | `cpp_oracle.rs`: 87,176 evaluations by Ghidra's compiled C++ | 1 |
| derived | `behavior_{integer,float,interface,wide}.rs` | 20 |
| property | `properties_int.rs` (4,096 cases each) | 27 |
| property | `properties_float.rs` (4,096 cases each) | 16 |
| property | `properties_robust.rs` (never panics) | 4 |
| benchmark | `bench.rs` (`#[ignore]`) | 4 |

**Ghidra tests ported and marked** (all listed in the spec):
`testfloatemu.cc` 31/31 and `testmultiprec.cc` 5/5
(`docs/inventory/tests/decompiler-cpp.md`); `BigFloatTest` 26/26 and
`FloatFormatTest` 58/58 (`framework-softwaremodeling.md`); all 40
`OpBehavior*Test` classes, 82 methods (`framework-emulation.md` — they live
in `Framework/Emulation`, not `SoftwareModeling` as the spec said). None
marked not applicable.

### Review of the ports written by helper subagents (unreviewed before)

How: two independent reviewer agents, read-only, each compared every Java
`@Test` with its Rust counterpart assertion by assertion, one with a script
that extracts and evaluates the Java and Rust assertions and diffs them row
by row plus reading each method side by side, the other by reading; I
spot-checked rows myself. Results:

- **`OpBehavior*Test` (22 classes, 46 methods): all matched.** Every Java
  assertion has a Rust row with the same inputs, sizes and expected value;
  no sign errors, truncated hex or swapped operands; no dropped cases. The
  only differing expectations are the three `INT_DIV`-by-zero rows (Java 0,
  basilisk `DivideByZero`), each with a `// Java:` comment — the documented
  difference. Confirmed: Ghidra's `OpBehaviorIntSLessTest` and
  `OpBehaviorIntSLessEqualTest` each test the other's operation (ported as
  they really test); `OpBehaviorIntMultTest` has two `assertEquals(long,
  long, 4|8)` that JUnit resolves to the delta overload — the port asserts
  the exact products, which were recomputed and are correct. Size
  conversions of the `BigInteger` rows (`sizeout` 1 compared at 16 bytes →
  `(16, 16)`) are each sound: those Java overloads never truncate.
- **`FloatFormatTest` (53 methods ported then): all matched.** Same inputs,
  random seeds and iteration counts (2,000 and 1,017-value loops included);
  the reimplemented `java.util.Random` is checked against the JDK. The only
  differing expectation is `op_round(-2.5)` on the host level (Java -2.0,
  basilisk -3.0: the C++ `round()`), documented. The list of 5 unported
  methods was exactly right.
- The **18 `OpBehaviorFloat*Test` classes and the last 5 `FloatFormatTest`
  methods** were ported in this session by a helper agent, which compiled
  Ghidra's real `FloatFormat`/`BigFloat`/behaviour classes and the original
  Java tests on a JDK outside the repository (all 41 Java methods pass
  there) and used those runs for extra literal checks. Assertion counts
  equal the Java's. Rows differing from Java: `FLOAT_ROUND(-2.5)` on the
  u64 path (documented), and two `FLOAT_TRUNC` `BigInteger` rows where Java
  compares a negative `BigInteger` and the wide path returns the same value
  cut to 8 bytes (representation only). No mismatch had to be `#[ignore]`d.
  I read the `Trunc` and `Less` ports against the Java myself.

## Differences from Ghidra — verdicts

Each was checked against the C++/Java it cites, and the C++ ones against
Ghidra's compiled code (`tests/cpp_oracle.rs`: an oracle program linked
against the reference build's `libsla.a` evaluated 87,176 cases on
AArch64; basilisk agrees with every row except the explained classes
below). Full text in the spec, section 8.

| Difference | Description accurate? | Verdict |
|---|---|---|
| Created NaN positive (u64 path) | Yes (x86-64 negative, AArch64 positive) | **Changed to negative (x86-64).** Ghidra's data test `datatests/floatprint.xml` folds `0.0f/0.0f` and expects `-NAN`; the reference build on AArch64 fails that test (`STAMP`: `Float print #6`, `#13`). The decompiler's output visibly depends on it, and the tested behaviour is x86-64's. |
| `TRUNC` out of range saturates (u64 path) | Yes (x86-64 `i64::MIN`, AArch64 saturates) | **Kept.** Java's `(long)` cast saturates and `FloatFormatTest.testOpTruncLongInt` / `OpBehaviorFloatTruncTest` pin it; no C++ test pins x86-64's value. I first switched it to x86-64 and reverted when the Java tests showed this. A differential test against a reference `decomp` built on x86-64 will differ for out-of-range constants. |
| Subnormal rounding up to smallest normal | Yes — the C++ returns a signed zero (seen in the differential run, both hosts mask the shift) | **Kept** as a fix of a rounding bug no test pins (3 rows in the oracle). |
| Shift counts modulo 64 for sizes 0 / > 8 | Yes | Kept; the oracle agrees at sizes 0–8. |
| `recover_input_binary` of a shift by 0 at 8 bytes | Yes — the C++ reports "not in range" on AArch64 too, not only x86-64 as the first agent wrote | **Kept** as a fix (only caller: jump-table recovery); 10 rows in the oracle. |
| `INT_SEXT` with `size_out < size_in` / size 0 | Not listed before; the first agent returned the input unchanged ("as Java") | **Reverted to Ghidra**: the differential run found 280 differing rows; `mask::sign_extend` now computes the C++ formula with shifts modulo 64, as both hosts do. |
| `INT_DIV` by zero → error, also on the wide path | Yes (C++ throws; Java returns 0 for `INT_DIV` only) | Kept; consistent with `SDIV`/`REM`/`SREM`, which Java also throws on. |
| `FLOAT_ROUND`: C++ `round()` on u64 path, Java `floor(x+0.5)` on the wide path | Yes | Kept (spec: C++ wins ≤ 8 bytes; the Java test pins -2 on the exact path). |
| `PIECE`, `SUBPIECE`, shift-size, `INT_LESS` masking disagreements | Yes (read) | Kept: u64 = C++ (oracle agrees). |
| Exact-path comparisons IEEE (Java: `+0 == -0` false, `x < NaN` true, `NaN <= NaN` true) | Yes — `opEqual` handles NaN correctly, `opLess`/`opLessEqual` use `compareTo`'s total order, `equals` distinguishes zero signs | Kept as a bug fix; no Java test pins the buggy values (both reviewers checked). |
| x87 rounding carry fixed | Yes — the carry test `leadBit(fraction) > frac_size` never fires for x87 and bit 64 is OR-ed into the exponent | Kept as a bug fix. |
| Java quirks kept (positive NaN on the exact path, `TRUNC` of infinity by the float's size, truncating `INT2FLOAT` for 2/10/16/32 bytes, no x87 subnormals, x87 infinity decoding as NaN, `1E+10.0`) | Spot-checked (`opTrunc(BigInteger)`, x87 decode) | Kept: defined Java behaviour, the emulator reference. |
| `printDecimal` | — | Kept; note that with libc++ (macOS) Ghidra itself prints `1.7976931348623157e+308` for `DBL_MAX` and fails its `double_decimal_precision` test (ran `decomp_test`); basilisk follows the test (libstdc++). |

## Benchmarks

Ran on an Apple M1 Pro, release, with other agents' builds running;
numbers and command in `docs/PERF.md`:

    CARGO_BUILD_JOBS=2 cargo test -p bk-pcode --release --test bench -- --ignored --nocapture --test-threads=1

`evaluate_binary` integer mix 2.4 ns/op vs 2.0 native (1.2×); `encoding`
5.9–8.8 ns, `host_float` 2.9–3.0 ns, host `op_add` 8.4/13.7 ns (binary32/64);
wide integer ops 6–28 ns at 16 and 64 bytes; exact-level float ops 216–630
ns at 8 and 16 bytes (allocates, as Java's `BigFloat` does).

## Gaps (stated plainly)

- **x86-64 not exercised.** Everything ran on macOS AArch64 only. The
  code paths are host-independent by construction (no host FPU sign or
  cast is observable: NaN signs and `TRUNC` are computed explicitly), but
  no run on x86-64 has confirmed that. The oracle table records AArch64's
  C++ results; on x86-64 the "created NaN" rows would match exactly and the
  out-of-range `TRUNC` rows would differ (see the verdicts).
- No property test compares the exact level at 10/16/32 bytes with an
  independent implementation (`rustc_apfloat` as a dev-only oracle was
  considered, not done); those sizes rest on `BigFloatTest`'s algorithms
  being checked at 24/53 bits, the round-trip property for every format,
  and hand-written constants.
- `to_decimal_string` for the 32-byte format at extreme exponents expands
  ~80,000 digits before rounding (as Java does): ~0.1 s per call. Bounded,
  but slow; not optimised.
- `tests/java_opbehavior_int_arith.rs` is 678 lines (ported test vectors;
  under the 1,000 limit, over the 600 guideline). Left as is.
- Opcode count: the spec's acceptance says 74 operations; Ghidra has 73
  (corrections note in the spec). All 73 match.
- `docs/PLAN.md`/`PARITY.md` not touched (coordinator's files).

## Follow-ups

- **SLEIGH runtime / emulator**: use `behavior::evaluate_*` for operands
  ≤ 8 bytes and `behavior::wide::evaluate_*` above (up to 64 bytes; above
  is `EvalError::UnsupportedSize`). Pass a `FloatFormats` table built from
  the language (`FloatFormats::DEFAULT` = 4 and 8, `IEEE` = all six;
  `with(format)` to add). The wide path returns results cut to `size_out`.
  `PTRADD`/`PTRSUB` evaluate (TypeOp wiring); the emulator's
  `registerInstructions` leaves them unimplemented — decide which the
  emulator wants. The emulator needs a decision on x87 infinities and
  subnormals (Java's decoding is kept).
- **Decompiler**: constant folding = the u64 path; jump-table recovery =
  `recover_input_*`; float constant printing = `FloatFormat::print_decimal`
  after handling NaN (`-NAN` for the negative NaN this crate creates) and
  infinity as `printc.cc` does. Errors carry Ghidra's messages.
  `multiprecision` has the `u128` helpers for M3's division rules.
- Sizes are plain `u32` byte counts; adopt `bk-core`'s size newtype at the
  entry points if one appears.
- **Proposed ADR**: "Where Ghidra's C++ result depends on the host,
  basilisk takes x86-64's (the platform Ghidra's tests are written for),
  unless a Ghidra test pins another value" — currently that is the created
  NaN sign (x86-64) and `TRUNC` (Java's pinned saturation). This matters
  for differential tests against a reference build: the reference on
  AArch64 fails `floatprint.xml` #6/#13 and `double_decimal_precision`.
- The oracle (`tests/oracle/opbehavior_oracle.cc`, `regen.sh`) can be run
  on an x86-64 reference build to produce an x86-64 table.
- `flate2` was added as a dev-dependency of `bk-pcode` (already a
  workspace dependency) to read the gzip-compressed oracle table.

## Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` (ran, on the
commit before this report) — exit **0**; file-size, unsafe, fmt, clippy,
rustdoc and `cargo deny` (`bans ok, licenses ok, sources ok`) passed; last
line `tests: 336 passed, 0 failed`.

## Commits

See `git log --oneline master..HEAD`.

---

# Track `x86-oracle` (2026-11-14)

Make the x86-64 Linux table of Ghidra's C++ results the oracle and make
`bk-pcode` follow it on every host (ADR-021, ADR-029, ADR-032). Branch
`x86-oracle`, worktree `/Users/tatu/slop/basilisk-wt/x86-oracle`.

## Status

Done: classification, product fix, table replaced, generator fixed, host
independence test, docs. Gate green (exit 0). Next (coordinator):
regenerate the table on x86-64 with the fixed generator (command below).

## What was measured (ran)

- The two tables (AArch64 checked in before, x86-64 from
  `../reference-x86_64/opbehavior_cpp.x86_64.txt.gz`) have 87,176 lines
  each, 82,156 distinct inputs each, 77,148 common; 161 common inputs give
  different results: `B 2f` 28, `B 30` 16, `B 31` 40, `B 32` 4, `U 35` 23,
  `U 38` 50. Not all are NaN signs: the 50 `U 38` (`FLOAT_TRUNC`) rows are
  `i64::MIN` (x86-64) against saturation (AArch64).
- The inputs differ only in rows whose random operands are drawn inside
  one argument list: 4,848 binary rows with the two operands swapped and
  160 `PTRADD` rows with the three draws reversed. GCC evaluated those
  arguments right to left, clang left to right.
- Replaying the x86-64 table unchanged: 106 unexplained rows,
  `SubnormalRoundsToNormal: 3`, `RecoverShiftByZero: 10`, as the
  coordinator measured.

## The 106 rows: classes and rules

1. **Two NaN inputs of opposite sign, `FLOAT_ADD`/`FLOAT_MULT`, 48 rows**
   (12 per op and size 4/8). x86-64 gives the quiet NaN with the sign of
   the *second* input; basilisk gave the first's. Over all two-NaN rows of
   the table (12 opposite-sign + 13 same-sign per op and size), x86-64
   is: ADD, MULT → sign of `b`; SUB, DIV → sign of `a`; AArch64 → sign of
   `a` for all four. One NaN input → its sign (both hosts, every row).
   Why (read): `getHostFloat` decodes any NaN to the host's
   `quiet_NaN()` with the encoding's sign, so payloads and the
   signalling bit are gone before the arithmetic and the result is always
   the format's quiet NaN, with only the sign varying (`getEncoding` →
   `getNaNEncoding(sign)`). SSE2 `addsd`/`mulsd`/`subsd`/`divsd` with two
   NaN operands return the first source operand (the destination
   register). For `val1 + val2` and `val1 * val2` GCC is free to swap the
   operands and uses `val2`, which the second `getHostFloat` call has just
   returned in `xmm0`, as the destination; for `-` and `/` it cannot. The
   table's rows are the evidence; the register allocation is inference
   (no x86-64 object code was available to disassemble).
   **Rule now in `bk-pcode`** (`src/float/host.rs`, `NanPriority`): a NaN
   result takes the sign of the first NaN in the order (`b`, `a`) for ADD
   and MULT and (`a`, `b`) for SUB and DIV, and is negative when no input is
   a NaN; computed explicitly from the inputs' bits, never taken from the
   host's arithmetic.
2. **`FLOAT_TRUNC` of a NaN or a value outside `i64`, 58 rows.** x86-64's
   `cvttsd2si` gives `0x8000_0000_0000_0000`, then cut to the output size
   (so 0 at sizes 1/2/4 for a positive overflow, and `i64::MIN` at size 8
   for NaN). basilisk saturates and maps NaN to 0. **Not changed**: ADR-021
   says so explicitly, because Ghidra's Java tests pin saturation
   (`FloatFormatTest.testOpTruncLongInt`, `OpBehaviorFloatTruncTest`) and
   the ported tests assert it on the `u64` path. It is now an explained
   class, `TruncSaturates`, recognised narrowly (input outside
   `[-2^63, 2^63)` or NaN, C++ = `i64::MIN & mask`, basilisk = saturated
   `& mask`).

## What changed in the product

- `FloatFormat::op_add`/`op_mult`: two-NaN sign from `b` (above). SUB/DIV
  unchanged. Every host gives the same bits: NaN signs were already
  computed explicitly (`settle_nan`); only the priority order changed.
- `op_ceil`/`op_floor` use `libm::ceil`/`libm::floor` instead of
  `f64::ceil`/`f64::floor`, which on baseline x86-64 (no SSE4.1) and with
  MSVC/MinGW call the C library. (Results were not seen to differ; this
  removes the dependence, as `op_round` did.)
- `BigFloat::to_f32` returns `f32::NAN` for a NaN explicitly instead of
  converting `f64::NAN` with `as`, whose NaN sign/payload Rust does not
  guarantee across targets.
- **Wide and exact paths**: not changed. They follow Java's `BigFloat`
  (authoritative for wide operands, spec 4.2), which has no NaN sign:
  every NaN result is the positive quiet NaN, for two NaN inputs too. This
  is defined behaviour, not the host's; the new test pins it at 4, 8 and
  16 bytes. Java and C++ therefore disagree on two-NaN signs (and on
  created NaNs); each path follows its authority, as before.
- Java-derived tests: all still pass unchanged except one assertion in
  `src/float/host_tests.rs` (`op_mult(+NaN, -NaN)` was `+NaN`, the AArch64
  value, now `-NaN`) and the NaN rule of `tests/properties_float.rs`
  (expected sign for ADD/MULT now from (`b`, `a`)); neither is a Java
  port. No Java test pins a two-NaN sign.

## Oracle table and test

- `tests/data/opbehavior_cpp.txt.gz` is the x86-64 table, byte for byte
  the file in `../reference-x86_64/`. `tests/data/README.md` gives the
  provenance (Ghidra `42db038f3c`, GCC 14.4.0, Linux x86_64, 2026-11-14,
  x86-64 reference build; the build's `STAMP` says `ghidra_commit:
  unknown`, the commit is the one ADR-029 states both builds used).
- `tests/cpp_oracle.rs`: the "created NaN sign" class is removed; the
  classes are `TruncSaturates` 58, `SubnormalRoundsToNormal` 3,
  `RecoverShiftByZero` 10, **0 unexplained**, and the test now fails if any
  class stops occurring.

## Explained differences that remain, and why

- `TruncSaturates` (58): ADR-021, Java tests pin saturation.
- `SubnormalRoundsToNormal` (3): the C++ returns zero for a subnormal that
  rounds up to the smallest normal ("TODO handle round to normal case",
  both hosts); basilisk rounds correctly, as Java does.
- `RecoverShiftByZero` (10): the C++ shifts by 64 and reports a shift by 0
  of an 8-byte value as not invertible; basilisk returns the output.
All three are in `docs/features/pcode.md`, section 8.

## Generator

`tests/oracle/opbehavior_oracle.cc` draws every random operand in its own
statement (`random_pair`, and the `PTRADD` loop), in the order GCC used,
last operand first. Built here against `../reference` (Apple clang 17,
macOS AArch64) and run: **its 87,176 inputs equal the checked-in x86-64
table's line for line** (0 input lines differ); 171 result lines differ,
all in `B 2f/30/31/32`, `U 35`, `U 38`, i.e. exactly the host-dependent
classes above plus created NaN signs. The checked-in table was not
replaced with the Mac's.

**Still to do (coordinator, on the x86-64 box)**: regenerate with the
fixed generator and confirm it is identical to the checked-in table:

    crates/bk-pcode/tests/oracle/regen.sh <x86-64-reference-dir>
    gzip -dc crates/bk-pcode/tests/data/opbehavior_cpp.txt.gz | cmp - <(git show HEAD:crates/bk-pcode/tests/data/opbehavior_cpp.txt.gz | gzip -dc)

(`<x86-64-reference-dir>` is the `scripts/build-reference.sh` output with
`src/cpp/libsla.a` and `src/zlib/libz.a`; compare decompressed text, the
gzip bytes depend on the gzip build.) Expected: no output from `cmp`.

## Host-independence test

`tests/host_independence.rs`: 188 directed rows with literal expected bits
at 4 and 8 bytes — `FLOAT_ADD/SUB/MULT/DIV` with quiet/signalling NaNs of
both signs in both positions, NaN with a number, created NaNs (`inf-inf`,
`0/0`, `0*inf`); `SQRT/CEIL/FLOOR/ROUND/NEG/ABS/NAN` of NaNs and of -1;
`FLOAT2FLOAT` of NaNs both ways; comparisons with NaN and `+0 == -0`;
`ROUND(0.49999999999999994)`; `INT2FLOAT` of the most negative integers.
Every expected value is x86-64's, and a second test checks each against
the oracle table so the two cannot drift. Plus 8 `FLOAT_TRUNC` rows with
basilisk's saturated values (x86-64's in comments) and the wide path's
positive NaN at 4, 8, 16 bytes. Before the fix, the `u64` rows with two
NaNs failed (they pinned the first operand's sign). CI runs it on Linux
x86-64, macOS AArch64 and Windows.

## Where `bk-pcode` touches the host's arithmetic (audit)

Production code only (`src/`):

| Place | What | Host-dependent? |
|---|---|---|
| `host.rs` `binary`/`unary` (`+ - * /`, `f64::sqrt`) | IEEE ops, correctly rounded on all targets; NaN *results* have unspecified sign/payload in Rust | Settled: `settle_nan` replaces every NaN result |
| `host.rs` `op_ceil`/`op_floor` | were `f64::ceil`/`floor` (C library on baseline x86-64, MSVC, MinGW) | Changed to `libm` |
| `host.rs` `op_round` | `libm::round` (earlier track) | No |
| `host.rs` `op_neg`/`op_abs`, `encoding` (`host.abs()`) | sign-bit operations, guaranteed bitwise by Rust | No |
| `host.rs` `op_trunc` (`f64 as i64`) | Rust saturating cast, defined | No (deliberately not x86-64) |
| `host.rs` `op_int2float` (`i64 as f64`) | round to nearest, defined | No |
| `host.rs` `create_float`, `convert.rs` | `libm::ldexp` | No |
| `bigfloat.rs` `to_f32`, `decimal.rs` `to_f32`, `encode.rs` (`f64 as f32`) | finite values already on the `f32` grid: exact | NaN case in `BigFloat::to_f32` made explicit; the other two never see a NaN |
| `encode.rs` `f64::from(scale10) / 0.3` | one IEEE division | No |
| `display.rs` | own decimal code, no C library printing | No |
| `bigfloat.rs` `to_f64` NaN | returns `f64::NAN` (a constant) | No |

Test code uses native `f32`/`f64` arithmetic as a reference only in
`properties_float.rs`, whose NaN expectation is computed, not taken from
the native result.

## Benchmarks (ran, Apple M1 Pro, release, other agents building)

`CARGO_BUILD_JOBS=2 cargo test -p bk-pcode --release --test bench -- --ignored --nocapture --test-threads=1`

| Benchmark | Before | After (2 runs) |
|---|---:|---:|
| `evaluate_binary` integer mix / native | 2.37 / 1.96 ns | 2.39 / 2.00, 2.38 / 1.99 |
| `encoding` f64 → binary32 | 6.72 | 8.01, 6.40 |
| `host_float` binary32 → f64 | 1.95 | 1.93, 1.94 |
| `op_add` host level, binary32 | 7.60 | 7.63, 7.77 |
| `encoding` f64 → binary64 | 5.45 | 5.64, 5.23 |
| `host_float` binary64 → f64 | 2.82 | 2.87, 2.80 |
| `op_add` host level, binary64 | 13.84 | 13.87, 13.81 |
| exact add/mult/div, 8 bytes | 209 / 241 / 278 | 212 / 246 / 290, 207 / 241 / 278 |
| exact add/mult/div, 16 bytes | 369 / 343 / 600 | 374 / 354 / 614, 382 / 344 / 619 |

No change beyond noise; `docs/PERF.md` not edited. `op_ceil`/`op_floor`
have no benchmark.

## Platforms

Ran on macOS AArch64: `cargo test -p bk-pcode` 339 passed, 0 failed (4
benchmarks ignored); `cargo clippy -p bk-pcode --all-targets -- -D
warnings` and the same with `--target x86_64-pc-windows-msvc` clean.
Linux x86-64 and Windows test runs rest on CI. Not run on x86-64 hardware.

## Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` (ran, on
commit `49c0e1d`): exit **0**; `bans ok, licenses ok, sources ok`; last
line `tests: 1711 passed, 0 failed`. No dependency added (`Cargo.lock`
unchanged).
