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
