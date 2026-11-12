#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::float_cmp,
    reason = "test code"
)]
//! Ghidra's JUnit tests of the floating-point conversion and rounding
//! behaviours, ported from
//! `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorFloatCeilTest`, `OpBehaviorFloatFloorTest`,
//! `OpBehaviorFloatRoundTest`, `OpBehaviorFloatTruncTest`,
//! `OpBehaviorFloatFloat2FloatTest` and `OpBehaviorFloatInt2FloatTest`.
//!
//! Each Java `@Test` method (`testEvaluateBinaryLong`,
//! `testEvaluateBinaryBigInteger`) is one test here, named after the class
//! and the method, and each Java assertion is one table row, in the Java
//! order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`], with [`FloatFormats::DEFAULT`]. Java checks
//!   a float result with `assertEquals(double, double, 0)` (any NaN equals
//!   any NaN); each row checks that and, as an extra, the exact encoding.
//!   Every NaN expected here is propagated from a positive NaN input, so it
//!   is the positive quiet NaN.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that
//!   is the wide path, [`bk_pcode::behavior::wide`], with
//!   [`FloatFormats::IEEE`] (Java's `FloatFormatFactory`). Java compares
//!   `BigFloat`s and so do these tests; as an extra each row also checks the
//!   exact encoding. The wide path returns the result cut to `size_out`
//!   bytes, where Java returns a possibly negative `BigInteger`
//!   (`docs/features/pcode.md` section 8, "Structure"); that changes how
//!   two `FLOAT_TRUNC` expectations are written, not their value.
//!
//! Where basilisk deliberately differs from the Java, the row asserts
//! basilisk's result and a `// Java:` comment keeps the Java expectation.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{BigFloat, FloatFormat, FloatFormats, OpCode, Wide};

/// The formats of the `u64` path (the Java `long` overloads).
const FORMATS: FloatFormats = FloatFormats::DEFAULT;
/// The formats of the wide path (the Java `BigInteger` overloads).
const WIDE_FORMATS: FloatFormats = FloatFormats::IEEE;

const INF: f64 = f64::INFINITY;
const NEG_INF: f64 = f64::NEG_INFINITY;
/// Java's `Double.NaN` (and `Float.NaN` widened): the positive quiet NaN.
const NAN: f64 = f64::NAN;

/// `AbstractOpBehaviorTest.FF4` / `FF8`.
fn float_format(size: u32) -> FloatFormat {
    FloatFormat::ieee(size).unwrap()
}

/// JUnit's `assertEquals(expected, actual, 0)` for doubles: both NaN, or
/// equal as numbers (so the two zeros are equal).
#[track_caller]
fn assert_double(expected: f64, actual: f64, case: &str) {
    if expected.is_nan() {
        assert!(actual.is_nan(), "{case}: expected NaN, got {actual:e}");
    } else {
        assert_eq!(expected, actual, "{case}");
    }
}

/// Checks a float result of the `u64` path: Java's assertion
/// (`assertEquals(expected, ff.decodeHostFloat(result), 0)`), then the
/// exact encoding (extra).
#[track_caller]
fn assert_long_result(ff: &FloatFormat, expected: f64, result: u64, case: &str) {
    assert_double(expected, ff.host_float(result).0, case);
    assert_eq!(ff.encoding(expected), result, "{case}: encoding");
}

/// Runs an 8-byte unary float operation on the `u64` path: each row is
/// `(a, expected)`, the operand given as `FF8.getEncoding(double)`.
#[track_caller]
fn check_unary_long(op: OpCode, rows: &[(f64, f64)]) {
    let ff = float_format(8);
    for (row, &(a, expected)) in rows.iter().enumerate() {
        let result = behavior::evaluate_unary(op, 8, 8, ff.encoding(a), &FORMATS).unwrap();
        assert_long_result(&ff, expected, result, &format!("{op} row {row}: ({a:e})"));
    }
}

/// An operand or an expected result of the `BigInteger` tests, named as the
/// Java builds it.
#[derive(Debug, Clone, Copy)]
enum Val {
    /// `ff.getBigFloat(d)` / `ff.getEncoding(ff.getBigFloat(d))`.
    Num(f64),
    /// `ff.getBigZero(false)` / `ff.getBigZeroEncoding(false)`.
    Zero,
    /// `ff.getBigInfinity(false)` / `ff.getBigInfinityEncoding(false)`
    /// (or `ff.getEncoding(ff.getBigInfinity(false))`, the same encoding).
    Inf,
    /// `ff.getBigInfinity(true)` / `ff.getBigInfinityEncoding(true)`.
    NegInf,
    /// `ff.getBigNaN(false)` / `ff.getBigNaNEncoding(false)`.
    Nan,
}

use Val::{Inf, Nan, NegInf, Num, Zero};

impl Val {
    /// The encoding the Java test passes to an operation.
    fn encoding(self, ff: &FloatFormat) -> Wide {
        match self {
            Num(d) => ff.encode_big_float(&ff.big_float_from_f64(d).unwrap()),
            Zero => ff.big_zero_encoding(false),
            Inf => ff.big_infinity_encoding(false),
            NegInf => ff.big_infinity_encoding(true),
            Nan => ff.big_nan_encoding(false),
        }
    }

    /// The `BigFloat` the Java test expects a result to decode to.
    fn big_float(self, ff: &FloatFormat) -> BigFloat {
        match self {
            Num(d) => ff.big_float_from_f64(d).unwrap(),
            Zero => ff.big_zero(false),
            Inf => ff.big_infinity(false),
            NegInf => ff.big_infinity(true),
            Nan => ff.big_nan(false),
        }
    }
}

/// Checks a float result of the wide path: Java's assertion
/// (`assertEquals(expected, ff.decodeBigFloat(result))`), then the exact
/// encoding (extra).
#[track_caller]
fn assert_wide_result(ff: &FloatFormat, expected: Val, result: &Wide, case: &str) {
    assert_eq!(
        expected.big_float(ff),
        ff.decode_big_float(result),
        "{case}"
    );
    assert_eq!(expected.encoding(ff), *result, "{case}: encoding");
}

/// Runs an 8-byte unary float operation on the wide path: each row is
/// `(a, expected)`.
#[track_caller]
fn check_unary_wide(op: OpCode, rows: &[(Val, Val)]) {
    let ff = float_format(8);
    for (row, &(a, expected)) in rows.iter().enumerate() {
        let result = wide::evaluate_unary(op, 8, 8, &a.encoding(&ff), &WIDE_FORMATS).unwrap();
        assert_wide_result(&ff, expected, &result, &format!("{op} row {row}: ({a:?})"));
    }
}

/// `OpBehaviorFloatCeilTest.testEvaluateBinaryLong`.
#[test]
fn float_ceil_evaluate_binary_long() {
    // Java's first assertion calls `FF8.opCeil` directly, not the behaviour.
    let ff = float_format(8);
    let result = ff.op_ceil(ff.encoding(2.5));
    assert_long_result(&ff, 3.0, result, "opCeil(2.5)");

    check_unary_long(
        OpCode::FloatCeil,
        &[(-2.5, -2.0), (INF, INF), (NEG_INF, NEG_INF), (NAN, NAN)],
    );
}

/// `OpBehaviorFloatCeilTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_ceil_evaluate_binary_big_integer() {
    check_unary_wide(
        OpCode::FloatCeil,
        &[
            (Num(2.5), Num(3.0)),
            (Num(-2.5), Num(-2.0)),
            (Inf, Inf),
            (NegInf, NegInf),
            (Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatFloorTest.testEvaluateBinaryLong`.
#[test]
fn float_floor_evaluate_binary_long() {
    check_unary_long(
        OpCode::FloatFloor,
        &[
            (2.5, 2.0),
            (-2.0, -2.0),
            (-2.5, -3.0),
            (INF, INF),
            (NEG_INF, NEG_INF),
            (NAN, NAN),
        ],
    );
}

/// `OpBehaviorFloatFloorTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_floor_evaluate_binary_big_integer() {
    check_unary_wide(
        OpCode::FloatFloor,
        &[
            (Num(2.5), Num(2.0)),
            (Num(-2.0), Num(-2.0)),
            (Num(-2.5), Num(-3.0)),
            (Inf, Inf),
            (NegInf, NegInf),
            (Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatRoundTest.testEvaluateBinaryLong`.
#[test]
fn float_round_evaluate_binary_long() {
    check_unary_long(
        OpCode::FloatRound,
        &[
            (2.5, 3.0),
            (2.25, 2.0),
            (2.75, 3.0),
            // Java: -2.0 — on the u64 path FLOAT_ROUND is the C++ `round()`,
            // halfway cases away from zero (pcode.md section 8).
            (-2.5, -3.0),
            (-2.25, -2.0),
            (-2.75, -3.0),
            (INF, INF),
            (NEG_INF, NEG_INF),
            (NAN, NAN),
        ],
    );
}

/// `OpBehaviorFloatRoundTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_round_evaluate_binary_big_integer() {
    // The wide path follows Java's `floor(x + 0.5)`: round(-2.5) = -2.
    check_unary_wide(
        OpCode::FloatRound,
        &[
            (Num(2.5), Num(3.0)),
            (Num(2.25), Num(2.0)),
            (Num(2.75), Num(3.0)),
            (Num(-2.5), Num(-2.0)),
            (Num(-2.25), Num(-2.0)),
            (Num(-2.75), Num(-3.0)),
            (Inf, Inf),
            (NegInf, NegInf),
            (Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatTruncTest.testEvaluateBinaryLong`.
#[test]
fn float_trunc_evaluate_binary_long() {
    let ff = float_format(8);
    // (operand, the Java `long` expected, as its 64-bit pattern)
    let rows: [(f64, u64); 5] = [
        (2.5, 2),
        (-2.5, -2i64 as u64),
        (INF, i64::MAX as u64),
        (NEG_INF, i64::MIN as u64),
        // Java: "TODO: What should the correct result be?"; the u64 path
        // saturates and maps NaN to 0 like Java's `(long)` cast.
        (NAN, 0),
    ];
    for (row, (a, expected)) in rows.into_iter().enumerate() {
        assert_eq!(
            behavior::evaluate_unary(OpCode::FloatTrunc, 8, 8, ff.encoding(a), &FORMATS),
            Ok(expected),
            "row {row}: ({a:e})"
        );
    }
}

/// `OpBehaviorFloatTruncTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_trunc_evaluate_binary_big_integer() {
    let ff = float_format(8);
    let rows: [(Val, u64); 5] = [
        (Num(2.5), 2),
        // Java: BigInteger.valueOf(-2) — the wide path returns the result
        // cut to size_out (8) bytes, the same value.
        (Num(-2.5), -2i64 as u64),
        (Inf, i64::MAX as u64),
        // Java: BigInteger.valueOf(Long.MIN_VALUE) — cut to 8 bytes, as
        // above.
        (NegInf, i64::MIN as u64),
        // Java: "TODO: What should the correct result be?"
        (Nan, 0),
    ];
    for (row, (a, expected)) in rows.into_iter().enumerate() {
        assert_eq!(
            wide::evaluate_unary(OpCode::FloatTrunc, 8, 8, &a.encoding(&ff), &WIDE_FORMATS),
            Ok(Wide::from_u64(expected)),
            "row {row}: ({a:?})"
        );
    }
}

/// `OpBehaviorFloatFloat2FloatTest.testEvaluateBinaryLong`.
#[test]
fn float_float2float_evaluate_binary_long() {
    let (ff4, ff8) = (float_format(4), float_format(8));
    // (the `float` constant Java encodes with `FF4.getEncoding`, widened to
    // double as Java widens it, the double expected)
    let rows = [
        (1.75, 1.75),
        (-1.75, -1.75),
        (INF, INF),
        (NEG_INF, NEG_INF),
        (NAN, NAN), // propagated: keeps the positive sign
    ];
    for (row, (a, expected)) in rows.into_iter().enumerate() {
        let result =
            behavior::evaluate_unary(OpCode::FloatFloat2Float, 8, 4, ff4.encoding(a), &FORMATS)
                .unwrap();
        assert_long_result(&ff8, expected, result, &format!("row {row}: ({a:e})"));
    }
}

/// `OpBehaviorFloatFloat2FloatTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_float2float_evaluate_binary_big_integer() {
    let (ff4, ff8) = (float_format(4), float_format(8));
    // (operand in FF4, expected in FF8)
    let rows = [
        (Num(1.75), Num(1.75)),
        (Num(-1.75), Num(-1.75)),
        (Inf, Inf),
        (NegInf, NegInf),
        (Nan, Nan),
    ];
    for (row, (a, expected)) in rows.into_iter().enumerate() {
        let result = wide::evaluate_unary(
            OpCode::FloatFloat2Float,
            8,
            4,
            &a.encoding(&ff4),
            &WIDE_FORMATS,
        )
        .unwrap();
        assert_wide_result(&ff8, expected, &result, &format!("row {row}: ({a:?})"));
    }
}

/// `OpBehaviorFloatInt2FloatTest.testEvaluateBinaryLong`.
#[test]
fn float_int2float_evaluate_binary_long() {
    let ff4 = float_format(4);
    // (the Java `long` operand, as its 64-bit pattern, the double expected
    // from `FF4.decodeHostFloat`)
    let rows: [(u64, f64); 4] = [
        (2, 2.0),
        (-2i64 as u64, -2.0),
        (0, 0.0),
        (0x0_ffff_ffff, -1.0),
    ];
    for (row, (a, expected)) in rows.into_iter().enumerate() {
        let result = behavior::evaluate_unary(OpCode::FloatInt2Float, 4, 4, a, &FORMATS).unwrap();
        // verify that only 4-bytes are used
        assert_eq!(0, result & 0xffff_ffff_0000_0000, "row {row}: ({a:#x})");
        assert_long_result(&ff4, expected, result, &format!("row {row}: ({a:#x})"));
    }
}

/// `OpBehaviorFloatInt2FloatTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_int2float_evaluate_binary_big_integer() {
    let ff4 = float_format(4);
    let limit = Wide::ONE << 32;
    // (the `BigInteger` operand, whether Java checks it against `limit`, the
    // `BigFloat` expected in FF4). `Wide` is unsigned: Java's
    // `BigInteger.valueOf(-2)` is written as its two's-complement pattern
    // (all 512 bits), which the operation reads as the 4-byte -2.
    let rows = [
        (Wide::from_u64(2), true, Num(2.0)),
        (Wide::from_u64(2).wrapping_neg(), true, Num(-2.0)),
        (Wide::ZERO, true, Zero),
        // `Utils.bytesToBigInteger({ff, ff, ff, ff}, 4, false, false)`:
        // unsigned, so 0xffffffff. Java does not check this one against
        // `limit`.
        (Wide::from_u64(0xffff_ffff), false, Num(-1.0)),
    ];
    for (row, (a, check_limit, expected)) in rows.into_iter().enumerate() {
        let result = wide::evaluate_unary(OpCode::FloatInt2Float, 4, 4, &a, &WIDE_FORMATS).unwrap();
        if check_limit {
            // verify that only 4-bytes are used
            assert!(result < limit, "row {row}: {result:?}");
        }
        assert_wide_result(&ff4, expected, &result, &format!("row {row}: ({a:?})"));
    }
}
