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
//! Ghidra's JUnit tests of the floating-point arithmetic behaviours, ported
//! from `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorFloatAbsTest`, `OpBehaviorFloatAddTest`,
//! `OpBehaviorFloatDivTest`, `OpBehaviorFloatMultTest`,
//! `OpBehaviorFloatNegTest`, `OpBehaviorFloatSqrtTest` and
//! `OpBehaviorFloatSubTest`. (The comparisons are in
//! `java_opbehavior_float_cmp.rs`.)
//!
//! Each Java `@Test` method (`testEvaluateBinaryLong`,
//! `testEvaluateBinaryBigInteger`; the names are Java's, also for the unary
//! operations) is one test here, named after the class and the method, and
//! each Java assertion is one table row, in the Java order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`], with [`FloatFormats::DEFAULT`]. Java checks
//!   a float result with `assertEquals(double, double, 0)`, which lets any
//!   NaN equal any NaN and `+0` equal `-0`; each row checks that and, as an
//!   extra, the exact encoding. An expected NaN is therefore written with
//!   the sign Basilisk gives it: [`NEG_NAN`] for a NaN an operation creates
//!   (x86-64's default NaN), the sign of the first NaN input for a
//!   propagated one.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that
//!   is the wide path, [`bk_pcode::behavior::wide`], with
//!   [`FloatFormats::IEEE`] (Java's `FloatFormatFactory`). Java compares
//!   `BigFloat`s (`decodeBigFloat(result)`), and so do these tests; as an
//!   extra each row also checks the exact encoding. Java builds some
//!   operands as `getEncoding(getBigInfinity(false))` and others as
//!   `getBigInfinityEncoding(false)`; both are the same encoding, [`Inf`].
//!
//! No expectation here differs from the Java.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{BigFloat, FloatFormat, FloatFormats, OpCode, Wide};

/// The formats of the `u64` path (the Java `long` overloads).
const FORMATS: FloatFormats = FloatFormats::DEFAULT;
/// The formats of the wide path (the Java `BigInteger` overloads).
const WIDE_FORMATS: FloatFormats = FloatFormats::IEEE;

const INF: f64 = f64::INFINITY;
const NEG_INF: f64 = f64::NEG_INFINITY;
/// Java's `Double.NaN`: the positive quiet NaN.
const NAN: f64 = f64::NAN;
/// The negative quiet NaN, which the `u64` path gives for a NaN an
/// operation creates.
const NEG_NAN: f64 = f64::from_bits(0xfff8_0000_0000_0000);

/// `AbstractOpBehaviorTest.FF8`.
fn ff8() -> FloatFormat {
    FloatFormat::ieee(8).unwrap()
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
/// (`assertEquals(expected, FF8.decodeHostFloat(result), 0)`), then the
/// exact encoding (extra).
#[track_caller]
fn assert_long_result(ff: &FloatFormat, expected: f64, result: u64, case: &str) {
    assert_double(expected, ff.host_float(result).0, case);
    assert_eq!(ff.encoding(expected), result, "{case}: encoding");
}

/// Runs an 8-byte binary operation on the `u64` path: each row is
/// `(a, b, expected)`, the operands given as `FF8.getEncoding(double)`.
#[track_caller]
fn check_binary_long(op: OpCode, rows: &[(f64, f64, f64)]) {
    let ff = ff8();
    for (row, &(a, b, expected)) in rows.iter().enumerate() {
        let result =
            behavior::evaluate_binary(op, 8, 8, ff.encoding(a), ff.encoding(b), &FORMATS).unwrap();
        assert_long_result(
            &ff,
            expected,
            result,
            &format!("{op} row {row}: ({a:e}, {b:e})"),
        );
    }
}

/// Runs an 8-byte unary operation on the `u64` path: each row is
/// `(a, expected)`.
#[track_caller]
fn check_unary_long(op: OpCode, rows: &[(f64, f64)]) {
    let ff = ff8();
    for (row, &(a, expected)) in rows.iter().enumerate() {
        let result = behavior::evaluate_unary(op, 8, 8, ff.encoding(a), &FORMATS).unwrap();
        assert_long_result(&ff, expected, result, &format!("{op} row {row}: ({a:e})"));
    }
}

/// An operand or an expected result of the `BigInteger` tests, named as the
/// Java builds it.
#[derive(Debug, Clone, Copy)]
enum Val {
    /// `FF8.getBigFloat(d)` / `FF8.getEncoding(FF8.getBigFloat(d))`.
    Num(f64),
    /// `FF8.getBigZero(false)` / `FF8.getBigZeroEncoding(false)`.
    Zero,
    /// `FF8.getBigInfinity(false)` / `FF8.getBigInfinityEncoding(false)`.
    Inf,
    /// `FF8.getBigInfinity(true)` / `FF8.getBigInfinityEncoding(true)`.
    NegInf,
    /// `FF8.getBigNaN(false)` / `FF8.getBigNaNEncoding(false)`.
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
/// (`assertEquals(expected, FF8.decodeBigFloat(result))`), then the exact
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

/// Runs an 8-byte binary operation on the wide path: each row is
/// `(a, b, expected)`.
#[track_caller]
fn check_binary_wide(op: OpCode, rows: &[(Val, Val, Val)]) {
    let ff = ff8();
    for (row, &(a, b, expected)) in rows.iter().enumerate() {
        let (wide1, wide2) = (a.encoding(&ff), b.encoding(&ff));
        let result = wide::evaluate_binary(op, 8, 8, &wide1, &wide2, &WIDE_FORMATS).unwrap();
        assert_wide_result(
            &ff,
            expected,
            &result,
            &format!("{op} row {row}: ({a:?}, {b:?})"),
        );
    }
}

/// Runs an 8-byte unary operation on the wide path: each row is
/// `(a, expected)`.
#[track_caller]
fn check_unary_wide(op: OpCode, rows: &[(Val, Val)]) {
    let ff = ff8();
    for (row, &(a, expected)) in rows.iter().enumerate() {
        let result = wide::evaluate_unary(op, 8, 8, &a.encoding(&ff), &WIDE_FORMATS).unwrap();
        assert_wide_result(&ff, expected, &result, &format!("{op} row {row}: ({a:?})"));
    }
}

/// `OpBehaviorFloatAbsTest.testEvaluateBinaryLong`.
#[test]
fn float_abs_evaluate_binary_long() {
    // Java's first assertion passes `FF8.opAbs(a)`, not `a`, to the
    // behaviour.
    let ff = ff8();
    let a = ff.op_abs(ff.encoding(2.5));
    let result = behavior::evaluate_unary(OpCode::FloatAbs, 8, 8, a, &FORMATS).unwrap();
    assert_long_result(&ff, 2.5, result, "abs(abs(2.5))");

    check_unary_long(
        OpCode::FloatAbs,
        &[(-2.5, 2.5), (INF, INF), (NEG_INF, INF), (NAN, NAN)],
    );
}

/// `OpBehaviorFloatAbsTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_abs_evaluate_binary_big_integer() {
    check_unary_wide(
        OpCode::FloatAbs,
        &[
            (Num(2.5), Num(2.5)),
            (Num(-2.5), Num(2.5)),
            (Inf, Inf),
            (NegInf, Inf),
            (Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatAddTest.testEvaluateBinaryLong`.
#[test]
fn float_add_evaluate_binary_long() {
    check_binary_long(
        OpCode::FloatAdd,
        &[
            (1.234, 1.123, 2.357),
            (-1.123, 1.123, 0.0),
            (INF, 1.123, INF),
            (NEG_INF, 1.123, NEG_INF),
            (NEG_INF, NEG_INF, NEG_INF),
            (NEG_INF, INF, NEG_NAN), // created
            (NAN, 1.123, NAN),       // propagated
        ],
    );
}

/// `OpBehaviorFloatAddTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_add_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::FloatAdd,
        &[
            (Num(1.234), Num(1.123), Num(2.357)),
            (Num(-1.123), Num(1.123), Zero),
            (Inf, Num(1.123), Inf),
            (NegInf, Num(1.123), NegInf),
            (NegInf, NegInf, NegInf),
            (NegInf, Inf, Nan),
            (Nan, Num(1.123), Nan),
        ],
    );
}

/// `OpBehaviorFloatDivTest.testEvaluateBinaryLong`.
#[test]
fn float_div_evaluate_binary_long() {
    // Java's first assertion calls `FF8.opDiv` directly, not the behaviour.
    let ff = ff8();
    let result = ff.op_div(ff.encoding(3.75), ff.encoding(1.5));
    assert_long_result(&ff, 2.5, result, "opDiv(3.75, 1.5)");

    check_binary_long(
        OpCode::FloatDiv,
        &[
            (3.75, 0.0, INF),
            (-3.75, 0.0, NEG_INF),
            (-3.75, NAN, NAN), // propagated
        ],
    );
}

/// `OpBehaviorFloatDivTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_div_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::FloatDiv,
        &[
            (Num(3.75), Num(1.5), Num(2.5)),
            (Num(3.75), Zero, Inf),
            (Num(-3.75), Zero, NegInf),
            (Num(-3.75), Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatMultTest.testEvaluateBinaryLong`.
#[test]
fn float_mult_evaluate_binary_long() {
    check_binary_long(
        OpCode::FloatMult,
        &[
            (2.5, 1.5, 3.75),
            (2.5, INF, INF),
            (NEG_INF, INF, NEG_INF),
            (NEG_INF, NAN, NAN), // propagated
        ],
    );
}

/// `OpBehaviorFloatMultTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_mult_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::FloatMult,
        &[
            (Num(2.5), Num(1.5), Num(3.75)),
            (Num(2.5), Inf, Inf),
            (NegInf, Inf, NegInf),
            (NegInf, Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatNegTest.testEvaluateBinaryLong`.
#[test]
fn float_neg_evaluate_binary_long() {
    check_unary_long(
        OpCode::FloatNeg,
        &[
            (2.5, -2.5),
            (-2.5, 2.5),
            (INF, NEG_INF),
            (NEG_INF, INF),
            (NAN, NEG_NAN), // the sign of a NaN is flipped too
        ],
    );
}

/// `OpBehaviorFloatNegTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_neg_evaluate_binary_big_integer() {
    check_unary_wide(
        OpCode::FloatNeg,
        &[
            (Num(2.5), Num(-2.5)),
            (Num(-2.5), Num(2.5)),
            (Inf, NegInf),
            (NegInf, Inf),
            (Nan, Nan),
        ],
    );
}

/// `OpBehaviorFloatSqrtTest.testEvaluateBinaryLong`.
#[test]
fn float_sqrt_evaluate_binary_long() {
    let ff = ff8();
    let longbits = ff.encoding(2.0);
    let longbits = behavior::evaluate_unary(OpCode::FloatSqrt, 8, 8, longbits, &FORMATS).unwrap();
    let d = ff.host_float(longbits).0;
    // Java: `Double.toString(d).substring(0, 17)`. Java prints this value as
    // "1.4142135623730951" (checked with a JDK); so does Rust's Display.
    let text = d.to_string();
    assert_eq!(Some("1.414213562373095"), text.get(..17));
    // Extra: the whole text.
    assert_eq!("1.4142135623730951", text);
}

/// `OpBehaviorFloatSqrtTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_sqrt_evaluate_binary_big_integer() {
    let ff = ff8();
    let big = ff.big_float_from_f64(2.0).unwrap();
    let encoding = ff.encode_big_float(&big);
    let encoding = wide::evaluate_unary(OpCode::FloatSqrt, 8, 8, &encoding, &WIDE_FORMATS).unwrap();
    let result = ff.decode_big_float(&encoding);
    // Java: `FF8.round(result).toString()`.
    assert_eq!(
        "1.414213562373095",
        ff.round_decimal(&result).unwrap().to_string()
    );
}

/// `OpBehaviorFloatSubTest.testEvaluateBinaryLong`.
#[test]
fn float_sub_evaluate_binary_long() {
    check_binary_long(
        OpCode::FloatSub,
        &[
            (1.5, 1.25, 0.25),
            (-1.25, 1.25, -2.5),
            (INF, 1.25, INF),
            (NEG_INF, 1.25, NEG_INF),
            (NEG_INF, NEG_INF, NEG_NAN), // created
            (NEG_INF, INF, NEG_INF),
            (NAN, 1.25, NAN), // propagated
        ],
    );
}

/// `OpBehaviorFloatSubTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_sub_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::FloatSub,
        &[
            (Num(1.5), Num(1.25), Num(0.25)),
            (Num(-1.25), Num(1.25), Num(-2.5)),
            (Inf, Num(1.25), Inf),
            (NegInf, Num(1.25), NegInf),
            (NegInf, NegInf, Nan),
            (NegInf, Inf, NegInf),
            (Nan, Num(1.25), Nan),
        ],
    );
}
