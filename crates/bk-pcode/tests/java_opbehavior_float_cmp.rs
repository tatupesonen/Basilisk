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
//! Ghidra's JUnit tests of the floating-point comparison behaviours, ported
//! from `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorFloatEqualTest`, `OpBehaviorFloatNotEqualTest`,
//! `OpBehaviorFloatLessTest`, `OpBehaviorFloatLessEqualTest` and
//! `OpBehaviorFloatNanTest`. (The arithmetic behaviours are in
//! `java_opbehavior_float_arith.rs`.)
//!
//! Each Java `@Test` method (`testEvaluateBinaryLong`,
//! `testEvaluateBinaryBigInteger`; the names are Java's, also for the unary
//! `FLOAT_NAN`) is one test here, named after the class and the method, and
//! each Java assertion is one table row, in the Java order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`], with [`FloatFormats::DEFAULT`]; operands
//!   are `FF8.getEncoding(double)`.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that
//!   is the wide path, [`bk_pcode::behavior::wide`], with
//!   [`FloatFormats::IEEE`] (Java's `FloatFormatFactory`). Java's
//!   comparisons return `BigInteger.ONE`/`ZERO`; the wide path returns 1/0
//!   cut to `size_out` bytes.
//!
//! Basilisk's wide-path comparisons are IEEE where Java's compare `BigFloat`
//! representations (`docs/features/pcode.md` section 8), but no expectation
//! here involves a signed zero or a NaN ordering, so none differs from the
//! Java.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{FloatFormat, FloatFormats, OpCode, Wide};

/// The formats of the `u64` path (the Java `long` overloads).
const FORMATS: FloatFormats = FloatFormats::DEFAULT;
/// The formats of the wide path (the Java `BigInteger` overloads).
const WIDE_FORMATS: FloatFormats = FloatFormats::IEEE;

const INF: f64 = f64::INFINITY;
const NEG_INF: f64 = f64::NEG_INFINITY;
/// Java's `Double.NaN`: the positive quiet NaN.
const NAN: f64 = f64::NAN;

/// `AbstractOpBehaviorTest.FF8`.
fn ff8() -> FloatFormat {
    FloatFormat::ieee(8).unwrap()
}

/// Runs a comparison of 8-byte operands on the `u64` path: each row is
/// `(a, b, expected)`.
#[track_caller]
fn check_compare_long(op: OpCode, size_out: u32, rows: &[(f64, f64, u64)]) {
    let ff = ff8();
    for (row, &(a, b, expected)) in rows.iter().enumerate() {
        assert_eq!(
            behavior::evaluate_binary(op, size_out, 8, ff.encoding(a), ff.encoding(b), &FORMATS),
            Ok(expected),
            "{op} row {row}: ({a:e}, {b:e})"
        );
    }
}

/// An operand of the `BigInteger` tests, named as the Java builds it.
#[derive(Debug, Clone, Copy)]
enum Val {
    /// `FF8.getEncoding(FF8.getBigFloat(d))`.
    Num(f64),
    /// `FF8.getBigZeroEncoding(false)`.
    Zero,
    /// `FF8.getBigInfinityEncoding(false)`.
    Inf,
    /// `FF8.getBigInfinityEncoding(true)`.
    NegInf,
    /// `FF8.getBigNaNEncoding(false)`.
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
}

/// Runs a comparison of 8-byte operands on the wide path: each row is
/// `(a, b, expected)`, `true` for Java's `BigInteger.ONE`.
#[track_caller]
fn check_compare_wide(op: OpCode, size_out: u32, rows: &[(Val, Val, bool)]) {
    let ff = ff8();
    for (row, &(a, b, expected)) in rows.iter().enumerate() {
        let (wide1, wide2) = (a.encoding(&ff), b.encoding(&ff));
        assert_eq!(
            wide::evaluate_binary(op, size_out, 8, &wide1, &wide2, &WIDE_FORMATS),
            Ok(Wide::from_u64(u64::from(expected))),
            "{op} row {row}: ({a:?}, {b:?})"
        );
    }
}

/// `OpBehaviorFloatEqualTest.testEvaluateBinaryLong`.
#[test]
fn float_equal_evaluate_binary_long() {
    check_compare_long(
        OpCode::FloatEqual,
        8,
        &[
            (1.234, 1.234, 1),
            (-1.234, -1.234, 1),
            (-1.234, 1.234, 0),
            (INF, INF, 1),
            (INF, NEG_INF, 0),
            (NEG_INF, NEG_INF, 1),
            (INF, NAN, 0),
        ],
    );
}

/// `OpBehaviorFloatEqualTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_equal_evaluate_binary_big_integer() {
    let (a, b) = (Num(1.234), Num(-1.234));
    check_compare_wide(
        OpCode::FloatEqual,
        8,
        &[
            (a, a, true),
            (b, b, true),
            (b, a, false),
            (Inf, Inf, true),
            (Inf, NegInf, false),
            (NegInf, NegInf, true),
            (Inf, Nan, false),
        ],
    );
}

/// `OpBehaviorFloatNotEqualTest.testEvaluateBinaryLong`.
#[test]
fn float_not_equal_evaluate_binary_long() {
    check_compare_long(
        OpCode::FloatNotEqual,
        1,
        &[
            (1.234, 1.234, 0),
            (-1.234, -1.234, 0),
            (-1.234, 1.234, 1),
            (INF, INF, 0),
            (INF, NEG_INF, 1),
            (NEG_INF, NEG_INF, 0),
            (INF, NAN, 1),
        ],
    );
}

/// `OpBehaviorFloatNotEqualTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_not_equal_evaluate_binary_big_integer() {
    let (a, b) = (Num(1.234), Num(-1.234));
    check_compare_wide(
        OpCode::FloatNotEqual,
        1,
        &[
            (a, a, false),
            (b, b, false),
            (b, a, true),
            (Inf, Inf, false),
            (Inf, NegInf, true),
            (NegInf, NegInf, false),
            (Inf, Nan, true),
        ],
    );
}

/// `OpBehaviorFloatLessTest.testEvaluateBinaryLong`.
#[test]
fn float_less_evaluate_binary_long() {
    check_compare_long(
        OpCode::FloatLess,
        8,
        &[
            (1.234, 1.234, 0),
            (-1.234, -1.234, 0),
            (1.234, -1.234, 0),
            (0.0, -1.234, 0),
            (0.0, 1.234, 1),
            (-1.234, 1.234, 1),
            (INF, 1.234, 0),
            (NEG_INF, 1.234, 1),
            (1.234, INF, 1),
            (1.234, NEG_INF, 0),
            (INF, INF, 0),
            (NEG_INF, INF, 1),
        ],
    );
}

/// `OpBehaviorFloatLessTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_less_evaluate_binary_big_integer() {
    let (a, b) = (Num(1.234), Num(-1.234));
    check_compare_wide(
        OpCode::FloatLess,
        8,
        &[
            (a, a, false),
            (b, b, false),
            (a, b, false),
            (Zero, b, false),
            (Zero, a, true),
            (b, a, true),
            (Inf, a, false),
            (NegInf, a, true),
            (a, Inf, true),
            (a, NegInf, false),
            (Inf, Inf, false),
            (NegInf, Inf, true),
        ],
    );
}

/// `OpBehaviorFloatLessEqualTest.testEvaluateBinaryLong`.
#[test]
fn float_less_equal_evaluate_binary_long() {
    check_compare_long(
        OpCode::FloatLessEqual,
        8,
        &[
            (1.234, 1.234, 1),
            (-1.234, -1.234, 1),
            (1.234, -1.234, 0),
            (0.0, -1.234, 0),
            (0.0, 1.234, 1),
            (-1.234, 1.234, 1),
            (INF, 1.234, 0),
            (NEG_INF, 1.234, 1),
            (1.234, INF, 1),
            (1.234, NEG_INF, 0),
            (INF, INF, 1),
            (NEG_INF, INF, 1),
        ],
    );
}

/// `OpBehaviorFloatLessEqualTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_less_equal_evaluate_binary_big_integer() {
    let (a, b) = (Num(1.234), Num(-1.234));
    check_compare_wide(
        OpCode::FloatLessEqual,
        8,
        &[
            (a, a, true),
            (b, b, true),
            (a, b, false),
            (Zero, b, false),
            (Zero, a, true),
            (b, a, true),
            (Inf, a, false),
            (NegInf, a, true),
            (a, Inf, true),
            (a, NegInf, false),
            (Inf, Inf, true),
            (NegInf, Inf, true),
        ],
    );
}

/// `OpBehaviorFloatNanTest.testEvaluateBinaryLong`.
#[test]
fn float_nan_evaluate_binary_long() {
    let ff = ff8();
    for (row, (a, expected)) in [(NAN, 1), (0.0, 0), (1.234, 0)].into_iter().enumerate() {
        assert_eq!(
            behavior::evaluate_unary(OpCode::FloatNan, 1, 8, ff.encoding(a), &FORMATS),
            Ok(expected),
            "row {row}: ({a:e})"
        );
    }
}

/// `OpBehaviorFloatNanTest.testEvaluateBinaryBigInteger`.
#[test]
fn float_nan_evaluate_binary_big_integer() {
    let ff = ff8();
    for (row, (a, expected)) in [(Nan, 1), (Zero, 0), (Num(1.234), 0)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            wide::evaluate_unary(OpCode::FloatNan, 1, 8, &a.encoding(&ff), &WIDE_FORMATS),
            Ok(Wide::from_u64(expected)),
            "row {row}: ({a:?})"
        );
    }
}
