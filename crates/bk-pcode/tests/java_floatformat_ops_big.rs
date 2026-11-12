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
//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.FloatFormatTest`,
//! part 4 of 5: the p-code float operations through Java's `BigInteger`
//! overloads, which are basilisk's exact level ([`Wide`] encodings computed
//! through [`BigFloat`]).
//!
//! Java methods ported here (each is one `#[test]` with the same name in
//! snake case): `testOpEqualBigIntegerBigInteger`,
//! `testOpNotEqualBigIntegerBigInteger`, `testOpLessBigIntegerBigInteger`,
//! `testOpLessEqualBigIntegerBigInteger`, `testOpNanBigInteger`,
//! `testOpAddBigIntegerBigInteger`, `testOpSubBigIntegerBigInteger`,
//! `testOpDivBigIntegerBigInteger`, `testOpMultBigIntegerBigInteger`,
//! `testOpNegBigInteger`, `testOpAbsBigInteger`, `testOpSqrtBigInteger`,
//! `testOpInt2FloatBigIntegerInt`, `testOpFloat2FloatBigIntegerFloatFormat`,
//! `testOpTruncBigIntegerInt`, `testOpCeilBigInteger`,
//! `testOpFloorBigInteger`, `testOpRoundBigInteger`.
//!
//! Java's comparisons return `BigInteger.ONE`/`ZERO`; basilisk's return
//! `bool`. basilisk's exact comparisons are IEEE where Java's compare
//! representations, but no expectation of this class depends on that.

use bk_pcode::num_bigint::BigInt;
use bk_pcode::{BigFloat, FloatFormat, Wide};

/// Java's `new FloatFormat(size)`.
fn float_format(size: u32) -> FloatFormat {
    FloatFormat::ieee(size).unwrap()
}

/// An operand or an expected result of the 8-byte tests, named as the Java
/// builds it.
#[derive(Debug, Clone, Copy)]
enum Val {
    /// `ff.getBigFloat(d)` / `ff.getEncoding(ff.getBigFloat(d))`.
    Num(f64),
    /// `ff.getBigZero(false)` / `ff.getBigZeroEncoding(false)`.
    Zero,
    /// `ff.getBigInfinity(false)` / `ff.getBigInfinityEncoding(false)`.
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

/// Runs a two-operand operation of the 8-byte format and compares the
/// decoded result with `BigFloat` equality: each case is `(a, b, expected)`.
#[track_caller]
fn check_binary(op: fn(&FloatFormat, &Wide, &Wide) -> Wide, cases: &[(Val, Val, Val)]) {
    let ff = float_format(8);
    for &(a, b, expected) in cases {
        let result = op(&ff, &a.encoding(&ff), &b.encoding(&ff));
        assert_eq!(
            expected.big_float(&ff),
            ff.decode_big_float(&result),
            "({a:?}, {b:?})"
        );
    }
}

/// Runs a one-operand operation of the 8-byte format and compares the
/// decoded result with `BigFloat` equality: each case is `(a, expected)`.
#[track_caller]
fn check_unary(op: fn(&FloatFormat, &Wide) -> Wide, cases: &[(Val, Val)]) {
    let ff = float_format(8);
    for &(a, expected) in cases {
        let result = op(&ff, &a.encoding(&ff));
        assert_eq!(
            expected.big_float(&ff),
            ff.decode_big_float(&result),
            "({a:?})"
        );
    }
}

/// Runs a comparison of the 8-byte format: each case is `(a, b, expected)`,
/// with `true` for Java's `BigInteger.ONE` and `false` for `ZERO`.
#[track_caller]
fn check_compare(op: fn(&FloatFormat, &Wide, &Wide) -> bool, cases: &[(Val, Val, bool)]) {
    let ff = float_format(8);
    for &(a, b, expected) in cases {
        assert_eq!(
            expected,
            op(&ff, &a.encoding(&ff), &b.encoding(&ff)),
            "({a:?}, {b:?})"
        );
    }
}

/// The operands `a` and `b` of the comparison tests.
const A: Val = Num(1.234);
const B: Val = Num(-1.234);

#[test]
fn test_op_equal_big_integer_big_integer() {
    check_compare(
        FloatFormat::op_equal_exact,
        &[
            (A, A, true),
            (B, B, true),
            (B, A, false),
            (Inf, Inf, true),
            (Inf, NegInf, false),
            (NegInf, NegInf, true),
            (Inf, Nan, false),
        ],
    );
}

#[test]
fn test_op_not_equal_big_integer_big_integer() {
    check_compare(
        FloatFormat::op_not_equal_exact,
        &[
            (A, A, false),
            (B, B, false),
            (B, A, true),
            (Inf, Inf, false),
            (Inf, NegInf, true),
            (NegInf, NegInf, false),
            (Inf, Nan, true),
        ],
    );
}

#[test]
fn test_op_less_big_integer_big_integer() {
    check_compare(
        FloatFormat::op_less_exact,
        &[
            (A, A, false),
            (B, B, false),
            (A, B, false),
            (Zero, B, false),
            (Zero, A, true),
            (B, A, true),
            (Inf, A, false),
            (NegInf, A, true),
            (A, Inf, true),
            (A, NegInf, false),
            (Inf, Inf, false),
            (NegInf, Inf, true),
        ],
    );
}

#[test]
fn test_op_less_equal_big_integer_big_integer() {
    check_compare(
        FloatFormat::op_less_equal_exact,
        &[
            (A, A, true),
            (B, B, true),
            (A, B, false),
            (Zero, B, false),
            (Zero, A, true),
            (B, A, true),
            (Inf, A, false),
            (NegInf, A, true),
            (A, Inf, true),
            (A, NegInf, false),
            (Inf, Inf, true),
            (NegInf, Inf, true),
        ],
    );
}

#[test]
fn test_op_nan_big_integer() {
    let ff = float_format(8);
    assert!(ff.op_nan_exact(&Nan.encoding(&ff)));
    assert!(!ff.op_nan_exact(&Zero.encoding(&ff)));
    assert!(!ff.op_nan_exact(&Num(1.234).encoding(&ff)));
}

#[test]
fn test_op_add_big_integer_big_integer() {
    check_binary(
        FloatFormat::op_add_exact,
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

#[test]
fn test_op_sub_big_integer_big_integer() {
    check_binary(
        FloatFormat::op_sub_exact,
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

#[test]
fn test_op_div_big_integer_big_integer() {
    check_binary(
        FloatFormat::op_div_exact,
        &[
            (Num(3.75), Num(1.5), Num(2.5)),
            (Num(3.75), Zero, Inf),
            (Num(-3.75), Zero, NegInf),
            (Num(-3.75), Nan, Nan),
        ],
    );
}

#[test]
fn test_op_mult_big_integer_big_integer() {
    check_binary(
        FloatFormat::op_mult_exact,
        &[
            (Num(2.5), Num(1.5), Num(3.75)),
            (Num(2.5), Inf, Inf),
            (NegInf, Inf, NegInf),
            (NegInf, Nan, Nan),
        ],
    );
}

#[test]
fn test_op_neg_big_integer() {
    check_unary(
        FloatFormat::op_neg_exact,
        &[
            (Num(2.5), Num(-2.5)),
            (Num(-2.5), Num(2.5)),
            (Inf, NegInf),
            (NegInf, Inf),
            (Nan, Nan),
        ],
    );
}

#[test]
fn test_op_abs_big_integer() {
    check_unary(
        FloatFormat::op_abs_exact,
        &[
            (Num(2.5), Num(2.5)),
            (Num(-2.5), Num(2.5)),
            (Inf, Inf),
            (NegInf, Inf),
            (Nan, Nan),
        ],
    );
}

#[test]
fn test_op_sqrt_big_integer() {
    let ff = float_format(8);
    let big = ff.big_float_from_f64(2.0).unwrap();
    let encoding = ff.encode_big_float(&big);
    let encoding = ff.op_sqrt_exact(&encoding);
    let result = ff.decode_big_float(&encoding);
    assert_eq!(
        "1.414213562373095",
        ff.round_decimal(&result).unwrap().to_string()
    );
}

#[test]
fn test_op_int2float_big_integer_int() {
    let ff = float_format(4);

    let limit = Wide::ONE << 32;

    // (the BigInteger Java passes, the BigFloat the result decodes to)
    let cases = [
        (2, ff.big_float_from_f64(2.0).unwrap()),
        (-2, ff.big_float_from_f64(-2.0).unwrap()),
        (0, ff.big_zero(false)),
    ];
    for (a, expected) in cases {
        let a = Wide::from_bigint(&BigInt::from(a));
        let result = ff.op_int2float_exact(&a, 4, true);
        // verify that only 4-bytes are used
        assert!(result < limit, "{a}");
        assert_eq!(expected, ff.decode_big_float(&result), "{a}");
    }
}

#[test]
fn test_op_float2float_big_integer_float_format() {
    let ff8 = float_format(8);
    let ff4 = float_format(4);

    // (the 4-byte value, the 8-byte value its conversion decodes to)
    let cases = [
        (
            ff4.big_float_from_f64(1.75).unwrap(),
            ff8.big_float_from_f64(1.75).unwrap(),
        ),
        (
            ff4.big_float_from_f64(-1.75).unwrap(),
            ff8.big_float_from_f64(-1.75).unwrap(),
        ),
        (ff4.big_infinity(false), ff8.big_infinity(false)),
        (ff4.big_infinity(true), ff8.big_infinity(true)),
        (ff4.big_nan(false), ff8.big_nan(false)),
    ];
    for (input, expected) in cases {
        let a = ff4.encode_big_float(&input);
        let result = ff4.op_float2float_exact(&a, &ff8);
        assert_eq!(expected, ff8.decode_big_float(&result), "{input:?}");
    }
}

#[test]
fn test_op_trunc_big_integer_int() {
    let ff = float_format(8);

    // Java's `opTrunc(BigInteger, 8)` returns a signed BigInteger; basilisk
    // returns its 512-bit two's complement, which is compared in full and
    // then read back as the signed 8-byte integer.
    let cases = [
        (Num(2.5), 2),
        (Num(-2.5), -2),
        (Inf, i64::MAX),
        (NegInf, i64::MIN),
        // Java: "TODO: What should the correct result be?"
        (Nan, 0),
    ];
    for (a, expected) in cases {
        let expected = BigInt::from(expected);
        let result = ff.op_trunc_exact(&a.encoding(&ff));
        assert_eq!(Wide::from_bigint(&expected), result, "{a:?}");
        assert_eq!(expected, result.truncate(8).to_bigint_signed(8), "{a:?}");
    }
}

#[test]
fn test_op_ceil_big_integer() {
    check_unary(
        FloatFormat::op_ceil_exact,
        &[
            (Num(2.5), Num(3.0)),
            (Num(-2.5), Num(-2.0)),
            (Inf, Inf),
            (NegInf, NegInf),
            (Nan, Nan),
        ],
    );
}

#[test]
fn test_op_floor_big_integer() {
    check_unary(
        FloatFormat::op_floor_exact,
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

#[test]
fn test_op_round_big_integer() {
    // The exact level keeps Java's floor(x + 0.5): round(-2.5) is -2.0 here
    // (the host level gives -3.0, see `test_op_round_long`).
    check_unary(
        FloatFormat::op_round_exact,
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
