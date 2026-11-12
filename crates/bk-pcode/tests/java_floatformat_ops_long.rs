#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.FloatFormatTest`,
//! part 3 of 5: the p-code float operations through Java's `long` overloads,
//! which are basilisk's host level (`u64` encodings computed through `f64`).
//!
//! Java methods ported here (each is one `#[test]` with the same name in
//! snake case): `testOpEqualLongLong`, `testOpNotEqualLongLong`,
//! `testOpLessLongLong`, `testOpLessEqualLongLong`, `testOpNanLong`,
//! `testOpAddLongLong`, `testOpSubLongLong`, `testOpDivLongLong`,
//! `testOpMultLongLong`, `testOpNegLong`, `testOpAbsLong`, `testOpSqrtLong`,
//! `testOpInt2FloatLongInt`, `testOpFloat2FloatLongFloatFormat`,
//! `testOpTruncLongInt`, `testOpCeilLong`, `testOpFloorLong`,
//! `testOpRoundLong`.
//!
//! The host level follows Ghidra's C++ (`float.cc`) where that differs from
//! the Java `long` overloads. The one expectation of this class that it
//! changes is in `test_op_round_long`, marked `// Java:` there.

use bk_pcode::FloatFormat;

const INF: f64 = f64::INFINITY;
const NEG_INF: f64 = f64::NEG_INFINITY;
const NAN: f64 = f64::NAN;

/// Java's `new FloatFormat(size)`.
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

/// Runs a two-operand operation of the 8-byte format on host values and
/// compares the decoded result: each case is `(a, b, expected)`.
#[track_caller]
fn check_binary(op: fn(&FloatFormat, u64, u64) -> u64, cases: &[(f64, f64, f64)]) {
    let ff = float_format(8);
    for &(a, b, expected) in cases {
        let result = op(&ff, ff.encoding(a), ff.encoding(b));
        assert_double(
            expected,
            ff.host_float(result).0,
            &format!("({a:e}, {b:e})"),
        );
    }
}

/// Runs a one-operand operation of the 8-byte format on host values and
/// compares the decoded result: each case is `(a, expected)`.
#[track_caller]
fn check_unary(op: fn(&FloatFormat, u64) -> u64, cases: &[(f64, f64)]) {
    let ff = float_format(8);
    for &(a, expected) in cases {
        let result = op(&ff, ff.encoding(a));
        assert_double(expected, ff.host_float(result).0, &format!("({a:e})"));
    }
}

/// Runs a comparison of the 8-byte format: each case is `(a, b, expected)`.
#[track_caller]
fn check_compare(op: fn(&FloatFormat, u64, u64) -> u64, cases: &[(f64, f64, u64)]) {
    let ff = float_format(8);
    for &(a, b, expected) in cases {
        assert_eq!(
            expected,
            op(&ff, ff.encoding(a), ff.encoding(b)),
            "({a:e}, {b:e})"
        );
    }
}

#[test]
fn test_op_equal_long_long() {
    check_compare(
        FloatFormat::op_equal,
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

#[test]
fn test_op_not_equal_long_long() {
    check_compare(
        FloatFormat::op_not_equal,
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

#[test]
fn test_op_less_long_long() {
    check_compare(
        FloatFormat::op_less,
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

#[test]
fn test_op_less_equal_long_long() {
    check_compare(
        FloatFormat::op_less_equal,
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

#[test]
fn test_op_nan_long() {
    let ff = float_format(8);
    assert_eq!(1, ff.op_nan(ff.encoding(NAN)));
    assert_eq!(0, ff.op_nan(ff.encoding(0.0)));
    assert_eq!(0, ff.op_nan(ff.encoding(1.234)));
}

#[test]
fn test_op_add_long_long() {
    check_binary(
        FloatFormat::op_add,
        &[
            (1.234, 1.123, 2.357),
            (-1.123, 1.123, 0.0),
            (INF, 1.123, INF),
            (NEG_INF, 1.123, NEG_INF),
            (NEG_INF, NEG_INF, NEG_INF),
            (NEG_INF, INF, NAN),
            (NAN, 1.123, NAN),
        ],
    );
}

#[test]
fn test_op_sub_long_long() {
    check_binary(
        FloatFormat::op_sub,
        &[
            (1.5, 1.25, 0.25),
            (-1.25, 1.25, -2.5),
            (INF, 1.25, INF),
            (NEG_INF, 1.25, NEG_INF),
            (NEG_INF, NEG_INF, NAN),
            (NEG_INF, INF, NEG_INF),
            (NAN, 1.25, NAN),
        ],
    );
}

#[test]
fn test_op_div_long_long() {
    check_binary(
        FloatFormat::op_div,
        &[
            (3.75, 1.5, 2.5),
            (3.75, 0.0, INF),
            (-3.75, 0.0, NEG_INF),
            (-3.75, NAN, NAN),
        ],
    );
}

#[test]
fn test_op_mult_long_long() {
    check_binary(
        FloatFormat::op_mult,
        &[
            (2.5, 1.5, 3.75),
            (2.5, INF, INF),
            (NEG_INF, INF, NEG_INF),
            (NEG_INF, NAN, NAN),
        ],
    );
}

#[test]
fn test_op_neg_long() {
    check_unary(
        FloatFormat::op_neg,
        &[
            (2.5, -2.5),
            (-2.5, 2.5),
            (INF, NEG_INF),
            (NEG_INF, INF),
            (NAN, NAN),
        ],
    );
}

#[test]
fn test_op_abs_long() {
    check_unary(
        FloatFormat::op_abs,
        &[
            (2.5, 2.5),
            (-2.5, 2.5),
            (INF, INF),
            (NEG_INF, INF),
            (NAN, NAN),
        ],
    );
}

#[test]
fn test_op_sqrt_long() {
    let ff = float_format(8);
    let longbits = ff.encoding(2.0);
    let longbits = ff.op_sqrt(longbits);
    let d = ff.host_float(longbits).0;
    // Java: Double.toString(d); Rust's Display prints the same shortest
    // digits for this value.
    assert_eq!("1.4142135623730951", d.to_string());
}

#[test]
fn test_op_int2float_long_int() {
    let ff = float_format(4);

    // (the long Java passes, the float expected)
    let cases: [(i64, f64); 3] = [(2, 2.0), (-2, -2.0), (0, 0.0)];
    for (a, expected) in cases {
        let result = ff.op_int2float(a as u64, 4);
        // verify that only 4-bytes are used
        assert_eq!(0, result & 0xffff_ffff_0000_0000, "{a}");
        assert_double(expected, ff.host_float(result).0, &format!("{a}"));
    }
}

#[test]
fn test_op_float2float_long_float_format() {
    let ff8 = float_format(8);
    let ff4 = float_format(4);

    // Java passes the `float` constants widened to double.
    let cases = [
        (1.75, 1.75),
        (-1.75, -1.75),
        (f64::from(f32::INFINITY), INF),
        (f64::from(f32::NEG_INFINITY), NEG_INF),
        (f64::from(f32::NAN), NAN),
    ];
    for (input, expected) in cases {
        let a = ff4.encoding(input);
        let result = ff4.op_float2float(a, &ff8);
        assert_double(expected, ff8.host_float(result).0, &format!("{input:e}"));
    }
}

#[test]
fn test_op_trunc_long_int() {
    let ff = float_format(8);

    let a = ff.encoding(2.5);
    assert_eq!(2, ff.op_trunc(a, 8));

    let a = ff.encoding(-2.5);
    assert_eq!((-2_i64) as u64, ff.op_trunc(a, 8));

    // Saturation at the infinities and 0 for a NaN are Java's `(long)` cast;
    // the C++ leaves these undefined and basilisk follows Java.
    let a = ff.encoding(INF);
    assert_eq!(i64::MAX as u64, ff.op_trunc(a, 8));

    let a = ff.encoding(NEG_INF);
    assert_eq!(i64::MIN as u64, ff.op_trunc(a, 8));

    // Java: "TODO: What should the correct result be?"
    let a = ff.encoding(NAN);
    assert_eq!(0, ff.op_trunc(a, 8));
}

#[test]
fn test_op_ceil_long() {
    check_unary(
        FloatFormat::op_ceil,
        &[
            (2.5, 3.0),
            (-2.5, -2.0),
            (INF, INF),
            (NEG_INF, NEG_INF),
            (NAN, NAN),
        ],
    );
}

#[test]
fn test_op_floor_long() {
    check_unary(
        FloatFormat::op_floor,
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

#[test]
fn test_op_round_long() {
    check_unary(
        FloatFormat::op_round,
        &[
            (2.5, 3.0),
            (2.25, 2.0),
            (2.75, 3.0),
            // Java: -2.0; Java's `long` overload computes floor(x + 0.5), the
            // host level rounds halfway cases away from zero as the C++
            // `round()` does (known difference 1).
            (-2.5, -3.0),
            (-2.25, -2.0),
            (-2.75, -3.0),
            (INF, INF),
            (NEG_INF, NEG_INF),
            (NAN, NAN),
        ],
    );
}
