//! Derived tests of the floating-point operations on the `u64` path, reached
//! through the format table, and of what happens without a format.

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

use bk_pcode::behavior::{evaluate_binary, evaluate_unary};
use bk_pcode::{EvalError, FloatFormat, FloatFormats, OpCode};

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn unary(op: OpCode, size_out: u32, size_in: u32, in1: u64) -> u64 {
    evaluate_unary(op, size_out, size_in, in1, &FORMATS).unwrap()
}

fn binary(op: OpCode, size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS).unwrap()
}

#[test]
fn float_operations_through_the_format_table() {
    let f4 = |x: f32| u64::from(x.to_bits());
    let nan = FloatFormat::SINGLE.nan_encoding(false);
    // A NaN created by an operation is x86-64's default NaN, negative.
    let created_nan = FloatFormat::SINGLE.nan_encoding(true);
    let inf = f4(f32::INFINITY);
    assert_eq!(binary(OpCode::FloatAdd, 4, 4, f4(1.5), f4(2.25)), f4(3.75));
    assert_eq!(binary(OpCode::FloatSub, 4, 4, f4(1.5), f4(2.25)), f4(-0.75));
    assert_eq!(binary(OpCode::FloatMult, 4, 4, f4(1.5), f4(2.0)), f4(3.0));
    assert_eq!(binary(OpCode::FloatDiv, 4, 4, f4(1.0), f4(0.0)), inf);
    assert_eq!(
        binary(OpCode::FloatDiv, 4, 4, f4(-1.0), f4(0.0)),
        f4(f32::NEG_INFINITY)
    );
    assert_eq!(
        binary(OpCode::FloatDiv, 4, 4, f4(0.0), f4(0.0)),
        created_nan
    );
    assert_eq!(binary(OpCode::FloatSub, 4, 4, inf, inf), created_nan);
    assert_eq!(
        binary(OpCode::FloatAdd, 8, 8, 0.1f64.to_bits(), 0.2f64.to_bits()),
        0.3_f64.next_up().to_bits()
    );
    assert_eq!(unary(OpCode::FloatNan, 1, 4, nan), 1);
    assert_eq!(unary(OpCode::FloatNan, 1, 4, inf), 0);
    assert_eq!(unary(OpCode::FloatNan, 1, 8, f64::NAN.to_bits()), 1);
    assert_eq!(unary(OpCode::FloatNeg, 4, 4, f4(0.0)), f4(-0.0));
    assert_eq!(unary(OpCode::FloatAbs, 4, 4, f4(-3.5)), f4(3.5));
    assert_eq!(unary(OpCode::FloatSqrt, 4, 4, f4(2.0)), f4(2.0f32.sqrt()));
    assert_eq!(unary(OpCode::FloatSqrt, 4, 4, f4(-1.0)), created_nan);
    assert_eq!(unary(OpCode::FloatSqrt, 4, 4, f4(-0.0)), f4(-0.0));
    assert_eq!(unary(OpCode::FloatTrunc, 4, 4, f4(-2.75)), 0xffff_fffe);
    assert_eq!(unary(OpCode::FloatTrunc, 8, 4, f4(-2.75)), (-2i64) as u64);
    assert_eq!(
        unary(OpCode::FloatTrunc, 4, 8, 1e10f64.to_bits()),
        u64::from(10_000_000_000u64 as u32)
    );
    assert_eq!(unary(OpCode::FloatTrunc, 4, 4, nan), 0);
    assert_eq!(unary(OpCode::FloatCeil, 4, 4, f4(2.25)), f4(3.0));
    assert_eq!(unary(OpCode::FloatCeil, 4, 4, f4(-2.25)), f4(-2.0));
    assert_eq!(unary(OpCode::FloatFloor, 4, 4, f4(2.75)), f4(2.0));
    assert_eq!(unary(OpCode::FloatFloor, 4, 4, f4(-2.25)), f4(-3.0));
    assert_eq!(unary(OpCode::FloatRound, 4, 4, f4(2.5)), f4(3.0));
    assert_eq!(unary(OpCode::FloatRound, 4, 4, f4(-2.5)), f4(-3.0));
    assert_eq!(unary(OpCode::FloatRound, 4, 4, inf), inf);
    assert_eq!(unary(OpCode::FloatInt2Float, 4, 4, 0xffff_ffff), f4(-1.0));
    assert_eq!(
        unary(OpCode::FloatInt2Float, 8, 4, 0xffff_ffff),
        (-1.0f64).to_bits()
    );
    assert_eq!(
        unary(OpCode::FloatInt2Float, 8, 8, 1 << 62),
        2f64.powi(62).to_bits()
    );
    assert_eq!(unary(OpCode::FloatInt2Float, 4, 1, 0x80), f4(-128.0));
    assert_eq!(
        unary(OpCode::FloatFloat2Float, 8, 4, f4(0.1)),
        f64::from(0.1f32).to_bits()
    );
    assert_eq!(
        unary(OpCode::FloatFloat2Float, 4, 8, 0.1f64.to_bits()),
        f4(0.1)
    );
    assert_eq!(
        unary(OpCode::FloatFloat2Float, 4, 8, 1e300f64.to_bits()),
        inf
    );
    assert_eq!(
        unary(OpCode::FloatFloat2Float, 4, 8, f64::NAN.to_bits()),
        nan
    );
    // Comparisons with a NaN: everything is false except "not equal".
    for other in [nan, f4(1.0), inf] {
        assert_eq!(binary(OpCode::FloatEqual, 1, 4, nan, other), 0);
        assert_eq!(binary(OpCode::FloatNotEqual, 1, 4, nan, other), 1);
        assert_eq!(binary(OpCode::FloatLess, 1, 4, nan, other), 0);
        assert_eq!(binary(OpCode::FloatLess, 1, 4, other, nan), 0);
        assert_eq!(binary(OpCode::FloatLessEqual, 1, 4, nan, other), 0);
        assert_eq!(binary(OpCode::FloatLessEqual, 1, 4, other, nan), 0);
    }
    assert_eq!(binary(OpCode::FloatEqual, 1, 4, f4(0.0), f4(-0.0)), 1);
    assert_eq!(binary(OpCode::FloatLess, 1, 4, f4(-0.0), f4(0.0)), 0);
    assert_eq!(binary(OpCode::FloatLess, 1, 4, f4(1.0), inf), 1);
    assert_eq!(
        binary(OpCode::FloatLessEqual, 1, 8, 2f64.to_bits(), 2f64.to_bits()),
        1
    );
}

#[test]
fn float_operations_need_a_format() {
    let no_format = |op, size| Err(EvalError::NoFloatFormat { op, size });
    for size in [0, 1, 2, 3, 5, 6, 7, 10, 16] {
        let add = evaluate_binary(OpCode::FloatAdd, size, size, 0, 0, &FORMATS);
        assert_eq!(add, no_format(OpCode::FloatAdd, size));
        let neg = evaluate_unary(OpCode::FloatNeg, size, size, 0, &FORMATS);
        assert_eq!(neg, no_format(OpCode::FloatNeg, size));
    }
    // INT2FLOAT looks up the output size; FLOAT2FLOAT the output, then the input.
    let int2float = evaluate_unary(OpCode::FloatInt2Float, 3, 4, 0, &FORMATS);
    assert_eq!(int2float, no_format(OpCode::FloatInt2Float, 3));
    assert!(evaluate_unary(OpCode::FloatInt2Float, 4, 3, 0, &FORMATS).is_ok());
    let convert = evaluate_unary(OpCode::FloatFloat2Float, 3, 5, 0, &FORMATS);
    assert_eq!(convert, no_format(OpCode::FloatFloat2Float, 3));
    let convert = evaluate_unary(OpCode::FloatFloat2Float, 4, 5, 0, &FORMATS);
    assert_eq!(convert, no_format(OpCode::FloatFloat2Float, 5));
    // TRUNC looks up the input size only.
    assert!(evaluate_unary(OpCode::FloatTrunc, 3, 4, 0, &FORMATS).is_ok());
    // With no formats at all, every float operation fails.
    let none = evaluate_binary(OpCode::FloatAdd, 4, 4, 0, 0, &FloatFormats::NONE);
    assert_eq!(none, no_format(OpCode::FloatAdd, 4));
    // The table with every standard format serves binary16 at the host level
    // but cannot serve formats wider than a u64 there.
    assert_eq!(
        evaluate_binary(OpCode::FloatAdd, 2, 2, 0x3c00, 0x3c00, &FloatFormats::IEEE),
        Ok(0x4000)
    );
    let too_wide = evaluate_binary(OpCode::FloatAdd, 16, 16, 0, 0, &FloatFormats::IEEE);
    assert_eq!(
        too_wide,
        Err(EvalError::UnsupportedSize { size: 16, limit: 8 })
    );
}
