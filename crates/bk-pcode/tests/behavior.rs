//! Tests derived from Ghidra's sources (`opbehavior.cc`, the Java
//! behaviours) rather than ported from its test suites: every edge case the
//! feature spec lists, the special operations, `recover_input_*`, and the
//! wide path at sizes the Java tests do not reach.

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

use bk_pcode::behavior::{
    evaluate_binary, evaluate_ternary, evaluate_unary, recover_input_binary, recover_input_unary,
    wide,
};
use bk_pcode::{Arity, EvalError, FloatFormat, FloatFormats, OpCode, RecoverOp, Wide};

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn unary(op: OpCode, size_out: u32, size_in: u32, in1: u64) -> u64 {
    evaluate_unary(op, size_out, size_in, in1, &FORMATS).unwrap()
}

fn binary(op: OpCode, size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS).unwrap()
}

fn wide_unary(op: OpCode, size_out: u32, size_in: u32, in1: Wide) -> Wide {
    wide::evaluate_unary(op, size_out, size_in, &in1, &FloatFormats::IEEE).unwrap()
}

fn wide_binary(op: OpCode, size_out: u32, size_in: u32, in1: Wide, in2: Wide) -> Wide {
    wide::evaluate_binary(op, size_out, size_in, &in1, &in2, &FloatFormats::IEEE).unwrap()
}

fn w(value: u128) -> Wide {
    Wide::from_u128(value)
}

#[test]
fn results_are_masked_to_the_output_size() {
    assert_eq!(binary(OpCode::IntAdd, 1, 1, 0xff, 1), 0);
    assert_eq!(binary(OpCode::IntAdd, 2, 2, 0xffff, 2), 1);
    assert_eq!(binary(OpCode::IntAdd, 8, 8, u64::MAX, 2), 1);
    assert_eq!(binary(OpCode::IntSub, 1, 1, 0, 1), 0xff);
    assert_eq!(binary(OpCode::IntSub, 4, 4, 0, 1), 0xffff_ffff);
    assert_eq!(binary(OpCode::IntMult, 2, 2, 0x1234, 0x100), 0x3400);
    assert_eq!(binary(OpCode::IntMult, 8, 8, u64::MAX, u64::MAX), 1);
    assert_eq!(unary(OpCode::Int2Comp, 1, 1, 1), 0xff);
    assert_eq!(unary(OpCode::Int2Comp, 4, 4, 0), 0);
    assert_eq!(unary(OpCode::Int2Comp, 8, 8, 1), u64::MAX);
    assert_eq!(unary(OpCode::IntNegate, 2, 2, 0x00ff), 0xff00);
    assert_eq!(unary(OpCode::IntNegate, 8, 8, 0), u64::MAX);
    assert_eq!(unary(OpCode::Copy, 4, 4, 0xdead_beef), 0xdead_beef);
    // Sizes 3, 5, 6 and 7 have masks too.
    assert_eq!(binary(OpCode::IntAdd, 3, 3, 0xff_ffff, 1), 0);
    assert_eq!(binary(OpCode::IntSub, 5, 5, 0, 1), 0xff_ffff_ffff);
    assert_eq!(unary(OpCode::IntNegate, 7, 7, 0), 0xff_ffff_ffff_ffff);
}

#[test]
fn extensions() {
    assert_eq!(unary(OpCode::IntZExt, 4, 1, 0x80), 0x80);
    assert_eq!(unary(OpCode::IntSExt, 4, 1, 0x80), 0xffff_ff80);
    assert_eq!(unary(OpCode::IntSExt, 4, 1, 0x7f), 0x7f);
    assert_eq!(
        unary(OpCode::IntSExt, 8, 4, 0x8000_0000),
        0xffff_ffff_8000_0000
    );
    assert_eq!(unary(OpCode::IntSExt, 8, 2, 0x7fff), 0x7fff);
    assert_eq!(unary(OpCode::IntSExt, 2, 1, 0xff), 0xffff);
    assert_eq!(unary(OpCode::IntSExt, 3, 2, 0x8001), 0xff_8001);
}

#[test]
fn shifts_by_the_width_or_more() {
    for (size, bits) in [(1u32, 8u64), (2, 16), (4, 32), (8, 64)] {
        let all = bk_pcode::mask::calc_mask(size);
        let top = 1u64 << (bits - 1);
        for amount in [bits, bits + 1, 255, u64::MAX] {
            assert_eq!(
                binary(OpCode::IntLeft, size, size, all, amount),
                0,
                "{size} {amount}"
            );
            assert_eq!(
                binary(OpCode::IntRight, size, size, all, amount),
                0,
                "{size} {amount}"
            );
            assert_eq!(
                binary(OpCode::IntSRight, size, size, top, amount),
                all,
                "{size} {amount}"
            );
            assert_eq!(
                binary(OpCode::IntSRight, size, size, top - 1, amount),
                0,
                "{size} {amount}"
            );
        }
        // One less than the width still shifts.
        assert_eq!(binary(OpCode::IntLeft, size, size, 1, bits - 1), top);
        assert_eq!(binary(OpCode::IntRight, size, size, top, bits - 1), 1);
        assert_eq!(binary(OpCode::IntSRight, size, size, top, bits - 1), all);
        assert_eq!(
            binary(OpCode::IntSRight, size, size, top, 1),
            top | (top >> 1)
        );
        assert_eq!(
            binary(OpCode::IntSRight, size, size, top - 1, 1),
            (top - 1) >> 1
        );
        assert_eq!(binary(OpCode::IntLeft, size, size, all, 0), all);
        assert_eq!(binary(OpCode::IntLeft, size, size, all, 1), all & !1);
    }
}

#[test]
fn division_and_remainder() {
    let div_zero = Err(EvalError::DivideByZero);
    let rem_zero = Err(EvalError::RemainderByZero);
    for size in [1, 2, 4, 8] {
        assert_eq!(
            evaluate_binary(OpCode::IntDiv, size, size, 7, 0, &FORMATS),
            div_zero
        );
        assert_eq!(
            evaluate_binary(OpCode::IntSDiv, size, size, 7, 0, &FORMATS),
            div_zero
        );
        assert_eq!(
            evaluate_binary(OpCode::IntRem, size, size, 7, 0, &FORMATS),
            rem_zero
        );
        assert_eq!(
            evaluate_binary(OpCode::IntSRem, size, size, 7, 0, &FORMATS),
            rem_zero
        );
        // Signed overflow: MIN / -1 is MIN and MIN % -1 is 0.
        let all = bk_pcode::mask::calc_mask(size);
        let min = (all >> 1) + 1;
        assert_eq!(binary(OpCode::IntSDiv, size, size, min, all), min, "{size}");
        assert_eq!(binary(OpCode::IntSRem, size, size, min, all), 0, "{size}");
    }
    assert_eq!(binary(OpCode::IntDiv, 4, 4, 0xffff_fffe, 2), 0x7fff_ffff);
    assert_eq!(binary(OpCode::IntSDiv, 4, 4, 0xffff_fffe, 2), 0xffff_ffff);
    assert_eq!(binary(OpCode::IntSDiv, 1, 1, 0xf9, 2), 0xfd); // -7 / 2 = -3
    assert_eq!(binary(OpCode::IntSDiv, 1, 1, 7, 0xfe), 0xfd); // 7 / -2 = -3
    assert_eq!(binary(OpCode::IntRem, 1, 1, 0xf9, 2), 1);
    assert_eq!(binary(OpCode::IntSRem, 1, 1, 0xf9, 2), 0xff); // -7 % 2 = -1
    assert_eq!(binary(OpCode::IntSRem, 1, 1, 7, 0xfe), 1); // 7 % -2 = 1
    assert_eq!(
        binary(OpCode::IntSDiv, 8, 8, (-7i64) as u64, 2),
        (-3i64) as u64
    );
    // The signed divisor is tested after sign extension by size.
    assert_eq!(
        evaluate_binary(OpCode::IntSDiv, 1, 1, 7, 0x100, &FORMATS),
        div_zero
    );
    assert_eq!(
        evaluate_binary(OpCode::IntSRem, 1, 1, 7, 0x100, &FORMATS),
        rem_zero
    );
}

#[test]
fn carries_and_borrows() {
    assert_eq!(binary(OpCode::IntCarry, 1, 1, 0xff, 1), 1);
    assert_eq!(binary(OpCode::IntCarry, 1, 1, 0xfe, 1), 0);
    assert_eq!(binary(OpCode::IntCarry, 1, 8, u64::MAX, 1), 1);
    assert_eq!(binary(OpCode::IntCarry, 1, 4, 0x8000_0000, 0x8000_0000), 1);
    assert_eq!(binary(OpCode::IntCarry, 1, 4, 0x7fff_ffff, 0x8000_0000), 0);
    assert_eq!(binary(OpCode::IntSCarry, 1, 1, 0x7f, 1), 1);
    assert_eq!(binary(OpCode::IntSCarry, 1, 1, 0x80, 0x80), 1);
    assert_eq!(binary(OpCode::IntSCarry, 1, 1, 0x7f, 0x80), 0);
    assert_eq!(binary(OpCode::IntSCarry, 1, 8, i64::MAX as u64, 1), 1);
    assert_eq!(
        binary(OpCode::IntSCarry, 1, 8, i64::MAX as u64, u64::MAX),
        0
    );
    assert_eq!(binary(OpCode::IntSBorrow, 1, 1, 0x80, 1), 1);
    assert_eq!(binary(OpCode::IntSBorrow, 1, 1, 0x7f, 0xff), 1);
    assert_eq!(binary(OpCode::IntSBorrow, 1, 1, 0x7f, 1), 0);
    assert_eq!(binary(OpCode::IntSBorrow, 1, 4, 0x8000_0000, 1), 1);
    assert_eq!(binary(OpCode::IntSBorrow, 1, 8, i64::MIN as u64, 1), 1);
    assert_eq!(binary(OpCode::IntSBorrow, 1, 8, 0, i64::MIN as u64), 1);
}

#[test]
fn comparisons() {
    assert_eq!(binary(OpCode::IntEqual, 1, 4, 5, 5), 1);
    assert_eq!(binary(OpCode::IntNotEqual, 1, 4, 5, 5), 0);
    assert_eq!(binary(OpCode::IntLess, 1, 1, 0x7f, 0x80), 1);
    assert_eq!(binary(OpCode::IntSLess, 1, 1, 0x7f, 0x80), 0);
    assert_eq!(binary(OpCode::IntSLess, 1, 1, 0x80, 0x7f), 1);
    assert_eq!(binary(OpCode::IntSLess, 1, 8, u64::MAX, 0), 1);
    assert_eq!(binary(OpCode::IntSLess, 1, 8, 0, u64::MAX), 0);
    assert_eq!(binary(OpCode::IntSLess, 1, 4, 0xffff_fffe, 0xffff_ffff), 1);
    assert_eq!(binary(OpCode::IntSLessEqual, 1, 2, 0x8000, 0x8000), 1);
    assert_eq!(binary(OpCode::IntSLessEqual, 1, 2, 0x7fff, 0x8000), 0);
    assert_eq!(binary(OpCode::IntLessEqual, 1, 2, 0x8000, 0x8000), 1);
    assert_eq!(binary(OpCode::IntLessEqual, 1, 2, 0x8001, 0x8000), 0);
    // A size of zero: the signed comparisons give 0, as `sizein <= 0` does in Ghidra.
    assert_eq!(binary(OpCode::IntSLess, 1, 0, 1, 2), 0);
    assert_eq!(binary(OpCode::IntSLessEqual, 1, 0, 1, 1), 0);
}

#[test]
fn piece_and_subpiece() {
    // PIECE: size_in is the size of the high piece; the low piece has the rest.
    assert_eq!(binary(OpCode::Piece, 4, 2, 0x1234, 0x5678), 0x1234_5678);
    assert_eq!(
        binary(OpCode::Piece, 8, 4, 0xdead_beef, 0x0bad_f00d),
        0xdead_beef_0bad_f00d
    );
    assert_eq!(binary(OpCode::Piece, 4, 1, 0x12, 0x34_5678), 0x1234_5678);
    assert_eq!(binary(OpCode::Piece, 4, 3, 0x12_3456, 0x78), 0x1234_5678);
    assert_eq!(binary(OpCode::SubPiece, 2, 4, 0x1234_5678, 0), 0x5678);
    assert_eq!(binary(OpCode::SubPiece, 2, 4, 0x1234_5678, 1), 0x3456);
    assert_eq!(binary(OpCode::SubPiece, 1, 4, 0x1234_5678, 3), 0x12);
    assert_eq!(
        binary(OpCode::SubPiece, 4, 8, 0x1122_3344_5566_7788, 4),
        0x1122_3344
    );
    assert_eq!(
        binary(OpCode::SubPiece, 1, 8, 0x1122_3344_5566_7788, 7),
        0x11
    );
    // An offset of 8 bytes or more leaves nothing of a 64-bit value.
    assert_eq!(binary(OpCode::SubPiece, 1, 8, u64::MAX, 8), 0);
    assert_eq!(binary(OpCode::SubPiece, 1, 8, u64::MAX, u64::MAX), 0);
}

#[test]
fn bit_counts() {
    assert_eq!(unary(OpCode::PopCount, 1, 4, 0), 0);
    assert_eq!(unary(OpCode::PopCount, 1, 4, 0xf0f0_f0f0), 16);
    assert_eq!(unary(OpCode::PopCount, 1, 8, u64::MAX), 64);
    assert_eq!(unary(OpCode::LzCount, 1, 1, 0), 8);
    assert_eq!(unary(OpCode::LzCount, 1, 1, 1), 7);
    assert_eq!(unary(OpCode::LzCount, 1, 1, 0x80), 0);
    assert_eq!(unary(OpCode::LzCount, 1, 2, 0), 16);
    assert_eq!(unary(OpCode::LzCount, 1, 4, 0), 32);
    assert_eq!(unary(OpCode::LzCount, 1, 4, 0x0001_0000), 15);
    assert_eq!(unary(OpCode::LzCount, 1, 8, 0), 64);
    assert_eq!(unary(OpCode::LzCount, 1, 8, 1), 63);
    assert_eq!(unary(OpCode::LzCount, 1, 8, u64::MAX), 0);
}

#[test]
fn booleans() {
    assert_eq!(unary(OpCode::BoolNegate, 1, 1, 0), 1);
    assert_eq!(unary(OpCode::BoolNegate, 1, 1, 1), 0);
    for (a, b) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        assert_eq!(binary(OpCode::BoolXor, 1, 1, a, b), a ^ b);
        assert_eq!(binary(OpCode::BoolAnd, 1, 1, a, b), a & b);
        assert_eq!(binary(OpCode::BoolOr, 1, 1, a, b), a | b);
    }
    assert_eq!(
        binary(OpCode::IntXor, 4, 4, 0xff00_ff00, 0x0ff0_0ff0),
        0xf0f0_f0f0
    );
    assert_eq!(
        binary(OpCode::IntAnd, 4, 4, 0xff00_ff00, 0x0ff0_0ff0),
        0x0f00_0f00
    );
    assert_eq!(
        binary(OpCode::IntOr, 4, 4, 0xff00_ff00, 0x0ff0_0ff0),
        0xfff0_fff0
    );
}

#[test]
fn pointer_arithmetic() {
    assert_eq!(binary(OpCode::PtrSub, 4, 4, 0xffff_fff0, 0x20), 0x10);
    assert_eq!(
        evaluate_ternary(OpCode::PtrAdd, 4, 4, 0x1000, 3, 8),
        Ok(0x1018)
    );
    assert_eq!(
        evaluate_ternary(OpCode::PtrAdd, 4, 4, 0xffff_fff0, 4, 8),
        Ok(0x10)
    );
    assert_eq!(
        evaluate_ternary(OpCode::PtrAdd, 8, 8, 0x1000, u64::MAX, 8),
        Ok(0xff8)
    );
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

#[test]
fn operations_without_arithmetic() {
    let special = [
        OpCode::Load,
        OpCode::Store,
        OpCode::Branch,
        OpCode::CBranch,
        OpCode::BranchInd,
        OpCode::Call,
        OpCode::CallInd,
        OpCode::CallOther,
        OpCode::Return,
        OpCode::MultiEqual,
        OpCode::Indirect,
        OpCode::Cast,
        OpCode::SegmentOp,
        OpCode::CPoolRef,
        OpCode::New,
        OpCode::Insert,
        OpCode::ZPull,
        OpCode::SPull,
    ];
    for op in special {
        let unimplemented = |arity| Err(EvalError::Unimplemented { op, arity });
        assert_eq!(
            evaluate_unary(op, 4, 4, 1, &FORMATS),
            unimplemented(Arity::Unary)
        );
        assert_eq!(
            evaluate_binary(op, 4, 4, 1, 2, &FORMATS),
            unimplemented(Arity::Binary)
        );
        assert_eq!(
            evaluate_ternary(op, 4, 4, 1, 2, 3),
            unimplemented(Arity::Ternary)
        );
        let (a, b) = (Wide::ONE, Wide::ONE);
        let wide_unary = wide::evaluate_unary(op, 4, 4, &a, &FORMATS);
        assert_eq!(
            wide_unary,
            Err(EvalError::Unimplemented {
                op,
                arity: Arity::Unary
            })
        );
        let wide_binary = wide::evaluate_binary(op, 4, 4, &a, &b, &FORMATS);
        assert_eq!(
            wide_binary,
            Err(EvalError::Unimplemented {
                op,
                arity: Arity::Binary
            })
        );
        assert_eq!(
            recover_input_unary(op, 4, 1, 4),
            Err(EvalError::CannotRecover)
        );
        assert_eq!(
            recover_input_binary(op, 0, 4, 1, 4, 1),
            Err(EvalError::CannotRecover)
        );
    }
    assert_eq!(
        evaluate_unary(OpCode::Load, 4, 4, 0, &FORMATS)
            .unwrap_err()
            .to_string(),
        "Unary emulation unimplemented for LOAD"
    );
}

#[test]
fn every_operation_has_exactly_the_interfaces_ghidra_gives_it() {
    for op in OpCode::ALL {
        let unary = evaluate_unary(op, 4, 4, 1, &FORMATS).is_ok();
        let binary = evaluate_binary(op, 4, 4, 1, 1, &FORMATS).is_ok();
        let ternary = evaluate_ternary(op, 4, 4, 1, 1, 1).is_ok();
        let implemented = u32::from(unary) + u32::from(binary) + u32::from(ternary);
        assert!(implemented <= 1, "{op}");
        // Unary operations evaluate through the unary interface only.
        assert_eq!(unary, op.is_unary(), "{op}");
        // Special operations evaluate through none.
        if op.is_special() {
            assert_eq!(implemented, 0, "{op}");
        }
        if ternary {
            assert_eq!(op, OpCode::PtrAdd);
        }
        if implemented == 0 {
            let unimplemented = matches!(op, OpCode::Insert | OpCode::ZPull | OpCode::SPull);
            assert!(op.is_special() || unimplemented, "{op}");
        }
    }
}

#[test]
fn recover_unary_inverts_evaluate() {
    for size in [1u32, 2, 4, 8] {
        let mask = bk_pcode::mask::calc_mask(size);
        for value in [0, 1, 0x7f, 0x80, 0xff, 0x1234_5678_9abc_def0, u64::MAX] {
            let value = value & mask;
            for op in [OpCode::Copy, OpCode::Int2Comp, OpCode::IntNegate] {
                let out = unary(op, size, size, value);
                assert_eq!(
                    recover_input_unary(op, size, out, size),
                    Ok(value),
                    "{op} {size}"
                );
            }
            for size_out in [size, size + 1, 8]
                .into_iter()
                .filter(|&out| out > size && out <= 8)
            {
                for op in [OpCode::IntZExt, OpCode::IntSExt] {
                    let out = unary(op, size_out, size, value);
                    let recovered = recover_input_unary(op, size_out, out, size);
                    assert_eq!(recovered, Ok(value), "{op} {size}->{size_out} {value:#x}");
                }
            }
        }
    }
    // Outputs no input produces.
    let zext = Err(EvalError::OutOfRange(RecoverOp::ZExt));
    let sext = Err(EvalError::OutOfRange(RecoverOp::SExt));
    assert_eq!(recover_input_unary(OpCode::IntZExt, 4, 0x100, 1), zext);
    assert_eq!(
        recover_input_unary(OpCode::IntZExt, 4, 0xffff_ff80, 1),
        zext
    );
    assert_eq!(recover_input_unary(OpCode::IntSExt, 4, 0x100, 1), sext);
    assert_eq!(
        recover_input_unary(OpCode::IntSExt, 4, 0x0000_ff80, 1),
        sext
    );
    assert_eq!(
        recover_input_unary(OpCode::IntSExt, 4, 0xffff_ff80, 1),
        Ok(0x80)
    );
    assert_eq!(recover_input_unary(OpCode::IntSExt, 4, 0x7f, 1), Ok(0x7f));
    // Operations Ghidra does not invert.
    for op in [
        OpCode::BoolNegate,
        OpCode::PopCount,
        OpCode::LzCount,
        OpCode::FloatNeg,
        OpCode::IntAdd,
    ] {
        assert_eq!(
            recover_input_unary(op, 4, 1, 4),
            Err(EvalError::CannotRecover),
            "{op}"
        );
    }
}

#[test]
fn recover_binary_inverts_evaluate() {
    for size in [1u32, 2, 4, 8] {
        let mask = bk_pcode::mask::calc_mask(size);
        let values = [0, 1, 0x7f, 0x80, 0xff, 0x1234_5678_9abc_def0, u64::MAX];
        for a in values.map(|v| v & mask) {
            for b in values.map(|v| v & mask) {
                let sum = binary(OpCode::IntAdd, size, size, a, b);
                assert_eq!(
                    recover_input_binary(OpCode::IntAdd, 0, size, sum, size, b),
                    Ok(a)
                );
                assert_eq!(
                    recover_input_binary(OpCode::IntAdd, 1, size, sum, size, a),
                    Ok(b)
                );
                let difference = binary(OpCode::IntSub, size, size, a, b);
                assert_eq!(
                    recover_input_binary(OpCode::IntSub, 0, size, difference, size, b),
                    Ok(a)
                );
                assert_eq!(
                    recover_input_binary(OpCode::IntSub, 1, size, difference, size, a),
                    Ok(b)
                );
            }
        }
        let bits = u64::from(size) * 8;
        for sa in 0..bits {
            // A left shift loses nothing when the top `sa` bits are clear.
            let a = (0x0123_4567_89ab_cdef & mask) >> sa;
            let out = binary(OpCode::IntLeft, size, size, a, sa);
            assert_eq!(
                recover_input_binary(OpCode::IntLeft, 0, size, out, size, sa),
                Ok(a),
                "{size} {sa}"
            );
            // A right shift loses nothing when the low `sa` bits are clear.
            let a = (0xfedc_ba98_7654_3210 & mask) >> sa << sa;
            let out = binary(OpCode::IntRight, size, size, a, sa);
            assert_eq!(
                recover_input_binary(OpCode::IntRight, 0, size, out, size, sa),
                Ok(a),
                "{size} {sa}"
            );
            // Ghidra only recovers an arithmetic shift of a negative value,
            // and returns the shifted-back output without masking it.
            let negative = (mask >> sa << sa) & mask;
            let out = binary(OpCode::IntSRight, size, size, negative, sa);
            let recovered =
                recover_input_binary(OpCode::IntSRight, 0, size, out, size, sa).unwrap();
            assert_eq!(recovered & mask, negative, "{size} {sa}");
        }
        // The shift amount cannot be recovered, nor an input shifted out entirely.
        for op in [OpCode::IntLeft, OpCode::IntRight, OpCode::IntSRight] {
            assert_eq!(
                recover_input_binary(op, 1, size, 0, size, 1),
                Err(EvalError::CannotRecover)
            );
            assert_eq!(
                recover_input_binary(op, 0, size, 0, size, bits),
                Err(EvalError::CannotRecover)
            );
        }
    }
    let left = Err(EvalError::OutOfRange(RecoverOp::LeftShift));
    let right = Err(EvalError::OutOfRange(RecoverOp::RightShift));
    assert_eq!(
        recover_input_binary(OpCode::IntLeft, 0, 4, 0x0000_0001, 4, 4),
        left
    );
    assert_eq!(
        recover_input_binary(OpCode::IntRight, 0, 4, 0xf000_0000, 4, 4),
        right
    );
    assert_eq!(
        recover_input_binary(OpCode::IntSRight, 0, 4, 0x0700_0000, 4, 4),
        right
    );
    assert_eq!(
        recover_input_binary(OpCode::IntSRight, 0, 4, 0x0000_0001, 4, 4),
        right
    );
    for op in [
        OpCode::IntMult,
        OpCode::IntXor,
        OpCode::IntDiv,
        OpCode::FloatAdd,
        OpCode::Piece,
    ] {
        assert_eq!(
            recover_input_binary(op, 0, 4, 1, 4, 1),
            Err(EvalError::CannotRecover),
            "{op}"
        );
    }
}

#[test]
fn wide_integer_operations() {
    let max16 = w(u128::MAX);
    assert_eq!(wide_binary(OpCode::IntAdd, 16, 16, max16, w(1)), Wide::ZERO);
    assert_eq!(
        wide_binary(OpCode::IntAdd, 32, 32, max16, w(1)),
        Wide::ONE << 128
    );
    assert_eq!(wide_binary(OpCode::IntSub, 16, 16, w(0), w(1)), max16);
    assert_eq!(wide_binary(OpCode::IntSub, 64, 64, w(0), w(1)), Wide::MAX);
    assert_eq!(wide_binary(OpCode::IntMult, 16, 16, max16, max16), w(1));
    assert_eq!(
        wide_binary(OpCode::IntMult, 32, 32, w(1 << 100), w(1 << 100)),
        Wide::ONE << 200
    );
    assert_eq!(wide_unary(OpCode::Int2Comp, 16, 16, w(1)), max16);
    assert_eq!(
        wide_unary(OpCode::IntNegate, 32, 32, Wide::ZERO),
        Wide::mask(32)
    );
    assert_eq!(wide_unary(OpCode::IntZExt, 32, 16, max16), max16);
    assert_eq!(wide_unary(OpCode::IntSExt, 32, 16, max16), Wide::mask(32));
    assert_eq!(
        wide_unary(OpCode::IntSExt, 16, 8, w(1 << 63)),
        w(u128::MAX << 63)
    );
    assert_eq!(wide_unary(OpCode::IntSExt, 32, 16, w(5)), w(5));
    assert_eq!(wide_unary(OpCode::PopCount, 2, 64, Wide::MAX), w(512));
    assert_eq!(wide_unary(OpCode::LzCount, 2, 64, Wide::ZERO), w(512));
    assert_eq!(wide_unary(OpCode::LzCount, 1, 16, w(1)), w(127));
    assert_eq!(wide_unary(OpCode::LzCount, 1, 16, max16), w(0));
    assert_eq!(wide_unary(OpCode::BoolNegate, 1, 1, w(0)), w(1));

    let min16 = w(1 << 127);
    assert_eq!(wide_binary(OpCode::IntLess, 1, 16, w(1), min16), w(1));
    assert_eq!(wide_binary(OpCode::IntSLess, 1, 16, w(1), min16), w(0));
    assert_eq!(wide_binary(OpCode::IntSLess, 1, 16, min16, w(1)), w(1));
    assert_eq!(
        wide_binary(OpCode::IntSLessEqual, 1, 16, max16, max16),
        w(1)
    );
    assert_eq!(wide_binary(OpCode::IntSLessEqual, 1, 16, w(0), max16), w(0));
    assert_eq!(wide_binary(OpCode::IntLessEqual, 1, 16, max16, w(0)), w(0));
    assert_eq!(wide_binary(OpCode::IntEqual, 1, 16, max16, max16), w(1));
    assert_eq!(wide_binary(OpCode::IntNotEqual, 1, 16, max16, max16), w(0));
    assert_eq!(wide_binary(OpCode::IntCarry, 1, 16, max16, w(1)), w(1));
    assert_eq!(wide_binary(OpCode::IntCarry, 1, 16, max16 >> 1, w(1)), w(0));
    assert_eq!(
        wide_binary(OpCode::IntSCarry, 1, 16, max16 >> 1, w(1)),
        w(1)
    );
    assert_eq!(wide_binary(OpCode::IntSCarry, 1, 16, max16, w(1)), w(0));
    assert_eq!(wide_binary(OpCode::IntSBorrow, 1, 16, min16, w(1)), w(1));
    assert_eq!(wide_binary(OpCode::IntSBorrow, 1, 16, w(0), w(1)), w(0));

    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, w(1), w(127)), min16);
    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, max16, w(128)), w(0));
    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, max16, Wide::MAX), w(0));
    assert_eq!(wide_binary(OpCode::IntRight, 16, 16, min16, w(127)), w(1));
    assert_eq!(wide_binary(OpCode::IntRight, 16, 16, max16, w(128)), w(0));
    assert_eq!(wide_binary(OpCode::IntSRight, 16, 16, min16, w(127)), max16);
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16, w(4)),
        w(0xf8 << 120)
    );
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16, w(1000)),
        max16
    );
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16 >> 1, w(1000)),
        w(0)
    );

    let div_zero = Err(EvalError::DivideByZero);
    let rem_zero = Err(EvalError::RemainderByZero);
    let evaluate = |op, a, b| wide::evaluate_binary(op, 16, 16, &a, &b, &FORMATS);
    assert_eq!(evaluate(OpCode::IntDiv, w(1), w(0)), div_zero);
    assert_eq!(evaluate(OpCode::IntSDiv, w(1), w(0)), div_zero);
    assert_eq!(evaluate(OpCode::IntRem, w(1), w(0)), rem_zero);
    assert_eq!(evaluate(OpCode::IntSRem, w(1), w(0)), rem_zero);
    assert_eq!(wide_binary(OpCode::IntDiv, 16, 16, max16, w(2)), max16 >> 1);
    assert_eq!(wide_binary(OpCode::IntSDiv, 16, 16, max16, w(2)), w(0)); // -1 / 2
    assert_eq!(
        wide_binary(OpCode::IntSDiv, 16, 16, w((-7i128) as u128), w(2)),
        w((-3i128) as u128)
    );
    assert_eq!(wide_binary(OpCode::IntSDiv, 16, 16, min16, max16), min16); // MIN / -1
    assert_eq!(wide_binary(OpCode::IntSRem, 16, 16, min16, max16), w(0)); // MIN % -1
    assert_eq!(
        wide_binary(OpCode::IntSRem, 16, 16, w((-7i128) as u128), w(2)),
        max16
    ); // -1
    assert_eq!(
        wide_binary(OpCode::IntRem, 16, 16, max16, w(10)),
        w(u128::MAX % 10)
    );

    assert_eq!(wide_binary(OpCode::BoolXor, 1, 1, w(1), w(1)), w(0));
    assert_eq!(
        wide_binary(OpCode::IntXor, 16, 16, max16, w(1)),
        w(u128::MAX - 1)
    );
    assert_eq!(wide_binary(OpCode::IntAnd, 16, 16, max16, w(0xf0)), w(0xf0));
    assert_eq!(
        wide_binary(OpCode::IntOr, 16, 16, min16, w(1)),
        w((1 << 127) | 1)
    );
}

#[test]
fn wide_piece_and_subpiece() {
    // An 8-byte high piece on a 16-byte low piece: 24 bytes.
    let high = w(0x1122_3344_5566_7788);
    let low = w(0xaabb_ccdd_eeff_0011_2233_4455_6677_8899);
    let joined = wide_binary(OpCode::Piece, 24, 8, high, low);
    assert_eq!(joined, (high << 128) | low);
    assert_eq!(wide_binary(OpCode::SubPiece, 8, 24, joined, w(16)), high);
    assert_eq!(wide_binary(OpCode::SubPiece, 16, 24, joined, w(0)), low);
    assert_eq!(
        wide_binary(OpCode::SubPiece, 4, 24, joined, w(20)),
        w(0x1122_3344)
    );
    assert_eq!(wide_binary(OpCode::SubPiece, 4, 24, joined, w(24)), w(0));
    assert_eq!(
        wide_binary(OpCode::SubPiece, 4, 24, joined, Wide::MAX),
        w(0)
    );
    // Two 32-byte halves of a 64-byte register.
    let whole = wide_binary(OpCode::Piece, 64, 32, Wide::mask(32), Wide::ONE);
    assert_eq!(whole, (Wide::mask(32) << 256) | Wide::ONE);
    assert_eq!(
        wide_binary(OpCode::SubPiece, 32, 64, whole, w(32)),
        Wide::mask(32)
    );
}

#[test]
fn wide_sizes_are_limited_to_64_bytes() {
    let too_big = Err(EvalError::UnsupportedSize {
        size: 65,
        limit: 64,
    });
    let (a, b) = (Wide::ONE, Wide::ONE);
    assert_eq!(
        wide::evaluate_unary(OpCode::Copy, 65, 4, &a, &FORMATS),
        too_big
    );
    assert_eq!(
        wide::evaluate_unary(OpCode::Copy, 4, 65, &a, &FORMATS),
        too_big
    );
    assert_eq!(
        wide::evaluate_binary(OpCode::IntAdd, 65, 65, &a, &b, &FORMATS),
        too_big
    );
    assert!(wide::evaluate_binary(OpCode::IntAdd, 64, 64, &a, &b, &FORMATS).is_ok());
    assert_eq!(wide_unary(OpCode::Copy, 0, 0, Wide::MAX), Wide::ZERO);
}

#[test]
fn wide_float_operations_use_the_exact_level() {
    let x87 = FloatFormat::EXTENDED;
    let quad = FloatFormat::QUAD;
    let encode = |format: &FloatFormat, value: f64| {
        format.encode_big_float(&format.big_float_from_f64(value).unwrap())
    };
    let decode = |format: &FloatFormat, encoding: Wide| format.decode_big_float(&encoding).to_f64();
    for (format, size) in [(&x87, 10u32), (&quad, 16), (&FloatFormat::OCTUPLE, 32)] {
        let (a, b) = (encode(format, 1.5), encode(format, 2.25));
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatAdd, size, size, a, b)),
            3.75
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatSub, size, size, a, b)),
            -0.75
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatMult, size, size, a, b)),
            3.375
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatDiv, size, size, b, a)),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatSqrt, size, size, b)),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatNeg, size, size, a)),
            -1.5
        );
        assert_eq!(
            decode(
                format,
                wide_unary(OpCode::FloatAbs, size, size, encode(format, -1.5))
            ),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatCeil, size, size, a)),
            2.0
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatFloor, size, size, a)),
            1.0
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatRound, size, size, a)),
            2.0
        );
        assert_eq!(wide_unary(OpCode::FloatTrunc, 8, size, b), w(2));
        assert_eq!(
            wide_unary(OpCode::FloatTrunc, 4, size, encode(format, -2.25)),
            w(0xffff_fffe)
        );
        assert_eq!(wide_binary(OpCode::FloatLess, 1, size, a, b), w(1));
        assert_eq!(wide_binary(OpCode::FloatLessEqual, 1, size, b, a), w(0));
        assert_eq!(wide_binary(OpCode::FloatEqual, 1, size, a, a), w(1));
        assert_eq!(wide_binary(OpCode::FloatNotEqual, 1, size, a, a), w(0));
        assert_eq!(wide_unary(OpCode::FloatNan, 1, size, a), w(0));
        assert_eq!(
            wide_unary(OpCode::FloatNan, 1, size, format.big_nan_encoding(false)),
            w(1)
        );
        // Conversions to and from binary64, and from integers.
        let from_double = wide_unary(
            OpCode::FloatFloat2Float,
            size,
            8,
            w(u128::from(0.1f64.to_bits())),
        );
        assert_eq!(decode(format, from_double), 0.1);
        let to_double = wide_unary(OpCode::FloatFloat2Float, 8, size, from_double);
        assert_eq!(to_double, w(u128::from(0.1f64.to_bits())));
        let from_int = wide_unary(
            OpCode::FloatInt2Float,
            size,
            8,
            w(u128::from((-12345i64) as u64)),
        );
        assert_eq!(decode(format, from_int), -12345.0);
        // The result is a clean value of the format's size.
        assert_eq!(
            wide_binary(OpCode::FloatAdd, size, size, a, b).truncate(size),
            wide_binary(OpCode::FloatAdd, size, size, a, b)
        );
    }
    // 1/3 in binary128 has the repeating fraction 0x5555…
    let third = wide_binary(
        OpCode::FloatDiv,
        16,
        16,
        encode(&quad, 1.0),
        encode(&quad, 3.0),
    );
    assert_eq!(third, w(0x3ffd_5555_5555_5555_5555_5555_5555_5555));
    // sqrt(2) in binary128.
    let root = wide_unary(OpCode::FloatSqrt, 16, 16, encode(&quad, 2.0));
    assert_eq!(root, w(0x3fff_6a09_e667_f3bc_c908_b2fb_1366_ea95));
    // 1/3 in the x87 format: exponent 0x3ffd, significand 0xaaaa…ab.
    let third = wide_binary(
        OpCode::FloatDiv,
        10,
        10,
        encode(&x87, 1.0),
        encode(&x87, 3.0),
    );
    assert_eq!(third, w((0x3ffd_u128 << 64) | 0xaaaa_aaaa_aaaa_aaab));
    // No format for 12 bytes.
    let none = wide::evaluate_binary(
        OpCode::FloatAdd,
        12,
        12,
        &Wide::ZERO,
        &Wide::ZERO,
        &FloatFormats::IEEE,
    );
    assert_eq!(
        none,
        Err(EvalError::NoFloatFormat {
            op: OpCode::FloatAdd,
            size: 12
        })
    );
    // The decompiler's table has no wide formats.
    let none = wide::evaluate_binary(OpCode::FloatAdd, 16, 16, &Wide::ZERO, &Wide::ZERO, &FORMATS);
    assert_eq!(
        none,
        Err(EvalError::NoFloatFormat {
            op: OpCode::FloatAdd,
            size: 16
        })
    );
}
