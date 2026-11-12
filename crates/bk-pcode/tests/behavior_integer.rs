//! Derived tests of the integer, boolean and pointer operations on the
//! `u64` path: every edge case the feature spec lists (masking, extension,
//! shifts by the width or more, division by zero, carries, pieces, bit
//! counts). Derived from Ghidra's sources (`opbehavior.cc`, the Java
//! behaviours) rather than ported from its test suites.

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

use bk_pcode::behavior::{evaluate_binary, evaluate_ternary, evaluate_unary};
use bk_pcode::{EvalError, FloatFormats, OpCode};

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn unary(op: OpCode, size_out: u32, size_in: u32, in1: u64) -> u64 {
    evaluate_unary(op, size_out, size_in, in1, &FORMATS).unwrap()
}

fn binary(op: OpCode, size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS).unwrap()
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
