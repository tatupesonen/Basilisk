//! Derived tests of the operations' interfaces: operations without
//! arithmetic, which entry points each operation has, and `recover_input_*`
//! inverting `evaluate_*`.

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
use bk_pcode::{Arity, EvalError, FloatFormats, OpCode, RecoverOp, Wide};

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn unary(op: OpCode, size_out: u32, size_in: u32, in1: u64) -> u64 {
    evaluate_unary(op, size_out, size_in, in1, &FORMATS).unwrap()
}

fn binary(op: OpCode, size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS).unwrap()
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
