//! The behaviour of each p-code operation: evaluation on constant operands
//! and, where Ghidra implements it, recovery of an input from the output.
//!
//! Ghidra sources: `opbehavior.hh`/`opbehavior.cc` (C++, the decompiler's
//! constant folding, operands of at most 8 bytes) and
//! `ghidra/pcode/opbehavior/*.java` (Java, the emulator, including
//! `BigInteger` operands of any size).
//!
//! Two paths:
//!
//! - [`evaluate_unary`], [`evaluate_binary`], [`evaluate_ternary`] and the
//!   `recover_input_*` pair work on `u64` operands of at most 8 bytes and
//!   reproduce the **C++**. They are one `match` on the [`OpCode`]: no
//!   allocation and no dynamic dispatch.
//! - [`wide`] works on [`Wide`](crate::wide::Wide) operands of at most 64
//!   bytes and reproduces the **Java `BigInteger`** behaviours.
//!
//! Sizes are in bytes. `size_in` is the size of the first input, as in
//! Ghidra.

mod float;
mod integer;
mod recover;
mod special;
pub mod wide;

pub use recover::{recover_input_binary, recover_input_unary};

use crate::error::{Arity, EvalError};
use crate::float::FloatFormats;
use crate::mask::{calc_mask, sign_extend, uintb_negate};
use crate::opcode::OpCode;

/// Evaluates a unary operation on the input `in1` of `size_in` bytes, giving
/// an output of `size_out` bytes (`OpBehavior::evaluateUnary`).
///
/// Floating-point operations look their format up in `formats`.
#[inline]
pub fn evaluate_unary(
    op: OpCode,
    size_out: u32,
    size_in: u32,
    in1: u64,
    formats: &FloatFormats,
) -> Result<u64, EvalError> {
    Ok(match op {
        OpCode::Copy | OpCode::IntZExt => in1,
        OpCode::IntSExt => sign_extend(in1, size_in, size_out),
        OpCode::Int2Comp => uintb_negate(in1.wrapping_sub(1), size_in),
        OpCode::IntNegate => uintb_negate(in1, size_in),
        OpCode::BoolNegate => in1 ^ 1,
        OpCode::PopCount => u64::from(in1.count_ones()),
        OpCode::LzCount => special::lzcount(size_in, in1),
        OpCode::FloatNan
        | OpCode::FloatNeg
        | OpCode::FloatAbs
        | OpCode::FloatSqrt
        | OpCode::FloatInt2Float
        | OpCode::FloatFloat2Float
        | OpCode::FloatTrunc
        | OpCode::FloatCeil
        | OpCode::FloatFloor
        | OpCode::FloatRound => return float::evaluate_unary(op, size_out, size_in, in1, formats),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Unary,
            });
        }
    })
}

/// Evaluates a binary operation on the inputs `in1` (of `size_in` bytes) and
/// `in2`, giving an output of `size_out` bytes
/// (`OpBehavior::evaluateBinary`).
///
/// Floating-point operations look their format up in `formats`.
#[inline]
pub fn evaluate_binary(
    op: OpCode,
    size_out: u32,
    size_in: u32,
    in1: u64,
    in2: u64,
    formats: &FloatFormats,
) -> Result<u64, EvalError> {
    Ok(match op {
        OpCode::IntEqual => u64::from(in1 == in2),
        OpCode::IntNotEqual => u64::from(in1 != in2),
        OpCode::IntSLess => integer::int_sless(size_in, in1, in2),
        OpCode::IntSLessEqual => integer::int_sless_equal(size_in, in1, in2),
        OpCode::IntLess => u64::from(in1 < in2),
        OpCode::IntLessEqual => u64::from(in1 <= in2),
        OpCode::IntAdd | OpCode::PtrSub => special::ptrsub(size_out, in1, in2),
        OpCode::IntSub => in1.wrapping_sub(in2) & calc_mask(size_out),
        OpCode::IntCarry => integer::int_carry(size_in, in1, in2),
        OpCode::IntSCarry => integer::int_scarry(size_in, in1, in2),
        OpCode::IntSBorrow => integer::int_sborrow(size_in, in1, in2),
        OpCode::IntXor | OpCode::BoolXor => in1 ^ in2,
        OpCode::IntAnd | OpCode::BoolAnd => in1 & in2,
        OpCode::IntOr | OpCode::BoolOr => in1 | in2,
        OpCode::IntLeft => integer::int_left(size_out, in1, in2),
        OpCode::IntRight => integer::int_right(size_out, in1, in2),
        OpCode::IntSRight => integer::int_sright(size_out, size_in, in1, in2),
        OpCode::IntMult => in1.wrapping_mul(in2) & calc_mask(size_out),
        OpCode::IntDiv => return integer::int_div(in1, in2),
        OpCode::IntSDiv => return integer::int_sdiv(size_out, size_in, in1, in2),
        OpCode::IntRem => return integer::int_rem(in1, in2),
        OpCode::IntSRem => return integer::int_srem(size_out, size_in, in1, in2),
        OpCode::Piece => special::piece(size_out, size_in, in1, in2),
        OpCode::SubPiece => special::subpiece(size_out, in1, in2),
        OpCode::FloatEqual
        | OpCode::FloatNotEqual
        | OpCode::FloatLess
        | OpCode::FloatLessEqual
        | OpCode::FloatAdd
        | OpCode::FloatDiv
        | OpCode::FloatMult
        | OpCode::FloatSub => return float::evaluate_binary(op, size_in, in1, in2, formats),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Binary,
            });
        }
    })
}

/// Evaluates a ternary operation (`OpBehavior::evaluateTernary`). Only
/// `PTRADD` has one: `in1 + in2 * in3`.
#[inline]
pub fn evaluate_ternary(
    op: OpCode,
    size_out: u32,
    _size_in: u32,
    in1: u64,
    in2: u64,
    in3: u64,
) -> Result<u64, EvalError> {
    match op {
        OpCode::PtrAdd => Ok(special::ptradd(size_out, in1, in2, in3)),
        _ => Err(EvalError::Unimplemented {
            op,
            arity: Arity::Ternary,
        }),
    }
}
