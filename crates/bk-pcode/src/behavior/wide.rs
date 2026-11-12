//! Evaluation on [`Wide`] operands of up to 64 bytes.
//!
//! This is the path for operands wider than a `u64` (vector registers, 80-
//! and 128-bit floats). It reproduces the `BigInteger` methods of Ghidra's
//! Java behaviours (`ghidra/pcode/opbehavior/*.java`), with the result cut to
//! `size_out` bytes — which is what Java's emulator does when it stores the
//! `BigInteger` into the output varnode.
//!
//! Floating-point operations use the exact level
//! ([`BigFloat`](crate::float::BigFloat)) for every size, as the Java
//! `BigInteger` methods do.
//!
//! Inputs are expected to be clean. An input with bits above its size is cut
//! to its size where an operation is sensitive to them.

use crate::error::{Arity, EvalError};
use crate::float::{FloatFormat, FloatFormats};
use crate::opcode::OpCode;
use crate::wide::Wide;

/// Checks that an operand size fits a [`Wide`].
#[inline]
fn check_size(size: u32) -> Result<(), EvalError> {
    if size > Wide::BYTES {
        Err(EvalError::UnsupportedSize {
            size,
            limit: Wide::BYTES,
        })
    } else {
        Ok(())
    }
}

/// The exact-level format for operands of `size` bytes.
#[inline]
fn format(formats: &FloatFormats, op: OpCode, size: u32) -> Result<&FloatFormat, EvalError> {
    formats
        .get(size)
        .ok_or(EvalError::NoFloatFormat { op, size })
}

#[inline]
fn wide_bool(value: bool) -> Wide {
    if value { Wide::ONE } else { Wide::ZERO }
}

/// `value`, a `size`-byte twos-complement integer, with its sign bit flipped
/// after sign extension: unsigned order on the result is signed order on the
/// value.
#[inline]
fn signed_key(value: Wide, size: u32) -> Wide {
    value.sign_extend(size) ^ (Wide::ONE << (Wide::BITS - 1))
}

/// A shift amount as a bit count, saturated.
#[inline]
fn shift_amount(amount: Wide) -> u32 {
    amount
        .to_u64()
        .and_then(|bits| u32::try_from(bits).ok())
        .unwrap_or(u32::MAX)
}

/// The magnitude and sign of a `size`-byte twos-complement integer.
#[inline]
fn magnitude(value: Wide, size: u32) -> (Wide, bool) {
    let extended = value.sign_extend(size);
    if value.truncate(size).is_negative(size) {
        (extended.wrapping_neg(), true)
    } else {
        (extended, false)
    }
}

/// Evaluates a unary operation on the input `in1` of `size_in` bytes, giving
/// an output of `size_out` bytes.
///
/// Sizes above 64 bytes give [`EvalError::UnsupportedSize`].
pub fn evaluate_unary(
    op: OpCode,
    size_out: u32,
    size_in: u32,
    in1: &Wide,
    formats: &FloatFormats,
) -> Result<Wide, EvalError> {
    check_size(size_out)?;
    check_size(size_in)?;
    let in1 = *in1;
    let res = match op {
        OpCode::Copy | OpCode::IntZExt => in1,
        OpCode::IntSExt => in1.sign_extend(size_in),
        OpCode::Int2Comp => in1.wrapping_neg(),
        OpCode::IntNegate => !in1,
        OpCode::BoolNegate => in1 ^ Wide::ONE,
        OpCode::PopCount => Wide::from_u64(u64::from(in1.count_ones())),
        OpCode::LzCount => Wide::from_u64(u64::from(size_in * 8 - in1.truncate(size_in).bit_len())),
        OpCode::FloatNan => wide_bool(format(formats, op, size_in)?.op_nan_exact(&in1)),
        OpCode::FloatNeg => format(formats, op, size_in)?.op_neg_exact(&in1),
        OpCode::FloatAbs => format(formats, op, size_in)?.op_abs_exact(&in1),
        OpCode::FloatSqrt => format(formats, op, size_in)?.op_sqrt_exact(&in1),
        OpCode::FloatInt2Float => {
            format(formats, op, size_out)?.op_int2float_exact(&in1, size_in, true)
        }
        OpCode::FloatFloat2Float => {
            let format_out = format(formats, op, size_out)?;
            format(formats, op, size_in)?.op_float2float_exact(&in1, format_out)
        }
        OpCode::FloatTrunc => format(formats, op, size_in)?.op_trunc_exact(&in1),
        OpCode::FloatCeil => format(formats, op, size_in)?.op_ceil_exact(&in1),
        OpCode::FloatFloor => format(formats, op, size_in)?.op_floor_exact(&in1),
        OpCode::FloatRound => format(formats, op, size_in)?.op_round_exact(&in1),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Unary,
            });
        }
    };
    Ok(res.truncate(size_out))
}

/// Evaluates a binary operation on the inputs `in1` (of `size_in` bytes) and
/// `in2`, giving an output of `size_out` bytes.
///
/// Sizes above 64 bytes give [`EvalError::UnsupportedSize`].
pub fn evaluate_binary(
    op: OpCode,
    size_out: u32,
    size_in: u32,
    in1: &Wide,
    in2: &Wide,
    formats: &FloatFormats,
) -> Result<Wide, EvalError> {
    check_size(size_out)?;
    check_size(size_in)?;
    let (in1, in2) = (*in1, *in2);
    let res = match op {
        OpCode::IntEqual => wide_bool(in1 == in2),
        OpCode::IntNotEqual => wide_bool(in1 != in2),
        OpCode::IntSLess => {
            wide_bool(size_in != 0 && signed_key(in1, size_in) < signed_key(in2, size_in))
        }
        OpCode::IntSLessEqual => {
            wide_bool(size_in != 0 && signed_key(in1, size_in) <= signed_key(in2, size_in))
        }
        OpCode::IntLess => wide_bool(in1 < in2),
        OpCode::IntLessEqual => wide_bool(in1 <= in2),
        OpCode::IntAdd => in1.wrapping_add(in2),
        OpCode::IntSub => in1.wrapping_sub(in2),
        OpCode::IntCarry => wide_bool(in1 > in1.wrapping_add(in2).truncate(size_in)),
        OpCode::IntSCarry => {
            let (a, b) = (in1.is_negative(size_in), in2.is_negative(size_in));
            let r = in1.wrapping_add(in2).is_negative(size_in);
            wide_bool(r != a && a == b)
        }
        OpCode::IntSBorrow => {
            let (a, b) = (in1.is_negative(size_in), in2.is_negative(size_in));
            let r = in1.wrapping_sub(in2).is_negative(size_in);
            wide_bool(a != r && r == b)
        }
        OpCode::IntXor | OpCode::BoolXor => in1 ^ in2,
        OpCode::IntAnd | OpCode::BoolAnd => in1 & in2,
        OpCode::IntOr | OpCode::BoolOr => in1 | in2,
        OpCode::IntLeft => {
            let amount = shift_amount(in2);
            if amount >= size_in * 8 {
                Wide::ZERO
            } else {
                in1 << amount
            }
        }
        OpCode::IntRight => {
            let amount = shift_amount(in2);
            if amount >= size_in * 8 {
                Wide::ZERO
            } else {
                in1 >> amount
            }
        }
        OpCode::IntSRight => {
            if size_in == 0 {
                Wide::ZERO
            } else {
                let amount = shift_amount(in2).min(size_in * 8 - 1);
                let extended = in1.sign_extend(size_in);
                let fill = if in1.truncate(size_in).is_negative(size_in) {
                    !(Wide::MAX >> amount)
                } else {
                    Wide::ZERO
                };
                (extended >> amount) | fill
            }
        }
        OpCode::IntMult => in1.wrapping_mul(in2),
        OpCode::IntDiv => in1.checked_div(in2).ok_or(EvalError::DivideByZero)?,
        OpCode::IntSDiv => {
            let (num, num_negative) = magnitude(in1, size_in);
            let (denom, denom_negative) = magnitude(in2, size_in);
            let quotient = num.checked_div(denom).ok_or(EvalError::DivideByZero)?;
            if num_negative == denom_negative {
                quotient
            } else {
                quotient.wrapping_neg()
            }
        }
        OpCode::IntRem => in1.checked_rem(in2).ok_or(EvalError::RemainderByZero)?,
        OpCode::IntSRem => {
            let (num, num_negative) = magnitude(in1, size_in);
            let (denom, _) = magnitude(in2, size_in);
            let remainder = num.checked_rem(denom).ok_or(EvalError::RemainderByZero)?;
            if num_negative {
                remainder.wrapping_neg()
            } else {
                remainder
            }
        }
        OpCode::Piece => (in1 << (size_out.saturating_sub(size_in) * 8)) | in2,
        OpCode::SubPiece => in1.truncate(size_in) >> shift_amount(in2).saturating_mul(8),
        OpCode::FloatEqual => wide_bool(format(formats, op, size_in)?.op_equal_exact(&in1, &in2)),
        OpCode::FloatNotEqual => {
            wide_bool(format(formats, op, size_in)?.op_not_equal_exact(&in1, &in2))
        }
        OpCode::FloatLess => wide_bool(format(formats, op, size_in)?.op_less_exact(&in1, &in2)),
        OpCode::FloatLessEqual => {
            wide_bool(format(formats, op, size_in)?.op_less_equal_exact(&in1, &in2))
        }
        OpCode::FloatAdd => format(formats, op, size_in)?.op_add_exact(&in1, &in2),
        OpCode::FloatDiv => format(formats, op, size_in)?.op_div_exact(&in1, &in2),
        OpCode::FloatMult => format(formats, op, size_in)?.op_mult_exact(&in1, &in2),
        OpCode::FloatSub => format(formats, op, size_in)?.op_sub_exact(&in1, &in2),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Binary,
            });
        }
    };
    Ok(res.truncate(size_out))
}
