//! Recovering an input of an operation from its output
//! (`recoverInputUnary`, `recoverInputBinary` in `opbehavior.cc`).

use crate::error::{EvalError, RecoverOp};
use crate::mask::{calc_mask, uintb_negate};
use crate::opcode::OpCode;

/// `val << sa`, or 0 when `sa` is outside `0..64`.
#[inline]
fn shl(val: u64, sa: i64) -> u64 {
    u32::try_from(sa)
        .ok()
        .and_then(|sa| val.checked_shl(sa))
        .unwrap_or(0)
}

/// `val >> sa`, or 0 when `sa` is outside `0..64`.
#[inline]
fn shr(val: u64, sa: i64) -> u64 {
    u32::try_from(sa)
        .ok()
        .and_then(|sa| val.checked_shr(sa))
        .unwrap_or(0)
}

/// Recovers the input of a unary operation from its output `out`.
///
/// Implemented, as in Ghidra, for `COPY`, `INT_ZEXT`, `INT_SEXT`, `INT_2COMP`
/// and `INT_NEGATE`. Every other operation gives
/// [`EvalError::CannotRecover`]; an output no input can produce gives
/// [`EvalError::OutOfRange`].
pub fn recover_input_unary(
    op: OpCode,
    size_out: u32,
    out: u64,
    size_in: u32,
) -> Result<u64, EvalError> {
    match op {
        OpCode::Copy => Ok(out),
        OpCode::IntZExt => {
            if calc_mask(size_in) & out == out {
                Ok(out)
            } else {
                Err(EvalError::OutOfRange(RecoverOp::ZExt))
            }
        }
        OpCode::IntSExt => {
            let mask_long = calc_mask(size_out);
            let mask_short = calc_mask(size_in);
            let in_range = if out & (mask_short ^ (mask_short >> 1)) == 0 {
                // Positive input.
                out & mask_short == out
            } else {
                // Negative input.
                out & (mask_long ^ mask_short) == mask_long ^ mask_short
            };
            if in_range {
                Ok(out & mask_short)
            } else {
                Err(EvalError::OutOfRange(RecoverOp::SExt))
            }
        }
        OpCode::Int2Comp => Ok(uintb_negate(out.wrapping_sub(1), size_in)),
        OpCode::IntNegate => Ok(uintb_negate(out, size_in)),
        _ => Err(EvalError::CannotRecover),
    }
}

/// Recovers input `slot` (0 or 1) of a binary operation from its output
/// `out` and its other input `known`.
///
/// Implemented, as in Ghidra, for `INT_ADD` and `INT_SUB` (either slot) and
/// for slot 0 of `INT_LEFT`, `INT_RIGHT` and `INT_SRIGHT` when the shift
/// amount is less than the operand width. Every other case gives
/// [`EvalError::CannotRecover`]; an output no input can produce gives
/// [`EvalError::OutOfRange`].
///
/// Two behaviours are Ghidra's and are kept: the shifted results are not
/// masked to the operand size, and `INT_SRIGHT` only accepts an output whose
/// top `known + 1` bits are all set (the result of shifting a negative
/// value).
pub fn recover_input_binary(
    op: OpCode,
    slot: u32,
    size_out: u32,
    out: u64,
    size_in: u32,
    known: u64,
) -> Result<u64, EvalError> {
    let shift_amount = || {
        if slot != 0 || known >= u64::from(size_out) * 8 || known >= 64 {
            Err(EvalError::CannotRecover)
        } else {
            Ok(known as i64)
        }
    };
    match op {
        OpCode::IntAdd => Ok(out.wrapping_sub(known) & calc_mask(size_out)),
        OpCode::IntSub => {
            let res = if slot == 0 {
                known.wrapping_add(out)
            } else {
                known.wrapping_sub(out)
            };
            Ok(res & calc_mask(size_out))
        }
        OpCode::IntLeft => {
            let sa = shift_amount()?;
            if shl(out, 8 * i64::from(size_out) - sa) & calc_mask(size_out) != 0 {
                return Err(EvalError::OutOfRange(RecoverOp::LeftShift));
            }
            Ok(out >> sa)
        }
        OpCode::IntRight => {
            let sa = shift_amount()?;
            if shr(out, 8 * i64::from(size_in) - sa) != 0 {
                return Err(EvalError::OutOfRange(RecoverOp::RightShift));
            }
            Ok(out << sa)
        }
        OpCode::IntSRight => {
            let sa = shift_amount()?;
            let testval = shr(out, 8 * i64::from(size_in) - sa - 1);
            let wanted = if sa == 63 {
                u64::MAX
            } else {
                (1u64 << (sa + 1)) - 1
            };
            if testval & wanted != wanted {
                return Err(EvalError::OutOfRange(RecoverOp::RightShift));
            }
            Ok(out << sa)
        }
        _ => Err(EvalError::CannotRecover),
    }
}
