//! Floating-point operations on operands of at most 8 bytes, evaluated at
//! the host level ([`crate::float::host`]) as `opbehavior.cc` does.

use crate::error::{Arity, EvalError};
use crate::float::{FloatFormat, FloatFormats};
use crate::opcode::OpCode;

/// The host-level format for operands of `size` bytes.
#[inline]
fn format(formats: &FloatFormats, op: OpCode, size: u32) -> Result<&FloatFormat, EvalError> {
    let format = formats
        .get(size)
        .ok_or(EvalError::NoFloatFormat { op, size })?;
    if format.is_host_format() {
        Ok(format)
    } else {
        Err(EvalError::UnsupportedSize { size, limit: 8 })
    }
}

/// Evaluates a unary floating-point operation.
pub(super) fn evaluate_unary(
    op: OpCode,
    size_out: u32,
    size_in: u32,
    in1: u64,
    formats: &FloatFormats,
) -> Result<u64, EvalError> {
    Ok(match op {
        OpCode::FloatNan => format(formats, op, size_in)?.op_nan(in1),
        OpCode::FloatNeg => format(formats, op, size_in)?.op_neg(in1),
        OpCode::FloatAbs => format(formats, op, size_in)?.op_abs(in1),
        OpCode::FloatSqrt => format(formats, op, size_in)?.op_sqrt(in1),
        OpCode::FloatInt2Float => format(formats, op, size_out)?.op_int2float(in1, size_in),
        OpCode::FloatFloat2Float => {
            let format_out = format(formats, op, size_out)?;
            format(formats, op, size_in)?.op_float2float(in1, format_out)
        }
        OpCode::FloatTrunc => format(formats, op, size_in)?.op_trunc(in1, size_out),
        OpCode::FloatCeil => format(formats, op, size_in)?.op_ceil(in1),
        OpCode::FloatFloor => format(formats, op, size_in)?.op_floor(in1),
        OpCode::FloatRound => format(formats, op, size_in)?.op_round(in1),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Unary,
            });
        }
    })
}

/// Evaluates a binary floating-point operation.
pub(super) fn evaluate_binary(
    op: OpCode,
    size_in: u32,
    in1: u64,
    in2: u64,
    formats: &FloatFormats,
) -> Result<u64, EvalError> {
    let format = format(formats, op, size_in)?;
    Ok(match op {
        OpCode::FloatEqual => format.op_equal(in1, in2),
        OpCode::FloatNotEqual => format.op_not_equal(in1, in2),
        OpCode::FloatLess => format.op_less(in1, in2),
        OpCode::FloatLessEqual => format.op_less_equal(in1, in2),
        OpCode::FloatAdd => format.op_add(in1, in2),
        OpCode::FloatDiv => format.op_div(in1, in2),
        OpCode::FloatMult => format.op_mult(in1, in2),
        OpCode::FloatSub => format.op_sub(in1, in2),
        _ => {
            return Err(EvalError::Unimplemented {
                op,
                arity: Arity::Binary,
            });
        }
    })
}
