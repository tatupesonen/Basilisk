//! Integer arithmetic, comparison, shift and extension operations on
//! operands of at most 8 bytes, as `opbehavior.cc` defines them.
//!
//! Inputs are expected to be *clean* (no bits above their size), as Ghidra's
//! callers guarantee; like the C++, most operations do not mask their inputs.

use crate::error::EvalError;
use crate::mask::{
    calc_mask, sign_bit_mask, sign_bit_shift, sign_extend_bit, signbit_negative, zero_extend_bit,
};

/// The position of the sign bit of a `size`-byte integer as the two-argument
/// `sign_extend` and `zero_extend` take it (`8 * size - 1`).
#[inline]
const fn top_bit(size: u32) -> u32 {
    size.wrapping_mul(8).wrapping_sub(1)
}

/// Whether a shift amount moves every bit out of an operand of `size` bytes.
#[inline]
fn shifts_out(amount: u64, size: u32) -> bool {
    amount >= u64::from(size) * 8 || amount >= 64
}

/// `INT_SLESS`.
#[inline]
pub(super) fn int_sless(size_in: u32, in1: u64, in2: u64) -> u64 {
    if size_in == 0 {
        return 0;
    }
    let mask = sign_bit_mask(size_in);
    let (bit1, bit2) = (in1 & mask, in2 & mask);
    u64::from(if bit1 == bit2 { in1 < in2 } else { bit1 != 0 })
}

/// `INT_SLESSEQUAL`.
#[inline]
pub(super) fn int_sless_equal(size_in: u32, in1: u64, in2: u64) -> u64 {
    if size_in == 0 {
        return 0;
    }
    let mask = sign_bit_mask(size_in);
    let (bit1, bit2) = (in1 & mask, in2 & mask);
    u64::from(if bit1 == bit2 { in1 <= in2 } else { bit1 != 0 })
}

/// `INT_CARRY`.
#[inline]
pub(super) fn int_carry(size_in: u32, in1: u64, in2: u64) -> u64 {
    u64::from(in1 > (in1.wrapping_add(in2) & calc_mask(size_in)))
}

/// `INT_SCARRY`.
#[inline]
pub(super) fn int_scarry(size_in: u32, in1: u64, in2: u64) -> u64 {
    let shift = sign_bit_shift(size_in);
    let a = (in1 >> shift) & 1;
    let b = (in2 >> shift) & 1;
    let r = (in1.wrapping_add(in2) >> shift) & 1;
    (r ^ a) & (a ^ b ^ 1)
}

/// `INT_SBORROW`.
#[inline]
pub(super) fn int_sborrow(size_in: u32, in1: u64, in2: u64) -> u64 {
    let shift = sign_bit_shift(size_in);
    let a = (in1 >> shift) & 1;
    let b = (in2 >> shift) & 1;
    let r = (in1.wrapping_sub(in2) >> shift) & 1;
    (a ^ r) & (r ^ b ^ 1)
}

/// `INT_LEFT`.
#[inline]
pub(super) fn int_left(size_out: u32, in1: u64, in2: u64) -> u64 {
    if shifts_out(in2, size_out) {
        0
    } else {
        (in1 << in2) & calc_mask(size_out)
    }
}

/// `INT_RIGHT`.
#[inline]
pub(super) fn int_right(size_out: u32, in1: u64, in2: u64) -> u64 {
    if shifts_out(in2, size_out) {
        0
    } else {
        (in1 & calc_mask(size_out)) >> in2
    }
}

/// `INT_SRIGHT`.
#[inline]
pub(super) fn int_sright(size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    let negative = signbit_negative(in1, size_in);
    if shifts_out(in2, size_out) {
        return if negative { calc_mask(size_out) } else { 0 };
    }
    let res = in1 >> in2;
    if negative {
        let mask = calc_mask(size_in);
        res | ((mask >> in2) ^ mask)
    } else {
        res
    }
}

/// `INT_DIV`.
#[inline]
pub(super) fn int_div(in1: u64, in2: u64) -> Result<u64, EvalError> {
    in1.checked_div(in2).ok_or(EvalError::DivideByZero)
}

/// `INT_SDIV`. `MIN / -1` is `MIN`.
#[inline]
pub(super) fn int_sdiv(size_out: u32, size_in: u32, in1: u64, in2: u64) -> Result<u64, EvalError> {
    let num = sign_extend_bit(in1, top_bit(size_in));
    let denom = sign_extend_bit(in2, top_bit(size_in));
    if denom == 0 {
        return Err(EvalError::DivideByZero);
    }
    Ok(zero_extend_bit(
        num.wrapping_div(denom) as u64,
        top_bit(size_out),
    ))
}

/// `INT_REM`.
#[inline]
pub(super) fn int_rem(in1: u64, in2: u64) -> Result<u64, EvalError> {
    in1.checked_rem(in2).ok_or(EvalError::RemainderByZero)
}

/// `INT_SREM`. `MIN % -1` is 0.
#[inline]
pub(super) fn int_srem(size_out: u32, size_in: u32, in1: u64, in2: u64) -> Result<u64, EvalError> {
    let val = sign_extend_bit(in1, top_bit(size_in));
    let modulus = sign_extend_bit(in2, top_bit(size_in));
    if modulus == 0 {
        return Err(EvalError::RemainderByZero);
    }
    Ok(zero_extend_bit(
        val.wrapping_rem(modulus) as u64,
        top_bit(size_out),
    ))
}
