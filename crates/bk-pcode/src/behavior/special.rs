//! Data-flow and pointer operations that do have arithmetic (`PIECE`,
//! `SUBPIECE`, `PTRADD`, `PTRSUB`, `LZCOUNT`), as `opbehavior.cc` defines
//! them.
//!
//! The remaining special operations (`LOAD`, `STORE`, the branches and calls,
//! `MULTIEQUAL`, `INDIRECT`, `CAST`, `SEGMENTOP`, `CPOOLREF`, `NEW`) and the
//! bit-range operations Ghidra leaves unimplemented (`INSERT`, `ZPULL`,
//! `SPULL`) have none: evaluating them is
//! [`EvalError::Unimplemented`](crate::error::EvalError::Unimplemented).

use crate::mask::calc_mask;

/// `PIECE`: `in1` shifted above the low piece `in2`. `size_in` is the size of
/// `in1`, so the low piece has `size_out - size_in` bytes.
#[inline]
pub(super) fn piece(size_out: u32, size_in: u32, in1: u64, in2: u64) -> u64 {
    in1.wrapping_shl(size_out.wrapping_sub(size_in).wrapping_mul(8)) | in2
}

/// `SUBPIECE`: `size_out` bytes of `in1` starting at byte `in2`.
#[inline]
pub(super) fn subpiece(size_out: u32, in1: u64, in2: u64) -> u64 {
    if in2 >= 8 {
        0
    } else {
        (in1 >> (in2 * 8)) & calc_mask(size_out)
    }
}

/// `PTRADD`: `in1 + in2 * in3`.
#[inline]
pub(super) fn ptradd(size_out: u32, in1: u64, in2: u64, in3: u64) -> u64 {
    in1.wrapping_add(in2.wrapping_mul(in3)) & calc_mask(size_out)
}

/// `PTRSUB`: `in1 + in2`.
#[inline]
pub(super) fn ptrsub(size_out: u32, in1: u64, in2: u64) -> u64 {
    in1.wrapping_add(in2) & calc_mask(size_out)
}

/// `LZCOUNT`: the leading zero bits of `in1` taken as a `size_in`-byte
/// integer. The C++ computes `count_leading_zeros(in1) - 8 * (8 - size_in)`
/// in unsigned 64-bit arithmetic, which this reproduces for every input.
#[inline]
pub(super) fn lzcount(size_in: u32, in1: u64) -> u64 {
    u64::from(in1.leading_zeros())
        .wrapping_sub(8u64.wrapping_mul(8u64.wrapping_sub(u64::from(size_in))))
}
