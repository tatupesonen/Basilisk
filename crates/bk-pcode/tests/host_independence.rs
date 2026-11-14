//! Results that Ghidra's C++ takes from the host and basilisk must give the
//! same on every host: directed NaN, conversion and rounding cases with the
//! expected bits written out, so that CI on Linux x86-64, macOS AArch64 and
//! Windows checks the same values.
//!
//! The `u64` path follows Ghidra's compiled C++ on x86-64 Linux (ADR-021);
//! every expected value in `HOST_LEVEL` is that build's result, and the test
//! also checks each against the checked-in oracle table
//! (`tests/data/opbehavior_cpp.txt.gz`). What the rows pin:
//!
//! - one NaN input: the result is the quiet NaN with its sign (a signalling
//!   NaN is quieted, the payload is not kept);
//! - two NaN inputs: `FLOAT_ADD` and `FLOAT_MULT` pass on the sign of the
//!   second, `FLOAT_SUB` and `FLOAT_DIV` that of the first (AArch64 takes the
//!   first for all four);
//! - a NaN created from non-NaN inputs (`inf - inf`, `0 / 0`, `0 * inf`,
//!   `sqrt(-1)`) is negative (AArch64: positive);
//! - unary operations on NaNs, `FLOAT_NEG`/`FLOAT_ABS` on the sign bit,
//!   `FLOAT2FLOAT` of NaNs, comparisons with NaNs, `FLOAT_ROUND` of the
//!   largest double below one half (the C library's `round` is wrong there
//!   on MinGW), `INT2FLOAT` of the most negative integers.
//!
//! `FLOAT_TRUNC` out of range is the one host-dependent case where basilisk
//! does not take x86-64's result (Java's tests pin saturation, ADR-021):
//! `TRUNC` rows give basilisk's value and x86-64's in a comment. The wide
//! path (Java `BigFloat`) gives the positive quiet NaN for every NaN result.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

use std::collections::HashMap;
use std::io::Read;

use bk_pcode::OpCode::{self, *};
use bk_pcode::behavior::{evaluate_binary, evaluate_unary, wide};
use bk_pcode::{FloatFormats, Wide};

/// `(op, size_out, size_in, a, b, expected)`; `b` is `None` for a unary
/// operation.
type Row = (OpCode, u32, u32, u64, Option<u64>, u64);

/// Ghidra's C++ results on x86-64 Linux (GCC 14.4).
#[rustfmt::skip]
const HOST_LEVEL: &[Row] = &[
    (FloatAdd, 4, 4, 0x7fc0_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatAdd, 4, 4, 0xffc0_0000, Some(0x7fc0_0000), 0x7fc0_0000),
    (FloatAdd, 4, 4, 0x7f80_0001, Some(0xffc0_0000), 0xffc0_0000),
    (FloatAdd, 4, 4, 0xff80_0001, Some(0x7fc0_0000), 0x7fc0_0000),
    (FloatAdd, 4, 4, 0xffc0_0000, Some(0x7f80_0001), 0x7fc0_0000),
    (FloatAdd, 4, 4, 0xff80_0001, Some(0x7f80_0001), 0x7fc0_0000),
    (FloatAdd, 4, 4, 0xffc0_0000, Some(0x3f80_0000), 0xffc0_0000),
    (FloatAdd, 4, 4, 0x3f80_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatAdd, 4, 4, 0x7f80_0001, Some(0x3f80_0000), 0x7fc0_0000),
    (FloatAdd, 4, 4, 0x3f80_0000, Some(0xff80_0001), 0xffc0_0000),
    (FloatAdd, 4, 4, 0x7f80_0000, Some(0x7f80_0000), 0x7f80_0000),
    (FloatAdd, 4, 4, 0x0, Some(0x0), 0x0),
    (FloatAdd, 4, 4, 0x0, Some(0x7f80_0000), 0x7f80_0000),
    (FloatAdd, 8, 8, 0x7ff8_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0x7ff0_0000_0000_0001, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff0_0000_0000_0001), 0x7ff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff0_0000_0000_0001), 0x7ff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0xfff8_0000_0000_0000, Some(0x3ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0x7ff0_0000_0000_0001, Some(0x3ff0_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatAdd, 8, 8, 0x7ff0_0000_0000_0000, Some(0x7ff0_0000_0000_0000), 0x7ff0_0000_0000_0000),
    (FloatAdd, 8, 8, 0x0, Some(0x0), 0x0),
    (FloatAdd, 8, 8, 0x0, Some(0x7ff0_0000_0000_0000), 0x7ff0_0000_0000_0000),
    (FloatDiv, 4, 4, 0x7fc0_0000, Some(0xffc0_0000), 0x7fc0_0000),
    (FloatDiv, 4, 4, 0xffc0_0000, Some(0x7fc0_0000), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x7f80_0001, Some(0xffc0_0000), 0x7fc0_0000),
    (FloatDiv, 4, 4, 0xff80_0001, Some(0x7fc0_0000), 0xffc0_0000),
    (FloatDiv, 4, 4, 0xffc0_0000, Some(0x7f80_0001), 0xffc0_0000),
    (FloatDiv, 4, 4, 0xff80_0001, Some(0x7f80_0001), 0xffc0_0000),
    (FloatDiv, 4, 4, 0xffc0_0000, Some(0x3f80_0000), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x3f80_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x7f80_0001, Some(0x3f80_0000), 0x7fc0_0000),
    (FloatDiv, 4, 4, 0x3f80_0000, Some(0xff80_0001), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x7f80_0000, Some(0x7f80_0000), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x0, Some(0x0), 0xffc0_0000),
    (FloatDiv, 4, 4, 0x0, Some(0x7f80_0000), 0x0),
    (FloatDiv, 8, 8, 0x7ff8_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x7ff0_0000_0000_0001, Some(0xfff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0xfff8_0000_0000_0000, Some(0x3ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x7ff0_0000_0000_0001, Some(0x3ff0_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x7ff0_0000_0000_0000, Some(0x7ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x0, Some(0x0), 0xfff8_0000_0000_0000),
    (FloatDiv, 8, 8, 0x0, Some(0x7ff0_0000_0000_0000), 0x0),
    (FloatMult, 4, 4, 0x7fc0_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatMult, 4, 4, 0xffc0_0000, Some(0x7fc0_0000), 0x7fc0_0000),
    (FloatMult, 4, 4, 0x7f80_0001, Some(0xffc0_0000), 0xffc0_0000),
    (FloatMult, 4, 4, 0xff80_0001, Some(0x7fc0_0000), 0x7fc0_0000),
    (FloatMult, 4, 4, 0xffc0_0000, Some(0x7f80_0001), 0x7fc0_0000),
    (FloatMult, 4, 4, 0xff80_0001, Some(0x7f80_0001), 0x7fc0_0000),
    (FloatMult, 4, 4, 0xffc0_0000, Some(0x3f80_0000), 0xffc0_0000),
    (FloatMult, 4, 4, 0x3f80_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatMult, 4, 4, 0x7f80_0001, Some(0x3f80_0000), 0x7fc0_0000),
    (FloatMult, 4, 4, 0x3f80_0000, Some(0xff80_0001), 0xffc0_0000),
    (FloatMult, 4, 4, 0x7f80_0000, Some(0x7f80_0000), 0x7f80_0000),
    (FloatMult, 4, 4, 0x0, Some(0x0), 0x0),
    (FloatMult, 4, 4, 0x0, Some(0x7f80_0000), 0xffc0_0000),
    (FloatMult, 8, 8, 0x7ff8_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatMult, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatMult, 8, 8, 0x7ff0_0000_0000_0001, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatMult, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatMult, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff0_0000_0000_0001), 0x7ff8_0000_0000_0000),
    (FloatMult, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff0_0000_0000_0001), 0x7ff8_0000_0000_0000),
    (FloatMult, 8, 8, 0xfff8_0000_0000_0000, Some(0x3ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatMult, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatMult, 8, 8, 0x7ff0_0000_0000_0001, Some(0x3ff0_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatMult, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatMult, 8, 8, 0x7ff0_0000_0000_0000, Some(0x7ff0_0000_0000_0000), 0x7ff0_0000_0000_0000),
    (FloatMult, 8, 8, 0x0, Some(0x0), 0x0),
    (FloatMult, 8, 8, 0x0, Some(0x7ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 4, 4, 0x7fc0_0000, Some(0xffc0_0000), 0x7fc0_0000),
    (FloatSub, 4, 4, 0xffc0_0000, Some(0x7fc0_0000), 0xffc0_0000),
    (FloatSub, 4, 4, 0x7f80_0001, Some(0xffc0_0000), 0x7fc0_0000),
    (FloatSub, 4, 4, 0xff80_0001, Some(0x7fc0_0000), 0xffc0_0000),
    (FloatSub, 4, 4, 0xffc0_0000, Some(0x7f80_0001), 0xffc0_0000),
    (FloatSub, 4, 4, 0xff80_0001, Some(0x7f80_0001), 0xffc0_0000),
    (FloatSub, 4, 4, 0xffc0_0000, Some(0x3f80_0000), 0xffc0_0000),
    (FloatSub, 4, 4, 0x3f80_0000, Some(0xffc0_0000), 0xffc0_0000),
    (FloatSub, 4, 4, 0x7f80_0001, Some(0x3f80_0000), 0x7fc0_0000),
    (FloatSub, 4, 4, 0x3f80_0000, Some(0xff80_0001), 0xffc0_0000),
    (FloatSub, 4, 4, 0x7f80_0000, Some(0x7f80_0000), 0xffc0_0000),
    (FloatSub, 4, 4, 0x0, Some(0x0), 0x0),
    (FloatSub, 4, 4, 0x0, Some(0x7f80_0000), 0xff80_0000),
    (FloatSub, 8, 8, 0x7ff8_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatSub, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x7ff0_0000_0000_0001, Some(0xfff8_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatSub, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0xfff8_0000_0000_0000, Some(0x7ff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0xfff0_0000_0000_0001, Some(0x7ff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0xfff8_0000_0000_0000, Some(0x3ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x7ff0_0000_0000_0001, Some(0x3ff0_0000_0000_0000), 0x7ff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x3ff0_0000_0000_0000, Some(0xfff0_0000_0000_0001), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x7ff0_0000_0000_0000, Some(0x7ff0_0000_0000_0000), 0xfff8_0000_0000_0000),
    (FloatSub, 8, 8, 0x0, Some(0x0), 0x0),
    (FloatSub, 8, 8, 0x0, Some(0x7ff0_0000_0000_0000), 0xfff0_0000_0000_0000),
    (FloatSqrt, 4, 4, 0x7fc0_0000, None, 0x7fc0_0000),
    (FloatSqrt, 4, 4, 0xffc0_0000, None, 0xffc0_0000),
    (FloatSqrt, 4, 4, 0x7f80_0001, None, 0x7fc0_0000),
    (FloatSqrt, 4, 4, 0xff80_0001, None, 0xffc0_0000),
    (FloatSqrt, 4, 4, 0xbf80_0000, None, 0xffc0_0000),
    (FloatSqrt, 8, 8, 0x7ff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatSqrt, 8, 8, 0xfff8_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatSqrt, 8, 8, 0x7ff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatSqrt, 8, 8, 0xfff0_0000_0000_0001, None, 0xfff8_0000_0000_0000),
    (FloatSqrt, 8, 8, 0xbff0_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatCeil, 4, 4, 0x7fc0_0000, None, 0x7fc0_0000),
    (FloatCeil, 4, 4, 0xffc0_0000, None, 0xffc0_0000),
    (FloatCeil, 4, 4, 0x7f80_0001, None, 0x7fc0_0000),
    (FloatCeil, 4, 4, 0xff80_0001, None, 0xffc0_0000),
    (FloatCeil, 4, 4, 0xbf80_0000, None, 0xbf80_0000),
    (FloatCeil, 8, 8, 0x7ff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatCeil, 8, 8, 0xfff8_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatCeil, 8, 8, 0x7ff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatCeil, 8, 8, 0xfff0_0000_0000_0001, None, 0xfff8_0000_0000_0000),
    (FloatCeil, 8, 8, 0xbff0_0000_0000_0000, None, 0xbff0_0000_0000_0000),
    (FloatFloor, 4, 4, 0x7fc0_0000, None, 0x7fc0_0000),
    (FloatFloor, 4, 4, 0xffc0_0000, None, 0xffc0_0000),
    (FloatFloor, 4, 4, 0x7f80_0001, None, 0x7fc0_0000),
    (FloatFloor, 4, 4, 0xff80_0001, None, 0xffc0_0000),
    (FloatFloor, 4, 4, 0xbf80_0000, None, 0xbf80_0000),
    (FloatFloor, 8, 8, 0x7ff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatFloor, 8, 8, 0xfff8_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatFloor, 8, 8, 0x7ff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatFloor, 8, 8, 0xfff0_0000_0000_0001, None, 0xfff8_0000_0000_0000),
    (FloatFloor, 8, 8, 0xbff0_0000_0000_0000, None, 0xbff0_0000_0000_0000),
    (FloatRound, 4, 4, 0x7fc0_0000, None, 0x7fc0_0000),
    (FloatRound, 4, 4, 0xffc0_0000, None, 0xffc0_0000),
    (FloatRound, 4, 4, 0x7f80_0001, None, 0x7fc0_0000),
    (FloatRound, 4, 4, 0xff80_0001, None, 0xffc0_0000),
    (FloatRound, 4, 4, 0xbf80_0000, None, 0xbf80_0000),
    (FloatRound, 8, 8, 0x7ff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatRound, 8, 8, 0xfff8_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatRound, 8, 8, 0x7ff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatRound, 8, 8, 0xfff0_0000_0000_0001, None, 0xfff8_0000_0000_0000),
    (FloatRound, 8, 8, 0xbff0_0000_0000_0000, None, 0xbff0_0000_0000_0000),
    (FloatNeg, 4, 4, 0x7fc0_0000, None, 0xffc0_0000),
    (FloatNeg, 4, 4, 0xffc0_0000, None, 0x7fc0_0000),
    (FloatNeg, 4, 4, 0x7f80_0001, None, 0xffc0_0000),
    (FloatNeg, 4, 4, 0xff80_0001, None, 0x7fc0_0000),
    (FloatNeg, 4, 4, 0xbf80_0000, None, 0x3f80_0000),
    (FloatNeg, 8, 8, 0x7ff8_0000_0000_0000, None, 0xfff8_0000_0000_0000),
    (FloatNeg, 8, 8, 0xfff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatNeg, 8, 8, 0x7ff0_0000_0000_0001, None, 0xfff8_0000_0000_0000),
    (FloatNeg, 8, 8, 0xfff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatNeg, 8, 8, 0xbff0_0000_0000_0000, None, 0x3ff0_0000_0000_0000),
    (FloatAbs, 4, 4, 0x7fc0_0000, None, 0x7fc0_0000),
    (FloatAbs, 4, 4, 0xffc0_0000, None, 0x7fc0_0000),
    (FloatAbs, 4, 4, 0x7f80_0001, None, 0x7fc0_0000),
    (FloatAbs, 4, 4, 0xff80_0001, None, 0x7fc0_0000),
    (FloatAbs, 4, 4, 0xbf80_0000, None, 0x3f80_0000),
    (FloatAbs, 8, 8, 0x7ff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatAbs, 8, 8, 0xfff8_0000_0000_0000, None, 0x7ff8_0000_0000_0000),
    (FloatAbs, 8, 8, 0x7ff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatAbs, 8, 8, 0xfff0_0000_0000_0001, None, 0x7ff8_0000_0000_0000),
    (FloatAbs, 8, 8, 0xbff0_0000_0000_0000, None, 0x3ff0_0000_0000_0000),
    (FloatNan, 1, 4, 0x7fc0_0000, None, 0x1),
    (FloatNan, 1, 4, 0xffc0_0000, None, 0x1),
    (FloatNan, 1, 4, 0x7f80_0001, None, 0x1),
    (FloatNan, 1, 4, 0xff80_0001, None, 0x1),
    (FloatNan, 1, 4, 0xbf80_0000, None, 0x0),
    (FloatNan, 1, 8, 0x7ff8_0000_0000_0000, None, 0x1),
    (FloatNan, 1, 8, 0xfff8_0000_0000_0000, None, 0x1),
    (FloatNan, 1, 8, 0x7ff0_0000_0000_0001, None, 0x1),
    (FloatNan, 1, 8, 0xfff0_0000_0000_0001, None, 0x1),
    (FloatNan, 1, 8, 0xbff0_0000_0000_0000, None, 0x0),
    (FloatFloat2Float, 8, 4, 0xff80_0001, None, 0xfff8_0000_0000_0000),
    (FloatFloat2Float, 4, 8, 0xfff0_0000_0000_0001, None, 0xffc0_0000),
    (FloatFloat2Float, 8, 4, 0x7fc0_0000, None, 0x7ff8_0000_0000_0000),
    (FloatFloat2Float, 4, 8, 0x7ff8_0000_0000_0000, None, 0x7fc0_0000),
    (FloatEqual, 1, 4, 0x7fc0_0000, Some(0x7fc0_0000), 0x0),
    (FloatNotEqual, 1, 4, 0x7fc0_0000, Some(0x7fc0_0000), 0x1),
    (FloatLess, 1, 8, 0x3ff0_0000_0000_0000, Some(0x7ff8_0000_0000_0000), 0x0),
    (FloatLessEqual, 1, 8, 0xfff8_0000_0000_0000, Some(0xfff8_0000_0000_0000), 0x0),
    (FloatEqual, 1, 4, 0x0, Some(0x8000_0000), 0x1),
    (FloatRound, 8, 8, 0x3fdf_ffff_ffff_ffff, None, 0x0),
    (FloatRound, 8, 8, 0xc004_0000_0000_0000, None, 0xc008_0000_0000_0000),
    (FloatRound, 4, 4, 0xc020_0000, None, 0xc040_0000),
    (FloatInt2Float, 4, 8, 0x8000_0000_0000_0000, None, 0xdf00_0000),
    (FloatInt2Float, 8, 4, 0x8000_0000, None, 0xc1e0_0000_0000_0000),
];

/// Out-of-range and NaN `FLOAT_TRUNC`: basilisk saturates and maps NaN to 0
/// (Java's `(long)`); x86-64's `cvttsd2si` gives `i64::MIN` cut to the size.
#[rustfmt::skip]
const TRUNC: &[Row] = &[
    (FloatTrunc, 8, 8, 0x7ff8_0000_0000_0000, None, 0), // x86-64: 0x8000_0000_0000_0000
    (FloatTrunc, 8, 4, 0x7fc0_0000, None, 0), // x86-64: 0x8000_0000_0000_0000
    (FloatTrunc, 8, 8, 0x7ff0_0000_0000_0000, None, 0x7fff_ffff_ffff_ffff), // x86-64: 0x8000_0000_0000_0000
    (FloatTrunc, 8, 8, 0x43e0_0000_0000_0000, None, 0x7fff_ffff_ffff_ffff), // x86-64: 0x8000_0000_0000_0000
    (FloatTrunc, 4, 8, 0x43e0_0000_0000_0000, None, 0xffff_ffff), // x86-64: 0
    (FloatTrunc, 1, 4, 0x7f80_0000, None, 0xff), // x86-64: 0
    (FloatTrunc, 8, 8, 0xfff0_0000_0000_0000, None, 0x8000_0000_0000_0000), // x86-64: the same
    (FloatTrunc, 4, 4, 0xff80_0001, None, 0), // x86-64: the same
];

fn evaluate(formats: &FloatFormats, row: &Row) -> u64 {
    let &(op, size_out, size_in, a, b, _) = row;
    match b {
        Some(b) => evaluate_binary(op, size_out, size_in, a, b, formats),
        None => evaluate_unary(op, size_out, size_in, a, formats),
    }
    .unwrap()
}

#[test]
fn host_dependent_results_are_x86_64s_on_every_host() {
    let formats = FloatFormats::DEFAULT;
    for row in HOST_LEVEL.iter().chain(TRUNC) {
        assert_eq!(evaluate(&formats, row), row.5, "{row:x?}");
    }
}

/// The expected values above are the checked-in oracle table's, so the two
/// cannot drift apart.
#[test]
fn directed_rows_agree_with_the_oracle_table() {
    let mut text = String::new();
    flate2::read::GzDecoder::new(&include_bytes!("data/opbehavior_cpp.txt.gz")[..])
        .read_to_string(&mut text)
        .unwrap();
    let table: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once(" = ")).collect();
    for row in HOST_LEVEL {
        let &(op, size_out, size_in, a, b, expected) = row;
        let key = match b {
            Some(b) => format!("B {:x} {size_out:x} {size_in:x} {a:x} {b:x}", op as u8),
            None => format!("U {:x} {size_out:x} {size_in:x} {a:x}", op as u8),
        };
        let cpp = table
            .get(key.as_str())
            .unwrap_or_else(|| panic!("{key} not in the table"));
        assert_eq!(u64::from_str_radix(cpp, 16).unwrap(), expected, "{key}");
    }
}

/// The wide path follows Java's `BigFloat`, which has no NaN sign: every NaN
/// result is the positive quiet NaN, whatever the inputs' signs.
#[test]
fn wide_path_nan_results_are_positive() {
    let formats = FloatFormats::IEEE;
    let cases: [(u32, u128, u128, u128); 3] = [
        (4, 0xffc0_0000, 0x7fc0_0000, 0x7fc0_0000),
        (
            8,
            0xfff8_0000_0000_0000,
            0xfff0_0000_0000_0001,
            0x7ff8_0000_0000_0000,
        ),
        (
            16,
            0xffff_8000_0000_0000_0000_0000_0000_0000,
            0xffff_0000_0000_0000_0000_0000_0000_0001,
            0x7fff_8000_0000_0000_0000_0000_0000_0000,
        ),
    ];
    for (size, a, b, nan) in cases {
        let (a, b, nan) = (Wide::from_u128(a), Wide::from_u128(b), Wide::from_u128(nan));
        for op in [FloatAdd, FloatSub, FloatMult, FloatDiv] {
            assert_eq!(
                wide::evaluate_binary(op, size, size, &a, &b, &formats),
                Ok(nan),
                "{op:?} at {size} bytes"
            );
        }
        assert_eq!(
            wide::evaluate_unary(FloatSqrt, size, size, &a, &formats),
            Ok(nan)
        );
    }
}
