#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Ghidra's JUnit tests of the boolean and bit-counting behaviours, ported
//! from `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorBoolAndTest`, `OpBehaviorBoolNegateTest`,
//! `OpBehaviorBoolOrTest`, `OpBehaviorBoolXorTest`, `OpBehaviorLzcountTest`
//! and `OpBehaviorPopcountTest`.
//!
//! Each Java `@Test` method is one test here, named after the class and the
//! method, and each Java assertion is one table row
//! `(size_out, size_in, inputs.., expected)`, in the Java order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`]. `Assert.assertEquals(long, long)` compares
//!   all 64 bits and so do these tests.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that is
//!   the wide path, [`bk_pcode::behavior::wide`], which returns the result cut
//!   to `size_out` bytes. Where Java passes a `sizeout` of 1 and then compares
//!   the low 16 (or 40) bytes
//!   (`AbstractOpBehaviorTest.assertEquals(expected, result, byteSize)`), the
//!   row here has the compared size as `size_out`; each such test says so.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{FloatFormats, OpCode, Wide};

const FORMATS: FloatFormats = FloatFormats::IEEE;

// The 16-byte constants of `AbstractOpBehaviorTest`.
const NEGATIVE_ONE: u128 = u128::MAX;
const BIG_POSITIVE: u128 = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const BIG_NEGATIVE: u128 = 0x8000_0000_0000_0000_0000_0000_0000_0000;

/// A row of a unary table: `(size_out, size_in, in1, expected)`.
type Unary<T> = (u32, u32, T, T);
/// A row of a binary table: `(size_out, size_in, in1, in2, expected)`.
type Binary<T> = (u32, u32, T, T, T);

/// Checks rows against the `u64` path (the Java `long` overload).
fn check_unary(op: OpCode, rows: &[Unary<u64>]) {
    for (row, &(size_out, size_in, in1, expected)) in rows.iter().enumerate() {
        assert_eq!(
            behavior::evaluate_unary(op, size_out, size_in, in1, &FORMATS),
            Ok(expected),
            "{op} row {row}: ({size_out}, {size_in}, {in1:#x})"
        );
    }
}

/// Checks rows against the `u64` path (the Java `long` overload).
fn check_binary(op: OpCode, rows: &[Binary<u64>]) {
    for (row, &(size_out, size_in, in1, in2, expected)) in rows.iter().enumerate() {
        assert_eq!(
            behavior::evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS),
            Ok(expected),
            "{op} row {row}: ({size_out}, {size_in}, {in1:#x}, {in2:#x})"
        );
    }
}

/// Checks rows against the wide path (the Java `BigInteger` overload).
fn check_unary_wide(op: OpCode, rows: &[Unary<u128>]) {
    for (row, &(size_out, size_in, in1, expected)) in rows.iter().enumerate() {
        assert_eq!(
            wide::evaluate_unary(op, size_out, size_in, &Wide::from_u128(in1), &FORMATS),
            Ok(Wide::from_u128(expected)),
            "{op} row {row}: ({size_out}, {size_in}, {in1:#x})"
        );
    }
}

/// Checks rows against the wide path (the Java `BigInteger` overload).
fn check_binary_wide(op: OpCode, rows: &[Binary<u128>]) {
    for (row, &(size_out, size_in, in1, in2, expected)) in rows.iter().enumerate() {
        let (wide1, wide2) = (Wide::from_u128(in1), Wide::from_u128(in2));
        assert_eq!(
            wide::evaluate_binary(op, size_out, size_in, &wide1, &wide2, &FORMATS),
            Ok(Wide::from_u128(expected)),
            "{op} row {row}: ({size_out}, {size_in}, {in1:#x}, {in2:#x})"
        );
    }
}

/// The 40-byte value the Java bit-counting tests build in a loop: twenty
/// 16-bit groups of `0x00ff`.
fn forty_bytes_of_00ff() -> Wide {
    let mut val = Wide::ZERO;
    for _ in 0..20 {
        val = (val << 16).wrapping_add(Wide::from_u64(0xff));
    }
    val
}

/// `OpBehaviorBoolAndTest.testEvaluateBinaryLong`.
#[test]
fn bool_and_evaluate_binary_long() {
    check_binary(
        OpCode::BoolAnd,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 0),
            (1, 1, 1, 0, 0),
            (1, 1, 1, 1, 1),
        ],
    );
}

/// `OpBehaviorBoolAndTest.testEvaluateBinaryBigInteger`.
#[test]
fn bool_and_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::BoolAnd,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 0),
            (1, 1, 1, 0, 0),
            (1, 1, 1, 1, 1),
        ],
    );
}

/// `OpBehaviorBoolNegateTest.testEvaluateBinaryLong`.
#[test]
fn bool_negate_evaluate_binary_long() {
    check_unary(OpCode::BoolNegate, &[(1, 1, 0, 1), (1, 1, 1, 0)]);
}

/// `OpBehaviorBoolNegateTest.testEvaluateBinaryBigInteger`.
#[test]
fn bool_negate_evaluate_binary_big_integer() {
    check_unary_wide(OpCode::BoolNegate, &[(1, 1, 0, 1), (1, 1, 1, 0)]);
}

/// `OpBehaviorBoolOrTest.testEvaluateBinaryLong`.
#[test]
fn bool_or_evaluate_binary_long() {
    check_binary(
        OpCode::BoolOr,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 1),
        ],
    );
}

/// `OpBehaviorBoolOrTest.testEvaluateBinaryBigInteger`.
#[test]
fn bool_or_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::BoolOr,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 1),
        ],
    );
}

/// `OpBehaviorBoolXorTest.testEvaluateBinaryLong`.
#[test]
fn bool_xor_evaluate_binary_long() {
    check_binary(
        OpCode::BoolXor,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 0),
        ],
    );
}

/// `OpBehaviorBoolXorTest.testEvaluateBinaryBigInteger`.
#[test]
fn bool_xor_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::BoolXor,
        &[
            (1, 1, 0, 0, 0),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 0),
        ],
    );
}

/// `OpBehaviorLzcountTest.testEvaluateUnaryLong`.
#[test]
fn lzcount_evaluate_unary_long() {
    check_unary(
        OpCode::LzCount,
        &[
            (1, 1, 0, 8),
            (1, 2, 0, 16),
            (1, 4, 0, 32),
            (1, 8, 0, 64),
            (1, 1, 0xff, 0),
            (1, 2, 0xffff, 0),
            (1, 4, 0xffff_ffff, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 0),
            (1, 1, 0x96, 0),
            (1, 2, 0xdbf4, 0),
            (1, 4, 0x460f_457b, 1),
            (1, 8, 0x1fae_97ef_ca7d_5759, 3),
            (1, 1, 0xa, 4),
            (1, 2, 0x2a5, 6),
            (1, 4, 0x60_dfff, 9),
            (1, 8, 0x6_3501_7ade_fe4e, 13),
            (1, 1, 0x17, 3),
            (1, 2, 0xd1, 8),
            (1, 4, 0x39e, 22),
            (1, 8, 0x18_9c17_8d6a, 27),
            (1, 1, 0xf, 4),
            (1, 2, 0xff0, 4),
            (1, 4, 0xffff_0000, 0),
            (1, 8, 0xff_00ff_00ff, 24),
        ],
    );
}

/// `OpBehaviorLzcountTest.testEvaluateUnaryBigInteger`.
#[test]
fn lzcount_evaluate_unary_big_integer() {
    // Java passes sizeout 1 and compares 16 (then 40) bytes; size_out is the compared size here.
    check_unary_wide(
        OpCode::LzCount,
        &[
            (16, 16, 0, 128),
            (16, 16, NEGATIVE_ONE, 0),
            (16, 16, BIG_POSITIVE, 1),
            (16, 16, BIG_NEGATIVE, 0),
            // Java builds this operand as `0x35017adefe4e << 64 | 0xd46223189c178d6a`.
            (16, 16, 0x3501_7ade_fe4e_d462_2318_9c17_8d6a, 18),
        ],
    );
    // Java builds this operand in a loop and passes sizes (1, 40).
    assert_eq!(
        wide::evaluate_unary(OpCode::LzCount, 40, 40, &forty_bytes_of_00ff(), &FORMATS),
        Ok(Wide::from_u64(8))
    );
}

/// `OpBehaviorPopcountTest.testEvaluateUnaryLong`.
#[test]
fn popcount_evaluate_unary_long() {
    check_unary(
        OpCode::PopCount,
        &[
            (1, 1, 0, 0),
            (1, 2, 0, 0),
            (1, 4, 0, 0),
            (1, 8, 0, 0),
            (1, 1, 0xff, 8),
            (1, 2, 0xffff, 16),
            (1, 4, 0xffff_ffff, 32),
            (1, 8, 0xffff_ffff_ffff_ffff, 64),
            (1, 1, 0x96, 4),
            (1, 2, 0xdbf4, 11),
            (1, 4, 0x460f_457b, 16),
            (1, 8, 0x1fae_97ef_ca7d_5759, 41),
            (1, 1, 0x7a, 5),
            (1, 2, 0xfca5, 10),
            (1, 4, 0x2660_dfff, 20),
            (1, 8, 0x79f6_3501_7ade_fe4e, 38),
            (1, 1, 0x17, 4),
            (1, 2, 0x77d1, 10),
            (1, 4, 0x5758_039e, 15),
            (1, 8, 0xd462_2318_9c17_8d6a, 28),
            (1, 1, 0xbf, 7),
            (1, 2, 0xe3ef, 12),
            (1, 4, 0xb2d7_e134, 17),
            (1, 8, 0x69_f7a0_fa6e_eda6, 34),
        ],
    );
}

/// `OpBehaviorPopcountTest.testEvaluateUnaryBigInteger`.
#[test]
fn popcount_evaluate_unary_big_integer() {
    // Java passes sizeout 1 and compares 16 (then 40) bytes; size_out is the compared size here.
    check_unary_wide(
        OpCode::PopCount,
        &[
            (16, 16, 0, 0),
            (16, 16, NEGATIVE_ONE, 128),
            (16, 16, BIG_POSITIVE, 127),
            (16, 16, BIG_NEGATIVE, 1),
            // Java builds this operand as `0x79f635017adefe4e << 64 | 0xd46223189c178d6a`.
            (16, 16, 0x79f6_3501_7ade_fe4e_d462_2318_9c17_8d6a, 66),
        ],
    );
    // Java builds this operand in a loop and passes sizes (1, 40).
    assert_eq!(
        wide::evaluate_unary(OpCode::PopCount, 40, 40, &forty_bytes_of_00ff(), &FORMATS),
        Ok(Wide::from_u64(160))
    );
}
