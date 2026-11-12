#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Ghidra's JUnit tests of the integer shift and comparison behaviours, ported
//! from `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorIntLeftTest`, `OpBehaviorIntRightTest`,
//! `OpBehaviorIntSRightTest`, `OpBehaviorIntLessTest`,
//! `OpBehaviorIntLessEqualTest`, `OpBehaviorIntSLessTest` and
//! `OpBehaviorIntSLessEqualTest`.
//!
//! Each Java `@Test` method is one test here, named after the class and the
//! method, and each Java assertion is one table row
//! `(size_out, size_in, in1, in2, expected)`, in the Java order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`]. A Java `long` is written as its 64-bit
//!   pattern. `Assert.assertEquals(long, long)` compares all 64 bits and so
//!   do these tests.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that is
//!   the wide path, [`bk_pcode::behavior::wide`], which returns the result cut
//!   to `size_out` bytes. The sizes are the ones Java passes.
//!
//! The Java classes `OpBehaviorIntSLessTest` and `OpBehaviorIntSLessEqualTest`
//! have their operations swapped: the first tests `INT_SLESSEQUAL` and the
//! second `INT_SLESS`. The tests here keep the Java class names and test the
//! operation the Java class tests.
//!
//! On the `u64` path basilisk compares a shift amount with `8 * size_out` as
//! the C++ does, where Java uses `8 * size_in`; every shift row here has equal
//! sizes, so the Java expectations hold unchanged.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{FloatFormats, OpCode, Wide};

const FORMATS: FloatFormats = FloatFormats::IEEE;

/// `Long.MIN_VALUE`.
const MIN: u64 = 1 << 63;
/// `Long.MAX_VALUE`.
const MAX: u64 = MIN - 1;

/// A negative Java `long` as its 64-bit pattern.
const fn long(value: i64) -> u64 {
    value as u64
}

// The 16-byte constants of `AbstractOpBehaviorTest`.
const NEGATIVE_ONE: u128 = u128::MAX;
const BIG_POSITIVE: u128 = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const BIG_NEGATIVE: u128 = 0x8000_0000_0000_0000_0000_0000_0000_0000;

/// A row of a table: `(size_out, size_in, in1, in2, expected)`.
type Binary<T> = (u32, u32, T, T, T);

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

/// `OpBehaviorIntLeftTest.testEvaluateBinaryLong`.
#[test]
fn int_left_evaluate_binary_long() {
    check_binary(
        OpCode::IntLeft,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, long(-1), 0),
            (4, 4, 1, 8, 0x100),
            (4, 4, 1, 31, 0x8000_0000),
            (4, 4, 1, 32, 0),
            (4, 4, 1, 33, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, long(-1), 0),
            (8, 8, 1, 8, 0x100),
            (8, 8, 1, 63, MIN),
            (8, 8, 1, 64, 0),
            (8, 8, 1, 65, 0),
        ],
    );
}

/// `OpBehaviorIntLeftTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_left_evaluate_binary_big_integer() {
    // Java compares `size_out` bytes. `getUnsignedBigInt(v)` is `v` as an unsigned 8-byte value.
    check_binary_wide(
        OpCode::IntLeft,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, 0xffff_ffff_ffff_ffff, 0),
            (4, 4, 1, 8, 0x100),
            (4, 4, 1, 31, 0x8000_0000),
            (4, 4, 1, 32, 0),
            (4, 4, 1, 33, 0),
            (4, 4, 0x8000_0000, 1, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (8, 8, 1, 8, 0x100),
            (8, 8, 1, 63, 0x8000_0000_0000_0000),
            (8, 8, 1, 64, 0),
            (8, 8, 1, 65, 0),
            // Java compares only the low 4 bytes of this result; all 8 are zero.
            (8, 8, 0x8000_0000_0000_0000, 1, 0),
        ],
    );
}

/// `OpBehaviorIntRightTest.testEvaluateBinaryLong`.
#[test]
fn int_right_evaluate_binary_long() {
    check_binary(
        OpCode::IntRight,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, long(-1), 0),
            (4, 4, 0x8000_0000, 8, 0x80_0000),
            (4, 4, 0x8000_0000, 31, 1),
            (4, 4, 0x8000_0000, 32, 0),
            (4, 4, 0x8000_0000, 33, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, long(-1), 0),
            (8, 8, 0x8000_0000_0000_0000, 8, 0x80_0000_0000_0000),
            (8, 8, 0x8000_0000_0000_0000, 63, 1),
            (8, 8, 0x8000_0000_0000_0000, 64, 0),
            (8, 8, 0x8000_0000_0000_0000, 65, 0),
        ],
    );
}

/// `OpBehaviorIntRightTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_right_evaluate_binary_big_integer() {
    // Java compares `size_out` bytes. `getUnsignedBigInt(v)` is `v` as an unsigned 8-byte value.
    check_binary_wide(
        OpCode::IntRight,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, 0xffff_ffff_ffff_ffff, 0),
            (4, 4, 0x8000_0000, 8, 0x80_0000),
            (4, 4, 0x8000_0000, 31, 1),
            (4, 4, 0x8000_0000, 32, 0),
            (4, 4, 0x8000_0000, 33, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (8, 8, 0x8000_0000_0000_0000, 8, 0x80_0000_0000_0000),
            (8, 8, 0x8000_0000_0000_0000, 63, 1),
            (8, 8, 0x8000_0000_0000_0000, 64, 0),
            (8, 8, 0x8000_0000_0000_0000, 65, 0),
        ],
    );
}

/// `OpBehaviorIntSRightTest.testEvaluateBinaryLong`.
#[test]
fn int_sright_evaluate_binary_long() {
    check_binary(
        OpCode::IntSRight,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, long(-1), 0),
            (4, 4, 0x8000_0000, 8, 0xff80_0000),
            (4, 4, 0x8000_0000, 31, 0xffff_ffff),
            (4, 4, 0x8000_0000, 32, 0xffff_ffff),
            (4, 4, 0x8000_0000, 33, 0xffff_ffff),
            (4, 4, 0x4000_0000, 8, 0x40_0000),
            (4, 4, 0x4000_0000, 31, 0),
            (4, 4, 0x4000_0000, 32, 0),
            (4, 4, 0x4000_0000, 33, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, long(-1), 0),
            (8, 8, 0x8000_0000_0000_0000, 8, 0xff80_0000_0000_0000),
            (8, 8, 0x8000_0000_0000_0000, 63, long(-1)),
            (8, 8, 0x8000_0000_0000_0000, 64, long(-1)),
            (8, 8, 0x8000_0000_0000_0000, 65, long(-1)),
            (8, 8, 0x4000_0000_0000_0000, 8, 0x40_0000_0000_0000),
            (8, 8, 0x4000_0000_0000_0000, 63, 0),
            (8, 8, 0x4000_0000_0000_0000, 64, 0),
            (8, 8, 0x4000_0000_0000_0000, 65, 0),
        ],
    );
}

/// `OpBehaviorIntSRightTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_sright_evaluate_binary_big_integer() {
    // Java compares `size_out` bytes. `getUnsignedBigInt(v)` is `v` as an unsigned 8-byte value.
    check_binary_wide(
        OpCode::IntSRight,
        &[
            (4, 4, 0, 8, 0),
            (4, 4, 0, 0xffff_ffff_ffff_ffff, 0),
            (4, 4, 0x8000_0000, 8, 0xff80_0000),
            (4, 4, 0x8000_0000, 31, 0xffff_ffff),
            (4, 4, 0x8000_0000, 32, 0xffff_ffff),
            (4, 4, 0x8000_0000, 33, 0xffff_ffff),
            (4, 4, 0x4000_0000, 8, 0x40_0000),
            (4, 4, 0x4000_0000, 31, 0),
            (4, 4, 0x4000_0000, 32, 0),
            (4, 4, 0x4000_0000, 33, 0),
            (8, 8, 0, 8, 0),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (8, 8, 0x8000_0000_0000_0000, 8, 0xff80_0000_0000_0000),
            (8, 8, 0x8000_0000_0000_0000, 63, 0xffff_ffff_ffff_ffff),
            (8, 8, 0x8000_0000_0000_0000, 64, 0xffff_ffff_ffff_ffff),
            (8, 8, 0x8000_0000_0000_0000, 65, 0xffff_ffff_ffff_ffff),
            (8, 8, 0x4000_0000_0000_0000, 8, 0x40_0000_0000_0000),
            (8, 8, 0x4000_0000_0000_0000, 63, 0),
            (8, 8, 0x4000_0000_0000_0000, 64, 0),
            (8, 8, 0x4000_0000_0000_0000, 65, 0),
        ],
    );
}

/// `OpBehaviorIntLessTest.testEvaluateBinaryLong`.
#[test]
fn int_less_evaluate_binary_long() {
    check_binary(
        OpCode::IntLess,
        &[
            (1, 4, 0, 0, 0),
            (1, 4, 1, 0, 0),
            (1, 4, 0, 1, 1),
            (1, 4, 0xffff_ffff, 0, 0),
            (1, 4, 0, 0xffff_ffff, 1),
            (1, 4, 0xffff_ffff, 1, 0),
            (1, 4, 1, 0xffff_ffff, 1),
            (1, 4, 0xffff_ffff, 0xffff_ffff, 0),
            (1, 4, 0x8000_0000, 0, 0),
            (1, 4, 0, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 1, 0),
            (1, 4, 1, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 0x7fff_ffff, 0),
            (1, 4, 0x7fff_ffff, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 0x8000_0000, 0),
            (1, 4, 0x7fff_ffff, 0x7fff_ffff, 0),
            (1, 4, 0xffff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0xffff_ffff, 1),
            (1, 8, 0, 0, 0),
            (1, 8, 1, 0, 0),
            (1, 8, 0, 1, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0, 0),
            (1, 8, 0, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 1, 0),
            (1, 8, 1, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, MIN, 0, 0),
            (1, 8, 0, MIN, 1),
            (1, 8, MIN, 1, 0),
            (1, 8, 1, MIN, 1),
            (1, 8, MIN, MAX, 0),
            (1, 8, MAX, MIN, 1),
            (1, 8, MIN, MIN, 0),
            (1, 8, MAX, MAX, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0),
            (1, 8, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1),
        ],
    );
}

/// `OpBehaviorIntLessTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_less_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::IntLess,
        &[
            (1, 16, 0, 0, 0),
            (1, 16, 1, 0, 0),
            (1, 16, 0, 1, 1),
            (1, 16, NEGATIVE_ONE, 0, 0),
            (1, 16, 0, NEGATIVE_ONE, 1),
            (1, 16, NEGATIVE_ONE, 1, 0),
            (1, 16, 1, NEGATIVE_ONE, 1),
            (1, 16, NEGATIVE_ONE, NEGATIVE_ONE, 0),
            (1, 16, BIG_NEGATIVE, 0, 0),
            (1, 16, 0, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, 1, 0),
            (1, 16, 1, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, BIG_POSITIVE, 0),
            (1, 16, BIG_POSITIVE, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, BIG_NEGATIVE, 0),
            (1, 16, BIG_POSITIVE, BIG_POSITIVE, 0),
        ],
    );
}

/// `OpBehaviorIntLessEqualTest.testEvaluateBinaryLong`.
#[test]
fn int_less_equal_evaluate_binary_long() {
    check_binary(
        OpCode::IntLessEqual,
        &[
            (1, 4, 0, 0, 1),
            (1, 4, 1, 0, 0),
            (1, 4, 0, 1, 1),
            (1, 4, 0xffff_ffff, 0, 0),
            (1, 4, 0, 0xffff_ffff, 1),
            (1, 4, 0xffff_ffff, 1, 0),
            (1, 4, 1, 0xffff_ffff, 1),
            (1, 4, 0xffff_ffff, 0xffff_ffff, 1),
            (1, 4, 0x8000_0000, 0, 0),
            (1, 4, 0, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 1, 0),
            (1, 4, 1, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 0x7fff_ffff, 0),
            (1, 4, 0x7fff_ffff, 0x8000_0000, 1),
            (1, 4, 0x8000_0000, 0x8000_0000, 1),
            (1, 4, 0x7fff_ffff, 0x7fff_ffff, 1),
            (1, 4, 0xffff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0xffff_ffff, 1),
            (1, 8, 0, 0, 1),
            (1, 8, 1, 0, 0),
            (1, 8, 0, 1, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0, 0),
            (1, 8, 0, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 1, 0),
            (1, 8, 1, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, MIN, 0, 0),
            (1, 8, 0, MIN, 1),
            (1, 8, MIN, 1, 0),
            (1, 8, 1, MIN, 1),
            (1, 8, MIN, MAX, 0),
            (1, 8, MAX, MIN, 1),
            (1, 8, MIN, MIN, 1),
            (1, 8, MAX, MAX, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0),
            (1, 8, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1),
        ],
    );
}

/// `OpBehaviorIntLessEqualTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_less_equal_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::IntLessEqual,
        &[
            (1, 16, 0, 0, 1),
            (1, 16, 1, 0, 0),
            (1, 16, 0, 1, 1),
            (1, 16, NEGATIVE_ONE, 0, 0),
            (1, 16, 0, NEGATIVE_ONE, 1),
            (1, 16, NEGATIVE_ONE, 1, 0),
            (1, 16, 1, NEGATIVE_ONE, 1),
            (1, 16, NEGATIVE_ONE, NEGATIVE_ONE, 1),
            (1, 16, BIG_NEGATIVE, 0, 0),
            (1, 16, 0, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, 1, 0),
            (1, 16, 1, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, BIG_POSITIVE, 0),
            (1, 16, BIG_POSITIVE, BIG_NEGATIVE, 1),
            (1, 16, BIG_NEGATIVE, BIG_NEGATIVE, 1),
            (1, 16, BIG_POSITIVE, BIG_POSITIVE, 1),
        ],
    );
}

/// `OpBehaviorIntSLessTest.testEvaluateBinaryLong`.
#[test]
fn int_sless_evaluate_binary_long() {
    // The Java class tests `OpBehavior.INT_SLESSEQUAL`, despite its name.
    check_binary(
        OpCode::IntSLessEqual,
        &[
            (1, 4, 0, 0, 1),
            (1, 4, 1, 0, 0),
            (1, 4, 0, 1, 1),
            (1, 4, 0xffff_ffff, 0, 1),
            (1, 4, 0, 0xffff_ffff, 0),
            (1, 4, 0xffff_ffff, 1, 1),
            (1, 4, 1, 0xffff_ffff, 0),
            (1, 4, 0xffff_ffff, 0xffff_ffff, 1),
            (1, 4, 0x8000_0000, 0, 1),
            (1, 4, 0, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 1, 1),
            (1, 4, 1, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0x7fff_ffff, 1),
            (1, 4, 0x7fff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0x8000_0000, 1),
            (1, 4, 0x7fff_ffff, 0x7fff_ffff, 1),
            (1, 4, 0xffff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0xffff_ffff, 1),
            (1, 8, 0, 0, 1),
            (1, 8, 1, 0, 0),
            (1, 8, 0, 1, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0, 1),
            (1, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 1, 1),
            (1, 8, 1, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 1),
            (1, 8, MIN, 0, 1),
            (1, 8, 0, MIN, 0),
            (1, 8, MIN, 1, 1),
            (1, 8, 1, MIN, 0),
            (1, 8, MIN, MAX, 1),
            (1, 8, MAX, MIN, 0),
            (1, 8, MIN, MIN, 1),
            (1, 8, MAX, MAX, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0),
            (1, 8, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1),
        ],
    );
}

/// `OpBehaviorIntSLessTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_sless_evaluate_binary_big_integer() {
    // The Java class tests `OpBehavior.INT_SLESSEQUAL`, despite its name.
    check_binary_wide(
        OpCode::IntSLessEqual,
        &[
            (1, 16, 0, 0, 1),
            (1, 16, 1, 0, 0),
            (1, 16, 0, 1, 1),
            (1, 16, NEGATIVE_ONE, 0, 1),
            (1, 16, 0, NEGATIVE_ONE, 0),
            (1, 16, NEGATIVE_ONE, 1, 1),
            (1, 16, 1, NEGATIVE_ONE, 0),
            (1, 16, NEGATIVE_ONE, NEGATIVE_ONE, 1),
            (1, 16, BIG_NEGATIVE, 0, 1),
            (1, 16, 0, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, 1, 1),
            (1, 16, 1, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, BIG_POSITIVE, 1),
            (1, 16, BIG_POSITIVE, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, BIG_NEGATIVE, 1),
            (1, 16, BIG_POSITIVE, BIG_POSITIVE, 1),
        ],
    );
}

/// `OpBehaviorIntSLessEqualTest.testEvaluateBinaryLong`.
#[test]
fn int_sless_equal_evaluate_binary_long() {
    // The Java class tests `OpBehavior.INT_SLESS`, despite its name.
    check_binary(
        OpCode::IntSLess,
        &[
            (1, 4, 0, 0, 0),
            (1, 4, 1, 0, 0),
            (1, 4, 0, 1, 1),
            (1, 4, 0xffff_ffff, 0, 1),
            (1, 4, 0, 0xffff_ffff, 0),
            (1, 4, 0xffff_ffff, 1, 1),
            (1, 4, 1, 0xffff_ffff, 0),
            (1, 4, 0xffff_ffff, 0xffff_ffff, 0),
            (1, 4, 0x8000_0000, 0, 1),
            (1, 4, 0, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 1, 1),
            (1, 4, 1, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0x7fff_ffff, 1),
            (1, 4, 0x7fff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0x8000_0000, 0),
            (1, 4, 0x7fff_ffff, 0x7fff_ffff, 0),
            (1, 4, 0xffff_ffff, 0x8000_0000, 0),
            (1, 4, 0x8000_0000, 0xffff_ffff, 1),
            (1, 8, 0, 0, 0),
            (1, 8, 1, 0, 0),
            (1, 8, 0, 1, 1),
            (1, 8, 0xffff_ffff_ffff_ffff, 0, 1),
            (1, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 1, 1),
            (1, 8, 1, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0),
            (1, 8, MIN, 0, 1),
            (1, 8, 0, MIN, 0),
            (1, 8, MIN, 1, 1),
            (1, 8, 1, MIN, 0),
            (1, 8, MIN, MAX, 1),
            (1, 8, MAX, MIN, 0),
            (1, 8, MIN, MIN, 0),
            (1, 8, MAX, MAX, 0),
            (1, 8, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0),
            (1, 8, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1),
        ],
    );
}

/// `OpBehaviorIntSLessEqualTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_sless_equal_evaluate_binary_big_integer() {
    // The Java class tests `OpBehavior.INT_SLESS`, despite its name.
    check_binary_wide(
        OpCode::IntSLess,
        &[
            (1, 16, 0, 0, 0),
            (1, 16, 1, 0, 0),
            (1, 16, 0, 1, 1),
            (1, 16, NEGATIVE_ONE, 0, 1),
            (1, 16, 0, NEGATIVE_ONE, 0),
            (1, 16, NEGATIVE_ONE, 1, 1),
            (1, 16, 1, NEGATIVE_ONE, 0),
            (1, 16, NEGATIVE_ONE, NEGATIVE_ONE, 0),
            (1, 16, BIG_NEGATIVE, 0, 1),
            (1, 16, 0, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, 1, 1),
            (1, 16, 1, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, BIG_POSITIVE, 1),
            (1, 16, BIG_POSITIVE, BIG_NEGATIVE, 0),
            (1, 16, BIG_NEGATIVE, BIG_NEGATIVE, 0),
            (1, 16, BIG_POSITIVE, BIG_POSITIVE, 0),
        ],
    );
}
