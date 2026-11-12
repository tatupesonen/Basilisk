#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Ghidra's JUnit tests of the integer arithmetic and logic behaviours, ported
//! from `Ghidra/Framework/Emulation/src/test/java/ghidra/pcode/opbehavior/`:
//! `OpBehaviorInt2CompTest`, `OpBehaviorIntAddTest`, `OpBehaviorIntAndTest`,
//! `OpBehaviorIntCarryTest`, `OpBehaviorIntDivTest`, `OpBehaviorIntMultTest`,
//! `OpBehaviorIntNegateTest`, `OpBehaviorIntOrTest` and `OpBehaviorIntRemTest`.
//!
//! Each Java `@Test` method is one test here, named after the class and the
//! method, and each Java assertion is one table row
//! `(size_out, size_in, inputs.., expected)`, in the Java order.
//!
//! - The `...Long` methods call the `long` overloads; here that is the `u64`
//!   path, [`bk_pcode::behavior`]. A Java `long` is written as its 64-bit
//!   pattern. `Assert.assertEquals(long, long)` compares all 64 bits and so
//!   do these tests.
//! - The `...BigInteger` methods call the `BigInteger` overloads; here that is
//!   the wide path, [`bk_pcode::behavior::wide`], which returns the result cut
//!   to `size_out` bytes. Where Java passes a `sizeout` that has nothing to do
//!   with its 16-byte operands and then compares the low 16 bytes
//!   (`AbstractOpBehaviorTest.assertEquals(expected, result, 16)`), the row
//!   here has the compared size as both sizes; each such test says so.
//!
//! Where basilisk deliberately differs from the Java, the row asserts
//! basilisk's result and a `// Java:` comment keeps the Java expectation.

use bk_pcode::behavior::{self, wide};
use bk_pcode::{EvalError, FloatFormats, OpCode, Wide};

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
const NEGATIVE_TWO: u128 = u128::MAX - 1;
const BIG_POSITIVE: u128 = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const BIG_NEGATIVE: u128 = 0x8000_0000_0000_0000_0000_0000_0000_0000;
const NEG_ONE: u128 = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const MIN_NUM: u128 = 0x8000_0000_0000_0000_0000_0000_0000_0000;
const MAX_NUM: u128 = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;

/// A row of a unary table: `(size_out, size_in, in1, expected)`.
type Unary<T> = (u32, u32, T, T);
/// A row of a binary table: `(size_out, size_in, in1, in2, expected)`.
type Binary<T> = (u32, u32, T, T, T);
/// A row of a binary table whose evaluation may fail.
type BinaryResult<T> = (u32, u32, T, T, Result<T, EvalError>);

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
fn check_binary_results(op: OpCode, rows: &[BinaryResult<u64>]) {
    for (row, &(size_out, size_in, in1, in2, expected)) in rows.iter().enumerate() {
        assert_eq!(
            behavior::evaluate_binary(op, size_out, size_in, in1, in2, &FORMATS),
            expected,
            "{op} row {row}: ({size_out}, {size_in}, {in1:#x}, {in2:#x})"
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
fn check_binary_wide_results(op: OpCode, rows: &[BinaryResult<u128>]) {
    for (row, &(size_out, size_in, in1, in2, expected)) in rows.iter().enumerate() {
        let (wide1, wide2) = (Wide::from_u128(in1), Wide::from_u128(in2));
        assert_eq!(
            wide::evaluate_binary(op, size_out, size_in, &wide1, &wide2, &FORMATS),
            expected.map(Wide::from_u128),
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

/// `OpBehaviorInt2CompTest.testEvaluateBinaryLong`.
#[test]
fn int_2comp_evaluate_binary_long() {
    check_unary(
        OpCode::Int2Comp,
        &[
            (4, 4, 0, 0),
            (4, 4, 0xffff_ffff, 1),
            (4, 4, 1, 0xffff_ffff),
            (4, 4, 0x7fff_ffff, 0x8000_0001),
            (4, 4, 0x8000_0000, 0x8000_0000), // overflow
            (8, 8, 0, 0),
            (8, 8, long(-1), 1),
            (8, 8, 1, long(-1)),
            (8, 8, MAX, MIN + 1),
            (8, 8, MIN, MIN), // overflow
        ],
    );
}

/// `OpBehaviorInt2CompTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_2comp_evaluate_binary_big_integer() {
    // Java passes sizes (8, 8) with 16-byte operands and compares 16 bytes; both sizes are 16 here.
    check_unary_wide(
        OpCode::Int2Comp,
        &[
            (16, 16, 0, 0),
            (16, 16, NEG_ONE, 1),
            (16, 16, 1, NEG_ONE),
            (16, 16, MAX_NUM, MIN_NUM + 1),
            (16, 16, MIN_NUM, MIN_NUM), // overflow
        ],
    );
}

/// `OpBehaviorIntAddTest.testEvaluateBinaryLong`.
#[test]
fn int_add_evaluate_binary_long() {
    check_binary(
        OpCode::IntAdd,
        &[
            (4, 4, 0, 0, 0),
            (4, 4, 1, 0, 1),
            (4, 4, 0, 1, 1),
            (4, 4, 0xffff_ffff, 0, 0xffff_ffff),
            (4, 4, 0, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0xffff_ffff, 1, 0),
            (4, 4, 1, 0xffff_ffff, 0),
            (4, 4, 0xffff_ffff, 0xffff_ffff, 0xffff_fffe),
            (4, 4, 0x8000_0000, 0, 0x8000_0000),
            (4, 4, 0, 0x8000_0000, 0x8000_0000),
            (4, 4, 0x8000_0000, 1, 0x8000_0001),
            (4, 4, 1, 0x8000_0000, 0x8000_0001),
            (4, 4, 0x8000_0000, 0x7fff_ffff, 0xffff_ffff),
            (4, 4, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff),
            (4, 4, 0x8000_0000, 0x8000_0000, 0), // overflow
            (4, 4, 0x7fff_ffff, 0x7fff_ffff, 0xffff_fffe), // overflow
            (8, 8, 0, 0, 0),
            (8, 8, 1, 0, 1),
            (8, 8, 0, 1, 1),
            (8, 8, 0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_ffff_ffff),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff),
            (8, 8, 0xffff_ffff_ffff_ffff, 1, 0),
            (8, 8, 1, 0xffff_ffff_ffff_ffff, 0),
            (
                8,
                8,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_fffe,
            ),
            (8, 8, MIN, 0, MIN),
            (8, 8, 0, MIN, MIN),
            (8, 8, MIN, 1, MIN + 1),
            (8, 8, 1, MIN, MIN + 1),
            (8, 8, MIN, MAX, 0xffff_ffff_ffff_ffff),
            (8, 8, MAX, MIN, 0xffff_ffff_ffff_ffff),
            (8, 8, MIN, MIN, 0),                     // overflow
            (8, 8, MAX, MAX, 0xffff_ffff_ffff_fffe), // overflow
        ],
    );
}

/// `OpBehaviorIntAddTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_add_evaluate_binary_big_integer() {
    // Java passes sizeout 1 and compares 16 bytes; size_out is 16 here.
    check_binary_wide(
        OpCode::IntAdd,
        &[
            (16, 16, 0, 0, 0),
            (16, 16, 1, 0, 1),
            (16, 16, 0, 1, 1),
            (16, 16, NEGATIVE_ONE, 0, NEGATIVE_ONE),
            (16, 16, 0, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, NEGATIVE_ONE, 1, 0),
            (16, 16, 1, NEGATIVE_ONE, 0),
            (16, 16, NEGATIVE_ONE, NEGATIVE_ONE, NEGATIVE_TWO),
            (16, 16, BIG_NEGATIVE, 0, BIG_NEGATIVE),
            (16, 16, 0, BIG_NEGATIVE, BIG_NEGATIVE),
            (16, 16, BIG_NEGATIVE, 1, BIG_NEGATIVE + 1),
            (16, 16, 1, BIG_NEGATIVE, BIG_NEGATIVE + 1),
            (16, 16, BIG_NEGATIVE, BIG_POSITIVE, NEGATIVE_ONE),
            (16, 16, BIG_POSITIVE, BIG_NEGATIVE, NEGATIVE_ONE),
            (16, 16, BIG_NEGATIVE, BIG_NEGATIVE, 0), // overflow
            (16, 16, BIG_POSITIVE, BIG_POSITIVE, NEGATIVE_TWO), // overflow
        ],
    );
}

/// `OpBehaviorIntAndTest.testEvaluateBinaryLong`.
#[test]
fn int_and_evaluate_binary_long() {
    check_binary(
        OpCode::IntAnd,
        &[
            (4, 4, 0, 0, 0),
            (4, 4, 1, 0, 0),
            (4, 4, 0, 1, 0),
            (4, 4, 0xffff_ffff, 0, 0),
            (4, 4, 0, 0xffff_ffff, 0),
            (4, 4, 0xffff_ffff, 1, 1),
            (4, 4, 1, 0xffff_ffff, 1),
            (4, 4, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0x8000_0000, 0, 0),
            (4, 4, 0, 0x8000_0000, 0),
            (4, 4, 0x8000_0000, 1, 0),
            (4, 4, 1, 0x8000_0000, 0),
            (4, 4, 0x8000_0000, 0x7fff_ffff, 0),
            (4, 4, 0x7fff_ffff, 0x8000_0000, 0),
            (4, 4, 0x8000_0000, 0x8000_0000, 0x8000_0000), // overflow
            (4, 4, 0x7fff_ffff, 0x7fff_ffff, 0x7fff_ffff), // overflow
            (8, 8, 0, 0, 0),
            (8, 8, 1, 0, 0),
            (8, 8, 0, 1, 0),
            (8, 8, 0xffff_ffff_ffff_ffff, 0, 0),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, 0),
            (8, 8, 0xffff_ffff_ffff_ffff, 1, 1),
            (8, 8, 1, 0xffff_ffff_ffff_ffff, 1),
            (
                8,
                8,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
            ),
            (8, 8, MIN, 0, 0),
            (8, 8, 0, MIN, 0),
            (8, 8, MIN, 1, 0),
            (8, 8, 1, MIN, 0),
            (8, 8, MIN, MAX, 0),
            (8, 8, MAX, MIN, 0),
            (8, 8, MIN, MIN, MIN), // overflow
            (8, 8, MAX, MAX, MAX), // overflow
        ],
    );
}

/// `OpBehaviorIntAndTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_and_evaluate_binary_big_integer() {
    // Java passes sizeout 1 and compares 16 bytes; size_out is 16 here.
    check_binary_wide(
        OpCode::IntAnd,
        &[
            (16, 16, 0, 0, 0),
            (16, 16, 1, 0, 0),
            (16, 16, 0, 1, 0),
            (16, 16, NEGATIVE_ONE, 0, 0),
            (16, 16, 0, NEGATIVE_ONE, 0),
            (16, 16, NEGATIVE_ONE, 1, 1),
            (16, 16, 1, NEGATIVE_ONE, 1),
            (16, 16, NEGATIVE_ONE, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, BIG_NEGATIVE, 0, 0),
            (16, 16, 0, BIG_NEGATIVE, 0),
            (16, 16, BIG_NEGATIVE, 1, 0),
            (16, 16, 1, BIG_NEGATIVE, 0),
            (16, 16, BIG_NEGATIVE, BIG_POSITIVE, 0),
            (16, 16, BIG_POSITIVE, BIG_NEGATIVE, 0),
            (16, 16, BIG_NEGATIVE, BIG_NEGATIVE, BIG_NEGATIVE), // overflow
            (16, 16, BIG_POSITIVE, BIG_POSITIVE, BIG_POSITIVE), // overflow
        ],
    );
}

/// `OpBehaviorIntCarryTest.testEvaluateBinaryLong`.
#[test]
fn int_carry_evaluate_binary_long() {
    check_binary(
        OpCode::IntCarry,
        &[
            (4, 4, 0, 0, 0),
            (4, 4, 1, 0xffff_ffff, 1),
            (4, 4, 0xffff_ffff, 1, 1),
            (4, 4, 0x7fff_ffff, 0x8000_0000, 0),
            (4, 4, 0x7fff_ffff, 0x8000_0001, 1),
            (4, 4, 0x8000_0000, 0x7fff_ffff, 0),
            (4, 4, 0x8000_0001, 0x7fff_ffff, 1),
            (8, 8, 0, 0, 0),
            (8, 8, MAX, MIN, 0),
            (8, 8, MAX, MIN + 1, 1),
            (8, 8, MIN, MAX, 0),
            (8, 8, MIN + 1, MAX, 1),
            (8, 8, 0x7fff_ffff_ffff_ffff, 1, 0),
            (8, 8, 1, 0x7fff_ffff_ffff_ffff, 0),
            (8, 8, 0xffff_ffff_ffff_ffff, 1, 1),
            (8, 8, 1, 0xffff_ffff_ffff_ffff, 1),
            (8, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 1),
        ],
    );
}

/// `OpBehaviorIntCarryTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_carry_evaluate_binary_big_integer() {
    // `OpBehaviorIntCarryTest` shadows these three constants with 8-byte values.
    const NEGATIVE_ONE: u128 = 0xffff_ffff_ffff_ffff;
    const BIG_POSITIVE: u128 = 0x7fff_ffff_ffff_ffff;
    const BIG_NEGATIVE: u128 = 0x8000_0000_0000_0000;
    check_binary_wide(
        OpCode::IntCarry,
        &[
            (8, 8, 0, 0, 0),
            (8, 8, 1, NEGATIVE_ONE, 1),
            (8, 8, NEGATIVE_ONE, 1, 1),
            (8, 8, BIG_POSITIVE, BIG_NEGATIVE, 0),
            (8, 8, BIG_POSITIVE, BIG_NEGATIVE + 1, 1),
            (8, 8, BIG_NEGATIVE, BIG_POSITIVE, 0),
            (8, 8, BIG_NEGATIVE + 1, BIG_POSITIVE, 1),
        ],
    );
}

/// `OpBehaviorIntDivTest.testEvaluateBinaryLong`.
#[test]
fn int_div_evaluate_binary_long() {
    check_binary_results(
        OpCode::IntDiv,
        &[
            // Java: 0. basilisk fails as the C++ does (and as Java does for SDIV, REM, SREM).
            (4, 4, 1, 0, Err(EvalError::DivideByZero)), // divide by zero
            (4, 4, 65, 5, Ok(13)),
            (4, 4, 0, 1, Ok(0)),
            (4, 4, 0, 0xffff_ffff, Ok(0)),
            (4, 4, 0xffff_ffff, 1, Ok(0xffff_ffff)),
            (4, 4, 1, 0xffff_ffff, Ok(0)),
            (4, 4, 0xffff_ffff, 0xffff_ffff, Ok(1)),
            (4, 4, 0, 0x8000_0000, Ok(0)),
            (4, 4, 0x8000_0000, 1, Ok(0x8000_0000)),
            (4, 4, 1, 0x8000_0000, Ok(0)),
            (4, 4, 0x8000_0000, 0x7fff_ffff, Ok(1)),
            (4, 4, 0x7fff_ffff, 0x8000_0000, Ok(0)),
            (4, 4, 0x8000_0000, 0x8000_0000, Ok(1)),
            (4, 4, 0x7fff_ffff, 0x7fff_ffff, Ok(1)),
            // Java: 0. basilisk fails as the C++ does (and as Java does for SDIV, REM, SREM).
            (8, 8, 1, 0, Err(EvalError::DivideByZero)), // divide by zero
            (8, 8, 0x25_1234_5678, 0x99, Ok(0x3e07_08ee)),
            (8, 8, 0, 1, Ok(0)),
            (8, 8, 0, 0xffff_ffff_ffff_ffff, Ok(0)),
            (8, 8, 0xffff_ffff_ffff_ffff, 1, Ok(0xffff_ffff_ffff_ffff)),
            (8, 8, 1, 0xffff_ffff_ffff_ffff, Ok(0)),
            (8, 8, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, Ok(1)),
            (8, 8, 0, MIN, Ok(0)),
            (8, 8, MIN, 1, Ok(MIN)),
            (8, 8, 1, MIN, Ok(0)),
            (8, 8, MIN, MAX, Ok(1)),
            (8, 8, MAX, MIN, Ok(0)),
            (8, 8, MIN, MIN, Ok(1)),
            (8, 8, MAX, MAX, Ok(1)),
        ],
    );
}

/// `OpBehaviorIntDivTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_div_evaluate_binary_big_integer() {
    // Java passes sizeout 1 and compares 16 bytes; size_out is 16 here. The second row is as in Java.
    check_binary_wide_results(
        OpCode::IntDiv,
        &[
            // Java: 0. basilisk fails as the C++ does (and as Java does for SDIV, REM, SREM).
            (16, 16, 1, 0, Err(EvalError::DivideByZero)),
            (8, 8, 0x25_1234_5678, 0x99, Ok(0x3e07_08ee)),
            (16, 16, 0, 1, Ok(0)),
            (16, 16, 0, NEGATIVE_ONE, Ok(0)),
            (16, 16, NEGATIVE_ONE, 1, Ok(NEGATIVE_ONE)),
            (16, 16, 1, NEGATIVE_ONE, Ok(0)),
            (16, 16, NEGATIVE_ONE, NEGATIVE_ONE, Ok(1)),
            (16, 16, 0, BIG_NEGATIVE, Ok(0)),
            (16, 16, BIG_NEGATIVE, 1, Ok(BIG_NEGATIVE)),
            (16, 16, 1, BIG_NEGATIVE, Ok(0)),
            (16, 16, BIG_NEGATIVE, BIG_POSITIVE, Ok(1)),
            (16, 16, BIG_POSITIVE, BIG_NEGATIVE, Ok(0)),
            (16, 16, BIG_NEGATIVE, BIG_NEGATIVE, Ok(1)), // overflow
            (16, 16, BIG_POSITIVE, BIG_POSITIVE, Ok(1)), // overflow
        ],
    );
}

/// `OpBehaviorIntMultTest.testEvaluateBinaryLong`.
#[test]
fn int_mult_evaluate_binary_long() {
    check_binary(
        OpCode::IntMult,
        &[
            (4, 4, 0, 0, 0),
            (4, 4, 1, 0, 0),
            (4, 4, 0, 1, 0),
            (4, 4, 0xffff_ffff, 0, 0),
            (4, 4, 0, 0xffff_ffff, 0),
            (4, 4, 0xffff_ffff, 1, 0xffff_ffff),
            (4, 4, 1, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0xffff_ffff, 0xffff_ffff, 1),
            (4, 4, 0x8000_0000, 0, 0),
            (4, 4, 0, 0x8000_0000, 0),
            (4, 4, 0x8000_0000, 1, 0x8000_0000),
            (4, 4, 1, 0x8000_0000, 0x8000_0000),
            // Java: `Assert.assertEquals(0x80000000L, .., 4)`, JUnit's float comparison with a
            // delta of 4 (surely meant to be a byte size). The expected value is exact.
            (4, 4, 0x8000_0000, 0x7fff_ffff, 0x8000_0000),
            (4, 4, 0x7fff_ffff, 0x8000_0000, 0x8000_0000),
            (4, 4, 0x8000_0000, 0x8000_0000, 0),
            (4, 4, 0x7fff_ffff, 0x7fff_ffff, 1),
            (4, 4, 0x5555_5555, 0xaaaa_aaaa, 0x71c7_1c72),
            (8, 8, 0, 0, 0),
            (8, 8, 1, 0, 0),
            (8, 8, 0, 1, 0),
            (8, 8, long(-1), 0, 0),
            (8, 8, 0, long(-1), 0),
            (8, 8, long(-1), 1, long(-1)),
            (8, 8, 1, long(-1), long(-1)),
            (8, 8, long(-1), long(-1), 1),
            (8, 8, MIN, 0, 0),
            (8, 8, 0, MIN, 0),
            (8, 8, MIN, 1, MIN),
            (8, 8, 1, MIN, MIN),
            (8, 8, MIN, MAX, MIN),
            (8, 8, MAX, MIN, MIN),
            (8, 8, MIN, MIN, 0),
            (8, 8, MAX, MAX, 1),
            // Java: JUnit's float comparison again, with a delta of 8. The expected value is exact.
            (
                8,
                8,
                0x5555_5555_5555_5555,
                0xaaaa_aaaa_aaaa_aaaa,
                0x1c71_c71c_71c7_1c72,
            ),
        ],
    );
}

/// `OpBehaviorIntMultTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_mult_evaluate_binary_big_integer() {
    // Java passes sizeout 1 (and sizes (8, 8) with 16-byte operands in the last row) and compares
    // 16 bytes; both sizes are 16 here.
    check_binary_wide(
        OpCode::IntMult,
        &[
            (16, 16, 0, 0, 0),
            (16, 16, 1, 0, 0),
            (16, 16, 0, 1, 0),
            (16, 16, NEGATIVE_ONE, 0, 0),
            (16, 16, 0, NEGATIVE_ONE, 0),
            (16, 16, NEGATIVE_ONE, 1, NEGATIVE_ONE),
            (16, 16, 1, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, NEGATIVE_ONE, NEGATIVE_ONE, 1),
            (16, 16, BIG_NEGATIVE, 0, 0),
            (16, 16, 0, BIG_NEGATIVE, 0),
            (16, 16, BIG_NEGATIVE, 1, BIG_NEGATIVE),
            (16, 16, 1, BIG_NEGATIVE, BIG_NEGATIVE),
            (16, 16, BIG_NEGATIVE, BIG_POSITIVE, BIG_NEGATIVE),
            (16, 16, BIG_POSITIVE, BIG_NEGATIVE, BIG_NEGATIVE),
            (16, 16, BIG_NEGATIVE, BIG_NEGATIVE, 0),
            (16, 16, BIG_POSITIVE, BIG_POSITIVE, 1),
            (
                16,
                16,
                0x5555_5555_5555_5555_5555_5555_5555_5555,
                0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
                0x71c7_1c71_c71c_71c7_1c71_c71c_71c7_1c72,
            ),
        ],
    );
}

/// `OpBehaviorIntNegateTest.testevaluateUnaryLong`.
#[test]
fn int_negate_evaluate_unary_long() {
    check_unary(
        OpCode::IntNegate,
        &[
            (4, 4, 0, 0xffff_ffff),
            (4, 4, 0xffff_ffff, 0),
            (4, 4, 2, 0xffff_fffd),
            (4, 4, 0xffff_fffd, 2),
            (4, 4, 0x7fff_ffff, 0x8000_0000),
            (4, 4, 0x8000_0000, 0x7fff_ffff),
            (4, 4, 0xffff_fffe, 1),
            (4, 4, 1, 0xffff_fffe),
            (8, 8, long(-1), 0),
            (8, 8, 0, long(-1)),
            (8, 8, 2, long(-3)),
            (8, 8, long(-3), 2),
            (8, 8, MAX, MIN),
            (8, 8, MIN, MAX),
            (8, 8, long(-2), 1),
            (8, 8, 1, long(-2)),
        ],
    );
}

/// `OpBehaviorIntNegateTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_negate_evaluate_binary_big_integer() {
    // Java passes sizes (8, 8) with 16-byte operands and compares 16 bytes; both sizes are 16 here.
    // `getUnsignedBigInt(v, 16)` is `v` sign-extended to 16 bytes.
    check_unary_wide(
        OpCode::IntNegate,
        &[
            (16, 16, 0, NEG_ONE),
            (16, 16, NEG_ONE, 0),
            (16, 16, 2, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffd),
            (16, 16, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffd, 2),
            (16, 16, MAX_NUM, MIN_NUM),
            (16, 16, MIN_NUM, MAX_NUM),
            (16, 16, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe, 1),
            (16, 16, 1, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe),
        ],
    );
}

/// `OpBehaviorIntOrTest.testEvaluateBinaryLong`.
#[test]
fn int_or_evaluate_binary_long() {
    check_binary(
        OpCode::IntOr,
        &[
            (4, 4, 0, 0, 0),
            (4, 4, 1, 0, 1),
            (4, 4, 0, 1, 1),
            (4, 4, 0xffff_ffff, 0, 0xffff_ffff),
            (4, 4, 0, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0xffff_ffff, 1, 0xffff_ffff),
            (4, 4, 1, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff),
            (4, 4, 0x8000_0000, 0, 0x8000_0000),
            (4, 4, 0, 0x8000_0000, 0x8000_0000),
            (4, 4, 0x8000_0000, 1, 0x8000_0001),
            (4, 4, 1, 0x8000_0000, 0x8000_0001),
            (4, 4, 0x8000_0000, 0x7fff_ffff, 0xffff_ffff),
            (4, 4, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff),
            (4, 4, 0x8000_0000, 0x8000_0000, 0x8000_0000), // overflow
            (4, 4, 0x7fff_ffff, 0x7fff_ffff, 0x7fff_ffff), // overflow
            (8, 8, 0, 0, 0),
            (8, 8, 1, 0, 1),
            (8, 8, 0, 1, 1),
            (8, 8, long(-1), 0, long(-1)),
            (8, 8, 0, long(-1), long(-1)),
            (8, 8, long(-1), 1, long(-1)),
            (8, 8, 1, long(-1), long(-1)),
            (8, 8, long(-1), long(-1), long(-1)),
            (8, 8, MIN, 0, MIN),
            (8, 8, 0, MIN, MIN),
            (8, 8, MIN, 1, MIN + 1),
            (8, 8, 1, MIN, MIN + 1),
            (8, 8, MIN, MAX, long(-1)),
            (8, 8, MAX, MIN, long(-1)),
            (8, 8, MIN, MIN, MIN), // overflow
            (8, 8, MAX, MAX, MAX), // overflow
        ],
    );
}

/// `OpBehaviorIntOrTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_or_evaluate_binary_big_integer() {
    // Java passes sizeout 1 and compares 16 bytes; size_out is 16 here.
    check_binary_wide(
        OpCode::IntOr,
        &[
            (16, 16, 0, 0, 0),
            (16, 16, 1, 0, 1),
            (16, 16, 0, 1, 1),
            (16, 16, NEGATIVE_ONE, 0, NEGATIVE_ONE),
            (16, 16, 0, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, NEGATIVE_ONE, 1, NEGATIVE_ONE),
            (16, 16, 1, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, NEGATIVE_ONE, NEGATIVE_ONE, NEGATIVE_ONE),
            (16, 16, BIG_NEGATIVE, 0, BIG_NEGATIVE),
            (16, 16, 0, BIG_NEGATIVE, BIG_NEGATIVE),
            (16, 16, BIG_NEGATIVE, 1, BIG_NEGATIVE + 1),
            (16, 16, 1, BIG_NEGATIVE, BIG_NEGATIVE + 1),
            (16, 16, BIG_NEGATIVE, BIG_POSITIVE, NEGATIVE_ONE),
            (16, 16, BIG_POSITIVE, BIG_NEGATIVE, NEGATIVE_ONE),
            (16, 16, BIG_NEGATIVE, BIG_NEGATIVE, BIG_NEGATIVE), // overflow
            (16, 16, BIG_POSITIVE, BIG_POSITIVE, BIG_POSITIVE), // overflow
        ],
    );
}

/// `OpBehaviorIntRemTest.testEvaluateBinaryLong`.
#[test]
fn int_rem_evaluate_binary_long() {
    check_binary(
        OpCode::IntRem,
        &[
            (4, 4, 16, 2, 0),
            (4, 4, 17, 2, 1),
            (8, 8, 0xffff_ffff_ffff_ffff, 2, 1),
        ],
    );
}

/// `OpBehaviorIntRemTest.testDivideByZeroLong`.
#[test]
fn int_rem_divide_by_zero_long() {
    // Java: `@Test(expected = LowlevelError.class)`.
    check_binary_results(
        OpCode::IntRem,
        &[(4, 4, 1, 0, Err(EvalError::RemainderByZero))],
    );
}

/// `OpBehaviorIntRemTest.testEvaluateBinaryBigInteger`.
#[test]
fn int_rem_evaluate_binary_big_integer() {
    check_binary_wide(
        OpCode::IntRem,
        &[(16, 16, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fff2, 2 + 2, 2)],
    );
}

/// `OpBehaviorIntRemTest.testDivideByZeroBigInteger`.
#[test]
fn int_rem_divide_by_zero_big_integer() {
    // Java: `@Test(expected = LowlevelError.class)`.
    check_binary_wide_results(
        OpCode::IntRem,
        &[(16, 16, 1, 0, Err(EvalError::RemainderByZero))],
    );
}
