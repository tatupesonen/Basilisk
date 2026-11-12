//! Property tests of the integer operations: the `u64` path against Rust's
//! native wrapping arithmetic at sizes 1, 2, 4 and 8; the wide path against
//! the `u64` path at sizes 1 to 8 and against `num-bigint` at 9 to 64 bytes;
//! `recover_input_*` inverting `evaluate_*`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

use bk_pcode::behavior::{
    evaluate_binary, evaluate_unary, recover_input_binary, recover_input_unary, wide,
};
use bk_pcode::num_bigint::BigUint;
use bk_pcode::{EvalError, FloatFormats, OpCode, Wide};
use proptest::prelude::*;

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn bin(op: OpCode, out: u32, size: u32, a: u64, b: u64) -> Result<u64, EvalError> {
    evaluate_binary(op, out, size, a, b, &FORMATS)
}

fn un(op: OpCode, out: u32, size: u32, a: u64) -> Result<u64, EvalError> {
    evaluate_unary(op, out, size, a, &FORMATS)
}

/// The `u64` path against native arithmetic on `$u` (unsigned) and `$i`
/// (signed) of `$size` bytes.
macro_rules! native_tests {
    ($name:ident, $u:ty, $i:ty, $size:expr) => {
        mod $name {
            use super::*;
            const S: u32 = $size;
            const BITS: u64 = S as u64 * 8;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(4096))]

                #[test]
                fn arithmetic_and_logic(a: $u, b: $u) {
                    let (x, y) = (u64::from(a), u64::from(b));
                    let v = |r: $u| Ok(u64::from(r));
                    prop_assert_eq!(bin(OpCode::IntAdd, S, S, x, y), v(a.wrapping_add(b)));
                    prop_assert_eq!(bin(OpCode::IntSub, S, S, x, y), v(a.wrapping_sub(b)));
                    prop_assert_eq!(bin(OpCode::IntMult, S, S, x, y), v(a.wrapping_mul(b)));
                    prop_assert_eq!(bin(OpCode::IntAnd, S, S, x, y), v(a & b));
                    prop_assert_eq!(bin(OpCode::IntOr, S, S, x, y), v(a | b));
                    prop_assert_eq!(bin(OpCode::IntXor, S, S, x, y), v(a ^ b));
                    prop_assert_eq!(bin(OpCode::PtrSub, S, S, x, y), v(a.wrapping_add(b)));
                    if b == 0 {
                        prop_assert_eq!(bin(OpCode::IntDiv, S, S, x, y), Err(EvalError::DivideByZero));
                        prop_assert_eq!(bin(OpCode::IntSDiv, S, S, x, y), Err(EvalError::DivideByZero));
                        prop_assert_eq!(bin(OpCode::IntRem, S, S, x, y), Err(EvalError::RemainderByZero));
                        prop_assert_eq!(bin(OpCode::IntSRem, S, S, x, y), Err(EvalError::RemainderByZero));
                    } else {
                        let (sa, sb) = (a as $i, b as $i);
                        prop_assert_eq!(bin(OpCode::IntDiv, S, S, x, y), v(a / b));
                        prop_assert_eq!(bin(OpCode::IntRem, S, S, x, y), v(a % b));
                        // MIN / -1 wraps to MIN and MIN % -1 is 0, as the C++
                        // sets explicitly.
                        prop_assert_eq!(bin(OpCode::IntSDiv, S, S, x, y), v(sa.wrapping_div(sb) as $u));
                        prop_assert_eq!(bin(OpCode::IntSRem, S, S, x, y), v(sa.wrapping_rem(sb) as $u));
                    }
                }

                #[test]
                fn comparisons_and_flags(a: $u, b: $u) {
                    let (x, y) = (u64::from(a), u64::from(b));
                    let (sa, sb) = (a as $i, b as $i);
                    let f = |c: bool| Ok(u64::from(c));
                    prop_assert_eq!(bin(OpCode::IntEqual, 1, S, x, y), f(a == b));
                    prop_assert_eq!(bin(OpCode::IntNotEqual, 1, S, x, y), f(a != b));
                    prop_assert_eq!(bin(OpCode::IntLess, 1, S, x, y), f(a < b));
                    prop_assert_eq!(bin(OpCode::IntLessEqual, 1, S, x, y), f(a <= b));
                    prop_assert_eq!(bin(OpCode::IntSLess, 1, S, x, y), f(sa < sb));
                    prop_assert_eq!(bin(OpCode::IntSLessEqual, 1, S, x, y), f(sa <= sb));
                    prop_assert_eq!(bin(OpCode::IntCarry, 1, S, x, y), f(a.overflowing_add(b).1));
                    prop_assert_eq!(bin(OpCode::IntSCarry, 1, S, x, y), f(sa.overflowing_add(sb).1));
                    prop_assert_eq!(bin(OpCode::IntSBorrow, 1, S, x, y), f(sa.overflowing_sub(sb).1));
                }

                #[test]
                fn shifts(a: $u, amount in 0u64..(2 * BITS + 2)) {
                    let x = u64::from(a);
                    let left = if amount < BITS { a << amount } else { 0 };
                    let right = if amount < BITS { a >> amount } else { 0 };
                    let sright = ((a as $i) >> amount.min(BITS - 1)) as $u;
                    prop_assert_eq!(bin(OpCode::IntLeft, S, S, x, amount), Ok(u64::from(left)));
                    prop_assert_eq!(bin(OpCode::IntRight, S, S, x, amount), Ok(u64::from(right)));
                    prop_assert_eq!(bin(OpCode::IntSRight, S, S, x, amount), Ok(u64::from(sright)));
                }

                #[test]
                fn unary_operations(a: $u) {
                    let x = u64::from(a);
                    prop_assert_eq!(un(OpCode::Int2Comp, S, S, x), Ok(u64::from(a.wrapping_neg())));
                    prop_assert_eq!(un(OpCode::IntNegate, S, S, x), Ok(u64::from(!a)));
                    prop_assert_eq!(un(OpCode::Copy, S, S, x), Ok(x));
                    prop_assert_eq!(un(OpCode::IntZExt, 8, S, x), Ok(x));
                    prop_assert_eq!(un(OpCode::IntSExt, 8, S, x), Ok(i64::from(a as $i) as u64));
                    prop_assert_eq!(un(OpCode::PopCount, 1, S, x), Ok(u64::from(a.count_ones())));
                    prop_assert_eq!(un(OpCode::LzCount, 1, S, x), Ok(u64::from(a.leading_zeros())));
                }

                #[test]
                fn pieces(a: u64, b: $u, offset in 0u64..8) {
                    // The high piece has 8 - S bytes, the low piece S.
                    let high = if S == 8 { 0 } else { a >> (8 * S) };
                    let piece = bin(OpCode::Piece, 8, 8 - S, high, u64::from(b));
                    let want = if S == 8 { u64::from(b) } else { (high << (8 * S)) | u64::from(b) };
                    prop_assert_eq!(piece, Ok(want));
                    let sub = bin(OpCode::SubPiece, S, 8, a, offset);
                    prop_assert_eq!(sub, Ok(clean(a >> (8 * offset), S)));
                }
            }

            #[test]
            fn booleans() {
                for a in 0..2u64 {
                    prop_assert_eq_bool(un(OpCode::BoolNegate, 1, 1, a), u64::from(a == 0));
                    for b in 0..2u64 {
                        prop_assert_eq_bool(bin(OpCode::BoolAnd, 1, 1, a, b), a & b);
                        prop_assert_eq_bool(bin(OpCode::BoolOr, 1, 1, a, b), a | b);
                        prop_assert_eq_bool(bin(OpCode::BoolXor, 1, 1, a, b), a ^ b);
                    }
                }
            }
        }
    };
}

fn prop_assert_eq_bool(got: Result<u64, EvalError>, want: u64) {
    assert_eq!(got, Ok(want));
}

native_tests!(size1, u8, i8, 1);
native_tests!(size2, u16, i16, 2);
native_tests!(size4, u32, i32, 4);
native_tests!(size8, u64, i64, 8);

/// Integer operations whose wide (Java `BigInteger`) and `u64` (C++) forms
/// must agree on clean operands of equal size.
const WIDE_BINARY: [(OpCode, bool); 25] = [
    (OpCode::IntEqual, true),
    (OpCode::IntNotEqual, true),
    (OpCode::IntLess, true),
    (OpCode::IntLessEqual, true),
    (OpCode::IntSLess, true),
    (OpCode::IntSLessEqual, true),
    (OpCode::IntCarry, true),
    (OpCode::IntSCarry, true),
    (OpCode::IntSBorrow, true),
    (OpCode::IntAdd, false),
    (OpCode::IntSub, false),
    (OpCode::IntXor, false),
    (OpCode::IntAnd, false),
    (OpCode::IntOr, false),
    (OpCode::IntLeft, false),
    (OpCode::IntRight, false),
    (OpCode::IntSRight, false),
    (OpCode::IntMult, false),
    (OpCode::IntDiv, false),
    (OpCode::IntSDiv, false),
    (OpCode::IntRem, false),
    (OpCode::IntSRem, false),
    (OpCode::BoolXor, true),
    (OpCode::BoolAnd, true),
    (OpCode::BoolOr, true),
];

const WIDE_UNARY: [OpCode; 6] = [
    OpCode::Copy,
    OpCode::Int2Comp,
    OpCode::IntNegate,
    OpCode::BoolNegate,
    OpCode::PopCount,
    OpCode::LzCount,
];

fn clean(value: u64, size: u32) -> u64 {
    value & (u64::MAX >> (64 - 8 * size))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn wide_path_equals_u64_path(size in 1u32..=8, a: u64, b: u64, small in 0u64..70, which: bool) {
        let a = clean(a, size);
        // Shift amounts and booleans need small second operands half the time.
        let b = if which { clean(b, size) } else { small.min(clean(u64::MAX, size)) };
        let ieee = FloatFormats::IEEE;
        for (op, boolean_out) in WIDE_BINARY {
            let (a, b) = if matches!(op, OpCode::BoolXor | OpCode::BoolAnd | OpCode::BoolOr) {
                (a & 1, b & 1)
            } else {
                (a, b)
            };
            let out = if boolean_out { 1 } else { size };
            let narrow = bin(op, out, size, a, b);
            let wide = wide::evaluate_binary(op, out, size, &Wide::from_u64(a), &Wide::from_u64(b), &ieee);
            match narrow {
                Ok(r) => prop_assert_eq!(wide, Ok(Wide::from_u64(r)), "{:?} {} {:#x} {:#x}", op, size, a, b),
                Err(_) => prop_assert!(wide.is_err(), "{:?} {} {:#x} {:#x}", op, size, a, b),
            }
        }
        for op in WIDE_UNARY {
            let a = if op == OpCode::BoolNegate { a & 1 } else { a };
            let out = if matches!(op, OpCode::PopCount | OpCode::LzCount) { 1 } else { size };
            let narrow = un(op, out, size, a).unwrap();
            let wide = wide::evaluate_unary(op, out, size, &Wide::from_u64(a), &ieee);
            prop_assert_eq!(wide, Ok(Wide::from_u64(narrow)), "{:?} {} {:#x}", op, size, a);
        }
        for out in size..=8 {
            for op in [OpCode::IntZExt, OpCode::IntSExt] {
                let narrow = un(op, out, size, a).unwrap();
                let wide = wide::evaluate_unary(op, out, size, &Wide::from_u64(a), &ieee);
                prop_assert_eq!(wide, Ok(Wide::from_u64(narrow)), "{:?} {} {} {:#x}", op, out, size, a);
            }
        }
    }

    #[test]
    fn wide_path_equals_big_integers(
        size in 9u32..=64,
        a in proptest::collection::vec(any::<u8>(), 64),
        b in proptest::collection::vec(any::<u8>(), 64),
        amount in 0u32..520,
    ) {
        let modulus = BigUint::from(1u8) << (8 * size);
        let big = |bytes: &[u8]| BigUint::from_bytes_le(&bytes[..size as usize]);
        let (ba, bb) = (big(&a), big(&b));
        let w = |v: &BigUint| Wide::from_biguint(v);
        let (wa, wb) = (w(&ba), w(&bb));
        let ieee = FloatFormats::IEEE;
        let eval = |op, x: &Wide, y: &Wide| wide::evaluate_binary(op, size, size, x, y, &ieee);
        prop_assert_eq!(eval(OpCode::IntAdd, &wa, &wb), Ok(w(&((&ba + &bb) % &modulus))));
        prop_assert_eq!(eval(OpCode::IntSub, &wa, &wb), Ok(w(&((&ba + &modulus - &bb) % &modulus))));
        prop_assert_eq!(eval(OpCode::IntMult, &wa, &wb), Ok(w(&((&ba * &bb) % &modulus))));
        prop_assert_eq!(eval(OpCode::IntAnd, &wa, &wb), Ok(w(&(&ba & &bb))));
        prop_assert_eq!(eval(OpCode::IntOr, &wa, &wb), Ok(w(&(&ba | &bb))));
        prop_assert_eq!(eval(OpCode::IntXor, &wa, &wb), Ok(w(&(&ba ^ &bb))));
        if bb != BigUint::ZERO {
            prop_assert_eq!(eval(OpCode::IntDiv, &wa, &wb), Ok(w(&(&ba / &bb))));
            prop_assert_eq!(eval(OpCode::IntRem, &wa, &wb), Ok(w(&(&ba % &bb))));
        }
        let sa = Wide::from_u64(u64::from(amount));
        let left = if amount < 8 * size { (&ba << amount) % &modulus } else { BigUint::ZERO };
        let right = if amount < 8 * size { &ba >> amount } else { BigUint::ZERO };
        prop_assert_eq!(eval(OpCode::IntLeft, &wa, &sa), Ok(w(&left)));
        prop_assert_eq!(eval(OpCode::IntRight, &wa, &sa), Ok(w(&right)));
        prop_assert_eq!(eval(OpCode::IntLess, &wa, &wb).map(Wide::low_u64), Ok(u64::from(ba < bb)));
    }

    #[test]
    fn recover_inverts_evaluate(size in 1u32..=8, x: u64, other: u64, sa in 0u64..64) {
        let x = clean(x, size);
        let other = clean(other, size);
        let bits = 8 * u64::from(size);
        for op in [OpCode::Copy, OpCode::Int2Comp, OpCode::IntNegate, OpCode::IntZExt] {
            let out = un(op, size, size, x).unwrap();
            prop_assert_eq!(recover_input_unary(op, size, out, size), Ok(x), "{:?}", op);
        }
        let sext = un(OpCode::IntSExt, 8, size, x).unwrap();
        prop_assert_eq!(recover_input_unary(OpCode::IntSExt, 8, sext, size), Ok(x));
        // INT_ADD and INT_SUB: either input from the output and the other.
        let sum = bin(OpCode::IntAdd, size, size, x, other).unwrap();
        prop_assert_eq!(recover_input_binary(OpCode::IntAdd, 0, size, sum, size, other), Ok(x));
        prop_assert_eq!(recover_input_binary(OpCode::IntAdd, 1, size, sum, size, other), Ok(x));
        let diff = bin(OpCode::IntSub, size, size, x, other).unwrap();
        prop_assert_eq!(recover_input_binary(OpCode::IntSub, 0, size, diff, size, other), Ok(x));
        let diff = bin(OpCode::IntSub, size, size, other, x).unwrap();
        prop_assert_eq!(recover_input_binary(OpCode::IntSub, 1, size, diff, size, other), Ok(x));
        // Shifts lose no bits when the shifted-out part is zero.
        let sa = sa % bits;
        let fits_left = clean(x >> sa, size);
        let out = bin(OpCode::IntLeft, size, size, fits_left, sa).unwrap();
        prop_assert_eq!(recover_input_binary(OpCode::IntLeft, 0, size, out, size, sa), Ok(fits_left));
        let fits_right = clean(x << sa, size);
        let out = bin(OpCode::IntRight, size, size, fits_right, sa).unwrap();
        prop_assert_eq!(recover_input_binary(OpCode::IntRight, 0, size, out, size, sa), Ok(fits_right));
        // INT_SRIGHT: Ghidra recovers only a shifted negative value.
        let negative = fits_right | (1 << (bits - 1));
        let out = bin(OpCode::IntSRight, size, size, negative, sa).unwrap();
        // The C++ returns `out << sa` without masking it to the size.
        prop_assert_eq!(recover_input_binary(OpCode::IntSRight, 0, size, out, size, sa), Ok(out << sa));
        prop_assert_eq!(clean(out << sa, size), negative);
    }
}
