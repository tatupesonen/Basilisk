//! 128-bit unsigned integer helpers.
//!
//! Ghidra's `multiprecision.hh`/`multiprecision.cc` implement 128-bit
//! arithmetic on pairs of 64-bit words (least significant word first) for
//! the decompiler's division-optimisation rules (`ruleaction.cc`). Rust has
//! `u128`, so each helper is the native operation; they exist so the ported
//! rules can call them by Ghidra's names, and so the word-pair layout Ghidra
//! uses converts in one place ([`from_words`], [`to_words`]).

use crate::error::EvalError;

/// The 128-bit value of Ghidra's two-word array `[low, high]`.
#[inline]
pub const fn from_words(words: [u64; 2]) -> u128 {
    ((words[1] as u128) << 64) | words[0] as u128
}

/// Ghidra's two-word array `[low, high]` for a 128-bit value.
#[inline]
pub const fn to_words(value: u128) -> [u64; 2] {
    [value as u64, (value >> 64) as u64]
}

/// A 128-bit value from a 64-bit value (`set_u128`).
#[inline]
pub const fn set_u128(val: u64) -> u128 {
    val as u128
}

/// 128-bit `INT_LEFT` by a constant amount (`leftshift128`). A shift of 128
/// bits or more gives 0.
#[inline]
pub const fn leftshift128(val: u128, sa: u32) -> u128 {
    match val.checked_shl(sa) {
        Some(res) => res,
        None => 0,
    }
}

/// 128-bit `INT_LESS` (`uless128`).
#[inline]
pub const fn uless128(in1: u128, in2: u128) -> bool {
    in1 < in2
}

/// 128-bit `INT_LESSEQUAL` (`ulessequal128`).
#[inline]
pub const fn ulessequal128(in1: u128, in2: u128) -> bool {
    in1 <= in2
}

/// 128-bit `INT_ADD`, wrapping (`add128`).
#[inline]
pub const fn add128(in1: u128, in2: u128) -> u128 {
    in1.wrapping_add(in2)
}

/// 128-bit `INT_SUB`, wrapping (`subtract128`).
#[inline]
pub const fn subtract128(in1: u128, in2: u128) -> u128 {
    in1.wrapping_sub(in2)
}

/// 128-bit `INT_DIV`: the quotient and the remainder (`udiv128`).
///
/// # Errors
///
/// [`EvalError::DivideByZero`] when `denom` is zero (the C++ throws
/// `LowlevelError("divide by 0")`, or faults when both operands fit 64
/// bits).
#[inline]
pub const fn udiv128(numer: u128, denom: u128) -> Result<(u128, u128), EvalError> {
    match (numer.checked_div(denom), numer.checked_rem(denom)) {
        (Some(quotient), Some(remainder)) => Ok((quotient, remainder)),
        _ => Err(EvalError::DivideByZero),
    }
}

#[cfg(test)]
mod tests {
    //! `unittests/testmultiprec.cc`.

    use super::*;

    const NUM1: [u64; 2] = [0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff];
    const DENOM1: [u64; 2] = [1, 0];
    const NUM2: [u64; 2] = [0x89a7_32a9_fb15_7c4d, 0x4ead_a203_9e48_443e];
    const DENOM2: [u64; 2] = [0xbabf_3b71, 0];
    const NUM3: [u64; 2] = [0xf7df_0315_d584_ad8d, 0xb9d5_5c0d_1d5c_fbbd];
    const DENOM3: [u64; 2] = [0x8aa7_97db_ccee_6e96, 0x0064_6be9];
    const A: [u64; 2] = [0x1a30_9a9d_f2ce_836a, 0xd66f_2248_906d_1bdf];
    const B: [u64; 2] = [0xf6c1_9070_4eb1_763e, 0xa05c_4221_2dfb_a7c6];

    fn udiv(numer: [u64; 2], denom: [u64; 2]) -> ([u64; 2], [u64; 2]) {
        let (q, r) = udiv128(from_words(numer), from_words(denom)).unwrap();
        (to_words(q), to_words(r))
    }

    #[test]
    fn multiprec_udiv() {
        assert_eq!(
            udiv(NUM1, DENOM1),
            ([0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff], [0, 0])
        );
        assert_eq!(
            udiv(NUM2, DENOM2),
            ([0x2a21_eef2_058d_7e9a, 0x6bda_ed99], [0x928d_1c53, 0])
        );
        assert_eq!(udiv(NUM2, NUM1), ([0, 0], NUM2));
        assert_eq!(
            udiv(NUM3, DENOM3),
            ([0x01d9_bc94_9e24, 0], [0x2e78_197d_c504_8c75, 0x0024_d9cc])
        );
    }

    #[test]
    fn multiprec_add() {
        let res = to_words(add128(from_words(A), from_words(B)));
        assert_eq!(res, [0x10f2_2b0e_417f_f9a8, 0x76cb_6469_be68_c3a6]);
    }

    #[test]
    fn multiprec_sub() {
        let res = to_words(subtract128(from_words(A), from_words(B)));
        assert_eq!(res, [0x236f_0a2d_a41d_0d2c, 0x3612_e027_6271_7418]);
    }

    #[test]
    fn multiprec_left() {
        let res = to_words(leftshift128(from_words(NUM2), 51));
        assert_eq!(res, [0xe268_0000_0000_0000, 0x21f4_4d39_954f_d8ab]);
    }

    #[test]
    fn multiprec_less() {
        let (a, num2, num3) = (from_words(A), from_words(NUM2), from_words(NUM3));
        let (denom1, denom2) = (from_words(DENOM1), from_words(DENOM2));
        assert!(!uless128(a, a));
        assert!(uless128(num2, num3));
        assert!(uless128(denom1, denom2));
        assert!(ulessequal128(a, a));
        assert!(ulessequal128(num2, num3));
        assert!(ulessequal128(denom2, denom2));
    }

    #[test]
    fn beyond_the_cpp_tests() {
        assert_eq!(udiv128(5, 0), Err(EvalError::DivideByZero));
        assert_eq!(udiv128(1 << 100, 0), Err(EvalError::DivideByZero));
        assert_eq!(leftshift128(1, 127), 1 << 127);
        assert_eq!(leftshift128(u128::MAX, 128), 0);
        assert_eq!(leftshift128(u128::MAX, 0), u128::MAX);
        assert_eq!(add128(u128::MAX, 1), 0);
        assert_eq!(subtract128(0, 1), u128::MAX);
        assert_eq!(set_u128(7), 7);
        assert_eq!(to_words(set_u128(u64::MAX)), [u64::MAX, 0]);
        assert_eq!(from_words(to_words(u128::MAX - 12345)), u128::MAX - 12345);
    }
}
