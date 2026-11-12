//! Size masks, sign extension and byte swapping for values of up to 8 bytes.
//!
//! Ghidra sources: the helpers in `address.hh`/`address.cc` that the op
//! behaviours use (`calc_mask`, `signbit_negative`, `uintb_negate`,
//! `sign_extend`, `zero_extend`, `byte_swap`) and their Java twins in
//! `ghidra/pcode/utils/Utils.java`.
//!
//! Sizes are byte counts. A `u64` holds at most 8 bytes, so every helper
//! treats a size above 8 as 8, as `calc_mask` does. Where the C++ shifts by an
//! amount outside `0..64` (undefined behaviour, reached only with a size of 0
//! or above 8), these helpers do what Java defines and what x86-64 and AArch64
//! compilers produce: the shift count is taken modulo 64.

/// The mask that keeps the low `size` bytes (`calc_mask`).
#[inline]
pub const fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Whether the sign bit of `val`, taken as a `size`-byte integer, is set
/// (`signbit_negative`).
#[inline]
pub const fn signbit_negative(val: u64, size: u32) -> bool {
    val & sign_bit_mask(size) != 0
}

/// The mask of the sign bit of a `size`-byte integer: `0x80 << 8 * (size - 1)`
/// with the shift count taken modulo 64.
#[inline]
pub(crate) const fn sign_bit_mask(size: u32) -> u64 {
    0x80u64.wrapping_shl(size.wrapping_sub(1).wrapping_mul(8))
}

/// The position of the sign bit of a `size`-byte integer, modulo 64
/// (`size * 8 - 1` in the C++ and Java).
#[inline]
pub(crate) const fn sign_bit_shift(size: u32) -> u32 {
    size.wrapping_mul(8).wrapping_sub(1) & 63
}

/// Inverts the low `size` bytes of `val` and clears the rest (`uintb_negate`).
#[inline]
pub const fn uintb_negate(val: u64, size: u32) -> u64 {
    !val & calc_mask(size)
}

/// Sign-extends the low `size_in` bytes of `val` to `size_out` bytes, leaving
/// more significant bytes zero (the three-argument `sign_extend`).
///
/// Sizes above 8 count as 8. When `size_in > size_out` or a size is 0, the
/// C++ shifts by a negative amount or by 64 (undefined behaviour); here, as
/// on x86-64 and AArch64, every shift count is taken modulo 64. So shrinking
/// gives the sign extension of the top `size_out` bytes of the input to 8
/// bytes, cut to `size_out` bytes, exactly as Ghidra's compiled code does.
#[inline]
pub const fn sign_extend(val: u64, size_in: u32, size_out: u32) -> u64 {
    let size_in = if size_in < 8 { size_in } else { 8 };
    let size_out = if size_out < 8 { size_out } else { 8 };
    let sval = (val as i64) << ((8 - size_in) * 8 % 64);
    let res = (sval >> (size_out.wrapping_sub(size_in).wrapping_mul(8) % 64)) as u64;
    res >> ((8 - size_out) * 8 % 64)
}

/// Sign-extends `val` above bit `bit` (0 is the least significant) to 64 bits
/// (the two-argument `sign_extend`, Java's `zzz_sign_extend`).
#[inline]
pub const fn sign_extend_bit(val: u64, bit: u32) -> i64 {
    let sa = 63u32.wrapping_sub(bit) & 63;
    ((val << sa) as i64) >> sa
}

/// Clears every bit of `val` above bit `bit` (`zero_extend`, Java's
/// `zzz_zero_extend`).
#[inline]
pub const fn zero_extend_bit(val: u64, bit: u32) -> u64 {
    let sa = 63u32.wrapping_sub(bit) & 63;
    (val << sa) >> sa
}

/// Reverses the order of the low `size` bytes of `val`; the result's other
/// bytes are zero (`byte_swap`).
#[inline]
pub const fn byte_swap(val: u64, size: u32) -> u64 {
    if size == 0 {
        0
    } else if size >= 8 {
        val.swap_bytes()
    } else {
        (val << (64 - size * 8)).swap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_mask_matches_uintbmasks() {
        let table = [
            0,
            0xff,
            0xffff,
            0xff_ffff,
            0xffff_ffff,
            0xff_ffff_ffff,
            0xffff_ffff_ffff,
            0xff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
        ];
        for (size, mask) in table.into_iter().enumerate() {
            assert_eq!(calc_mask(u32::try_from(size).unwrap()), mask);
        }
        assert_eq!(calc_mask(9), u64::MAX);
        assert_eq!(calc_mask(u32::MAX), u64::MAX);
    }

    #[test]
    fn signbit_negative_by_size() {
        assert!(signbit_negative(0x80, 1));
        assert!(!signbit_negative(0x7f, 1));
        assert!(!signbit_negative(0x80, 2));
        assert!(signbit_negative(0x8000, 2));
        assert!(signbit_negative(0x8000_0000, 4));
        assert!(signbit_negative(1 << 63, 8));
        assert!(!signbit_negative(u64::MAX >> 1, 8));
        // Out-of-contract sizes: the shift count wraps modulo 64.
        assert!(signbit_negative(1 << 63, 0));
        assert!(signbit_negative(0x80, 9));
    }

    #[test]
    fn uintb_negate_by_size() {
        assert_eq!(uintb_negate(0, 1), 0xff);
        assert_eq!(uintb_negate(0xf0, 1), 0x0f);
        assert_eq!(uintb_negate(0x1234, 2), 0xedcb);
        assert_eq!(uintb_negate(0, 8), u64::MAX);
        assert_eq!(uintb_negate(0, 0), 0);
    }

    #[test]
    fn sign_extend_between_sizes() {
        assert_eq!(sign_extend(0x80, 1, 2), 0xff80);
        assert_eq!(sign_extend(0x7f, 1, 2), 0x7f);
        assert_eq!(sign_extend(0x80, 1, 8), 0xffff_ffff_ffff_ff80);
        assert_eq!(sign_extend(0xffff_8000, 2, 4), 0xffff_8000);
        assert_eq!(sign_extend(0x1_8000, 2, 4), 0xffff_8000);
        assert_eq!(sign_extend(0x8000_0000, 4, 8), 0xffff_ffff_8000_0000);
        assert_eq!(sign_extend(0x8000_0000, 4, 4), 0x8000_0000);
        assert_eq!(sign_extend(1 << 63, 8, 16), 1 << 63);
        // Shrinking and size 0 follow the C++ with shift counts modulo 64
        // (checked against Ghidra's compiled code in tests/cpp_oracle.rs).
        assert_eq!(sign_extend(0x8000, 2, 1), 0xff);
        assert_eq!(sign_extend(0x7fff, 2, 1), 0);
        assert_eq!(sign_extend(0x1234_5678, 4, 2), 0);
        assert_eq!(sign_extend(0x8234_5678, 4, 2), 0xffff);
        assert_eq!(sign_extend(5, 0, 0), 5);
    }

    #[test]
    fn extend_above_a_bit() {
        assert_eq!(sign_extend_bit(0x80, 7), -128);
        assert_eq!(sign_extend_bit(0x7f, 7), 127);
        assert_eq!(sign_extend_bit(0x1ff, 7), -1);
        assert_eq!(sign_extend_bit(u64::MAX, 63), -1);
        assert_eq!(sign_extend_bit(5, 63), 5);
        assert_eq!(zero_extend_bit(u64::MAX, 7), 0xff);
        assert_eq!(zero_extend_bit(u64::MAX, 31), 0xffff_ffff);
        assert_eq!(zero_extend_bit(u64::MAX, 63), u64::MAX);
        // Out-of-contract bit positions wrap modulo 64 (a size of 0 gives bit -1).
        assert_eq!(sign_extend_bit(0x1234, u32::MAX), 0x1234);
        assert_eq!(zero_extend_bit(0x1234, u32::MAX), 0x1234);
        assert_eq!(sign_extend_bit(0x80, 71), -128);
    }

    #[test]
    fn byte_swap_by_size() {
        assert_eq!(byte_swap(0x1234, 2), 0x3412);
        assert_eq!(byte_swap(0x12_3456, 3), 0x56_3412);
        assert_eq!(byte_swap(0x1122_3344_5566_7788, 8), 0x8877_6655_4433_2211);
        assert_eq!(byte_swap(0xaabb_ccdd, 1), 0xdd);
        assert_eq!(byte_swap(0xaabb_ccdd, 0), 0);
    }
}
