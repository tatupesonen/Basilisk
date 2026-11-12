//! Tests of the bit helpers against transliterations of Ghidra's loops.
use super::*;
use proptest::prelude::*;

/// Literal transliterations of Ghidra's loops, as the reference the fast
/// forms above are checked against.
mod reference {
    pub(super) fn leastsigbit_set(mut val: u64) -> i32 {
        if val == 0 {
            return -1;
        }
        let mut res = 0;
        let mut sz = 32;
        let mut mask = u64::MAX;
        loop {
            mask >>= sz;
            if mask & val == 0 {
                res += sz;
                val >>= sz;
            }
            sz >>= 1;
            if sz == 0 {
                return res;
            }
        }
    }

    pub(super) fn mostsigbit_set(mut val: u64) -> i32 {
        if val == 0 {
            return -1;
        }
        let mut res = 63;
        let mut sz = 32;
        let mut mask = u64::MAX;
        loop {
            mask <<= sz;
            if mask & val == 0 {
                res -= sz;
                val <<= sz;
            }
            sz >>= 1;
            if sz == 0 {
                return res;
            }
        }
    }

    pub(super) fn popcount(mut val: u64) -> i32 {
        val = (val & 0x5555_5555_5555_5555) + ((val >> 1) & 0x5555_5555_5555_5555);
        val = (val & 0x3333_3333_3333_3333) + ((val >> 2) & 0x3333_3333_3333_3333);
        val = (val & 0x0f0f_0f0f_0f0f_0f0f) + ((val >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
        val = (val & 0x00ff_00ff_00ff_00ff) + ((val >> 8) & 0x00ff_00ff_00ff_00ff);
        val = (val & 0x0000_ffff_0000_ffff) + ((val >> 16) & 0x0000_ffff_0000_ffff);
        (val & 0xff) as i32 + ((val >> 32) & 0xff) as i32
    }

    pub(super) fn count_leading_zeros(val: u64) -> i32 {
        if val == 0 {
            return 64;
        }
        let mut mask = u64::MAX;
        let mut mask_size = 32;
        mask &= mask << mask_size;
        let mut bit = 0;
        loop {
            if mask & val == 0 {
                bit += mask_size;
                mask_size >>= 1;
                mask |= mask >> mask_size;
            } else {
                mask_size >>= 1;
                mask &= mask << mask_size;
            }
            if mask_size == 0 {
                return bit;
            }
        }
    }

    pub(super) fn coveringmask(val: u64) -> u64 {
        let mut res = val;
        let mut sz = 1;
        while sz < 64 {
            res |= res >> sz;
            sz <<= 1;
        }
        res
    }

    pub(super) fn bit_transitions(mut val: u64, sz: u32) -> i32 {
        let mut res = 0;
        let mut last = val & 1;
        for _ in 1..8 * u64::from(sz) {
            val >>= 1;
            let cur = val & 1;
            if cur != last {
                res += 1;
                last = cur;
            }
            if val == 0 {
                break;
            }
        }
        res
    }

    pub(super) fn byte_swap(mut val: u64, size: u32) -> u64 {
        let mut res = 0u64;
        for _ in 0..size {
            res <<= 8;
            res |= val & 0xff;
            val >>= 8;
        }
        res
    }
}

#[test]
fn masks_and_limits() {
    let masks = [
        0,
        0xff,
        0xffff,
        0x00ff_ffff,
        0xffff_ffff,
        0x00ff_ffff_ffff,
        0xffff_ffff_ffff,
        0x00ff_ffff_ffff_ffff,
        u64::MAX,
    ];
    for (size, mask) in masks.into_iter().enumerate() {
        let size = size as u32;
        assert_eq!(calc_mask(size), mask);
        assert_eq!(calc_uint_max(size), mask);
        assert_eq!(calc_int_max(size), mask >> 1);
    }
    for size in [9, 16, 1000, u32::MAX] {
        assert_eq!(calc_mask(size), u64::MAX);
    }
    assert_eq!(calc_int_min(0), 0);
    assert_eq!(calc_int_min(1), 0x80);
    assert_eq!(calc_int_min(2), 0x8000);
    assert_eq!(calc_int_min(4), 0x8000_0000);
    assert_eq!(calc_int_min(8), 0x8000_0000_0000_0000);
    assert_eq!(calc_int_min(9), 0);
    assert_eq!(calc_int_max(1), 0x7f);
    assert_eq!(calc_int_max(8), 0x7fff_ffff_ffff_ffff);
}

#[test]
fn shifts() {
    assert_eq!(pcode_right(0x80, 4), 8);
    assert_eq!(pcode_right(u64::MAX, 63), 1);
    assert_eq!(pcode_right(u64::MAX, 64), 0);
    assert_eq!(pcode_right(u64::MAX, 1000), 0);
    assert_eq!(pcode_right(5, 0), 5);
    assert_eq!(pcode_left(1, 63), 0x8000_0000_0000_0000);
    assert_eq!(pcode_left(1, 64), 0);
    assert_eq!(pcode_left(u64::MAX, u32::MAX), 0);
    assert_eq!(pcode_left(5, 0), 5);
}

#[test]
fn minimal_masks() {
    let cases = [
        (0, 0xff),
        (0xff, 0xff),
        (0x100, 0xffff),
        (0xffff, 0xffff),
        (0x1_0000, 0xffff_ffff),
        (0xffff_ffff, 0xffff_ffff),
        (0x1_0000_0000, u64::MAX),
        (u64::MAX, u64::MAX),
    ];
    for (val, mask) in cases {
        assert_eq!(minimalmask(val), mask, "{val:#x}");
    }
}

#[test]
fn bit_extension() {
    assert_eq!(sign_extend_bit(0x80, 7), -128);
    assert_eq!(sign_extend_bit(0x7f, 7), 127);
    assert_eq!(sign_extend_bit(0x1ff, 7), -1);
    assert_eq!(sign_extend_bit(1, 0), -1);
    assert_eq!(sign_extend_bit(0, 0), 0);
    assert_eq!(sign_extend_bit(0x4000_0000_0000_0000, 62), i64::MIN >> 1);
    assert_eq!(sign_extend_bit(i64::MIN, 63), i64::MIN);
    assert_eq!(sign_extend_bit(5, 200), 5);
    assert_eq!(zero_extend_bit(-1, 7), 0xff);
    assert_eq!(zero_extend_bit(-1, 0), 1);
    assert_eq!(zero_extend_bit(0x1234, 7), 0x34);
    assert_eq!(zero_extend_bit(-1, 62), i64::MAX);
    assert_eq!(zero_extend_bit(-1, 63), -1);
    assert_eq!(zero_extend_bit(-1, 64), -1);
}

#[test]
fn sign_bits() {
    assert!(signbit_negative(0x80, 1));
    assert!(!signbit_negative(0x7f, 1));
    assert!(!signbit_negative(0x80, 2));
    assert!(signbit_negative(0x8000, 2));
    assert!(signbit_negative(0xff80_0000, 3));
    assert!(signbit_negative(u64::MAX, 8));
    assert!(!signbit_negative(i64::MAX as u64, 8));
    assert!(!signbit_negative(u64::MAX, 0));
    assert!(!signbit_negative(u64::MAX, 9));
    assert_eq!(uintb_negate(0, 1), 0xff);
    assert_eq!(uintb_negate(0x0f, 1), 0xf0);
    assert_eq!(uintb_negate(0x1234, 2), 0xedcb);
    assert_eq!(uintb_negate(0, 8), u64::MAX);
    assert_eq!(uintb_negate(0, 12), u64::MAX);
    assert_eq!(uintb_negate(0, 0), 0);
}

#[test]
fn size_extension() {
    let cases = [
        (0x80, 1, 2, 0xff80),
        (0x7f, 1, 2, 0x7f),
        (0x80, 1, 4, 0xffff_ff80),
        (0x80, 1, 8, 0xffff_ffff_ffff_ff80),
        (0x1280, 1, 2, 0xff80), // bytes above size_in are ignored
        (0x8000, 2, 4, 0xffff_8000),
        (0x8000_0000, 4, 8, 0xffff_ffff_8000_0000),
        (0x1234, 2, 2, 0x1234),
        (0xff_1234, 2, 2, 0x1234),
        (0x8000_0000_0000_0000, 8, 8, 0x8000_0000_0000_0000),
        (0x80, 1, 100, 0xffff_ffff_ffff_ff80), // sizes are capped at 8
        (0x8000_0000_0000_0000, 100, 100, 0x8000_0000_0000_0000),
        (0x1234, 2, 1, 0x34), // defined here; undefined in C++
        (0x1234, 0, 4, 0),
        (0x1234, 4, 0, 0),
        (0x80_0000, 3, 5, 0xff_ff80_0000),
    ];
    for (val, size_in, size_out, expected) in cases {
        assert_eq!(
            sign_extend(val, size_in, size_out),
            expected,
            "{val:#x} {size_in}->{size_out}"
        );
    }
    let cases = [
        (0x7, 3, 1, 0xff),
        (0x3, 3, 1, 0x3),
        (0x7, 3, 2, 0xffff),
        (0x80, 8, 1, 0x80),
        (0x80, 8, 2, 0xff80),
        (0x1, 1, 8, u64::MAX),
        (0xff, 16, 1, 0xff), // already fills the integer
        (0x1234, 64, 8, 0x1234),
        (0x8000_0000_0000_0000, 64, 9, 0x8000_0000_0000_0000),
        (0x5, 0, 4, 0),
        (0x5, 70, 16, 0x5),
    ];
    for (val, numbits, size, expected) in cases {
        assert_eq!(
            extend_signbit(val, numbits, size),
            expected,
            "{val:#x} {numbits} bits, {size} bytes"
        );
    }
}

#[test]
fn byte_swaps() {
    let cases = [
        (0x1234_5678, 4, 0x7856_3412),
        (0x1234_5678, 2, 0x7856),
        (0x1234_5678, 1, 0x78),
        (0x1234_5678, 0, 0),
        (0x0102_0304_0506_0708, 8, 0x0807_0605_0403_0201),
        (0x0102_0304_0506_0708, 3, 0x08_0706),
        (0x0102_0304_0506_0708, 9, 0x0706_0504_0302_0100),
        (0x0102_0304_0506_0708, 16, 0),
        (0x0102_0304_0506_0708, 1000, 0),
    ];
    for (val, size, expected) in cases {
        assert_eq!(byte_swap(val, size), expected, "{val:#x} size {size}");
        assert_eq!(
            byte_swap(val, size),
            reference::byte_swap(val, size.min(16))
        );
    }
    assert_eq!(byte_swap_signed(0x1234_5678, 4), 0x7856_3412);
    assert_eq!(byte_swap_signed(-2, 2), 0xfeff);
    assert_eq!(byte_swap_signed(-2, 8), 0xfeff_ffff_ffff_ffffu64 as i64);
    // Above 8 bytes the sign is shifted in.
    assert_eq!(byte_swap_signed(-2, 9), 0xffff_ffff_ffff_ffffu64 as i64);
    assert_eq!(
        byte_swap_signed(0x0102_0304_0506_0708, 9),
        0x0706_0504_0302_0100
    );
}

#[test]
fn bit_searches() {
    let cases: [(u64, i32, i32, i32, i32); 9] = [
        // value, least, most, popcount, leading zeros
        (0, -1, -1, 0, 64),
        (1, 0, 0, 1, 63),
        (2, 1, 1, 1, 62),
        (0x80, 7, 7, 1, 56),
        (0xf0, 4, 7, 4, 56),
        (0x8000_0000, 31, 31, 1, 32),
        (0x1_0000_0000, 32, 32, 1, 31),
        (0x8000_0000_0000_0001, 0, 63, 2, 0),
        (u64::MAX, 0, 63, 64, 0),
    ];
    for (val, least, most, count, zeros) in cases {
        assert_eq!(leastsigbit_set(val), least, "{val:#x}");
        assert_eq!(mostsigbit_set(val), most, "{val:#x}");
        assert_eq!(popcount(val), count, "{val:#x}");
        assert_eq!(count_leading_zeros(val), zeros, "{val:#x}");
    }
    let cases = [
        (0, 0),
        (1, 1),
        (2, 3),
        (4, 7),
        (5, 7),
        (0x100, 0x1ff),
        (0x8000_0000_0000_0000, u64::MAX),
        (u64::MAX, u64::MAX),
    ];
    for (val, mask) in cases {
        assert_eq!(coveringmask(val), mask, "{val:#x}");
    }
}

#[test]
fn transitions() {
    let cases = [
        (0, 4, 0),
        (1, 4, 1),
        (0xff, 1, 0),
        (0xff, 2, 1),
        (0x0f, 1, 1),
        (0xf0, 1, 1),
        (0x3c, 1, 2),
        (0x55, 1, 7),
        (0xaa, 1, 7),
        (0xaa, 2, 8),
        (u64::MAX, 8, 0),
        (0x8000_0000_0000_0000, 8, 1),
        (0x7fff_ffff_ffff_ffff, 8, 1),
        (0x1234, 0, 0),
        (0xff00, 1, 0),                // only the low byte is scanned
        (0x1ff, 1, 0),                 // the transition above bit 7 is outside the size
        (0x8000_0000_0000_0000, 9, 2), // past 8 bytes the top bit falls to zero
        (0x5, 100, 3),
    ];
    for (val, size, expected) in cases {
        assert_eq!(bit_transitions(val, size), expected, "{val:#x} size {size}");
        assert_eq!(
            reference::bit_transitions(val, size),
            expected,
            "reference {val:#x} size {size}"
        );
    }
}

proptest! {
    #[test]
    fn fast_forms_match_ghidras_loops(val in any::<u64>(), size in 0u32..12) {
        prop_assert_eq!(leastsigbit_set(val), reference::leastsigbit_set(val));
        prop_assert_eq!(mostsigbit_set(val), reference::mostsigbit_set(val));
        prop_assert_eq!(popcount(val), reference::popcount(val));
        prop_assert_eq!(count_leading_zeros(val), reference::count_leading_zeros(val));
        prop_assert_eq!(coveringmask(val), reference::coveringmask(val));
        prop_assert_eq!(bit_transitions(val, size), reference::bit_transitions(val, size));
        prop_assert_eq!(byte_swap(val, size), reference::byte_swap(val, size));
    }

    #[test]
    fn sparse_values_match_too(bit_a in 0u32..64, bit_b in 0u32..64, size in 0u32..12) {
        for val in [1u64 << bit_a, (1u64 << bit_a) | (1u64 << bit_b), !(1u64 << bit_a), (1u64 << bit_a).wrapping_sub(1)] {
            prop_assert_eq!(leastsigbit_set(val), reference::leastsigbit_set(val));
            prop_assert_eq!(mostsigbit_set(val), reference::mostsigbit_set(val));
            prop_assert_eq!(count_leading_zeros(val), reference::count_leading_zeros(val));
            prop_assert_eq!(coveringmask(val), reference::coveringmask(val));
            prop_assert_eq!(bit_transitions(val, size), reference::bit_transitions(val, size));
        }
    }

    #[test]
    fn extension_properties(val in any::<u64>(), size_in in 1u32..=8, extra in 0u32..=8) {
        let size_out = (size_in + extra).min(8);
        let extended = sign_extend(val, size_in, size_out);
        // The low bytes are kept, and the result fits the output size.
        prop_assert_eq!(extended & calc_mask(size_in), val & calc_mask(size_in));
        prop_assert_eq!(extended & !calc_mask(size_out), 0);
        // The bytes added are all sign.
        let negative = signbit_negative(val, size_in);
        prop_assert_eq!(signbit_negative(extended, size_out), negative);
        prop_assert_eq!(extended, extend_signbit(val & calc_mask(size_in), size_in * 8, size_out));
        // Swapping twice restores the low bytes.
        prop_assert_eq!(byte_swap(byte_swap(val, size_in), size_in), val & calc_mask(size_in));
        prop_assert_eq!(uintb_negate(uintb_negate(val, size_in), size_in), val & calc_mask(size_in));
        let bit = size_in * 8 - 1;
        prop_assert_eq!(sign_extend_bit(val.cast_signed(), bit).cast_unsigned(), sign_extend(val, size_in, 8));
        prop_assert_eq!(zero_extend_bit(val.cast_signed(), bit).cast_unsigned(), val & calc_mask(size_in));
    }
}
