//! Bit arithmetic helpers on 64-bit values of a given byte size.
//!
//! Ghidra: the free functions at the end of `address.hh` and `address.cc`.
//! They keep Ghidra's names, and its conventions of returning -1 from the bit
//! searches when no bit is set, because the p-code and decompiler code ported
//! later does arithmetic on those results. Sizes are in bytes. Where the C++
//! is undefined (a shift by the full width or more, a size of 0 where a sign
//! bit is asked for), the result here is defined and documented per function.

/// A mask covering the low `size` bytes; all ones for 8 bytes and more, 0 for
/// 0 bytes (Ghidra `calc_mask` and its table `uintbmasks`).
pub const fn calc_mask(size: u32) -> u64 {
    if size < 8 {
        (1 << (size * 8)) - 1
    } else {
        u64::MAX
    }
}

/// The largest unsigned value of `size` bytes.
pub const fn calc_uint_max(size: u32) -> u64 {
    calc_mask(size)
}

/// The largest signed value of `size` bytes.
pub const fn calc_int_max(size: u32) -> u64 {
    calc_mask(size) >> 1
}

/// The smallest signed value of `size` bytes, as a bit pattern: only the sign
/// bit set. Undefined in C++ for 0 bytes and for more than 8; 0 here.
pub const fn calc_int_min(size: u32) -> u64 {
    if size == 0 || size > 8 {
        0
    } else {
        1 << (size * 8 - 1)
    }
}

/// A logical right shift as p-code's `INT_RIGHT` defines it: a shift by 64
/// bits or more gives 0.
pub const fn pcode_right(val: u64, sa: u32) -> u64 {
    if sa >= u64::BITS { 0 } else { val >> sa }
}

/// A left shift as p-code's `INT_LEFT` defines it: a shift by 64 bits or more
/// gives 0.
pub const fn pcode_left(val: u64, sa: u32) -> u64 {
    if sa >= u64::BITS { 0 } else { val << sa }
}

/// The smallest of the masks for 1, 2, 4 and 8 bytes that covers `val`.
pub const fn minimalmask(val: u64) -> u64 {
    if val > 0xffff_ffff {
        u64::MAX
    } else if val > 0xffff {
        0xffff_ffff
    } else if val > 0xff {
        0xffff
    } else {
        0xff
    }
}

/// Sign-extends `val` above bit `bit` (bit 0 is the least significant).
/// Ghidra: `sign_extend(intb val, int4 bit)`. For `bit` 63 and above the
/// value is returned unchanged.
pub const fn sign_extend_bit(val: i64, bit: u32) -> i64 {
    if bit >= 63 {
        return val;
    }
    let sa = 63 - bit;
    (val << sa) >> sa
}

/// Clears all bits of `val` above bit `bit`. Ghidra: `zero_extend(intb val,
/// int4 bit)`. For `bit` 63 and above the value is returned unchanged.
pub const fn zero_extend_bit(val: i64, bit: u32) -> i64 {
    if bit >= 63 {
        return val;
    }
    let sa = 63 - bit;
    ((val.cast_unsigned() << sa) >> sa).cast_signed()
}

/// Whether the sign bit of `val`, taken as a value of `size` bytes, is set.
/// For 0 bytes and for more than 8, where there is no such bit in a 64-bit
/// value, the answer is `false`.
pub const fn signbit_negative(val: u64, size: u32) -> bool {
    if size == 0 || size > 8 {
        return false;
    }
    val & (0x80 << (8 * (size - 1))) != 0
}

/// The bitwise complement of `val` within `size` bytes; higher bytes are 0.
pub const fn uintb_negate(val: u64, size: u32) -> u64 {
    !val & calc_mask(size)
}

/// Takes the low `size_in` bytes of `val` and sign-extends them to `size_out`
/// bytes, leaving higher bytes 0. Both sizes are capped at 8. Ghidra:
/// `sign_extend(uintb in, int4 sizein, int4 sizeout)`.
///
/// The C++ is undefined when `size_in` is 0 or `size_out` is smaller than
/// `size_in`; here the first gives 0 and the second truncates to `size_out`
/// bytes.
pub const fn sign_extend(val: u64, size_in: u32, size_out: u32) -> u64 {
    let size_in = if size_in < 8 { size_in } else { 8 };
    let size_out = if size_out < 8 { size_out } else { 8 };
    if size_in == 0 || size_out == 0 {
        return 0;
    }
    if size_out <= size_in {
        return val & calc_mask(size_out);
    }
    let sval = val.cast_signed() << ((8 - size_in) * 8);
    let res = (sval >> ((size_out - size_in) * 8)).cast_unsigned();
    res >> ((8 - size_out) * 8)
}

/// Sign-extends a value of `numbits` bits to an integer of `size` bytes.
/// A value that already fills the integer is returned unchanged. The C++ is
/// undefined for 0 bits; the result here is 0.
pub const fn extend_signbit(val: u64, numbits: u32, size: u32) -> u64 {
    if (numbits as u64) < (size as u64) * 8 {
        if numbits == 0 {
            return 0;
        }
        if numbits >= u64::BITS {
            return val & calc_mask(size);
        }
        let sa = u64::BITS - numbits;
        ((val.cast_signed() << sa) >> sa).cast_unsigned() & calc_mask(size)
    } else {
        val
    }
}

/// Reverses the order of the low `size` bytes of `val`; higher bytes of the
/// result are 0. As in Ghidra's loop, a size above 8 shifts the reversed
/// bytes up by the excess.
pub const fn byte_swap(val: u64, size: u32) -> u64 {
    let mut val = val;
    let mut res = 0;
    // After 16 rounds every bit of the input has been shifted out again.
    let mut remaining = if size < 16 { size } else { 16 };
    while remaining > 0 {
        res = (res << 8) | (val & 0xff);
        val >>= 8;
        remaining -= 1;
    }
    res
}

/// The signed form of [`byte_swap`] (Ghidra `byte_swap(intb &val, int4
/// size)`): the same for sizes up to 8; above that the sign fills the bytes
/// shifted in.
pub const fn byte_swap_signed(val: i64, size: u32) -> i64 {
    let mut val = val;
    let mut res: i64 = 0;
    let mut remaining = if size < 16 { size } else { 16 };
    while remaining > 0 {
        res = (res << 8) | (val & 0xff);
        val >>= 8;
        remaining -= 1;
    }
    res
}

/// The index of the least significant set bit (bit 0 is the least
/// significant), or -1 if `val` is 0.
pub const fn leastsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        val.trailing_zeros().cast_signed()
    }
}

/// The index of the most significant set bit, or -1 if `val` is 0.
pub const fn mostsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        val.ilog2().cast_signed()
    }
}

/// The number of set bits.
pub const fn popcount(val: u64) -> i32 {
    val.count_ones().cast_signed()
}

/// The number of zero bits above the most significant set bit; 64 for 0.
pub const fn count_leading_zeros(val: u64) -> i32 {
    val.leading_zeros().cast_signed()
}

/// The smallest value of the form 2^n - 1 that is not below `val`.
pub const fn coveringmask(val: u64) -> u64 {
    if val == 0 {
        0
    } else {
        u64::MAX >> val.leading_zeros()
    }
}

/// The number of 0→1 and 1→0 transitions across the bits of `val`, taken as
/// a value of `size` bytes and scanned from the least significant bit. Two or
/// fewer suggest a flag or a mask.
pub const fn bit_transitions(val: u64, size: u32) -> i32 {
    // Bits above the size never enter Ghidra's loop.
    let bits = if size >= 8 { u64::BITS } else { size * 8 };
    if bits == 0 {
        return 0;
    }
    let mask = if bits == u64::BITS {
        u64::MAX
    } else {
        (1 << bits) - 1
    };
    // A transition sits between bit i and bit i+1 wherever they differ, for
    // the pairs that lie within the size.
    let transitions = ((val ^ (val >> 1)) & (mask >> 1)).count_ones();
    // Past 8 bytes Ghidra's loop also sees the top bit fall to zero.
    let beyond = if size > 8 { (val >> 63) as u32 } else { 0 };
    (transitions + beyond).cast_signed()
}

#[cfg(test)]
mod tests {
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
}
