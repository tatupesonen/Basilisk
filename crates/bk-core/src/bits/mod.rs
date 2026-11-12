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
mod tests;
