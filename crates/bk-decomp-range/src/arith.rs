//! The C++ integer semantics `rangeutil.cc` relies on, written out.
//!
//! Ghidra mixes `uintb` (`u64`), `int4` (`i32`) and `uint4` (`u32`) freely,
//! so each expression has to be evaluated with the conversions C++ applies:
//! an `int4` step used with a `uintb` is sign-extended to 64 bits and then
//! read as unsigned, and an `int4` used with a `uint4` is read as 32-bit
//! unsigned. Where the C++ is undefined, the result here is the one both
//! reference builds produce (ADR-024): a shift count is taken modulo the
//! operand width, as x86-64 and AArch64 shift instructions do, and signed
//! arithmetic wraps. Division by zero, which Ghidra never performs for a
//! valid range (its steps are at least 1), gives AArch64's answer: a
//! quotient of 0 and a remainder equal to the dividend.

/// An `int4` step converted to `uintb`: sign-extended, then unsigned.
#[inline]
pub(crate) const fn wide(step: i32) -> u64 {
    (step as i64).cast_unsigned()
}

/// An `int4` converted to `uint4`.
#[inline]
pub(crate) const fn narrow(step: i32) -> u32 {
    step.cast_unsigned()
}

/// `a % b` on `uintb`; `a` when `b` is 0.
#[inline]
pub(crate) const fn rem(a: u64, b: u64) -> u64 {
    match a.checked_rem(b) {
        Some(r) => r,
        None => a,
    }
}

/// `a / b` on `uintb`; 0 when `b` is 0.
#[inline]
pub(crate) const fn div(a: u64, b: u64) -> u64 {
    match a.checked_div(b) {
        Some(q) => q,
        None => 0,
    }
}

/// `a % b` on `uint4`; `a` when `b` is 0.
#[inline]
pub(crate) const fn rem32(a: u32, b: u32) -> u32 {
    match a.checked_rem(b) {
        Some(r) => r,
        None => a,
    }
}

/// `a % step` for a `uintb` and an `int4` step, as C++ evaluates it.
#[inline]
pub(crate) const fn rem_step(a: u64, step: i32) -> u64 {
    rem(a, wide(step))
}

/// `v << n` on `uintb`, the count taken modulo 64.
#[inline]
pub(crate) const fn shl(v: u64, n: u64) -> u64 {
    v << (n & 63)
}

/// `v >> n` (logical) on `uintb`, the count taken modulo 64.
#[inline]
pub(crate) const fn shr(v: u64, n: u64) -> u64 {
    v >> (n & 63)
}

/// `v >> n` (arithmetic) on `intb`, the count taken modulo 64.
#[inline]
pub(crate) const fn sar(v: i64, n: u64) -> i64 {
    v >> (n & 63)
}

/// An `int4` shift count (possibly negative) as the count register sees it.
#[inline]
pub(crate) const fn count(n: i32) -> u64 {
    wide(n)
}

/// Ghidra's `calc_mask` for an `int4` size: a negative size reads as a
/// large unsigned one and gives the full mask.
#[inline]
pub(crate) const fn mask_of(size: u32) -> u64 {
    bk_core::bits::calc_mask(size)
}

/// Ghidra's `sign_extend(uintb in, int4 sizein, int4 sizeout)` from
/// `address.cc`, evaluated as both reference builds do when `sizeout` is
/// smaller than `sizein` or a size is 0: each shift count modulo 64.
/// (`bk_core::bits::sign_extend` defines those cases differently.)
#[inline]
pub(crate) const fn sign_extend_sizes(val: u64, size_in: u32, size_out: u32) -> u64 {
    let size_in = if size_in < 8 { size_in } else { 8 } as i64;
    let size_out = if size_out < 8 { size_out } else { 8 } as i64;
    let sval = val.cast_signed();
    let sval = sval << (((8 - size_in) * 8) & 63);
    let res = (sval >> (((size_out - size_in) * 8) & 63)).cast_unsigned();
    res >> (((8 - size_out) * 8) & 63)
}

/// Ghidra's inline `sign_extend(intb val, int4 bit)` from `address.hh`:
/// `sa = 64 - (bit + 1)`, then `(val << sa) >> sa`, each count modulo 64.
#[inline]
pub(crate) const fn sign_extend_bit(val: i64, bit: i32) -> i64 {
    let sa = count(64i32.wrapping_sub(bit.wrapping_add(1)));
    (val << (sa & 63)) >> (sa & 63)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_follow_cpp() {
        assert_eq!(wide(-1), u64::MAX);
        assert_eq!(wide(4), 4);
        assert_eq!(narrow(-1), u32::MAX);
        assert_eq!(rem_step(10, 4), 2);
        assert_eq!(rem_step(10, 0), 10);
        assert_eq!(rem_step(10, -1), 10);
        assert_eq!(div(10, 0), 0);
        assert_eq!(rem32(7, 0), 7);
    }

    #[test]
    fn shifts_wrap_their_count() {
        assert_eq!(shl(1, 64), 1);
        assert_eq!(shl(1, 65), 2);
        assert_eq!(shr(0x80, 71), 1);
        assert_eq!(sar(-8, 66), -2);
        assert_eq!(count(-8) & 63, 56);
    }

    #[test]
    fn sign_extend_matches_bits_where_defined() {
        for (v, i, o) in [
            (0x80u64, 1, 2),
            (0x7f, 1, 8),
            (0x8000, 2, 4),
            (0xffff_ffff, 4, 8),
        ] {
            assert_eq!(
                sign_extend_sizes(v, i, o),
                bk_core::bits::sign_extend(v, i, o)
            );
        }
        // Narrowing: (v << 32) >> 48 (arithmetic), then >> 48.
        assert_eq!(sign_extend_sizes(0x8000_0000, 4, 2), 0xffff);
        assert_eq!(sign_extend_sizes(0x1234, 4, 2), 0);
    }

    #[test]
    fn sign_extend_bit_counts_modulo_64() {
        assert_eq!(sign_extend_bit(0x80, 7), -128);
        assert_eq!(sign_extend_bit(0x80, 63), 0x80);
        // bit -1: sa = 64, taken as 0.
        assert_eq!(sign_extend_bit(0x80, -1), 0x80);
        // bit 71: sa = -8, taken as 56.
        assert_eq!(sign_extend_bit(0x80, 71), -128);
    }
}
