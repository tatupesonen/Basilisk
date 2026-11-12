//! A range of bits within a byte container (Ghidra `BitRange` in
//! `address.hh`/`address.cc`).
//!
//! The container is `byte_size` bytes at `byte_offset` (relative to some
//! storage the caller knows about); the range is `num_bits` bits starting at
//! bit `least_sig_bit`, counted from the least significant bit of the
//! container's value. Endianness says which end of the container holds the
//! least significant byte. The arithmetic is Ghidra's, done with wrapping
//! `i32` operations so that no input panics; results for inputs Ghidra would
//! overflow on are unspecified but deterministic.

use std::cmp::Ordering;

use crate::bits::{leastsigbit_set, mostsigbit_set};

/// How two bit ranges overlap (Ghidra `BitRange::overlapTest`, whose return
/// value is given with each variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BitOverlap {
    /// No overlap, and `self` comes first: before `other` in a big-endian
    /// container, below it in a little-endian one (-1).
    Before,
    /// No overlap, and `self` comes after `other` (1).
    After,
    /// The same bits (0).
    Equal,
    /// `self` lies within `other` (2).
    Contained,
    /// `other` lies within `self` (3).
    Contains,
    /// The ranges overlap partially (4).
    Partial,
}

/// A range of bits within a range of bytes (Ghidra `BitRange`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitRange {
    /// Offset of the byte container.
    pub byte_offset: i32,
    /// Size of the byte container in bytes.
    pub byte_size: i32,
    /// The least significant bit of the range within the container.
    pub least_sig_bit: i32,
    /// The number of bits in the range.
    pub num_bits: i32,
    /// Whether the container is big endian.
    pub is_big_endian: bool,
}

impl Default for BitRange {
    /// The undefined range: every field -1, little endian (Ghidra's default
    /// constructor).
    fn default() -> Self {
        Self {
            byte_offset: -1,
            byte_size: -1,
            least_sig_bit: -1,
            num_bits: -1,
            is_big_endian: false,
        }
    }
}

impl BitRange {
    /// A range of `num_bits` bits from `least_sig_bit` in the given
    /// container.
    pub const fn new(
        byte_offset: i32,
        byte_size: i32,
        least_sig_bit: i32,
        num_bits: i32,
        is_big_endian: bool,
    ) -> Self {
        Self {
            byte_offset,
            byte_size,
            least_sig_bit,
            num_bits,
            is_big_endian,
        }
    }

    /// The whole of a byte container as a bit range.
    pub const fn bytes(byte_offset: i32, byte_size: i32, is_big_endian: bool) -> Self {
        Self::new(
            byte_offset,
            byte_size,
            0,
            byte_size.wrapping_mul(8),
            is_big_endian,
        )
    }

    /// The bits of `other` placed in a different container (Ghidra's copy
    /// constructor `BitRange(op2, off, sz)`).
    pub const fn in_container(other: &Self, byte_offset: i32, byte_size: i32) -> Self {
        let mut range = Self::new(
            byte_offset,
            byte_size,
            0,
            other.num_bits,
            other.is_big_endian,
        );
        range.least_sig_bit = range.translate_lsb(other);
        range
    }

    /// Whether the range has no bits.
    pub const fn is_empty(&self) -> bool {
        self.num_bits <= 0
    }

    /// Compares the containers and then the ranges: byte offset, byte size,
    /// least significant bit, number of bits (Ghidra `compare`).
    pub fn compare(&self, other: &Self) -> Ordering {
        (
            self.byte_offset,
            self.byte_size,
            self.least_sig_bit,
            self.num_bits,
        )
            .cmp(&(
                other.byte_offset,
                other.byte_size,
                other.least_sig_bit,
                other.num_bits,
            ))
    }

    /// The least significant bit of `other` as a bit position in this
    /// range's container (Ghidra `translateLSB`).
    pub const fn translate_lsb(&self, other: &Self) -> i32 {
        let shift = if self.is_big_endian {
            let this_end = self.byte_offset.wrapping_add(self.byte_size);
            let other_end = other.byte_offset.wrapping_add(other.byte_size);
            this_end.wrapping_sub(other_end)
        } else {
            other.byte_offset.wrapping_sub(self.byte_offset)
        };
        other.least_sig_bit.wrapping_add(shift.wrapping_mul(8))
    }

    /// How this range and `other` overlap (Ghidra `overlapTest`).
    pub const fn overlap_test(&self, other: &Self) -> BitOverlap {
        let other_lsb = self.translate_lsb(other);
        let this_most = self.least_sig_bit.wrapping_add(self.num_bits);
        let other_most = other_lsb.wrapping_add(other.num_bits);
        if self.is_big_endian {
            if self.least_sig_bit >= other_most {
                return BitOverlap::Before;
            }
            if other_lsb >= this_most {
                return BitOverlap::After;
            }
        } else {
            if this_most <= other_lsb {
                return BitOverlap::Before;
            }
            if other_most <= self.least_sig_bit {
                return BitOverlap::After;
            }
        }
        if self.least_sig_bit == other_lsb && this_most == other_most {
            BitOverlap::Equal
        } else if other_lsb <= self.least_sig_bit && other_most >= this_most {
            BitOverlap::Contained
        } else if self.least_sig_bit <= other_lsb && this_most >= other_most {
            BitOverlap::Contains
        } else {
            BitOverlap::Partial
        }
    }

    /// Narrows this range to its intersection with `other` (Ghidra
    /// `intersection`); an empty intersection leaves 0 bits at bit 0.
    pub const fn intersect(&mut self, other: &Self) {
        let other_lsb = self.translate_lsb(other);
        let other_most = other_lsb.wrapping_add(other.num_bits);
        let this_most = self.least_sig_bit.wrapping_add(self.num_bits);
        if other_lsb > self.least_sig_bit {
            self.num_bits = self
                .num_bits
                .wrapping_sub(other_lsb.wrapping_sub(self.least_sig_bit));
            self.least_sig_bit = other_lsb;
        }
        if other_most < this_most {
            self.num_bits = self
                .num_bits
                .wrapping_sub(this_most.wrapping_sub(other_most));
        }
        if self.num_bits < 0 {
            self.least_sig_bit = 0;
            self.num_bits = 0;
        }
    }

    /// Narrows this range to the bits set in `mask`, a value aligned with the
    /// container: to the span from the lowest to the highest set bit within
    /// the range (Ghidra `intersectMask`).
    pub const fn intersect_mask(&mut self, mask: u64) {
        let mask = mask & self.mask();
        if mask == 0 {
            self.least_sig_bit = 0;
            self.num_bits = 0;
            return;
        }
        let new_least = leastsigbit_set(mask);
        let new_most = mostsigbit_set(mask).wrapping_add(1);
        let this_most = self.least_sig_bit.wrapping_add(self.num_bits);
        if new_least > self.least_sig_bit {
            self.num_bits = self
                .num_bits
                .wrapping_sub(new_least.wrapping_sub(self.least_sig_bit));
            self.least_sig_bit = new_least;
        }
        if new_most < this_most {
            self.num_bits = self.num_bits.wrapping_sub(this_most.wrapping_sub(new_most));
        }
    }

    /// Shifts the range left by `amount` bits (right if negative), cutting
    /// it at the ends of the container (Ghidra `shift`).
    pub const fn shift(&mut self, amount: i32) {
        self.least_sig_bit = self.least_sig_bit.wrapping_add(amount);
        let most = self.least_sig_bit.wrapping_add(self.num_bits);
        let container_bits = self.byte_size.wrapping_mul(8);
        if self.least_sig_bit < 0 {
            self.num_bits = self.num_bits.wrapping_add(self.least_sig_bit);
            self.least_sig_bit = 0;
        } else if most > container_bits {
            self.num_bits = self
                .num_bits
                .wrapping_sub(most.wrapping_sub(container_bits));
        }
        if self.num_bits < 0 {
            self.least_sig_bit = 0;
            self.num_bits = 0;
        }
    }

    /// Removes the `count` most significant bytes from the container,
    /// cutting the range to fit (Ghidra `truncateMostSigBytes`).
    pub const fn truncate_most_sig_bytes(&mut self, count: i32) {
        if self.is_big_endian {
            self.byte_offset = self.byte_offset.wrapping_add(count);
        }
        self.byte_size = self.byte_size.wrapping_sub(count);
        let max = self.least_sig_bit.wrapping_add(self.num_bits);
        let container_bits = self.byte_size.wrapping_mul(8);
        if max > container_bits {
            self.num_bits = self.num_bits.wrapping_sub(max.wrapping_sub(container_bits));
        }
        if self.num_bits < 0 {
            self.num_bits = 0;
        }
    }

    /// Removes the `count` least significant bytes from the container,
    /// cutting the range to fit (Ghidra `truncateLeastSigBytes`).
    pub const fn truncate_least_sig_bytes(&mut self, count: i32) {
        if !self.is_big_endian {
            self.byte_offset = self.byte_offset.wrapping_add(count);
        }
        self.byte_size = self.byte_size.wrapping_sub(count);
        self.least_sig_bit = self.least_sig_bit.wrapping_sub(count.wrapping_mul(8));
        if self.least_sig_bit < 0 {
            self.num_bits = self.num_bits.wrapping_add(self.least_sig_bit);
            self.least_sig_bit = 0;
            if self.num_bits < 0 {
                self.num_bits = 0;
            }
        }
    }

    /// Adds `count` most significant bytes to the container (Ghidra
    /// `extendBytes`).
    pub const fn extend_bytes(&mut self, count: i32) {
        if self.is_big_endian {
            self.byte_offset = self.byte_offset.wrapping_sub(count);
        }
        self.byte_size = self.byte_size.wrapping_add(count);
    }

    /// The range as a mask over the container's value (Ghidra `getMask`).
    /// Bits beyond the 64 of the value are dropped; a negative bit count or
    /// position gives 0, where Ghidra's shift is undefined.
    pub const fn mask(&self) -> u64 {
        if self.num_bits < 0 || self.least_sig_bit < 0 || self.least_sig_bit >= 64 {
            return 0;
        }
        let ones = if self.num_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << self.num_bits).wrapping_sub(1)
        };
        ones << self.least_sig_bit
    }

    /// Whether the range is also a whole number of bytes (Ghidra
    /// `isByteRange`).
    pub const fn is_byte_range(&self) -> bool {
        self.num_bits.trailing_zeros() >= 3 && self.least_sig_bit.trailing_zeros() >= 3
    }

    /// Whether the range reaches the most significant bit of the container
    /// (Ghidra `isMostSignificant`).
    pub const fn is_most_significant(&self) -> bool {
        self.byte_size.wrapping_mul(8) == self.least_sig_bit.wrapping_add(self.num_bits)
    }

    /// Shrinks the container to the bytes the range touches (Ghidra
    /// `minimizeContainer`).
    pub const fn minimize_container(&mut self) {
        let trunc = self.least_sig_bit / 8;
        if self.is_big_endian {
            self.byte_size = self.byte_size.wrapping_sub(trunc);
        } else {
            self.byte_offset = self.byte_offset.wrapping_add(trunc);
        }
        self.least_sig_bit &= 7;
        let needed = self
            .least_sig_bit
            .wrapping_add(self.num_bits)
            .wrapping_add(7)
            / 8;
        let extra = self.byte_size.wrapping_sub(needed);
        if extra > 0 {
            if self.is_big_endian {
                self.byte_offset = self.byte_offset.wrapping_add(extra);
            }
            self.byte_size -= extra;
        }
    }

    /// Extends the range up to the most significant bit of the container
    /// (Ghidra `expandToMost`).
    pub const fn expand_to_most(&mut self) {
        self.num_bits = self
            .byte_size
            .wrapping_mul(8)
            .wrapping_sub(self.least_sig_bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_mask() {
        let whole = BitRange::bytes(4, 2, false);
        assert_eq!(whole.mask(), 0xffff);
        assert!(whole.is_byte_range() && whole.is_most_significant());
        assert!(BitRange::default().is_empty());
        let bits = BitRange::new(0, 4, 3, 5, false);
        assert_eq!(bits.mask(), 0b1111_1000);
        assert!(!bits.is_byte_range());
        assert_eq!(BitRange::new(0, 8, 0, 64, false).mask(), u64::MAX);
        assert_eq!(BitRange::new(0, 8, 70, 4, false).mask(), 0);
        assert_eq!(BitRange::new(0, 8, 0, -3, false).mask(), 0);
    }

    #[test]
    fn translation_between_containers() {
        // Little endian: bytes 2..4 of a container at 0 sit 16 bits up.
        let outer = BitRange::bytes(0, 4, false);
        let inner = BitRange::new(2, 2, 1, 3, false);
        assert_eq!(outer.translate_lsb(&inner), 17);
        // Big endian: the last bytes are the least significant.
        let outer = BitRange::bytes(0, 4, true);
        let inner = BitRange::new(0, 2, 1, 3, true);
        assert_eq!(outer.translate_lsb(&inner), 17);
        let moved = BitRange::in_container(&inner, 0, 4);
        assert_eq!((moved.least_sig_bit, moved.num_bits), (17, 3));
    }

    #[test]
    fn overlap_cases() {
        let a = BitRange::new(0, 4, 8, 8, false);
        let cases = [
            (BitRange::new(0, 4, 16, 8, false), BitOverlap::Before),
            (BitRange::new(0, 4, 0, 8, false), BitOverlap::After),
            (BitRange::new(0, 4, 8, 8, false), BitOverlap::Equal),
            (BitRange::new(0, 4, 4, 16, false), BitOverlap::Contained),
            (BitRange::new(0, 4, 10, 2, false), BitOverlap::Contains),
            (BitRange::new(0, 4, 12, 8, false), BitOverlap::Partial),
        ];
        for (other, expected) in cases {
            assert_eq!(a.overlap_test(&other), expected, "{other:?}");
        }
        let b = BitRange::new(0, 4, 8, 8, true);
        assert_eq!(
            b.overlap_test(&BitRange::new(0, 4, 0, 8, true)),
            BitOverlap::Before
        );
        assert_eq!(
            b.overlap_test(&BitRange::new(0, 4, 16, 8, true)),
            BitOverlap::After
        );
    }

    #[test]
    fn narrowing_and_shifting() {
        let mut a = BitRange::new(0, 4, 4, 16, false);
        a.intersect(&BitRange::new(0, 4, 8, 32, false));
        assert_eq!((a.least_sig_bit, a.num_bits), (8, 12));
        a.intersect(&BitRange::new(0, 4, 24, 4, false));
        assert_eq!((a.least_sig_bit, a.num_bits), (0, 0));

        let mut m = BitRange::new(0, 4, 0, 32, false);
        m.intersect_mask(0x00f0_0f00);
        assert_eq!((m.least_sig_bit, m.num_bits), (8, 16));
        m.intersect_mask(0);
        assert!(m.is_empty());

        let mut s = BitRange::new(0, 2, 4, 8, false);
        s.shift(6);
        assert_eq!((s.least_sig_bit, s.num_bits), (10, 6));
        s.shift(-12);
        assert_eq!((s.least_sig_bit, s.num_bits), (0, 4));
        s.shift(-40);
        assert_eq!((s.least_sig_bit, s.num_bits), (0, 0));
    }

    #[test]
    fn container_changes() {
        let mut a = BitRange::new(0, 4, 4, 24, true);
        a.truncate_most_sig_bytes(1);
        assert_eq!((a.byte_offset, a.byte_size, a.num_bits), (1, 3, 20));
        a.truncate_least_sig_bytes(1);
        assert_eq!(
            (a.byte_offset, a.byte_size, a.least_sig_bit, a.num_bits),
            (1, 2, 0, 16)
        );
        a.extend_bytes(2);
        assert_eq!((a.byte_offset, a.byte_size), (-1, 4));
        a.expand_to_most();
        assert_eq!(a.num_bits, 32);

        let mut le = BitRange::new(0, 8, 12, 8, false);
        le.minimize_container();
        assert_eq!(
            (le.byte_offset, le.byte_size, le.least_sig_bit, le.num_bits),
            (1, 2, 4, 8)
        );
        let mut be = BitRange::new(0, 8, 12, 8, true);
        be.minimize_container();
        assert_eq!(
            (be.byte_offset, be.byte_size, be.least_sig_bit, be.num_bits),
            (5, 2, 4, 8)
        );
        assert_eq!(
            BitRange::new(0, 4, 0, 8, false).compare(&BitRange::new(0, 4, 0, 9, false)),
            Ordering::Less
        );
    }
}
