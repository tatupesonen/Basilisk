//! A pattern block: required bit values over a run of bytes
//! (`PatternBlock`, inventory 10 b.1–b.2), and the builders that turn a
//! field and a value into one (`buildSingle`, `buildBigBlock`,
//! `buildLittleBlock`, 10 a.2).
//!
//! Bits are numbered from the most significant bit of byte 0. Word `k`
//! covers bytes `offset + 4k .. offset + 4k + 3`, most significant byte
//! first. Blocks are kept in Ghidra's canonical form (`normalize`), which is
//! exactly what the file stores.

use bk_sla::{MaskWord, normalize_block};

/// A block of mask and value words starting at a byte offset.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    /// The byte of the first stored word.
    pub offset: i32,
    /// Bytes from `offset` to the last constrained byte; 0 always true,
    /// −1 always false.
    pub nonzero: i32,
    /// The words.
    pub words: Vec<MaskWord>,
}

impl Block {
    /// The always-true (`true`) or always-false block.
    pub const fn constant(value: bool) -> Self {
        Self {
            offset: 0,
            nonzero: if value { 0 } else { -1 },
            words: Vec::new(),
        }
    }

    /// One word at a byte offset, normalised (`PatternBlock(off,msk,val)`).
    pub fn word(offset: i32, mask: u32, value: u32) -> Self {
        Self::normalized(offset, 4, vec![MaskWord { mask, value }])
    }

    fn normalized(mut offset: i32, mut nonzero: i32, mut words: Vec<MaskWord>) -> Self {
        normalize_block(&mut offset, &mut nonzero, &mut words);
        Self {
            offset,
            nonzero,
            words,
        }
    }

    /// Matches everything.
    pub const fn always_true(&self) -> bool {
        self.nonzero == 0
    }

    /// Matches nothing.
    pub const fn always_false(&self) -> bool {
        self.nonzero == -1
    }

    /// `getLength`: one past the last constrained byte (−1 when false).
    pub const fn length(&self) -> i32 {
        self.offset.wrapping_add(self.nonzero)
    }

    /// Moves the block `sa` bytes later (`shift`).
    pub fn shift(&mut self, sa: i32) {
        self.offset = self.offset.wrapping_add(sa);
        let words = std::mem::take(&mut self.words);
        *self = Self::normalized(self.offset, self.nonzero, words);
    }

    /// `size` (1–32) bits of the mask starting at absolute bit `start`,
    /// right-aligned; bits outside the stored words are 0.
    pub fn mask(&self, start: i32, size: i32) -> u32 {
        self.extract(start, size, |w| w.mask)
    }

    /// `size` (1–32) bits of the value starting at absolute bit `start`.
    pub fn value(&self, start: i32, size: i32) -> u32 {
        self.extract(start, size, |w| w.value)
    }

    fn extract(&self, start: i32, size: i32, part: impl Fn(&MaskWord) -> u32) -> u32 {
        if !(1..=32).contains(&size) {
            return 0;
        }
        let bit = i64::from(start) - 8 * i64::from(self.offset);
        let word = |n: i64| -> u32 {
            usize::try_from(n)
                .ok()
                .and_then(|n| self.words.get(n))
                .map_or(0, &part)
        };
        let first = bit.div_euclid(32);
        let shift = bit.rem_euclid(32) as u32;
        let last = (bit + i64::from(size) - 1).div_euclid(32);
        let mut res = word(first) << shift;
        if first != last && shift != 0 {
            res |= word(last) >> (32 - shift);
        }
        res >> (32 - size as u32)
    }

    /// The words of both blocks over the longer one, word by word, combined
    /// by `f`; `None` from `f` makes the result `None`.
    fn combine(
        &self,
        other: &Self,
        mut f: impl FnMut(u32, u32, u32, u32) -> Option<MaskWord>,
    ) -> Option<Self> {
        let max = self.length().max(other.length());
        let mut words = Vec::with_capacity(usize::try_from(max).unwrap_or(0).div_ceil(4));
        let mut byte = 0_i32;
        while byte < max {
            let bit = byte.wrapping_mul(8);
            words.push(f(
                self.mask(bit, 32),
                self.value(bit, 32),
                other.mask(bit, 32),
                other.value(bit, 32),
            )?);
            byte = byte.wrapping_add(4);
        }
        Some(Self::normalized(0, max, words))
    }

    /// The block matching what both match (`intersect`).
    pub fn intersect(&self, other: &Self) -> Self {
        if self.always_false() || other.always_false() {
            return Self::constant(false);
        }
        self.combine(other, |m1, v1, m2, v2| {
            let common = m1 & m2;
            ((common & v1) == (common & v2)).then_some(MaskWord {
                mask: m1 | m2,
                value: (m1 & v1) | (m2 & v2),
            })
        })
        .unwrap_or(Self::constant(false))
    }

    /// The bits both constrain to the same value (`commonSubPattern`). No
    /// special case for false blocks: false with anything gives true, false
    /// with false gives false (Ghidra's behaviour through `getLength`).
    pub fn common(&self, other: &Self) -> Self {
        self.combine(other, |m1, v1, m2, v2| {
            let mask = m1 & m2 & !(v1 ^ v2);
            Some(MaskWord {
                mask,
                value: v1 & v2 & mask,
            })
        })
        .unwrap_or(Self::constant(true))
    }

    /// Runs `f` over both blocks in chunks of at most 32 bits over the
    /// first `bits` bits; false as soon as `f` is.
    fn all_chunks(&self, other: &Self, bits: i32, f: impl Fn(u32, u32, u32, u32) -> bool) -> bool {
        let mut start = 0_i32;
        while start < bits {
            let len = (bits - start).min(32);
            if !f(
                self.mask(start, len),
                self.value(start, len),
                other.mask(start, len),
                other.value(start, len),
            ) {
                return false;
            }
            start += len;
        }
        true
    }

    /// Every bit `other` constrains is constrained here to the same value
    /// (`specializes`).
    pub fn specializes(&self, other: &Self) -> bool {
        let bits = other.length().wrapping_mul(8);
        self.all_chunks(other, bits, |m1, v1, m2, v2| {
            (m1 & m2) == m2 && (v1 & m2) == (v2 & m2)
        })
    }

    /// Same mask and masked values over the longer length (`identical`).
    pub fn identical(&self, other: &Self) -> bool {
        let bits = other.length().max(self.length()).wrapping_mul(8);
        self.all_chunks(other, bits, |m1, v1, m2, v2| {
            m1 == m2 && (m1 & v1) == (m2 & v2)
        })
    }

    /// The block for bits `start..=end` (at most 8, within one byte) set to
    /// the low bits of `value` (`buildSingle`).
    pub fn single(start: i32, end: i32, value: u32) -> Self {
        let size = end.wrapping_sub(start).wrapping_add(1);
        if !(1..=32).contains(&size) || start < 0 {
            return Self::constant(true);
        }
        let offset = start / 8;
        let start = start % 8;
        let mask = u32::MAX << (32 - size as u32);
        let value = (value << (32 - size as u32)) & mask;
        let start = start as u32;
        Self::word(offset, mask >> start, value >> start)
    }

    /// The block for bits `bitstart..=bitend` of a big-endian token of
    /// `size` bytes (bits numbered from the least significant end) holding
    /// `value` (`buildBigBlock`).
    pub fn big(size: i32, bitstart: i32, bitend: i32, mut value: i64) -> Self {
        let start = size.wrapping_mul(8) - 1 - bitend;
        let mut end = size.wrapping_mul(8) - 1 - bitstart;
        let mut block: Option<Self> = None;
        while end >= start {
            let piece_start = (end - (end & 7)).max(start);
            let piece = Self::single(piece_start, end, value as u32);
            block = Some(match block {
                None => piece,
                Some(b) => b.intersect(&piece),
            });
            value = value.wrapping_shr((end - piece_start + 1) as u32);
            end = piece_start - 1;
        }
        block.unwrap_or(Self::constant(true))
    }

    /// The block for bits `bitstart..=bitend` of a little-endian token
    /// holding `value` (`buildLittleBlock`).
    pub fn little(bitstart: i32, bitend: i32, mut value: i64) -> Self {
        let mut start = (bitstart / 8) * 8;
        let end = (bitend / 8) * 8;
        let low_end = bitend % 8;
        let low_start = bitstart % 8;
        if start == end {
            return Self::single(start + 7 - low_end, end + 7 - low_start, value as u32);
        }
        let mut block = Self::single(start, start + (7 - low_start), value as u32);
        value = value.wrapping_shr((8 - low_start) as u32);
        start += 8;
        while start < end {
            block = block.intersect(&Self::single(start, start + 7, value as u32));
            value = value.wrapping_shr(8);
            start += 8;
        }
        block.intersect(&Self::single(end + (7 - low_end), end + 7, value as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(b: &Block) -> Vec<(u32, u32)> {
        b.words.iter().map(|w| (w.mask, w.value)).collect()
    }

    #[test]
    fn single_inside_a_byte() {
        // Bits 2..=4 of byte 1 = 0b101.
        let b = Block::single(10, 12, 5);
        assert_eq!((b.offset, b.nonzero), (1, 1));
        assert_eq!(words(&b), [(0x3800_0000, 0x2800_0000)]);
    }

    #[test]
    fn big_endian_field_across_bytes() {
        // 2-byte big-endian token, bits 4..=11 (LSB numbering) = 0xab.
        let b = Block::big(2, 4, 11, 0xab);
        assert_eq!((b.offset, b.nonzero), (0, 2));
        assert_eq!(words(&b), [(0x0ff0_0000, 0x0ab0_0000)]);
    }

    #[test]
    fn little_endian_field_across_bytes() {
        // Little-endian, bits 4..=11 = 0xab: low nibble 0xb in the top of
        // byte 0, high nibble 0xa in the bottom of byte 1.
        let b = Block::little(4, 11, 0xab);
        assert_eq!((b.offset, b.nonzero), (0, 2));
        assert_eq!(words(&b), [(0xf00f_0000, 0xb00a_0000)]);
    }

    #[test]
    fn little_endian_field_in_one_byte_and_over_three() {
        let b = Block::little(0, 2, 5);
        assert_eq!(words(&b), [(0x0700_0000, 0x0500_0000)]);
        let b = Block::little(4, 19, 0x1234);
        assert_eq!((b.offset, b.nonzero), (0, 3));
        assert_eq!(words(&b), [(0xf0ff_0f00, 0x4023_0100)]);
    }

    #[test]
    fn eight_byte_big_endian_token() {
        let b = Block::big(8, 0, 63, -1);
        assert_eq!((b.offset, b.nonzero), (0, 8));
        assert_eq!(words(&b), [(u32::MAX, u32::MAX), (u32::MAX, u32::MAX)]);
        let b = Block::big(8, 60, 63, 0x9);
        assert_eq!(words(&b), [(0xf000_0000, 0x9000_0000)]);
    }

    #[test]
    fn intersect_conflict_is_false() {
        let a = Block::word(0, 0xff00_0000, 0x1200_0000);
        let b = Block::word(0, 0x0f00_0000, 0x0300_0000);
        assert!(a.intersect(&b).always_false());
        let c = Block::word(1, 0xff00_0000, 0x3400_0000);
        let ac = a.intersect(&c);
        assert_eq!((ac.offset, ac.nonzero), (0, 2));
        assert_eq!(words(&ac), [(0xffff_0000, 0x1234_0000)]);
    }

    #[test]
    fn common_and_false_blocks() {
        let f = Block::constant(false);
        let a = Block::word(0, 0xff00_0000, 0x1200_0000);
        assert!(f.common(&a).always_true());
        assert!(f.common(&f).always_false());
        let b = Block::word(0, 0xff00_0000, 0x1300_0000);
        assert_eq!(words(&a.common(&b)), [(0xfe00_0000, 0x1200_0000)]);
    }

    #[test]
    fn specializes_and_identical() {
        let a = Block::word(0, 0xff00_0000, 0x1200_0000);
        let b = Block::word(0, 0xf000_0000, 0x1000_0000);
        assert!(a.specializes(&b));
        assert!(!b.specializes(&a));
        assert!(a.specializes(&Block::constant(true)));
        assert!(a.identical(&a.clone()));
        assert!(!a.identical(&b));
    }

    #[test]
    fn masks_outside_the_words_are_zero() {
        let a = Block::word(2, 0xff00_0000, 0x1200_0000);
        assert_eq!(a.mask(0, 8), 0);
        assert_eq!(a.mask(16, 8), 0xff);
        assert_eq!(a.value(12, 8), 0x01);
        assert_eq!(a.mask(-8, 32), 0x0000_00ff);
        assert_eq!(a.value(-100, 8), 0);
    }

    #[test]
    fn shift_moves_the_offset() {
        let mut a = Block::word(0, 0xff00_0000, 0x1200_0000);
        a.shift(3);
        assert_eq!((a.offset, a.nonzero), (3, 1));
    }
}
