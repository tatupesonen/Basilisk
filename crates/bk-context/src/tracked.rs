//! Tracked register values (`<tracked_set>`; Ghidra `TrackedContext`).

use bk_core::SpaceId;

/// A register the decompiler assumes holds a value on entry to code in a
/// range. It does not affect decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrackedValue {
    /// The register's space.
    pub space: SpaceId,
    /// The register's offset.
    pub offset: u64,
    /// The register's size in bytes.
    pub size: u32,
    /// Whether the space is big endian (decides which bytes a contained
    /// register takes).
    pub big_endian: bool,
    /// The value.
    pub value: u64,
}

impl TrackedValue {
    /// The value of the `size` bytes at (`space`, `offset`) if this register
    /// contains them (Ghidra `ContextDatabase::getTrackedValue`, one entry).
    pub fn extract(&self, space: SpaceId, offset: u64, size: u32) -> Option<u64> {
        if self.space != space || self.offset > offset {
            return None;
        }
        let end = offset.wrapping_add(u64::from(size)).wrapping_sub(1);
        let tracked_end = self
            .offset
            .wrapping_add(u64::from(self.size))
            .wrapping_sub(1);
        if tracked_end < end {
            return None;
        }
        let mut value = self.value;
        if self.big_endian {
            if end != tracked_end {
                value = shift_right(value, tracked_end.wrapping_sub(offset));
            }
        } else if offset != self.offset {
            value = shift_right(value, offset.wrapping_sub(self.offset));
        }
        Some(value & calc_mask(size))
    }
}

/// `value >> (8 * bytes)`, with Ghidra's x86-64 behaviour for counts of 64
/// bits or more (the count taken modulo 64; ADR-021).
fn shift_right(value: u64, bytes: u64) -> u64 {
    value.wrapping_shr(bytes.wrapping_mul(8) as u32)
}

/// Ghidra `calc_mask`: all ones for sizes of 8 bytes or more.
fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)).wrapping_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(big_endian: bool) -> TrackedValue {
        TrackedValue {
            space: SpaceId::new(4),
            offset: 0x10,
            size: 4,
            big_endian,
            value: 0x1122_3344,
        }
    }

    #[test]
    fn contained_registers_take_bytes_by_endianness() {
        let space = SpaceId::new(4);
        assert_eq!(reg(false).extract(space, 0x10, 4), Some(0x1122_3344));
        assert_eq!(reg(false).extract(space, 0x10, 1), Some(0x44));
        assert_eq!(reg(false).extract(space, 0x12, 2), Some(0x1122));
        assert_eq!(reg(true).extract(space, 0x10, 1), Some(0x11));
        assert_eq!(reg(true).extract(space, 0x12, 2), Some(0x3344));
        assert_eq!(reg(true).extract(space, 0x13, 1), Some(0x44));
        assert_eq!(reg(true).extract(space, 0x12, 4), None);
        assert_eq!(reg(true).extract(space, 0x0f, 1), None);
        assert_eq!(reg(true).extract(SpaceId::new(3), 0x10, 1), None);
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(9), u64::MAX);
    }
}
