//! Join records: the pieces behind an address in the join space (Ghidra
//! `JoinRecord` in `translate.hh`/`translate.cc`).
//!
//! A variable split across several storage locations (a 64-bit value in two
//! 32-bit registers, say) is given one address in the join space. The record
//! holds the pieces, most significant first, and the unified location in the
//! join space. Records live in the [`SpaceManager`],
//! which creates them on demand.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::address::Address;
use crate::manager::SpaceManager;
use crate::space::CONSTANT_SPACE;
use crate::varnode::VarnodeData;

/// The physical pieces of a variable and its address in the join space
/// (Ghidra `JoinRecord`).
#[derive(Clone, Debug)]
pub struct JoinRecord {
    pieces: Vec<VarnodeData>,
    unified: VarnodeData,
}

impl JoinRecord {
    pub(crate) const fn new(pieces: Vec<VarnodeData>, unified: VarnodeData) -> Self {
        Self { pieces, unified }
    }

    pub(crate) fn into_pieces(self) -> Vec<VarnodeData> {
        self.pieces
    }

    /// The pieces, most significant first.
    pub fn pieces(&self) -> &[VarnodeData] {
        &self.pieces
    }

    /// The number of pieces.
    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    /// The `index`-th piece, most significant first.
    pub fn piece(&self, index: usize) -> Option<&VarnodeData> {
        self.pieces.get(index)
    }

    /// The whole variable as one location in the join space.
    pub const fn unified(&self) -> &VarnodeData {
        &self.unified
    }

    fn single_piece(&self) -> Option<&VarnodeData> {
        match self.pieces.as_slice() {
            [piece] => Some(piece),
            _ => None,
        }
    }

    /// Whether the record extends a floating-point value to a larger logical
    /// size: one piece that is not padding (Ghidra `isFloatExtension`).
    pub fn is_float_extension(&self) -> bool {
        self.single_piece()
            .is_some_and(|piece| piece.space() != Some(CONSTANT_SPACE))
    }

    /// Whether the record is only padding: one piece in the constant space
    /// (Ghidra `isPurePadding`).
    pub fn is_pure_padding(&self) -> bool {
        self.single_piece()
            .is_some_and(|piece| piece.space() == Some(CONSTANT_SPACE))
    }

    /// For an `offset` in the join space, the byte it stands for: its
    /// address, the index of the piece holding it, and its distance from the
    /// start of that piece (Ghidra `getEquivalentAddress`, whose `pos` and
    /// `trunc` are the second and third values). Join offsets run through the
    /// pieces in memory order: most significant piece first in a big-endian
    /// space, least significant first otherwise. `None` when the offset is
    /// outside the record. A padding piece gives offset 0 in the constant
    /// space.
    pub fn equivalent_address(
        &self,
        manager: &SpaceManager,
        offset: u64,
    ) -> Option<(Address, usize, u32)> {
        let mut small = offset.checked_sub(self.unified.offset)?;
        let big_endian = self
            .pieces
            .first()
            .is_some_and(|piece| piece.addr().is_big_endian(manager));
        let mut found = None;
        let mut visit = |index: usize, piece: &VarnodeData| {
            let size = u64::from(piece.size);
            if small < size {
                found = Some(index);
                true
            } else {
                small -= size;
                false
            }
        };
        if big_endian {
            self.pieces
                .iter()
                .enumerate()
                .any(|(index, piece)| visit(index, piece));
        } else {
            self.pieces
                .iter()
                .enumerate()
                .rev()
                .any(|(index, piece)| visit(index, piece));
        }
        let index = found?;
        let piece = self.pieces.get(index)?;
        let space = piece.space()?;
        let address = if space == CONSTANT_SPACE {
            Address::new(space, 0)
        } else {
            Address::new(space, piece.offset.wrapping_add(small))
        };
        Some((address, index, small as u32))
    }
}

/// Records compare by number of pieces, then the pieces in order, then the
/// unified size (Ghidra `JoinRecord::operator<`). The unified offset takes no
/// part: it is assigned when the record is created.
impl Ord for JoinRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pieces
            .len()
            .cmp(&other.pieces.len())
            .then_with(|| self.pieces.cmp(&other.pieces))
            .then(self.unified.size.cmp(&other.unified.size))
    }
}

impl PartialOrd for JoinRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for JoinRecord {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for JoinRecord {}

/// The join records of a manager (Ghidra's `splitset`, `splitlist` and
/// `joinallocate`).
#[derive(Debug, Default)]
pub(crate) struct JoinTable {
    /// Records in creation order, which is also unified-offset order.
    pub(crate) by_offset: Vec<Arc<JoinRecord>>,
    /// The same records ordered for lookup by pieces.
    pub(crate) by_pieces: BTreeSet<Arc<JoinRecord>>,
    /// The next offset to allocate in the join space.
    pub(crate) next_offset: u64,
}

impl JoinTable {
    /// The record whose unified offset is exactly `offset` (Ghidra
    /// `findJoin`).
    pub(crate) fn at(&self, offset: u64) -> Option<&Arc<JoinRecord>> {
        self.by_offset
            .binary_search_by_key(&offset, |record| record.unified.offset)
            .ok()
            .and_then(|index| self.by_offset.get(index))
    }

    /// The record whose unified range contains `offset` (Ghidra
    /// `findJoinInternal`).
    pub(crate) fn covering(&self, offset: u64) -> Option<&Arc<JoinRecord>> {
        let after = self
            .by_offset
            .partition_point(|record| record.unified.offset <= offset);
        let record = self.by_offset.get(after.checked_sub(1)?)?;
        let end = record
            .unified
            .offset
            .wrapping_add(u64::from(record.unified.size));
        (offset < end).then_some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bk_marshal::SpaceId;

    fn record(pieces: &[(u32, u64, u32)], offset: u64, size: u32) -> JoinRecord {
        JoinRecord::new(
            pieces
                .iter()
                .map(|&(space, offset, size)| VarnodeData::new(SpaceId::new(space), offset, size))
                .collect(),
            VarnodeData::new(SpaceId::new(9), offset, size),
        )
    }

    #[test]
    fn ordering_is_pieces_count_then_pieces_then_size() {
        let one = record(&[(2, 0, 4)], 0, 8);
        let one_bigger = record(&[(2, 0, 4)], 0x10, 16);
        let two = record(&[(2, 0, 4), (2, 4, 4)], 0x20, 8);
        let two_later = record(&[(2, 4, 4), (2, 0, 4)], 0x30, 8);
        assert!(one < one_bigger);
        assert!(one_bigger < two);
        assert!(two < two_later);
        // The unified offset takes no part.
        assert_eq!(one, record(&[(2, 0, 4)], 0x99, 8));
    }

    #[test]
    fn padding_and_float_extension() {
        assert!(record(&[(0, 0, 4)], 0, 4).is_pure_padding());
        assert!(!record(&[(0, 0, 4)], 0, 4).is_float_extension());
        assert!(record(&[(2, 0, 4)], 0, 10).is_float_extension());
        assert!(!record(&[(2, 0, 4), (2, 4, 4)], 0, 8).is_float_extension());
    }

    #[test]
    fn table_lookup_by_offset() {
        let mut table = JoinTable::default();
        for (offset, size) in [(0, 8), (16, 4), (32, 20)] {
            table
                .by_offset
                .push(Arc::new(record(&[(2, offset, size)], offset, size)));
        }
        assert!(table.at(16).is_some());
        assert!(table.at(17).is_none());
        assert_eq!(table.covering(19).map(|r| r.unified.offset), Some(16));
        assert!(table.covering(20).is_none());
        assert_eq!(table.covering(51).map(|r| r.unified.offset), Some(32));
        assert!(table.covering(52).is_none());
    }
}
