//! Join records in the manager (Ghidra `AddrSpaceManager::findAddJoin`,
//! `findJoin`, `joinPieces`, `constructJoinAddress` and relatives, and
//! `JoinRecord::mergeSequence`).
//!
//! Join offsets are handed out in creation order, so two managers that create
//! the same joins in a different order give them different addresses.

use std::sync::{Arc, PoisonError, RwLockReadGuard, RwLockWriteGuard};

use super::SpaceManager;
use crate::address::Address;
use crate::error::SpaceError;
use crate::join::{JoinRecord, JoinTable};
use crate::space::{CONSTANT_SPACE, SpaceType};
use crate::varnode::VarnodeData;

impl SpaceManager {
    fn joins_read(&self) -> RwLockReadGuard<'_, JoinTable> {
        self.joins.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn joins_write(&self) -> RwLockWriteGuard<'_, JoinTable> {
        self.joins.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The join record for the given pieces, most significant first, creating
    /// it if it does not exist (Ghidra `findAddJoin`).
    ///
    /// `logical_size` is 0 except for a single piece that stands for a larger
    /// value (a float extension), where it gives that value's size. A single
    /// piece in the constant space is pure padding and needs no logical size.
    pub fn find_add_join(
        &self,
        pieces: Vec<VarnodeData>,
        logical_size: u32,
    ) -> Result<Arc<JoinRecord>, SpaceError> {
        let total = match pieces.as_slice() {
            [] => return Err(SpaceError::JoinWithoutPieces),
            [piece] if logical_size == 0 && piece.space() != Some(CONSTANT_SPACE) => {
                return Err(SpaceError::JoinWithoutLogicalSize);
            }
            [_] if logical_size != 0 => logical_size,
            _ if logical_size != 0 => return Err(SpaceError::JoinLogicalSizeWithPieces),
            _ => pieces
                .iter()
                .fold(0u32, |sum, piece| sum.wrapping_add(piece.size)),
        };
        if total == 0 {
            return Err(SpaceError::ZeroSizeJoin);
        }
        let join = self.join.ok_or(SpaceError::NoJoinSpace)?;
        let probe = JoinRecord::new(pieces, VarnodeData::new(join, 0, total));
        if let Some(found) = self.joins_read().by_pieces.get(&probe) {
            return Ok(Arc::clone(found));
        }
        let mut table = self.joins_write();
        if let Some(found) = table.by_pieces.get(&probe) {
            return Ok(Arc::clone(found));
        }
        // Each record takes the next multiple of 16 bytes in the join space.
        let rounded = total.wrapping_add(15) & !0xf;
        let offset = table.next_offset;
        table.next_offset = offset.wrapping_add(u64::from(rounded));
        let record = Arc::new(JoinRecord::new(
            probe.into_pieces(),
            VarnodeData::new(join, offset, total),
        ));
        table.by_pieces.insert(Arc::clone(&record));
        table.by_offset.push(Arc::clone(&record));
        Ok(record)
    }

    /// The join record whose unified address is at `offset` in the join space
    /// (Ghidra `findJoin`).
    pub fn find_join(&self, offset: u64) -> Result<Arc<JoinRecord>, SpaceError> {
        self.joins_read()
            .at(offset)
            .map(Arc::clone)
            .ok_or(SpaceError::UnlinkedJoin)
    }

    /// The join record whose unified range contains `offset` (Ghidra
    /// `findJoinInternal`).
    pub fn find_join_covering(&self, offset: u64) -> Option<Arc<JoinRecord>> {
        self.joins_read().covering(offset).map(Arc::clone)
    }

    /// Every join record, in creation order.
    pub fn join_records(&self) -> Vec<Arc<JoinRecord>> {
        self.joins_read().by_offset.clone()
    }

    /// The records that are pure padding, in the order Ghidra's
    /// `beginJoinPadding` iterates them.
    pub fn padding_join_records(&self) -> Vec<Arc<JoinRecord>> {
        self.joins_read()
            .by_pieces
            .iter()
            .filter(|record| record.is_pure_padding())
            .map(Arc::clone)
            .collect()
    }

    /// The address standing for the given pieces, most significant first:
    /// contiguous pieces are merged first, and if one piece remains its own
    /// address is returned, otherwise a join address (Ghidra `joinPieces`).
    pub fn join_pieces(&self, mut pieces: Vec<VarnodeData>) -> Result<Address, SpaceError> {
        self.merge_join_sequence(&mut pieces);
        if let [piece] = pieces.as_slice() {
            return Ok(piece.addr());
        }
        Ok(self.find_add_join(pieces, 0)?.unified().addr())
    }

    /// Merges adjacent pieces of a sequence, most significant first, where
    /// they are contiguous in memory (Ghidra `JoinRecord::mergeSequence`).
    /// If a merge produces a location in a processor space that is not
    /// exactly a register, the sequence is left as it was.
    pub fn merge_join_sequence(&self, sequence: &mut Vec<VarnodeData>) {
        let mergeable = |hi: &VarnodeData, lo: &VarnodeData| {
            hi.space() != Some(CONSTANT_SPACE) && hi.is_contiguous(self, lo)
        };
        if !sequence
            .windows(2)
            .any(|pair| matches!(pair, [hi, lo] if mergeable(hi, lo)))
        {
            return;
        }
        let Some((&first, rest)) = sequence.split_first() else {
            return;
        };
        let mut merged = vec![first];
        let mut last_is_informal = false;
        for &lo in rest {
            let Some(hi) = merged.last_mut() else {
                return;
            };
            if mergeable(hi, &lo) {
                if !hi.addr().is_big_endian(self) {
                    hi.offset = lo.offset;
                }
                hi.size = hi.size.wrapping_add(lo.size);
                let spacebase = hi
                    .space()
                    .and_then(|space| self.space(space))
                    .is_some_and(|space| space.space_type() == SpaceType::Spacebase);
                if !spacebase && let Some(space) = hi.space() {
                    last_is_informal = self
                        .registers
                        .exact_register_name(space, hi.offset, hi.size)
                        .is_none();
                }
            } else {
                if last_is_informal {
                    break;
                }
                merged.push(lo);
            }
        }
        if !last_is_informal {
            *sequence = merged;
        }
    }

    /// The address of a floating-point value of `logical_size` bytes stored
    /// in `real_size` bytes at `real`: `real` itself if the sizes agree,
    /// otherwise a one-piece join (Ghidra `constructFloatExtensionAddress`).
    pub fn construct_float_extension_address(
        &self,
        real: Address,
        real_size: u32,
        logical_size: u32,
    ) -> Result<Address, SpaceError> {
        if logical_size == real_size {
            return Ok(real);
        }
        let piece = VarnodeData::from_address(real, real_size);
        Ok(self
            .find_add_join(vec![piece], logical_size)?
            .unified()
            .addr())
    }

    /// The address of a value whose most significant `hi_size` bytes are at
    /// `hi` and least significant `lo_size` bytes at `lo` (Ghidra
    /// `constructJoinAddress`).
    pub fn construct_join_address(
        &self,
        hi: Address,
        hi_size: u32,
        lo: Address,
        lo_size: u32,
    ) -> Result<Address, SpaceError> {
        self.join_pieces(vec![
            VarnodeData::from_address(hi, hi_size),
            VarnodeData::from_address(lo, lo_size),
        ])
    }

    /// The address of `size` bytes at `address`, as a join of the end and the
    /// start of the space when they run past its end (Ghidra
    /// `constructWrappingAddress`). Spaces that are not heritaged ignore the
    /// size.
    pub fn construct_wrapping_address(
        &self,
        address: Address,
        size: u32,
    ) -> Result<Address, SpaceError> {
        let space = self.space_of(address).ok_or(SpaceError::InvalidAddress)?;
        if !space.is_heritaged() {
            return Ok(address);
        }
        let dist = space
            .highest()
            .wrapping_sub(address.offset())
            .wrapping_add(1);
        if u64::from(size) <= dist {
            return Ok(address);
        }
        if !space.allows_wrapped_range() {
            return Err(SpaceError::RangeBeyondSpace(space.name().to_owned()));
        }
        let size_hi = dist as u32;
        let size_lo = size.wrapping_sub(size_hi);
        let hi = VarnodeData::new(space.id(), address.offset(), size_hi);
        let lo = VarnodeData::new(space.id(), 0, size_lo);
        let pieces = if space.is_big_endian() {
            vec![hi, lo]
        } else {
            vec![lo, hi]
        };
        Ok(self.find_add_join(pieces, 0)?.unified().addr())
    }

    /// The address that describes exactly the `size` bytes at a join
    /// address, which may be part of a larger join: one piece's own address
    /// if the bytes fall in one piece, otherwise a join of the parts of the
    /// pieces they cover (Ghidra `renormalizeJoinAddress`).
    pub fn renormalize_join_address(
        &self,
        address: Address,
        size: u32,
    ) -> Result<Address, SpaceError> {
        let record = self
            .find_join_covering(address.offset())
            .ok_or(SpaceError::JoinNotCovered)?;
        let unified = record.unified();
        if address.offset() == unified.offset && size == unified.size {
            return Ok(address);
        }
        let last = address
            .offset()
            .wrapping_add(u64::from(size).wrapping_sub(1));
        let (Some((addr1, pos1, trunc1)), Some((_, pos2, trunc2))) = (
            record.equivalent_address(self, address.offset()),
            record.equivalent_address(self, last),
        ) else {
            return Err(SpaceError::JoinRangeNotCovered);
        };
        if pos1 == pos2 && !addr1.is_constant() {
            return Ok(addr1);
        }
        let piece2_size = record.piece(pos2).map_or(0, |piece| piece.size);
        let trunc2 = piece2_size.wrapping_sub(trunc2).wrapping_sub(1);
        let (low, high) = if pos2 < pos1 {
            (pos2, pos1)
        } else {
            (pos1, pos2)
        };
        let mut pieces = record
            .pieces()
            .get(low..=high)
            .ok_or(SpaceError::JoinRangeNotCovered)?
            .to_vec();
        // The piece holding the first byte starts at it; the piece holding the
        // last byte ends at it. Which end of the list each is depends on the
        // walking order (little endian when pos2 < pos1).
        let (first_piece, last_piece) = if pos2 < pos1 {
            (pieces.len().saturating_sub(1), 0)
        } else {
            (0, pieces.len().saturating_sub(1))
        };
        if let Some(piece) = pieces.get_mut(first_piece) {
            piece.offset = addr1.offset();
            piece.size = piece.size.wrapping_sub(trunc1);
        }
        if let Some(piece) = pieces.get_mut(last_piece) {
            piece.size = piece.size.wrapping_sub(trunc2);
        }
        Ok(self.find_add_join(pieces, 0)?.unified().addr())
    }

    /// The location that remains when the first or last piece is removed
    /// from a join: the one remaining piece, or a join of the rest (Ghidra
    /// `stripJoinPiece`).
    pub fn strip_join_piece(
        &self,
        record: &JoinRecord,
        index: usize,
    ) -> Result<VarnodeData, SpaceError> {
        let count = record.num_pieces();
        let last = count.wrapping_sub(1);
        let (start, end) = if index == 0 {
            (1, last)
        } else if index == last {
            (0, count.wrapping_sub(2))
        } else {
            return Err(SpaceError::StripMiddlePiece);
        };
        if start == end
            && let Some(piece) = record.piece(start)
        {
            return Ok(*piece);
        }
        let pieces = if start <= end {
            record
                .pieces()
                .get(start..=end)
                .unwrap_or_default()
                .to_vec()
        } else {
            Vec::new()
        };
        Ok(*self.find_add_join(pieces, 0)?.unified())
    }

    /// How the byte `skip` bytes after `point` falls in the `size` bytes at
    /// `range`: its distance from the start of the range, or `None` (Ghidra
    /// `AddrSpace::overlapJoin` and its `JoinSpace` and `ConstantSpace`
    /// overrides). For a join range the byte may also lie in one of the
    /// join's pieces.
    pub(crate) fn overlap_join(
        &self,
        range: Address,
        size: u32,
        point: Address,
        skip: i32,
    ) -> Option<u32> {
        let space = self.space_of(range)?;
        let skip = i64::from(skip).cast_unsigned();
        match space.space_type() {
            SpaceType::Constant => None,
            SpaceType::Join => self.overlap_join_space(range, size, point, skip),
            _ => {
                if range.space() != point.space() {
                    return None;
                }
                let point_offset = point.offset().wrapping_add(skip);
                let dist = space.wrap_offset(point_offset.wrapping_sub(range.offset()));
                (dist < u64::from(size)).then_some(dist as u32)
            }
        }
    }

    fn overlap_join_space(
        &self,
        range: Address,
        size: u32,
        point: Address,
        skip: u64,
    ) -> Option<u32> {
        let point_space = self.space_of(point)?;
        let point_offset = point_space.wrap_offset(point.offset().wrapping_add(skip));
        if range.space() == point.space() {
            let diff = point_offset.checked_sub(range.offset())?;
            return (diff < u64::from(size)).then_some(diff as u32);
        }
        if point_space.space_type() == SpaceType::Constant {
            return None;
        }
        let record = self.find_join(range.offset()).ok()?;
        let join_big_endian = self
            .space_of(range)
            .is_some_and(crate::Space::is_big_endian);
        let mut accumulated: u64 = 0;
        let mut visit = |piece: &VarnodeData| -> Option<Option<u32>> {
            let last = piece
                .offset
                .wrapping_add(u64::from(piece.size).wrapping_sub(1));
            if piece.space() == point.space()
                && point_offset >= piece.offset
                && point_offset <= last
            {
                let result = (point_offset - piece.offset).wrapping_add(accumulated);
                return Some((result < u64::from(size)).then_some(result as u32));
            }
            accumulated = accumulated.wrapping_add(u64::from(piece.size));
            None
        };
        if join_big_endian {
            record.pieces().iter().find_map(&mut visit).flatten()
        } else {
            record.pieces().iter().rev().find_map(&mut visit).flatten()
        }
    }
}
