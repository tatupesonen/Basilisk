//! A sorted set of ranges (Ghidra `RangeList` in `address.hh`/`address.cc`).

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;

use bk_marshal::{Decoder, Encoder, SpaceId};

use crate::address::Address;
use crate::error::SpaceError;
use crate::ids::ELEM_RANGELIST;
use crate::manager::SpaceManager;
use crate::range::Range;
use crate::space::Space;

/// The key of a range in the list: its space and first offset, which is how
/// Ghidra's `set<Range>` orders and identifies ranges.
type Key = (SpaceId, u64);

/// A set of disjoint ranges, kept sorted by space index and first offset
/// (Ghidra `RangeList`).
///
/// Inserting a range merges it with the ranges it overlaps. As in Ghidra,
/// ranges that merely touch are not merged, and [`RangeList::decode`] inserts
/// ranges without merging them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeList {
    /// First offset → last offset, by space.
    tree: BTreeMap<Key, u64>,
}

fn range_of(key: Key, last: u64) -> Range {
    Range::new(key.0, key.1, last)
}

impl RangeList {
    /// An empty list.
    pub const fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
        }
    }

    /// Removes every range.
    pub fn clear(&mut self) {
        self.tree.clear();
    }

    /// Whether the list has no ranges.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// The number of ranges (Ghidra `numRanges`).
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// The ranges in order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Range> + '_ {
        self.tree.iter().map(|(&key, &last)| range_of(key, last))
    }

    /// The first range (Ghidra `getFirstRange`).
    pub fn first_range(&self) -> Option<Range> {
        self.iter().next()
    }

    /// The last range (Ghidra `getLastRange`).
    pub fn last_range(&self) -> Option<Range> {
        self.iter().next_back()
    }

    /// The last range in `key`'s position or before it: Ghidra's
    /// `--upper_bound(Range(space, offset, offset))`.
    fn at_or_before(&self, key: Key) -> Option<Range> {
        self.tree
            .range(..=key)
            .next_back()
            .map(|(&key, &last)| range_of(key, last))
    }

    /// The keys from `start` up to and including `end`, collected so the
    /// tree can be changed while visiting them. Empty when `end` comes
    /// before `start`, where `BTreeMap::range` would panic.
    fn keys_between(&self, start: Bound<Key>, end: Key) -> Vec<(Key, u64)> {
        let empty = match start {
            Bound::Included(start) => start > end,
            Bound::Excluded(start) => start >= end,
            Bound::Unbounded => false,
        };
        if empty {
            return Vec::new();
        }
        self.tree
            .range((start, Bound::Included(end)))
            .map(|(&key, &last)| (key, last))
            .collect()
    }

    /// The ranges that [`RangeList::insert_range`] and
    /// [`RangeList::remove_range`] must visit for `first..=last`: those from
    /// the one containing `first` (if any) to the last starting at or before
    /// `last`.
    fn affected(&self, space: SpaceId, first: u64, last: u64) -> Vec<(Key, u64)> {
        let start = match self.at_or_before((space, first)) {
            Some(before) if before.space() == space && before.last() >= first => {
                Bound::Included((space, before.first()))
            }
            _ => Bound::Excluded((space, first)),
        };
        self.keys_between(start, (space, last))
    }

    /// Adds the bytes `first..=last` of `space`, merging the ranges they
    /// overlap into one (Ghidra `insertRange`).
    pub fn insert_range(&mut self, space: SpaceId, mut first: u64, mut last: u64) {
        for (key, old_last) in self.affected(space, first, last) {
            first = first.min(key.1);
            last = last.max(old_last);
            self.tree.remove(&key);
        }
        self.tree.entry((space, first)).or_insert(last);
    }

    /// Adds a range (Ghidra `insertRange(const Range &)`).
    pub fn insert(&mut self, range: Range) {
        self.insert_range(range.space(), range.first(), range.last());
    }

    /// Removes the bytes `first..=last` of `space`, splitting ranges that
    /// extend past either end (Ghidra `removeRange`).
    pub fn remove_range(&mut self, space: SpaceId, first: u64, last: u64) {
        for (key, old_last) in self.affected(space, first, last) {
            self.tree.remove(&key);
            if key.1 < first {
                self.tree.entry(key).or_insert(first - 1);
            }
            if old_last > last {
                self.tree.entry((space, last + 1)).or_insert(old_last);
            }
        }
    }

    /// Removes a range (Ghidra `removeRange(const Range &)`).
    pub fn remove(&mut self, range: Range) {
        self.remove_range(range.space(), range.first(), range.last());
    }

    /// Adds every range of `other` (Ghidra `merge`).
    pub fn merge(&mut self, other: &Self) {
        for range in other.iter() {
            self.insert(range);
        }
    }

    /// Whether the `size` bytes at `address` lie within one range of the
    /// list (Ghidra `inRange(Address, size)`). The invalid address is in
    /// range; a size that runs past the end of the offsets is not.
    pub fn in_range(&self, address: Address, size: u64) -> bool {
        let Some(space) = address.space() else {
            return address.is_invalid();
        };
        let Some(range) = self.at_or_before((space, address.offset())) else {
            return false;
        };
        if range.space() != space {
            return false;
        }
        let end = address.offset().wrapping_add(size).wrapping_sub(1);
        end >= address.offset() && range.last() >= end
    }

    /// Whether `range` lies within one range of the list (Ghidra
    /// `inRange(const Range &)`).
    pub fn contains_range(&self, range: &Range) -> bool {
        self.at_or_before((range.space(), range.first()))
            .is_some_and(|found| found.space() == range.space() && found.last() >= range.last())
    }

    /// The range containing the given byte (Ghidra `getRange`).
    pub fn get_range(&self, space: SpaceId, offset: u64) -> Option<Range> {
        self.at_or_before((space, offset))
            .filter(|range| range.space() == space && range.last() >= offset)
    }

    /// The range containing the given byte or, failing that, the closest
    /// range in the same space, preferring the earlier one at equal distance
    /// (Ghidra `getNearestRange`).
    pub fn nearest_range(&self, space: SpaceId, offset: u64) -> Option<Range> {
        let after = self
            .tree
            .range((Bound::Excluded((space, offset)), Bound::Unbounded))
            .next()
            .map(|(&key, &last)| range_of(key, last))
            .filter(|range| range.space() == space);
        let Some(before) = self
            .at_or_before((space, offset))
            .filter(|range| range.space() == space)
        else {
            return after;
        };
        let Some(after) = after else {
            return Some(before);
        };
        if before.last() >= offset {
            return Some(before);
        }
        let dist_after = after.first().wrapping_sub(offset);
        let dist_before = offset.wrapping_sub(before.last());
        Some(if dist_after < dist_before {
            after
        } else {
            before
        })
    }

    /// The number of bytes from `address` that are covered, following ranges
    /// that continue exactly where the previous one ends, stopping once the
    /// count reaches `max_size` (Ghidra `longestFit`).
    pub fn longest_fit(&self, address: Address, max_size: u64) -> u64 {
        let Some(space) = address.space() else {
            return 0;
        };
        let mut offset = address.offset();
        let Some(start) = self.at_or_before((space, offset)) else {
            return 0;
        };
        if start.last() < offset {
            return 0;
        }
        let mut size: u64 = 0;
        for (&(range_space, first), &last) in self.tree.range((start.space(), start.first())..) {
            if range_space != space || first > offset {
                break;
            }
            size = size.wrapping_add(last.wrapping_add(1).wrapping_sub(offset));
            offset = last.wrapping_add(1);
            if size >= max_size {
                break;
            }
        }
        size
    }

    /// The last range of `space` when offsets are read as signed: the range
    /// containing the largest non-negative offset, or failing that the last
    /// range of the space (Ghidra `getLastSignedRange`).
    pub fn last_signed_range(&self, space: &Space) -> Option<Range> {
        let id = space.id();
        let midway = space.highest() / 2;
        [midway, space.highest()].into_iter().find_map(|offset| {
            self.at_or_before((id, offset))
                .filter(|range| range.space() == id)
        })
    }

    /// A value that prints each range on its own line, or `all` for an empty
    /// list (Ghidra `printBounds`).
    pub fn bounds<'m>(&'m self, manager: &'m SpaceManager) -> RangeListBounds<'m> {
        RangeListBounds {
            manager,
            list: self,
        }
    }

    /// Writes the list as a `<rangelist>` element (Ghidra `encode`).
    pub fn encode<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        encoder.open_element(ELEM_RANGELIST);
        for range in self.iter() {
            range.encode(encoder, manager)?;
        }
        encoder.close_element(ELEM_RANGELIST);
        Ok(())
    }

    /// Reads a `<rangelist>` element and adds its ranges (Ghidra `decode`).
    /// As in Ghidra, the ranges are not merged, and a range starting where
    /// one already starts is dropped.
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(
        &mut self,
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        let element = decoder.open_element_expecting(ELEM_RANGELIST)?;
        while decoder.peek_element().is_some() {
            let range = Range::decode(decoder, manager)?;
            self.tree
                .entry((range.space(), range.first()))
                .or_insert_with(|| range.last());
        }
        decoder.close_element(element)?;
        Ok(())
    }
}

/// A range list printed as Ghidra's `printBounds` does; see
/// [`RangeList::bounds`].
#[derive(Debug)]
pub struct RangeListBounds<'m> {
    manager: &'m SpaceManager,
    list: &'m RangeList,
}

impl fmt::Display for RangeListBounds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.list.is_empty() {
            return writeln!(f, "all");
        }
        for range in self.list.iter() {
            writeln!(f, "{}", range.bounds(self.manager))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: SpaceId = SpaceId::new(3);
    const T: SpaceId = SpaceId::new(4);

    fn ranges(list: &RangeList) -> Vec<(u32, u64, u64)> {
        list.iter()
            .map(|r| (r.space().index(), r.first(), r.last()))
            .collect()
    }

    #[test]
    fn insert_merges_overlaps_but_not_neighbours() {
        let mut list = RangeList::new();
        list.insert_range(S, 0x10, 0x1f);
        list.insert_range(S, 0x20, 0x2f);
        assert_eq!(ranges(&list), [(3, 0x10, 0x1f), (3, 0x20, 0x2f)]);
        list.insert_range(S, 0x18, 0x22);
        assert_eq!(ranges(&list), [(3, 0x10, 0x2f)]);
        list.insert_range(T, 0, 5);
        list.insert_range(S, 0x40, 0x50);
        list.insert_range(S, 0x0, 0x100);
        assert_eq!(ranges(&list), [(3, 0, 0x100), (4, 0, 5)]);
        // Inside an existing range: nothing changes.
        list.insert_range(S, 0x20, 0x30);
        assert_eq!(ranges(&list), [(3, 0, 0x100), (4, 0, 5)]);
        // A reversed range neither panics nor removes anything.
        list.insert_range(T, 9, 7);
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn remove_splits() {
        let mut list = RangeList::new();
        list.insert_range(S, 0x10, 0x3f);
        list.remove_range(S, 0x20, 0x2f);
        assert_eq!(ranges(&list), [(3, 0x10, 0x1f), (3, 0x30, 0x3f)]);
        list.remove_range(S, 0x0, 0x18);
        assert_eq!(ranges(&list), [(3, 0x19, 0x1f), (3, 0x30, 0x3f)]);
        list.remove_range(S, 0x1f, 0x30);
        assert_eq!(ranges(&list), [(3, 0x19, 0x1e), (3, 0x31, 0x3f)]);
        list.remove_range(S, 0, u64::MAX - 1);
        assert!(list.is_empty());
        list.remove_range(S, 5, 1);
    }

    #[test]
    fn queries() {
        let mut list = RangeList::new();
        list.insert_range(S, 0x10, 0x1f);
        list.insert_range(S, 0x20, 0x2f);
        list.insert_range(S, 0x40, 0x4f);
        list.insert_range(T, 0x0, 0xff);
        assert!(list.in_range(Address::new(S, 0x10), 0x10));
        assert!(!list.in_range(Address::new(S, 0x10), 0x11));
        assert!(!list.in_range(Address::new(S, 0x10), 0));
        assert!(list.in_range(Address::INVALID, 4));
        assert!(!list.in_range(Address::new(SpaceId::new(2), 0), 1));
        assert!(list.contains_range(&Range::new(S, 0x41, 0x4f)));
        assert!(!list.contains_range(&Range::new(S, 0x3f, 0x40)));
        assert_eq!(list.get_range(S, 0x25), Some(Range::new(S, 0x20, 0x2f)));
        assert_eq!(list.get_range(S, 0x35), None);
        assert_eq!(list.nearest_range(S, 0x35), Some(Range::new(S, 0x20, 0x2f)));
        assert_eq!(list.nearest_range(S, 0x3a), Some(Range::new(S, 0x40, 0x4f)));
        assert_eq!(list.nearest_range(S, 0x5), Some(Range::new(S, 0x10, 0x1f)));
        assert_eq!(list.nearest_range(S, 0x90), Some(Range::new(S, 0x40, 0x4f)));
        assert_eq!(list.longest_fit(Address::new(S, 0x18), 100), 0x18);
        assert_eq!(list.longest_fit(Address::new(S, 0x18), 4), 8);
        assert_eq!(list.longest_fit(Address::new(S, 0x30), 100), 0);
        assert_eq!(list.first_range(), Some(Range::new(S, 0x10, 0x1f)));
        assert_eq!(list.last_range(), Some(Range::new(T, 0, 0xff)));
    }
}
