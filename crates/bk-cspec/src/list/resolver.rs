//! The map from storage offset to the entries covering it (Ghidra
//! `ParamEntryResolver`, a `rangemap<ParamEntryRange>`).
//!
//! Ghidra's `rangemap` partitions each space into disjoint sub-ranges at
//! every entry boundary and lists, per sub-range, the entries covering it in
//! the order they were added (their *position*). Entries never change after
//! decoding, so the partition is built once as sorted vectors and searched
//! by binary search.

use bk_core::VarnodeData;

use crate::entry::ParamEntry;

/// One disjoint sub-range and the entries covering it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Part {
    first: u64,
    last: u64,
    /// Range of `Resolver::members` holding the entries, in position order.
    start: u32,
    len: u32,
}

/// The partition of one space.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SpaceParts {
    parts: Vec<Part>,
}

/// Per-space interval maps from offset to entry index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resolver {
    /// Indexed by space index.
    spaces: Vec<Option<SpaceParts>>,
    /// Entry indices, grouped by part.
    members: Vec<u32>,
}

/// A cursor over the parts of one space: an index into its part list.
pub(crate) type PartIndex = usize;

impl Resolver {
    /// Builds the maps for a list of entries (Ghidra `populateResolver`).
    /// Join entries are mapped through each of their pieces that is not
    /// padding.
    pub(crate) fn build(entries: &[ParamEntry]) -> Self {
        // (space, first, last, position, entry)
        let mut ranges: Vec<(u32, u64, u64, u32, u32)> = Vec::new();
        let mut position = 0u32;
        for (index, entry) in entries.iter().enumerate() {
            let index = index as u32;
            if let Some(pieces) = entry.join_pieces() {
                for piece in pieces {
                    let Some(space) = piece.space() else { continue };
                    if space == bk_core::space::CONSTANT_SPACE {
                        continue;
                    }
                    ranges.push((space.index(), piece.offset, piece_last(piece), position, index));
                    position += 1;
                }
            } else {
                let last = entry
                    .base()
                    .wrapping_add(entry.size() as u64)
                    .wrapping_sub(1);
                ranges.push((entry.space().index(), entry.base(), last, position, index));
                position += 1;
            }
        }
        let mut res = Self::default();
        let max_space = ranges.iter().map(|r| r.0).max();
        let Some(max_space) = max_space else {
            return res;
        };
        res.spaces = vec![None; max_space as usize + 1];
        for space in 0..=max_space {
            let mine: Vec<_> = ranges.iter().filter(|r| r.0 == space).collect();
            if mine.is_empty() {
                continue;
            }
            let mut points: Vec<u64> = Vec::with_capacity(mine.len() * 2);
            for r in &mine {
                points.push(r.1);
                if let Some(after) = r.2.checked_add(1) {
                    points.push(after);
                }
            }
            points.sort_unstable();
            points.dedup();
            let mut parts = Vec::new();
            for (i, &first) in points.iter().enumerate() {
                let last = points.get(i + 1).map_or(u64::MAX, |n| n - 1);
                let mut covering: Vec<(u32, u32)> = mine
                    .iter()
                    .filter(|r| r.1 <= first && last <= r.2 && r.1 <= r.2)
                    .map(|r| (r.3, r.4))
                    .collect();
                if covering.is_empty() {
                    continue;
                }
                covering.sort_unstable();
                let start = res.members.len() as u32;
                res.members.extend(covering.iter().map(|c| c.1));
                parts.push(Part {
                    first,
                    last,
                    start,
                    len: covering.len() as u32,
                });
            }
            if let Some(slot) = res.spaces.get_mut(space as usize) {
                *slot = Some(SpaceParts { parts });
            }
        }
        res
    }

    fn parts(&self, space: u32) -> Option<&[Part]> {
        self.spaces
            .get(space as usize)
            .and_then(Option::as_ref)
            .map(|s| s.parts.as_slice())
    }

    /// Whether the space has any entry.
    pub(crate) fn has_space(&self, space: u32) -> bool {
        self.parts(space).is_some()
    }

    /// The entries of the part containing `point`, in position order, and
    /// the index of the first part after it (Ghidra `rangemap::find`). When
    /// no part contains the point the slice is empty and the index is the
    /// first part after the point.
    pub(crate) fn find(&self, space: u32, point: u64) -> (&[u32], PartIndex) {
        let Some(parts) = self.parts(space) else {
            return (&[], 0);
        };
        let i = parts.partition_point(|p| p.last < point);
        match parts.get(i) {
            Some(p) if p.first <= point => (self.members_of(p), i + 1),
            _ => (&[], i),
        }
    }

    /// The first part ending at or after `point` (Ghidra `find_begin`).
    pub(crate) fn find_begin(&self, space: u32, point: u64) -> PartIndex {
        self.parts(space)
            .map_or(0, |parts| parts.partition_point(|p| p.last < point))
    }

    /// The first part entirely after `point` (Ghidra `find_end`).
    pub(crate) fn find_end(&self, space: u32, point: u64) -> PartIndex {
        self.parts(space)
            .map_or(0, |parts| parts.partition_point(|p| p.first <= point))
    }

    /// The entries of the parts `from..to` of a space, part by part (an
    /// entry covering several parts appears once per part, as in Ghidra).
    pub(crate) fn walk(&self, space: u32, from: PartIndex, to: PartIndex) -> impl Iterator<Item = u32> + '_ {
        let parts = self.parts(space).unwrap_or(&[]);
        let to = to.min(parts.len());
        parts
            .get(from.min(to)..to)
            .unwrap_or(&[])
            .iter()
            .flat_map(|p| self.members_of(p).iter().copied())
    }

    /// Number of parts of a space.
    pub(crate) fn part_count(&self, space: u32) -> usize {
        self.parts(space).map_or(0, <[Part]>::len)
    }

    fn members_of(&self, p: &Part) -> &[u32] {
        let start = p.start as usize;
        self.members
            .get(start..start + p.len as usize)
            .unwrap_or(&[])
    }
}

fn piece_last(piece: &VarnodeData) -> u64 {
    piece
        .offset
        .wrapping_add(u64::from(piece.size))
        .wrapping_sub(1)
}
