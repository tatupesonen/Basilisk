//! Look-ups on the fragments of an [`EntryMap`] (Ghidra `rangemap::find`,
//! `find_begin`, `find_end`, `find_overlap`, `find_first_after`,
//! `find_last_before`; spec 4.2 "Look-ups").

use std::collections::btree_map;
use std::ops::Bound;

use super::{EntryMap, Line, Pos, RecordId, Subsort};

/// One fragment as a query sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<R, L, S> {
    /// First point of the piece.
    pub first: L,
    /// Last point of the piece.
    pub last: L,
    /// First point of the whole record.
    pub a: L,
    /// Last point of the whole record.
    pub b: L,
    /// The record's subsort.
    pub subsort: S,
    /// The record.
    pub record: RecordId,
    /// The record's value.
    pub value: R,
}

type Buckets<'m, L, S> = btree_map::Range<'m, (L, S), super::Bucket>;

impl<R: Copy, L: Line, S: Subsort> EntryMap<R, L, S> {
    fn view(&self, id: u32) -> Option<Fragment<R, L, S>> {
        let frag = self.frag(id)?;
        let record = self.records.get(frag.rec as usize)?;
        Some(Fragment {
            first: frag.first,
            last: frag.last,
            a: frag.a,
            b: frag.b,
            subsort: frag.sub,
            record: RecordId(frag.rec),
            value: record.value,
        })
    }

    /// The fragment at a position.
    pub fn fragment(&self, pos: Pos<L, S>) -> Option<Fragment<R, L, S>> {
        self.frag_id_at(pos).and_then(|id| self.view(id))
    }

    fn whole_buckets(
        &self,
        keys: Option<((L, S), (L, S))>,
    ) -> impl DoubleEndedIterator<Item = Fragment<R, L, S>> + '_ {
        let range: Option<Buckets<'_, L, S>> = keys
            .filter(|(lo, hi)| lo <= hi)
            .map(|(lo, hi)| self.tree.range(lo..=hi));
        range
            .into_iter()
            .flatten()
            .flat_map(|(_, bucket)| bucket.as_slice().iter())
            .filter_map(move |&id| self.view(id))
    }

    /// Every fragment in multiset order.
    pub fn fragments(&self) -> impl DoubleEndedIterator<Item = Fragment<R, L, S>> + '_ {
        self.tree
            .values()
            .flat_map(|bucket| bucket.as_slice().iter())
            .filter_map(move |&id| self.view(id))
    }

    /// The fragments of the piece containing `p`, in order (Ghidra
    /// `find(point)`); empty when no piece contains it.
    pub fn find(&self, p: L) -> impl DoubleEndedIterator<Item = Fragment<R, L, S>> + '_ {
        self.find_sub(p, S::EARLIEST, S::LATEST)
    }

    /// The fragments of the piece containing `p` with subsorts from `s1` to
    /// `s2` (Ghidra `find(point, sub1, sub2)`). As in Ghidra, `s1` only
    /// filters when `p` is the last point of its piece.
    pub fn find_sub(
        &self,
        p: L,
        s1: S,
        s2: S,
    ) -> impl DoubleEndedIterator<Item = Fragment<R, L, S>> + '_ {
        let keys = self
            .lower_bound((p, s1))
            .and_then(|pos| self.frag_at(pos).map(|frag| (pos, frag)))
            .filter(|(_, frag)| frag.first <= p)
            .map(|(pos, frag)| (pos.key, (frag.last, s2)));
        self.whole_buckets(keys)
    }

    /// The first fragment with key `>= (p, earliest)` (Ghidra `find_begin`).
    pub fn find_begin(&self, p: L) -> Option<Pos<L, S>> {
        self.lower_bound((p, S::EARLIEST))
    }

    /// The first fragment after the piece containing `p`, or after `p`
    /// (Ghidra `find_end`).
    pub fn find_end(&self, p: L) -> Option<Pos<L, S>> {
        let pos = self.upper_bound((p, S::LATEST))?;
        let frag = self.frag_at(pos)?;
        if p < frag.first {
            return Some(pos);
        }
        self.upper_bound((frag.last, S::LATEST))
    }

    /// The first fragment overlapping `[p, e]` (Ghidra `find_overlap`).
    pub fn find_overlap(&self, p: L, e: L) -> Option<Pos<L, S>> {
        let pos = self.lower_bound((p, S::EARLIEST))?;
        let frag = self.frag_at(pos)?;
        (frag.first <= e).then_some(pos)
    }

    /// The first fragment whose record starts after `p` (Ghidra
    /// `find_first_after`).
    pub fn find_first_after(&self, p: L) -> Option<Pos<L, S>> {
        let mut cur = self.find_end(p);
        while let Some(pos) = cur {
            if self.frag_at(pos).is_some_and(|frag| p < frag.a) {
                return Some(pos);
            }
            cur = self.next_pos(pos);
        }
        None
    }

    /// Walking back from [`find_begin`](Self::find_begin), the first
    /// fragment whose record ends before `p` (Ghidra `find_last_before`).
    pub fn find_last_before(&self, p: L) -> Option<Pos<L, S>> {
        let mut cur = match self.find_begin(p) {
            Some(pos) => self.prev_pos(pos),
            None => self.last_pos(),
        };
        while let Some(pos) = cur {
            if self.frag_at(pos).is_some_and(|frag| frag.b < p) {
                return Some(pos);
            }
            cur = self.prev_pos(pos);
        }
        None
    }

    /// The fragments from `pos` (included) to the end.
    pub fn iter_from(&self, pos: Pos<L, S>) -> impl Iterator<Item = Fragment<R, L, S>> + '_ {
        let here = self.tree.get(&pos.key).map_or(&[][..], |bucket| {
            bucket.as_slice().get(pos.idx..).unwrap_or(&[])
        });
        let rest = self
            .tree
            .range((Bound::Excluded(pos.key), Bound::Unbounded))
            .flat_map(|(_, bucket)| bucket.as_slice().iter());
        here.iter().chain(rest).filter_map(move |&id| self.view(id))
    }

    /// The fragments from `pos` (included) back to the first.
    pub fn iter_back_from(&self, pos: Pos<L, S>) -> impl Iterator<Item = Fragment<R, L, S>> + '_ {
        let here = self.tree.get(&pos.key).map_or(&[][..], |bucket| {
            let slice = bucket.as_slice();
            slice.get(..=pos.idx).unwrap_or(slice)
        });
        let rest = self
            .tree
            .range(..pos.key)
            .rev()
            .flat_map(|(_, bucket)| bucket.as_slice().iter().rev());
        here.iter()
            .rev()
            .chain(rest)
            .filter_map(move |&id| self.view(id))
    }
}
