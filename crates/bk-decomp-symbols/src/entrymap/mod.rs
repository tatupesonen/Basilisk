//! The interval map behind every per-space entry map and the scope resolve
//! map (Ghidra `rangemap`, `CPP/rangemap.hh`; spec 4.2).
//!
//! An [`EntryMap`] stores *records*, each covering a closed interval
//! `[a, b]` of a linear domain, and keeps two structures:
//!
//! * the record list, in the order Ghidra's `std::list` has it (what
//!   `MapIterator` and `printEntries` walk);
//! * the *fragments*, a sorted multiset that partitions the union of the
//!   records' intervals into maximal pieces on which the set of covering
//!   records is constant. Fragments are ordered by `(last, subsort)` only;
//!   fragments with equal keys keep the order C++'s `multiset` gives them
//!   with the hints `rangemap` passes (spec 4.2, "Multiset insertion
//!   order"), because Ghidra's queries walk them in that order.
//!
//! Equal fragments live in one *bucket* per key, so the three outcomes of a
//! hinted C++ insertion become "insert at position k", "push front" and
//! "push back" of a bucket.
//!
//! Ghidra quirk reproduced: when a record ends exactly at the end of an
//! existing piece, `insert` breaks out of its walk after inserting the last
//! fragment and then inserts `[f, b]` once more, so that record has the
//! fragment twice (`rangemap.hh` `insert`, the `if (f <= b)` after the
//! loop). Every walk sees both copies, as in Ghidra.
//!
//! Ghidra defect reproduced: `erase` decides whether to merge the pieces at
//! `b | b + 1` from the first fragment after the erased record only, so a
//! record that starts at `b + 1` but is not first in that piece's order is
//! stretched left over addresses it does not cover. Queries then see it
//! there (as Ghidra's do). Ghidra defect defined: erasing such a stretched
//! record later walks from its own start and leaves the stretched
//! fragments pointing at the freed record (a use after free); Basilisk
//! removes them with the record.

mod bucket;
mod look;

use std::collections::BTreeMap;
use std::fmt;

use bucket::Bucket;
pub use look::Fragment;

/// The linear domain of an [`EntryMap`]: offsets (`u64`) or addresses.
///
/// `prev` and `next` are Ghidra's `linetype` arithmetic (`a - 1`, `b + 1`),
/// which wraps.
pub trait Line: Copy + Ord + fmt::Debug {
    /// The point before this one, wrapping.
    #[must_use]
    fn prev(self) -> Self;
    /// The point after this one, wrapping.
    #[must_use]
    fn next(self) -> Self;
}

impl Line for u64 {
    fn prev(self) -> Self {
        self.wrapping_sub(1)
    }
    fn next(self) -> Self {
        self.wrapping_add(1)
    }
}

/// How records that end at the same point are ordered (Ghidra's
/// `subsorttype`), with the bounds queries use.
pub trait Subsort: Copy + Ord + fmt::Debug {
    /// Before every real subsort (Ghidra `subsorttype(false)`).
    const EARLIEST: Self;
    /// After every real subsort (Ghidra `subsorttype(true)`).
    const LATEST: Self;
}

/// The subsort of a symbol entry (Ghidra `SymbolRange::EntrySubsort`): the
/// space index and offset of the first range of its use limit, or `(0, 0)`
/// for an address-tied symbol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntrySubsort {
    /// Index of the space of the use point.
    pub use_index: u32,
    /// Offset of the use point.
    pub use_offset: u64,
}

impl Subsort for EntrySubsort {
    const EARLIEST: Self = Self {
        use_index: 0,
        use_offset: 0,
    };
    // Ghidra sets the index to 0xffff and leaves the offset uninitialised;
    // no space has that index, so the offset is never compared. Any value
    // above every real index gives the same order.
    const LATEST: Self = Self {
        use_index: u32::MAX,
        use_offset: u64::MAX,
    };
}

/// The subsort of the scope resolve map (Ghidra `ScopeMapper::NullSubsort`):
/// every value compares equal.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullSubsort;

impl std::hash::Hash for NullSubsort {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}

impl PartialEq for NullSubsort {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for NullSubsort {}
impl PartialOrd for NullSubsort {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for NullSubsort {
    fn cmp(&self, _: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}
impl Subsort for NullSubsort {
    const EARLIEST: Self = Self;
    const LATEST: Self = Self;
}

/// A record handle, stable until the record is erased.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(u32);

impl RecordId {
    /// The raw slot index (for diagnostics).
    pub const fn index(self) -> u32 {
        self.0
    }
}

const NIL: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct Frag<L, S> {
    first: L,
    last: L,
    a: L,
    b: L,
    sub: S,
    rec: u32,
}

#[derive(Clone, Debug)]
struct Record<R, L, S> {
    value: R,
    a: L,
    b: L,
    sub: S,
    prev: u32,
    next: u32,
    live: bool,
    /// How many fragments name this record.
    frags: u32,
}

/// A position in the fragment multiset: a bucket key and an index in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pos<L, S> {
    key: (L, S),
    idx: usize,
}

/// Where a new fragment goes within the bucket of its key.
#[derive(Clone, Copy, Debug)]
enum Place {
    At(usize),
    Front,
    Back,
}

/// An interval map with Ghidra's `rangemap` behaviour; see the module
/// documentation.
#[derive(Clone, Debug)]
pub struct EntryMap<R, L, S> {
    frags: Vec<Frag<L, S>>,
    free_frags: Vec<u32>,
    tree: BTreeMap<(L, S), Bucket>,
    records: Vec<Record<R, L, S>>,
    free_records: Vec<u32>,
    head: u32,
    tail: u32,
    len: usize,
}

impl<R: Copy, L: Line, S: Subsort> Default for EntryMap<R, L, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Copy, L: Line, S: Subsort> EntryMap<R, L, S> {
    /// An empty map.
    pub fn new() -> Self {
        Self {
            frags: Vec::new(),
            free_frags: Vec::new(),
            tree: BTreeMap::new(),
            records: Vec::new(),
            free_records: Vec::new(),
            head: NIL,
            tail: NIL,
            len: 0,
        }
    }

    /// Whether the map holds no record (Ghidra `empty`).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The number of records.
    pub fn len(&self) -> usize {
        self.len
    }

    /// The number of fragments (duplicates counted).
    pub fn fragment_count(&self) -> usize {
        self.frags.len() - self.free_frags.len()
    }

    /// Removes every record (Ghidra `clear`).
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// The value of a live record.
    pub fn value(&self, rec: RecordId) -> Option<R> {
        self.live_record(rec.0).map(|r| r.value)
    }

    /// The interval `[a, b]` of a live record.
    pub fn bounds(&self, rec: RecordId) -> Option<(L, L)> {
        self.live_record(rec.0).map(|r| (r.a, r.b))
    }

    /// The subsort a live record was inserted with.
    pub fn subsort(&self, rec: RecordId) -> Option<S> {
        self.live_record(rec.0).map(|r| r.sub)
    }

    fn live_record(&self, index: u32) -> Option<&Record<R, L, S>> {
        self.records
            .get(index as usize)
            .filter(|record| record.live)
    }

    /// The records in list order (Ghidra `begin_list` to `end_list`).
    pub fn records(&self) -> Records<'_, R, L, S> {
        Records {
            map: self,
            cur: self.head,
            back: self.tail,
            remaining: self.len,
        }
    }

    // ----- multiset primitives -------------------------------------------

    fn frag(&self, id: u32) -> Option<&Frag<L, S>> {
        self.frags.get(id as usize)
    }

    fn frag_id_at(&self, pos: Pos<L, S>) -> Option<u32> {
        self.tree
            .get(&pos.key)
            .and_then(|bucket| bucket.get(pos.idx))
    }

    fn frag_at(&self, pos: Pos<L, S>) -> Option<Frag<L, S>> {
        self.frag_id_at(pos).and_then(|id| self.frag(id)).copied()
    }

    /// The first fragment with key `>= key` (Ghidra `lower_bound`).
    fn lower_bound(&self, key: (L, S)) -> Option<Pos<L, S>> {
        self.tree
            .range(key..)
            .next()
            .map(|(k, _)| Pos { key: *k, idx: 0 })
    }

    /// The first fragment with key `> key` (Ghidra `upper_bound`).
    fn upper_bound(&self, key: (L, S)) -> Option<Pos<L, S>> {
        use std::ops::Bound;
        self.tree
            .range((Bound::Excluded(key), Bound::Unbounded))
            .next()
            .map(|(k, _)| Pos { key: *k, idx: 0 })
    }

    fn next_pos(&self, pos: Pos<L, S>) -> Option<Pos<L, S>> {
        let len = self.tree.get(&pos.key).map_or(0, Bucket::len);
        if pos.idx + 1 < len {
            return Some(Pos {
                key: pos.key,
                idx: pos.idx + 1,
            });
        }
        self.upper_bound(pos.key)
    }

    fn prev_pos(&self, pos: Pos<L, S>) -> Option<Pos<L, S>> {
        if pos.idx > 0 {
            return Some(Pos {
                key: pos.key,
                idx: pos.idx - 1,
            });
        }
        self.tree
            .range(..pos.key)
            .next_back()
            .map(|(k, bucket)| Pos {
                key: *k,
                idx: bucket.len().saturating_sub(1),
            })
    }

    fn last_pos(&self) -> Option<Pos<L, S>> {
        self.tree.iter().next_back().map(|(k, bucket)| Pos {
            key: *k,
            idx: bucket.len().saturating_sub(1),
        })
    }

    fn alloc_frag(&mut self, frag: Frag<L, S>) -> u32 {
        if let Some(id) = self.free_frags.pop()
            && let Some(slot) = self.frags.get_mut(id as usize)
        {
            *slot = frag;
            return id;
        }
        let id = self.frags.len() as u32;
        self.frags.push(frag);
        id
    }

    /// Inserts a fragment into the bucket of its key; returns where it went.
    fn place(&mut self, frag: Frag<L, S>, place: Place) -> Pos<L, S> {
        let key = (frag.last, frag.sub);
        if let Some(record) = self.records.get_mut(frag.rec as usize) {
            record.frags += 1;
        }
        let id = self.alloc_frag(frag);
        let bucket = self.tree.entry(key).or_default();
        let idx = match place {
            Place::Front => 0,
            Place::Back => bucket.len(),
            Place::At(i) => i.min(bucket.len()),
        };
        bucket.insert(idx, id);
        Pos { key, idx }
    }

    /// Inserts with a C++ hint (`multiset::insert(hint, value)`): the
    /// fragment goes immediately before `hint` when it fits there, before
    /// every equal element when `*hint` is less, after every equal element
    /// otherwise (spec 4.2). Returns the hint's position after the
    /// insertion.
    fn place_hinted(&mut self, frag: Frag<L, S>, hint: Pos<L, S>) -> Pos<L, S> {
        let key = (frag.last, frag.sub);
        match key.cmp(&hint.key) {
            std::cmp::Ordering::Equal => {
                self.place(frag, Place::At(hint.idx));
                Pos {
                    key: hint.key,
                    idx: hint.idx + 1,
                }
            }
            std::cmp::Ordering::Less => {
                self.place(frag, Place::Back);
                hint
            }
            std::cmp::Ordering::Greater => {
                self.place(frag, Place::Front);
                hint
            }
        }
    }

    /// Removes the fragment at `pos` and returns its slot to the free list.
    fn remove_at(&mut self, pos: Pos<L, S>) {
        let mut emptied = false;
        let mut removed = None;
        if let Some(bucket) = self.tree.get_mut(&pos.key) {
            removed = bucket.remove(pos.idx);
            emptied = bucket.len() == 0;
        }
        if let Some(id) = removed {
            self.free_frags.push(id);
            let rec = self.frag(id).map_or(NIL, |frag| frag.rec);
            if let Some(record) = self.records.get_mut(rec as usize) {
                record.frags = record.frags.saturating_sub(1);
            }
        }
        if emptied {
            self.tree.remove(&pos.key);
        }
    }

    fn set_first(&mut self, pos: Pos<L, S>, first: L) {
        if let Some(id) = self.frag_id_at(pos)
            && let Some(frag) = self.frags.get_mut(id as usize)
        {
            frag.first = first;
        }
    }

    // ----- record list --------------------------------------------------

    fn alloc_record(&mut self, value: R, a: L, b: L, sub: S) -> u32 {
        let record = Record {
            value,
            a,
            b,
            sub,
            prev: NIL,
            next: NIL,
            live: true,
            frags: 0,
        };
        if let Some(id) = self.free_records.pop()
            && let Some(slot) = self.records.get_mut(id as usize)
        {
            *slot = record;
            return id;
        }
        let id = self.records.len() as u32;
        self.records.push(record);
        id
    }

    /// Links record `id` into the list before `before` (`NIL`: at the end).
    fn link_before(&mut self, id: u32, before: u32) {
        let prev = if before == NIL {
            self.tail
        } else {
            self.records.get(before as usize).map_or(NIL, |r| r.prev)
        };
        if let Some(r) = self.records.get_mut(id as usize) {
            r.prev = prev;
            r.next = before;
        }
        match self.records.get_mut(prev as usize) {
            Some(p) if prev != NIL => p.next = id,
            _ => self.head = id,
        }
        match self.records.get_mut(before as usize) {
            Some(n) if before != NIL => n.prev = id,
            _ => self.tail = id,
        }
        self.len += 1;
    }

    fn unlink(&mut self, id: u32) {
        let Some(r) = self.records.get(id as usize) else {
            return;
        };
        let (prev, next) = (r.prev, r.next);
        match self.records.get_mut(prev as usize) {
            Some(p) if prev != NIL => p.next = next,
            _ => self.head = next,
        }
        match self.records.get_mut(next as usize) {
            Some(n) if next != NIL => n.prev = prev,
            _ => self.tail = prev,
        }
        if let Some(r) = self.records.get_mut(id as usize) {
            r.live = false;
            r.prev = NIL;
            r.next = NIL;
        }
        self.free_records.push(id);
        self.len -= 1;
    }

    // ----- refinement ----------------------------------------------------

    /// Ghidra `unzip(i, iter)`: splits the piece at `pos` so that `i` and
    /// `i + 1` lie in different pieces.
    fn unzip(&mut self, i: L, start: Pos<L, S>) {
        let Some(first) = self.frag_at(start) else {
            return;
        };
        if first.last == i {
            return;
        }
        let plus1 = i.next();
        let mut cur = Some(start);
        while let Some(pos) = cur {
            let Some(frag) = self.frag_at(pos) else {
                break;
            };
            if frag.first > i {
                break;
            }
            self.set_first(pos, plus1);
            let copy = Frag {
                first: frag.first,
                last: i,
                ..frag
            };
            // The copy's key ends at `i`, before every key of the piece at
            // `start`: the hint is greater, so it goes after its equals and
            // positions in the piece do not move.
            self.place(copy, Place::Back);
            cur = self.next_pos(pos);
        }
    }

    /// Ghidra `zip(i, iter)`: merges the pieces at `i | i + 1`.
    fn zip(&mut self, i: L, start: Option<Pos<L, S>>) {
        let Some(mut pos) = start else {
            return;
        };
        let Some(head) = self.frag_at(pos) else {
            return;
        };
        let f = head.first;
        // Erase every fragment ending at `i`; erasing at a position moves the
        // next one into it (or past the end of the bucket).
        loop {
            match self.frag_at(pos) {
                Some(frag) if frag.last == i => {}
                _ => break,
            }
            let len = self.tree.get(&pos.key).map_or(0, Bucket::len);
            self.remove_at(pos);
            let next = if pos.idx + 1 < len {
                Some(pos)
            } else {
                self.upper_bound(pos.key)
            };
            match next {
                Some(p) => pos = p,
                None => return,
            }
        }
        let plus1 = i.next();
        let mut cur = Some(pos);
        while let Some(p) = cur {
            match self.frag_at(p) {
                Some(frag) if frag.first == plus1 => self.set_first(p, f),
                _ => break,
            }
            cur = self.next_pos(p);
        }
    }

    // ----- insert and erase ----------------------------------------------

    /// Inserts a record covering `[a, b]` with the given subsort (Ghidra
    /// `insert`). The caller guarantees `a <= b`.
    pub fn insert(&mut self, value: R, a: L, b: L, sub: S) -> RecordId {
        let mut f = a;
        let low = self.lower_bound((f, S::EARLIEST));
        if let Some(pos) = low
            && self.frag_at(pos).is_some_and(|frag| frag.first < f)
        {
            // Copies go into buckets ending at f - 1, before `pos`'s.
            self.unzip(f.prev(), pos);
        }
        let rec = self.alloc_record(value, a, b, sub);
        let spot = self.lower_bound((b, sub));
        let before = spot
            .and_then(|pos| self.frag_at(pos))
            .map_or(NIL, |frag| frag.rec);
        self.link_before(rec, before);
        let proto = Frag {
            first: f,
            last: b,
            a,
            b,
            sub,
            rec,
        };
        let mut low = low;
        while let Some(mut pos) = low {
            let Some(cur) = self.frag_at(pos) else {
                break;
            };
            if cur.first > b {
                break;
            }
            if f <= cur.last {
                if f < cur.first {
                    let frag = Frag {
                        first: f,
                        last: cur.first.prev(),
                        ..proto
                    };
                    pos = self.place_hinted(frag, pos);
                    f = cur.first;
                }
                if cur.last <= b {
                    let frag = Frag {
                        first: f,
                        last: cur.last,
                        ..proto
                    };
                    pos = self.place_hinted(frag, pos);
                    if cur.last == b {
                        break;
                    }
                    f = cur.last.next();
                } else {
                    self.unzip(b, pos);
                    break;
                }
            }
            low = self.next_pos(pos);
        }
        if f <= b {
            let frag = Frag {
                first: f,
                last: b,
                ..proto
            };
            self.place(frag, Place::Back);
        }
        RecordId(rec)
    }

    /// Erases a record and re-sews the partition around it (Ghidra
    /// `erase`). An id that is not live is ignored.
    pub fn erase(&mut self, rec: RecordId) {
        let Some(record) = self.live_record(rec.0) else {
            return;
        };
        let (a, b) = (record.a, record.b);
        let mut leftsew = true;
        let mut rightsew = true;
        let mut leftoverlap = false;
        let mut rightoverlap = false;
        let low = self.lower_bound((a, S::EARLIEST));
        let aminus1 = a.prev();
        let mut uplow = match low {
            Some(pos) => self.prev_pos(pos),
            None => self.last_pos(),
        };
        while let Some(pos) = uplow {
            let Some(frag) = self.frag_at(pos) else {
                break;
            };
            if frag.last != aminus1 {
                break;
            }
            if frag.b == aminus1 {
                leftsew = false;
                break;
            }
            uplow = self.prev_pos(pos);
        }
        // Walk the fragments overlapping [a, b]: the walk only reads
        // `first`, which erasing does not change, so collect it first.
        let mut walk: Vec<Pos<L, S>> = Vec::new();
        let mut after = None;
        if let Some(start) = low {
            let mut pos = start;
            loop {
                walk.push(pos);
                match self.next_pos(pos) {
                    Some(next) if self.frag_at(next).is_some_and(|f| f.first <= b) => pos = next,
                    other => {
                        after = other;
                        break;
                    }
                }
            }
        }
        let after_frag = after.and_then(|pos| self.frag_at(pos));
        let mut doomed: Vec<u32> = Vec::new();
        for pos in &walk {
            let Some(id) = self.frag_id_at(*pos) else {
                continue;
            };
            let Some(frag) = self.frag(id) else {
                continue;
            };
            if frag.rec == rec.0 {
                doomed.push(id);
            } else {
                if frag.a < a {
                    leftoverlap = true;
                } else if frag.a == a {
                    leftsew = false;
                }
                if b < frag.b {
                    rightoverlap = true;
                } else if frag.b == b {
                    rightsew = false;
                }
            }
        }
        if after_frag.is_some_and(|frag| frag.a.prev() == b) {
            rightsew = false;
        }
        for id in doomed {
            self.remove_frag_id(id);
        }
        if leftsew && leftoverlap {
            let start = self.lower_bound((aminus1, S::EARLIEST));
            self.zip(aminus1, start);
        }
        if rightsew && rightoverlap {
            let start = self.lower_bound((b, S::EARLIEST));
            self.zip(b, start);
        }
        // Fragments the record still has lie outside the walk: an earlier
        // erase stretched it left of `a` (the right re-sew defect, module
        // documentation). Ghidra leaves them pointing at the freed list
        // node; Basilisk removes them.
        if self.live_record(rec.0).is_some_and(|r| r.frags > 0) {
            let strays: Vec<u32> = self
                .tree
                .values()
                .flat_map(|bucket| bucket.as_slice().iter().copied())
                .filter(|&id| self.frag(id).is_some_and(|frag| frag.rec == rec.0))
                .collect();
            for id in strays {
                self.remove_frag_id(id);
            }
        }
        self.unlink(rec.0);
    }

    /// Rebuilds a map from a recorded state: the records in list order
    /// (`(value, a, b, subsort)`) and the fragments in multiset order
    /// (`(first, last, index of the record)`). `None` when a fragment names
    /// no record or the fragments are not in key order.
    pub fn from_parts(records: &[(R, L, L, S)], fragments: &[(L, L, usize)]) -> Option<Self> {
        let mut map = Self::new();
        let mut ids = Vec::with_capacity(records.len());
        for &(value, a, b, sub) in records {
            let id = map.alloc_record(value, a, b, sub);
            map.link_before(id, NIL);
            ids.push(id);
        }
        let mut last_key: Option<(L, S)> = None;
        for &(first, last, rec) in fragments {
            let (_, a, b, sub) = *records.get(rec)?;
            let id = *ids.get(rec)?;
            let key = (last, sub);
            if last_key.is_some_and(|k| k > key) {
                return None;
            }
            last_key = Some(key);
            map.place(
                Frag {
                    first,
                    last,
                    a,
                    b,
                    sub,
                    rec: id,
                },
                Place::Back,
            );
        }
        Some(map)
    }

    fn remove_frag_id(&mut self, id: u32) {
        let Some(frag) = self.frag(id).copied() else {
            return;
        };
        let key = (frag.last, frag.sub);
        let idx = self.tree.get(&key).and_then(|bucket| bucket.position(id));
        if let Some(idx) = idx {
            self.remove_at(Pos { key, idx });
        }
    }
}

/// The records of an [`EntryMap`] in list order.
#[derive(Debug)]
pub struct Records<'m, R, L, S> {
    map: &'m EntryMap<R, L, S>,
    cur: u32,
    back: u32,
    remaining: usize,
}

impl<R: Copy, L: Line, S: Subsort> Iterator for Records<'_, R, L, S> {
    type Item = (RecordId, R);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let record = self.map.records.get(self.cur as usize)?;
        let item = (RecordId(self.cur), record.value);
        self.cur = record.next;
        self.remaining -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<R: Copy, L: Line, S: Subsort> DoubleEndedIterator for Records<'_, R, L, S> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let record = self.map.records.get(self.back as usize)?;
        let item = (RecordId(self.back), record.value);
        self.back = record.prev;
        self.remaining -= 1;
        Some(item)
    }
}

impl<R: Copy, L: Line, S: Subsort> ExactSizeIterator for Records<'_, R, L, S> {}

#[cfg(test)]
mod tests;
