//! The context database (Ghidra `ContextInternal`, `CPP/globalcontext.cc`).

use bk_core::{Address, SpaceId};

use super::partmap::PartMap;
use super::tracked::TrackedValue;
use super::{ContextSink, ContextSource, ContextVar, OffsetRange};

/// Context words at one split point: the values, then the bits explicitly
/// set at this point (Ghidra `FreeArray`).
#[derive(Clone, Debug, Default)]
struct Blob {
    words: Box<[u32]>,
}

impl Blob {
    fn zeroed(size: usize) -> Self {
        Self {
            words: vec![0; size.saturating_mul(2)].into_boxed_slice(),
        }
    }

    /// A copy made by splitting: the values, but not the fact that they
    /// were set here (Ghidra `FreeArray::operator=`).
    fn split_copy(&self) -> Self {
        let size = self.words.len() / 2;
        let mut words = self.words.clone();
        if let Some(mask) = words.get_mut(size..) {
            mask.fill(0);
        }
        Self { words }
    }

    fn values(&self) -> &[u32] {
        let size = self.words.len() / 2;
        self.words.get(..size).unwrap_or_default()
    }

    /// The value and explicitly-set mask of word `word`.
    fn word_mut(&mut self, word: usize) -> Option<(&mut u32, &mut u32)> {
        let size = self.words.len() / 2;
        let (values, masks) = self.words.split_at_mut(size);
        Some((values.get_mut(word)?, masks.get_mut(word)?))
    }
}

/// Context words over the address line: a default, then split points
/// ordered by (space index, offset), each with the words in force from there
/// and the bits explicitly set there; plus tracked register values
/// (`<tracked_set>`).
///
/// Plain data: clone it to snapshot it. It knows nothing of a language
/// beyond the number of words and, optionally, the highest offset of each
/// space (for the ranges [`ContextSource::context_at`] reports).
#[derive(Clone, Debug)]
pub struct ContextDb {
    size: usize,
    highest: Vec<u64>,
    blobs: PartMap<Blob>,
    tracked: PartMap<Vec<TrackedValue>>,
    changes: u64,
}

impl ContextDb {
    /// An empty database of `size` words, all zero.
    pub fn new(size: usize) -> Self {
        Self {
            size,
            highest: Vec::new(),
            blobs: PartMap::new(Blob::zeroed(size)),
            tracked: PartMap::new(Vec::new()),
            changes: 0,
        }
    }

    /// Sets the highest offset of each space, by space index, used for the
    /// end of the constant range around an address with no later split point
    /// in its space. Spaces not listed reach `u64::MAX`.
    pub fn set_space_limits(&mut self, highest: Vec<u64>) {
        self.highest = highest;
    }

    /// The number of context words.
    pub fn size(&self) -> usize {
        self.size
    }

    /// A counter that changes whenever the context changes.
    pub fn change_count(&self) -> u64 {
        self.changes
    }

    /// The default words, in force before the first split point.
    pub fn default_words(&self) -> &[u32] {
        self.blobs.default_value().values()
    }

    /// Changes bits of the default words (Ghidra `setVariableDefault` by
    /// word).
    pub fn set_default(&mut self, word: usize, mask: u32, value: u32) {
        self.changes = self.changes.wrapping_add(1);
        if let Some((slot, _)) = self.blobs.default_value_mut().word_mut(word) {
            *slot = (*slot & !mask) | (value & mask);
        }
    }

    /// Sets a variable's default value (Ghidra `setVariableDefault`).
    pub fn set_variable_default(&mut self, var: &ContextVar, value: u32) {
        let shifted = (value & var.value_mask()) << var.shift();
        self.set_default(var.word(), var.word_mask(), shifted);
    }

    /// The words in force at `addr` (Ghidra `getContext`).
    pub fn get(&self, addr: Address) -> &[u32] {
        self.blobs.get(addr).values()
    }

    /// The words in force at `addr` and the offsets around it over which they
    /// are constant (Ghidra `getContext(addr, first, last)`).
    pub fn get_with_range(&self, addr: Address) -> (&[u32], OffsetRange) {
        let (blob, bounds) = self.blobs.bounds(addr);
        let first = match bounds.before {
            Some(before) if before.space() == addr.space() => before.offset(),
            _ => 0,
        };
        let last = match bounds.after {
            Some(after) if after.space() == addr.space() => after.offset().wrapping_sub(1),
            _ => self.highest_of(addr.space()),
        };
        (blob.values(), OffsetRange { first, last })
    }

    fn highest_of(&self, space: Option<SpaceId>) -> u64 {
        space
            .and_then(|space| self.highest.get(space.index() as usize).copied())
            .unwrap_or(u64::MAX)
    }

    /// The value of a variable at `addr` (Ghidra `getVariable`).
    pub fn variable(&self, var: &ContextVar, addr: Address) -> u32 {
        var.get(self.get(addr))
    }

    /// The flowing set by word (Ghidra `setContextChangePoint`); also
    /// [`ContextSink::set_change_point`]. As in Ghidra, `value` is combined
    /// with a bitwise OR, without masking.
    pub fn change_point(&mut self, addr: Address, word: usize, mask: u32, value: u32) {
        self.changes = self.changes.wrapping_add(1);
        self.blobs.split_with(addr, Blob::split_copy);
        let mut first = true;
        for (_, blob) in self.blobs.range_mut(addr, None) {
            let Some((slot, set)) = blob.word_mut(word) else {
                break;
            };
            if first {
                *set |= mask;
                first = false;
            } else if *set & mask != 0 {
                break;
            }
            *slot = (*slot & !mask) | value;
        }
    }

    /// The region set by word (Ghidra `setContextRegion`); also
    /// [`ContextSink::set_region`]. As in Ghidra, `value` is combined with a
    /// bitwise OR, without masking.
    pub fn region(
        &mut self,
        first: Address,
        end: Option<Address>,
        word: usize,
        mask: u32,
        value: u32,
    ) {
        self.changes = self.changes.wrapping_add(1);
        self.blobs.split_with(first, Blob::split_copy);
        if let Some(end) = end {
            self.blobs.split_with(end, Blob::split_copy);
        }
        for (_, blob) in self.blobs.range_mut(first, end) {
            if let Some((slot, set)) = blob.word_mut(word) {
                *set |= mask;
                *slot = (*slot & !mask) | value;
            }
        }
    }

    /// The flowing set of a variable (Ghidra `setVariable`).
    pub fn set_variable(&mut self, var: &ContextVar, addr: Address, value: u32) {
        let shifted = (value & var.value_mask()) << var.shift();
        self.change_point(addr, var.word(), var.word_mask(), shifted);
    }

    /// The region set of a variable (Ghidra `setVariableRegion`).
    pub fn set_variable_region(
        &mut self,
        var: &ContextVar,
        first: Address,
        end: Option<Address>,
        value: u32,
    ) {
        let shifted = (value & var.value_mask()) << var.shift();
        self.region(first, end, var.word(), var.word_mask(), shifted);
    }

    /// The split points with their words and explicitly-set masks, in order.
    pub fn split_points(&self) -> impl Iterator<Item = (Address, &[u32], &[u32])> {
        self.blobs.iter().map(|(addr, blob)| {
            let (values, masks) = blob.words.split_at(blob.words.len() / 2);
            (*addr, values, masks)
        })
    }

    /// Replaces the tracked values over `[first, end)` (Ghidra `createSet`
    /// followed by `decodeTracked`).
    pub fn set_tracked(&mut self, first: Address, end: Address, values: Vec<TrackedValue>) {
        if let Some(set) = self.tracked.clear_range(first, end, Clone::clone) {
            *set = values;
        }
    }

    /// The tracked values in force at `addr` (Ghidra `getTrackedSet`).
    pub fn tracked_set(&self, addr: Address) -> &[TrackedValue] {
        self.tracked.get(addr)
    }

    /// The value assumed for the `size` bytes at (`space`, `offset`) at
    /// `addr`: taken from the first tracked value that contains them,
    /// trimmed by its endianness; 0 if none (Ghidra `getTrackedValue`).
    pub fn tracked_value(&self, space: SpaceId, offset: u64, size: u32, addr: Address) -> u64 {
        self.tracked_set(addr)
            .iter()
            .find_map(|tracked| tracked.extract(space, offset, size))
            .unwrap_or(0)
    }

    /// Whether the database has no split points and no tracked sets.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty() && self.tracked.is_empty()
    }
}

impl ContextSource for ContextDb {
    fn context_at(&self, addr: Address, out: &mut [u32]) -> OffsetRange {
        let (words, range) = self.get_with_range(addr);
        for (slot, word) in out.iter_mut().zip(words.iter().chain(std::iter::repeat(&0))) {
            *slot = *word;
        }
        range
    }
}

impl ContextSink for ContextDb {
    fn set_change_point(&mut self, addr: Address, word: usize, mask: u32, value: u32) {
        self.change_point(addr, word, mask, value);
    }

    fn set_region(&mut self, first: Address, end: Option<Address>, word: usize, mask: u32, value: u32) {
        self.region(first, end, word, mask, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(offset: u64) -> Address {
        Address::new(SpaceId::new(3), offset)
    }

    fn var() -> ContextVar {
        ContextVar::new("v", 4, 7).unwrap()
    }

    #[test]
    fn defaults_apply_before_any_split_point() {
        let mut db = ContextDb::new(2);
        db.set_variable_default(&var(), 0xa);
        assert_eq!(db.default_words(), [0x0a00_0000, 0]);
        assert_eq!(db.variable(&var(), at(0x1234)), 0xa);
        let (words, range) = db.get_with_range(at(5));
        assert_eq!(words, [0x0a00_0000, 0]);
        assert_eq!(range, OffsetRange { first: 0, last: u64::MAX });
        assert!(db.is_empty());
    }

    #[test]
    fn a_flowing_set_stops_at_an_earlier_explicit_set() {
        let mut db = ContextDb::new(1);
        // Explicit region set at 0x200..0x300.
        db.set_variable_region(&var(), at(0x200), Some(at(0x300)), 3);
        // A flowing set from 0x100 changes 0x100..0x200 only.
        db.set_variable(&var(), at(0x100), 5);
        assert_eq!(db.variable(&var(), at(0x100)), 5);
        assert_eq!(db.variable(&var(), at(0x1ff)), 5);
        assert_eq!(db.variable(&var(), at(0x200)), 3);
        // After the region, the value that was in force before it returns.
        assert_eq!(db.variable(&var(), at(0x300)), 0);
        // A flowing set of other bits passes the region.
        let other = ContextVar::new("o", 0, 3).unwrap();
        db.set_variable(&other, at(0x80), 1);
        assert_eq!(db.variable(&other, at(0x2ff)), 1);
        assert_eq!(db.variable(&other, at(0x400)), 1);
        assert_eq!(db.variable(&other, at(0x7f)), 0);
        // Ranges reflect the split points around an address.
        let (_, range) = db.get_with_range(at(0x250));
        assert_eq!(range, OffsetRange { first: 0x200, last: 0x2ff });
        let points: Vec<u64> = db.split_points().map(|(a, _, _)| a.offset()).collect();
        assert_eq!(points, [0x80, 0x100, 0x200, 0x300]);
        let masks: Vec<u32> = db.split_points().map(|(_, _, m)| m[0]).collect();
        assert_eq!(masks, [0xf000_0000, 0x0f00_0000, 0x0f00_0000, 0]);
    }

    #[test]
    fn region_sets_cover_their_range_and_to_the_end() {
        let mut db = ContextDb::new(1);
        db.set_space_limits(vec![0, 0, 0, 0xffff]);
        db.region(at(0x10), Some(at(0x20)), 0, 0xff, 0x12);
        db.region(at(0x18), None, 0, 0xff00, 0x3400);
        assert_eq!(db.get(at(0x0f)), [0]);
        assert_eq!(db.get(at(0x10)), [0x12]);
        assert_eq!(db.get(at(0x18)), [0x3412]);
        assert_eq!(db.get(at(0x20)), [0x3400]);
        let (_, range) = db.get_with_range(at(0x30));
        assert_eq!(range, OffsetRange { first: 0x20, last: 0xffff });
        // Another space starts from the default.
        assert_eq!(db.get(Address::new(SpaceId::new(4), 0)), [0x3400]);
        let (_, range) = db.get_with_range(Address::new(SpaceId::new(4), 7));
        assert_eq!(range.first, 0);
        assert!(db.change_count() >= 2);
        // Words past the database's size are ignored.
        db.region(at(0), None, 5, 1, 1);
        db.change_point(at(0), 5, 1, 1);
        db.set_default(5, 1, 1);
        let mut out = [9u32; 2];
        let _ = ContextSource::context_at(&db, at(0x18), &mut out);
        assert_eq!(out, [0x3412, 0]);
    }

    #[test]
    fn tracked_sets_replace_ranges() {
        let mut db = ContextDb::new(0);
        let reg = |value| TrackedValue {
            space: SpaceId::new(4),
            offset: 0x10,
            size: 4,
            big_endian: true,
            value,
        };
        db.set_tracked(at(0x100), at(0x200), vec![reg(0x1122_3344)]);
        assert_eq!(db.tracked_value(SpaceId::new(4), 0x10, 4, at(0x150)), 0x1122_3344);
        assert_eq!(db.tracked_value(SpaceId::new(4), 0x12, 2, at(0x150)), 0x3344);
        assert_eq!(db.tracked_value(SpaceId::new(4), 0x10, 4, at(0x200)), 0);
        db.set_tracked(at(0x180), at(0x190), vec![reg(7)]);
        assert_eq!(db.tracked_value(SpaceId::new(4), 0x10, 4, at(0x185)), 7);
        assert_eq!(db.tracked_value(SpaceId::new(4), 0x10, 4, at(0x190)), 0x1122_3344);
        assert_eq!(db.tracked_set(at(0x50)).len(), 0);
    }
}
