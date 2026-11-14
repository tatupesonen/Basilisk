//! The effect a called function has on a storage range (Ghidra
//! `EffectRecord`, `ProtoModel::lookupEffect`, `ProtoModel::lookupRecord`).

use std::cmp::Ordering;

use bk_core::{Address, SpaceManager, SpaceType, VarnodeData};

/// What a call does to a storage range (Ghidra's `EffectRecord` types, with
/// their numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EffectKind {
    /// The call does not change the value.
    Unaffected = 1,
    /// The call changes the value to something unrelated.
    KilledByCall = 2,
    /// The storage holds the return address.
    ReturnAddress = 3,
    /// Nothing is known (the absence of a record).
    Unknown = 4,
}

impl EffectKind {
    /// Ghidra's name for the kind, as the element that lists it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unaffected => "unaffected",
            Self::KilledByCall => "killedbycall",
            Self::ReturnAddress => "returnaddress",
            Self::Unknown => "unknown",
        }
    }
}

/// The effect of a call on one storage range (Ghidra `EffectRecord`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EffectRecord {
    /// The range affected.
    pub range: VarnodeData,
    /// What happens to it.
    pub kind: EffectKind,
}

impl EffectRecord {
    /// A record for a range and kind.
    pub const fn new(range: VarnodeData, kind: EffectKind) -> Self {
        Self { range, kind }
    }

    /// The start of the range.
    pub fn address(&self) -> Address {
        self.range.addr()
    }

    /// The size of the range in bytes.
    pub const fn size(&self) -> u32 {
        self.range.size
    }

    /// Orders records by space index then offset, ignoring size and kind
    /// (Ghidra `EffectRecord::compareByAddress`).
    pub fn cmp_by_address(&self, other: &Self) -> Ordering {
        self.range
            .space()
            .cmp(&other.range.space())
            .then(self.range.offset.cmp(&other.range.offset))
    }
}

/// Sorts an effect list by address, keeping records with equal addresses in
/// their original (document) order, the default return address last
/// (ADR-040). Ghidra's `std::sort` leaves their order to the C++ library:
/// libstdc++ reorders 28 of the corpus's lists, libc++ none; a stable order
/// makes the result the same on every host.
pub fn sort_effects(list: &mut [EffectRecord]) {
    list.sort_by(EffectRecord::cmp_by_address);
}

/// The effect recorded for a range in a list sorted by address, or
/// [`EffectKind::Unknown`] (Ghidra `ProtoModel::lookupEffect`). The unique
/// space is always [`EffectKind::Unaffected`]. Where several records start
/// at one address, the last of them decides, as in Ghidra; with
/// [`sort_effects`] that is the last in document order (ADR-040).
pub fn lookup_effect(
    list: &[EffectRecord],
    manager: &SpaceManager,
    addr: Address,
    size: u32,
) -> EffectKind {
    if manager
        .space_of(addr)
        .is_some_and(|s| s.space_type() == SpaceType::Internal)
    {
        return EffectKind::Unaffected;
    }
    let probe = EffectRecord::new(VarnodeData::from_address(addr, size), EffectKind::Unknown);
    // upper_bound: the first record greater than the probe.
    let upper = list.partition_point(|r| r.cmp_by_address(&probe) != Ordering::Greater);
    let Some(hit) = upper.checked_sub(1).and_then(|i| list.get(i)) else {
        return EffectKind::Unknown;
    };
    let hit_addr = hit.address();
    let sz = hit.size();
    if sz == 0 && hit_addr.space() == addr.space() {
        return EffectKind::Unaffected;
    }
    match addr.overlap(manager, 0, hit_addr, sz) {
        Some(where_) if u64::from(where_) + u64::from(size) <= u64::from(sz) => hit.kind,
        _ => EffectKind::Unknown,
    }
}

/// Where a record for exactly this range sits among the first `list_size`
/// records of a sorted list (Ghidra `ProtoModel::lookupRecord`):
/// `Ok(index)` for an exact match, `Err(false)` when nothing overlaps (-1),
/// `Err(true)` for a partial overlap (-2).
pub fn lookup_record(
    list: &[EffectRecord],
    list_size: usize,
    manager: &SpaceManager,
    addr: Address,
    size: u32,
) -> Result<usize, bool> {
    let Some(list) = list.get(..list_size) else {
        return Err(false);
    };
    if list.is_empty() {
        return Err(false);
    }
    let probe = EffectRecord::new(VarnodeData::from_address(addr, size), EffectKind::Unknown);
    let upper = list.partition_point(|r| r.cmp_by_address(&probe) != Ordering::Greater);
    let Some(index) = upper.checked_sub(1) else {
        // Ghidra reads the first record here (its comparison is against the
        // whole list's begin, which equals the window's begin).
        let close = list.first().map_or(Address::INVALID, EffectRecord::address);
        return Err(close.overlap(manager, 0, addr, size).is_some());
    };
    let Some(close) = list.get(index) else {
        return Err(false);
    };
    if close.address() == addr && close.size() == size {
        return Ok(index);
    }
    Err(addr
        .overlap(manager, 0, close.address(), close.size())
        .is_some())
}
