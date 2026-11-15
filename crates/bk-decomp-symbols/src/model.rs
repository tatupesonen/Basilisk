//! The data of symbols, entries and scopes (spec 5.2).
//!
//! These are plain records in the [`Database`](crate::Database)'s arenas;
//! the behaviour lives in the `scope` and `database` modules.

use std::collections::BTreeMap;

use bk_core::{Address, Provenance, RangeList};
use bk_decomp_types::TypeId;

use crate::entrymap::{EntryMap, EntrySubsort, RecordId};
use crate::flags::{VarnodeFlags, category, disp, entry_props};
use crate::ids::{EntryId, ScopeId, SymbolId};

/// The per-space entry map of a scope.
pub type SpaceMap = EntryMap<EntryId, u64, EntrySubsort>;

/// What kind of symbol, with the kind-specific data (Ghidra's `Symbol`
/// subclasses).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolKind {
    /// A plain `Symbol`.
    Plain,
    /// A `FunctionSymbol`; `consume_size` is the bytes it takes in the
    /// address map.
    Function {
        /// Ghidra `consumeSize`.
        consume_size: i32,
    },
    /// An `EquateSymbol`.
    Equate {
        /// The constant.
        value: u64,
    },
    /// A `UnionFacetSymbol`.
    UnionFacet {
        /// The field, −1 for the whole union.
        field: i32,
        /// Whether it matches any op at the address.
        addr_based: bool,
    },
    /// A `LabSymbol` (code label).
    Label,
    /// An `ExternRefSymbol`.
    ExternRef {
        /// The placeholder address of the referenced function.
        ref_addr: Address,
    },
}

/// One symbol (Ghidra `Symbol`).
#[derive(Clone, Debug)]
pub struct SymbolData {
    pub(crate) scope: ScopeId,
    pub(crate) kind: SymbolKind,
    pub(crate) name: Box<str>,
    pub(crate) display_name: Box<str>,
    pub(crate) ty: TypeId,
    pub(crate) type_size: i32,
    pub(crate) type_unknown: bool,
    pub(crate) primitive_whole: bool,
    pub(crate) dedup: u32,
    pub(crate) flags: VarnodeFlags,
    pub(crate) disp: u32,
    pub(crate) category: i16,
    pub(crate) catindex: u32,
    pub(crate) ghidra_id: u64,
    pub(crate) entries: Vec<EntryId>,
    pub(crate) whole_count: u32,
    pub(crate) depth_scope: Option<ScopeId>,
    pub(crate) depth: i32,
    pub(crate) name_provenance: Provenance,
    pub(crate) type_provenance: Provenance,
    pub(crate) live: bool,
}

impl SymbolData {
    /// The scope owning the symbol.
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
    /// The kind and its data.
    pub fn kind(&self) -> &SymbolKind {
        &self.kind
    }
    /// The local name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The name to display.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    /// The data type.
    pub fn type_id(&self) -> TypeId {
        self.ty
    }
    /// The size of the data type.
    pub fn type_size(&self) -> i32 {
        self.type_size
    }
    /// The deduplication number among symbols of the same name.
    pub fn dedup(&self) -> u32 {
        self.dedup
    }
    /// The varnode-like flags.
    pub fn flags(&self) -> VarnodeFlags {
        self.flags
    }
    /// The display flags.
    pub fn display_flags(&self) -> u32 {
        self.disp
    }
    /// The display format (the low three display bits).
    pub fn display_format(&self) -> u32 {
        self.disp & disp::FORMAT_MASK
    }
    /// The category, −1 for none.
    pub fn category(&self) -> i16 {
        self.category
    }
    /// The position within the category.
    pub fn category_index(&self) -> u32 {
        self.catindex
    }
    /// Ghidra's 64-bit symbol id (0 = unassigned).
    pub fn ghidra_id(&self) -> u64 {
        self.ghidra_id
    }
    /// The entries, in the order they were added.
    pub fn entries(&self) -> &[EntryId] {
        &self.entries
    }
    /// Whether two or more entries map the whole symbol.
    pub fn is_multi_entry(&self) -> bool {
        self.whole_count > 1
    }
    /// Number of whole-size entries.
    pub fn whole_count(&self) -> u32 {
        self.whole_count
    }
    /// Who supplied the name (ADR-025 3f; in no key or comparison).
    pub fn name_provenance(&self) -> Provenance {
        self.name_provenance
    }
    /// Who supplied the type.
    pub fn type_provenance(&self) -> Provenance {
        self.type_provenance
    }
    /// Ghidra `isTypeLocked`.
    pub fn is_type_locked(&self) -> bool {
        self.flags.contains(VarnodeFlags::TYPELOCK)
    }
    /// Ghidra `isNameLocked`.
    pub fn is_name_locked(&self) -> bool {
        self.flags.contains(VarnodeFlags::NAMELOCK)
    }
    /// Ghidra `isSizeTypeLocked`.
    pub fn is_size_type_locked(&self) -> bool {
        self.disp & disp::SIZE_TYPELOCK != 0
    }
    /// Ghidra `isIsolated`.
    pub fn is_isolated(&self) -> bool {
        self.disp & disp::ISOLATE != 0
    }
    /// Ghidra `isThisPointer`.
    pub fn is_this_pointer(&self) -> bool {
        self.disp & disp::IS_THIS_PTR != 0
    }
    /// Ghidra `isNameUndefined`: 15 bytes starting `$$undef`.
    pub fn is_name_undefined(&self) -> bool {
        is_undefined_name(&self.name)
    }
    /// Ghidra `getBytesConsumed`.
    pub fn bytes_consumed(&self) -> i32 {
        match self.kind {
            SymbolKind::Function { consume_size } => consume_size,
            _ => self.type_size,
        }
    }
    /// Whether this is a function symbol.
    pub fn is_function(&self) -> bool {
        matches!(self.kind, SymbolKind::Function { .. })
    }
    /// Whether this is in the equate category.
    pub fn is_equate(&self) -> bool {
        self.category == category::EQUATE
    }

    /// Ghidra `checkSizeTypeLock`.
    pub(crate) fn check_size_type_lock(&mut self) {
        self.disp &= !disp::SIZE_TYPELOCK;
        if self.is_type_locked() && self.type_unknown {
            self.disp |= disp::SIZE_TYPELOCK;
        }
    }
}

/// Whether a name is one of `buildUndefinedName`'s.
pub(crate) fn is_undefined_name(name: &str) -> bool {
    name.len() == 15 && name.as_bytes().starts_with(b"$$undef")
}

/// What kind of entry (Ghidra's `SymbolEntry` subclasses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A `MapEntry`, or a `MapEntryConflict` when `conflict` holds the
    /// defining op's time.
    Map {
        /// The first address of the storage.
        addr: Address,
        /// For a conflict entry, the `uniq` (op time).
        conflict: Option<u32>,
    },
    /// A `DynamicEntry`.
    Dynamic {
        /// The dynamic hash.
        hash: u64,
    },
    /// An `UnassignedEntry`.
    Unassigned,
}

/// Where an entry is stored in its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handle {
    /// In the entry map of a space.
    Map(u32, RecordId),
    /// In the dynamic list, under this sequence number.
    Dynamic(u64),
    /// Only in the symbol's list.
    None,
}

/// One storage location of a symbol (Ghidra `SymbolEntry`).
#[derive(Clone, Debug)]
pub struct EntryData {
    pub(crate) symbol: SymbolId,
    pub(crate) kind: EntryKind,
    pub(crate) use_limit: RangeList,
    pub(crate) properties: u32,
    pub(crate) extra_flags: VarnodeFlags,
    pub(crate) offset: i32,
    pub(crate) size: i32,
    pub(crate) handle: Handle,
    pub(crate) live: bool,
}

impl EntryData {
    /// The symbol.
    pub fn symbol(&self) -> SymbolId {
        self.symbol
    }
    /// The kind.
    pub fn kind(&self) -> EntryKind {
        self.kind
    }
    /// The code addresses where this storage holds the symbol (empty: all).
    pub fn use_limit(&self) -> &RangeList {
        &self.use_limit
    }
    /// The entry property bits (`map_entry` …).
    pub fn properties(&self) -> u32 {
        self.properties
    }
    /// Flags specific to this storage.
    pub fn extra_flags(&self) -> VarnodeFlags {
        self.extra_flags
    }
    /// Offset into the symbol.
    pub fn offset(&self) -> i32 {
        self.offset
    }
    /// Bytes of this (piece of) storage.
    pub fn size(&self) -> i32 {
        self.size
    }
    /// The first address, for a map entry.
    pub fn addr(&self) -> Option<Address> {
        match self.kind {
            EntryKind::Map { addr, .. } => Some(addr),
            _ => None,
        }
    }
    /// Ghidra `isPiece`.
    pub fn is_piece(&self) -> bool {
        self.properties & entry_props::PIECE != 0
    }
    /// Ghidra `isMapEntry`.
    pub fn is_map_entry(&self) -> bool {
        self.properties & entry_props::MAP_ENTRY != 0
    }
    /// Ghidra `isDynamic`.
    pub fn is_dynamic(&self) -> bool {
        self.properties & entry_props::DYNAMIC_ENTRY != 0
    }
    /// Ghidra `isConflict`.
    pub fn is_conflict(&self) -> bool {
        self.properties & entry_props::CONFLICT_ENTRY != 0
    }
    /// Ghidra `getFirstUseAddress`: the first use-limit address, or invalid.
    pub fn first_use_address(&self) -> Address {
        self.use_limit
            .first_range()
            .map_or(Address::INVALID, |r| r.first_addr())
    }
    /// The last offset of a map entry (Ghidra `getLast`, wrapping).
    pub fn last_offset(&self) -> Option<u64> {
        self.addr().map(|addr| {
            addr.offset()
                .wrapping_add(i64::from(self.size) as u64)
                .wrapping_sub(1)
        })
    }
}

/// The kind of a scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    /// The global scope (no parent).
    Global,
    /// A namespace below the global scope.
    Namespace,
    /// The local scope of the function symbol given (Ghidra `restrictScope`).
    Function(SymbolId),
}

/// One scope (Ghidra `Scope` with `ScopeInternal`'s tables).
#[derive(Clone, Debug)]
pub struct ScopeData {
    pub(crate) name: Box<str>,
    pub(crate) display_name: Box<str>,
    pub(crate) ghidra_id: u64,
    pub(crate) parent: Option<ScopeId>,
    pub(crate) children: BTreeMap<u64, ScopeId>,
    pub(crate) ranges: RangeList,
    pub(crate) kind: ScopeKind,
    pub(crate) maps: Vec<Option<SpaceMap>>,
    pub(crate) names: BTreeMap<(Box<str>, u32), SymbolId>,
    pub(crate) categories: Vec<Vec<Option<SymbolId>>>,
    pub(crate) dynamic: BTreeMap<u64, EntryId>,
    pub(crate) next_dynamic: u64,
    pub(crate) multi: BTreeMap<(Box<str>, u32), SymbolId>,
    pub(crate) next_unique_id: u64,
    pub(crate) live: bool,
}

impl ScopeData {
    pub(crate) fn new(name: &str, ghidra_id: u64, kind: ScopeKind, spaces: usize) -> Self {
        Self {
            name: name.into(),
            display_name: name.into(),
            ghidra_id,
            parent: None,
            children: BTreeMap::new(),
            ranges: RangeList::default(),
            kind,
            maps: vec![None; spaces],
            names: BTreeMap::new(),
            categories: Vec::new(),
            dynamic: BTreeMap::new(),
            next_dynamic: 0,
            multi: BTreeMap::new(),
            next_unique_id: 0,
            live: true,
        }
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The name to display.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Ghidra's 64-bit scope id.
    pub fn ghidra_id(&self) -> u64 {
        self.ghidra_id
    }
    /// The parent scope.
    pub fn parent(&self) -> Option<ScopeId> {
        self.parent
    }
    /// The children, in Ghidra id order.
    pub fn children(&self) -> impl Iterator<Item = ScopeId> + '_ {
        self.children.values().copied()
    }
    /// The owned address ranges.
    pub fn ranges(&self) -> &RangeList {
        &self.ranges
    }
    /// The kind.
    pub fn kind(&self) -> ScopeKind {
        self.kind
    }
    /// Ghidra `isGlobal`: true for every scope that is not a function's.
    pub fn is_global(&self) -> bool {
        !matches!(self.kind, ScopeKind::Function(_))
    }
    /// The next symbol id counter (Ghidra `nextUniqueId`).
    pub fn next_unique_id(&self) -> u64 {
        self.next_unique_id
    }
    /// The symbols in name order.
    pub fn symbols_by_name(&self) -> impl Iterator<Item = SymbolId> + '_ {
        self.names.values().copied()
    }
    /// The multi-entry symbols in name order.
    pub fn multi_entry(&self) -> impl Iterator<Item = SymbolId> + '_ {
        self.multi.values().copied()
    }
    /// The slots of a category (`None` for an empty slot).
    pub fn category(&self, cat: i16) -> &[Option<SymbolId>] {
        usize::try_from(cat)
            .ok()
            .and_then(|c| self.categories.get(c))
            .map_or(&[], Vec::as_slice)
    }
    /// The number of categories that exist.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }
    /// The dynamic entries in insertion order.
    pub fn dynamic_entries(&self) -> impl Iterator<Item = EntryId> + '_ {
        self.dynamic.values().copied()
    }
    /// The entry map of a space, if it was ever used.
    pub fn space_map(&self, space_index: u32) -> Option<&SpaceMap> {
        self.maps.get(space_index as usize).and_then(Option::as_ref)
    }
}
