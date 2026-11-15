//! Adding symbols and entries (database.cc 1214–1300, 1630–1900,
//! 1966–2050; spec 4.4, 4.5, 4.9).

use bk_core::{Address, Provenance, RangeList};
use bk_decomp_types::{Metatype, TypeFactory, TypeId};

use crate::database::Database;
use crate::entrymap::EntrySubsort;
use crate::error::{Result, SymbolError, limits};
use crate::flags::{VarnodeFlags, category, entry_props};
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{EntryData, EntryKind, Handle, SpaceMap, SymbolData, SymbolKind};

/// Ghidra `Symbol::ID_BASE`.
pub const ID_BASE: u64 = 0x4000_0000_0000_0000;

/// What a conflict entry needs of its varnode (Ghidra `MapEntryConflict`'s
/// constructor reads them from a `Varnode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConflictFacts {
    /// The varnode's address.
    pub addr: Address,
    /// The varnode's size.
    pub size: i32,
    /// Whether the varnode is written (required).
    pub written: bool,
    /// The address of the defining op.
    pub def_addr: Address,
    /// The time of the defining op (its `SeqNum` time).
    pub def_time: u32,
}

/// The facts of a type a symbol keeps.
pub(crate) struct TypeFacts {
    pub(crate) size: i32,
    pub(crate) unknown: bool,
    pub(crate) primitive_whole: bool,
}

pub(crate) fn type_facts(types: &TypeFactory, ty: TypeId) -> Result<TypeFacts> {
    let entry = types.entry_checked(ty)?;
    Ok(TypeFacts {
        size: entry.size(),
        unknown: entry.metatype() == Metatype::Unknown,
        primitive_whole: types.is_primitive_whole(ty),
    })
}

/// A type's stripped form, or the type (Ghidra `hasStripped`/`getStripped`).
pub(crate) fn stripped(types: &TypeFactory, ty: TypeId) -> TypeId {
    match types.get(ty) {
        Some(e) if e.has_stripped() => e.stripped().unwrap_or(ty),
        _ => ty,
    }
}

impl Database {
    /// A fresh, unattached symbol record.
    pub(crate) fn new_symbol(
        &self,
        scope: ScopeId,
        kind: SymbolKind,
        name: &str,
        ty: TypeId,
        types: &TypeFactory,
    ) -> Result<SymbolData> {
        if name.len() > limits::MAX_NAME {
            return Err(SymbolError::Limit("symbol name length"));
        }
        let facts = type_facts(types, ty)?;
        let category = match kind {
            SymbolKind::Equate { .. } => category::EQUATE,
            SymbolKind::UnionFacet { .. } => category::UNION_FACET,
            _ => category::NONE,
        };
        Ok(SymbolData {
            scope,
            kind,
            name: name.into(),
            display_name: name.into(),
            ty,
            type_size: facts.size,
            type_unknown: facts.unknown,
            primitive_whole: facts.primitive_whole,
            dedup: 0,
            flags: VarnodeFlags::empty(),
            disp: 0,
            category,
            catindex: 0,
            ghidra_id: 0,
            entries: Vec::new(),
            whole_count: 0,
            depth_scope: None,
            depth: 0,
            name_provenance: Provenance::Analysis,
            type_provenance: Provenance::Analysis,
            live: true,
        })
    }

    /// Ghidra `ScopeInternal::addSymbolInternal`: assigns an id (consumed
    /// even when the symbol is then refused), names an unnamed symbol,
    /// checks its type, enters it in the name tree and its category.
    pub(crate) fn add_symbol_internal(
        &mut self,
        scope: ScopeId,
        mut sym: SymbolData,
    ) -> Result<SymbolId> {
        let data = self.scope_mut(scope)?;
        if sym.ghidra_id == 0 {
            if data.next_unique_id >= limits::MAX_SYMBOLS {
                return Err(SymbolError::Limit("symbols per scope"));
            }
            sym.ghidra_id = ID_BASE
                .wrapping_add((data.ghidra_id & 0xffff) << 40)
                .wrapping_add(data.next_unique_id);
            data.next_unique_id += 1;
        }
        if sym.name.is_empty() {
            let name = self.build_undefined_name(scope)?;
            sym.display_name = name.clone().into();
            sym.name = name.into();
            sym.name_provenance = Provenance::Default;
        }
        if sym.type_size < 1 {
            return Err(SymbolError::ZeroSizeType {
                name: sym.name.to_string(),
            });
        }
        let dedup = self.free_dedup(scope, &sym.name)?;
        sym.dedup = dedup;
        let id = SymbolId(self.symbols.len() as u32);
        if sym.category >= 0 {
            let cat = sym.category as usize;
            let data = self.scope_mut(scope)?;
            while data.categories.len() <= cat {
                data.categories.push(Vec::new());
            }
            if let Some(list) = data.categories.get_mut(cat) {
                if sym.category > 0 {
                    sym.catindex = u32::try_from(list.len())
                        .map_err(|_| SymbolError::Limit("category index"))?;
                }
                let index = sym.catindex as usize;
                if index as u64 >= limits::MAX_SYMBOLS {
                    return Err(SymbolError::Limit("category index"));
                }
                while list.len() <= index {
                    list.push(None);
                }
                if let Some(slot) = list.get_mut(index) {
                    *slot = Some(id);
                }
            }
        }
        let key = (sym.name.clone(), sym.dedup);
        self.symbols.push(sym);
        self.scope_mut(scope)?.names.insert(key, id);
        Ok(id)
    }

    /// Ghidra `insertNameTree`'s choice of dedup number: 0, else one more
    /// than the last symbol of that name; a second clash is an error.
    pub(crate) fn free_dedup(&self, scope: ScopeId, name: &str) -> Result<u32> {
        let data = self.scope(scope)?;
        let key: (Box<str>, u32) = (name.into(), 0);
        if !data.names.contains_key(&key) {
            return Ok(0);
        }
        let last = data
            .names
            .range(key..=(name.into(), u32::MAX))
            .next_back()
            .map_or(0, |((_, d), _)| *d);
        let dedup = last.wrapping_add(1);
        if data.names.contains_key(&(name.into(), dedup)) {
            return Err(SymbolError::Dedup { name: name.into() });
        }
        Ok(dedup)
    }

    fn push_entry(&mut self, entry: EntryData) -> EntryId {
        let id = EntryId(self.entries.len() as u32);
        self.entries.push(entry);
        id
    }

    /// The offset of the last byte of `size` bytes at `addr`, or the
    /// "extends beyond the end of the address space" error (Ghidra
    /// `addMapInternal`, checked here before anything changes).
    fn last_in_space(&self, sym: SymbolId, addr: Address, size: i32) -> Result<u64> {
        let last = addr.add(&self.env.spaces, i64::from(size) - 1);
        if last.offset() < addr.offset() {
            return Err(SymbolError::BeyondSpace {
                name: self.symbol(sym)?.name.to_string(),
            });
        }
        Ok(last.offset())
    }

    /// Ghidra `ScopeInternal::addMapInternal`, after the checks: appends the
    /// entry to its symbol and inserts it in its space's map.
    fn add_map_internal(&mut self, scope: ScopeId, entry: EntryData, last: u64) -> Result<EntryId> {
        let sym_id = entry.symbol;
        let EntryKind::Map { addr, .. } = entry.kind else {
            return Err(SymbolError::DecodeConflict);
        };
        let space = addr.space().map_or(0, |s| s.index());
        let sub = self.subsort(&entry)?;
        let size = entry.size;
        let id = self.push_entry(entry);
        let data = self.scope_mut(scope)?;
        let slot = space as usize;
        if data.maps.len() <= slot {
            data.maps.resize(slot + 1, None);
        }
        let map = data
            .maps
            .get_mut(slot)
            .map(|m| m.get_or_insert_with(SpaceMap::new))
            .ok_or(SymbolError::Limit("space index"))?;
        let record = map.insert(id, addr.offset(), last, sub);
        if let Some(e) = self.entries.get_mut(id.0 as usize) {
            e.handle = Handle::Map(space, record);
        }
        self.note_entry(scope, sym_id, id, size)?;
        Ok(id)
    }

    /// Appends an entry to its symbol and updates the whole-entry count.
    fn note_entry(
        &mut self,
        scope: ScopeId,
        sym_id: SymbolId,
        id: EntryId,
        size: i32,
    ) -> Result<()> {
        let sym = self.symbol_mut(sym_id)?;
        sym.entries.push(id);
        if size == sym.type_size {
            sym.whole_count += 1;
            if sym.whole_count == 2 {
                let key = (sym.name.clone(), sym.dedup);
                self.scope_mut(scope)?.multi.insert(key, sym_id);
            }
        }
        Ok(())
    }

    /// The subsort of an entry (Ghidra `SymbolRange::getSubsort`).
    fn subsort(&self, entry: &EntryData) -> Result<EntrySubsort> {
        if self
            .symbol(entry.symbol)?
            .flags
            .contains(VarnodeFlags::ADDRTIED)
        {
            return Ok(EntrySubsort::default());
        }
        let range = entry
            .use_limit
            .first_range()
            .ok_or(SymbolError::EmptyUseLimit)?;
        Ok(EntrySubsort {
            use_index: range.space().index(),
            use_offset: range.first(),
        })
    }

    /// Ghidra `ScopeInternal::addDynamicMapInternal`.
    fn add_dynamic_internal(&mut self, scope: ScopeId, mut entry: EntryData) -> Result<EntryId> {
        let sym_id = entry.symbol;
        let size = entry.size;
        let data = self.scope_mut(scope)?;
        let seq = data.next_dynamic;
        data.next_dynamic += 1;
        entry.handle = Handle::Dynamic(seq);
        let id = self.push_entry(entry);
        self.scope_mut(scope)?.dynamic.insert(seq, id);
        self.note_entry(scope, sym_id, id, size)?;
        Ok(id)
    }

    /// Ghidra `Scope::addMap`: integrates a map entry (spec 4.4, six
    /// steps). The wrap check comes first, so a refused entry changes
    /// nothing.
    pub(crate) fn add_map(&mut self, scope: ScopeId, mut entry: EntryData) -> Result<EntryId> {
        let sym_id = entry.symbol;
        let EntryKind::Map { addr, .. } = entry.kind else {
            return Err(SymbolError::DecodeConflict);
        };
        if addr.is_invalid() {
            return self.add_unassigned(scope, sym_id);
        }
        let size = self.symbol(sym_id)?.bytes_consumed();
        let last = self.last_in_space(sym_id, addr, size)?;
        let pieces = self.join_pieces(sym_id, addr)?;
        let is_global = self.scope(scope)?.is_global();
        let global = self.global_scope()?;
        let in_global = self.scope(global)?.ranges.in_range(addr, 1);
        let mut add_flags = VarnodeFlags::empty();
        if is_global || in_global {
            add_flags |= VarnodeFlags::PERSIST;
        }
        if in_global {
            entry.use_limit.clear();
        }
        entry.extra_flags = VarnodeFlags::MAPPED;
        entry.offset = 0;
        entry.size = size;
        if entry.use_limit.is_empty() {
            add_flags |= VarnodeFlags::ADDRTIED | self.property(addr);
        }
        self.symbol_mut(sym_id)?.flags |= add_flags;
        let use_limit = entry.use_limit.clone();
        let id = self.add_map_internal(scope, entry, last)?;
        for piece in pieces {
            let piece_entry = EntryData {
                symbol: sym_id,
                kind: EntryKind::Map {
                    addr: piece.addr,
                    conflict: None,
                },
                use_limit: use_limit.clone(),
                properties: entry_props::MAP_ENTRY | entry_props::PIECE,
                extra_flags: piece.flags,
                offset: piece.offset,
                size: piece.size,
                handle: Handle::None,
                live: true,
            };
            self.add_map_internal(scope, piece_entry, piece.last)?;
        }
        Ok(id)
    }

    /// The piece entries of a join address (spec 4.4 step 6), each checked
    /// against the end of its space.
    fn join_pieces(&self, sym_id: SymbolId, addr: Address) -> Result<Vec<Piece>> {
        if !addr.is_join(&self.env.spaces) {
            return Ok(Vec::new());
        }
        let record = self.env.spaces.find_join(addr.offset())?;
        let sym = self.symbol(sym_id)?;
        let whole = sym.primitive_whole;
        let big = addr.is_big_endian(&self.env.spaces);
        let num = record.num_pieces();
        let mut out = Vec::new();
        let mut off: i32 = 0;
        for j in 0..num {
            let i = if big { j } else { num - 1 - j };
            let Some(vdat) = record.piece(i) else {
                continue;
            };
            let is_const = vdat
                .space()
                .and_then(|sp| self.env.spaces.space(sp))
                .is_some_and(|s| s.space_type() == bk_core::SpaceType::Constant);
            let size = i32::try_from(vdat.size).unwrap_or(i32::MAX);
            if !is_const {
                let mut flags = VarnodeFlags::empty();
                if whole {
                    flags = if i == 0 {
                        VarnodeFlags::PRECISHI
                    } else if i == num - 1 {
                        VarnodeFlags::PRECISLO
                    } else {
                        VarnodeFlags::PRECISLO | VarnodeFlags::PRECISHI
                    };
                }
                let paddr = vdat.addr();
                let last = self.last_in_space(sym_id, paddr, size)?;
                out.push(Piece {
                    addr: paddr,
                    size,
                    offset: off,
                    flags,
                    last,
                });
            }
            off = off.wrapping_add(size);
        }
        Ok(out)
    }

    /// Ghidra `Scope::addUnassigned` (with the read after `delete` replaced
    /// by the symbol it meant).
    fn add_unassigned(&mut self, scope: ScopeId, sym_id: SymbolId) -> Result<EntryId> {
        let is_global = self.scope(scope)?.is_global();
        let size = self.symbol(sym_id)?.bytes_consumed();
        let entry = EntryData {
            symbol: sym_id,
            kind: EntryKind::Unassigned,
            use_limit: RangeList::default(),
            properties: entry_props::UNASSIGNED_ENTRY,
            extra_flags: VarnodeFlags::empty(),
            offset: 0,
            size,
            handle: Handle::None,
            live: true,
        };
        let id = self.push_entry(entry);
        let sym = self.symbol_mut(sym_id)?;
        if is_global {
            sym.flags |= VarnodeFlags::PERSIST;
        }
        sym.entries.push(id);
        Ok(id)
    }

    /// Ghidra `Scope::addDynamic`.
    pub(crate) fn add_dynamic(&mut self, scope: ScopeId, mut entry: EntryData) -> Result<EntryId> {
        let sym_id = entry.symbol;
        let is_global = self.scope(scope)?.is_global();
        let sym = self.symbol_mut(sym_id)?;
        if is_global {
            sym.flags |= VarnodeFlags::PERSIST;
        }
        entry.size = sym.bytes_consumed();
        entry.extra_flags = VarnodeFlags::MAPPED;
        entry.offset = 0;
        self.add_dynamic_internal(scope, entry)
    }

    /// A map entry with a one-point use limit (or none).
    pub(crate) fn map_entry(sym: SymbolId, addr: Address, usepoint: Address) -> EntryData {
        let mut use_limit = RangeList::default();
        if let Some(space) = usepoint.space() {
            use_limit.insert_range(space, usepoint.offset(), usepoint.offset());
        }
        EntryData {
            symbol: sym,
            kind: EntryKind::Map {
                addr,
                conflict: None,
            },
            use_limit,
            properties: entry_props::MAP_ENTRY,
            extra_flags: VarnodeFlags::empty(),
            offset: 0,
            size: -1,
            handle: Handle::None,
            live: true,
        }
    }

    /// Maps a symbol to an address, valid at `usepoint` only when that is
    /// valid (Ghidra `addMapPoint`), in the symbol's scope.
    pub fn add_map_point(
        &mut self,
        sym: SymbolId,
        addr: Address,
        usepoint: Address,
    ) -> Result<EntryId> {
        let scope = self.symbol(sym)?.scope;
        self.add_map(scope, Self::map_entry(sym, addr, usepoint))
    }

    /// A dynamic entry with a one-point use limit (or none), added directly
    /// (Ghidra's `addDynamicSymbol` family bypasses `addDynamic`).
    pub(crate) fn direct_dynamic_entry(
        &mut self,
        scope: ScopeId,
        sym: SymbolId,
        hash: u64,
        size: i32,
        caddr: Address,
    ) -> Result<EntryId> {
        let mut use_limit = RangeList::default();
        if let Some(space) = caddr.space() {
            use_limit.insert_range(space, caddr.offset(), caddr.offset());
        }
        let entry = EntryData {
            symbol: sym,
            kind: EntryKind::Dynamic { hash },
            use_limit,
            properties: entry_props::DYNAMIC_ENTRY,
            extra_flags: VarnodeFlags::MAPPED,
            offset: 0,
            size,
            handle: Handle::None,
            live: true,
        };
        self.add_dynamic_internal(scope, entry)
    }
}

/// A join piece about to become an entry.
struct Piece {
    addr: Address,
    size: i32,
    offset: i32,
    flags: VarnodeFlags,
    last: u64,
}
