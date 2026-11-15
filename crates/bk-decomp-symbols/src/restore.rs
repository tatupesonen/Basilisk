//! A scope as plain data, and rebuilding a scope exactly from it (spec 6.4):
//! the symbols with their ids, dedup numbers and entries, the category
//! slots, the multi-entry set, each space's entry map with its record list
//! and fragment multiset, and the dynamic list — the orders that follow
//! insertion history and cannot be recomputed. D00's `@scope` (version 2)
//! carries exactly this; D11 can rebuild a function's scope from a dump.

use bk_core::{Address, RangeList, SpaceId};
use bk_decomp_types::{TypeFactory, TypeId};

use crate::database::Database;
use crate::entrymap::EntrySubsort;
use crate::error::{Result, SymbolError};
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{EntryData, EntryKind, Handle, SpaceMap, SymbolData, SymbolKind};
use crate::scope::add::type_facts;

/// One entry of a symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryImage {
    /// Kind and storage.
    pub kind: EntryKind,
    /// The use limit.
    pub use_limit: RangeList,
    /// Flags specific to the storage.
    pub extra_flags: VarnodeFlags,
    /// Property bits (`map_entry` …).
    pub properties: u32,
    /// Offset into the symbol.
    pub offset: i32,
    /// Size of the (piece of) storage.
    pub size: i32,
}

/// One symbol with its entries in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolImage {
    /// Ghidra's id.
    pub ghidra_id: u64,
    /// Name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Type.
    pub ty: TypeId,
    /// Kind (data the dump does not carry takes defaults).
    pub kind: SymbolKind,
    /// Flags.
    pub flags: VarnodeFlags,
    /// Display flags.
    pub disp: u32,
    /// Category.
    pub category: i16,
    /// Position in the category.
    pub catindex: u32,
    /// Dedup number.
    pub dedup: u32,
    /// Whole-entry count.
    pub whole_count: u32,
    /// Entries in the symbol's order.
    pub entries: Vec<EntryImage>,
}

/// An entry named by symbol index and entry index (the dump's
/// `s<id>:<index>`).
pub type EntryRef = (usize, usize);

/// One record of a space's entry map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordImage {
    /// The space.
    pub space: SpaceId,
    /// The entry.
    pub entry: EntryRef,
    /// First offset.
    pub first: u64,
    /// Last offset.
    pub last: u64,
    /// The subsort stored at insertion.
    pub subsort: EntrySubsort,
}

/// One fragment of a space's entry map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentImage {
    /// The space.
    pub space: SpaceId,
    /// First offset of the piece.
    pub first: u64,
    /// Last offset of the piece.
    pub last: u64,
    /// The record's entry.
    pub entry: EntryRef,
}

/// A scope as plain data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeImage {
    /// Ghidra's scope id.
    pub ghidra_id: u64,
    /// The symbol id counter.
    pub next_unique_id: u64,
    /// The display name.
    pub display_name: String,
    /// The symbols.
    pub symbols: Vec<SymbolImage>,
    /// Category slots (symbol indices).
    pub categories: Vec<Vec<Option<usize>>>,
    /// The multi-entry set in order.
    pub multi: Vec<usize>,
    /// Entry-map records, space by space in record order.
    pub records: Vec<RecordImage>,
    /// Fragments, space by space in multiset order.
    pub fragments: Vec<FragmentImage>,
    /// The dynamic list in order.
    pub dynamic: Vec<EntryRef>,
}

fn bad(what: &'static str) -> SymbolError {
    SymbolError::Limit(what)
}

impl Database {
    /// Fills an empty scope from an image (symbols, entries, orders).
    pub fn restore_scope(
        &mut self,
        scope: ScopeId,
        image: &ScopeImage,
        types: &TypeFactory,
    ) -> Result<()> {
        if !self.scope(scope)?.names.is_empty() {
            return Err(bad("restore into a non-empty scope"));
        }
        let mut sym_ids = Vec::with_capacity(image.symbols.len());
        let mut entry_ids: Vec<Vec<EntryId>> = Vec::with_capacity(image.symbols.len());
        for s in &image.symbols {
            let facts = type_facts(types, s.ty)?;
            let id = SymbolId(self.symbols.len() as u32);
            let mut entries = Vec::with_capacity(s.entries.len());
            for e in &s.entries {
                let eid = EntryId(self.entries.len() as u32);
                self.entries.push(EntryData {
                    symbol: id,
                    kind: e.kind,
                    use_limit: e.use_limit.clone(),
                    properties: e.properties,
                    extra_flags: e.extra_flags,
                    offset: e.offset,
                    size: e.size,
                    handle: Handle::None,
                    live: true,
                });
                entries.push(eid);
            }
            self.symbols.push(SymbolData {
                scope,
                kind: s.kind.clone(),
                name: s.name.as_str().into(),
                display_name: s.display_name.as_str().into(),
                ty: s.ty,
                type_size: facts.size,
                type_unknown: facts.unknown,
                primitive_whole: facts.primitive_whole,
                dedup: s.dedup,
                flags: s.flags,
                disp: s.disp,
                category: s.category,
                catindex: s.catindex,
                ghidra_id: s.ghidra_id,
                entries: entries.clone(),
                whole_count: s.whole_count,
                depth_scope: None,
                depth: 0,
                name_provenance: bk_core::Provenance::Analysis,
                type_provenance: bk_core::Provenance::Analysis,
                live: true,
            });
            self.scope_mut(scope)?
                .names
                .insert((s.name.as_str().into(), s.dedup), id);
            sym_ids.push(id);
            entry_ids.push(entries);
        }
        let entry_of = |r: EntryRef| -> Result<EntryId> {
            entry_ids
                .get(r.0)
                .and_then(|v| v.get(r.1))
                .copied()
                .ok_or(bad("entry reference"))
        };
        let sym_of = |i: usize| -> Result<SymbolId> {
            sym_ids.get(i).copied().ok_or(bad("symbol reference"))
        };
        // Entry maps, space by space.
        let mut spaces: Vec<SpaceId> = image.records.iter().map(|r| r.space).collect();
        spaces.dedup();
        for space in spaces {
            let recs: Vec<&RecordImage> =
                image.records.iter().filter(|r| r.space == space).collect();
            let parts: Vec<(EntryId, u64, u64, EntrySubsort)> = recs
                .iter()
                .map(|r| Ok((entry_of(r.entry)?, r.first, r.last, r.subsort)))
                .collect::<Result<_>>()?;
            let frags: Vec<(u64, u64, usize)> = image
                .fragments
                .iter()
                .filter(|f| f.space == space)
                .map(|f| {
                    let i = recs
                        .iter()
                        .position(|r| r.entry == f.entry)
                        .ok_or(bad("fragment of no record"))?;
                    Ok((f.first, f.last, i))
                })
                .collect::<Result<_>>()?;
            let map = SpaceMap::from_parts(&parts, &frags).ok_or(bad("fragment order"))?;
            let handles: Vec<(EntryId, crate::entrymap::RecordId)> =
                map.records().map(|(rec, e)| (e, rec)).collect();
            let data = self.scope_mut(scope)?;
            let slot = space.index() as usize;
            if data.maps.len() <= slot {
                data.maps.resize(slot + 1, None);
            }
            if let Some(m) = data.maps.get_mut(slot) {
                *m = Some(map);
            }
            for (e, rec) in handles {
                self.entry_mut(e)?.handle = Handle::Map(space.index(), rec);
            }
        }
        for (seq, r) in image.dynamic.iter().enumerate() {
            let e = entry_of(*r)?;
            self.entry_mut(e)?.handle = Handle::Dynamic(seq as u64);
            self.scope_mut(scope)?.dynamic.insert(seq as u64, e);
        }
        let mut categories = Vec::with_capacity(image.categories.len());
        for slots in &image.categories {
            categories.push(
                slots
                    .iter()
                    .map(|s| s.map(&sym_of).transpose())
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        let mut multi = std::collections::BTreeMap::new();
        for &i in &image.multi {
            let id = sym_of(i)?;
            let s = self.symbol(id)?;
            multi.insert((s.name.clone(), s.dedup), id);
        }
        let data = self.scope_mut(scope)?;
        data.categories = categories;
        data.multi = multi;
        data.next_dynamic = image.dynamic.len() as u64;
        data.next_unique_id = image.next_unique_id;
        data.display_name = image.display_name.as_str().into();
        Ok(())
    }

    /// A scope as plain data, symbols in name order.
    pub fn scope_image(&self, scope: ScopeId) -> Result<ScopeImage> {
        let data = self.scope(scope)?;
        let order: Vec<SymbolId> = data.names.values().copied().collect();
        let index_of = |s: SymbolId| order.iter().position(|x| *x == s);
        let entry_ref = |e: EntryId| -> Option<EntryRef> {
            let sym = self.entry(e).ok()?.symbol;
            let i = index_of(sym)?;
            let j = self
                .symbol(sym)
                .ok()?
                .entries
                .iter()
                .position(|x| *x == e)?;
            Some((i, j))
        };
        let mut symbols = Vec::with_capacity(order.len());
        for &id in &order {
            let s = self.symbol(id)?;
            let entries = s
                .entries
                .iter()
                .map(|e| {
                    let d = self.entry(*e)?;
                    Ok(EntryImage {
                        kind: d.kind,
                        use_limit: d.use_limit.clone(),
                        extra_flags: d.extra_flags,
                        properties: d.properties,
                        offset: d.offset,
                        size: d.size,
                    })
                })
                .collect::<Result<_>>()?;
            symbols.push(SymbolImage {
                ghidra_id: s.ghidra_id,
                name: s.name.to_string(),
                display_name: s.display_name.to_string(),
                ty: s.ty,
                kind: s.kind.clone(),
                flags: s.flags,
                disp: s.disp,
                category: s.category,
                catindex: s.catindex,
                dedup: s.dedup,
                whole_count: s.whole_count,
                entries,
            });
        }
        let mut records = Vec::new();
        let mut fragments = Vec::new();
        for (i, map) in data.maps.iter().enumerate() {
            let Some(map) = map else { continue };
            let space = SpaceId::new(i as u32);
            for (rec, e) in map.records() {
                let (a, b) = map.bounds(rec).ok_or(bad("record"))?;
                records.push(RecordImage {
                    space,
                    entry: entry_ref(e).ok_or(bad("entry reference"))?,
                    first: a,
                    last: b,
                    subsort: map.subsort(rec).unwrap_or_default(),
                });
            }
            for f in map.fragments() {
                fragments.push(FragmentImage {
                    space,
                    first: f.first,
                    last: f.last,
                    entry: entry_ref(f.value).ok_or(bad("entry reference"))?,
                });
            }
        }
        Ok(ScopeImage {
            ghidra_id: data.ghidra_id,
            next_unique_id: data.next_unique_id,
            display_name: data.display_name.to_string(),
            symbols,
            categories: data
                .categories
                .iter()
                .map(|slots| slots.iter().map(|s| s.and_then(index_of)).collect())
                .collect(),
            multi: data.multi.values().filter_map(|s| index_of(*s)).collect(),
            records,
            fragments,
            dynamic: data
                .dynamic
                .values()
                .filter_map(|e| entry_ref(*e))
                .collect(),
        })
    }
}

/// The kind of a symbol from the dump's kind name, with defaults for the
/// data the dump does not carry.
pub fn kind_from_name(name: &str, min_funcsymbol_size: i32) -> SymbolKind {
    match name {
        "function" => SymbolKind::Function {
            consume_size: min_funcsymbol_size,
        },
        "equate" => SymbolKind::Equate { value: 0 },
        "unionfacet" => SymbolKind::UnionFacet {
            field: -1,
            addr_based: false,
        },
        "label" => SymbolKind::Label,
        "externref" => SymbolKind::ExternRef {
            ref_addr: Address::INVALID,
        },
        _ => SymbolKind::Plain,
    }
}

/// The dump's kind name of a symbol.
pub fn kind_name(kind: &SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function { .. } => "function",
        SymbolKind::Equate { .. } => "equate",
        SymbolKind::UnionFacet { .. } => "unionfacet",
        SymbolKind::Label => "label",
        SymbolKind::ExternRef { .. } => "externref",
        SymbolKind::Plain => "symbol",
    }
}
