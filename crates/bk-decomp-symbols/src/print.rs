//! Ghidra's debugging text (`printEntries`, `printEntry`, `printBounds`;
//! database.cc 158–300, 2939–2952; spec 4.4) and the per-symbol helpers
//! `getMapEntry`, `getFirstWholeMap`, `getMapEntryPosition`,
//! `getSizedType`.

use std::fmt::Write as _;

use bk_core::Address;
use bk_decomp_types::{TypeFactory, TypeId};

use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::EntryKind;

impl Database {
    /// The shortcut character of an address's space as Ghidra prints it (a
    /// blank when none is assigned).
    pub(crate) fn shortcut_char(&self, addr: Address) -> char {
        addr.shortcut(&self.env.spaces).unwrap_or(' ')
    }

    /// Ghidra `SymbolEntry::printEntry` (each kind's form).
    pub fn print_entry(&self, entry: EntryId, types: &TypeFactory) -> Result<String> {
        let e = self.entry(entry)?;
        let sym = self.symbol(e.symbol)?;
        let ty = types.print_raw(sym.ty);
        let size = sym.type_size as u32;
        let bounds = e.use_limit.bounds(&self.env.spaces).to_string();
        let mut s = String::new();
        match e.kind {
            EntryKind::Map { addr, conflict } => {
                let _ = write!(
                    s,
                    "{} : {}{}:{size} {ty} : {bounds}",
                    sym.name,
                    self.shortcut_char(addr),
                    addr.raw(&self.env.spaces)
                );
                if conflict.is_some() {
                    s.push_str(" (conflicts)");
                }
            }
            EntryKind::Dynamic { .. } => {
                let _ = write!(s, "{} : <dynamic>:{size} {ty} : {bounds}", sym.name);
            }
            EntryKind::Unassigned => {
                let _ = write!(s, "{} : <unassigned>:{size} {ty}", sym.name);
            }
        }
        Ok(s)
    }

    /// Ghidra `ScopeInternal::printEntries`: `Scope <name>` and every map
    /// entry, space by space, in record order.
    pub fn print_entries(&self, scope: ScopeId, types: &TypeFactory) -> Result<String> {
        let data = self.scope(scope)?;
        let mut s = format!("Scope {}\n", data.name);
        for map in data.maps.iter().flatten() {
            for (_, entry) in map.records() {
                s.push_str(&self.print_entry(entry, types)?);
            }
        }
        Ok(s)
    }

    /// Ghidra `Scope::printBounds`: the owned ranges, one per line, or
    /// `all`.
    pub fn print_bounds(&self, scope: ScopeId) -> Result<String> {
        Ok(self.scope(scope)?.ranges.bounds(&self.env.spaces).to_string())
    }

    /// The map entries of one space of a scope in record order (what
    /// `MapState::gatherSymbols` walks).
    pub fn entries_in_record_order(&self, scope: ScopeId, space_index: u32) -> Result<Vec<EntryId>> {
        Ok(self
            .scope(scope)?
            .space_map(space_index)
            .map(|m| m.records().map(|(_, e)| e).collect())
            .unwrap_or_default())
    }

    /// Every map entry of a scope, space by space in record order (Ghidra
    /// `MapIterator`).
    pub fn map_entries(&self, scope: ScopeId) -> Result<Vec<EntryId>> {
        let data = self.scope(scope)?;
        Ok(data
            .maps
            .iter()
            .flatten()
            .flat_map(|m| m.records().map(|(_, e)| e))
            .collect())
    }

    /// Ghidra `getMapEntry(addr)`: the first map entry (in entry order) in
    /// `addr`'s space that contains it. The distance is truncated to 32 bits
    /// as Ghidra does.
    pub fn map_entry_at(&self, sym: SymbolId, addr: Address) -> Result<Option<EntryId>> {
        for &id in &self.symbol(sym)?.entries {
            let e = self.entry(id)?;
            let EntryKind::Map { addr: start, .. } = e.kind else {
                continue;
            };
            if !e.is_map_entry() || addr.space() != start.space() || addr.offset() < start.offset() {
                continue;
            }
            let diff = addr.offset().wrapping_sub(start.offset()) as i32;
            if diff >= e.size {
                continue;
            }
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// Ghidra `getFirstWholeMap`: entry 0 (not checked to be whole).
    pub fn first_whole_map(&self, sym: SymbolId) -> Result<EntryId> {
        let data = self.symbol(sym)?;
        data.entries.first().copied().ok_or_else(|| SymbolError::NoMapping {
            name: data.name.to_string(),
        })
    }

    /// Ghidra `getMapEntryPosition`, with its quirk: it counts preceding
    /// entries only when *the argument* is whole-sized, so a piece gets 0
    /// (spec 4.5). `None` when the entry is not the symbol's.
    pub fn map_entry_position(&self, sym: SymbolId, entry: EntryId) -> Result<Option<i32>> {
        let data = self.symbol(sym)?;
        let whole = self.entry(entry)?.size == data.type_size;
        let mut pos = 0;
        for &id in &data.entries {
            if id == entry {
                return Ok(Some(pos));
            }
            if whole {
                pos += 1;
            }
        }
        Ok(None)
    }

    /// Ghidra `getSizedType`: the piece of the symbol's type that matches
    /// `size` bytes at `addr`.
    pub fn sized_type(&self, entry: EntryId, addr: Address, size: i32, types: &mut TypeFactory) -> Result<Option<TypeId>> {
        let e = self.entry(entry)?;
        let sym = self.symbol(e.symbol)?;
        let off = match e.kind {
            EntryKind::Map { addr: start, .. } => {
                (addr.offset().wrapping_sub(start.offset()) as i32).wrapping_add(e.offset)
            }
            _ => e.offset,
        };
        Ok(types.exact_piece(sym.ty, off, size)?)
    }
}
