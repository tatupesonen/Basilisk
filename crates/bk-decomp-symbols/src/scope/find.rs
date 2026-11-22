//! Look-ups within one scope (Ghidra `ScopeInternal::find*`,
//! `findByName`, `isNameUsed`; database.cc 2373–2614; spec 4.6).

use bk_core::Address;

use crate::database::Database;
use crate::entrymap::{EntrySubsort, Fragment, Subsort};
use crate::error::Result;
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{EntryData, SpaceMap, SymbolKind};

type Frag = Fragment<EntryId, u64, EntrySubsort>;

fn use_subsort(usepoint: Address) -> EntrySubsort {
    match usepoint.space() {
        Some(space) => EntrySubsort {
            use_index: space.index(),
            use_offset: usepoint.offset(),
        },
        None => EntrySubsort::LATEST,
    }
}

impl Database {
    /// The entry map of `addr`'s space in a scope.
    pub(crate) fn space_map_of(&self, scope: ScopeId, addr: Address) -> Result<Option<&SpaceMap>> {
        let data = self.scope(scope)?;
        Ok(addr.space().and_then(|s| data.space_map(s.index())))
    }

    /// Ghidra `SymbolEntry::inUse`.
    pub fn entry_in_use(&self, entry: &EntryData, usepoint: Address) -> bool {
        let addrtied = self
            .symbol(entry.symbol)
            .is_ok_and(|s| s.flags.contains(VarnodeFlags::ADDRTIED));
        if addrtied {
            return true;
        }
        if usepoint.is_invalid() {
            return false;
        }
        entry.use_limit.in_range(usepoint, 1)
    }

    fn frag_entry(&self, frag: &Frag) -> Option<(EntryId, &EntryData)> {
        self.entry(frag.value).ok().map(|e| (frag.value, e))
    }

    /// Ghidra `findAddr`: the entry starting exactly at `addr` that is in
    /// use at `usepoint`, walking the piece backwards.
    pub fn find_addr(
        &self,
        scope: ScopeId,
        addr: Address,
        usepoint: Address,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let hit = map
            .find_sub(addr.offset(), EntrySubsort::EARLIEST, use_subsort(usepoint))
            .rev()
            .filter_map(|f| self.frag_entry(&f))
            .find(|(_, e)| {
                e.addr().map(Address::offset) == Some(addr.offset())
                    && self.entry_in_use(e, usepoint)
            });
        Ok(hit.map(|(id, _)| id))
    }

    /// Ghidra `findContainer`: the smallest entry in use that contains the
    /// `size` bytes at `addr` (the first of equal size, walking backwards).
    pub fn find_container(
        &self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let end = addr
            .offset()
            .wrapping_add(i64::from(size) as u64)
            .wrapping_sub(1);
        let mut best = None;
        let mut oldsize: i32 = -1;
        for frag in map
            .find_sub(addr.offset(), EntrySubsort::EARLIEST, use_subsort(usepoint))
            .rev()
        {
            let Some((id, entry)) = self.frag_entry(&frag) else {
                continue;
            };
            if entry.last_offset().is_some_and(|last| last >= end)
                && (entry.size < oldsize || oldsize == -1)
                && self.entry_in_use(entry, usepoint)
            {
                best = Some(id);
                if entry.size == size {
                    break;
                }
                oldsize = entry.size;
            }
        }
        Ok(best)
    }

    /// Ghidra `findClosestFit`.
    pub fn find_closest_fit(
        &self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let mut best = None;
        let mut olddiff: i32 = -10000;
        for frag in map
            .find_sub(addr.offset(), EntrySubsort::EARLIEST, use_subsort(usepoint))
            .rev()
        {
            let Some((id, entry)) = self.frag_entry(&frag) else {
                continue;
            };
            if entry
                .last_offset()
                .is_some_and(|last| last >= addr.offset())
            {
                let newdiff = entry.size.wrapping_sub(size);
                let better = (olddiff < 0 && newdiff > olddiff)
                    || (olddiff >= 0 && newdiff >= 0 && newdiff < olddiff);
                if better && self.entry_in_use(entry, usepoint) {
                    best = Some(id);
                    if newdiff == 0 {
                        break;
                    }
                    olddiff = newdiff;
                }
            }
        }
        Ok(best)
    }

    /// Ghidra `findFunction`: the first function symbol whose entry starts
    /// exactly at `addr`, walking the piece forwards.
    pub fn find_function(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        for frag in map.find(addr.offset()) {
            let Some((_, entry)) = self.frag_entry(&frag) else {
                continue;
            };
            if entry.addr().map(Address::offset) == Some(addr.offset())
                && self.symbol(entry.symbol)?.is_function()
            {
                return Ok(Some(entry.symbol));
            }
        }
        Ok(None)
    }

    /// Ghidra `findExternalRef`: the symbol of the first entry starting at
    /// `addr` if it is an external reference, else none.
    pub fn find_external_ref(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        for frag in map.find(addr.offset()) {
            let Some((_, entry)) = self.frag_entry(&frag) else {
                continue;
            };
            if entry.addr().map(Address::offset) == Some(addr.offset()) {
                let is_ref = matches!(
                    self.symbol(entry.symbol)?.kind,
                    SymbolKind::ExternRef { .. }
                );
                return Ok(is_ref.then_some(entry.symbol));
            }
        }
        Ok(None)
    }

    /// Ghidra `findCodeLabel`.
    pub fn find_code_label(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        for frag in map
            .find_sub(addr.offset(), EntrySubsort::EARLIEST, use_subsort(addr))
            .rev()
        {
            let Some((_, entry)) = self.frag_entry(&frag) else {
                continue;
            };
            if entry.addr().map(Address::offset) == Some(addr.offset())
                && self.entry_in_use(entry, addr)
            {
                let is_label = matches!(self.symbol(entry.symbol)?.kind, SymbolKind::Label);
                return Ok(is_label.then_some(entry.symbol));
            }
        }
        Ok(None)
    }

    /// Ghidra `findOverlap`.
    pub fn find_overlap(
        &self,
        scope: ScopeId,
        addr: Address,
        size: i32,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let end = addr
            .offset()
            .wrapping_add(i64::from(size) as u64)
            .wrapping_sub(1);
        Ok(map
            .find_overlap(addr.offset(), end)
            .and_then(|pos| map.fragment(pos))
            .map(|f| f.value))
    }

    /// Ghidra `findSymbolBefore`.
    pub fn find_symbol_before(
        &self,
        scope: ScopeId,
        addr: Address,
        usepoint: Address,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let Some(pos) = map.find_last_before(addr.offset()) else {
            return Ok(None);
        };
        Ok(map
            .iter_back_from(pos)
            .filter_map(|f| self.frag_entry(&f))
            .find(|(_, e)| self.entry_in_use(e, usepoint))
            .map(|(id, _)| id))
    }

    /// Ghidra `findSymbolAfter`.
    pub fn find_symbol_after(
        &self,
        scope: ScopeId,
        addr: Address,
        usepoint: Address,
    ) -> Result<Option<EntryId>> {
        let Some(map) = self.space_map_of(scope, addr)? else {
            return Ok(None);
        };
        let Some(pos) = map.find_first_after(addr.offset()) else {
            return Ok(None);
        };
        Ok(map
            .iter_from(pos)
            .filter_map(|f| self.frag_entry(&f))
            .find(|(_, e)| self.entry_in_use(e, usepoint))
            .map(|(id, _)| id))
    }

    /// Ghidra `findByName`: the symbols of that name in this scope, in
    /// dedup order.
    pub fn find_by_name(&self, scope: ScopeId, name: &str) -> Result<Vec<SymbolId>> {
        let data = self.scope(scope)?;
        let lo: (Box<str>, u32) = (name.into(), 0);
        let hi: (Box<str>, u32) = (name.into(), u32::MAX);
        Ok(data.names.range(lo..=hi).map(|(_, id)| *id).collect())
    }

    /// Whether a symbol of this name exists in this scope.
    pub(crate) fn name_exists(&self, scope: ScopeId, name: &str) -> bool {
        self.scope(scope).is_ok_and(|data| {
            let lo: (Box<str>, u32) = (name.into(), 0);
            data.names
                .range(lo..)
                .next()
                .is_some_and(|((n, _), _)| n.as_ref() == name)
        })
    }

    /// Ghidra `ScopeInternal::isNameUsed`: here, else in the parents up to
    /// (not including) `stop` and never in the global scope.
    pub fn is_name_used(&self, scope: ScopeId, name: &str, stop: Option<ScopeId>) -> Result<bool> {
        let mut cur = scope;
        for _ in 0..=crate::error::limits::MAX_SCOPE_DEPTH {
            if self.name_exists(cur, name) {
                return Ok(true);
            }
            let Some(parent) = self.scope(cur)?.parent else {
                return Ok(false);
            };
            if Some(parent) == stop || self.scope(parent)?.parent.is_none() {
                return Ok(false);
            }
            cur = parent;
        }
        Ok(false)
    }

    /// Ghidra `Scope::inScope`: the scope owns all `size` bytes at `addr`.
    pub fn in_scope(&self, scope: ScopeId, addr: Address, size: i32) -> Result<bool> {
        Ok(self
            .scope(scope)?
            .ranges
            .in_range(addr, u64::try_from(size).unwrap_or(0)))
    }
}
