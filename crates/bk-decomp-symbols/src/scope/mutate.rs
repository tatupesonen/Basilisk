//! Renaming, retyping, attributes, categories and removal (database.cc
//! 2126–2366, 3009–3030, 1547–1600; spec 4.9).

use bk_core::{Address, Provenance};
use bk_decomp_types::{Metatype, TypeFactory, TypeId};

use super::add::{stripped, type_facts};
use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::{VarnodeFlags, category, disp};
use crate::ids::{ScopeId, SymbolId};
use crate::model::{EntryKind, Handle};

impl Database {
    fn name_key(&self, sym: SymbolId) -> Result<(Box<str>, u32)> {
        let s = self.symbol(sym)?;
        Ok((s.name.clone(), s.dedup))
    }

    /// Ghidra `removeSymbolMappings`: every entry out of its map or the
    /// dynamic list.
    pub fn remove_symbol_mappings(&mut self, sym: SymbolId) -> Result<()> {
        let data = self.symbol(sym)?;
        let scope = data.scope;
        let entries = data.entries.clone();
        if data.whole_count > 1 {
            let key = self.name_key(sym)?;
            self.scope_mut(scope)?.multi.remove(&key);
        }
        for id in entries {
            let handle = self.entry(id)?.handle;
            match handle {
                Handle::Map(space, record) => {
                    if let Some(Some(map)) = self.scope_mut(scope)?.maps.get_mut(space as usize) {
                        map.erase(record);
                    }
                }
                Handle::Dynamic(seq) => {
                    self.scope_mut(scope)?.dynamic.remove(&seq);
                }
                Handle::None => {}
            }
            if let Ok(entry) = self.entry_mut(id) {
                entry.live = false;
            }
        }
        let data = self.symbol_mut(sym)?;
        data.whole_count = 0;
        data.entries.clear();
        Ok(())
    }

    /// Empties a symbol's category slot and drops trailing empty slots.
    fn leave_category(&mut self, sym: SymbolId) -> Result<()> {
        let data = self.symbol(sym)?;
        let (scope, cat, index) = (data.scope, data.category, data.catindex);
        if cat < 0 {
            return Ok(());
        }
        if let Some(list) = self.scope_mut(scope)?.categories.get_mut(cat as usize) {
            if let Some(slot) = list.get_mut(index as usize) {
                *slot = None;
            }
            while matches!(list.last(), Some(None)) {
                list.pop();
            }
        }
        Ok(())
    }

    /// Ghidra `removeSymbol`.
    pub fn remove_symbol(&mut self, sym: SymbolId) -> Result<()> {
        self.leave_category(sym)?;
        self.remove_symbol_mappings(sym)?;
        let key = self.name_key(sym)?;
        let scope = self.symbol(sym)?.scope;
        self.scope_mut(scope)?.names.remove(&key);
        self.symbol_mut(sym)?.live = false;
        Ok(())
    }

    /// Ghidra `renameSymbol`, with the new name's provenance. The resolution
    /// depth cache is not reset (spec 4.5).
    pub fn rename_symbol_as(&mut self, sym: SymbolId, name: &str, provenance: Provenance) -> Result<()> {
        let scope = self.symbol(sym)?.scope;
        let old = self.name_key(sym)?;
        let whole = self.symbol(sym)?.whole_count;
        self.scope_mut(scope)?.names.remove(&old);
        let dedup = match self.free_dedup(scope, name) {
            Ok(d) => d,
            Err(e) => {
                // Refused: put the symbol back as it was.
                self.scope_mut(scope)?.names.insert(old, sym);
                return Err(e);
            }
        };
        if whole > 1 {
            self.scope_mut(scope)?.multi.remove(&old);
        }
        let data = self.symbol_mut(sym)?;
        data.name = name.into();
        data.display_name = name.into();
        data.dedup = dedup;
        data.name_provenance = provenance;
        let key = (data.name.clone(), dedup);
        let scope_data = self.scope_mut(scope)?;
        scope_data.names.insert(key.clone(), sym);
        if whole > 1 {
            scope_data.multi.insert(key, sym);
        }
        Ok(())
    }

    /// Ghidra `renameSymbol` (the engine's own rename: `Analysis`).
    pub fn rename_symbol(&mut self, sym: SymbolId, name: &str) -> Result<()> {
        self.rename_symbol_as(sym, name, Provenance::Analysis)
    }

    fn set_type(&mut self, sym: SymbolId, ty: TypeId, types: &TypeFactory) -> Result<()> {
        let facts = type_facts(types, ty)?;
        let data = self.symbol_mut(sym)?;
        data.ty = ty;
        data.type_size = facts.size;
        data.type_unknown = facts.unknown;
        data.primitive_whole = facts.primitive_whole;
        Ok(())
    }

    /// Ghidra `retypeSymbol` with the type's provenance (spec 4.9).
    pub fn retype_symbol_as(&mut self, sym: SymbolId, ty: TypeId, provenance: Provenance, types: &TypeFactory) -> Result<()> {
        let ty = stripped(types, ty);
        let new_size = type_facts(types, ty)?.size;
        let data = self.symbol(sym)?;
        if data.type_size == new_size || data.entries.is_empty() {
            self.set_type(sym, ty, types)?;
            let data = self.symbol_mut(sym)?;
            data.type_provenance = provenance;
            data.check_size_type_lock();
            return Ok(());
        }
        if let [only] = data.entries[..] {
            let entry = self.entry(only)?;
            let addrtied = data.flags.contains(VarnodeFlags::ADDRTIED);
            if let (EntryKind::Map { addr, .. }, true) = (entry.kind, entry.is_map_entry() && addrtied) {
                // Basilisk checks the re-added entry first (Ghidra would
                // leave the symbol unmapped and throw).
                let consumed = if data.is_function() { data.bytes_consumed() } else { new_size };
                let last = addr.add(&self.env.spaces, i64::from(consumed) - 1);
                if last.offset() < addr.offset() {
                    return Err(SymbolError::BeyondSpace {
                        name: data.name.to_string(),
                    });
                }
                let scope = data.scope;
                if let Handle::Map(space, record) = entry.handle
                    && let Some(Some(map)) = self.scope_mut(scope)?.maps.get_mut(space as usize)
                {
                    map.erase(record);
                }
                self.entry_mut(only)?.live = false;
                {
                    let data = self.symbol_mut(sym)?;
                    data.entries.pop();
                    data.whole_count = 0;
                }
                self.set_type(sym, ty, types)?;
                let data = self.symbol_mut(sym)?;
                data.type_provenance = provenance;
                data.check_size_type_lock();
                self.add_map_point(sym, addr, Address::INVALID)?;
                return Ok(());
            }
        }
        Err(SymbolError::Retype {
            name: data.name.to_string(),
        })
    }

    /// Ghidra `retypeSymbol` (the engine's own retype: `Analysis`).
    pub fn retype_symbol(&mut self, sym: SymbolId, ty: TypeId, types: &TypeFactory) -> Result<()> {
        self.retype_symbol_as(sym, ty, Provenance::Analysis, types)
    }

    /// Ghidra `setAttribute` (masked to the settable flags).
    pub fn set_attribute(&mut self, sym: SymbolId, attr: VarnodeFlags) -> Result<()> {
        let data = self.symbol_mut(sym)?;
        data.flags |= attr & VarnodeFlags::SETTABLE;
        data.check_size_type_lock();
        Ok(())
    }

    /// Ghidra `clearAttribute`.
    pub fn clear_attribute(&mut self, sym: SymbolId, attr: VarnodeFlags) -> Result<()> {
        let data = self.symbol_mut(sym)?;
        data.flags.remove(attr & VarnodeFlags::SETTABLE);
        data.check_size_type_lock();
        Ok(())
    }

    /// Ghidra `setDisplayFormat`: replaces the low three display bits (the
    /// value is ORed in unmasked, as Ghidra does).
    pub fn set_display_format(&mut self, sym: SymbolId, format: u32) -> Result<()> {
        let data = self.symbol_mut(sym)?;
        data.disp = (data.disp & 0xffff_fff8) | format;
        Ok(())
    }

    /// Ghidra `setIsolated`.
    pub fn set_isolated(&mut self, sym: SymbolId, isolated: bool) -> Result<()> {
        let data = self.symbol_mut(sym)?;
        if isolated {
            data.disp |= disp::ISOLATE;
            data.flags |= VarnodeFlags::TYPELOCK;
            data.check_size_type_lock();
        } else {
            data.disp &= !disp::ISOLATE;
        }
        Ok(())
    }

    /// Ghidra `setThisPointer`.
    pub fn set_this_pointer(&mut self, sym: SymbolId, value: bool) -> Result<()> {
        let data = self.symbol_mut(sym)?;
        if value {
            data.disp |= disp::IS_THIS_PTR;
        } else {
            data.disp &= !disp::IS_THIS_PTR;
        }
        Ok(())
    }

    /// Ghidra `setMergeProblems`.
    pub fn set_merge_problems(&mut self, sym: SymbolId) -> Result<()> {
        self.symbol_mut(sym)?.disp |= disp::MERGE_PROBLEMS;
        Ok(())
    }

    /// Ghidra `setCategory`: category 0 keeps `index`, others append.
    pub fn set_category(&mut self, sym: SymbolId, cat: i16, index: u32) -> Result<()> {
        self.leave_category(sym)?;
        let scope = self.symbol(sym)?.scope;
        {
            let data = self.symbol_mut(sym)?;
            data.category = cat;
            data.catindex = index;
        }
        if cat < 0 {
            return Ok(());
        }
        let scope_data = self.scope_mut(scope)?;
        let c = cat as usize;
        while scope_data.categories.len() <= c {
            scope_data.categories.push(Vec::new());
        }
        let Some(list) = scope_data.categories.get_mut(c) else {
            return Ok(());
        };
        let index = if cat > 0 {
            u32::try_from(list.len()).map_err(|_| SymbolError::Limit("category index"))?
        } else {
            index
        };
        if u64::from(index) >= crate::error::limits::MAX_SYMBOLS {
            return Err(SymbolError::Limit("category index"));
        }
        while list.len() <= index as usize {
            list.push(None);
        }
        if let Some(slot) = list.get_mut(index as usize) {
            *slot = Some(sym);
        }
        self.symbol_mut(sym)?.catindex = index;
        Ok(())
    }

    /// Ghidra `categorySanity`: a category with an empty slot is dissolved.
    pub fn category_sanity(&mut self, scope: ScopeId) -> Result<()> {
        let count = self.scope(scope)?.categories.len();
        for i in 0..count {
            let list = self
                .scope(scope)?
                .categories
                .get(i)
                .cloned()
                .unwrap_or_default();
            if list.is_empty() || list.iter().all(Option::is_some) {
                continue;
            }
            for sym in list.into_iter().flatten() {
                self.set_category(sym, category::NONE, 0)?;
            }
        }
        Ok(())
    }

    fn symbols_in_name_order(&self, scope: ScopeId) -> Result<Vec<SymbolId>> {
        Ok(self.scope(scope)?.names.values().copied().collect())
    }

    /// Ghidra `ScopeInternal::clear`: every symbol removed, ids restart.
    pub fn clear_scope(&mut self, scope: ScopeId) -> Result<()> {
        for sym in self.symbols_in_name_order(scope)? {
            self.remove_symbol(sym)?;
        }
        self.scope_mut(scope)?.next_unique_id = 0;
        Ok(())
    }

    /// Ghidra `clearCategory`: a category's symbols (in slot order, empty
    /// slots skipped where Ghidra dereferences them), or with `cat < 0`
    /// every symbol without a category.
    pub fn clear_category(&mut self, scope: ScopeId, cat: i16) -> Result<()> {
        if cat >= 0 {
            let list = self.scope(scope)?.category(cat).to_vec();
            for sym in list.into_iter().flatten() {
                self.remove_symbol(sym)?;
            }
            return Ok(());
        }
        for sym in self.symbols_in_name_order(scope)? {
            if self.symbol(sym)?.category < 0 {
                self.remove_symbol(sym)?;
            }
        }
        Ok(())
    }

    /// Ghidra `ScopeInternal::clearUnlocked`.
    pub(crate) fn clear_unlocked_scope(&mut self, scope: ScopeId, types: &mut TypeFactory) -> Result<()> {
        for sym in self.symbols_in_name_order(scope)? {
            let data = self.symbol(sym)?;
            if data.is_type_locked() {
                if !data.is_name_locked() && !data.is_name_undefined() {
                    let name = self.build_undefined_name(scope)?;
                    self.rename_symbol_as(sym, &name, Provenance::Default)?;
                }
                self.clear_attribute(sym, VarnodeFlags::NOLOCALALIAS)?;
                if self.symbol(sym)?.is_size_type_locked() {
                    self.reset_size_lock_type(sym, types)?;
                }
            } else if data.category == category::EQUATE {
                continue;
            } else {
                self.remove_symbol(sym)?;
            }
        }
        Ok(())
    }

    /// Ghidra `clearUnlockedCategory`.
    pub fn clear_unlocked_category(&mut self, scope: ScopeId, cat: i16, types: &mut TypeFactory) -> Result<()> {
        let list: Vec<SymbolId> = if cat >= 0 {
            self.scope(scope)?.category(cat).iter().flatten().copied().collect()
        } else {
            let all = self.symbols_in_name_order(scope)?;
            all.into_iter()
                .filter(|s| self.symbol(*s).is_ok_and(|d| d.category < 0))
                .collect()
        };
        for sym in list {
            let data = self.symbol(sym)?;
            if data.is_type_locked() {
                if !data.is_name_locked() && !data.is_name_undefined() {
                    let name = self.build_undefined_name(scope)?;
                    self.rename_symbol_as(sym, &name, Provenance::Default)?;
                }
                if cat >= 0 && self.symbol(sym)?.is_size_type_locked() {
                    self.reset_size_lock_type(sym, types)?;
                }
            } else {
                self.remove_symbol(sym)?;
            }
        }
        Ok(())
    }

    /// Ghidra `overrideSizeLockType`.
    pub fn override_size_lock_type(&mut self, sym: SymbolId, ty: TypeId, types: &TypeFactory) -> Result<()> {
        let new_size = type_facts(types, ty)?.size;
        let data = self.symbol(sym)?;
        if data.type_size != new_size {
            return Err(SymbolError::DifferentSize);
        }
        if !data.is_size_type_locked() {
            return Err(SymbolError::NotSizeLocked);
        }
        self.set_type(sym, ty, types)
    }

    /// Ghidra `resetSizeLockType`: a type that is not `TYPE_UNKNOWN` is
    /// replaced by the undefined type of its size.
    pub fn reset_size_lock_type(&mut self, sym: SymbolId, types: &mut TypeFactory) -> Result<()> {
        let data = self.symbol(sym)?;
        if data.type_unknown {
            return Ok(());
        }
        let ty = types.base(data.type_size, Metatype::Unknown)?;
        self.set_type(sym, ty, types)
    }
}
