//! The cache layer a program-database host is used through: Ghidra's
//! `ScopeGhidra` and `ScopeGhidraNamespace` (`database_ghidra.cc`; spec
//! 4.19). Its observable rules are Ghidra's: an address is asked only when
//! its space has a global range, no cached entry contains it and it is not
//! in a hole; namespace symbols mark their range as a hole; `FUN_`/`DAT_`
//! names are not asked; `clear` empties the cache and restores the property
//! map the replies changed.
//!
//! The other services' caches are in [`super::test`]'s sibling types below
//! ([`HostComments`], [`HostStrings`], [`HostConstantPool`],
//! [`HostImage`], [`HostTracked`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use bk_context::PartMap;
use bk_core::{Address, Provenance, Range, RangeList, SpaceId};
use bk_decomp_types::{Metatype, TypeFactory, TypeId};

use super::{HostReply, HostSymbol, HostSymbolKind, ProgramHost, is_dynamic_symbol_name};
use crate::database::{ArchEnv, Database};
use crate::error::{Result, SymbolError};
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{SymbolKind, is_undefined_name};
use crate::scope::query::Found;

pub use super::services::{HostComments, HostConstantPool, HostImage, HostStrings, HostTracked};

/// The symbol table of a host-backed architecture: a [`Database`] whose
/// global scope is the cache, plus Ghidra `ScopeGhidra`'s state.
pub struct HostDatabase {
    db: Database,
    host: Arc<dyn ProgramHost>,
    holes: RangeList,
    space_range: Vec<bool>,
    cache_dirty: bool,
    default_props: PartMap<u32>,
    host_namespaces: BTreeSet<ScopeId>,
}

impl std::fmt::Debug for HostDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostDatabase")
            .field("db", &self.db)
            .field("holes", &self.holes)
            .finish_non_exhaustive()
    }
}

impl HostDatabase {
    /// An empty cache over a host.
    pub fn new(env: ArchEnv, host: Arc<dyn ProgramHost>) -> Self {
        Self {
            db: Database::new(env, true),
            host,
            holes: RangeList::default(),
            space_range: Vec::new(),
            cache_dirty: false,
            default_props: PartMap::new(0),
            host_namespaces: BTreeSet::new(),
        }
    }

    /// The cache.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// The cache, to change it directly.
    pub fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    /// The ranges already asked about.
    pub fn holes(&self) -> &RangeList {
        &self.holes
    }

    fn global(&self) -> Result<ScopeId> {
        self.db.global_scope()
    }

    /// Ghidra `ScopeGhidra::addRange`: a global range, and its space marked
    /// as one to ask about.
    pub fn add_global_range(&mut self, space: SpaceId, first: u64, last: u64) -> Result<()> {
        let global = self.global()?;
        self.db.add_range(global, space, first, last)?;
        let i = space.index() as usize;
        if self.space_range.len() <= i {
            self.space_range.resize(i + 1, false);
        }
        if let Some(slot) = self.space_range.get_mut(i) {
            *slot = true;
        }
        Ok(())
    }

    /// Ghidra `lockDefaultProperties`.
    pub fn lock_default_properties(&mut self) {
        self.default_props = self.db.properties().clone();
        self.cache_dirty = false;
    }

    /// Ghidra `ScopeGhidra::clear`.
    pub fn clear(&mut self) -> Result<()> {
        let global = self.global()?;
        self.db.clear_scope(global)?;
        self.holes.clear();
        if self.cache_dirty {
            self.db.set_properties(self.default_props.clone());
            self.cache_dirty = false;
        }
        Ok(())
    }

    /// Ghidra `reresolveScope`: the scope of a reported id (0: the cache),
    /// fetching and creating its namespace path when unknown.
    fn reresolve_scope(&mut self, id: u64) -> Result<ScopeId> {
        if id == 0 {
            return self.global();
        }
        if let Some(scope) = self.db.resolve_scope_id(id) {
            return Ok(scope);
        }
        let path = self.host.namespace_path(id)?;
        if path.len() > crate::error::limits::MAX_PATH {
            return Err(SymbolError::Limit("namespace path length"));
        }
        let mut cur = self.global()?;
        for ns in path {
            if ns.id == 0 {
                return Err(SymbolError::MissingScopeId);
            }
            let known = self.db.resolve_scope_id(ns.id).is_some();
            cur = self.db.find_create_scope(ns.id, &ns.name, Some(cur))?;
            if !known {
                self.host_namespaces.insert(cur);
            }
            if let Some(label) = ns.label.filter(|l| !l.is_empty()) {
                self.db.scope_mut(cur)?.display_name = label.into();
            }
        }
        Ok(cur)
    }

    /// Adds a reported symbol to a scope as `addMapSym` would; a failure
    /// while mapping prints `Throwing out symbol with invalid mapping` and
    /// yields `None`.
    fn add_record(
        &mut self,
        scope: ScopeId,
        sym: &HostSymbol,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let rec = &sym.record;
        let mut data = match &rec.kind {
            HostSymbolKind::Data { ty } => {
                Database::new_symbol(scope, SymbolKind::Plain, &rec.name, *ty, types)?
            }
            HostSymbolKind::Function => {
                let code = types.type_code()?;
                let consume_size = self.db.env.min_funcsymbol_size;
                let mut d = Database::new_symbol(
                    scope,
                    SymbolKind::Function { consume_size },
                    &rec.name,
                    code,
                    types,
                )?;
                d.flags |= VarnodeFlags::NAMELOCK | VarnodeFlags::TYPELOCK;
                d
            }
            HostSymbolKind::Label => {
                let ty = types.base(1, Metatype::Unknown)?;
                Database::new_symbol(scope, SymbolKind::Label, &rec.name, ty, types)?
            }
            HostSymbolKind::ExternRef { ref_addr } => self
                .db
                .new_extern_ref(scope, *ref_addr, &rec.name, "", types)?,
        };
        let id = rec.id;
        data.ghidra_id = if id >> 56 == crate::ID_BASE >> 56 {
            0
        } else {
            id
        };
        data.flags |= rec.flags
            & (VarnodeFlags::NAMELOCK
                | VarnodeFlags::TYPELOCK
                | VarnodeFlags::READONLY
                | VarnodeFlags::VOLATILE);
        data.check_size_type_lock();
        data.name_provenance = if is_undefined_name(&rec.name) {
            Provenance::Default
        } else {
            sym.name_provenance
        };
        data.type_provenance = sym.type_provenance;
        let id = self.db.add_symbol_internal(scope, data)?;
        let mut ok = true;
        for entry in &rec.entries {
            let mut e = Database::map_entry(id, entry.addr, Address::INVALID);
            e.use_limit = entry.use_limit.clone();
            if self.db.add_map(scope, e).is_err() {
                ok = false;
                break;
            }
        }
        if !ok {
            let name = self.db.symbol(id)?.name.to_string();
            self.db
                .warn(format!("Throwing out symbol with invalid mapping: {name}"));
            self.db.remove_symbol(id)?;
            return Ok(None);
        }
        if self.host_namespaces.contains(&scope) {
            // ScopeGhidraNamespace::addMapInternal: every entry extends the
            // namespace's ownership.
            for e in self.db.symbol(id)?.entries.clone() {
                let entry = self.db.entry(e)?;
                if let (Some(addr), Some(last)) = (entry.addr(), entry.last_offset())
                    && let Some(space) = addr.space()
                {
                    self.db.add_range(scope, space, addr.offset(), last)?;
                }
            }
        }
        Ok(Some(id))
    }

    /// Ghidra `dump2Cache`.
    fn dump_to_cache(
        &mut self,
        reply: HostReply,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let sym = match reply {
            HostReply::Nothing => return Ok(None),
            HostReply::Hole {
                range,
                readonly,
                volatile,
            } => {
                self.holes.insert(range);
                let mut flags = VarnodeFlags::empty();
                if readonly {
                    flags |= VarnodeFlags::READONLY;
                }
                if volatile {
                    flags |= VarnodeFlags::VOLATILE;
                }
                if !flags.is_empty() {
                    self.db.set_property_range(flags, &range);
                    self.cache_dirty = true;
                }
                return Ok(None);
            }
            HostReply::Symbol(sym) => sym,
        };
        let scope = self.reresolve_scope(sym.scope)?;
        let Some(id) = self.add_record(scope, &sym, types)? else {
            return Ok(None);
        };
        let global = self.global()?;
        let first = self.db.symbol(id)?.entries.first().copied();
        if let Some(e) = first {
            let entry = self.db.entry(e)?;
            if entry.is_map_entry()
                && let (Some(addr), Some(last)) = (entry.addr(), entry.last_offset())
                && let Some(space) = addr.space()
            {
                let range = Range::new(space, addr.offset(), last);
                if scope != global {
                    self.holes.insert(range);
                }
                let props =
                    self.db.symbol(id)?.flags & (VarnodeFlags::READONLY | VarnodeFlags::VOLATILE);
                if !props.is_empty() {
                    self.db.set_property_range(props, &range);
                    self.cache_dirty = true;
                }
            }
        }
        Ok(Some(id))
    }

    /// Ghidra `removeQuery`: asks the host about `addr` unless its space has
    /// no global range or the address is in a hole.
    fn remove_query(&mut self, addr: Address, types: &mut TypeFactory) -> Result<Option<SymbolId>> {
        let Some(space) = addr.space() else {
            return Ok(None);
        };
        if !self
            .space_range
            .get(space.index() as usize)
            .copied()
            .unwrap_or(false)
        {
            return Ok(None);
        }
        if self.holes.in_range(addr, 1) {
            return Ok(None);
        }
        let reply = self.host.mapped_symbol(addr)?;
        self.dump_to_cache(reply, types)
    }

    /// Ghidra `ScopeGhidra::findAddr`.
    pub fn find_addr(
        &mut self,
        addr: Address,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        let global = self.global()?;
        let mut entry = self.db.find_addr(global, addr, usepoint)?;
        if entry.is_none() {
            if self
                .db
                .find_container(global, addr, 1, Address::INVALID)?
                .is_some()
            {
                return Ok(None);
            }
            if let Some(sym) = self.remove_query(addr, types)? {
                entry = self.db.map_entry_at(sym, addr)?;
            }
        }
        Ok(entry.filter(|e| {
            self.db
                .entry(*e)
                .ok()
                .and_then(super::super::model::EntryData::addr)
                == Some(addr)
        }))
    }

    /// Ghidra `ScopeGhidra::findContainer`.
    pub fn find_container(
        &mut self,
        addr: Address,
        size: i32,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        let global = self.global()?;
        let mut entry = self.db.find_closest_fit(global, addr, size, usepoint)?;
        if entry.is_none()
            && let Some(sym) = self.remove_query(addr, types)?
        {
            entry = self.db.map_entry_at(sym, addr)?;
        }
        let end = addr
            .offset()
            .wrapping_add(i64::from(size) as u64)
            .wrapping_sub(1);
        Ok(entry.filter(|e| {
            self.db
                .entry(*e)
                .ok()
                .and_then(super::super::model::EntryData::last_offset)
                .is_some_and(|last| last >= end)
        }))
    }

    /// Ghidra `ScopeGhidra::findFunction`.
    pub fn find_function(
        &mut self,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let global = self.global()?;
        if let Some(f) = self.db.find_function(global, addr)? {
            return Ok(Some(f));
        }
        if self
            .db
            .find_container(global, addr, 1, Address::INVALID)?
            .is_some()
        {
            return Ok(None);
        }
        let sym = self.remove_query(addr, types)?;
        Ok(sym.filter(|s| {
            self.db
                .symbol(*s)
                .is_ok_and(crate::model::SymbolData::is_function)
        }))
    }

    /// Ghidra `ScopeGhidra::findExternalRef`.
    pub fn find_external_ref(
        &mut self,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let global = self.global()?;
        if let Some(x) = self.db.find_external_ref(global, addr)? {
            return Ok(Some(x));
        }
        if self
            .db
            .find_container(global, addr, 1, Address::INVALID)?
            .is_some()
        {
            return Ok(None);
        }
        let sym = self.remove_query(addr, types)?;
        Ok(sym.filter(|s| {
            self.db
                .symbol(*s)
                .is_ok_and(|d| matches!(d.kind, SymbolKind::ExternRef { .. }))
        }))
    }

    /// Ghidra `ScopeGhidra::findCodeLabel`: asks only when no cached entry
    /// starts at the address; a name becomes a cached label.
    pub fn find_code_label(
        &mut self,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let global = self.global()?;
        if let Some(l) = self.db.find_code_label(global, addr)? {
            return Ok(Some(l));
        }
        if self.db.find_addr(global, addr, Address::INVALID)?.is_some() {
            return Ok(None);
        }
        match self.host.code_label(addr)? {
            Some((name, provenance)) if !name.is_empty() => {
                let l = self.db.add_code_label(global, addr, &name, types)?;
                self.db.symbol_mut(l)?.name_provenance = provenance;
                Ok(Some(l))
            }
            _ => Ok(None),
        }
    }

    /// Ghidra `ScopeGhidra::findSymbolBefore`: probes 8-byte aligned
    /// offsets before the container.
    pub fn find_symbol_before(
        &mut self,
        addr: Address,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        let mut off = addr.offset();
        if let Some(e) = self.find_container(addr, 1, usepoint, types)? {
            off = self.db.entry(e)?.addr().map_or(off, Address::offset);
        }
        if off == 0 {
            return Ok(None);
        }
        let misalign = off & 7;
        off -= if misalign == 0 { 8 } else { misalign };
        let Some(space) = addr.space() else {
            return Ok(None);
        };
        self.find_container(Address::new(space, off), 1, usepoint, types)
    }

    /// Ghidra `ScopeGhidra::findSymbolAfter`.
    pub fn find_symbol_after(
        &mut self,
        addr: Address,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        let mut off = addr.offset();
        if let Some(e) = self.find_container(addr, 1, usepoint, types)? {
            off = self.db.entry(e)?.last_offset().unwrap_or(off);
        }
        if off & 7 != 0 {
            off -= off & 7;
        }
        off = off.wrapping_add(8);
        let highest = self
            .db
            .spaces()
            .space_of(addr)
            .map_or(u64::MAX, bk_core::Space::highest);
        if off < addr.offset() || off > highest {
            return Ok(None);
        }
        let Some(space) = addr.space() else {
            return Ok(None);
        };
        self.find_container(Address::new(space, off), 1, usepoint, types)
    }

    /// Ghidra `ScopeGhidra::addSymbol`: only the cache learns of it.
    pub fn add_symbol_at(
        &mut self,
        name: &str,
        ty: TypeId,
        addr: Address,
        usepoint: Address,
        types: &TypeFactory,
    ) -> Result<EntryId> {
        let global = self.global()?;
        self.db
            .add_symbol_at(global, name, ty, addr, usepoint, types)
    }

    /// Ghidra `ScopeGhidraNamespace::isNameUsed` for host namespaces (asks
    /// the host, except for `FUN_`/`DAT_` names); `ScopeInternal`'s rule
    /// elsewhere.
    pub fn is_name_used(&self, scope: ScopeId, name: &str, stop: Option<ScopeId>) -> Result<bool> {
        if !self.host_namespaces.contains(&scope) {
            return self.db.is_name_used(scope, name, stop);
        }
        if is_dynamic_symbol_name(name) {
            return Ok(false);
        }
        let start = self.db.scope(scope)?.ghidra_id;
        let stop_id = match stop {
            Some(s) if self.host_namespaces.contains(&s) => self.db.scope(s)?.ghidra_id,
            _ => 0,
        };
        Ok(self.host.is_name_used(name, start, stop_id)?)
    }

    /// A walk up the scopes with the global scope answered through the
    /// cache rules.
    fn walk<T>(
        &mut self,
        scope: ScopeId,
        addr: Address,
        discover: Option<i32>,
        types: &mut TypeFactory,
        mut global_find: impl FnMut(&mut Self, &mut TypeFactory) -> Result<Option<T>>,
        mut local_find: impl FnMut(&Database, ScopeId) -> Result<Option<T>>,
    ) -> Result<Found<T>> {
        if addr.is_constant() {
            return Ok(Found::Nothing);
        }
        let global = self.global()?;
        let mut cur = Some(self.db.map_scope(scope, addr));
        let mut steps = 0;
        while let Some(s) = cur {
            if steps > crate::error::limits::MAX_SCOPE_DEPTH {
                break;
            }
            let hit = if s == global {
                global_find(self, types)?
            } else {
                local_find(&self.db, s)?
            };
            if let Some(t) = hit {
                return Ok(Found::Hit(s, t));
            }
            if let Some(size) = discover
                && self.db.in_scope(s, addr, size)?
            {
                return Ok(Found::Discovered(s));
            }
            cur = self.db.scope(s)?.parent;
            steps += 1;
        }
        Ok(Found::Nothing)
    }

    /// Ghidra `queryByAddr` over the host.
    pub fn query_by_addr(
        &mut self,
        scope: ScopeId,
        addr: Address,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        Ok(self
            .walk(
                scope,
                addr,
                Some(1),
                types,
                |h, t| h.find_addr(addr, usepoint, t),
                |db, s| db.find_addr(s, addr, usepoint),
            )?
            .hit())
    }

    /// Ghidra `queryContainer` over the host.
    pub fn query_container(
        &mut self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<EntryId>> {
        Ok(self
            .container_walk(scope, addr, size, usepoint, types)?
            .hit())
    }

    fn container_walk(
        &mut self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<Found<EntryId>> {
        self.walk(
            scope,
            addr,
            Some(size),
            types,
            |h, t| h.find_container(addr, size, usepoint, t),
            |db, s| db.find_container(s, addr, size, usepoint),
        )
    }

    /// Ghidra `queryProperties` over the host.
    pub fn query_properties(
        &mut self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
        types: &mut TypeFactory,
    ) -> Result<(Option<EntryId>, VarnodeFlags)> {
        let found = self.container_walk(scope, addr, size, usepoint, types)?;
        self.db.properties_of(found, addr)
    }

    /// Ghidra `queryFunction(addr)` over the host.
    pub fn query_function(
        &mut self,
        scope: ScopeId,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        Ok(self
            .walk(
                scope,
                addr,
                Some(1),
                types,
                |h, t| h.find_function(addr, t),
                |db, s| db.find_function(s, addr),
            )?
            .hit())
    }

    /// Ghidra `queryCodeLabel` over the host.
    pub fn query_code_label(
        &mut self,
        scope: ScopeId,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        Ok(self
            .walk(
                scope,
                addr,
                Some(1),
                types,
                |h, t| h.find_code_label(addr, t),
                |db, s| db.find_code_label(s, addr),
            )?
            .hit())
    }

    /// Ghidra `queryExternalRefFunction` over the host (no discovery).
    pub fn query_external_ref_function(
        &mut self,
        scope: ScopeId,
        addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let found = self.walk(
            scope,
            addr,
            None,
            types,
            |h, t| h.find_external_ref(addr, t),
            |db, s| db.find_external_ref(s, addr),
        )?;
        let Found::Hit(at, sym) = found else {
            return Ok(None);
        };
        let SymbolKind::ExternRef { ref_addr } = self.db.symbol(sym)?.kind else {
            return Ok(None);
        };
        if at == self.global()? {
            return self.resolve_external_ref_function(sym, ref_addr, types);
        }
        self.query_function(at, ref_addr, types)
    }

    /// Ghidra `ScopeGhidra::resolveExternalRefFunction`.
    fn resolve_external_ref_function(
        &mut self,
        sym: SymbolId,
        ref_addr: Address,
        types: &mut TypeFactory,
    ) -> Result<Option<SymbolId>> {
        let global = self.global()?;
        let base = self.db.map_scope(global, ref_addr);
        let found = self
            .db
            .stack_walk(base, Some(global), ref_addr, Some(1), |db, s| {
                db.find_function(s, ref_addr)
            })?;
        if let Some(f) = found.hit() {
            return Ok(Some(f));
        }
        if let Some(f) = self.db.find_function(global, ref_addr)? {
            return Ok(Some(f));
        }
        let entry = self.db.first_whole_map(sym)?;
        let Some(at) = self.db.entry(entry)?.addr() else {
            return Ok(None);
        };
        let Some(reply) = self.host.external_ref(at)? else {
            return Ok(None);
        };
        let f = self.dump_to_cache(HostReply::Symbol(reply), types)?;
        Ok(f.filter(|s| {
            self.db
                .symbol(*s)
                .is_ok_and(crate::model::SymbolData::is_function)
        }))
    }
}
