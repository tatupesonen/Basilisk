//! Queries that walk up the scope tree (Ghidra `Scope::stack*`,
//! `query*`, `discoverScope`, `getResolutionDepth`; database.cc 999–1182,
//! 1318–1547, 409–446; spec 4.5, 4.6).

use bk_core::Address;

use crate::database::Database;
use crate::error::{Result, limits};
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::SymbolKind;

/// What a walk up the scopes found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found<T> {
    /// A scope answered.
    Hit(ScopeId, T),
    /// No scope answered, but this one owns the address ("discovery").
    Discovered(ScopeId),
    /// Nothing.
    Nothing,
}

impl<T> Found<T> {
    /// The answer, if any.
    pub fn hit(self) -> Option<T> {
        match self {
            Self::Hit(_, t) => Some(t),
            _ => None,
        }
    }
}

impl Database {
    /// The generic `stack*` walk: from `start` up the parents, stopping
    /// before `stop`; each scope is asked with `find`; when `discover` is
    /// given, a scope owning `size` bytes at the address ends the walk.
    pub(crate) fn stack_walk<T>(
        &self,
        start: ScopeId,
        stop: Option<ScopeId>,
        addr: Address,
        discover: Option<i32>,
        mut find: impl FnMut(&Self, ScopeId) -> Result<Option<T>>,
    ) -> Result<Found<T>> {
        if addr.is_constant() {
            return Ok(Found::Nothing);
        }
        let mut cur = Some(start);
        let mut steps = 0;
        while let Some(scope) = cur {
            if Some(scope) == stop || steps > limits::MAX_SCOPE_DEPTH {
                break;
            }
            if let Some(t) = find(self, scope)? {
                return Ok(Found::Hit(scope, t));
            }
            if let Some(size) = discover
                && self.in_scope(scope, addr, size)?
            {
                return Ok(Found::Discovered(scope));
            }
            cur = self.scope(scope)?.parent;
            steps += 1;
        }
        Ok(Found::Nothing)
    }

    /// Ghidra `queryByAddr`.
    pub fn query_by_addr(&self, scope: ScopeId, addr: Address, usepoint: Address) -> Result<Option<EntryId>> {
        let base = self.map_scope(scope, addr);
        Ok(self
            .stack_walk(base, None, addr, Some(1), |db, s| db.find_addr(s, addr, usepoint))?
            .hit())
    }

    /// The walk behind `queryContainer` and `queryProperties`.
    pub(crate) fn stack_container(&self, scope: ScopeId, addr: Address, size: i32, usepoint: Address) -> Result<Found<EntryId>> {
        let base = self.map_scope(scope, addr);
        self.stack_walk(base, None, addr, Some(size), |db, s| db.find_container(s, addr, size, usepoint))
    }

    /// Ghidra `queryContainer`.
    pub fn query_container(&self, scope: ScopeId, addr: Address, size: i32, usepoint: Address) -> Result<Option<EntryId>> {
        Ok(self.stack_container(scope, addr, size, usepoint)?.hit())
    }

    /// Ghidra `queryProperties`: the containing entry and the flags at the
    /// address (spec 4.6).
    pub fn query_properties(
        &self,
        scope: ScopeId,
        addr: Address,
        size: i32,
        usepoint: Address,
    ) -> Result<(Option<EntryId>, VarnodeFlags)> {
        let found = self.stack_container(scope, addr, size, usepoint)?;
        self.properties_of(found, addr)
    }

    /// The flags `queryProperties` reports for a walk's result.
    pub(crate) fn properties_of(&self, found: Found<EntryId>, addr: Address) -> Result<(Option<EntryId>, VarnodeFlags)> {
        Ok(match found {
            Found::Hit(_, entry) => {
                let e = self.entry(entry)?;
                (Some(entry), e.extra_flags | self.symbol(e.symbol)?.flags)
            }
            Found::Discovered(scope) => {
                let mut flags = VarnodeFlags::MAPPED | VarnodeFlags::ADDRTIED;
                if self.scope(scope)?.is_global() {
                    flags |= VarnodeFlags::PERSIST;
                }
                (None, flags | self.property(addr))
            }
            Found::Nothing => (None, self.property(addr)),
        })
    }

    /// Ghidra `isReadOnly`.
    pub fn is_read_only(&self, scope: ScopeId, addr: Address, size: i32, usepoint: Address) -> Result<bool> {
        let (_, flags) = self.query_properties(scope, addr, size, usepoint)?;
        Ok(flags.contains(VarnodeFlags::READONLY))
    }

    /// Ghidra `queryFunction(addr)`: the function symbol at `addr`.
    pub fn query_function(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let base = self.map_scope(scope, addr);
        Ok(self
            .stack_walk(base, None, addr, Some(1), |db, s| {
                // stackFunction tests ownership with an invalid use point,
                // which inScope ignores.
                db.find_function(s, addr)
            })?
            .hit())
    }

    /// Ghidra `queryCodeLabel`.
    pub fn query_code_label(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let base = self.map_scope(scope, addr);
        Ok(self
            .stack_walk(base, None, addr, Some(1), |db, s| db.find_code_label(s, addr))?
            .hit())
    }

    /// Ghidra `queryExternalRefFunction`: the external reference at `addr`
    /// (no discovery) resolved from the scope where it was found.
    pub fn query_external_ref_function(&self, scope: ScopeId, addr: Address) -> Result<Option<SymbolId>> {
        let base = self.map_scope(scope, addr);
        let found = self.stack_walk(base, None, addr, None, |db, s| db.find_external_ref(s, addr))?;
        let Found::Hit(at, sym) = found else {
            return Ok(None);
        };
        let SymbolKind::ExternRef { ref_addr } = self.symbol(sym)?.kind else {
            return Ok(None);
        };
        self.query_function(at, ref_addr)
    }

    /// Ghidra `discoverScope`: the first scope from `mapScope` upwards that
    /// owns the range.
    pub fn discover_scope(&self, scope: ScopeId, addr: Address, size: i32) -> Result<Option<ScopeId>> {
        if addr.is_constant() {
            return Ok(None);
        }
        let mut cur = Some(self.map_scope(scope, addr));
        let mut steps = 0;
        while let Some(s) = cur {
            if steps > limits::MAX_SCOPE_DEPTH {
                break;
            }
            if self.in_scope(s, addr, size)? {
                return Ok(Some(s));
            }
            cur = self.scope(s)?.parent;
            steps += 1;
        }
        Ok(None)
    }

    /// Ghidra `queryByName`: the symbols of that name in the first scope
    /// upwards that has any.
    pub fn query_by_name(&self, scope: ScopeId, name: &str) -> Result<Vec<SymbolId>> {
        let mut cur = Some(scope);
        let mut steps = 0;
        while let Some(s) = cur {
            let found = self.find_by_name(s, name)?;
            if !found.is_empty() || steps > limits::MAX_SCOPE_DEPTH {
                return Ok(found);
            }
            cur = self.scope(s)?.parent;
            steps += 1;
        }
        Ok(Vec::new())
    }

    /// Ghidra `queryFunction(name)`: the first function symbol of
    /// `query_by_name`.
    pub fn query_function_by_name(&self, scope: ScopeId, name: &str) -> Result<Option<SymbolId>> {
        for sym in self.query_by_name(scope, name)? {
            if self.symbol(sym)?.is_function() {
                return Ok(Some(sym));
            }
        }
        Ok(None)
    }

    /// Ghidra `getResolutionDepth`: how many scope names must be printed to
    /// name the symbol from `use_scope`. Cached per use scope in the
    /// symbol and, as in Ghidra, never invalidated by renames.
    pub fn resolution_depth(&mut self, sym: SymbolId, use_scope: Option<ScopeId>) -> Result<i32> {
        let data = self.symbol(sym)?;
        let home = data.scope;
        if Some(home) == use_scope {
            return Ok(0);
        }
        let Some(use_scope) = use_scope else {
            let count = self.scope_path(home).len() as i32;
            return Ok(count - 1);
        };
        if data.depth_scope == Some(use_scope) {
            return Ok(data.depth);
        }
        let name = data.name.to_string();
        let distinguish = self.find_distinguishing_scope(home, use_scope);
        let mut depth = 0;
        let (distinguish_name, terminating) = match distinguish {
            None => (name, Some(home)),
            Some(d) => {
                let mut cur = home;
                let mut steps = 0;
                while cur != d && steps <= limits::MAX_SCOPE_DEPTH {
                    depth += 1;
                    cur = self.scope(cur)?.parent.unwrap_or(d);
                    steps += 1;
                }
                depth += 1;
                (self.scope(d)?.name.to_string(), self.scope(d)?.parent)
            }
        };
        if self.is_name_used(use_scope, &distinguish_name, terminating)? {
            depth += 1;
        }
        let data = self.symbol_mut(sym)?;
        data.depth_scope = Some(use_scope);
        data.depth = depth;
        Ok(depth)
    }
}
