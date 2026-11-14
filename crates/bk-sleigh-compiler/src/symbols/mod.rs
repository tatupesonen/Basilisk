//! The symbol table (`SymbolTable`, `SymbolScope`, `slghsymbol.cc`): one
//! list of symbols whose index is the id, and a tree of scopes mapping names
//! to symbols.

pub mod kinds;

use bk_sleigh_syntax::{Interner, Span, Symbol as Name};
use rustc_hash::FxHashMap;

use crate::ids::{ScopeId, SymbolId};
pub use kinds::{OperandData, SymbolData, SymbolKind, VarnodeData};

/// The largest number of symbols the `.sla` reader accepts
/// (`SymbolTable::MAX_SYMBOLS`); also the compiler's bound (spec 4.5).
pub const MAX_SYMBOLS: usize = 0x100_0000;
/// The largest number of scopes the `.sla` reader accepts.
pub const MAX_SCOPES: usize = 0x10_0000;

#[derive(Clone, Debug, Default)]
struct Scope {
    parent: Option<ScopeId>,
    names: FxHashMap<Name, SymbolId>,
}

/// A symbol could not be added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AddError {
    /// A symbol of that name is already in the scope. The new symbol still
    /// took an id, as in Ghidra.
    Duplicate(SymbolId),
    /// The table is full (spec 4.5).
    Full,
}

/// The symbol table.
#[derive(Clone, Debug, Default)]
pub struct SymbolTable {
    symbols: Vec<SymbolData>,
    scopes: Vec<Scope>,
    current: ScopeId,
}

impl SymbolTable {
    /// The number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// The number of scopes.
    pub fn num_scopes(&self) -> usize {
        self.scopes.len()
    }

    /// A scope's parent.
    pub fn scope_parent(&self, scope: ScopeId) -> Option<ScopeId> {
        self.scopes.get(scope.slot()).and_then(|s| s.parent)
    }

    /// One symbol.
    pub fn get(&self, id: SymbolId) -> Option<&SymbolData> {
        self.symbols.get(id.slot())
    }

    /// The kind of a symbol.
    pub fn kind(&self, id: SymbolId) -> Option<&SymbolKind> {
        self.get(id).map(|s| &s.kind)
    }

    /// All symbols in id order.
    pub fn iter(&self) -> impl Iterator<Item = (SymbolId, &SymbolData)> {
        self.symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (SymbolId::next(i), s))
    }

    /// The current scope.
    pub fn current(&self) -> ScopeId {
        self.current
    }

    /// Creates a scope under the current one and makes it current
    /// (`SymbolTable::addScope`).
    pub(crate) fn add_scope(&mut self) -> Result<ScopeId, AddError> {
        if self.scopes.len() >= MAX_SCOPES {
            return Err(AddError::Full);
        }
        let id = ScopeId::next(self.scopes.len());
        let parent = (!self.scopes.is_empty()).then_some(self.current);
        self.scopes.push(Scope {
            parent,
            names: FxHashMap::default(),
        });
        self.current = id;
        Ok(id)
    }

    /// Makes the current scope's parent current (`popScope`).
    pub(crate) fn pop_scope(&mut self) {
        if let Some(parent) = self.scope_parent(self.current) {
            self.current = parent;
        }
    }

    /// Makes `scope` current.
    pub(crate) fn set_current(&mut self, scope: ScopeId) {
        if scope.slot() < self.scopes.len() {
            self.current = scope;
        }
    }

    /// Adds a symbol to the current scope (`SymbolTable::addSymbol`).
    pub(crate) fn add(
        &mut self,
        name: Name,
        kind: SymbolKind,
        at: Option<Span>,
    ) -> Result<SymbolId, AddError> {
        self.add_to(self.current, name, kind, at)
    }

    /// Adds a symbol to the global scope (`addGlobalSymbol`).
    pub(crate) fn add_global(
        &mut self,
        name: Name,
        kind: SymbolKind,
        at: Option<Span>,
    ) -> Result<SymbolId, AddError> {
        self.add_to(ScopeId::GLOBAL, name, kind, at)
    }

    fn add_to(
        &mut self,
        scope: ScopeId,
        name: Name,
        kind: SymbolKind,
        at: Option<Span>,
    ) -> Result<SymbolId, AddError> {
        if self.symbols.len() >= MAX_SYMBOLS {
            return Err(AddError::Full);
        }
        let id = SymbolId::next(self.symbols.len());
        self.symbols.push(SymbolData {
            name,
            scope,
            kind,
            defined_at: at,
        });
        let Some(table) = self.scopes.get_mut(scope.slot()) else {
            return Err(AddError::Full);
        };
        match table.names.entry(name) {
            std::collections::hash_map::Entry::Occupied(_) => Err(AddError::Duplicate(id)),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(id);
                Ok(id)
            }
        }
    }

    /// Replaces a symbol's kind in place, keeping its id and scope
    /// (`SymbolTable::replaceSymbol`).
    pub(crate) fn replace(&mut self, id: SymbolId, kind: SymbolKind) {
        if let Some(symbol) = self.symbols.get_mut(id.slot()) {
            symbol.kind = kind;
        }
    }

    /// Looks a name up from the current scope outwards (`findSymbol`).
    pub fn lookup(&self, name: Name) -> Option<SymbolId> {
        self.lookup_from(self.current, name)
    }

    /// Looks a name up from `scope` outwards.
    pub fn lookup_from(&self, scope: ScopeId, name: Name) -> Option<SymbolId> {
        let mut scope = Some(scope);
        let mut guard = self.scopes.len();
        while let Some(id) = scope {
            let table = self.scopes.get(id.slot())?;
            if let Some(&found) = table.names.get(&name) {
                return Some(found);
            }
            scope = table.parent;
            guard = guard.checked_sub(1)?;
        }
        None
    }

    /// Looks a name up skipping `skip` scopes outwards from the current one
    /// first (`findSymbol(name, skip)`).
    pub fn lookup_skipping(&self, name: Name, skip: usize) -> Option<SymbolId> {
        let mut scope = self.current;
        for _ in 0..skip {
            match self.scope_parent(scope) {
                Some(parent) => scope = parent,
                None => break,
            }
        }
        self.lookup_from(scope, name)
    }

    /// The symbols of one scope in name order, as Ghidra's `SymbolTree`
    /// iterates them.
    pub fn scope_symbols_by_name(&self, scope: ScopeId, names: &Interner) -> Vec<SymbolId> {
        let Some(table) = self.scopes.get(scope.slot()) else {
            return Vec::new();
        };
        let mut list: Vec<(&str, SymbolId)> = table
            .names
            .iter()
            .map(|(name, id)| (names.resolve(*name), *id))
            .collect();
        list.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        list.into_iter().map(|(_, id)| id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_shadow_and_duplicates_take_an_id() {
        let mut names = Interner::new();
        let a = names.intern("a");
        let mut table = SymbolTable::default();
        table.add_scope().unwrap();
        let g = table.add(a, SymbolKind::Epsilon, None).unwrap();
        assert_eq!(
            table.add(a, SymbolKind::Start, None),
            Err(AddError::Duplicate(SymbolId(1)))
        );
        assert_eq!(table.lookup(a), Some(g));
        let local_scope = table.add_scope().unwrap();
        let l = table.add(a, SymbolKind::End, None).unwrap();
        assert_eq!(table.lookup(a), Some(l));
        assert_eq!(table.lookup_skipping(a, 1), Some(g));
        table.pop_scope();
        assert_eq!(table.lookup(a), Some(g));
        assert_eq!(table.scope_parent(local_scope), Some(ScopeId::GLOBAL));
        assert_eq!(table.len(), 3);
    }
}
