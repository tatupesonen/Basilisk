//! The symbol table: scopes, symbols and entries in arenas, the scope
//! resolve map and the property map (Ghidra `Database`, database.cc
//! 3055–3617; spec 4.3, 4.7).

mod resolve;
mod tree;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use bk_context::PartMap;
use bk_core::{Address, Range, RangeList, SpaceId, SpaceManager};

use crate::entrymap::{EntryMap, NullSubsort};
use crate::error::{Result, SymbolError, limits};
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{EntryData, ScopeData, ScopeKind, SymbolData};

pub use resolve::ResolveLine;
pub use tree::hash_scope_name;

/// Register names, from the translator (Ghidra `Translate::getRegisterName`).
pub trait RegisterNames: Send + Sync + fmt::Debug {
    /// The name of the register at exactly `(space, offset, size)`, if any.
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str>;
}

/// What the crate needs of the architecture (spec 5.3).
#[derive(Clone, Debug)]
pub struct ArchEnv {
    /// The address spaces.
    pub spaces: Arc<SpaceManager>,
    /// Bytes a function symbol takes at its entry point (Ghidra
    /// `min_funcsymbol_size`: the instruction alignment when at most 8,
    /// else 1).
    pub min_funcsymbol_size: i32,
    /// The scope delimiter of full names (`::`).
    pub scope_delimiter: Box<str>,
    /// Register names for `buildVariableName`.
    pub registers: Option<Arc<dyn RegisterNames>>,
}

impl ArchEnv {
    /// An environment over these spaces with Ghidra's defaults: function
    /// symbols of one byte, `::` as delimiter, no register names.
    pub fn new(spaces: Arc<SpaceManager>) -> Self {
        Self {
            spaces,
            min_funcsymbol_size: 1,
            scope_delimiter: "::".into(),
            registers: None,
        }
    }
}

/// The resolve map from addresses to the namespace owning them.
pub(crate) type ResolveMap = EntryMap<ScopeId, ResolveLine, NullSubsort>;

/// The decompiler's symbol table (Ghidra `Database` with its scopes).
///
/// Ids are arena indices; slots of removed objects stay dead, so a stale id
/// never names a new object.
#[derive(Clone, Debug)]
pub struct Database {
    pub(crate) env: ArchEnv,
    pub(crate) scopes: Vec<ScopeData>,
    pub(crate) symbols: Vec<SymbolData>,
    pub(crate) entries: Vec<EntryData>,
    pub(crate) by_ghidra_scope: BTreeMap<u64, ScopeId>,
    pub(crate) global: Option<ScopeId>,
    pub(crate) resolve: ResolveMap,
    pub(crate) properties: PartMap<u32>,
    pub(crate) id_by_name_hash: bool,
    pub(crate) warnings: Vec<String>,
}

impl Database {
    /// A database with the empty global scope of Ghidra id 0 (as
    /// `Architecture::buildDatabase` makes it).
    pub fn new(env: ArchEnv, id_by_name_hash: bool) -> Self {
        let mut db = Self::without_global(env, id_by_name_hash);
        let spaces = db.num_spaces();
        db.scopes
            .push(ScopeData::new("", 0, ScopeKind::Global, spaces));
        db.global = Some(ScopeId(0));
        db.by_ghidra_scope.insert(0, ScopeId(0));
        db
    }

    /// A database without any scope (for decoding a `<db>` that names its
    /// own global scope).
    pub fn without_global(env: ArchEnv, id_by_name_hash: bool) -> Self {
        Self {
            env,
            scopes: Vec::new(),
            symbols: Vec::new(),
            entries: Vec::new(),
            by_ghidra_scope: BTreeMap::new(),
            global: None,
            resolve: ResolveMap::new(),
            properties: PartMap::new(0),
            id_by_name_hash,
            warnings: Vec::new(),
        }
    }

    /// The architecture environment.
    pub fn env(&self) -> &ArchEnv {
        &self.env
    }

    /// The address spaces.
    pub fn spaces(&self) -> &SpaceManager {
        &self.env.spaces
    }

    pub(crate) fn num_spaces(&self) -> usize {
        self.env.spaces.num_spaces() as usize
    }

    /// Whether namespace ids are hashes of their names.
    pub fn id_by_name_hash(&self) -> bool {
        self.id_by_name_hash
    }

    /// The global scope (`None` only before a `<db>` decode created one).
    pub fn global(&self) -> Option<ScopeId> {
        self.global
    }

    /// The global scope, or an error.
    pub(crate) fn global_scope(&self) -> Result<ScopeId> {
        self.global.ok_or(SymbolError::StaleId {
            kind: "global scope",
            index: 0,
        })
    }

    /// Warnings printed so far (Ghidra `printWarning`), taken out.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    pub(crate) fn warn(&mut self, message: String) {
        tracing::warn!("{message}");
        self.warnings.push(message);
    }

    // ----- arena access ----------------------------------------------------

    /// A live scope.
    pub fn scope(&self, id: ScopeId) -> Result<&ScopeData> {
        self.scopes
            .get(id.0 as usize)
            .filter(|s| s.live)
            .ok_or(SymbolError::StaleId {
                kind: "scope",
                index: id.0,
            })
    }

    pub(crate) fn scope_mut(&mut self, id: ScopeId) -> Result<&mut ScopeData> {
        self.scopes
            .get_mut(id.0 as usize)
            .filter(|s| s.live)
            .ok_or(SymbolError::StaleId {
                kind: "scope",
                index: id.0,
            })
    }

    /// A live symbol.
    pub fn symbol(&self, id: SymbolId) -> Result<&SymbolData> {
        self.symbols
            .get(id.0 as usize)
            .filter(|s| s.live)
            .ok_or(SymbolError::StaleId {
                kind: "symbol",
                index: id.0,
            })
    }

    pub(crate) fn symbol_mut(&mut self, id: SymbolId) -> Result<&mut SymbolData> {
        self.symbols
            .get_mut(id.0 as usize)
            .filter(|s| s.live)
            .ok_or(SymbolError::StaleId {
                kind: "symbol",
                index: id.0,
            })
    }

    /// A live entry.
    pub fn entry(&self, id: EntryId) -> Result<&EntryData> {
        self.entries
            .get(id.0 as usize)
            .filter(|e| e.live)
            .ok_or(SymbolError::StaleId {
                kind: "entry",
                index: id.0,
            })
    }

    pub(crate) fn entry_mut(&mut self, id: EntryId) -> Result<&mut EntryData> {
        self.entries
            .get_mut(id.0 as usize)
            .filter(|e| e.live)
            .ok_or(SymbolError::StaleId {
                kind: "entry",
                index: id.0,
            })
    }

    /// Every live scope id, in arena order.
    pub fn scope_ids(&self) -> impl Iterator<Item = ScopeId> + '_ {
        (0..self.scopes.len() as u32)
            .map(ScopeId)
            .filter(|id| self.scope(*id).is_ok())
    }

    /// The scope of a Ghidra scope id (Ghidra `resolveScope(id)`).
    pub fn resolve_scope_id(&self, ghidra_id: u64) -> Option<ScopeId> {
        self.by_ghidra_scope.get(&ghidra_id).copied()
    }

    // ----- scope tree -----------------------------------------------------

    /// Registers a new scope (Ghidra `attachScope`): with no parent it must
    /// be the only, unnamed global scope; otherwise it needs a name and a
    /// new Ghidra id.
    pub fn attach_scope(
        &mut self,
        name: &str,
        ghidra_id: u64,
        parent: Option<ScopeId>,
        kind: ScopeKind,
    ) -> Result<ScopeId> {
        if name.len() > limits::MAX_NAME {
            return Err(SymbolError::Limit("scope name length"));
        }
        let Some(parent) = parent else {
            if self.global.is_some() {
                return Err(SymbolError::MultipleGlobal);
            }
            if !name.is_empty() {
                return Err(SymbolError::NamedGlobal);
            }
            let id = self.push_scope(ScopeData::new("", ghidra_id, ScopeKind::Global, 0));
            self.global = Some(id);
            self.by_ghidra_scope.insert(ghidra_id, id);
            return Ok(id);
        };
        if name.is_empty() {
            return Err(SymbolError::EmptyScopeName);
        }
        self.scope(parent)?;
        if self.depth_of(parent) >= limits::MAX_SCOPE_DEPTH {
            return Err(SymbolError::Limit("scope nesting"));
        }
        if self.by_ghidra_scope.contains_key(&ghidra_id) {
            // Ghidra asks the new scope for its full name before it has a
            // parent, so the name in the message is always empty.
            return Err(SymbolError::DuplicateScope {
                full_name: String::new(),
            });
        }
        let kind = match kind {
            ScopeKind::Global => ScopeKind::Namespace,
            other => other,
        };
        let id = self.push_scope(ScopeData::new(name, ghidra_id, kind, 0));
        self.by_ghidra_scope.insert(ghidra_id, id);
        if let Some(scope) = self.scopes.get_mut(id.0 as usize) {
            scope.parent = Some(parent);
        }
        self.scope_mut(parent)?.children.insert(ghidra_id, id);
        Ok(id)
    }

    fn push_scope(&mut self, mut scope: ScopeData) -> ScopeId {
        scope.maps = vec![None; self.num_spaces()];
        let id = ScopeId(self.scopes.len() as u32);
        self.scopes.push(scope);
        id
    }

    fn depth_of(&self, mut scope: ScopeId) -> usize {
        let mut depth = 0;
        while let Some(parent) = self.scope(scope).ok().and_then(|s| s.parent) {
            depth += 1;
            if depth > limits::MAX_SCOPE_DEPTH {
                break;
            }
            scope = parent;
        }
        depth
    }

    /// The existing scope of this Ghidra id, whatever its name or parent, or
    /// a new namespace under `parent` (Ghidra `findCreateScope`).
    pub fn find_create_scope(
        &mut self,
        ghidra_id: u64,
        name: &str,
        parent: Option<ScopeId>,
    ) -> Result<ScopeId> {
        if let Some(id) = self.resolve_scope_id(ghidra_id) {
            return Ok(id);
        }
        self.attach_scope(name, ghidra_id, parent, ScopeKind::Namespace)
    }

    /// Attaches the local scope of a function symbol (spec 3.3 item 1):
    /// named after the function, Ghidra id = the symbol's id (or
    /// `0x57AB12CD << 32 | (address & 0xffffffff)` without one), a child of
    /// the symbol's scope, never in the resolve map.
    pub fn create_function_scope(&mut self, function: SymbolId) -> Result<ScopeId> {
        let sym = self.symbol(function)?;
        let name = sym.name.clone();
        let parent = sym.scope;
        let mut id = sym.ghidra_id;
        if id == 0 {
            let addr = sym
                .entries
                .first()
                .and_then(|e| self.entry(*e).ok())
                .and_then(EntryData::addr)
                .map_or(0, Address::offset);
            id = (0x57AB_12CD_u64 << 32) | (addr & 0xffff_ffff);
        }
        self.attach_scope(&name, id, Some(parent), ScopeKind::Function(function))
    }

    /// Deletes a scope and its sub-scopes (Ghidra `deleteScope`).
    pub fn delete_scope(&mut self, scope: ScopeId) -> Result<()> {
        self.scope(scope)?;
        self.clear_references(scope)?;
        if self.global == Some(scope) {
            self.global = None;
        } else {
            let (parent, ghidra_id, name) = {
                let s = self.scope(scope)?;
                (s.parent, s.ghidra_id, s.name.to_string())
            };
            let parent = parent.ok_or(SymbolError::NoParentRef { name: name.clone() })?;
            let removed = self.scope_mut(parent)?.children.remove(&ghidra_id);
            if removed.is_none() {
                return Err(SymbolError::NoParentRef { name });
            }
        }
        self.kill_subtree(scope);
        Ok(())
    }

    /// Deletes every sub-scope of a scope (Ghidra `deleteSubScopes`).
    pub fn delete_sub_scopes(&mut self, scope: ScopeId) -> Result<()> {
        let children: Vec<(u64, ScopeId)> = self
            .scope(scope)?
            .children
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        for (ghidra_id, child) in children {
            self.clear_references(child)?;
            self.scope_mut(scope)?.children.remove(&ghidra_id);
            self.kill_subtree(child);
        }
        Ok(())
    }

    /// The scopes of a sub-tree in Ghidra's recursion order (children in id
    /// order, each sub-tree before its root), without recursion.
    pub(crate) fn post_order(&self, root: ScopeId) -> Vec<ScopeId> {
        let mut out = Vec::new();
        let mut stack: Vec<(ScopeId, bool)> = vec![(root, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                out.push(id);
                continue;
            }
            stack.push((id, true));
            if let Ok(scope) = self.scope(id) {
                for child in scope.children.values().rev() {
                    stack.push((*child, false));
                }
            }
        }
        out
    }

    /// Ghidra `clearReferences`: removes the ids and resolve entries of a
    /// sub-tree.
    fn clear_references(&mut self, root: ScopeId) -> Result<()> {
        for id in self.post_order(root) {
            let ghidra_id = self.scope(id)?.ghidra_id;
            self.by_ghidra_scope.remove(&ghidra_id);
            self.clear_resolve(id)?;
        }
        Ok(())
    }

    /// Marks a sub-tree and everything in it dead.
    fn kill_subtree(&mut self, root: ScopeId) {
        for id in self.post_order(root) {
            let Some(scope) = self.scopes.get_mut(id.0 as usize) else {
                continue;
            };
            scope.live = false;
            let symbols: Vec<SymbolId> = scope.names.values().copied().collect();
            for sym in symbols {
                let entries = self
                    .symbols
                    .get(sym.0 as usize)
                    .map(|s| s.entries.clone())
                    .unwrap_or_default();
                for e in entries {
                    if let Some(entry) = self.entries.get_mut(e.0 as usize) {
                        entry.live = false;
                    }
                }
                if let Some(s) = self.symbols.get_mut(sym.0 as usize) {
                    s.live = false;
                }
            }
        }
    }

    /// Clears the unlocked symbols of a scope and its sub-scopes (Ghidra
    /// `Database::clearUnlocked`).
    pub fn clear_unlocked(&mut self, scope: ScopeId, types: &mut bk_decomp_types::TypeFactory) -> Result<()> {
        for id in self.post_order(scope) {
            self.clear_unlocked_scope(id, types)?;
        }
        Ok(())
    }

    /// Lets every scope adjust to the number of spaces (Ghidra
    /// `adjustCaches`).
    pub fn adjust_caches(&mut self) {
        let n = self.num_spaces();
        for scope in &mut self.scopes {
            scope.maps.resize(n, None);
        }
    }

    // ----- ownership and the resolve map ---------------------------------

    /// Replaces a scope's owned ranges (Ghidra `setRange`).
    pub fn set_range(&mut self, scope: ScopeId, ranges: RangeList) -> Result<()> {
        self.clear_resolve(scope)?;
        self.scope_mut(scope)?.ranges = ranges;
        self.fill_resolve(scope)
    }

    /// Adds a range to a scope's ownership (Ghidra `addRange`).
    pub fn add_range(&mut self, scope: ScopeId, space: SpaceId, first: u64, last: u64) -> Result<()> {
        self.clear_resolve(scope)?;
        self.scope_mut(scope)?.ranges.insert_range(space, first, last);
        self.fill_resolve(scope)
    }

    /// Removes a range from a scope's ownership (Ghidra `removeRange`).
    pub fn remove_range(&mut self, scope: ScopeId, space: SpaceId, first: u64, last: u64) -> Result<()> {
        self.clear_resolve(scope)?;
        self.scope_mut(scope)?.ranges.remove_range(space, first, last);
        self.fill_resolve(scope)
    }

    // ----- properties -----------------------------------------------------

    /// The property flags at an address (Ghidra `getProperty`).
    pub fn property(&self, addr: Address) -> VarnodeFlags {
        VarnodeFlags::from_bits_retain(*self.properties.get(addr))
    }

    /// The property map's split points and values, in order.
    pub fn property_points(&self) -> impl Iterator<Item = (Address, u32)> + '_ {
        self.properties.iter().map(|(a, v)| (*a, *v))
    }

    /// The value before the first split point.
    pub fn property_default(&self) -> u32 {
        *self.properties.default_value()
    }

    /// Replaces the whole property map (Ghidra `setProperties`).
    pub fn set_properties(&mut self, properties: PartMap<u32>) {
        self.properties = properties;
    }

    /// The whole property map (Ghidra `getProperties`).
    pub fn properties(&self) -> &PartMap<u32> {
        &self.properties
    }

    /// ORs flags into the properties of a range (Ghidra `setPropertyRange`).
    pub fn set_property_range(&mut self, flags: VarnodeFlags, range: &Range) {
        let bits = flags.bits();
        self.change_properties(range, |v| *v |= bits);
    }

    /// Clears flags in the properties of a range (Ghidra
    /// `clearPropertyRange`).
    pub fn clear_property_range(&mut self, flags: VarnodeFlags, range: &Range) {
        let bits = !flags.bits();
        self.change_properties(range, |v| *v &= bits);
    }

    fn change_properties(&mut self, range: &Range, change: impl Fn(&mut u32)) {
        let first = range.first_addr();
        // Ghidra's getLastAddrOpen is never invalid: past the end of a space
        // it is offset 0 of the next space (or the maximal address).
        let end = range.last_addr_open(&self.env.spaces);
        self.properties.split_with(first, |v| *v);
        self.properties.split_with(end, |v| *v);
        for (_, value) in self.properties.range_mut(first, Some(end)) {
            change(value);
        }
    }

    /// Sets the value at a property split point (`flagbase.split(addr) =
    /// val`, as `<db>` decoding does).
    pub fn set_property_point(&mut self, addr: Address, value: u32) {
        self.properties.split_with(addr, |v| *v);
        if let Some(slot) = self.properties.point_mut(&addr) {
            *slot = value;
        }
    }
}
