//! The type factory (Ghidra `TypeFactory`): the arena of types, its two
//! indexes, interning, and the per-function overlay.

pub mod base;
pub mod composite;
pub mod enumeration;
mod index;
mod order;
mod partial;
mod pointer;
pub mod typedef;

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use bk_core::Provenance;
use rustc_hash::FxHashMap;

use crate::compare::identity::{compare_dependency, identity_hash};
use crate::entry::{TypeEntry, TypeFlags, TypeKind};
use crate::error::{Result, TypeError};
use crate::ids::TypeId;
use crate::meta::Metatype;
use crate::org::{DataOrganization, TypeEnv};
use index::{HashIndex, name_hash};

/// An entry slot: the entry, and whether it is still in the factory
/// (destroyed entries keep their slot so stale ids never alias new types).
#[derive(Clone, Debug)]
struct Slot {
    entry: TypeEntry,
    live: bool,
}

/// The caches of common atomic types (Ghidra `typecache`, `typecache10`,
/// `typecache16`, `type_nochar`, `charcache`).
#[derive(Clone, Debug, Default)]
pub(crate) struct BaseCache {
    pub(crate) table: [[Option<TypeId>; 8]; 9],
    pub(crate) float10: Option<TypeId>,
    pub(crate) float16: Option<TypeId>,
    pub(crate) nochar: Option<TypeId>,
    pub(crate) chars: [Option<TypeId>; 5],
}

impl BaseCache {
    /// Column of a metatype in [`BaseCache::table`] (`m - TYPE_FLOAT`).
    pub(crate) fn column(meta: Metatype) -> Option<usize> {
        (meta as usize).checked_sub(Metatype::Float as usize)
    }
}

/// The placeholder returned for an id that names no entry. Public entry
/// points validate ids, so internal code sees it only for ids a caller
/// invented.
static INVALID: LazyLock<TypeEntry> =
    LazyLock::new(|| TypeEntry::new(0, 1, Metatype::Void, TypeKind::Void));

/// The container of all data-types of an architecture, or of one function's
/// decompilation when forked (Ghidra `TypeFactory`; ADR-025 3e).
#[derive(Clone, Debug)]
pub struct TypeFactory {
    pub(crate) env: TypeEnv,
    pub(crate) org: DataOrganization,
    parent: Option<Arc<TypeFactory>>,
    slots: Vec<Slot>,
    identity: HashIndex,
    names: HashIndex,
    pointers_to: FxHashMap<TypeId, Vec<TypeId>>,
    pub(crate) cache: BaseCache,
    warnings: BTreeMap<TypeId, String>,
    incomplete_typedefs: Vec<TypeId>,
    provenance: Provenance,
    pub(crate) hooks: crate::xml::Hooks,
    pub(crate) decode_depth: usize,
}

impl TypeFactory {
    /// An empty factory for an architecture whose data organisation is
    /// already complete (see [`DataOrganization::setup_sizes`]).
    pub fn new(env: TypeEnv, mut org: DataOrganization) -> Self {
        org.setup_sizes(&env);
        Self {
            env,
            org,
            parent: None,
            slots: Vec::new(),
            identity: HashIndex::default(),
            names: HashIndex::default(),
            pointers_to: FxHashMap::default(),
            cache: BaseCache::default(),
            warnings: BTreeMap::new(),
            incomplete_typedefs: Vec::new(),
            provenance: Provenance::Default,
            hooks: crate::xml::Hooks::default(),
            decode_depth: 0,
        }
    }

    /// A factory with Ghidra's default core types
    /// (`SleighArchitecture::buildCoreTypes`), cached.
    pub fn with_core_types(env: TypeEnv, org: DataOrganization) -> Result<Self> {
        let mut f = Self::new(env, org);
        f.build_default_core_types()?;
        Ok(f)
    }

    /// Forks a frozen factory: the child reads through to `parent` and takes
    /// every new entry itself (one child per function decompilation). New
    /// entries are marked [`Provenance::Analysis`] unless the caller sets
    /// another provenance. Forking a fork is an error.
    pub fn fork(parent: &Arc<Self>) -> Result<Self> {
        if parent.parent.is_some() {
            return Err(TypeError::new("Cannot fork a forked type factory"));
        }
        Ok(Self {
            env: parent.env.clone(),
            org: parent.org.clone(),
            parent: Some(Arc::clone(parent)),
            slots: Vec::new(),
            identity: HashIndex::default(),
            names: HashIndex::default(),
            pointers_to: FxHashMap::default(),
            cache: parent.cache.clone(),
            warnings: BTreeMap::new(),
            incomplete_typedefs: Vec::new(),
            provenance: Provenance::Analysis,
            hooks: parent.hooks.clone(),
            decode_depth: 0,
        })
    }

    /// Installs the hooks (type source, prototype codec, scope look-ups).
    pub fn set_hooks(&mut self, hooks: crate::xml::Hooks) {
        self.hooks = hooks;
    }

    /// Whether this is a fork.
    pub fn is_fork(&self) -> bool {
        self.parent.is_some()
    }

    /// The ids of the entries this fork created (the inferred types), in
    /// creation order; empty for a root factory.
    pub fn overlay_ids(&self) -> Vec<TypeId> {
        if self.parent.is_none() {
            return Vec::new();
        }
        self.own_ids().collect()
    }

    /// The architecture facts.
    pub fn env(&self) -> &TypeEnv {
        &self.env
    }

    /// The data organisation.
    pub fn data_organization(&self) -> &DataOrganization {
        &self.org
    }

    /// The provenance given to entries created from now on.
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// Sets the provenance given to entries created from now on, and merged
    /// into entries found again (the more trusted is kept).
    pub fn set_provenance(&mut self, provenance: Provenance) {
        self.provenance = provenance;
    }

    /// The entry of `id`, if it is a live type of this factory.
    pub fn get(&self, id: TypeId) -> Option<&TypeEntry> {
        let slot = self.slot(id)?;
        slot.live.then_some(&slot.entry)
    }

    /// The entry of `id`, or an error.
    pub fn entry_checked(&self, id: TypeId) -> Result<&TypeEntry> {
        self.get(id).ok_or(TypeError::InvalidId(id))
    }

    fn slot(&self, id: TypeId) -> Option<&Slot> {
        if id.is_overlay() == self.parent.is_some() {
            self.slots.get(id.index())
        } else if let Some(parent) = &self.parent {
            parent.slots.get(id.index())
        } else {
            None
        }
    }

    /// The entry of `id`, live or destroyed; a void placeholder for an id
    /// this factory never issued.
    pub(crate) fn entry(&self, id: TypeId) -> &TypeEntry {
        self.slot(id).map_or(&INVALID, |s| &s.entry)
    }

    /// Whether an id belongs to this factory's own layer (not to a frozen
    /// parent).
    fn is_own(&self, id: TypeId) -> bool {
        id.is_overlay() == self.parent.is_some()
    }

    fn entry_mut(&mut self, id: TypeId) -> Result<&mut TypeEntry> {
        if !self.is_own(id) {
            return Err(if self.parent.is_some() {
                TypeError::FrozenParent(id)
            } else {
                TypeError::InvalidId(id)
            });
        }
        self.slots
            .get_mut(id.index())
            .map(|s| &mut s.entry)
            .ok_or(TypeError::InvalidId(id))
    }

    fn own_ids(&self) -> impl Iterator<Item = TypeId> + '_ {
        let overlay = self.parent.is_some();
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.live)
            .map(move |(i, _)| TypeId::new(i as u32, overlay))
    }

    /// Every live type, parent's first, in creation order.
    pub fn ids(&self) -> Vec<TypeId> {
        let mut out: Vec<TypeId> = self
            .parent
            .as_ref()
            .map(|p| p.own_ids().collect())
            .unwrap_or_default();
        out.extend(self.own_ids());
        out
    }

    /// Number of live types.
    pub fn len(&self) -> usize {
        let own = self.slots.iter().filter(|s| s.live).count();
        own + self.parent.as_ref().map_or(0, |p| p.len())
    }

    /// Whether the factory holds no types.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ---- indexes -----------------------------------------------------

    fn lookup_identity(&self, cand: &TypeEntry) -> Option<TypeId> {
        let hash = identity_hash(cand);
        let layers = self
            .parent
            .iter()
            .map(|p| &**p)
            .chain(std::iter::once(self));
        for layer in layers {
            for &id in layer.identity.candidates(hash) {
                let e = layer.entry(id);
                if e.id == cand.id && compare_dependency(e, cand) == 0 {
                    return Some(id);
                }
            }
        }
        None
    }

    /// Ghidra `findByIdLocal`: the type of that name and id, or with id 0
    /// the type of that name with the smallest id.
    pub fn find_by_id_local(&self, name: &str, id: u64) -> Option<TypeId> {
        let hash = name_hash(name);
        let mut best: Option<(u64, TypeId)> = None;
        let layers = self
            .parent
            .iter()
            .map(|p| &**p)
            .chain(std::iter::once(self));
        for layer in layers {
            for &tid in layer.names.candidates(hash) {
                let e = layer.entry(tid);
                if &*e.name != name {
                    continue;
                }
                if id != 0 {
                    if e.id == id {
                        return Some(tid);
                    }
                } else if best.is_none_or(|(b, _)| e.id < b) {
                    best = Some((e.id, tid));
                }
            }
        }
        if id != 0 { None } else { best.map(|(_, t)| t) }
    }

    /// Ghidra `findById` (base class): looks in this factory only; a
    /// non-zero size selects the sized instance of a variable-length type.
    pub fn find_by_id(&self, name: &str, id: u64, size: i32) -> Option<TypeId> {
        let id = if size > 0 {
            crate::entry::hash_size(id, size)
        } else {
            id
        };
        self.find_by_id_local(name, id)
    }

    /// Ghidra `findByName`: the first type with the name.
    pub fn find_by_name(&self, name: &str) -> Option<TypeId> {
        self.find_by_id(name, 0, 0)
    }

    fn index_entry(&mut self, id: TypeId) {
        let e = self.entry(id);
        let ih = identity_hash(e);
        let nh = (e.id != 0).then(|| name_hash(&e.name));
        let ptrto = e.pointer().map(|p| p.ptrto);
        self.identity.insert(ih, id);
        if let Some(nh) = nh {
            self.names.insert(nh, id);
        }
        if let Some(target) = ptrto {
            let list = self.pointers_to.entry(target).or_default();
            if !list.contains(&id) {
                list.push(id);
            }
        }
    }

    fn unindex_entry(&mut self, id: TypeId) {
        let e = self.entry(id);
        let ih = identity_hash(e);
        let nh = (e.id != 0).then(|| name_hash(&e.name));
        self.identity.remove(ih, id);
        if let Some(nh) = nh {
            self.names.remove(nh, id);
        }
    }

    /// Changes an own entry in place, keeping the indexes right.
    pub(crate) fn modify<R>(
        &mut self,
        id: TypeId,
        change: impl FnOnce(&mut TypeEntry) -> R,
    ) -> Result<R> {
        self.entry_mut(id)?;
        self.unindex_entry(id);
        let res = change(self.entry_mut(id)?);
        self.index_entry(id);
        Ok(res)
    }

    /// Ghidra `insert`: adds a new entry, refusing a duplicate.
    pub(crate) fn insert(&mut self, mut entry: TypeEntry) -> Result<TypeId> {
        if let Some(old) = self.lookup_identity(&entry) {
            let mut msg = format!("Shared type id: {:x}\n  ", entry.id);
            msg.push_str(&self.print_raw_entry(&entry));
            msg.push_str(" : ");
            msg.push_str(&self.print_raw(old));
            return Err(TypeError::new(msg));
        }
        let index = u32::try_from(self.slots.len())
            .ok()
            .filter(|&i| i < (1 << 31))
            .ok_or_else(|| TypeError::new("Too many data-types"))?;
        entry.provenance = self.provenance;
        let id = TypeId::new(index, self.parent.is_some());
        self.slots.push(Slot { entry, live: true });
        self.index_entry(id);
        Ok(id)
    }

    /// Ghidra `findAdd`: the existing equal type, or the candidate added.
    pub(crate) fn find_add(&mut self, mut cand: TypeEntry) -> Result<TypeId> {
        let found = if cand.name.is_empty() {
            self.lookup_identity(&cand)
        } else {
            if cand.id == 0 {
                return Err(TypeError::new(format!(
                    "Datatype must have a valid id: {}",
                    cand.name
                )));
            }
            match self.find_by_id_local(&cand.name, cand.id) {
                Some(res) => {
                    if compare_dependency(self.entry(res), &cand) != 0 {
                        return Err(TypeError::new(format!(
                            "Trying to alter definition of type: {}",
                            cand.name
                        )));
                    }
                    Some(res)
                }
                None => None,
            }
        };
        if let Some(res) = found {
            self.merge_provenance(res);
            return Ok(res);
        }
        if cand.alignment < 0 {
            cand.align_size = self.org.primitive_align_size(cand.size.max(0) as u32);
            cand.alignment = self.org.alignment(cand.align_size.max(0) as u32);
        }
        self.insert(cand)
    }

    /// Keeps the more trusted provenance on a type found again.
    fn merge_provenance(&mut self, id: TypeId) {
        let p = self.provenance;
        if let Ok(e) = self.entry_mut(id) {
            e.provenance = e.provenance.or_more_trusted(p);
        }
    }

    /// Ghidra `destroyType`: removes a non-core type from both indexes.
    pub fn destroy_type(&mut self, id: TypeId) -> Result<()> {
        let e = self.entry_checked(id)?;
        if e.is_core() {
            return Err(TypeError::new("Cannot destroy core type"));
        }
        self.entry_mut(id)?;
        self.warnings.remove(&id);
        self.unindex_entry(id);
        if let Some(slot) = self.slots.get_mut(id.index()) {
            slot.live = false;
        }
        Ok(())
    }

    /// Ghidra `clear`: removes every type of this factory's own layer.
    pub fn clear(&mut self) {
        let ids: Vec<TypeId> = self.own_ids().collect();
        for id in ids {
            if let Some(slot) = self.slots.get_mut(id.index()) {
                slot.live = false;
            }
        }
        self.identity.clear();
        self.names.clear();
        self.pointers_to.clear();
        self.cache = self
            .parent
            .as_ref()
            .map(|p| p.cache.clone())
            .unwrap_or_default();
        self.warnings.clear();
        self.incomplete_typedefs.clear();
    }

    /// Ghidra `clearNoncore`: removes every non-core type of this layer.
    pub fn clear_noncore(&mut self) {
        let ids: Vec<TypeId> = self
            .own_ids()
            .filter(|&id| !self.entry(id).is_core())
            .collect();
        for id in ids {
            self.unindex_entry(id);
            if let Some(slot) = self.slots.get_mut(id.index()) {
                slot.live = false;
            }
        }
        self.warnings.clear();
        self.incomplete_typedefs.clear();
    }

    // ---- warnings ----------------------------------------------------

    /// Ghidra `insertWarning`.
    pub(crate) fn insert_warning(&mut self, id: TypeId, warning: String) -> Result<()> {
        if self.entry(id).id == 0 {
            return Err(TypeError::new(
                "Can only issue warnings for named data-types",
            ));
        }
        self.entry_mut(id)?.flags |= TypeFlags::WARNING_ISSUED;
        self.warnings.insert(id, warning);
        Ok(())
    }

    /// Ghidra `findWarning`: the warning for a type, looking through
    /// pointers, typedefs and partial types.
    pub fn find_warning(&self, mut id: TypeId) -> Option<&str> {
        let mut guard = 0;
        while let Some(p) = self
            .entry(id)
            .pointer()
            .filter(|_| self.entry(id).metatype == Metatype::Ptr)
        {
            id = p.ptrto;
            guard += 1;
            if guard > 1000 {
                return None;
            }
        }
        while let Some(t) = self.entry(id).typedef_imm {
            id = t;
            guard += 1;
            if guard > 2000 {
                return None;
            }
        }
        if let Some(base) = self.entry(id).partial_base() {
            id = base;
        }
        self.warnings
            .get(&id)
            .or_else(|| self.parent.as_ref().and_then(|p| p.warnings.get(&id)))
            .map(String::as_str)
    }

    /// Ghidra `setDisplayFormat`.
    pub fn set_display_format(&mut self, id: TypeId, format: u32) -> Result<()> {
        self.entry_mut(id)?.set_display_format(format);
        Ok(())
    }

    /// The pointers recorded as pointing to `target`.
    pub(crate) fn pointers_to(&self, target: TypeId) -> Vec<TypeId> {
        let mut out: Vec<TypeId> = self
            .parent
            .as_ref()
            .and_then(|p| p.pointers_to.get(&target).cloned())
            .unwrap_or_default();
        if let Some(own) = self.pointers_to.get(&target) {
            out.extend(own);
        }
        out.retain(|&p| self.slot(p).is_some_and(|s| s.live));
        out
    }
}
