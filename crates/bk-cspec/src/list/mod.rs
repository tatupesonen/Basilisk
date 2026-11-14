//! Ordered storage resources for inputs or outputs (Ghidra `ParamList` and
//! its five implementations, one struct here with a [`ListKind`]).

mod assign;
mod decode;
mod merged;
pub(crate) mod resolver;
mod trials;

use bk_core::{Address, RangeList, SpaceId, SpaceManager, VarnodeData};

pub use assign::AssignResult;
pub(crate) use assign::{Env, pointer_shape_for};
pub(crate) use decode::decode_list;

use crate::entry::{Containment, Extension, ParamEntry};
use crate::rules::ModelRule;
use crate::types::TypeClass;
use resolver::Resolver;

/// Which of Ghidra's `ParamList` classes a list behaves as (Ghidra's
/// `p_standard` … `p_merged`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListKind {
    /// Inputs, allocated in order without holes (`ParamListStandard`).
    Standard,
    /// Return values (`ParamListStandardOut`).
    StandardOut,
    /// Inputs in any subset of the registers (`ParamListRegister`).
    Register,
    /// Return values, first fitting entry (`ParamListRegisterOut`).
    RegisterOut,
    /// The union of several input lists (`ParamListMerged`).
    Merged,
}

impl ListKind {
    /// Ghidra's name for the class.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::StandardOut => "standard_out",
            Self::Register => "register",
            Self::RegisterOut => "register_out",
            Self::Merged => "merged",
        }
    }

    /// Whether the list describes return values.
    pub const fn is_output(self) -> bool {
        matches!(self, Self::StandardOut | Self::RegisterOut)
    }
}

/// A parameter list (Ghidra `ParamListStandard` and subclasses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamList {
    pub(crate) kind: ListKind,
    pub(crate) entries: Vec<ParamEntry>,
    pub(crate) rules: Vec<ModelRule>,
    pub(crate) resolver: Resolver,
    pub(crate) numgroup: i32,
    pub(crate) maxdelay: i32,
    pub(crate) thisbeforeret: bool,
    pub(crate) auto_killed_by_call: bool,
    pub(crate) resource_start: Vec<i32>,
    pub(crate) use_fillin_fallback: bool,
}

impl ParamList {
    /// An empty list of the given kind.
    pub(crate) fn empty(kind: ListKind) -> Self {
        Self {
            kind,
            entries: Vec::new(),
            rules: Vec::new(),
            resolver: Resolver::default(),
            numgroup: 0,
            maxdelay: 0,
            thisbeforeret: false,
            auto_killed_by_call: false,
            resource_start: Vec::new(),
            use_fillin_fallback: false,
        }
    }

    /// The kind of list (Ghidra `getType`).
    pub const fn kind(&self) -> ListKind {
        self.kind
    }
    /// The entries in order (Ghidra `getEntry`).
    pub fn entries(&self) -> &[ParamEntry] {
        &self.entries
    }
    /// The rules in order, including the one `pointermax` appends.
    pub fn rules(&self) -> &[ModelRule] {
        &self.rules
    }
    /// Number of groups (Ghidra `numgroup`).
    pub const fn num_groups(&self) -> i32 {
        self.numgroup
    }
    /// The first group of each resource section, and the group count last
    /// (Ghidra `resourceStart`).
    pub fn resource_start(&self) -> &[i32] {
        &self.resource_start
    }
    /// Largest heritage delay of any entry's space (Ghidra `getMaxDelay`).
    pub const fn max_delay(&self) -> i32 {
        self.maxdelay
    }
    /// Whether `this` comes before a hidden return pointer (Ghidra
    /// `isThisBeforeRetPointer`).
    pub const fn is_this_before_ret_pointer(&self) -> bool {
        self.thisbeforeret
    }
    /// Whether entries are killed by call automatically (Ghidra
    /// `isAutoKilledByCall`).
    pub const fn is_auto_killed_by_call(&self) -> bool {
        self.auto_killed_by_call
    }
    /// Whether an output list uses the fall-back recovery (no rule can
    /// produce return storage).
    pub const fn uses_fillin_fallback(&self) -> bool {
        self.use_fillin_fallback
    }

    /// Whether the resources are big endian (Ghidra `isBigEndian`: the
    /// first entry's space).
    pub fn is_big_endian(&self) -> bool {
        self.entries.first().is_some_and(|e| e.big_endian)
    }

    /// The stack entry, which is the last entry when present (Ghidra
    /// `getStackEntry`).
    pub fn stack_entry(&self) -> Option<usize> {
        let last = self.entries.len().checked_sub(1)?;
        self.entries
            .get(last)
            .filter(|e| e.is_stack_spill())
            .map(|_| last)
    }

    /// Exclusive single-group entries of a class (Ghidra `extractTiles`).
    pub fn extract_tiles(&self, class: TypeClass) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_exclusion() && e.class == class && e.groups.len() == 1)
            .map(|(i, _)| i)
            .collect()
    }

    pub(crate) fn entry(&self, index: usize) -> Option<&ParamEntry> {
        self.entries.get(index)
    }

    /// The first entry containing the range, justified if `just` (Ghidra
    /// `findEntry`).
    pub fn find_entry(
        &self,
        manager: &SpaceManager,
        loc: Address,
        size: i32,
        just: bool,
    ) -> Option<usize> {
        let space = loc.space()?.index();
        let (members, _) = self.resolver.find(space, loc.offset());
        members.iter().map(|&i| i as usize).find(|&i| {
            self.entries.get(i).is_some_and(|e| {
                e.minsize <= size && (!just || e.justified_contain(manager, loc, size) == Some(0))
            })
        })
    }

    /// How the range relates to the entries (Ghidra `characterizeAsParam`).
    pub fn characterize(&self, manager: &SpaceManager, loc: Address, size: i32) -> Containment {
        let Some(space) = loc.space().map(SpaceId::index) else {
            return Containment::None;
        };
        if !self.resolver.has_space(space) {
            return Containment::None;
        }
        let (members, next) = self.resolver.find(space, loc.offset());
        let mut contains = false;
        let mut contained_by = false;
        for &i in members {
            let Some(e) = self.entries.get(i as usize) else {
                continue;
            };
            match e.justified_contain(manager, loc, size) {
                Some(0) => return Containment::ContainsJustified,
                Some(_) => contains = true,
                None => {}
            }
            if e.is_exclusion() && e.contained_by(loc, size) {
                contained_by = true;
            }
        }
        if contains {
            return Containment::ContainsUnjustified;
        }
        if contained_by {
            return Containment::ContainedBy;
        }
        if next < self.resolver.part_count(space) {
            let end_point = loc.offset().wrapping_add(size as u64).wrapping_sub(1);
            let end = self.resolver.find_end(space, end_point);
            let found = self.resolver.walk(space, next, end).any(|i| {
                self.entries
                    .get(i as usize)
                    .is_some_and(|e| e.is_exclusion() && e.contained_by(loc, size))
            });
            if found {
                return Containment::ContainedBy;
            }
        }
        Containment::None
    }

    /// Whether the location can be a parameter (Ghidra `possibleParam`;
    /// output lists accept any containment, justified or not).
    pub fn possible_param(&self, manager: &SpaceManager, loc: Address, size: i32) -> bool {
        if self.kind.is_output() {
            return self
                .entries
                .iter()
                .any(|e| e.justified_contain(manager, loc, size).is_some());
        }
        self.find_entry(manager, loc, size, true).is_some()
    }

    /// The slot and number of slots of a parameter location (Ghidra
    /// `possibleParamWithSlot`).
    pub fn possible_param_with_slot(
        &self,
        manager: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<(i32, i32)> {
        let e = self
            .entries
            .get(self.find_entry(manager, loc, size, true)?)?;
        let slot = e.slot(loc, 0);
        let slotsize = if e.is_exclusion() {
            e.groups.len() as i32
        } else {
            size.wrapping_sub(1)
                .wrapping_div(e.alignment)
                .wrapping_add(1)
        };
        Some((slot, slotsize))
    }

    /// The biggest exclusive entry inside the range (Ghidra
    /// `getBiggestContainedParam`).
    pub fn biggest_contained_param(
        &self,
        manager: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        let space = loc.space()?.index();
        if !self.resolver.has_space(space) {
            return None;
        }
        let end = loc.add(manager, i64::from(size.wrapping_sub(1)));
        if end.offset() < loc.offset() {
            return None;
        }
        let from = self.resolver.find_begin(space, loc.offset());
        let to = self.resolver.find_end(space, end.offset());
        let mut best: Option<&ParamEntry> = None;
        for i in self.resolver.walk(space, from, to) {
            let Some(e) = self.entries.get(i as usize) else {
                continue;
            };
            if e.contained_by(loc, size) && best.is_none_or(|b| e.size > b.size) {
                best = Some(e);
            }
        }
        let best = best?;
        best.is_exclusion()
            .then(|| VarnodeData::new(best.space, best.base, best.size as u32))
    }

    /// The full container of a location that is not justified in it
    /// (Ghidra `unjustifiedContainer`).
    pub fn unjustified_container(
        &self,
        manager: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        for e in &self.entries {
            if e.minsize > size {
                continue;
            }
            match e.justified_contain(manager, loc, size) {
                None => {}
                Some(0) => return None,
                Some(_) => return e.container(manager, loc, size),
            }
        }
        None
    }

    /// The extension assumed for a small value (Ghidra `assumedExtension`).
    pub fn assumed_extension(
        &self,
        manager: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        for e in &self.entries {
            if e.minsize > size {
                continue;
            }
            let (ext, res) = e.assumed_extension(manager, loc, size);
            if ext != Extension::Copy {
                return (ext, res);
            }
        }
        (Extension::Copy, None)
    }

    /// The stack space of the list, if it has a stack entry (Ghidra
    /// `getSpacebase`).
    pub fn spacebase(&self) -> Option<SpaceId> {
        self.stack_entry()
            .and_then(|i| self.entries.get(i))
            .map(ParamEntry::space)
    }

    /// Adds the ranges of the entries in a space to `res` (Ghidra
    /// `getRangeList`).
    pub fn range_list(&self, space: SpaceId, res: &mut RangeList) {
        for e in self.entries.iter().filter(|e| e.space == space) {
            let last = e.base.wrapping_add(e.size as u64).wrapping_sub(1);
            res.insert_range(space, e.base, last);
        }
    }

    /// Whether two locations can be one parameter (Ghidra `checkJoin`).
    pub fn check_join(
        &self,
        manager: &SpaceManager,
        hi: (Address, i32),
        lo: (Address, i32),
    ) -> bool {
        let (hiaddr, hisize) = hi;
        let (loaddr, losize) = lo;
        let Some(ehi) = self
            .find_entry(manager, hiaddr, hisize, true)
            .and_then(|i| self.entries.get(i))
        else {
            return false;
        };
        let Some(elo) = self
            .find_entry(manager, loaddr, losize, true)
            .and_then(|i| self.entries.get(i))
        else {
            return false;
        };
        if ehi.group() == elo.group() {
            if ehi.is_exclusion() || elo.is_exclusion() {
                return false;
            }
            if !hiaddr.is_contiguous(manager, hisize as u32, loaddr, losize as u32) {
                return false;
            }
            let aligned = |a: Address, e: &ParamEntry| {
                a.offset()
                    .wrapping_sub(e.base)
                    .is_multiple_of(e.alignment as u64)
            };
            return aligned(hiaddr, ehi) && aligned(loaddr, elo);
        }
        let sum = hisize.wrapping_add(losize);
        self.entries.iter().any(|e| {
            e.size >= sum
                && e.justified_contain(manager, loaddr, losize) == Some(0)
                && e.justified_contain(manager, hiaddr, hisize) == Some(losize)
        })
    }

    /// Whether a location can be split into two parameters at `split`
    /// bytes (Ghidra `checkSplit`).
    pub fn check_split(&self, manager: &SpaceManager, loc: Address, size: i32, split: i32) -> bool {
        let loc2 = loc.add(manager, i64::from(split));
        self.find_entry(manager, loc, split, true).is_some()
            && self
                .find_entry(manager, loc2, size.wrapping_sub(split), true)
                .is_some()
    }
}
