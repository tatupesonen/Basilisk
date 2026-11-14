//! Candidate parameter locations and the set of them for one function or
//! call site (Ghidra `ParamTrial`, `ParamActive`), as plain data. The
//! data-flow side (which varnode a trial stands for) belongs to the
//! decompiler (D07).

use std::cmp::Ordering;

use bitflags::bitflags;
use bk_core::{Address, SpaceManager, SpaceType};

use crate::error::{CspecError, Result};
use crate::list::ParamList;

bitflags! {
    /// Properties of a trial (Ghidra's `ParamTrial` flag values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct TrialFlags: u32 {
        /// The trial has been checked.
        const CHECKED = 1;
        /// The trial is a parameter (final verdict).
        const USED = 2;
        /// The trial is definitely not a parameter.
        const DEFNOUSE = 4;
        /// The trial looks used in data-flow.
        const ACTIVE = 8;
        /// No varnode stands for the trial.
        const UNREF = 0x10;
        /// The storage is killed by calls.
        const KILLEDBYCALL = 0x20;
        /// Formed by a remainder operation.
        const REM_FORMED = 0x40;
        /// Formed by an indirect creation.
        const INDCREATE_FORMED = 0x80;
        /// Possibly affected by conditional execution.
        const CONDEXE_EFFECT = 0x100;
        /// Has a realistic ancestor.
        const ANCESTOR_REALISTIC = 0x200;
        /// Shows solid movement into the varnode.
        const ANCESTOR_SOLID = 0x400;
    }
}

/// A storage location that may be a parameter (Ghidra `ParamTrial`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamTrial {
    /// Start of the location.
    pub addr: Address,
    /// Size in bytes.
    pub size: i32,
    /// The slot (input index) the trial stands for, from 1.
    pub slot: i32,
    /// Properties.
    pub flags: TrialFlags,
    /// Index of the matching entry in the list it was classified against.
    pub entry: Option<usize>,
    /// Justified offset into the entry, or -1.
    pub offset: i32,
    /// Argument position if a fixed argument of a variadic function, or -1.
    pub fixed_position: i32,
}

impl ParamTrial {
    /// A trial for a location and slot (Ghidra's constructor).
    pub const fn new(addr: Address, size: i32, slot: i32) -> Self {
        Self {
            addr,
            size,
            slot,
            flags: TrialFlags::empty(),
            entry: None,
            offset: -1,
            fixed_position: -1,
        }
    }

    /// Copies location and flags with a new slot (Ghidra's copy constructor
    /// with slot).
    pub const fn with_slot(other: &Self, slot: i32) -> Self {
        let mut t = Self::new(other.addr, other.size, slot);
        t.flags = other.flags;
        t
    }

    /// Records the matching entry (Ghidra `setEntry`).
    pub fn set_entry(&mut self, entry: Option<usize>, offset: i32) {
        self.entry = entry;
        self.offset = offset;
    }
    /// Marks the trial as a parameter (Ghidra `markUsed`).
    pub fn mark_used(&mut self) {
        self.flags |= TrialFlags::USED;
    }
    /// Marks the trial as used in data-flow (Ghidra `markActive`).
    pub fn mark_active(&mut self) {
        self.flags |= TrialFlags::ACTIVE | TrialFlags::CHECKED;
    }
    /// Marks the trial as not used in data-flow (Ghidra `markInactive`).
    pub fn mark_inactive(&mut self) {
        self.flags.remove(TrialFlags::ACTIVE);
        self.flags |= TrialFlags::CHECKED;
    }
    /// Marks the trial as definitely not a parameter (Ghidra `markNoUse`).
    pub fn mark_no_use(&mut self) {
        self.flags.remove(TrialFlags::ACTIVE | TrialFlags::USED);
        self.flags |= TrialFlags::CHECKED | TrialFlags::DEFNOUSE;
    }
    /// Marks the trial as having no varnode (Ghidra `markUnref`).
    pub fn mark_unref(&mut self) {
        self.flags |= TrialFlags::UNREF | TrialFlags::CHECKED;
        self.slot = -1;
    }
    /// Marks the storage as killed by calls (Ghidra `markKilledByCall`).
    pub fn mark_killed_by_call(&mut self) {
        self.flags |= TrialFlags::KILLEDBYCALL;
    }
    /// Ghidra `isChecked`.
    pub const fn is_checked(&self) -> bool {
        self.flags.contains(TrialFlags::CHECKED)
    }
    /// Ghidra `isActive`.
    pub const fn is_active(&self) -> bool {
        self.flags.contains(TrialFlags::ACTIVE)
    }
    /// Ghidra `isDefinitelyNotUsed`.
    pub const fn is_definitely_not_used(&self) -> bool {
        self.flags.contains(TrialFlags::DEFNOUSE)
    }
    /// Ghidra `isUsed`.
    pub const fn is_used(&self) -> bool {
        self.flags.contains(TrialFlags::USED)
    }
    /// Ghidra `isUnref`.
    pub const fn is_unref(&self) -> bool {
        self.flags.contains(TrialFlags::UNREF)
    }
    /// Ghidra `isKilledByCall`.
    pub const fn is_killed_by_call(&self) -> bool {
        self.flags.contains(TrialFlags::KILLEDBYCALL)
    }
    /// Ghidra `isRemFormed`.
    pub const fn is_rem_formed(&self) -> bool {
        self.flags.contains(TrialFlags::REM_FORMED)
    }
    /// Ghidra `isIndCreateFormed`.
    pub const fn is_ind_create_formed(&self) -> bool {
        self.flags.contains(TrialFlags::INDCREATE_FORMED)
    }
    /// Ghidra `hasAncestorRealistic`.
    pub const fn has_ancestor_realistic(&self) -> bool {
        self.flags.contains(TrialFlags::ANCESTOR_REALISTIC)
    }
    /// Ghidra `hasAncestorSolid`.
    pub const fn has_ancestor_solid(&self) -> bool {
        self.flags.contains(TrialFlags::ANCESTOR_SOLID)
    }

    /// The position of the trial within its group (Ghidra `slotGroup`).
    pub fn slot_group(&self, list: &ParamList) -> i32 {
        self.entry
            .and_then(|e| list.entry(e))
            .map_or(0, |e| e.slot(self.addr, self.size.wrapping_sub(1)))
    }

    /// The trial for the first `size` bytes (Ghidra `splitHi`).
    #[must_use]
    pub const fn split_hi(&self, size: i32) -> Self {
        let mut t = Self::new(self.addr, size, self.slot);
        t.flags = self.flags;
        t
    }

    /// The trial for the last `size` bytes (Ghidra `splitLo`).
    #[must_use]
    pub fn split_lo(&self, manager: &SpaceManager, size: i32) -> Self {
        let addr = self
            .addr
            .add(manager, i64::from(self.size.wrapping_sub(size)));
        let mut t = Self::new(addr, size, self.slot.wrapping_add(1));
        t.flags = self.flags;
        t
    }

    /// Whether the trial can shrink to the given range (Ghidra
    /// `testShrink`).
    pub fn test_shrink(&self, manager: &SpaceManager, addr: Address, size: i32) -> bool {
        let test = if self.addr.is_big_endian(manager) {
            self.addr
                .add(manager, i64::from(self.size.wrapping_sub(size)))
        } else {
            self.addr
        };
        test == addr && self.entry.is_none()
    }

    /// Formal parameter order (Ghidra `ParamTrial::operator<`): by group,
    /// by justified offset within one exclusive entry, by address (reversed
    /// for a reverse stack), then by size. Trials without an entry go last.
    pub fn cmp_formal(&self, other: &Self, list: &ParamList) -> Ordering {
        let a = self.entry.and_then(|e| list.entry(e));
        let b = other.entry.and_then(|e| list.entry(e));
        let (a, b) = match (a, b) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Greater,
            (Some(_), None) => return Ordering::Less,
            (Some(a), Some(b)) => (a, b),
        };
        let g = a.group().cmp(&b.group());
        if g != Ordering::Equal {
            return g;
        }
        if self.entry == other.entry && a.is_exclusion() && self.offset != other.offset {
            return self.offset.cmp(&other.offset);
        }
        if self.addr != other.addr {
            return if a.is_reverse_stack() {
                other.addr.cmp(&self.addr)
            } else {
                self.addr.cmp(&other.addr)
            };
        }
        self.size.cmp(&other.size)
    }
}

/// The trials of one function or call site (Ghidra `ParamActive`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamActive {
    trials: Vec<ParamTrial>,
    slotbase: i32,
    stackplaceholder: i32,
    numpasses: i32,
    maxpass: i32,
    isfullychecked: bool,
    needsfinalcheck: bool,
    recoversubcall: bool,
    join_most_sig_first: bool,
}

impl ParamActive {
    /// An empty set for a called function (`recover_sub`) or the function
    /// itself (Ghidra's constructor).
    pub const fn new(recover_sub: bool) -> Self {
        Self {
            trials: Vec::new(),
            slotbase: 1,
            stackplaceholder: -1,
            numpasses: 0,
            maxpass: 0,
            isfullychecked: false,
            needsfinalcheck: false,
            recoversubcall: recover_sub,
            join_most_sig_first: false,
        }
    }

    /// Resets to an empty set (Ghidra `clear`).
    pub fn clear(&mut self) {
        self.trials.clear();
        self.slotbase = 1;
        self.stackplaceholder = -1;
        self.numpasses = 0;
        self.isfullychecked = false;
        self.join_most_sig_first = false;
    }

    /// Adds a trial in the next slot; storage outside a register-relative
    /// space is marked killed by call (Ghidra `registerTrial`). Returns the
    /// trial's index.
    pub fn register_trial(&mut self, manager: &SpaceManager, addr: Address, size: i32) -> usize {
        let mut t = ParamTrial::new(addr, size, self.slotbase);
        let spacebase = manager
            .space_of(addr)
            .is_some_and(|s| s.space_type() == SpaceType::Spacebase);
        if !spacebase {
            t.mark_killed_by_call();
        }
        self.slotbase += 1;
        self.trials.push(t);
        self.trials.len() - 1
    }

    /// Adds a copy of an existing trial in the next slot (Ghidra
    /// `reregisterTrial`).
    pub fn reregister_trial(&mut self, old: &ParamTrial) {
        self.trials.push(ParamTrial::with_slot(old, self.slotbase));
        self.slotbase += 1;
    }

    /// Number of trials.
    pub fn num_trials(&self) -> usize {
        self.trials.len()
    }
    /// The trials in their current order.
    pub fn trials(&self) -> &[ParamTrial] {
        &self.trials
    }
    /// The trials, mutably.
    pub fn trials_mut(&mut self) -> &mut [ParamTrial] {
        &mut self.trials
    }
    /// The `i`-th trial.
    pub fn trial(&self, i: usize) -> Option<&ParamTrial> {
        self.trials.get(i)
    }
    /// The `i`-th trial, mutably.
    pub fn trial_mut(&mut self, i: usize) -> Option<&mut ParamTrial> {
        self.trials.get_mut(i)
    }

    /// The trial for a call's input varnode in slot `slot` (Ghidra
    /// `getTrialForInputVarnode`).
    pub fn trial_for_input_varnode(&self, slot: i32) -> Option<&ParamTrial> {
        let adjust = if self.stackplaceholder < 0 || slot < self.stackplaceholder {
            1
        } else {
            2
        };
        usize::try_from(slot - adjust)
            .ok()
            .and_then(|i| self.trials.get(i))
    }

    /// The first trial overlapping the range (Ghidra `whichTrial`).
    pub fn which_trial(&self, manager: &SpaceManager, addr: Address, size: i32) -> Option<usize> {
        for (i, t) in self.trials.iter().enumerate() {
            if addr.overlap(manager, 0, t.addr, t.size as u32).is_some() {
                return Some(i);
            }
            if size <= 1 {
                return None;
            }
            let end = addr.add(manager, i64::from(size - 1));
            if end.overlap(manager, 0, t.addr, t.size as u32).is_some() {
                return Some(i);
            }
        }
        None
    }

    /// Ghidra `needsFinalCheck`.
    pub const fn needs_final_check(&self) -> bool {
        self.needsfinalcheck
    }
    /// Ghidra `markNeedsFinalCheck`.
    pub fn mark_needs_final_check(&mut self) {
        self.needsfinalcheck = true;
    }
    /// Ghidra `isJoinMostSigFirst`.
    pub const fn is_join_most_sig_first(&self) -> bool {
        self.join_most_sig_first
    }
    /// Ghidra `setJoinMostSigFirst`.
    pub fn set_join_most_sig_first(&mut self) {
        self.join_most_sig_first = true;
    }
    /// Ghidra `isRecoverSubcall`.
    pub const fn is_recover_subcall(&self) -> bool {
        self.recoversubcall
    }
    /// Ghidra `isFullyChecked`.
    pub const fn is_fully_checked(&self) -> bool {
        self.isfullychecked
    }
    /// Ghidra `markFullyChecked`.
    pub fn mark_fully_checked(&mut self) {
        self.isfullychecked = true;
    }
    /// Reserves a slot for the stack placeholder (Ghidra
    /// `setPlaceholderSlot`).
    pub fn set_placeholder_slot(&mut self) {
        self.stackplaceholder = self.slotbase;
        self.slotbase += 1;
    }
    /// Frees the placeholder slot, renumbering later slots (Ghidra
    /// `freePlaceholderSlot`).
    pub fn free_placeholder_slot(&mut self) {
        for t in &mut self.trials {
            if t.slot > self.stackplaceholder {
                t.slot -= 1;
            }
        }
        self.stackplaceholder = -2;
        self.slotbase -= 1;
        self.maxpass = 0;
    }
    /// Ghidra `getNumPasses`.
    pub const fn num_passes(&self) -> i32 {
        self.numpasses
    }
    /// Ghidra `getMaxPass`.
    pub const fn max_pass(&self) -> i32 {
        self.maxpass
    }
    /// Ghidra `setMaxPass`.
    pub fn set_max_pass(&mut self, val: i32) {
        self.maxpass = val;
    }
    /// Ghidra `finishPass`.
    pub fn finish_pass(&mut self) {
        self.numpasses += 1;
    }

    /// Sorts in formal parameter order (Ghidra `sortTrials`; stable, where
    /// `std::sort` leaves equal trials in a library-dependent order).
    pub fn sort_trials(&mut self, list: &ParamList) {
        self.trials.sort_by(|a, b| a.cmp_formal(b, list));
    }

    /// Sorts by fixed position, then formally (Ghidra
    /// `sortFixedPosition`).
    pub fn sort_fixed_position(&mut self, list: &ParamList) {
        self.trials
            .sort_by(|a, b| match (a.fixed_position, b.fixed_position) {
                (-1, -1) => a.cmp_formal(b, list),
                (-1, _) => Ordering::Greater,
                (_, -1) => Ordering::Less,
                (x, y) => x.cmp(&y),
            });
    }

    /// Removes trials that are not parameters, renumbering slots (Ghidra
    /// `deleteUnusedTrials`).
    pub fn delete_unused_trials(&mut self) {
        self.trials.retain(ParamTrial::is_used);
        for (i, t) in self.trials.iter_mut().enumerate() {
            t.slot = i as i32 + 1;
        }
    }

    /// Splits trial `i` in two, the first of `size` bytes (Ghidra
    /// `splitTrial`).
    pub fn split_trial(&mut self, manager: &SpaceManager, i: usize, size: i32) -> Result<()> {
        if self.stackplaceholder >= 0 {
            return Err(CspecError::new(
                "Cannot split parameter when the placeholder has not been recovered",
            ));
        }
        let Some(&t) = self.trials.get(i) else {
            return Ok(());
        };
        for o in &mut self.trials {
            if o.slot > t.slot {
                o.slot += 1;
            }
        }
        let hi = t.split_hi(size);
        let lo = t.split_lo(manager, t.size - size);
        self.trials.splice(i..=i, [hi, lo]);
        self.slotbase += 1;
        Ok(())
    }

    /// Joins the trial in `slot` with the next into one used trial (Ghidra
    /// `joinTrial`).
    pub fn join_trial(&mut self, slot: i32, addr: Address, size: i32) -> Result<()> {
        if self.stackplaceholder >= 0 {
            return Err(CspecError::new(
                "Cannot join parameters when the placeholder has not been removed",
            ));
        }
        let mut out = Vec::with_capacity(self.trials.len());
        let mut sizecheck = 0;
        for t in &self.trials {
            if t.slot < slot {
                out.push(*t);
            } else if t.slot == slot {
                sizecheck += t.size;
                let mut n = ParamTrial::new(addr, size, slot);
                n.mark_used();
                n.mark_active();
                out.push(n);
            } else if t.slot == slot + 1 {
                sizecheck += t.size;
            } else {
                let mut n = *t;
                n.slot -= 1;
                out.push(n);
            }
        }
        if sizecheck != size {
            return Err(CspecError::new("Size mismatch when joining parameters"));
        }
        self.slotbase -= 1;
        self.trials = out;
        Ok(())
    }

    /// Number of leading used trials (Ghidra `getNumUsed`).
    pub fn num_used(&self) -> usize {
        self.trials.iter().take_while(|t| t.is_used()).count()
    }
}
