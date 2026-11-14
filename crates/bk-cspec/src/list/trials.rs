//! Deciding which trials are parameters (Ghidra `fillinMap` of each list
//! kind, `buildTrialMap`, `separateSections`, `markGroupNoUse`,
//! `markBestInactive`, `forceExclusionGroup`, `forceNoUse`,
//! `forceInactiveChain`, `ParamListStandardOut::fillinMapFallback`).

use bk_core::{SpaceManager, SpaceType};

use super::{ListKind, ParamList};
use crate::error::{CspecError, Result};
use crate::trial::ParamActive;
use crate::types::TypeClass;

impl ParamList {
    /// Marks each trial used or not and puts them in formal order (Ghidra
    /// `fillinMap`).
    pub fn fillin_map(&self, manager: &SpaceManager, active: &mut ParamActive) -> Result<()> {
        if active.num_trials() == 0 {
            return Ok(());
        }
        match self.kind {
            ListKind::Standard => self.fillin_standard(manager, active),
            ListKind::Register => {
                for t in active.trials_mut() {
                    match self.find_entry(manager, t.addr, t.size, true) {
                        None => t.mark_no_use(),
                        Some(e) => {
                            t.set_entry(Some(e), 0);
                            if t.is_active() {
                                t.mark_used();
                            }
                        }
                    }
                }
                active.sort_trials(self);
                Ok(())
            }
            ListKind::StandardOut | ListKind::RegisterOut => {
                self.fillin_output(manager, active);
                Ok(())
            }
            ListKind::Merged => Err(CspecError::new(
                "Cannot determine prototype before model has been resolved",
            )),
        }
    }

    fn fillin_standard(&self, manager: &SpaceManager, active: &mut ParamActive) -> Result<()> {
        if self.entries.is_empty() {
            return Err(CspecError::new(
                "Cannot derive parameter storage for prototype model without parameter entries",
            ));
        }
        self.build_trial_map(manager, active)?;
        self.force_exclusion_group(active);
        let starts = self.separate_sections(active)?;
        for w in starts.windows(2) {
            if let [a, b] = *w {
                self.force_no_use(active, a, b);
            }
        }
        for (i, w) in starts.windows(2).enumerate() {
            if let [a, b] = *w {
                let group_start = if self.resource_start.len() >= 2 {
                    self.resource_start.get(i).copied().unwrap_or(0)
                } else {
                    0
                };
                self.force_inactive_chain(manager, active, (a, b), group_start);
            }
        }
        for t in active.trials_mut() {
            if t.is_active() {
                t.mark_used();
            }
        }
        Ok(())
    }

    /// From among the entries of a group, the one best matching a class
    /// (Ghidra `selectUnreferenceEntry`).
    fn select_unreference_entry(&self, grp: i32, pref: TypeClass) -> Option<usize> {
        let mut best = None;
        let mut best_score = -1;
        for (i, e) in self.entries.iter().enumerate() {
            if e.group() != grp {
                continue;
            }
            let score = if e.type_class() == pref {
                2
            } else {
                i32::from(pref == TypeClass::General)
            };
            if score > best_score {
                best_score = score;
                best = Some(i);
            }
        }
        best
    }

    /// Ghidra `buildTrialMap`.
    fn build_trial_map(&self, manager: &SpaceManager, active: &mut ParamActive) -> Result<()> {
        let mut hitlist: Vec<Option<usize>> = Vec::new();
        let (mut float_count, mut int_count) = (0, 0);
        for t in active.trials_mut() {
            match self.find_entry(manager, t.addr, t.size, true) {
                None => t.mark_no_use(),
                Some(ei) => {
                    t.set_entry(Some(ei), 0);
                    let Some(e) = self.entries.get(ei) else {
                        continue;
                    };
                    if t.is_active() {
                        if e.type_class() == TypeClass::Float {
                            float_count += 1;
                        } else {
                            int_count += 1;
                        }
                    }
                    let grp = usize::try_from(e.group()).unwrap_or(0);
                    if hitlist.len() <= grp {
                        hitlist.resize(grp + 1, None);
                    }
                    if let Some(slot @ None) = hitlist.get_mut(grp) {
                        *slot = Some(ei);
                    }
                }
            }
        }
        let pref = if float_count > int_count {
            TypeClass::Float
        } else {
            TypeClass::General
        };
        for (i, hit) in hitlist.iter().enumerate() {
            match hit {
                None => {
                    let Some(ei) = self.select_unreference_entry(i as i32, pref) else {
                        continue;
                    };
                    let Some(e) = self.entries.get(ei) else {
                        continue;
                    };
                    let sz = if e.is_exclusion() {
                        e.size()
                    } else {
                        e.align()
                    };
                    let mut slot = 0;
                    let addr = e.addr_by_slot(manager, &mut slot, sz, 1)?;
                    let ti = active.register_trial(manager, addr, sz);
                    if let Some(t) = active.trial_mut(ti) {
                        t.mark_unref();
                        t.set_entry(Some(ei), 0);
                    }
                }
                Some(ei) => {
                    let Some(e) = self.entries.get(*ei) else {
                        continue;
                    };
                    if e.is_exclusion() {
                        continue;
                    }
                    let mut slots: Vec<bool> = Vec::new();
                    for t in active.trials() {
                        if t.entry != Some(*ei) {
                            continue;
                        }
                        let mut s = e.slot(t.addr, 0) - e.group();
                        let mut end = e.slot(t.addr, t.size - 1) - e.group();
                        if end < s {
                            std::mem::swap(&mut s, &mut end);
                        }
                        let (Ok(s), Ok(end)) = (usize::try_from(s), usize::try_from(end)) else {
                            continue;
                        };
                        if end > 1 << 16 {
                            continue;
                        }
                        if slots.len() <= end {
                            slots.resize(end + 1, false);
                        }
                        for slot in slots.get_mut(s..=end).unwrap_or(&mut []) {
                            *slot = true;
                        }
                    }
                    for (j, used) in slots.iter().enumerate() {
                        if *used {
                            continue;
                        }
                        let mut next = j as i32;
                        let addr = e.addr_by_slot(manager, &mut next, e.align(), 1)?;
                        let ti = active.register_trial(manager, addr, e.align());
                        if let Some(t) = active.trial_mut(ti) {
                            t.mark_unref();
                            t.set_entry(Some(*ei), 0);
                        }
                    }
                }
            }
        }
        active.sort_trials(self);
        Ok(())
    }

    /// Start index of the trials of each resource section, and the trial
    /// count last (Ghidra `separateSections`).
    fn separate_sections(&self, active: &ParamActive) -> Result<Vec<usize>> {
        let n = active.num_trials();
        let mut starts = vec![0];
        if self.resource_start.len() < 2 {
            // Ghidra reads past the end of `resourceStart` here (lists with
            // `separatefloat="false"`); treat the list as one section.
            starts.push(n);
            return Ok(starts);
        }
        let mut next_group = self.resource_start.get(1).copied().unwrap_or(i32::MAX);
        let mut next_section = 2;
        for (i, t) in active.trials().iter().enumerate() {
            let Some(e) = t.entry.and_then(|e| self.entries.get(e)) else {
                continue;
            };
            if e.group() >= next_group {
                if next_section > self.resource_start.len() {
                    return Err(CspecError::new("Missing next resource start"));
                }
                // Ghidra reads one past the end when `next_section` equals
                // the length; no later group can reach it.
                next_group = self
                    .resource_start
                    .get(next_section)
                    .copied()
                    .unwrap_or(i32::MAX);
                next_section += 1;
                starts.push(i);
            }
        }
        starts.push(n);
        Ok(starts)
    }

    /// Marks every other trial of the active trial's groups as not used
    /// (Ghidra `markGroupNoUse`).
    fn mark_group_no_use(&self, active: &mut ParamActive, active_trial: usize, start: usize) {
        let Some(active_entry) = active
            .trial(active_trial)
            .and_then(|t| t.entry)
            .and_then(|e| self.entries.get(e))
        else {
            return;
        };
        for (i, t) in active.trials_mut().iter_mut().enumerate().skip(start) {
            if i == active_trial || t.is_definitely_not_used() {
                continue;
            }
            let overlaps = t
                .entry
                .and_then(|e| self.entries.get(e))
                .is_some_and(|e| e.group_overlap(active_entry));
            if !overlaps {
                break;
            }
            t.mark_no_use();
        }
    }

    /// Keeps the most likely of several inactive trials in a group (Ghidra
    /// `markBestInactive`).
    fn mark_best_inactive(
        &self,
        active: &mut ParamActive,
        group: i32,
        start: usize,
        pref: TypeClass,
    ) {
        let mut best = None;
        let mut best_score = -1;
        for (i, t) in active.trials().iter().enumerate().skip(start) {
            if t.is_definitely_not_used() {
                continue;
            }
            let Some(e) = t.entry.and_then(|e| self.entries.get(e)) else {
                continue;
            };
            if e.group() != group {
                break;
            }
            if e.all_groups().len() > 1 {
                continue;
            }
            let mut score = 0;
            if t.has_ancestor_realistic() {
                score += 5;
                if t.has_ancestor_solid() {
                    score += 5;
                }
            }
            if e.type_class() == pref {
                score += 1;
            }
            if score > best_score {
                best_score = score;
                best = Some(i);
            }
        }
        if let Some(b) = best {
            self.mark_group_no_use(active, b, start);
        }
    }

    /// Ghidra `forceExclusionGroup`.
    fn force_exclusion_group(&self, active: &mut ParamActive) {
        let mut cur_group = -1;
        let mut group_start = 0usize;
        let mut inactive = 0;
        for i in 0..active.num_trials() {
            let Some(t) = active.trial(i).copied() else {
                continue;
            };
            if t.is_definitely_not_used() {
                continue;
            }
            let Some(e) = t.entry.and_then(|e| self.entries.get(e)) else {
                continue;
            };
            if !e.is_exclusion() {
                continue;
            }
            let grp = e.group();
            if grp != cur_group {
                if inactive > 1 {
                    self.mark_best_inactive(active, cur_group, group_start, TypeClass::General);
                }
                cur_group = grp;
                group_start = i;
                inactive = 0;
            }
            if t.is_active() {
                self.mark_group_no_use(active, i, group_start);
            } else {
                inactive += 1;
            }
        }
        if inactive > 1 {
            self.mark_best_inactive(active, cur_group, group_start, TypeClass::General);
        }
    }

    /// Ghidra `forceNoUse`.
    fn force_no_use(&self, active: &mut ParamActive, start: usize, stop: usize) {
        let mut seen = false;
        let mut cur_group = -1;
        let mut all_defnouse = false;
        for t in active.trials_mut().get_mut(start..stop).unwrap_or(&mut []) {
            let Some(e) = t.entry.and_then(|e| self.entries.get(e)) else {
                continue;
            };
            let grp = e.group();
            if grp <= cur_group && e.is_exclusion() {
                if !t.is_definitely_not_used() {
                    all_defnouse = false;
                }
            } else {
                if all_defnouse {
                    seen = true;
                }
                all_defnouse = t.is_definitely_not_used();
                cur_group = grp;
            }
            if seen {
                t.mark_inactive();
            }
        }
    }

    /// Ghidra `forceInactiveChain` with the given chain limit.
    fn force_inactive_chain(
        &self,
        manager: &SpaceManager,
        active: &mut ParamActive,
        (start, stop): (usize, usize),
        group_start: i32,
    ) {
        const MAXCHAIN: i32 = 2;
        let recover_sub = active.is_recover_subcall();
        let mut seen = false;
        let mut chain = 0i32;
        let mut max: Option<usize> = None;
        let mut prev_slot = 0;
        for i in start..stop {
            let Some(t) = active.trial(i).copied() else {
                continue;
            };
            let slot_group = t.slot_group(self);
            if i > start {
                prev_slot = active.trial(i - 1).map_or(0, |p| p.slot_group(self));
            }
            if t.is_definitely_not_used() {
                continue;
            }
            if t.is_active() {
                chain = 0;
                if !seen {
                    max = Some(i);
                }
            } else {
                if t.is_unref()
                    && recover_sub
                    && manager
                        .space_of(t.addr)
                        .is_some_and(|s| s.space_type() == SpaceType::Spacebase)
                {
                    seen = true;
                }
                chain = if i == start {
                    chain.wrapping_add(slot_group - group_start + 1)
                } else {
                    chain.wrapping_add(slot_group - prev_slot)
                };
                if chain > MAXCHAIN {
                    seen = true;
                }
            }
            if seen && let Some(t) = active.trial_mut(i) {
                t.mark_inactive();
            }
        }
        if let Some(max) = max {
            for t in active.trials_mut().get_mut(start..=max).unwrap_or(&mut []) {
                if !t.is_definitely_not_used() && !t.is_active() {
                    t.mark_active();
                }
            }
        }
    }

    /// `ParamListStandardOut::fillinMap`.
    fn fillin_output(&self, manager: &SpaceManager, active: &mut ParamActive) {
        if self.use_fillin_fallback {
            self.fillin_fallback(manager, active, false);
            return;
        }
        for t in active.trials_mut() {
            t.set_entry(None, 0);
            if !t.is_active() {
                continue;
            }
            let Some(ei) = self.find_entry(manager, t.addr, t.size, false) else {
                t.mark_no_use();
                continue;
            };
            let Some(e) = self.entries.get(ei) else {
                continue;
            };
            let res = e.justified_contain(manager, t.addr, t.size).unwrap_or(-1);
            if (t.is_rem_formed() || t.is_ind_create_formed()) && !e.is_first_in_class() {
                t.mark_no_use();
                continue;
            }
            t.set_entry(Some(ei), res);
        }
        active.sort_trials(self);
        for rule in &self.rules {
            if rule.fillin_output_map(self, active) {
                for t in active.trials_mut() {
                    if t.is_active() {
                        t.mark_used();
                    } else {
                        t.mark_no_use();
                        t.set_entry(None, 0);
                    }
                }
                return;
            }
        }
        self.fillin_fallback(manager, active, true);
    }

    /// Ghidra `fillinMapFallback`.
    fn fillin_fallback(&self, manager: &SpaceManager, active: &mut ParamActive, first_only: bool) {
        let mut best: Option<usize> = None;
        let mut best_cover = 0;
        let mut best_class = TypeClass::Ptr;
        for (ei, e) in self.entries.iter().enumerate() {
            if first_only && !e.is_first_in_class() && e.is_exclusion() && e.all_groups().len() == 1
            {
                continue;
            }
            let mut putative = false;
            for t in active.trials_mut() {
                if t.is_active() {
                    match e.justified_contain(manager, t.addr, t.size) {
                        Some(res) => {
                            t.set_entry(Some(ei), res);
                            putative = true;
                        }
                        None => t.set_entry(None, 0),
                    }
                } else {
                    t.set_entry(None, 0);
                }
            }
            if !putative {
                continue;
            }
            active.sort_trials(self);
            let mut offmatch = 0;
            let mut k = 0;
            let n = active.num_trials();
            while k < n {
                let Some(t) = active.trial(k) else { break };
                if t.entry.is_some() {
                    if offmatch != t.offset {
                        break;
                    }
                    let check = (offmatch == 0 && e.is_param_check_low())
                        || (offmatch != 0 && e.is_param_check_high());
                    if check && (t.is_rem_formed() || t.is_ind_create_formed()) {
                        break;
                    }
                    offmatch += t.size;
                }
                k += 1;
            }
            if offmatch < e.min_size() {
                k = 0;
            }
            if k == n && (e.type_class() < best_class || offmatch > best_cover) {
                best = Some(ei);
                best_cover = offmatch;
                best_class = e.type_class();
            }
        }
        let Some(bi) = best else {
            for t in active.trials_mut() {
                t.mark_no_use();
            }
            return;
        };
        let Some(be) = self.entries.get(bi) else {
            return;
        };
        for t in active.trials_mut() {
            if t.is_active()
                && let Some(res) = be.justified_contain(manager, t.addr, t.size)
            {
                t.mark_used();
                t.set_entry(Some(bi), res);
                continue;
            }
            t.mark_no_use();
            t.set_entry(None, 0);
        }
        active.sort_trials(self);
    }
}
