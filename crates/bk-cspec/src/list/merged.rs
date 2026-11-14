//! The union of several input lists (Ghidra `ParamListMerged::foldIn` and
//! `finalize`).

use super::resolver::Resolver;
use super::{ListKind, ParamList};

impl ParamList {
    /// An empty merged list.
    pub(crate) fn merged() -> Self {
        Self::empty(ListKind::Merged)
    }

    /// Adds another list's entries: duplicates are dropped and containing
    /// entries replace what they contain (Ghidra `foldIn`).
    pub(crate) fn fold_in(&mut self, other: &Self) {
        if self.entries.is_empty() {
            self.entries.clone_from(&other.entries);
            return;
        }
        for op in &other.entries {
            let mut typeint = 0;
            let mut at = None;
            for (i, own) in self.entries.iter().enumerate() {
                if own.subsumes_definition(op) {
                    typeint = 2;
                    at = Some(i);
                    break;
                }
                if op.subsumes_definition(own) {
                    typeint = 1;
                    at = Some(i);
                    break;
                }
            }
            let own_min = at
                .and_then(|i| self.entries.get(i))
                .map(crate::entry::ParamEntry::min_size);
            if typeint != 0 && own_min != Some(op.min_size()) {
                typeint = 0;
            }
            if typeint == 1
                && let Some(slot) = at.and_then(|i| self.entries.get_mut(i))
            {
                *slot = op.clone();
            }
            if typeint == 0 {
                self.entries.push(op.clone());
            }
        }
    }

    /// Builds the resolver once every list is folded in (Ghidra
    /// `finalize`). Ghidra leaves the group count, delay and flags of a
    /// merged list uninitialised; here they are the largest group, the
    /// largest delay of the folded lists, and false.
    pub(crate) fn finalize_merged(&mut self, maxdelay: i32) {
        self.resolver = Resolver::build(&self.entries);
        self.numgroup = self
            .entries
            .iter()
            .filter_map(|e| e.all_groups().last().copied())
            .max()
            .map_or(0, |g| g.saturating_add(1));
        self.maxdelay = maxdelay;
    }
}
