//! A space resolver that follows a manager while it is being built.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use bk_marshal::{SpaceId, SpaceResolver};

/// The names and indices of a [`SpaceManager`](super::SpaceManager)'s spaces,
/// shared with a decoder while the manager is still being filled.
///
/// A decoder holds its [`SpaceResolver`] by shared reference for as long as
/// it runs, so it cannot hold the manager that
/// [`SpaceManager::decode_spaces`](super::SpaceManager::decode_spaces) is
/// adding spaces to. Ghidra's decoder simply points at the manager it fills.
/// Here the manager keeps this directory up to date as spaces are inserted,
/// and a decoder built on [`SpaceManager::directory`](super::SpaceManager::directory)
/// resolves each space as soon as it exists: an overlay can name the space it
/// overlays, and elements after `<spaces>` can name any space.
#[derive(Debug, Default)]
pub struct SpaceDirectory {
    inner: RwLock<Entries>,
}

#[derive(Debug, Default)]
struct Entries {
    names: HashMap<Box<str>, SpaceId>,
    /// Whether each index is in use.
    present: Vec<bool>,
    stack: Option<SpaceId>,
    join: Option<SpaceId>,
}

impl SpaceDirectory {
    /// Records a newly inserted space and the manager's current stack and
    /// join spaces.
    pub(super) fn add(
        &self,
        name: &str,
        id: SpaceId,
        stack: Option<SpaceId>,
        join: Option<SpaceId>,
    ) {
        let mut entries = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        entries.names.insert(name.into(), id);
        let index = id.index() as usize;
        if entries.present.len() <= index {
            entries.present.resize(index + 1, false);
        }
        if let Some(slot) = entries.present.get_mut(index) {
            *slot = true;
        }
        entries.stack = stack;
        entries.join = join;
    }

    fn read<T>(&self, f: impl FnOnce(&Entries) -> T) -> T {
        f(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl SpaceResolver for SpaceDirectory {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        self.read(|entries| entries.names.get(name).copied())
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        let index32 = u32::try_from(index).ok()?;
        let slot = usize::try_from(index).ok()?;
        self.read(|entries| {
            entries
                .present
                .get(slot)
                .copied()
                .unwrap_or(false)
                .then_some(SpaceId::new(index32))
        })
    }

    fn space_count(&self) -> u64 {
        self.read(|entries| entries.present.len() as u64)
    }

    fn stack_space(&self) -> Option<SpaceId> {
        self.read(|entries| entries.stack)
    }

    fn join_space(&self) -> Option<SpaceId> {
        self.read(|entries| entries.join)
    }
}
