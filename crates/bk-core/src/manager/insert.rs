//! Adding spaces to a manager (Ghidra `AddrSpaceManager::insertSpace`,
//! `assignShortcut` and `copySpaces`).

use super::SpaceManager;
use crate::error::SpaceError;
use crate::space::{
    CONSTANT_SPACE, CONSTANT_SPACE_NAME, FSPEC_SPACE_NAME, IOP_SPACE_NAME, JOIN_SPACE_NAME,
    OTHER_SPACE, STACK_SPACE_NAME, Space, SpaceFlags, SpaceType, UNIQUE_SPACE_NAME,
};
use bk_marshal::SpaceId;

impl SpaceManager {
    /// Adds a space (Ghidra `insertSpace`).
    ///
    /// The checks are Ghidra's: the reserved kinds carry their reserved names,
    /// there is at most one of each special space and one space called
    /// `stack`, the constant space has index 0 and `OTHER` index 1, indices
    /// and names are unique. basilisk adds one: no space but the constant
    /// space may take index 0, which lets an address tell whether it is a
    /// constant without the manager. Inserting an overlay marks its base
    /// space as overlaid. The space is given a shortcut character.
    pub fn insert_space(&mut self, mut space: Space) -> Result<SpaceId, SpaceError> {
        let id = space.id();
        let name = space.name();
        let reserved = |expected: &str, slot: Option<SpaceId>| {
            if name != expected {
                Err(SpaceError::WrongSpaceType {
                    name: name.to_owned(),
                })
            } else if slot.is_some() {
                Err(SpaceError::DuplicateSpace {
                    name: name.to_owned(),
                })
            } else {
                Ok(())
            }
        };
        let mut overlaid = None;
        match space.space_type() {
            SpaceType::Constant => {
                if name != CONSTANT_SPACE_NAME {
                    return Err(SpaceError::WrongSpaceType {
                        name: name.to_owned(),
                    });
                }
                if id != CONSTANT_SPACE {
                    return Err(SpaceError::ConstantSpaceIndex);
                }
            }
            SpaceType::Internal => reserved(UNIQUE_SPACE_NAME, self.unique)?,
            SpaceType::Fspec => reserved(FSPEC_SPACE_NAME, self.fspec)?,
            SpaceType::Join => reserved(JOIN_SPACE_NAME, self.join)?,
            SpaceType::Iop => reserved(IOP_SPACE_NAME, self.iop)?,
            SpaceType::Spacebase | SpaceType::Processor => {
                if name == STACK_SPACE_NAME
                    && space.space_type() == SpaceType::Spacebase
                    && self.stack.is_some()
                {
                    return Err(SpaceError::DuplicateSpace {
                        name: name.to_owned(),
                    });
                }
                if space.is_overlay() {
                    let base = space.contain().ok_or(SpaceError::NoSuchSpace(id))?;
                    self.space(base).ok_or(SpaceError::NoSuchSpace(base))?;
                    overlaid = Some(base);
                } else if space.is_other_space() && id != OTHER_SPACE {
                    return Err(SpaceError::OtherSpaceIndex);
                }
            }
        }
        if id == CONSTANT_SPACE && space.space_type() != SpaceType::Constant {
            return Err(SpaceError::ReservedIndexZero {
                name: name.to_owned(),
            });
        }
        let index = id.index() as usize;
        if let Some(existing) = self.space(id) {
            return Err(SpaceError::DuplicateIndex {
                name: name.to_owned(),
                existing: existing.name().to_owned(),
            });
        }
        if self.names.contains_key(name) {
            return Err(SpaceError::DuplicateSpace {
                name: name.to_owned(),
            });
        }

        let slot = match space.space_type() {
            SpaceType::Constant => Some(&mut self.constant),
            SpaceType::Internal => Some(&mut self.unique),
            SpaceType::Fspec => Some(&mut self.fspec),
            SpaceType::Join => Some(&mut self.join),
            SpaceType::Iop => Some(&mut self.iop),
            SpaceType::Spacebase if name == STACK_SPACE_NAME => Some(&mut self.stack),
            SpaceType::Spacebase | SpaceType::Processor => None,
        };
        if let Some(slot) = slot {
            *slot = Some(id);
        }
        if let Some(base) = overlaid
            && let Some(base) = self.space_mut(base)
        {
            base.insert_flags(SpaceFlags::OVERLAYBASE);
        }
        self.assign_shortcut(&mut space);
        self.names.insert(space.name().into(), id);
        self.directory.add(space.name(), id, self.stack, self.join);
        if self.spaces.len() <= index {
            self.spaces.resize_with(index + 1, || None);
        }
        if let Some(entry) = self.spaces.get_mut(index) {
            *entry = Some(Box::new(space));
        }
        Ok(id)
    }

    /// Picks a shortcut character for a new space (Ghidra `assignShortcut`):
    /// `#` for the constant space, `%` for a processor space named
    /// `register`, otherwise the first letter of the name or a letter for the
    /// kind, lowercased; on a collision the next letter, wrapping from `z` to
    /// `a`; after 26 collisions `z`, which is then not registered.
    fn assign_shortcut(&mut self, space: &mut Space) {
        if let Some(assigned) = space.shortcut() {
            self.shortcuts
                .entry(assigned as u8)
                .or_insert_with(|| space.id());
            return;
        }
        let mut shortcut = match space.space_type() {
            SpaceType::Constant => b'#',
            SpaceType::Processor if space.name() == "register" => b'%',
            SpaceType::Processor => space.name().bytes().next().unwrap_or(0),
            SpaceType::Spacebase => b's',
            SpaceType::Internal => b'u',
            SpaceType::Fspec => b'f',
            SpaceType::Join => b'j',
            SpaceType::Iop => b'i',
        };
        shortcut = shortcut.to_ascii_lowercase();
        let mut collisions = 0;
        while self.shortcuts.contains_key(&shortcut) {
            collisions += 1;
            if collisions > 26 {
                space.set_shortcut(b'z');
                return;
            }
            shortcut = shortcut.wrapping_add(1);
            if !shortcut.is_ascii_lowercase() {
                shortcut = b'a';
            }
        }
        self.shortcuts.insert(shortcut, space.id());
        space.set_shortcut(shortcut);
    }

    /// Adds every space of `other` to this manager, with the same default
    /// code and data spaces (Ghidra `copySpaces`). Ghidra shares the space
    /// objects between the two managers; here they are copied, so later
    /// changes to one manager's spaces do not show in the other.
    pub fn copy_spaces(&mut self, other: &Self) -> Result<(), SpaceError> {
        for space in other.spaces() {
            self.insert_space(space.clone())?;
        }
        let code = other.default_code.ok_or(SpaceError::NoDefaultSpace)?;
        self.set_default_code_space(code)?;
        let data = other.default_data.ok_or(SpaceError::NoDefaultSpace)?;
        self.set_default_data_space(data)
    }
}
