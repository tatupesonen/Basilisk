//! The space manager: the set of address spaces of one processor (Ghidra
//! `AddrSpaceManager` in `translate.hh`/`translate.cc`).
//!
//! The manager owns every [`Space`], looks spaces up by index, name and
//! shortcut, knows the special spaces (constant, unique, join, stack, fspec,
//! iop) and the default code and data spaces, records where pointers cannot
//! point, holds the join records and the processor's registers. Join
//! operations are in the `join` submodule and the `<spaces>` decoder in
//! `decode`.

mod decode;
mod directory;
mod join;

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use bk_marshal::{SpaceId, SpaceResolver};

use crate::address::Address;
use crate::error::SpaceError;
use crate::join::JoinTable;
use crate::range::Range;
use crate::rangelist::RangeList;
use crate::register::{NoRegisters, RegisterLookup};
use crate::space::{
    CONSTANT_SPACE, CONSTANT_SPACE_NAME, FSPEC_SPACE_NAME, IOP_SPACE_NAME, JOIN_SPACE_NAME,
    OTHER_SPACE, STACK_SPACE_NAME, Space, SpaceFlags, SpaceType, UNIQUE_SPACE_NAME,
};
use crate::varnode::VarnodeData;

pub use decode::TruncationTag;
pub use directory::SpaceDirectory;

/// Maps a constant in a space with an unusual pointer encoding to the
/// address it means (Ghidra `AddressResolver`), for example a segmented
/// pointer whose segment comes from context.
pub trait AddressResolver: Debug + Send + Sync {
    /// The address that the `size`-byte constant `value`, used as a pointer at
    /// `point`, refers to, and the full encoding of the pointer (which may
    /// carry bits from context).
    fn resolve(&self, value: u64, size: u32, point: Address) -> (Address, u64);
}

/// The address spaces of one processor and everything attached to them
/// (Ghidra `AddrSpaceManager`).
///
/// A manager is built with [`SpaceManager::insert_space`] or
/// [`SpaceManager::decode_spaces`] and is then read through `&self`. The one
/// thing that changes behind `&self` is the table of join records, which
/// decoding or building a join address may extend; it sits behind a lock.
#[derive(Debug)]
pub struct SpaceManager {
    /// Spaces by index (Ghidra `baselist`); `None` for unused indices.
    spaces: Vec<Option<Box<Space>>>,
    names: HashMap<Box<str>, SpaceId>,
    shortcuts: HashMap<u8, SpaceId>,
    constant: Option<SpaceId>,
    default_code: Option<SpaceId>,
    default_data: Option<SpaceId>,
    iop: Option<SpaceId>,
    fspec: Option<SpaceId>,
    join: Option<SpaceId>,
    stack: Option<SpaceId>,
    unique: Option<SpaceId>,
    /// Ranges that pointers cannot point to (Ghidra `nohighptr`).
    no_high_ptr: RangeList,
    /// Special constant resolvers by space index (Ghidra `resolvelist`).
    resolvers: Vec<Option<Box<dyn AddressResolver>>>,
    registers: Arc<dyn RegisterLookup>,
    joins: RwLock<JoinTable>,
    directory: Arc<SpaceDirectory>,
}

impl Default for SpaceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SpaceManager {
    /// An empty manager without spaces or registers.
    pub fn new() -> Self {
        Self {
            spaces: Vec::new(),
            names: HashMap::new(),
            shortcuts: HashMap::new(),
            constant: None,
            default_code: None,
            default_data: None,
            iop: None,
            fspec: None,
            join: None,
            stack: None,
            unique: None,
            no_high_ptr: RangeList::new(),
            resolvers: Vec::new(),
            registers: Arc::new(NoRegisters),
            joins: RwLock::new(JoinTable::default()),
            directory: Arc::new(SpaceDirectory::default()),
        }
    }

    /// The processor's registers, consulted when addresses are read, printed
    /// or decoded by register name.
    pub fn registers(&self) -> &dyn RegisterLookup {
        &*self.registers
    }

    /// Attaches the processor's registers (in Ghidra every space points at
    /// its `Translate`, which answers these queries).
    pub fn set_registers(&mut self, registers: Arc<dyn RegisterLookup>) {
        self.registers = registers;
    }

    /// The location of the register called `name` (Ghidra
    /// `Translate::getRegister`).
    pub fn register(&self, name: &str) -> Result<VarnodeData, SpaceError> {
        self.registers
            .register(name)
            .ok_or_else(|| SpaceError::UnknownRegister(name.to_owned()))
    }

    /// A resolver that follows this manager as spaces are added, for a
    /// decoder that reads the `<spaces>` element and goes on to read elements
    /// referring to those spaces (see [`SpaceManager::decode_spaces`]).
    pub fn directory(&self) -> Arc<SpaceDirectory> {
        Arc::clone(&self.directory)
    }

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

    /// Sets the default code space, which is also made the default data
    /// space (Ghidra `setDefaultCodeSpace`). It can be set only once.
    pub fn set_default_code_space(&mut self, space: SpaceId) -> Result<(), SpaceError> {
        if self.default_code.is_some() {
            return Err(SpaceError::DefaultSpaceSetTwice);
        }
        if self.space(space).is_none() {
            return Err(SpaceError::BadDefaultSpaceIndex);
        }
        self.default_code = Some(space);
        self.default_data = Some(space);
        Ok(())
    }

    /// Sets the default data space, after the code space (Ghidra
    /// `setDefaultDataSpace`).
    pub fn set_default_data_space(&mut self, space: SpaceId) -> Result<(), SpaceError> {
        if self.default_code.is_none() {
            return Err(SpaceError::DataSpaceBeforeCodeSpace);
        }
        if self.space(space).is_none() {
            return Err(SpaceError::BadDefaultDataSpaceIndex);
        }
        self.default_data = Some(space);
        Ok(())
    }

    /// Marks a space as justified opposite to its endianness (Ghidra
    /// `setReverseJustified`).
    pub fn set_reverse_justified(&mut self, space: SpaceId) -> Result<(), SpaceError> {
        self.require_mut(space)?
            .insert_flags(SpaceFlags::REVERSE_JUSTIFICATION);
        Ok(())
    }

    /// Records that near pointers of `size` bytes can reach the space (Ghidra
    /// `markNearPointers`).
    pub fn mark_near_pointers(&mut self, space: SpaceId, size: u32) -> Result<(), SpaceError> {
        self.require_mut(space)?.mark_near_pointers(size);
        Ok(())
    }

    /// Attaches the base register of a register-relative space (Ghidra
    /// `addSpacebasePointer`). `truncated_size` is the register's size as
    /// used, `stack_grows_negative` the direction of a push.
    pub fn add_spacebase_pointer(
        &mut self,
        space: SpaceId,
        register: VarnodeData,
        truncated_size: u32,
        stack_grows_negative: bool,
    ) -> Result<(), SpaceError> {
        let register_big_endian = register.addr().is_big_endian(self);
        self.require_mut(space)?.set_base_register(
            register,
            truncated_size,
            stack_grows_negative,
            register_big_endian,
        )
    }

    /// Records a range that pointers cannot point to; once a whole space is
    /// covered, no pointer into it is possible (Ghidra `addNoHighPtr`).
    pub fn add_no_high_ptr(&mut self, range: &Range) -> Result<(), SpaceError> {
        let space = self.require_mut(range.space())?;
        if space.flags().contains(SpaceFlags::ADDRESSABLE_NONE) {
            return Ok(());
        }
        space.remove_flags(SpaceFlags::ADDRESSABLE_ALL);
        let highest = space.highest();
        self.no_high_ptr
            .insert_range(range.space(), range.first(), range.last());
        let whole = Range::new(range.space(), 0, highest);
        if self.no_high_ptr.contains_range(&whole) {
            self.require_mut(range.space())?
                .insert_flags(SpaceFlags::ADDRESSABLE_NONE);
        }
        Ok(())
    }

    /// Replaces the constant resolver of a space (Ghidra `insertResolver`).
    pub fn insert_resolver(
        &mut self,
        space: SpaceId,
        resolver: Box<dyn AddressResolver>,
    ) -> Result<(), SpaceError> {
        self.require(space)?;
        let index = space.index() as usize;
        if self.resolvers.len() <= index {
            self.resolvers.resize_with(index + 1, || None);
        }
        if let Some(slot) = self.resolvers.get_mut(index) {
            *slot = Some(resolver);
        }
        Ok(())
    }

    /// Sets the range of offsets in a space that constants may be taken to
    /// point into (Ghidra `setInferPtrBounds`).
    pub fn set_infer_ptr_bounds(&mut self, range: &Range) -> Result<(), SpaceError> {
        self.require_mut(range.space())?
            .set_pointer_bounds(range.first(), range.last());
        Ok(())
    }

    /// Sets the dead-code delay of a space (Ghidra `setDeadcodeDelay`).
    pub fn set_deadcode_delay(&mut self, space: SpaceId, delay: i32) -> Result<(), SpaceError> {
        self.require_mut(space)?.set_deadcode_delay(delay);
        Ok(())
    }

    /// Truncates a space to the size a `<truncate_space>` element gives
    /// (Ghidra `truncateSpace`).
    pub fn truncate_space(&mut self, tag: &TruncationTag) -> Result<(), SpaceError> {
        let id = self
            .space_by_name(tag.name())
            .map(Space::id)
            .ok_or_else(|| SpaceError::UnknownTruncatedSpace(tag.name().to_owned()))?;
        self.require_mut(id)?.truncate(tag.size());
        Ok(())
    }

    /// The space with the given id, if this manager has it.
    pub fn space(&self, id: SpaceId) -> Option<&Space> {
        self.spaces.get(id.index() as usize)?.as_deref()
    }

    /// The space with the given id, or [`SpaceError::NoSuchSpace`].
    pub fn require(&self, id: SpaceId) -> Result<&Space, SpaceError> {
        self.space(id).ok_or(SpaceError::NoSuchSpace(id))
    }

    fn space_mut(&mut self, id: SpaceId) -> Option<&mut Space> {
        self.spaces.get_mut(id.index() as usize)?.as_deref_mut()
    }

    fn require_mut(&mut self, id: SpaceId) -> Result<&mut Space, SpaceError> {
        self.space_mut(id).ok_or(SpaceError::NoSuchSpace(id))
    }

    /// The space of an address; `None` for the invalid and maximal addresses
    /// and for spaces this manager does not have.
    pub fn space_of(&self, address: Address) -> Option<&Space> {
        self.space(address.space()?)
    }

    /// The space with the given index (Ghidra `getSpace`).
    pub fn space_at(&self, index: u32) -> Option<&Space> {
        self.space(SpaceId::new(index))
    }

    /// One more than the highest space index in use (Ghidra `numSpaces`).
    pub fn num_spaces(&self) -> u32 {
        self.spaces.len() as u32
    }

    /// Every space, in index order.
    pub fn spaces(&self) -> impl Iterator<Item = &Space> {
        self.spaces.iter().filter_map(Option::as_deref)
    }

    /// The space with the given name (Ghidra `getSpaceByName`).
    #[expect(
        clippy::same_name_method,
        reason = "the inherent method returns the space; the SpaceResolver one only its id"
    )]
    pub fn space_by_name(&self, name: &str) -> Option<&Space> {
        self.space(*self.names.get(name)?)
    }

    /// The space with the given shortcut character (Ghidra
    /// `getSpaceByShortcut`).
    pub fn space_by_shortcut(&self, shortcut: char) -> Option<&Space> {
        let byte = u8::try_from(shortcut).ok()?;
        self.space(*self.shortcuts.get(&byte)?)
    }

    fn special(&self, id: Option<SpaceId>) -> Option<&Space> {
        self.space(id?)
    }

    /// The constant space.
    pub fn constant_space(&self) -> Option<&Space> {
        self.special(self.constant)
    }

    /// The space of p-code operation references (Ghidra `getIopSpace`).
    pub fn iop_space(&self) -> Option<&Space> {
        self.special(self.iop)
    }

    /// The space of call-specification references (Ghidra `getFspecSpace`).
    pub fn fspec_space(&self) -> Option<&Space> {
        self.special(self.fspec)
    }

    /// The join space (Ghidra `getJoinSpace`).
    #[expect(
        clippy::same_name_method,
        reason = "the inherent method returns the space; the SpaceResolver one only its id"
    )]
    pub fn join_space(&self) -> Option<&Space> {
        self.special(self.join)
    }

    /// The register-relative space called `stack` (Ghidra `getStackSpace`).
    #[expect(
        clippy::same_name_method,
        reason = "the inherent method returns the space; the SpaceResolver one only its id"
    )]
    pub fn stack_space(&self) -> Option<&Space> {
        self.special(self.stack)
    }

    /// The pool of temporary registers (Ghidra `getUniqueSpace`).
    pub fn unique_space(&self) -> Option<&Space> {
        self.special(self.unique)
    }

    /// The space where code lives by default, usually main memory (Ghidra
    /// `getDefaultCodeSpace`).
    pub fn default_code_space(&self) -> Option<&Space> {
        self.special(self.default_code)
    }

    /// The space where data lives by default (Ghidra `getDefaultDataSpace`).
    pub fn default_data_space(&self) -> Option<&Space> {
        self.special(self.default_data)
    }

    /// The size of an offset in the default code space (Ghidra
    /// `getDefaultSize`).
    pub fn default_size(&self) -> Result<u32, SpaceError> {
        self.default_code_space()
            .map(Space::addr_size)
            .ok_or(SpaceError::NoDefaultSpace)
    }

    /// Whether pointers to the `size` bytes at `address` can exist (Ghidra
    /// `highPtrPossible`). False for an address without a space.
    pub fn high_ptr_possible(&self, address: Address, size: u32) -> bool {
        let Some(space) = self.space_of(address) else {
            return false;
        };
        let flags = space.flags() & (SpaceFlags::ADDRESSABLE_ALL | SpaceFlags::ADDRESSABLE_NONE);
        if !flags.is_empty() {
            return flags == SpaceFlags::ADDRESSABLE_ALL;
        }
        !self.no_high_ptr.in_range(address, u64::from(size))
    }

    /// The address that the `size`-byte constant `value` in `space`, used at
    /// `point`, refers to, and the pointer's full encoding (Ghidra
    /// `resolveConstant`). Without a resolver for the space, the value is
    /// scaled from addressable units to bytes and wrapped to the space.
    pub fn resolve_constant(
        &self,
        space: SpaceId,
        value: u64,
        size: u32,
        point: Address,
    ) -> Result<(Address, u64), SpaceError> {
        if let Some(Some(resolver)) = self.resolvers.get(space.index() as usize) {
            return Ok(resolver.resolve(value, size, point));
        }
        let spc = self.require(space)?;
        let offset = spc.wrap_offset(spc.address_to_byte(value));
        Ok((Address::new(space, offset), value))
    }

    /// The space with the lowest index (Ghidra `getNextSpaceInOrder(null)`).
    pub fn first_space(&self) -> Option<SpaceId> {
        self.spaces().next().map(Space::id)
    }

    /// The space with the next higher index after `space`; `None` after the
    /// last, where Ghidra returns its maximal space marker (Ghidra
    /// `getNextSpaceInOrder`).
    pub fn next_space_after(&self, space: SpaceId) -> Option<SpaceId> {
        let start = (space.index() as usize).saturating_add(1);
        self.spaces
            .get(start..)?
            .iter()
            .find_map(|slot| slot.as_deref().map(Space::id))
    }

    /// Reads an address written as `[space:][0x]hex`, scaling the offset from
    /// addressable units to bytes; without a space name the default data
    /// space is used (Ghidra `parseAddressSimple`).
    pub fn parse_address_simple(&self, text: &str) -> Result<Address, SpaceError> {
        let (space, rest) = match text.split_once(':') {
            None => (
                self.default_data_space()
                    .ok_or(SpaceError::NoDefaultSpace)?,
                text,
            ),
            Some((name, rest)) => (
                self.space_by_name(name)
                    .ok_or_else(|| SpaceError::UnknownSpaceName(name.to_owned()))?,
                rest,
            ),
        };
        let digits = rest.strip_prefix("0x").unwrap_or(rest);
        let value = bk_marshal::xml::number::scan(digits, bk_marshal::xml::number::Radix::Hex);
        Ok(Address::new(
            space.id(),
            space.address_to_byte(value.as_u64()),
        ))
    }
}

impl SpaceResolver for SpaceManager {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        self.names.get(name).copied()
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        let index = u32::try_from(index).ok()?;
        self.space_at(index).map(Space::id)
    }

    fn space_count(&self) -> u64 {
        self.spaces.len() as u64
    }

    fn stack_space(&self) -> Option<SpaceId> {
        self.stack
    }

    fn join_space(&self) -> Option<SpaceId> {
        self.join
    }
}
