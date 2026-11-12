//! `VarnodeData`: a space, an offset and a size (Ghidra `pcoderaw.hh`).

use std::cmp::Ordering;

use bk_marshal::{Decoder, Encoder, SpaceId};

use crate::address::{Address, SpaceKey};
use crate::error::SpaceError;
use crate::manager::SpaceManager;

/// The data that defines a memory location: an address space, an offset
/// within it and a number of bytes (Ghidra `VarnodeData`).
///
/// This is the bare triple, without the data-flow links of a varnode in a
/// syntax tree. Like an [`Address`] it may have no space: decoding an empty
/// `<addr/>` element gives such a value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarnodeData {
    space: SpaceKey,
    /// The offset within the space, in bytes.
    pub offset: u64,
    /// The number of bytes in the location.
    pub size: u32,
}

impl VarnodeData {
    /// A location in no space, of size 0.
    pub const NONE: Self = Self {
        space: SpaceKey::NONE,
        offset: 0,
        size: 0,
    };

    /// A location given by its space, offset and size.
    pub const fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space: SpaceKey::of(space),
            offset,
            size,
        }
    }

    /// The location of `size` bytes starting at `address`.
    pub const fn from_address(address: Address, size: u32) -> Self {
        Self {
            space: address.key(),
            offset: address.offset(),
            size,
        }
    }

    /// The address space, if the location has one.
    pub const fn space(&self) -> Option<SpaceId> {
        self.space.id()
    }

    /// Moves the location to another space, keeping offset and size.
    pub const fn set_space(&mut self, space: SpaceId) {
        self.space = SpaceKey::of(space);
    }

    /// The address of the first byte of the location (Ghidra `getAddr`).
    pub const fn addr(&self) -> Address {
        Address::from_key(self.space, self.offset)
    }

    /// Treats the location as a constant that names an address space, as the
    /// first input of a `LOAD` or `STORE` does, and returns that space
    /// (Ghidra `getSpaceFromConst`).
    ///
    /// Ghidra stores the host pointer to the space in the constant; basilisk
    /// stores the space's index (see
    /// [`Address::const_from_space`]).
    pub fn space_from_const(&self) -> Option<SpaceId> {
        u32::try_from(self.offset).ok().map(SpaceId::new)
    }

    /// Whether this location, as a range of bytes, contains `other`.
    pub const fn contains(&self, other: &Self) -> bool {
        if self.space.raw() != other.space.raw() || other.offset < self.offset {
            return false;
        }
        let last = self.offset.wrapping_add((self.size as u64).wrapping_sub(1));
        let other_last = other
            .offset
            .wrapping_add((other.size as u64).wrapping_sub(1));
        last >= other_last
    }

    /// Whether this location and `lo` are adjacent, with this one holding the
    /// more significant bytes: `lo` follows it in a big-endian space and
    /// precedes it in a little-endian one.
    pub fn is_contiguous(&self, manager: &SpaceManager, lo: &Self) -> bool {
        self.addr()
            .is_contiguous(manager, self.size, lo.addr(), lo.size)
    }

    /// Reads a location from the next element, which may be `<addr>`,
    /// `<register>` or `<varnode>` (Ghidra `decode`).
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        let Some(element) = decoder.open_element()? else {
            return Err(bk_marshal::DecodeError::NoElement { expected: "addr" }.into());
        };
        let data = Self::decode_from_attributes(decoder, manager)?;
        decoder.close_element(element)?;
        Ok(data)
    }

    /// Reads a location from the attributes of the element that is open,
    /// which may have other attributes too (Ghidra `decodeFromAttributes`).
    ///
    /// A `space` attribute gives the space, whose own rules read the rest
    /// (`offset` and `size`, or the pieces of a join); a `name` attribute
    /// names a register. With neither, the result has no space.
    pub fn decode_from_attributes<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == bk_marshal::ids::ATTRIB_SPACE {
                let space = decoder.read_space()?;
                decoder.rewind_attributes();
                let (offset, size) = manager.decode_attributes(space, decoder)?;
                return Ok(Self::new(space, offset, size));
            } else if attribute == bk_marshal::ids::ATTRIB_NAME {
                let name = decoder.read_string()?;
                return manager.register(name);
            }
        }
        Ok(Self::NONE)
    }

    /// Writes the location as an `<addr>` element with its size. Ghidra has
    /// no `VarnodeData::encode`; this is `Address::encode(encoder, size)`.
    pub fn encode<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        self.addr().encode_sized(encoder, manager, self.size)
    }
}

impl VarnodeData {
    /// A value that prints the location as a register name or as the
    /// space's shortcut and raw offset (Ghidra `printRaw`).
    pub fn raw(self, manager: &SpaceManager) -> crate::address::RawAddress<'_> {
        self.addr().raw_sized(manager, self.size)
    }
}

impl Default for VarnodeData {
    fn default() -> Self {
        Self::NONE
    }
}

impl std::fmt::Debug for VarnodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VarnodeData({:?}:{})", self.addr(), self.size)
    }
}

/// Locations sort by space index, then offset, then size with the larger
/// first, as Ghidra's `operator<` does.
impl Ord for VarnodeData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
            .then(other.size.cmp(&self.size))
    }
}

impl PartialOrd for VarnodeData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
