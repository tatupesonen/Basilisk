//! Addresses (Ghidra `Address` in `address.hh`/`address.cc`).
//!
//! An [`Address`] is a space and an offset. It is `Copy`, 16 bytes, and
//! ordered without consulting the [`SpaceManager`]: the space is stored as
//! its index, which is also how Ghidra orders addresses. Everything that needs
//! the space's properties (size, endianness, join records) takes the manager.

use std::fmt;

use bk_marshal::{Decoder, Encoder, SpaceId};

use crate::error::SpaceError;
use crate::ids::ELEM_ADDR;
use crate::manager::SpaceManager;
use crate::space::{CONSTANT_SPACE, SpaceType};
use crate::varnode::VarnodeData;

/// The space of an address as stored: 0 for no space (Ghidra's null space
/// pointer), `u32::MAX` for the maximal extreme (Ghidra's `~0` pointer), and
/// the space index plus one otherwise. Deriving `Ord` on this gives exactly
/// Ghidra's address order: invalid first, maximal last, otherwise by index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SpaceKey(u32);

impl SpaceKey {
    /// No space: the invalid (and minimal) address.
    pub(crate) const NONE: Self = Self(0);
    /// The space of the maximal address, after every real space.
    pub(crate) const MAXIMAL: Self = Self(u32::MAX);

    /// The key of a real space. A manager never hands out an index above
    /// [`MAX_SPACE_INDEX`](crate::space::MAX_SPACE_INDEX), so the result is
    /// never one of the two extremes for a space it owns.
    pub(crate) const fn of(space: SpaceId) -> Self {
        Self(space.index().saturating_add(1))
    }

    /// The space, if the key names a real one.
    pub(crate) const fn id(self) -> Option<SpaceId> {
        match self.0 {
            0 | u32::MAX => None,
            raw => Some(SpaceId::new(raw - 1)),
        }
    }

    /// The raw key, for comparisons in `const` functions.
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for SpaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NONE => f.write_str("none"),
            Self::MAXIMAL => f.write_str("maximal"),
            Self(raw) => write!(f, "#{}", raw - 1),
        }
    }
}

/// A location in an address space: a space and a byte offset (Ghidra
/// `Address`).
///
/// Besides real addresses there are three extremes: the invalid address
/// (no space; it is also the minimal address and sorts before every other),
/// and the maximal address, which sorts after every other. Addresses order
/// by space index, then offset.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct Address {
    space: SpaceKey,
    offset: u64,
}

impl Address {
    /// The invalid address (Ghidra's default `Address()`, and
    /// `Address(m_minimal)`): no space, offset 0.
    pub const INVALID: Self = Self {
        space: SpaceKey::NONE,
        offset: 0,
    };
    /// The smallest address (Ghidra `Address(m_minimal)`), equal to
    /// [`Address::INVALID`].
    pub const MINIMAL: Self = Self::INVALID;
    /// The largest address (Ghidra `Address(m_maximal)`).
    pub const MAXIMAL: Self = Self {
        space: SpaceKey::MAXIMAL,
        offset: u64::MAX,
    };

    /// The address at `offset` bytes into `space`.
    pub const fn new(space: SpaceId, offset: u64) -> Self {
        Self {
            space: SpaceKey::of(space),
            offset,
        }
    }

    /// The address in the maximal extreme's space at the given offset. Only
    /// [`Range::last_addr_open`](crate::Range::last_addr_open) builds one with
    /// an offset other than `u64::MAX`.
    pub(crate) const fn maximal_at(offset: u64) -> Self {
        Self {
            space: SpaceKey::MAXIMAL,
            offset,
        }
    }

    /// A constant as an address in the constant space (Ghidra
    /// `AddrSpaceManager::getConstant`).
    pub const fn constant(value: u64) -> Self {
        Self::new(CONSTANT_SPACE, value)
    }

    /// A constant that names an address space, as the first input of a
    /// `LOAD` or `STORE` does (Ghidra `AddrSpaceManager::createConstFromSpace`).
    /// Ghidra puts the host pointer to the space in the constant; Basilisk
    /// puts the space's index, which
    /// [`VarnodeData::space_from_const`](crate::VarnodeData::space_from_const)
    /// reads back.
    pub const fn const_from_space(space: SpaceId) -> Self {
        Self::new(CONSTANT_SPACE, space.index() as u64)
    }

    pub(crate) const fn from_key(space: SpaceKey, offset: u64) -> Self {
        Self { space, offset }
    }

    pub(crate) const fn key(self) -> SpaceKey {
        self.space
    }

    /// The address space; `None` for the invalid and maximal addresses.
    pub const fn space(self) -> Option<SpaceId> {
        self.space.id()
    }

    /// The offset in bytes.
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Whether this is the invalid (minimal) address, which has no space.
    pub const fn is_invalid(self) -> bool {
        self.space.raw() == SpaceKey::NONE.raw()
    }

    /// Whether this is in the maximal extreme's space.
    pub const fn is_maximal(self) -> bool {
        self.space.raw() == SpaceKey::MAXIMAL.raw()
    }

    /// Whether the address is in the constant space, so that its offset is a
    /// value rather than a location (Ghidra `isConstant`). The constant space
    /// always has index 0, so the manager is not needed.
    pub const fn is_constant(self) -> bool {
        self.space.raw() == SpaceKey::of(CONSTANT_SPACE).raw()
    }

    /// Whether the address is in the join space (Ghidra `isJoin`).
    pub fn is_join(self, manager: &SpaceManager) -> bool {
        self.space_type(manager) == Some(SpaceType::Join)
    }

    fn space_type(self, manager: &SpaceManager) -> Option<SpaceType> {
        manager.space_of(self).map(crate::Space::space_type)
    }

    /// The size in bytes of an offset in the address's space; 0 without a
    /// space (Ghidra `getAddrSize`).
    pub fn addr_size(self, manager: &SpaceManager) -> u32 {
        manager.space_of(self).map_or(0, crate::Space::addr_size)
    }

    /// Whether data at this address is big endian (Ghidra `isBigEndian`).
    pub fn is_big_endian(self, manager: &SpaceManager) -> bool {
        manager
            .space_of(self)
            .is_some_and(crate::Space::is_big_endian)
    }

    /// The shortcut character of the address's space (Ghidra `getShortcut`).
    pub fn shortcut(self, manager: &SpaceManager) -> Option<char> {
        manager.space_of(self).and_then(crate::Space::shortcut)
    }

    /// The address `delta` bytes further on, wrapping at the end of the space
    /// (Ghidra `operator+`). Without a space the offset wraps at 2^64.
    pub fn add(self, manager: &SpaceManager, delta: i64) -> Self {
        let offset = self.offset.wrapping_add(delta.cast_unsigned());
        self.with_wrapped_offset(manager, offset)
    }

    /// The address `delta` bytes back, wrapping at the start of the space
    /// (Ghidra `operator-`).
    pub fn sub(self, manager: &SpaceManager, delta: i64) -> Self {
        let offset = self.offset.wrapping_sub(delta.cast_unsigned());
        self.with_wrapped_offset(manager, offset)
    }

    fn with_wrapped_offset(self, manager: &SpaceManager, offset: u64) -> Self {
        let offset = manager
            .space_of(self)
            .map_or(offset, |space| space.wrap_offset(offset));
        Self::from_key(self.space, offset)
    }

    /// Whether `size` bytes starting here fit in the space without wrapping
    /// (Ghidra `isValidRange`). False without a space.
    pub fn is_valid_range(self, manager: &SpaceManager, size: u64) -> bool {
        manager
            .space_of(self)
            .is_some_and(|space| size.wrapping_sub(1) <= space.highest().wrapping_sub(self.offset))
    }

    /// Whether the `size` bytes here lie within the `other_size` bytes at
    /// `other` (Ghidra `containedBy`).
    pub const fn contained_by(self, size: u32, other: Self, other_size: u32) -> bool {
        if self.space.raw() != other.space.raw() || other.offset > self.offset {
            return false;
        }
        let last = last_byte(self.offset, size);
        let other_last = last_byte(other.offset, other_size);
        other_last >= last
    }

    /// If the `other_size` bytes at `other` lie within the `size` bytes here,
    /// how far `other` is from the least significant end of this range (or
    /// from its start when `force_left` is set or the space is little
    /// endian); `None` if not contained (Ghidra `justifiedContain`, which
    /// returns -1).
    pub fn justified_contain(
        self,
        manager: &SpaceManager,
        size: u32,
        other: Self,
        other_size: u32,
        force_left: bool,
    ) -> Option<u32> {
        if self.space != other.space || other.offset < self.offset {
            return None;
        }
        let last = last_byte(self.offset, size);
        let other_last = last_byte(other.offset, other_size);
        if other_last > last {
            return None;
        }
        if self.is_big_endian(manager) && !force_left {
            return Some(last.wrapping_sub(other_last) as u32);
        }
        Some(other.offset.wrapping_sub(self.offset) as u32)
    }

    /// Where the byte `skip` bytes after this address falls in the `size`
    /// bytes at `range`: its distance from the start of the range, or `None`
    /// if it falls outside, the spaces differ or the space is the constant
    /// space (Ghidra `overlap`, which returns -1).
    pub fn overlap(self, manager: &SpaceManager, skip: i32, range: Self, size: u32) -> Option<u32> {
        if self.space != range.space || self.is_constant() {
            return None;
        }
        let space = manager.space_of(self)?;
        let point = self.offset.wrapping_add(i64::from(skip).cast_unsigned());
        let dist = space.wrap_offset(point.wrapping_sub(range.offset));
        (dist < u64::from(size)).then_some(dist as u32)
    }

    /// Like [`Address::overlap`], but when `range` is a join address the byte
    /// is also looked for in the join's pieces (Ghidra `overlapJoin`).
    pub fn overlap_join(
        self,
        manager: &SpaceManager,
        skip: i32,
        range: Self,
        size: u32,
    ) -> Option<u32> {
        manager.overlap_join(range, size, self, skip)
    }

    /// Whether the `size` bytes here and the `lo_size` bytes at `lo` are
    /// adjacent with this range the more significant part (Ghidra
    /// `isContiguous`).
    pub fn is_contiguous(self, manager: &SpaceManager, size: u32, lo: Self, lo_size: u32) -> bool {
        if self.space != lo.space {
            return false;
        }
        let Some(space) = manager.space_of(self) else {
            return false;
        };
        if space.is_big_endian() {
            space.wrap_offset(self.offset.wrapping_add(u64::from(size))) == lo.offset
        } else {
            space.wrap_offset(lo.offset.wrapping_add(u64::from(lo_size))) == self.offset
        }
    }

    /// Whether pointers to the `size` bytes here can exist (Ghidra
    /// `highPtrPossible`).
    pub fn high_ptr_possible(self, manager: &SpaceManager, size: u32) -> bool {
        manager.high_ptr_possible(self, size)
    }

    /// For a join address, the address that describes exactly the `size`
    /// bytes here, creating a join record if needed; other addresses are
    /// returned unchanged (Ghidra `renormalize`).
    pub fn renormalize(self, manager: &SpaceManager, size: u32) -> Result<Self, SpaceError> {
        if self.is_join(manager) {
            manager.renormalize_join_address(self, size)
        } else {
            Ok(self)
        }
    }

    /// Writes the address as an `<addr>` element (Ghidra `encode`). The
    /// invalid address is written as an empty element.
    pub fn encode<E: Encoder + ?Sized>(
        self,
        encoder: &mut E,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        encoder.open_element(ELEM_ADDR);
        if let Some(space) = self.space() {
            manager.encode_attributes(encoder, space, self.offset)?;
        }
        encoder.close_element(ELEM_ADDR);
        Ok(())
    }

    /// Writes the address and a size as an `<addr>` element (Ghidra
    /// `encode(encoder, size)`).
    pub fn encode_sized<E: Encoder + ?Sized>(
        self,
        encoder: &mut E,
        manager: &SpaceManager,
        size: u32,
    ) -> Result<(), SpaceError> {
        encoder.open_element(ELEM_ADDR);
        if let Some(space) = self.space() {
            manager.encode_attributes_sized(encoder, space, self.offset, size)?;
        }
        encoder.close_element(ELEM_ADDR);
        Ok(())
    }

    /// Reads an address from the next element, in any form
    /// [`VarnodeData::decode`] accepts (Ghidra `Address::decode`).
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        VarnodeData::decode(decoder, manager).map(|data| data.addr())
    }

    /// Reads an address and its size from the next element (Ghidra
    /// `Address::decode(decoder, size)`).
    pub fn decode_sized<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<(Self, u32), SpaceError> {
        VarnodeData::decode(decoder, manager).map(|data| (data.addr(), data.size))
    }

    /// A value that prints the address in Ghidra's raw form, such as
    /// `0x00401000` or `invalid_addr` (Ghidra `printRaw`).
    pub fn raw(self, manager: &SpaceManager) -> RawAddress<'_> {
        RawAddress {
            manager,
            address: self,
            size: None,
        }
    }

    /// A value that prints `size` bytes here as a register name (with a
    /// `+n` suffix when inside the register) or as the space's shortcut
    /// followed by the raw offset (Ghidra `printRaw(s, size)`).
    pub fn raw_sized(self, manager: &SpaceManager, size: u32) -> RawAddress<'_> {
        RawAddress {
            manager,
            address: self,
            size: Some(size),
        }
    }

    /// Reads an offset into this address's space from text, keeping the
    /// space and returning the size the text implies (Ghidra
    /// `Address::read`; see [`SpaceManager::read`]).
    pub fn read(&mut self, manager: &SpaceManager, text: &str) -> Result<u32, SpaceError> {
        let space = self.space().ok_or(SpaceError::InvalidAddress)?;
        let (offset, size) = manager.read(space, text)?;
        self.offset = offset;
        Ok(size)
    }
}

/// The offset of the last of `size` bytes starting at `offset`, with C's
/// unsigned wrap-around (a size of 0 gives the byte before `offset`).
const fn last_byte(offset: u64, size: u32) -> u64 {
    offset.wrapping_add((size as u64).wrapping_sub(1))
}

impl Default for Address {
    fn default() -> Self {
        Self::INVALID
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{:#x}", self.space, self.offset)
    }
}

/// An address printed in Ghidra's raw form; see [`Address::raw`] and
/// [`Address::raw_sized`].
#[derive(Debug)]
pub struct RawAddress<'m> {
    manager: &'m SpaceManager,
    address: Address,
    size: Option<u32>,
}

impl fmt::Display for RawAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.size {
            None => self.manager.write_raw_address(f, self.address),
            Some(size) => self
                .manager
                .write_raw_sized(f, self.address, size)
                .map(|_| ()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_small() {
        assert!(size_of::<Address>() <= 16);
    }

    #[test]
    fn order_matches_ghidra() {
        let a = Address::new(SpaceId::new(1), 0x100);
        let b = Address::new(SpaceId::new(1), 0x200);
        let c = Address::new(SpaceId::new(2), 0);
        let mut v = vec![Address::MAXIMAL, c, b, Address::INVALID, a];
        v.sort();
        assert_eq!(v, [Address::INVALID, a, b, c, Address::MAXIMAL]);
        assert!(Address::maximal_at(0) < Address::MAXIMAL);
        assert!(c < Address::maximal_at(0));
        assert_eq!(a.space(), Some(SpaceId::new(1)));
        assert_eq!(Address::MAXIMAL.space(), None);
        assert!(Address::INVALID.is_invalid());
        assert!(Address::new(CONSTANT_SPACE, 5).is_constant());
    }

    #[test]
    fn contained_by_wraps_like_c() {
        let s = SpaceId::new(3);
        assert!(Address::new(s, 4).contained_by(2, Address::new(s, 0), 8));
        assert!(!Address::new(s, 4).contained_by(8, Address::new(s, 0), 8));
        assert!(!Address::new(s, 0).contained_by(1, Address::new(s, 1), 8));
        assert!(!Address::new(s, 0).contained_by(1, Address::new(SpaceId::new(4), 0), 8));
    }
}
