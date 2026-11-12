//! A range of bytes in one space (Ghidra `Range` and `RangeProperties` in
//! `address.hh`/`address.cc`).

use std::fmt;

use bk_marshal::ids::{ATTRIB_NAME, ATTRIB_SPACE};
use bk_marshal::{DecodeError, Decoder, Encoder, SpaceId};

use crate::address::Address;
use crate::error::SpaceError;
use crate::ids::{ATTRIB_FIRST, ATTRIB_LAST, ELEM_RANGE, ELEM_REGISTER};
use crate::manager::SpaceManager;

/// The bytes from `first` to `last`, both included, in one space (Ghidra
/// `Range`).
///
/// Ranges are ordered by space index, then first offset, then last offset.
/// (Ghidra orders only by space and first offset; a
/// [`RangeList`](crate::RangeList) keys its ranges that way.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    space: SpaceId,
    first: u64,
    last: u64,
}

impl Range {
    /// The bytes from `first` to `last` in `space`.
    pub const fn new(space: SpaceId, first: u64, last: u64) -> Self {
        Self { space, first, last }
    }

    /// Builds a range from the properties read off a `<range>` or
    /// `<register>` element, looking the space or register up by name
    /// (Ghidra's `Range(RangeProperties, AddrSpaceManager)`).
    pub fn from_properties(
        properties: &RangeProperties,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        if properties.is_register {
            let register = manager.register(&properties.space_name)?;
            return Self::of_register(register.space(), register.offset, register.size);
        }
        let space = manager
            .space_by_name(&properties.space_name)
            .ok_or_else(|| SpaceError::UnknownSpaceName(properties.space_name.clone()))?;
        let last = if properties.seen_last {
            properties.last
        } else {
            space.highest()
        };
        checked(space.id(), properties.first, last, space.highest())
    }

    fn of_register(space: Option<SpaceId>, offset: u64, size: u32) -> Result<Self, SpaceError> {
        let space = space.ok_or(SpaceError::RangeWithoutSpace)?;
        let last = offset.wrapping_sub(1).wrapping_add(u64::from(size));
        Ok(Self::new(space, offset, last))
    }

    /// The space holding the range.
    pub const fn space(&self) -> SpaceId {
        self.space
    }

    /// The offset of the first byte.
    pub const fn first(&self) -> u64 {
        self.first
    }

    /// The offset of the last byte.
    pub const fn last(&self) -> u64 {
        self.last
    }

    /// The address of the first byte.
    pub const fn first_addr(&self) -> Address {
        Address::new(self.space, self.first)
    }

    /// The address of the last byte.
    pub const fn last_addr(&self) -> Address {
        Address::new(self.space, self.last)
    }

    /// The address just after the range: the next byte, or offset 0 of the
    /// next space when the range runs to the end of its space, or past the
    /// last space the maximal space at offset 0 (Ghidra `getLastAddrOpen`).
    pub fn last_addr_open(&self, manager: &SpaceManager) -> Address {
        let highest = manager
            .space(self.space)
            .map_or(u64::MAX, crate::Space::highest);
        if self.last != highest {
            return Address::new(self.space, self.last.wrapping_add(1));
        }
        match manager.next_space_after(self.space) {
            Some(next) => Address::new(next, 0),
            None => Address::maximal_at(0),
        }
    }

    /// Whether the address lies in the range (Ghidra `contains`).
    pub fn contains(&self, address: Address) -> bool {
        address.space() == Some(self.space)
            && self.first <= address.offset()
            && address.offset() <= self.last
    }

    /// A value that prints the range as `space: first-last` in hexadecimal
    /// (Ghidra `printBounds`).
    pub fn bounds<'m>(&self, manager: &'m SpaceManager) -> RangeBounds<'m> {
        RangeBounds {
            manager,
            range: *self,
        }
    }

    /// Writes the range as a `<range>` element (Ghidra `encode`).
    pub fn encode<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        let space = manager.require(self.space)?;
        encoder.open_element(ELEM_RANGE);
        encoder.write_space(ATTRIB_SPACE, &space.marshal_ref());
        encoder.write_unsigned(ATTRIB_FIRST, self.first);
        encoder.write_unsigned(ATTRIB_LAST, self.last);
        encoder.close_element(ELEM_RANGE);
        Ok(())
    }

    /// Reads a `<range>` or `<register>` element (Ghidra `decode`).
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        let element = open_range_or_register(decoder)?;
        let range = Self::decode_from_attributes(decoder, manager)?;
        decoder.close_element(element)?;
        Ok(range)
    }

    /// Reads a range from the attributes of the open element: `space`,
    /// `first` (default 0) and `last` (default the end of the space), or
    /// `name`, a register (Ghidra `decodeFromAttributes`).
    pub fn decode_from_attributes<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        let mut space = None;
        let mut first = 0;
        let mut last = None;
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_SPACE {
                space = Some(decoder.read_space()?);
            } else if attribute == ATTRIB_FIRST {
                first = decoder.read_unsigned()?;
            } else if attribute == ATTRIB_LAST {
                last = Some(decoder.read_unsigned()?);
            } else if attribute == ATTRIB_NAME {
                let register = manager.register(decoder.read_string()?)?;
                return Self::of_register(register.space(), register.offset, register.size);
            }
        }
        let space = space.ok_or(SpaceError::RangeWithoutSpace)?;
        let highest = manager.require(space)?.highest();
        checked(space, first, last.unwrap_or(highest), highest)
    }
}

/// Ghidra's "Illegal range tag" check.
fn checked(space: SpaceId, first: u64, last: u64, highest: u64) -> Result<Range, SpaceError> {
    if first > highest || last > highest || last < first {
        return Err(SpaceError::IllegalRange);
    }
    Ok(Range::new(space, first, last))
}

fn open_range_or_register<'a, D: Decoder<'a> + ?Sized>(
    decoder: &mut D,
) -> Result<bk_marshal::ElemCode, SpaceError> {
    match decoder.open_element()? {
        Some(element) if element == ELEM_RANGE || element == ELEM_REGISTER => Ok(element),
        _ => Err(DecodeError::NoElement {
            expected: "range or register",
        }
        .into()),
    }
}

/// A range printed as Ghidra's `printBounds` does; see [`Range::bounds`].
#[derive(Debug)]
pub struct RangeBounds<'m> {
    manager: &'m SpaceManager,
    range: Range,
}

impl fmt::Display for RangeBounds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self
            .manager
            .space(self.range.space)
            .map_or("?", crate::Space::name);
        write!(f, "{name}: {:x}-{:x}", self.range.first, self.range.last)
    }
}

/// The attributes of a `<range>` or `<register>` element, read before the
/// spaces they name exist (Ghidra `RangeProperties`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeProperties {
    space_name: String,
    first: u64,
    last: u64,
    is_register: bool,
    seen_last: bool,
}

impl RangeProperties {
    /// Reads a `<range>` or `<register>` element (Ghidra `decode`).
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(decoder: &mut D) -> Result<Self, SpaceError> {
        let element = open_range_or_register(decoder)?;
        let mut properties = Self::default();
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_SPACE {
                decoder
                    .read_string()?
                    .clone_into(&mut properties.space_name);
            } else if attribute == ATTRIB_FIRST {
                properties.first = decoder.read_unsigned()?;
            } else if attribute == ATTRIB_LAST {
                properties.last = decoder.read_unsigned()?;
                properties.seen_last = true;
            } else if attribute == ATTRIB_NAME {
                decoder
                    .read_string()?
                    .clone_into(&mut properties.space_name);
                properties.is_register = true;
            }
        }
        decoder.close_element(element)?;
        Ok(properties)
    }

    /// The name of the space, or of the register for a `<register>` element.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Whether the element named a register rather than a space.
    pub const fn is_register(&self) -> bool {
        self.is_register
    }
}
