//! Decoding the `<spaces>` element and `<truncate_space>` (Ghidra
//! `AddrSpaceManager::decodeSpaces`/`decodeSpace`, the `decode` methods of
//! `AddrSpace`, `OtherSpace`, `UniqueSpace`, `OverlaySpace` and
//! `SpacebaseSpace`, and `TruncationTag`).

use bk_marshal::ids::{
    ATTRIB_BIGENDIAN, ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_WORDSIZE,
};
use bk_marshal::{Decoder, ElemCode};

use super::SpaceManager;
use crate::error::SpaceError;
use crate::ids::{
    ATTRIB_BASE, ATTRIB_CONTAIN, ATTRIB_DEADCODEDELAY, ATTRIB_DEFAULTSPACE, ATTRIB_DELAY,
    ATTRIB_PHYSICAL, ELEM_SPACE, ELEM_SPACE_BASE, ELEM_SPACE_OTHER, ELEM_SPACE_OVERLAY,
    ELEM_SPACE_UNIQUE, ELEM_SPACES, ELEM_TRUNCATE_SPACE,
};
use crate::space::{Space, SpaceFlags, SpaceKind, SpaceParts, checked_index, checked_word_size};

/// A `<truncate_space>` element: a space and the size its offsets are cut to
/// (Ghidra `TruncationTag`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TruncationTag {
    space_name: String,
    size: u32,
}

impl TruncationTag {
    /// A truncation of the named space to `size` bytes.
    pub fn new(space_name: impl Into<String>, size: u32) -> Self {
        Self {
            space_name: space_name.into(),
            size,
        }
    }

    /// The name of the space to truncate.
    pub fn name(&self) -> &str {
        &self.space_name
    }

    /// The new size of offsets into the space, in bytes.
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// Reads a `<truncate_space>` element (Ghidra `TruncationTag::decode`).
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(decoder: &mut D) -> Result<Self, SpaceError> {
        let element = decoder.open_element_expecting(ELEM_TRUNCATE_SPACE)?;
        let space_name = decoder.read_string_attr(ATTRIB_SPACE)?.to_owned();
        let size = decoder.read_unsigned_attr(ATTRIB_SIZE)? as u32;
        decoder.close_element(element)?;
        Ok(Self { space_name, size })
    }
}

/// The attributes common to every space element (Ghidra
/// `AddrSpace::decodeBasicAttributes`).
struct BasicAttributes<'a> {
    name: &'a str,
    index: i64,
    size: u32,
    word_size: u32,
    flags: SpaceFlags,
    delay: i32,
    deadcode_delay: i32,
}

impl SpaceManager {
    /// Reads a `<spaces>` element and adds the constant space and every
    /// space it describes, then sets the default code space it names (Ghidra
    /// `decodeSpaces`).
    ///
    /// Overlay and register-relative spaces name other spaces, which must
    /// already be known to the decoder's [`SpaceResolver`](bk_marshal::SpaceResolver).
    /// Build the decoder on [`SpaceManager::directory`] so that each space
    /// is known to it as soon as it is inserted.
    pub fn decode_spaces<'a, D: Decoder<'a> + ?Sized>(
        &mut self,
        decoder: &mut D,
    ) -> Result<(), SpaceError> {
        self.insert_space(Space::constant())?;
        let element = decoder.open_element_expecting(ELEM_SPACES)?;
        let default_name = decoder.read_string_attr(ATTRIB_DEFAULTSPACE)?;
        while decoder.peek_element().is_some() {
            let space = self.decode_space(decoder)?;
            self.insert_space(space)?;
        }
        decoder.close_element(element)?;
        let default = self
            .space_by_name(default_name)
            .map(Space::id)
            .ok_or_else(|| SpaceError::BadDefaultSpaceName(default_name.to_owned()))?;
        self.set_default_code_space(default)
    }

    /// Reads one space element — `<space>`, `<space_base>`, `<space_unique>`,
    /// `<space_other>` or `<space_overlay>` — without inserting it (Ghidra
    /// `decodeSpace`).
    ///
    /// As in Ghidra, a decoded space is neither marked addressable nor
    /// unaddressable. Where Ghidra leaves a missing `name`, `index` or `size`
    /// uninitialised this fails, and a missing `delay` reads as 0.
    pub fn decode_space<'a, D: Decoder<'a> + ?Sized>(
        &self,
        decoder: &mut D,
    ) -> Result<Space, SpaceError> {
        let next = decoder
            .peek_element()
            .ok_or(SpaceError::InvalidSpaceElement)?;
        let kind_of = |id: bk_marshal::ElementId| next == id;
        if kind_of(ELEM_SPACE_OVERLAY) {
            return self.decode_overlay(decoder);
        }
        let (kind_flags, is_base) = if kind_of(ELEM_SPACE_BASE) {
            (
                SpaceFlags::HERITAGED
                    | SpaceFlags::DOES_DEADCODE
                    | SpaceFlags::PROGRAM_SPECIFIC
                    | SpaceFlags::ALLOWS_WRAPPED_RANGE,
                true,
            )
        } else if kind_of(ELEM_SPACE_UNIQUE) {
            (
                SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE | SpaceFlags::HAS_PHYSICAL,
                false,
            )
        } else if kind_of(ELEM_SPACE_OTHER) {
            (SpaceFlags::IS_OTHERSPACE, false)
        } else if kind_of(ELEM_SPACE) {
            (SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE, false)
        } else {
            return Err(SpaceError::InvalidSpaceElement);
        };
        let element = decoder
            .open_element()?
            .ok_or(SpaceError::InvalidSpaceElement)?;
        let basic = decode_basic_attributes(decoder)?;
        let kind = if is_base {
            SpaceKind::Spacebase {
                contain: decoder.read_space_attr(ATTRIB_CONTAIN)?,
                base_register: None,
                negative_stack: true,
            }
        } else if kind_of(ELEM_SPACE_UNIQUE) {
            SpaceKind::Unique
        } else if kind_of(ELEM_SPACE_OTHER) {
            SpaceKind::Other
        } else {
            SpaceKind::Processor
        };
        decoder.close_element(element)?;
        Ok(Space::from_parts(SpaceParts {
            kind,
            name: basic.name,
            index: checked_index(basic.name, basic.index)?,
            addr_size: basic.size,
            word_size: checked_word_size(basic.name, basic.word_size)?,
            flags: kind_flags | basic.flags,
            delay: basic.delay,
            deadcode_delay: basic.deadcode_delay,
        }))
    }

    /// Reads a `<space_overlay>` element (Ghidra `OverlaySpace::decode`); the
    /// overlaid space must already be in this manager.
    fn decode_overlay<'a, D: Decoder<'a> + ?Sized>(
        &self,
        decoder: &mut D,
    ) -> Result<Space, SpaceError> {
        let element: ElemCode = decoder.open_element_expecting(ELEM_SPACE_OVERLAY)?;
        let name = decoder.read_string_attr(ATTRIB_NAME)?;
        let index = decoder.read_signed_attr(ATTRIB_INDEX)?;
        let base = decoder.read_space_attr(ATTRIB_BASE)?;
        decoder.close_element(element)?;
        let base = self.require(base)?;
        let index = checked_index(name, index)?;
        Space::overlay(name, index.index(), base)
    }
}

fn decode_basic_attributes<'a, D: Decoder<'a> + ?Sized>(
    decoder: &mut D,
) -> Result<BasicAttributes<'a>, SpaceError> {
    let mut name = None;
    let mut index = None;
    let mut size = None;
    let mut word_size = 1;
    let mut flags = SpaceFlags::empty();
    let mut delay = 0;
    let mut deadcode_delay = -1;
    while let Some(attribute) = decoder.next_attribute()? {
        if attribute == ATTRIB_NAME {
            name = Some(decoder.read_string()?);
        } else if attribute == ATTRIB_INDEX {
            index = Some(decoder.read_signed()?);
        } else if attribute == ATTRIB_SIZE {
            size = Some(decoder.read_signed()? as u32);
        } else if attribute == ATTRIB_WORDSIZE {
            word_size = decoder.read_unsigned()? as u32;
        } else if attribute == ATTRIB_BIGENDIAN {
            if decoder.read_bool()? {
                flags |= SpaceFlags::BIG_ENDIAN;
            }
        } else if attribute == ATTRIB_DELAY {
            delay = decoder.read_signed()? as i32;
        } else if attribute == ATTRIB_DEADCODEDELAY {
            deadcode_delay = decoder.read_signed()? as i32;
        } else if attribute == ATTRIB_PHYSICAL && decoder.read_bool()? {
            flags |= SpaceFlags::HAS_PHYSICAL;
        }
    }
    let missing = |attribute| SpaceError::MissingSpaceAttribute { attribute };
    // As in Ghidra, a dead-code delay of -1, given or defaulted, means "the
    // same as the delay".
    if deadcode_delay == -1 {
        deadcode_delay = delay;
    }
    Ok(BasicAttributes {
        name: name.ok_or_else(|| missing("name"))?,
        index: index.ok_or_else(|| missing("index"))?,
        size: size.ok_or_else(|| missing("size"))?,
        word_size,
        flags,
        delay,
        deadcode_delay,
    })
}
