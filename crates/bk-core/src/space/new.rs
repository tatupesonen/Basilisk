//! Building spaces: the constructors of Ghidra's `AddrSpace` subclasses and
//! the checks on their arguments.

use std::num::NonZeroU32;

use bk_marshal::SpaceId;

use super::{
    CONSTANT_SPACE, CONSTANT_SPACE_NAME, FSPEC_SPACE_NAME, IOP_SPACE_NAME, JOIN_SPACE_NAME,
    MAX_SPACE_INDEX, OTHER_SPACE, OTHER_SPACE_NAME, Space, SpaceFlags, SpaceKind, SpaceParts,
    UNIQUE_SPACE_NAME, UNIQUE_SPACE_SIZE,
};
use crate::error::SpaceError;

/// Checks a space index against the limit.
pub(crate) fn checked_index(name: &str, index: i64) -> Result<SpaceId, SpaceError> {
    u32::try_from(index)
        .ok()
        .filter(|&index| index <= MAX_SPACE_INDEX)
        .map(SpaceId::new)
        .ok_or_else(|| SpaceError::IndexTooLarge {
            name: name.to_owned(),
            index,
            limit: MAX_SPACE_INDEX,
        })
}

/// Checks that a word size is not 0.
pub(crate) fn checked_word_size(name: &str, word_size: u32) -> Result<NonZeroU32, SpaceError> {
    NonZeroU32::new(word_size).ok_or_else(|| SpaceError::ZeroWordSize {
        name: name.to_owned(),
    })
}

/// The flags Ghidra's full `AddrSpace` constructor sets.
fn constructed_flags(big_endian: bool, has_physical: bool, delay: i32) -> SpaceFlags {
    let mut flags = SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE;
    flags.set(SpaceFlags::HAS_PHYSICAL, has_physical);
    flags.set(SpaceFlags::BIG_ENDIAN, big_endian);
    flags
        | if delay == 0 {
            SpaceFlags::ADDRESSABLE_NONE
        } else {
            SpaceFlags::ADDRESSABLE_ALL
        }
}

impl Space {
    /// Builds a space from its parts, deriving the highest offset and the
    /// default pointer bounds.
    pub(crate) fn from_parts(parts: SpaceParts<'_>) -> Self {
        let mut space = Self {
            name: parts.name.into(),
            kind: parts.kind,
            index: parts.index,
            flags: parts.flags,
            shortcut: b' ',
            addr_size: parts.addr_size,
            word_size: parts.word_size,
            minimum_pointer_size: 0,
            delay: parts.delay,
            deadcode_delay: parts.deadcode_delay,
            highest: 0,
            pointer_lower_bound: 0,
            pointer_upper_bound: 0,
        };
        space.calc_scale_mask();
        space
    }

    /// One of the special spaces with byte-sized words and no physical
    /// memory, as Ghidra's subclass constructors build them.
    fn special(
        kind: SpaceKind,
        name: &str,
        big_endian: bool,
        addr_size: u32,
        index: SpaceId,
        delay: i32,
    ) -> Self {
        Self::from_parts(SpaceParts {
            kind,
            name,
            index,
            addr_size,
            word_size: NonZeroU32::MIN,
            flags: constructed_flags(big_endian, false, delay),
            delay,
            deadcode_delay: delay,
        })
    }

    /// The constant space: name `const`, index 0, eight-byte offsets
    /// (Ghidra `ConstantSpace`).
    ///
    /// Ghidra gives this space the endianness of the host it runs on;
    /// Basilisk always makes it little endian, x86-64's, so that results do
    /// not depend on the host (ADR-021).
    pub fn constant() -> Self {
        let mut space = Self::special(
            SpaceKind::Constant,
            CONSTANT_SPACE_NAME,
            false,
            8,
            CONSTANT_SPACE,
            0,
        );
        space
            .flags
            .remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
        space
    }

    /// The `OTHER` space: index 1, eight-byte offsets (Ghidra `OtherSpace`).
    pub fn other() -> Self {
        let mut space = Self::special(SpaceKind::Other, OTHER_SPACE_NAME, false, 8, OTHER_SPACE, 0);
        space
            .flags
            .remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
        space.flags.insert(SpaceFlags::IS_OTHERSPACE);
        space
    }

    /// The unique space, the pool of temporary registers (Ghidra
    /// `UniqueSpace`).
    pub fn unique(index: u32, big_endian: bool) -> Result<Self, SpaceError> {
        let index = checked_index(UNIQUE_SPACE_NAME, i64::from(index))?;
        let mut space = Self::special(
            SpaceKind::Unique,
            UNIQUE_SPACE_NAME,
            big_endian,
            UNIQUE_SPACE_SIZE,
            index,
            0,
        );
        space.flags.insert(SpaceFlags::HAS_PHYSICAL);
        Ok(space)
    }

    /// The join space, where logically joined variables live (Ghidra
    /// `JoinSpace`). It is never heritaged but does dead-code analysis.
    pub fn join(index: u32, big_endian: bool) -> Result<Self, SpaceError> {
        let index = checked_index(JOIN_SPACE_NAME, i64::from(index))?;
        let mut space = Self::special(SpaceKind::Join, JOIN_SPACE_NAME, big_endian, 4, index, 0);
        space.flags.remove(SpaceFlags::HERITAGED);
        Ok(space)
    }

    /// The space of function-call-specification references (Ghidra
    /// `FspecSpace`). Little endian for the reason given at
    /// [`Space::constant`].
    pub fn fspec(index: u32) -> Result<Self, SpaceError> {
        Self::internal_reference(SpaceKind::Fspec, FSPEC_SPACE_NAME, index)
    }

    /// The space of p-code operation references (Ghidra `IopSpace`). Little
    /// endian for the reason given at [`Space::constant`].
    pub fn iop(index: u32) -> Result<Self, SpaceError> {
        Self::internal_reference(SpaceKind::Iop, IOP_SPACE_NAME, index)
    }

    fn internal_reference(kind: SpaceKind, name: &str, index: u32) -> Result<Self, SpaceError> {
        let index = checked_index(name, i64::from(index))?;
        let mut space = Self::special(kind, name, false, 8, index, 1);
        space
            .flags
            .remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
        Ok(space)
    }

    /// An ordinary processor space (Ghidra's plain `AddrSpace` of type
    /// `IPTR_PROCESSOR`).
    ///
    /// `addr_size` is the size of an offset in bytes, `word_size` the number
    /// of bytes in an addressable unit, `delay` and `deadcode_delay` the
    /// numbers of heritage passes to wait before tracing data flow and before
    /// removing dead code.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors Ghidra's AddrSpace constructor"
    )]
    pub fn processor(
        name: &str,
        big_endian: bool,
        addr_size: u32,
        word_size: u32,
        index: u32,
        has_physical: bool,
        delay: i32,
        deadcode_delay: i32,
    ) -> Result<Self, SpaceError> {
        Ok(Self::from_parts(SpaceParts {
            kind: SpaceKind::Processor,
            name,
            index: checked_index(name, i64::from(index))?,
            addr_size,
            word_size: checked_word_size(name, word_size)?,
            flags: constructed_flags(big_endian, has_physical, delay),
            delay,
            deadcode_delay,
        }))
    }

    /// A register-relative space contained in `base` (Ghidra
    /// `SpacebaseSpace`). `is_formal_stack` marks the space attached to the
    /// formal stack pointer.
    pub fn spacebase(
        name: &str,
        index: u32,
        addr_size: u32,
        base: &Self,
        delay: i32,
        is_formal_stack: bool,
        big_endian: bool,
    ) -> Result<Self, SpaceError> {
        let mut flags =
            constructed_flags(big_endian, false, delay) | SpaceFlags::ALLOWS_WRAPPED_RANGE;
        flags.set(SpaceFlags::FORMAL_STACKSPACE, is_formal_stack);
        Ok(Self::from_parts(SpaceParts {
            kind: SpaceKind::Spacebase {
                contain: base.index,
                base_register: None,
                negative_stack: true,
            },
            name,
            index: checked_index(name, i64::from(index))?,
            addr_size,
            word_size: base.word_size,
            flags,
            delay,
            deadcode_delay: delay,
        }))
    }

    /// An overlay of `base`: the same sizes, delays, endianness and physical
    /// backing under another name and index (Ghidra `OverlaySpace`).
    pub fn overlay(name: &str, index: u32, base: &Self) -> Result<Self, SpaceError> {
        let mut flags = SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE | SpaceFlags::OVERLAY;
        flags |= base.flags & (SpaceFlags::BIG_ENDIAN | SpaceFlags::HAS_PHYSICAL);
        Ok(Self::from_parts(SpaceParts {
            kind: SpaceKind::Overlay { base: base.index },
            name,
            index: checked_index(name, i64::from(index))?,
            addr_size: base.addr_size,
            word_size: base.word_size,
            flags,
            delay: base.delay,
            deadcode_delay: base.deadcode_delay,
        }))
    }
}
