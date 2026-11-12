//! Address spaces.
//!
//! Ghidra: `AddrSpace` and its subclasses `ConstantSpace`, `OtherSpace`,
//! `UniqueSpace`, `JoinSpace`, `OverlaySpace` (`space.hh`, `space.cc`) and
//! `SpacebaseSpace` (`translate.hh`). Here a space is one plain struct with a
//! [`SpaceKind`]; what the subclasses override is a `match` on the kind.
//! Operations that need other spaces, the join records or the registers are
//! methods of the [`SpaceManager`](crate::SpaceManager) in the sibling
//! modules: [`codec`] (marshalling) and [`text`] (printing and parsing).

pub mod codec;
pub mod text;

use std::num::NonZeroU32;

use bitflags::bitflags;
use bk_marshal::{PackedSpace, SpaceId, SpaceRef};

use crate::bits::calc_mask;
use crate::error::SpaceError;
use crate::varnode::VarnodeData;

/// The index reserved for the constant space (Ghidra `ConstantSpace::INDEX`).
pub const CONSTANT_SPACE: SpaceId = SpaceId::new(0);
/// The index reserved for the `OTHER` space (Ghidra `OtherSpace::INDEX`).
pub const OTHER_SPACE: SpaceId = SpaceId::new(1);
/// The name of the constant space (Ghidra `ConstantSpace::NAME`).
pub const CONSTANT_SPACE_NAME: &str = "const";
/// The name of the `OTHER` space (Ghidra `OtherSpace::NAME`).
pub const OTHER_SPACE_NAME: &str = "OTHER";
/// The name of the unique space (Ghidra `UniqueSpace::NAME`).
pub const UNIQUE_SPACE_NAME: &str = "unique";
/// The size in bytes of offsets into the unique space (Ghidra
/// `UniqueSpace::SIZE`).
pub const UNIQUE_SPACE_SIZE: u32 = 4;
/// The name of the join space (Ghidra `JoinSpace::NAME`).
pub const JOIN_SPACE_NAME: &str = "join";
/// The name of the function-call-specification space (Ghidra
/// `FspecSpace::NAME`).
pub const FSPEC_SPACE_NAME: &str = "fspec";
/// The name of the p-code operation reference space (Ghidra `IopSpace::NAME`).
pub const IOP_SPACE_NAME: &str = "iop";
/// The name that makes a register-relative space the stack space.
pub const STACK_SPACE_NAME: &str = "stack";
/// The largest space index a manager accepts. Ghidra has no limit; a hostile
/// document could otherwise make the manager allocate without bound
/// (ADR-009).
pub const MAX_SPACE_INDEX: u32 = 0xffff;

bitflags! {
    /// The attributes of a space (the anonymous enum in Ghidra's `AddrSpace`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct SpaceFlags: u32 {
        /// Values in the space are big endian.
        const BIG_ENDIAN = 1;
        /// Data flow is traced through the space.
        const HERITAGED = 2;
        /// Dead-code analysis is done on the space.
        const DOES_DEADCODE = 4;
        /// The space is specific to one load image.
        const PROGRAM_SPECIFIC = 8;
        /// Justification within an aligned word is opposite to the endianness.
        const REVERSE_JUSTIFICATION = 0x10;
        /// The space is attached to the formal stack pointer.
        const FORMAL_STACKSPACE = 0x20;
        /// The space is an overlay of another space.
        const OVERLAY = 0x40;
        /// Other spaces overlay this space.
        const OVERLAYBASE = 0x80;
        /// The space is truncated from its original size; pointers may be
        /// larger than it.
        const TRUNCATED = 0x100;
        /// Physical memory is associated with the space.
        const HAS_PHYSICAL = 0x200;
        /// The space is the `OTHER` space.
        const IS_OTHERSPACE = 0x400;
        /// Near pointers into the space exist.
        const HAS_NEARPOINTERS = 0x800;
        /// A memory range in the space may wrap from high addresses to low.
        const ALLOWS_WRAPPED_RANGE = 0x1000;
        /// Pointers can address the entire space.
        const ADDRESSABLE_ALL = 0x2000;
        /// Pointers into the space do not exist.
        const ADDRESSABLE_NONE = 0x4000;
    }
}

/// The fundamental type of a space (Ghidra `spacetype`, the `IPTR_*` values).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SpaceType {
    /// The space of constants (`IPTR_CONSTANT`).
    Constant = 0,
    /// A space modelled by the processor (`IPTR_PROCESSOR`).
    Processor = 1,
    /// Offsets from a base register (`IPTR_SPACEBASE`).
    Spacebase = 2,
    /// The internally managed temporary space (`IPTR_INTERNAL`).
    Internal = 3,
    /// References to function-call specifications (`IPTR_FSPEC`).
    Fspec = 4,
    /// References to p-code operations (`IPTR_IOP`).
    Iop = 5,
    /// The virtual space of split variables (`IPTR_JOIN`).
    Join = 6,
}

/// What a register-relative space knows about its base register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseRegister {
    /// The register as used: truncated to the size of the space.
    pub location: VarnodeData,
    /// The register before truncation.
    pub original: VarnodeData,
}

/// The kind of a space, with the data particular to it (Ghidra's `AddrSpace`
/// subclasses).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpaceKind {
    /// The space of constants (`ConstantSpace`).
    Constant,
    /// An ordinary processor space such as `ram` or `register`.
    Processor,
    /// The `OTHER` space (`OtherSpace`).
    Other,
    /// The pool of temporary registers (`UniqueSpace`).
    Unique,
    /// The space of logically joined variables (`JoinSpace`).
    Join,
    /// The space of function-call-specification references (`FspecSpace`).
    Fspec,
    /// The space of p-code operation references (`IopSpace`).
    Iop,
    /// A different layout occupying the memory of another space
    /// (`OverlaySpace`).
    Overlay {
        /// The space being overlaid.
        base: SpaceId,
    },
    /// Offsets relative to a base register, such as the stack
    /// (`SpacebaseSpace`).
    Spacebase {
        /// The space the offsets ultimately index into.
        contain: SpaceId,
        /// The base register, once attached.
        base_register: Option<BaseRegister>,
        /// Whether a push decreases the base register.
        negative_stack: bool,
    },
}

impl SpaceKind {
    /// The fundamental type of a space of this kind.
    pub const fn space_type(&self) -> SpaceType {
        match self {
            Self::Constant => SpaceType::Constant,
            Self::Processor | Self::Other | Self::Overlay { .. } => SpaceType::Processor,
            Self::Unique => SpaceType::Internal,
            Self::Join => SpaceType::Join,
            Self::Fspec => SpaceType::Fspec,
            Self::Iop => SpaceType::Iop,
            Self::Spacebase { .. } => SpaceType::Spacebase,
        }
    }
}

/// The values every space is built from (the arguments of Ghidra's
/// `AddrSpace` constructor), already validated.
#[derive(Clone, Debug)]
pub(crate) struct SpaceParts<'a> {
    pub(crate) kind: SpaceKind,
    pub(crate) name: &'a str,
    pub(crate) index: SpaceId,
    pub(crate) addr_size: u32,
    pub(crate) word_size: NonZeroU32,
    pub(crate) flags: SpaceFlags,
    pub(crate) delay: i32,
    pub(crate) deadcode_delay: i32,
}

/// A region where a processor stores data, or one of the special spaces the
/// analysis uses (Ghidra `AddrSpace`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    name: Box<str>,
    kind: SpaceKind,
    index: SpaceId,
    flags: SpaceFlags,
    /// Shortcut character; a space until the manager assigns one.
    shortcut: u8,
    addr_size: u32,
    word_size: NonZeroU32,
    minimum_pointer_size: u32,
    delay: i32,
    deadcode_delay: i32,
    highest: u64,
    pointer_lower_bound: u64,
    pointer_upper_bound: u64,
}

/// Checks a space index against the limit.
pub(crate) fn checked_index(name: &str, index: i64) -> Result<SpaceId, SpaceError> {
    u32::try_from(index).ok().filter(|&index| index <= MAX_SPACE_INDEX).map(SpaceId::new).ok_or_else(
        || SpaceError::IndexTooLarge { name: name.to_owned(), index, limit: MAX_SPACE_INDEX },
    )
}

/// Checks that a word size is not 0.
pub(crate) fn checked_word_size(name: &str, word_size: u32) -> Result<NonZeroU32, SpaceError> {
    NonZeroU32::new(word_size).ok_or_else(|| SpaceError::ZeroWordSize { name: name.to_owned() })
}

/// The flags Ghidra's full `AddrSpace` constructor sets.
fn constructed_flags(big_endian: bool, has_physical: bool, delay: i32) -> SpaceFlags {
    let mut flags = SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE;
    flags.set(SpaceFlags::HAS_PHYSICAL, has_physical);
    flags.set(SpaceFlags::BIG_ENDIAN, big_endian);
    flags | if delay == 0 { SpaceFlags::ADDRESSABLE_NONE } else { SpaceFlags::ADDRESSABLE_ALL }
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
    /// basilisk always makes it little endian so that results do not depend
    /// on the host.
    pub fn constant() -> Self {
        let mut space =
            Self::special(SpaceKind::Constant, CONSTANT_SPACE_NAME, false, 8, CONSTANT_SPACE, 0);
        space.flags.remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
        space
    }

    /// The `OTHER` space: index 1, eight-byte offsets (Ghidra `OtherSpace`).
    pub fn other() -> Self {
        let mut space = Self::special(SpaceKind::Other, OTHER_SPACE_NAME, false, 8, OTHER_SPACE, 0);
        space.flags.remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
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
        space.flags.remove(SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE);
        Ok(space)
    }

    /// An ordinary processor space (Ghidra's plain `AddrSpace` of type
    /// `IPTR_PROCESSOR`).
    ///
    /// `addr_size` is the size of an offset in bytes, `word_size` the number
    /// of bytes in an addressable unit, `delay` and `deadcode_delay` the
    /// numbers of heritage passes to wait before tracing data flow and before
    /// removing dead code.
    #[expect(clippy::too_many_arguments, reason = "mirrors Ghidra's AddrSpace constructor")]
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
        base: &Space,
        delay: i32,
        is_formal_stack: bool,
        big_endian: bool,
    ) -> Result<Self, SpaceError> {
        let mut flags = constructed_flags(big_endian, false, delay) | SpaceFlags::ALLOWS_WRAPPED_RANGE;
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
    pub fn overlay(name: &str, index: u32, base: &Space) -> Result<Self, SpaceError> {
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

    /// Recomputes the highest offset and the default pointer bounds from the
    /// address and word sizes (Ghidra `calcScaleMask`).
    fn calc_scale_mask(&mut self) {
        let word_size = u64::from(self.word_size.get());
        self.highest = calc_mask(self.addr_size).wrapping_mul(word_size).wrapping_add(word_size - 1);
        let buffer: u64 = if self.addr_size < 3 { 0x100 } else { 0x1000 };
        self.pointer_lower_bound = buffer;
        self.pointer_upper_bound = self.highest.wrapping_sub(buffer);
    }

    /// The name of the space.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The kind of the space with its particular data.
    pub fn kind(&self) -> &SpaceKind {
        &self.kind
    }

    /// The fundamental type of the space.
    pub fn space_type(&self) -> SpaceType {
        self.kind.space_type()
    }

    /// The index of the space in its manager, which is also its identity.
    pub fn id(&self) -> SpaceId {
        self.index
    }

    /// The index of the space as a number.
    pub fn index(&self) -> u32 {
        self.index.index()
    }

    /// The attributes of the space.
    pub fn flags(&self) -> SpaceFlags {
        self.flags
    }

    /// The number of heritage passes to wait before tracing data flow.
    pub fn delay(&self) -> i32 {
        self.delay
    }

    /// The number of heritage passes to wait before removing dead code.
    pub fn deadcode_delay(&self) -> i32 {
        self.deadcode_delay
    }

    /// The number of bytes in an addressable unit; almost always 1.
    pub fn word_size(&self) -> u32 {
        self.word_size.get()
    }

    /// The number of bytes needed to hold an offset into the space.
    pub fn addr_size(&self) -> u32 {
        self.addr_size
    }

    /// The highest byte offset in the space.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// The offset below which constants are not taken for pointers.
    pub fn pointer_lower_bound(&self) -> u64 {
        self.pointer_lower_bound
    }

    /// The offset above which constants are not taken for pointers.
    pub fn pointer_upper_bound(&self) -> u64 {
        self.pointer_upper_bound
    }

    /// The smallest size of a pointer into the space in bytes; 0 means a
    /// pointer must match the address size exactly.
    pub fn minimum_pointer_size(&self) -> u32 {
        self.minimum_pointer_size
    }

    /// The shortcut character used when printing addresses in the space, once
    /// the manager has assigned one.
    pub fn shortcut(&self) -> Option<char> {
        (self.shortcut != b' ').then_some(char::from(self.shortcut))
    }

    /// The shortcut as a byte; a space if unassigned.
    pub(crate) fn shortcut_byte(&self) -> u8 {
        self.shortcut
    }

    /// Whether data flow is traced through the space.
    pub fn is_heritaged(&self) -> bool {
        self.flags.contains(SpaceFlags::HERITAGED)
    }

    /// Whether dead-code analysis is done on the space.
    pub fn does_deadcode(&self) -> bool {
        self.flags.contains(SpaceFlags::DOES_DEADCODE)
    }

    /// Whether the space has readable and writable bytes behind it.
    pub fn has_physical(&self) -> bool {
        self.flags.contains(SpaceFlags::HAS_PHYSICAL)
    }

    /// Whether values in the space are big endian.
    pub fn is_big_endian(&self) -> bool {
        self.flags.contains(SpaceFlags::BIG_ENDIAN)
    }

    /// Whether small values are justified opposite to the endianness.
    pub fn is_reverse_justified(&self) -> bool {
        self.flags.contains(SpaceFlags::REVERSE_JUSTIFICATION)
    }

    /// Whether the space is attached to the formal stack pointer.
    pub fn is_formal_stack_space(&self) -> bool {
        self.flags.contains(SpaceFlags::FORMAL_STACKSPACE)
    }

    /// Whether the space overlays another.
    pub fn is_overlay(&self) -> bool {
        self.flags.contains(SpaceFlags::OVERLAY)
    }

    /// Whether other spaces overlay this one.
    pub fn is_overlay_base(&self) -> bool {
        self.flags.contains(SpaceFlags::OVERLAYBASE)
    }

    /// Whether this is the `OTHER` space.
    pub fn is_other_space(&self) -> bool {
        self.flags.contains(SpaceFlags::IS_OTHERSPACE)
    }

    /// Whether the space is truncated from its original size.
    pub fn is_truncated(&self) -> bool {
        self.flags.contains(SpaceFlags::TRUNCATED)
    }

    /// Whether pointers into the space are known not to exist (Ghidra
    /// `noHighPtrPossible`).
    pub fn no_high_ptr_possible(&self) -> bool {
        self.flags.contains(SpaceFlags::ADDRESSABLE_NONE)
    }

    /// Whether near (truncated) pointers into the space are possible.
    pub fn has_near_pointers(&self) -> bool {
        self.flags.contains(SpaceFlags::HAS_NEARPOINTERS)
    }

    /// Whether a memory range may wrap from high addresses to low.
    pub fn allows_wrapped_range(&self) -> bool {
        self.flags.contains(SpaceFlags::ALLOWS_WRAPPED_RANGE)
    }

    /// The offset equivalent to `offset` modulo the size of the space.
    pub fn wrap_offset(&self, offset: u64) -> u64 {
        if offset <= self.highest {
            return offset;
        }
        // Here `highest` is below `u64::MAX`, so the modulus is not 0.
        let modulus = self.highest.wrapping_add(1).cast_signed();
        let mut remainder = offset.cast_signed().checked_rem(modulus).unwrap_or(0);
        if remainder < 0 {
            remainder = remainder.wrapping_add(modulus);
        }
        remainder.cast_unsigned()
    }

    /// Scales an offset in addressable units to bytes.
    pub fn address_to_byte(&self, value: u64) -> u64 {
        value.wrapping_mul(u64::from(self.word_size.get()))
    }

    /// Scales an offset in bytes to addressable units.
    pub fn byte_to_address(&self, value: u64) -> u64 {
        value / u64::from(self.word_size)
    }

    /// Scales a signed offset in addressable units to bytes.
    pub fn address_to_byte_int(&self, value: i64) -> i64 {
        value.wrapping_mul(i64::from(self.word_size.get()))
    }

    /// Scales a signed offset in bytes to addressable units.
    pub fn byte_to_address_int(&self, value: i64) -> i64 {
        value / i64::from(self.word_size)
    }

    /// The space this one is contained in: the overlaid space of an overlay,
    /// the indexed space of a register-relative space (Ghidra `getContain`).
    pub fn contain(&self) -> Option<SpaceId> {
        match self.kind {
            SpaceKind::Overlay { base } => Some(base),
            SpaceKind::Spacebase { contain, .. } => Some(contain),
            _ => None,
        }
    }

    /// The number of base registers attached to the space: 1 for a
    /// register-relative space whose register is known, else 0.
    pub fn num_spacebase(&self) -> usize {
        match self.kind {
            SpaceKind::Spacebase { base_register: Some(_), .. } => 1,
            _ => 0,
        }
    }

    fn base_register(&self, index: usize) -> Result<&BaseRegister, SpaceError> {
        match &self.kind {
            SpaceKind::Spacebase { base_register: Some(register), .. } if index == 0 => Ok(register),
            SpaceKind::Spacebase { .. } => {
                Err(SpaceError::NoBaseRegister { name: self.name.to_string() })
            }
            _ => Err(SpaceError::NotVirtual { name: self.name.to_string() }),
        }
    }

    /// The `index`-th base register of a register-relative space, truncated
    /// to the size of the space.
    pub fn spacebase(&self, index: usize) -> Result<VarnodeData, SpaceError> {
        self.base_register(index).map(|register| register.location)
    }

    /// The `index`-th base register before truncation.
    pub fn spacebase_full(&self, index: usize) -> Result<VarnodeData, SpaceError> {
        self.base_register(index).map(|register| register.original)
    }

    /// Whether a push decreases the base register. True for spaces that are
    /// not register-relative, as in Ghidra.
    pub fn stack_grows_negative(&self) -> bool {
        match self.kind {
            SpaceKind::Spacebase { negative_stack, .. } => negative_stack,
            _ => true,
        }
    }

    /// What an encoder writes for a reference to this space.
    pub fn marshal_ref(&self) -> SpaceRef<'_> {
        let packed = match self.space_type() {
            SpaceType::Fspec => PackedSpace::Fspec,
            SpaceType::Iop => PackedSpace::Iop,
            SpaceType::Join => PackedSpace::Join,
            SpaceType::Spacebase if self.is_formal_stack_space() => PackedSpace::Stack,
            SpaceType::Spacebase => PackedSpace::Spacebase,
            _ => PackedSpace::Index(self.index.index()),
        };
        SpaceRef { name: &self.name, packed }
    }

    pub(crate) fn insert_flags(&mut self, flags: SpaceFlags) {
        self.flags.insert(flags);
    }

    pub(crate) fn remove_flags(&mut self, flags: SpaceFlags) {
        self.flags.remove(flags);
    }

    pub(crate) fn set_shortcut(&mut self, shortcut: u8) {
        self.shortcut = shortcut;
    }

    pub(crate) fn set_deadcode_delay(&mut self, delay: i32) {
        self.deadcode_delay = delay;
    }

    pub(crate) fn set_pointer_bounds(&mut self, lower: u64, upper: u64) {
        self.pointer_lower_bound = lower;
        self.pointer_upper_bound = upper;
    }

    /// Marks near pointers of the given size as possible (Ghidra
    /// `markNearPointers`).
    pub(crate) fn mark_near_pointers(&mut self, size: u32) {
        self.flags.insert(SpaceFlags::HAS_NEARPOINTERS);
        if self.minimum_pointer_size == 0 && self.addr_size != size {
            self.minimum_pointer_size = size;
        }
    }

    /// Makes the logical space smaller than its actual size: pointers keep
    /// the original size but their most significant bytes are ignored
    /// (Ghidra `truncateSpace`).
    pub(crate) fn truncate(&mut self, new_size: u32) {
        self.flags.insert(SpaceFlags::TRUNCATED);
        self.addr_size = new_size;
        self.minimum_pointer_size = new_size;
        self.calc_scale_mask();
    }

    /// Attaches the base register of a register-relative space (Ghidra
    /// `SpacebaseSpace::setBaseRegister`). `register_big_endian` is the
    /// endianness of the space the register lives in.
    pub(crate) fn set_base_register(
        &mut self,
        data: VarnodeData,
        truncated_size: u32,
        stack_grows_negative: bool,
        register_big_endian: bool,
    ) -> Result<(), SpaceError> {
        let name = &self.name;
        let SpaceKind::Spacebase { base_register, negative_stack, .. } = &mut self.kind else {
            return Err(SpaceError::NotVirtual { name: name.to_string() });
        };
        if let Some(existing) = base_register
            && (existing.location != data || *negative_stack != stack_grows_negative)
        {
            return Err(SpaceError::SecondBaseRegister { name: name.to_string() });
        }
        let mut location = data;
        if truncated_size != location.size {
            if register_big_endian {
                location.offset =
                    location.offset.wrapping_add(u64::from(location.size.wrapping_sub(truncated_size)));
            }
            location.size = truncated_size;
        }
        *negative_stack = stack_grows_negative;
        *base_register = Some(BaseRegister { location, original: data });
        Ok(())
    }
}
