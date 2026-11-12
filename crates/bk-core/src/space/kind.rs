//! The closed sets that describe a space: its kind, type and flags, and the
//! reserved names and indices of the special spaces.

use bitflags::bitflags;
use bk_marshal::SpaceId;

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
