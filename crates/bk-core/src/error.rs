//! Errors of the address model.
//!
//! Ghidra throws `LowlevelError` with a message in these places; here each
//! case is a variant carrying its context. The messages follow Ghidra's.

use bk_marshal::{DecodeError, EncodeError, SpaceId};

/// A failure in the address model (Ghidra `LowlevelError` as thrown by
/// `space.cc`, `address.cc`, `pcoderaw.cc` and `translate.cc`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpaceError {
    /// The document being decoded is malformed.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// A value cannot be encoded.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// A space id does not belong to this manager.
    #[error("No address space with index {}", .0.index())]
    NoSuchSpace(SpaceId),
    /// A space name is not registered.
    #[error("Unknown address space: {0}")]
    UnknownSpaceName(String),
    /// An operation needs a space and the address has none.
    #[error("Address has no address space")]
    InvalidAddress,
    /// A space was given a name reserved for another kind of space, or a
    /// reserved kind was given the wrong name.
    #[error("Space {name} was initialized with wrong type")]
    WrongSpaceType {
        /// The name of the offending space.
        name: String,
    },
    /// The constant space must have index 0, and only it may.
    #[error("const space must be assigned index 0")]
    ConstantSpaceIndex,
    /// Index 0 belongs to the constant space (a Basilisk rule; see
    /// [`SpaceManager::insert_space`](crate::SpaceManager::insert_space)).
    #[error("Space {name} cannot take index 0, which is reserved for the const space")]
    ReservedIndexZero {
        /// The name of the offending space.
        name: String,
    },
    /// The `OTHER` space must have index 1.
    #[error("OTHER space must be assigned index 1")]
    OtherSpaceIndex,
    /// A second space of a kind of which there is one, or a second space with
    /// the same name.
    #[error("Space {name} was initialized more than once")]
    DuplicateSpace {
        /// The name of the offending space.
        name: String,
    },
    /// Two spaces claim the same index.
    #[error("Space {name} was assigned id duplicating: {existing}")]
    DuplicateIndex {
        /// The space being inserted.
        name: String,
        /// The space already holding the index.
        existing: String,
    },
    /// A space index is larger than the manager allows.
    #[error("Space {name} has index {index}, above the limit of {limit}")]
    IndexTooLarge {
        /// The name of the offending space.
        name: String,
        /// The index asked for.
        index: i64,
        /// The largest index allowed.
        limit: u32,
    },
    /// A space was described with a word size of 0.
    #[error("Space {name} has a word size of 0")]
    ZeroWordSize {
        /// The name of the offending space.
        name: String,
    },
    /// A space element lacks an attribute that defines the space.
    #[error("Address space element is missing its `{attribute}` attribute")]
    MissingSpaceAttribute {
        /// The name of the missing attribute.
        attribute: &'static str,
    },
    /// The element is not one that describes an address space.
    #[error("Invalid address space element")]
    InvalidSpaceElement,
    /// The default code space was set twice.
    #[error("Default space set multiple times")]
    DefaultSpaceSetTwice,
    /// The index given for the default code space names no space.
    #[error("Bad index for default space")]
    BadDefaultSpaceIndex,
    /// The default data space was set before the default code space.
    #[error("Default data space must be set after the code space")]
    DataSpaceBeforeCodeSpace,
    /// The index given for the default data space names no space.
    #[error("Bad index for default data space")]
    BadDefaultDataSpaceIndex,
    /// The `defaultspace` attribute names no space.
    #[error("Bad 'defaultspace' attribute: {0}")]
    BadDefaultSpaceName(String),
    /// An operation needs the default code space and none is set.
    #[error("No default address space has been set")]
    NoDefaultSpace,
    /// A `<truncate_space>` command names no space.
    #[error("Unknown space in <truncate_space> command: {0}")]
    UnknownTruncatedSpace(String),
    /// An address element has a `space` attribute but no `offset`.
    #[error("Address is missing offset")]
    MissingOffset,
    /// A register name is not known to the processor.
    #[error("Unknown register name: {0}")]
    UnknownRegister(String),
    /// A base register was asked of a space that is not register-relative.
    #[error("{name} space is not virtual and has no associated base register")]
    NotVirtual {
        /// The name of the space.
        name: String,
    },
    /// A register-relative space has no base register (yet), or an index
    /// other than 0 was asked for.
    #[error("No base register specified for space: {name}")]
    NoBaseRegister {
        /// The name of the space.
        name: String,
    },
    /// A second, different base register was assigned to a space.
    #[error("Attempt to assign more than one base register to space: {name}")]
    SecondBaseRegister {
        /// The name of the space.
        name: String,
    },
    /// A join was asked for with no pieces.
    #[error("Cannot create a join without pieces")]
    JoinWithoutPieces,
    /// A single-piece join needs a logical size (unless it is padding).
    #[error("Cannot create a single piece join without a logical size")]
    JoinWithoutLogicalSize,
    /// A logical size was given for a join of several pieces.
    #[error("Cannot specify logical size for multiple piece join")]
    JoinLogicalSizeWithPieces,
    /// The pieces of a join add up to nothing.
    #[error("Cannot create a zero size join")]
    ZeroSizeJoin,
    /// The manager has no join space to place the join in.
    #[error("No join space has been registered")]
    NoJoinSpace,
    /// A join offset is not the start of any join record.
    #[error("Unlinked join address")]
    UnlinkedJoin,
    /// A join offset falls in no join record.
    #[error("Join address not covered by a JoinRecord")]
    JoinNotCovered,
    /// A range in the join space runs outside its join record.
    #[error("Join address range not covered")]
    JoinRangeNotCovered,
    /// Only the first or last piece can be stripped from a join.
    #[error("Stripping middle piece from JoinRecord")]
    StripMiddlePiece,
    /// A join address has more pieces than can be marshalled.
    #[error("Exceeded maximum pieces in one join address")]
    TooManyJoinPieces,
    /// A `piece` attribute of a join address cannot be parsed, or a piece of
    /// the sequence is missing.
    #[error("join address piece attribute is malformed")]
    MalformedJoinPiece,
    /// The text form of a join address cannot be parsed.
    #[error("Could not parse join string")]
    BadJoinString,
    /// A range element names no address space.
    #[error("No address space indicated in range tag")]
    RangeWithoutSpace,
    /// A range lies outside its space or ends before it starts.
    #[error("Illegal range tag")]
    IllegalRange,
    /// A range runs past the end of a space that does not allow wrapping.
    #[error("Trying to construct memory range beyond end of address space: {0}")]
    RangeBeyondSpace(String),
}
