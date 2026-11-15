//! Errors, with Ghidra's messages (spec 5.6).
//!
//! The `Display` text of every variant Ghidra also raises is Ghidra's
//! `explain` string, so warnings and oracle rows compare equal.

use bk_core::{Address, SpaceError};
use bk_decomp_types::TypeError;
use bk_marshal::DecodeError;
use thiserror::Error;

/// A failed load-image read (Ghidra `DataUnavailError`).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct DataUnavail {
    /// The first address that could not be read.
    pub addr: Address,
    /// Ghidra's message (`Bytes at … are not mapped`, …).
    pub message: String,
}

/// An error a [`ProgramHost`](crate::host::ProgramHost) reports.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum HostError {
    /// The host could not answer (its own message).
    #[error("{0}")]
    Failed(String),
    /// The host has no constant pool record for the reference.
    #[error("Could not retrieve constant pool record for reference: 0x{0:x}")]
    NoCpoolRecord(u64),
    /// The host has no bytes at the address.
    #[error("GHIDRA has no data in the loadimage at {0}")]
    NoData(String),
}

/// Everything that can go wrong in this crate.
#[derive(Clone, Debug, PartialEq, Error)]
#[non_exhaustive]
pub enum SymbolError {
    /// An id that names no live object.
    #[error("stale or foreign {kind} id {index}")]
    StaleId {
        /// What kind of id.
        kind: &'static str,
        /// Its index.
        index: u32,
    },
    /// A non-address-tied entry without a use limit (Ghidra
    /// `SymbolRange::getSubsort`).
    #[error("Map entry with empty uselimit")]
    EmptyUseLimit,
    /// A symbol whose type has no size.
    #[error("{name} symbol created with zero size type")]
    ZeroSizeType {
        /// The symbol.
        name: String,
    },
    /// A symbol without a type.
    #[error("{name} symbol created with no type")]
    NoType {
        /// The symbol.
        name: String,
    },
    /// The name tree refused a second deduplication (two spaces, as Ghidra).
    #[error("Could  not deduplicate symbol: {name}")]
    Dedup {
        /// The symbol.
        name: String,
    },
    /// An entry that runs past the end of its space (Ghidra raises this after
    /// changing the symbol and then crashes; Basilisk checks first).
    #[error("Symbol {name} extends beyond the end of the address space")]
    BeyondSpace {
        /// The symbol.
        name: String,
    },
    /// A symbol without entries asked for its first.
    #[error("No mapping for symbol: {name}")]
    NoMapping {
        /// The symbol.
        name: String,
    },
    /// `retypeSymbol` could not move the storage (Ghidra `RecovError`).
    #[error("Unable to retype symbol: {name}")]
    Retype {
        /// The symbol.
        name: String,
    },
    /// The undefined-name counter is exhausted.
    #[error("Error creating undefined name")]
    UndefinedName,
    /// `makeNameUnique`'s result is taken.
    #[error("Unable to uniquify name: {name}")]
    Uniquify {
        /// The candidate.
        name: String,
    },
    /// A conflict symbol for a varnode that is not written.
    #[error("Conflict symbol created on illegal Varnode")]
    ConflictVarnode,
    /// `overrideSizeLockType` on a symbol that is not size-locked.
    #[error("Overriding symbol that is not size locked")]
    NotSizeLocked,
    /// `overrideSizeLockType` with a type of another size.
    #[error("Overriding symbol with different type size")]
    DifferentSize,
    /// A second global scope.
    #[error("Multiple global scopes")]
    MultipleGlobal,
    /// A global scope with a name.
    #[error("Global scope does not have empty name")]
    NamedGlobal,
    /// A non-global scope without a name.
    #[error("Non-global scope has empty name")]
    EmptyScopeName,
    /// A scope id already in use (Ghidra `RecovError`).
    #[error("Duplicate scope id: {full_name}")]
    DuplicateScope {
        /// The full name of the new scope.
        full_name: String,
    },
    /// A function whose scope id is taken (Ghidra `DuplicateFunctionError`).
    #[error("Duplicate Function")]
    DuplicateFunction {
        /// The function's address.
        address: Address,
        /// The function's name.
        name: String,
    },
    /// Creating a namespace by name in a database without hashed ids.
    #[error("Scope name hashes not allowed")]
    ScopeHashes,
    /// A scope missing from its parent's children.
    #[error("Could not remove parent reference to: {name}")]
    NoParentRef {
        /// The scope.
        name: String,
    },
    /// The element inside `<mapsym>` is not a symbol.
    #[error("Unknown symbol type")]
    UnknownSymbolType,
    /// An unknown child of `<symbollist>`.
    #[error("Unknown symbollist tag")]
    UnknownSymbollistTag,
    /// A `<parent>` id that names no scope.
    #[error("Could not find scope matching id")]
    NoScopeMatchingId,
    /// A `<val>` without an id in a namespace path.
    #[error("Missing name and id in scope")]
    MissingScopeId,
    /// A union facet whose type is not a union.
    #[error("<unionfacetsymbol> does not have a union type")]
    FacetNotUnion,
    /// A union facet whose field number is out of range.
    #[error("<unionfacetsymbol> field attribute is out of bounds")]
    FacetField,
    /// A conflict entry cannot be decoded.
    #[error("Cannot decode MapEntryConflict")]
    DecodeConflict,
    /// A `<function>` symbol without a [`FunctionCodec`](crate::codec::FunctionCodec).
    #[error("<function> symbols need a function codec")]
    NoFunctionCodec,
    /// A comment type name that does not exist.
    #[error("Unknown comment type: {name}")]
    UnknownCommentType {
        /// The name.
        name: String,
    },
    /// A comment type value that is not exactly one type.
    #[error("Unknown comment type")]
    CommentTypeValue,
    /// A comment whose key exists (past 65,535 comments at one address;
    /// Ghidra drops and leaks it).
    #[error("too many comments at one address")]
    CommentKey,
    /// A negative codepoint.
    #[error("Negative unicode codepoint")]
    NegativeCodepoint,
    /// A codepoint above 21 bits.
    #[error("Bad unicode codepoint")]
    BadCodepoint,
    /// A constant pool key that exists.
    #[error("Creating duplicate entry in constant pool: {token}")]
    DuplicateCpool {
        /// The token of the existing record.
        token: String,
    },
    /// `<data length>` out of range.
    #[error("Bad constant pool record: bad <data> size")]
    CpoolDataSize,
    /// A string literal without data.
    #[error("Bad constant pool record: missing <data>")]
    CpoolMissingData,
    /// Fewer or malformed hex bytes than `<data length>` says (undefined in
    /// Ghidra).
    #[error("Bad constant pool record: bad <data> byte")]
    CpoolDataByte,
    /// A constant pool reference list without elements (undefined in
    /// Ghidra).
    #[error("constant pool reference list is empty")]
    CpoolNoRefs,
    /// The root element of an XML image is not `<binaryimage>`.
    #[error("Missing binaryimage tag in {file}")]
    MissingBinaryImage {
        /// The file name.
        file: String,
    },
    /// An unknown child of `<binaryimage>`.
    #[error("Unknown LoadImageXml tag")]
    UnknownImageTag,
    /// A load-image read failed.
    #[error(transparent)]
    DataUnavail(#[from] DataUnavail),
    /// Context variables registered after the first split point.
    #[error("Cannot register new context variables after database is initialized")]
    ContextInitialized,
    /// A context variable across two words.
    #[error("Context variable does not fit in one word")]
    ContextWord,
    /// An unknown context variable.
    #[error("Non-existent context variable: {name}")]
    UnknownContextVariable {
        /// The name.
        name: String,
    },
    /// An unknown child of `<context_points>`.
    #[error("Bad <context_points> tag")]
    ContextPointsTag,
    /// An unknown child of `<context_data>`.
    #[error("Bad <context_data> tag")]
    ContextDataTag,
    /// An unknown flow override name.
    #[error("Unknown flow override name: {name}")]
    UnknownFlowOverride {
        /// The name.
        name: String,
    },
    /// An unknown call destination override name.
    #[error("Unknown call destination override name: {name}")]
    UnknownCallDestOverride {
        /// The name.
        name: String,
    },
    /// A negative dead-code delay.
    #[error("Bad deadcodedelay tag")]
    DeadcodeDelay,
    /// An invalid flow override address.
    #[error("Bad flow override address")]
    FlowAddress,
    /// An invalid call destination override address.
    #[error("Bad destination override address")]
    DestinationAddress,
    /// A `<default_symbols>` symbol without a name.
    #[error("Missing name attribute in <symbol> element")]
    DefaultSymbolName,
    /// A `<default_symbols>` symbol without an address.
    #[error("Missing address attribute in <symbol> element")]
    DefaultSymbolAddress,
    /// The host-backed global scope does not support the operation (Ghidra
    /// `ScopeGhidra`'s `… unimplemented`).
    #[error("{0} unimplemented")]
    Unimplemented(&'static str),
    /// A limit of ADR-009 was exceeded.
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    /// A decoding error.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// An address-space error.
    #[error(transparent)]
    Space(#[from] SpaceError),
    /// A type error.
    #[error(transparent)]
    Type(#[from] TypeError),
    /// A host error.
    #[error(transparent)]
    Host(#[from] HostError),
}

/// Results of this crate.
pub type Result<T, E = SymbolError> = std::result::Result<T, E>;

/// Limits on hostile input (spec 4.21, ADR-009).
pub mod limits {
    /// Components of one namespace path.
    pub const MAX_PATH: usize = 64;
    /// Depth of the scope tree.
    pub const MAX_SCOPE_DEPTH: usize = 1024;
    /// Bytes of one name.
    pub const MAX_NAME: usize = 64 * 1024;
    /// Bytes of a constant-pool `<data>` (Ghidra's `MAX_STRING_SIZE`).
    pub const MAX_CPOOL_DATA: i64 = 0x10_0000;
    /// Words of context.
    pub const MAX_CONTEXT_WORDS: usize = 64;
    /// Symbols of one scope (ids and category indices are 32-bit).
    pub const MAX_SYMBOLS: u64 = u32::MAX as u64;
}
