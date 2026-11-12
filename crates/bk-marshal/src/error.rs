//! Errors raised while decoding and encoding.
//!
//! Ghidra throws `DecoderError` (and `LowlevelError` for a few cases) with a
//! message; here each case is a variant carrying what was expected and found.
//! The messages follow Ghidra's wording.

use crate::xml::XmlError;

/// The kind of value an attribute read asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeKind {
    /// A boolean.
    Boolean,
    /// A signed integer.
    SignedInteger,
    /// An unsigned integer.
    UnsignedInteger,
    /// A string.
    String,
    /// An address space.
    Space,
}

impl AttributeKind {
    /// The noun Ghidra uses in "Expecting … attribute".
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::SignedInteger => "signed integer",
            Self::UnsignedInteger => "unsigned integer",
            Self::String => "string",
            Self::Space => "space",
        }
    }
}

/// A failure to decode a document (Ghidra `DecoderError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The packed stream ended inside a record.
    #[error("Unexpected end of stream (at byte {offset})")]
    UnexpectedEof {
        /// Offset of the byte that could not be read.
        offset: usize,
    },
    /// An element was required but the current element has no further child
    /// (or the document has already been traversed).
    #[error("Expecting <{expected}> but no element remains")]
    NoElement {
        /// Name of the element that was expected.
        expected: &'static str,
    },
    /// A different element than the one required comes next.
    #[error("Expecting <{expected}> but got {found}")]
    ElementMismatch {
        /// Name of the element that was expected.
        expected: &'static str,
        /// The element found: `<name>` in the XML form, `id N` in the packed form.
        found: String,
    },
    /// The current element was closed while children remained unread.
    #[error("Expecting element close: {element} has additional children")]
    UnreadChildren {
        /// The element being closed: `<name>` in XML, `id N` in the packed form.
        element: String,
    },
    /// The id passed to a close does not match the element being closed.
    #[error("Did not see expected closing element: closing id {expected} but found id {found}")]
    CloseMismatch {
        /// The id the caller passed.
        expected: u32,
        /// The id of the element actually open.
        found: u32,
    },
    /// Elements are nested deeper than the decoders allow. The limit protects
    /// the recursive routines that consume documents (ADR-009).
    #[error("Elements are nested more than {limit} deep")]
    TooDeep {
        /// The nesting limit.
        limit: usize,
    },
    /// An operation needs an open element and none is open.
    #[error("No element is open")]
    NoOpenElement,
    /// The packed stream holds a record that cannot appear at this point.
    #[error("Corrupt stream (at byte {offset})")]
    CorruptStream {
        /// Offset of the offending byte.
        offset: usize,
    },
    /// A named attribute is not present in the current element.
    #[error("Attribute {name} is not present")]
    AttributeMissing {
        /// Name of the attribute searched for.
        name: &'static str,
    },
    /// A value was read without a current attribute: no call to
    /// `next_attribute` came first, or it returned `None`.
    #[error("No current attribute to read")]
    NoCurrentAttribute,
    /// The attributes of the current element can no longer be read by name
    /// because one of its children has been closed (packed form only: the
    /// stream position has moved past them).
    #[error("Attributes cannot be read after a child element has been closed")]
    AttributesUnavailable,
    /// The attribute holds a different kind of value than the one asked for.
    #[error("Expecting {} attribute (at byte {offset})", expected.describe())]
    WrongAttributeKind {
        /// The kind asked for.
        expected: AttributeKind,
        /// Offset of the attribute's type byte.
        offset: usize,
    },
    /// A string attribute did not hold the one string that stands for a value.
    #[error("Expecting string \"{expected}\" but read \"{found}\"")]
    UnexpectedString {
        /// The string that was acceptable.
        expected: String,
        /// The string found.
        found: String,
    },
    /// The XML form names an address space the resolver does not know.
    #[error("Unknown address space name: {0}")]
    UnknownSpaceName(String),
    /// The packed form holds a space index beyond the number of spaces.
    #[error("Invalid address space index: {0}")]
    InvalidSpaceIndex(u64),
    /// The packed form holds a space index with no space assigned.
    #[error("Unknown address space index: {0}")]
    UnknownSpaceIndex(u64),
    /// The packed form holds a special space code that cannot be decoded
    /// (fspec, iop and spacebase references never cross the marshalling
    /// boundary), or a stack or join reference where no such space exists.
    #[error("Cannot marshal special address space (code {0})")]
    UnsupportedSpecialSpace(u8),
    /// An attribute name starts with an indexed attribute's base name but is
    /// not followed by a positive decimal index.
    #[error("Bad indexed attribute: {name}")]
    BadIndexedAttribute {
        /// The base name of the indexed attribute.
        name: &'static str,
    },
    /// An enumeration attribute holds a name the caller does not recognise.
    #[error("Unknown enumeration name: {0}")]
    UnknownEnumName(String),
    /// A packed string is not valid UTF-8.
    #[error("String attribute is not valid UTF-8 (at byte {offset})")]
    InvalidUtf8 {
        /// Offset of the first byte that is not valid UTF-8.
        offset: usize,
    },
    /// The XML text could not be parsed.
    #[error(transparent)]
    Xml(#[from] XmlError),
}

/// A failure to encode a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The packed form cannot hold a string containing a NUL character,
    /// because Ghidra reads the stream up to the first NUL byte.
    #[error("PackedEncode: string with null character")]
    StringWithNul,
}
