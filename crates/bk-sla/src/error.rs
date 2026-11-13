//! Errors of reading, validating and writing a compiled language.

use std::fmt;
use std::path::PathBuf;

/// Where in a document an error was found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Location {
    /// The element path, with the symbol and constructor concerned, for
    /// example `sleigh/symbol_table/subtable_sym "instruction"/constructor 12/construct_tpl`.
    pub path: String,
    /// Byte offset in the inflated packed stream, when reading that form.
    pub offset: Option<usize>,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.path.is_empty() { "<document>" } else { &self.path })?;
        if let Some(offset) = self.offset {
            write!(f, " (at byte {offset})")?;
        }
        Ok(())
    }
}

/// What was wrong in the element stream.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// The stream ended inside a record or an open element.
    #[error("unexpected end of stream")]
    UnexpectedEof,
    /// A byte that cannot start a record here.
    #[error("corrupt stream: byte {byte:#04x} cannot appear here")]
    Corrupt {
        /// The byte.
        byte: u8,
    },
    /// A different element was found than the one the grammar requires.
    #[error("expected {expected}, found {found}")]
    UnexpectedElement {
        /// What the grammar allows here.
        expected: &'static str,
        /// What was there.
        found: String,
    },
    /// The element has children left that the grammar does not allow.
    #[error("unexpected child element {found}")]
    UnexpectedChild {
        /// The child.
        found: String,
    },
    /// The end record names another element than the one open.
    #[error("element closed with the id {found} instead of {expected}")]
    CloseMismatch {
        /// The id of the open element.
        expected: u32,
        /// The id the end record carries.
        found: u32,
    },
    /// A required attribute is missing.
    #[error("missing attribute `{0}`")]
    MissingAttribute(&'static str),
    /// An attribute holds another kind of value than the format requires.
    #[error("attribute `{attribute}` is not {expected}")]
    WrongType {
        /// The attribute.
        attribute: &'static str,
        /// The kind required.
        expected: &'static str,
    },
    /// An attribute's value does not fit the field Ghidra stores it in, or
    /// is outside the values the format allows.
    #[error("attribute `{attribute}` value {value} is out of range")]
    OutOfRange {
        /// The attribute.
        attribute: &'static str,
        /// The value read.
        value: i128,
    },
    /// A string attribute is not valid UTF-8.
    #[error("string attribute is not valid UTF-8")]
    InvalidUtf8,
    /// An address-space reference names no declared space.
    #[error("unknown address space {0}")]
    UnknownSpace(String),
    /// An opcode attribute names no p-code operation.
    #[error("unknown opcode {0}")]
    UnknownOpcode(String),
    /// Any other violation of the grammar, in Ghidra's words where it has
    /// them.
    #[error("{0}")]
    Invalid(String),
    /// The XML text could not be parsed or decoded.
    #[error(transparent)]
    Marshal(#[from] bk_marshal::DecodeError),
}

/// A failure to read, validate or write a compiled language.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SlaError {
    /// The file does not start with `sla` and format version 4.
    #[error("not a version 4 .sla file: header {found:02x?}")]
    Header {
        /// The bytes found (up to four).
        found: Vec<u8>,
    },
    /// The zlib stream is damaged or truncated.
    #[error("the compressed stream cannot be inflated: {message}")]
    Compression {
        /// What zlib reported.
        message: String,
    },
    /// Bytes follow the end of the zlib stream.
    #[error("{count} bytes follow the end of the compressed stream")]
    TrailingBytes {
        /// How many.
        count: usize,
    },
    /// Data follows the end of the `<sleigh>` element.
    #[error("data follows the end of the document (at byte {offset})")]
    TrailingData {
        /// Offset of the first byte after the document.
        offset: usize,
    },
    /// The element stream does not follow the format's grammar.
    #[error("{location}: {error}")]
    Stream {
        /// Where.
        location: Location,
        /// What.
        error: StreamError,
    },
    /// The document is well formed but breaks a validation rule
    /// (`features/sla.md` 4.3).
    #[error("{path}: {message}")]
    Structure {
        /// The element path, symbol and constructor concerned.
        path: String,
        /// The rule broken.
        message: String,
    },
    /// A limit of [`Limits`](crate::Limits) was exceeded.
    #[error("{location}: {what} exceeds the limit of {limit} (found {found})")]
    Limit {
        /// Where.
        location: Location,
        /// The quantity limited.
        what: &'static str,
        /// The limit.
        limit: u64,
        /// The value found (at least the limit plus one).
        found: u64,
    },
    /// The file could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// A string cannot be written in the packed form.
    #[error(transparent)]
    Encode(#[from] bk_marshal::EncodeError),
    /// The model's address spaces cannot be built.
    #[error(transparent)]
    Space(#[from] bk_core::SpaceError),
}

impl SlaError {
    /// A structure error with its path.
    pub(crate) fn structure(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Structure {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// An error raised inside the reader, before its location is attached.
#[derive(Debug)]
pub(crate) enum Fail {
    Stream(StreamError),
    Limit {
        what: &'static str,
        limit: u64,
        found: u64,
    },
}

impl From<StreamError> for Fail {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<bk_marshal::DecodeError> for Fail {
    fn from(error: bk_marshal::DecodeError) -> Self {
        Self::Stream(StreamError::Marshal(error))
    }
}

impl Fail {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Stream(StreamError::Invalid(message.into()))
    }

    pub(crate) fn limit(what: &'static str, limit: u64, found: u64) -> Self {
        Self::Limit { what, limit, found }
    }

    pub(crate) fn at(self, location: Location) -> SlaError {
        match self {
            Self::Stream(error) => SlaError::Stream { location, error },
            Self::Limit { what, limit, found } => SlaError::Limit {
                location,
                what,
                limit,
                found,
            },
        }
    }
}
