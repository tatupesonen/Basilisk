//! Errors of the type system.
//!
//! Ghidra throws `LowlevelError` (and `ParseError` from the C parser) with a
//! message; tests and the console show those messages, so they are kept
//! verbatim here.

use bk_marshal::DecodeError;

use crate::ids::TypeId;

/// A failure in the type system.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypeError {
    /// A rule of the type system was broken (Ghidra `LowlevelError`); the
    /// message is Ghidra's.
    #[error("{0}")]
    Lowlevel(String),
    /// The C declaration parser rejected its input (Ghidra `ParseError`).
    #[error("{0}")]
    Parse(String),
    /// A document could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// An encoder rejected a value.
    #[error(transparent)]
    Encode(#[from] bk_marshal::EncodeError),
    /// The id does not name a live type of this factory.
    #[error("invalid type id {0:?}")]
    InvalidId(TypeId),
    /// An input is nested deeper than the limit that keeps recursion bounded
    /// (ADR-009).
    #[error("nesting deeper than {0} levels")]
    TooDeep(usize),
}

impl TypeError {
    /// A [`TypeError::Lowlevel`] with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self::Lowlevel(message.into())
    }

    /// A [`TypeError::Parse`] with the given message.
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Parse(message.into())
    }
}

/// Result type of this crate.
pub type Result<T, E = TypeError> = std::result::Result<T, E>;
