//! The error type shared by providers and the reader.

use std::path::PathBuf;

/// Result alias used throughout the crate.
pub type Result<T, E = BinError> = std::result::Result<T, E>;

/// Why a provider or reader operation failed.
///
/// Ghidra throws `IOException` (and `EOFException`) in these places; here
/// every failure is a value that says where it happened and what was wanted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BinError {
    /// A read reached outside the provider.
    #[error(
        "cannot read {len} byte(s) at offset {offset:#x}: outside the data (length {provider_len:#x})"
    )]
    OutOfBounds {
        /// Offset at which the read started.
        offset: u64,
        /// Number of bytes wanted.
        len: u64,
        /// Length of the provider.
        provider_len: u64,
    },

    /// A terminated string was requested at or past the end of the data, so
    /// not even its first character could be read.
    #[error("attempted to read a string at {offset:#x}, at or past the end of the data")]
    StringAtEof {
        /// Offset at which the string was to start.
        offset: u64,
    },

    /// The data ended before the string's terminator was found.
    #[error("unterminated string at {start:#x}..{end:#x}")]
    UnterminatedString {
        /// Offset of the first character.
        start: u64,
        /// Offset at which reading stopped.
        end: u64,
    },

    /// A terminated string grew past [`MAX_STRING_BYTES`](crate::MAX_STRING_BYTES)
    /// without a terminator.
    #[error("run-on unterminated string at {start:#x}..{end:#x}")]
    RunOnString {
        /// Offset of the first character.
        start: u64,
        /// Offset at which reading stopped.
        end: u64,
    },

    /// An array read asked for more elements than
    /// [`MAX_ARRAY_ELEMENTS`](crate::MAX_ARRAY_ELEMENTS), or its byte size overflowed.
    #[error(
        "invalid number of elements: {count} element(s) of {element_size} byte(s) at {offset:#x}"
    )]
    InvalidElementCount {
        /// Offset of the array.
        offset: u64,
        /// Number of elements asked for.
        count: u64,
        /// Size of one element in bytes.
        element_size: usize,
    },

    /// A variable-length integer read was given a length outside 1 to 8 bytes.
    #[error("invalid integer length {len}: must be 1 to 8 bytes")]
    InvalidValueLength {
        /// The length asked for.
        len: usize,
    },

    /// A LEB128 value needs more than 64 bits.
    #[error("LEB128 value at {offset:#x} does not fit in 64 bits")]
    Leb128TooLarge {
        /// Offset of the first byte of the value.
        offset: u64,
    },

    /// A value read from the data does not fit the type the caller needs.
    #[error("value {value} is out of range for {target}")]
    ValueOutOfRange {
        /// The value read.
        value: i128,
        /// What it had to fit into.
        target: &'static str,
    },

    /// The operating system reported an error while reading.
    #[error("I/O error reading {len} byte(s) at offset {offset:#x}: {source}")]
    Io {
        /// Offset at which the read started.
        offset: u64,
        /// Number of bytes wanted.
        len: u64,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A file could not be opened or its size could not be determined.
    #[error("cannot open {}: {source}", path.display())]
    Open {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl BinError {
    /// True when the error means "the data ended" — the cases in which Ghidra
    /// throws `EOFException` rather than a plain `IOException`.
    pub fn is_eof(&self) -> bool {
        matches!(
            self,
            Self::OutOfBounds { .. } | Self::StringAtEof { .. } | Self::UnterminatedString { .. }
        )
    }

    /// Convenience constructor for [`BinError::OutOfBounds`].
    pub(crate) fn out_of_bounds(offset: u64, len: u64, provider_len: u64) -> Self {
        Self::OutOfBounds {
            offset,
            len,
            provider_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BinError;

    #[test]
    fn messages_carry_context() {
        let e = BinError::out_of_bounds(0x10, 4, 0x12);
        assert_eq!(
            e.to_string(),
            "cannot read 4 byte(s) at offset 0x10: outside the data (length 0x12)"
        );
        assert!(e.is_eof());
        let e = BinError::UnterminatedString { start: 3, end: 9 };
        assert_eq!(e.to_string(), "unterminated string at 0x3..0x9");
        assert!(e.is_eof());
        assert!(!BinError::InvalidValueLength { len: 9 }.is_eof());
        assert!(!BinError::Leb128TooLarge { offset: 0 }.is_eof());
    }
}
