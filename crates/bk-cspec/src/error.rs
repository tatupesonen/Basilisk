//! Errors of the compiler specification reader and the prototype models.
//!
//! Ghidra throws `LowlevelError` (and `DecoderError`) with a message in
//! these places; the messages are kept verbatim, with the element path where
//! the reader knows it. `ParamUnassignedError` is its own variant because
//! callers recover from it (Ghidra catches it in `assignParameterStorage`
//! and `updateAllTypes`).

use bk_core::SpaceError;
use bk_marshal::{DecodeError, EncodeError};

use crate::types::TypeQueryError;

/// A failure while reading a compiler specification or using a model.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CspecError {
    /// A rule of the specification or the model was broken (Ghidra
    /// `LowlevelError` or `DecoderError`); `message` is Ghidra's.
    #[error("{}{message}", path_prefix(.path))]
    Spec {
        /// Ghidra's message.
        message: String,
        /// Where in the document, as `compiler_spec/prototype[name]/input`;
        /// empty when not known.
        path: String,
    },
    /// No storage could be assigned to a parameter (Ghidra
    /// `ParamUnassignedError`).
    #[error("{0}")]
    ParamUnassigned(String),
    /// A register named in the file is not known to the register source.
    #[error("{}Unknown register name '{name}'", path_prefix(.path))]
    UnknownRegister {
        /// The register name.
        name: String,
        /// Where in the document.
        path: String,
    },
    /// The XML could not be parsed or decoded.
    #[error("{}{source}", path_prefix(.path))]
    Decode {
        /// The decoder's error.
        source: DecodeError,
        /// Where in the document.
        path: String,
    },
    /// An address space operation failed.
    #[error("{}{source}", path_prefix(.path))]
    Space {
        /// The space manager's error.
        source: SpaceError,
        /// Where in the document.
        path: String,
    },
    /// An encoder rejected a value.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// The type model rejected a request.
    #[error(transparent)]
    Types(#[from] TypeQueryError),
}

fn path_prefix(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!("{path}: ")
    }
}

impl CspecError {
    /// A [`CspecError::Spec`] with Ghidra's message and no path.
    pub fn new(message: impl Into<String>) -> Self {
        Self::Spec {
            message: message.into(),
            path: String::new(),
        }
    }

    /// The same error with `path` recorded, unless a more precise path is
    /// already there.
    #[must_use]
    pub fn at(mut self, at: &str) -> Self {
        match &mut self {
            Self::Spec { path, .. }
            | Self::UnknownRegister { path, .. }
            | Self::Decode { path, .. }
            | Self::Space { path, .. } => {
                if path.is_empty() {
                    at.clone_into(path);
                } else if !at.is_empty() && !path.starts_with(at) {
                    *path = format!("{at}/{path}");
                }
            }
            Self::ParamUnassigned(_) | Self::Encode(_) | Self::Types(_) => {}
        }
        self
    }

    /// The message without the path.
    pub fn message(&self) -> String {
        match self {
            Self::Spec { message, .. } => message.clone(),
            Self::UnknownRegister { name, .. } => format!("Unknown register name '{name}'"),
            Self::Decode { source, .. } => source.to_string(),
            Self::Space { source, .. } => source.to_string(),
            other => other.to_string(),
        }
    }
}

impl From<DecodeError> for CspecError {
    fn from(source: DecodeError) -> Self {
        Self::Decode {
            source,
            path: String::new(),
        }
    }
}

impl From<SpaceError> for CspecError {
    fn from(source: SpaceError) -> Self {
        match source {
            SpaceError::UnknownRegister(name) => Self::UnknownRegister {
                name,
                path: String::new(),
            },
            SpaceError::Decode(source) => Self::Decode {
                source,
                path: String::new(),
            },
            source => Self::Space {
                source,
                path: String::new(),
            },
        }
    }
}

/// Result type of this crate.
pub type Result<T, E = CspecError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_prefix_messages() {
        let e = CspecError::new("Missing prototype attributes").at("compiler_spec/prototype");
        assert_eq!(
            e.to_string(),
            "compiler_spec/prototype: Missing prototype attributes"
        );
        assert_eq!(e.message(), "Missing prototype attributes");
        let e = e.at("compiler_spec");
        assert_eq!(
            e.to_string(),
            "compiler_spec/prototype: Missing prototype attributes"
        );
        let e = CspecError::new("x").at("input").at("prototype[a]");
        assert_eq!(e.to_string(), "prototype[a]/input: x");
    }

    #[test]
    fn unknown_registers_are_their_own_variant() {
        let e: CspecError = SpaceError::UnknownRegister("EAX".into()).into();
        assert!(matches!(e, CspecError::UnknownRegister { .. }));
        assert_eq!(e.message(), "Unknown register name 'EAX'");
    }
}
