//! Identity types: language ids, compiler spec ids, their pairing, and
//! processors (Ghidra: `LanguageID`, `CompilerSpecID`,
//! `LanguageCompilerSpecPair`, `Processor`).

use std::{borrow::Borrow, fmt, sync::Arc};

/// An id was given as an empty string where Ghidra requires a non-empty one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("empty {what} not allowed")]
pub struct EmptyIdError {
    what: &'static str,
}

/// The id of a language, conventionally `processor:endian:size:variant`
/// (`x86:LE:64:default`).
///
/// The id is an opaque non-empty string: equality and ordering are by the
/// string, and the fields of a language come from its description, never
/// from splitting the id. Cloning is cheap (the text is shared).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LanguageId(Arc<str>);

impl LanguageId {
    /// Creates a language id; an empty string is rejected, as in Ghidra.
    pub fn new(id: impl AsRef<str>) -> Result<Self, EmptyIdError> {
        let id = id.as_ref();
        if id.is_empty() {
            return Err(EmptyIdError {
                what: "language id",
            });
        }
        Ok(Self(Arc::from(id)))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for LanguageId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// The id of a compiler specification within a language (`gcc`,
/// `windows`, `default`).
///
/// Any string is an id. `default` is only a convention: lookups never fall
/// back to it, and a language's default compiler spec is the first one its
/// `.ldefs` entry lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompilerSpecId(Arc<str>);

impl CompilerSpecId {
    /// The id Ghidra substitutes when none is given: `default`.
    pub const DEFAULT: &'static str = "default";

    /// Creates a compiler spec id.
    #[must_use]
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CompilerSpecId {
    /// The id `default`, which Ghidra's `CompilerSpecID(null)` yields.
    fn default() -> Self {
        Self::new(Self::DEFAULT)
    }
}

impl fmt::Display for CompilerSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for CompilerSpecId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// A language together with one of its compiler specs: what a loader
/// needs to import a file.
///
/// Ordered by language id, then compiler spec id; displayed as
/// `language:compiler`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LanguageCompilerSpecPair {
    /// The language.
    pub language_id: LanguageId,
    /// The compiler spec.
    pub compiler_spec_id: CompilerSpecId,
}

impl LanguageCompilerSpecPair {
    /// Pairs a language id with a compiler spec id.
    #[must_use]
    pub fn new(language_id: LanguageId, compiler_spec_id: CompilerSpecId) -> Self {
        Self {
            language_id,
            compiler_spec_id,
        }
    }

    /// Builds a pair from two strings, rejecting an empty one as Ghidra's
    /// string constructor does.
    pub fn from_strs(language_id: &str, compiler_spec_id: &str) -> Result<Self, EmptyIdError> {
        let language_id = LanguageId::new(language_id)?;
        if compiler_spec_id.is_empty() {
            return Err(EmptyIdError {
                what: "compiler spec id",
            });
        }
        Ok(Self {
            language_id,
            compiler_spec_id: CompilerSpecId::new(compiler_spec_id),
        })
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.language_id, self.compiler_spec_id)
    }
}

/// A processor family known to a [`LanguageRegistry`](crate::LanguageRegistry):
/// a typed index into the registry's table of processor names.
///
/// Ghidra keeps processors in a process-wide table; here the registry that
/// read the `.ldefs` files owns the names, and a `Processor` is only
/// meaningful with the registry that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Processor(pub(crate) u32);

impl Processor {
    /// The position of this processor in its registry's table, in order of
    /// first appearance.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_id_rejects_empty_and_orders_by_text() {
        assert_eq!(
            LanguageId::new("").unwrap_err().to_string(),
            "empty language id not allowed"
        );
        let a = LanguageId::new("8051:BE:16:default").unwrap();
        let b = LanguageId::new("x86:LE:32:default").unwrap();
        assert!(a < b);
        assert_eq!(a, LanguageId::new("8051:BE:16:default").unwrap());
        assert_eq!(b.to_string(), "x86:LE:32:default");
        assert_eq!(b.as_str(), "x86:LE:32:default");
    }

    #[test]
    fn compiler_spec_id_defaults_to_default() {
        assert_eq!(CompilerSpecId::default().as_str(), "default");
        assert_eq!(CompilerSpecId::new("gcc").to_string(), "gcc");
        assert!(CompilerSpecId::new("borlandcpp") < CompilerSpecId::new("gcc"));
        // Ghidra accepts an empty compiler spec id on its own.
        assert_eq!(CompilerSpecId::new("").as_str(), "");
    }

    #[test]
    fn pair_orders_by_language_then_compiler_and_displays_both() {
        let p1 = LanguageCompilerSpecPair::from_strs("x86:LE:32:default", "gcc").unwrap();
        let p2 = LanguageCompilerSpecPair::from_strs("x86:LE:32:default", "windows").unwrap();
        let p3 = LanguageCompilerSpecPair::from_strs("x86:LE:64:default", "gcc").unwrap();
        assert!(p1 < p2 && p2 < p3);
        assert_eq!(p1.to_string(), "x86:LE:32:default:gcc");
        assert_eq!(
            p1,
            LanguageCompilerSpecPair::new(
                LanguageId::new("x86:LE:32:default").unwrap(),
                CompilerSpecId::new("gcc")
            )
        );
    }

    #[test]
    fn pair_from_strs_rejects_empty_parts() {
        assert_eq!(
            LanguageCompilerSpecPair::from_strs("", "gcc")
                .unwrap_err()
                .to_string(),
            "empty language id not allowed"
        );
        assert_eq!(
            LanguageCompilerSpecPair::from_strs("x86:LE:32:default", "")
                .unwrap_err()
                .to_string(),
            "empty compiler spec id not allowed"
        );
    }
}
