//! Source positions.
//!
//! A [`Span`] is a byte range in the *preprocessed* text of a specification
//! (the text the lexer reads, after `@include` and `$(NAME)` expansion).
//! [`crate::SourceMap`] turns a span back into a [`Location`] in the file the
//! text originally came from.

use std::fmt;

/// A half-open byte range `start..end` in the preprocessed text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    /// Offset of the first byte.
    pub start: u32,
    /// Offset one past the last byte.
    pub end: u32,
}

impl Span {
    /// A span covering `start..end`.
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// An empty span at `offset`.
    pub const fn at(offset: u32) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }

    /// The smallest span covering both `self` and `other`.
    #[must_use]
    pub fn to(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// Length in bytes.
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }

    /// The span as a `usize` range, for slicing the preprocessed text.
    pub const fn range(self) -> std::ops::Range<usize> {
        self.start as usize..self.end as usize
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// Index of a source file within one parse, in order of first inclusion.
///
/// This is not the index Ghidra's `SourceFileIndexer` writes into a `.sla`,
/// which numbers files in order of their first constructor; the compiler
/// builds that with [`crate::SourceFileIndexer`] from [`crate::SourceFile::name`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FileId(pub u32);

/// One inclusion of a file: the root file, or one `@include` of a file.
///
/// A file included twice has one [`FileId`] and two `IncludeId`s, each with
/// its own include chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct IncludeId(pub u32);

/// A position in an original source file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Location {
    /// The file.
    pub file: FileId,
    /// The inclusion of that file the position belongs to.
    pub include: IncludeId,
    /// Line number, starting at 1.
    pub line: u32,
    /// Column in characters, starting at 1. For text produced by a `$(NAME)`
    /// expansion this is the column of the `$`.
    pub column: u32,
    /// Whether the position lies inside the value of a `$(NAME)` expansion.
    pub in_expansion: bool,
}
