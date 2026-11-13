//! Decompiled code: lines of tokens with the addresses they came from.
//!
//! Mirrors Ghidra's `ClangLine`/`ClangToken` tree flattened to lines: each
//! token knows its kind and referent, and each line knows the address
//! ranges of the instructions it was produced from, which is what links
//! the decompiler and the listing in both directions.

use super::location::Address;
use super::token::Token;

/// A half-open address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRange {
    /// First address in the range.
    pub start: Address,
    /// First address after the range.
    pub end: Address,
}

impl AddressRange {
    /// Whether `a` lies in the range.
    pub fn contains(&self, a: Address) -> bool {
        self.start <= a && a < self.end
    }
}

/// One line of decompiled C.
#[derive(Debug, Clone, PartialEq)]
pub struct DecompLine {
    /// Indentation in levels (Ghidra indents by two spaces per level).
    pub indent: u16,
    /// The tokens of the line, in order, including spaces as `Plain`.
    pub tokens: Vec<Token>,
    /// Instruction ranges this line was produced from (empty for
    /// declarations and braces).
    pub ranges: Vec<AddressRange>,
}

impl DecompLine {
    /// Whether the line was produced from the instruction at `a`.
    pub fn covers(&self, a: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(a))
    }
}

/// A variable of a decompiled function (parameters first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompVariable {
    /// Its name.
    pub name: Box<str>,
    /// Its data type.
    pub datatype: Box<str>,
    /// Whether it is a parameter.
    pub is_parameter: bool,
}

/// The decompiled form of one function.
#[derive(Debug, Clone, PartialEq)]
pub struct DecompiledFunction {
    /// Entry address of the function.
    pub entry: Address,
    /// The function's name.
    pub name: Box<str>,
    /// Its signature as text, for the pane title.
    pub signature: Box<str>,
    /// The lines of C.
    pub lines: Vec<DecompLine>,
    /// Its variables, indexed by `Referent::Variable::index`.
    pub variables: Vec<DecompVariable>,
}
