//! Symbols: the Symbol Tree's nodes, memory blocks, and name lookup.

use super::location::Address;

/// The Symbol Tree's top-level folders, in Ghidra's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolCategory {
    /// Imported functions and libraries.
    Imports,
    /// Exported symbols (entry points).
    Exports,
    /// Functions.
    Functions,
    /// Labels that are not functions.
    Labels,
    /// Classes (C++).
    Classes,
    /// Namespaces.
    Namespaces,
}

impl SymbolCategory {
    /// All categories in display order.
    pub const ALL: [Self; 6] = [
        Self::Imports,
        Self::Exports,
        Self::Functions,
        Self::Labels,
        Self::Classes,
        Self::Namespaces,
    ];

    /// The folder name Ghidra uses.
    pub fn title(self) -> &'static str {
        match self {
            Self::Imports => "Imports",
            Self::Exports => "Exports",
            Self::Functions => "Functions",
            Self::Labels => "Labels",
            Self::Classes => "Classes",
            Self::Namespaces => "Namespaces",
        }
    }
}

/// What kind of symbol a node or lookup result is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymbolKind {
    /// A function.
    Function,
    /// An imported function.
    Import,
    /// A code label.
    Label,
    /// A data label (global variable, pointer).
    Data,
    /// A defined string.
    String,
    /// A library (the parent of imports).
    Library,
}

impl SymbolKind {
    /// The token kind a name of this kind is shown as.
    pub fn token_kind(self) -> super::TokenKind {
        use super::TokenKind;
        match self {
            Self::Function => TokenKind::Function,
            Self::Import => TokenKind::Import,
            Self::Data => TokenKind::Global,
            Self::Label | Self::String | Self::Library => TokenKind::Label,
        }
    }
}

/// A symbol: a name at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Its name.
    pub name: Box<str>,
    /// Its address.
    pub address: Address,
    /// Its kind.
    pub kind: SymbolKind,
    /// Namespace or library it belongs to ("" for global).
    pub namespace: Box<str>,
}

/// A memory block (Ghidra's Program Tree fragments and Memory Map rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlock {
    /// Block name (`__text`).
    pub name: Box<str>,
    /// Segment or parent name (`__TEXT`).
    pub parent: Box<str>,
    /// Start address.
    pub start: Address,
    /// Size in bytes.
    pub size: u64,
    /// Permissions as `rwx` text.
    pub permissions: Box<str>,
}
