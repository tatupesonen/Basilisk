//! The data interface: what the views ask of a program.
//!
//! [`ProgramSource`] is the one trait a program model implements to be
//! shown by the interface. Today the demo source implements it; later an
//! adapter over `bk-program` and `bk-decomp` will. Its methods are
//! synchronous and may be slow (storage, decompilation): the UI never calls
//! them on its own thread but through [`crate::task::DataClient`], which
//! runs them on worker threads and hands results back over a channel.
//!
//! Every method that could return a lot is paged: the listing by row range,
//! tables by [`TableQuery`] windows, searches by a result limit. Nothing
//! here depends on egui.

use super::commands::{Command, CommentKind};
use super::decomp::DecompiledFunction;
use super::functions::{
    FunctionColumn, FunctionInfo, Page, Reference, StringColumn, StringInfo, TableQuery,
};
use super::listing::{ListingRow, RowIndex, RowSpan};
use super::location::Address;
use super::symbols::{MemoryBlock, Symbol, SymbolCategory};

/// Facts about the open program, for the title bar and status bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    /// Program name (`licd`).
    pub name: String,
    /// Ghidra language id (`x86:LE:64:default`).
    pub language: String,
    /// Executable format (`Mach-O x86-64`).
    pub format: String,
    /// Image base.
    pub image_base: Address,
    /// Entry point, where the tool opens.
    pub entry: Address,
}

/// What to search for (Ghidra's Search Memory and Search Program Text).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SearchQuery {
    /// Text in the listing (mnemonics, operands, labels, comments),
    /// case-insensitive.
    Text(String),
    /// A byte sequence.
    Bytes(Vec<u8>),
}

/// One search result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Where it was found.
    pub address: Address,
    /// The listing text of that code unit, for the results table.
    pub preview: Box<str>,
}

/// An error from a data source, with what the user can do about it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// The address is outside every memory block.
    #[error("address {0} is not in the program's memory")]
    NoSuchAddress(Address),
    /// No function contains or starts at the address.
    #[error("no function at {0}")]
    NoFunction(Address),
    /// A name was rejected.
    #[error("invalid name {name:?}: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Why.
        reason: &'static str,
    },
    /// The edit refers to something that does not exist.
    #[error("cannot apply: {0}")]
    Rejected(String),
    /// The backing store failed.
    #[error("program data unavailable: {0}")]
    Unavailable(String),
}

/// Result type of the data interface.
pub type SourceResult<T> = Result<T, SourceError>;

/// A program, as the views see it.
///
/// Implementations must be `Send + Sync`: calls arrive from several worker
/// threads at once. Edits made through [`ProgramSource::apply`] must be
/// visible to every later call.
pub trait ProgramSource: Send + Sync + std::fmt::Debug {
    /// Facts about the program.
    fn info(&self) -> ProgramInfo;

    /// Number of rows in the listing.
    fn listing_len(&self) -> SourceResult<u64>;

    /// Rows `start .. start + count` of the listing (fewer at the end).
    fn listing_rows(&self, start: RowIndex, count: u32) -> SourceResult<Vec<ListingRow>>;

    /// The rows of the code unit containing `address`, or of the nearest
    /// code unit after it.
    fn rows_for_address(&self, address: Address) -> SourceResult<RowSpan>;

    /// Memory blocks, in address order.
    fn memory_blocks(&self) -> SourceResult<Vec<MemoryBlock>>;

    /// One page of the Functions table.
    fn functions(&self, query: &TableQuery<FunctionColumn>) -> SourceResult<Page<FunctionInfo>>;

    /// The function containing `address`, if any.
    fn function_containing(&self, address: Address) -> SourceResult<Option<FunctionInfo>>;

    /// Decompiles the function containing `address`.
    fn decompile(&self, address: Address) -> SourceResult<DecompiledFunction>;

    /// Symbols in one Symbol Tree category whose names contain `filter`
    /// (case-insensitive), at most `limit`, with the total.
    fn symbols(
        &self,
        category: SymbolCategory,
        filter: &str,
        limit: u32,
    ) -> SourceResult<Page<Symbol>>;

    /// Symbols whose names match `query` for go-to and the palette, best
    /// first, at most `limit`.
    fn lookup(&self, query: &str, limit: u32) -> SourceResult<Vec<Symbol>>;

    /// References to `address` (or, for a function, to its entry).
    fn references_to(&self, address: Address, limit: u32) -> SourceResult<Page<Reference>>;

    /// One page of the Defined Strings table.
    fn strings(&self, query: &TableQuery<StringColumn>) -> SourceResult<Page<StringInfo>>;

    /// Searches the program, returning at most `limit` hits in address order.
    fn search(&self, query: &SearchQuery, limit: u32) -> SourceResult<Page<SearchHit>>;

    /// The comments at a code unit (for the comment editor).
    fn comments(&self, address: Address) -> SourceResult<Vec<(CommentKind, String)>>;

    /// Applies an edit.
    fn apply(&self, command: &Command) -> SourceResult<()>;
}
