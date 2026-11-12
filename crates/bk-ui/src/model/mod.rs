//! The data interface between the views and a program (spec section 4.2).
//!
//! Plain data and one trait, [`ProgramSource`], with no egui types: the
//! real program model implements it later without any change to the
//! views. See `source` for the paging and threading contract.

pub mod commands;
pub mod decomp;
pub mod functions;
pub mod listing;
pub mod location;
pub mod source;
pub mod symbols;
pub mod token;

pub use commands::{Command, CommentKind};
pub use decomp::{AddressRange, DecompLine, DecompVariable, DecompiledFunction};
pub use functions::{
    FunctionColumn, FunctionInfo, Page, Reference, SortOrder, StringColumn, StringInfo, TableQuery,
};
pub use listing::{ListingRow, RefKind, RowContent, RowIndex, RowSpan, XrefEntry};
pub use location::{Address, Location};
pub use source::{ProgramInfo, ProgramSource, SearchHit, SearchQuery, SourceError, SourceResult};
pub use symbols::{MemoryBlock, Symbol, SymbolCategory, SymbolKind};
pub use token::{Referent, Token, TokenKind};
