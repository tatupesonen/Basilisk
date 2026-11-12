//! Functions, defined strings and references: the tables beside the listing.

use super::listing::RefKind;
use super::location::Address;

/// Order of a table query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SortOrder {
    /// Smallest first.
    #[default]
    Ascending,
    /// Largest first.
    Descending,
}

/// A query for one page of a table: filter text, sort column, window.
///
/// The source applies the filter and the order and returns only
/// `offset..offset + limit`, with the total, so a table of a million rows
/// is served one screenful at a time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableQuery<C> {
    /// Case-insensitive substring filter on the name column ("" = all).
    pub filter: String,
    /// Column to sort by.
    pub sort: C,
    /// Sort direction.
    pub order: SortOrder,
    /// First row wanted.
    pub offset: u64,
    /// Number of rows wanted.
    pub limit: u32,
}

/// One page of a table and the size of the whole (filtered) table.
#[derive(Debug, Clone, PartialEq)]
pub struct Page<T> {
    /// The rows of this page.
    pub rows: Vec<T>,
    /// Rows matching the query in total.
    pub total: u64,
}

/// Columns of the Functions table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FunctionColumn {
    /// By name.
    Name,
    /// By entry address.
    #[default]
    Location,
    /// By size in bytes.
    Size,
    /// By number of references to it.
    References,
}

/// A row of the Functions table (Ghidra's Functions window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Entry address.
    pub entry: Address,
    /// Name.
    pub name: Box<str>,
    /// Signature as text.
    pub signature: Box<str>,
    /// Size of its body in bytes.
    pub size: u64,
    /// Number of references to it.
    pub references: u32,
    /// Whether it is a thunk to an imported function.
    pub is_thunk: bool,
}

/// Columns of the Defined Strings table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StringColumn {
    /// By address.
    #[default]
    Location,
    /// By text.
    Value,
    /// By length.
    Length,
}

/// A row of the Defined Strings table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringInfo {
    /// Where the string is.
    pub address: Address,
    /// Its text (escapes shown as C escapes).
    pub value: Box<str>,
    /// Length in bytes including the terminator.
    pub length: u32,
    /// Its data type (`ds` for a C string).
    pub datatype: Box<str>,
}

/// A reference to an address, as listed by "Show References to".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The referring address.
    pub from: Address,
    /// The referenced address.
    pub to: Address,
    /// Function containing `from`, if any.
    pub from_function: Option<Box<str>>,
    /// The referring instruction as text (`CALL parse_config`).
    pub code: Box<str>,
    /// The kind of reference.
    pub kind: RefKind,
}
