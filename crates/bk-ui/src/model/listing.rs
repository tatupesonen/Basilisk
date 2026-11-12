//! The listing: the program as a sequence of display rows.
//!
//! Ghidra's listing lays out each code unit as a stack of fields (plate
//! comment, function signature, variables, labels, cross-references, the
//! instruction line, end-of-line and post comments). Here every visual line
//! of that stack is one [`ListingRow`] of uniform height, numbered by a
//! [`RowIndex`]. A data source can therefore serve "rows from index *i*,
//! *n* of them" and map an address to its row in O(1) or O(log n), and a
//! view can scroll to any row without measuring the rows before it.

use super::location::Address;
use super::token::Token;

/// Position of a row in the listing (0 is the first row of the program).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RowIndex(pub u64);

/// The rows that display one address: where its block starts (plate
/// comment, function header) and the row of the code unit itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowSpan {
    /// First row belonging to the address (top of its header).
    pub first: RowIndex,
    /// The row holding the instruction or data item (where the cursor goes).
    pub unit: RowIndex,
}

/// Kind of a cross-reference, shown in Ghidra's notation after the
/// referring address: `(c)` call, `(j)` jump, `(R)` read, `(W)` write,
/// `(*)` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefKind {
    /// A call.
    Call,
    /// A jump or branch.
    Jump,
    /// A data read.
    Read,
    /// A data write.
    Write,
    /// The address is taken (a pointer, `LEA`).
    Pointer,
}

impl RefKind {
    /// Ghidra's one-letter tag.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Call => "c",
            Self::Jump => "j",
            Self::Read => "R",
            Self::Write => "W",
            Self::Pointer => "*",
        }
    }

    /// The name used in the References table.
    pub fn name(self) -> &'static str {
        match self {
            Self::Call => "UNCONDITIONAL_CALL",
            Self::Jump => "JUMP",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Pointer => "DATA",
        }
    }
}

/// One cross-reference as shown in an XREF field: the referring address,
/// the function it is in, and the kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefEntry {
    /// The referring address.
    pub from: Address,
    /// Name of the function containing `from`, if any.
    pub from_function: Option<Box<str>>,
    /// Kind of reference.
    pub kind: RefKind,
}

/// The content of one listing row, field by field.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RowContent {
    /// An empty separator line.
    Blank,
    /// The top or bottom border of a plate comment (`****…`).
    PlateBorder,
    /// One line of a plate comment, drawn inside the border.
    Plate(Box<str>),
    /// A function signature: return type, name, parameters.
    Signature(Vec<Token>),
    /// A parameter or local variable of the function below.
    Variable {
        /// Data type name.
        datatype: Box<str>,
        /// Storage (`EDI:4`, `Stack[-0x28]:8`).
        storage: Box<str>,
        /// The variable's name.
        name: Token,
    },
    /// A label (function name, `LAB_…`, data name), with the first
    /// cross-reference to it.
    Label {
        /// The label.
        name: Token,
        /// Number of references to this address.
        xref_count: u32,
        /// The first reference, shown on the label's line.
        first_xref: Option<XrefEntry>,
    },
    /// A further cross-reference below a label.
    Xref(XrefEntry),
    /// "[more]": more references exist than the listing shows.
    XrefMore(u32),
    /// A pre-comment line, above the code unit.
    PreComment(Box<str>),
    /// A post-comment line, below the code unit.
    PostComment(Box<str>),
    /// A section header (`// __text`), as Ghidra prints memory block starts.
    Section {
        /// Block name.
        name: Box<str>,
        /// Block range as text (`ram:100000650-1000019c7`).
        range: Box<str>,
    },
    /// An instruction.
    Instruction {
        /// Its bytes.
        bytes: Box<[u8]>,
        /// The mnemonic token.
        mnemonic: Token,
        /// Operand tokens, including separators.
        operands: Vec<Token>,
        /// End-of-line comment.
        comment: Option<Box<str>>,
    },
    /// A defined data item.
    Data {
        /// Its bytes (the first few, for display).
        bytes: Box<[u8]>,
        /// Its data type name (`ds`, `int`, `addr`).
        datatype: Token,
        /// Its value.
        value: Vec<Token>,
        /// End-of-line comment.
        comment: Option<Box<str>>,
    },
}

/// One listing row.
#[derive(Debug, Clone, PartialEq)]
pub struct ListingRow {
    /// The address this row belongs to.
    pub address: Address,
    /// What the row shows.
    pub content: RowContent,
}

impl ListingRow {
    /// Whether this row is a code unit (where a cursor naturally rests).
    pub fn is_unit(&self) -> bool {
        matches!(
            self.content,
            RowContent::Instruction { .. } | RowContent::Data { .. }
        )
    }

    /// The tokens of this row that can be clicked, in display order.
    pub fn tokens(&self) -> Vec<&Token> {
        match &self.content {
            RowContent::Signature(t) => t.iter().collect(),
            RowContent::Variable { name, .. } | RowContent::Label { name, .. } => vec![name],
            RowContent::Instruction {
                mnemonic, operands, ..
            } => std::iter::once(mnemonic).chain(operands.iter()).collect(),
            RowContent::Data {
                datatype, value, ..
            } => std::iter::once(datatype).chain(value.iter()).collect(),
            _ => Vec::new(),
        }
    }
}
