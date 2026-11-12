//! Edits, expressed as commands sent back through the data interface.

use super::location::Address;

/// Kinds of comment, with Ghidra's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CommentKind {
    /// End-of-line comment (right of the instruction).
    Eol,
    /// Pre-comment (above the instruction).
    Pre,
    /// Post-comment (below the instruction).
    Post,
    /// Plate comment (boxed, above a function or block).
    Plate,
}

impl CommentKind {
    /// All kinds, in the order of Ghidra's Set Comment dialog tabs.
    pub const ALL: [Self; 4] = [Self::Eol, Self::Pre, Self::Post, Self::Plate];

    /// Ghidra's name for the kind.
    pub fn title(self) -> &'static str {
        match self {
            Self::Eol => "EOL Comment",
            Self::Pre => "Pre Comment",
            Self::Post => "Post Comment",
            Self::Plate => "Plate Comment",
        }
    }
}

/// An edit to the program.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Rename the label or function at an address (Ghidra's Edit Label,
    /// Rename Function).
    RenameSymbol {
        /// Where the symbol is.
        address: Address,
        /// The new name.
        name: String,
    },
    /// Remove a user label (Ghidra's Remove Label); undoes adding one.
    RemoveLabel {
        /// Where the label is.
        address: Address,
    },
    /// Rename a local variable or parameter of a function.
    RenameVariable {
        /// Entry address of the function.
        function: Address,
        /// Index of the variable.
        index: u32,
        /// The new name.
        name: String,
    },
    /// Set (or, with empty text, clear) a comment.
    SetComment {
        /// The code unit commented.
        address: Address,
        /// Which comment.
        kind: CommentKind,
        /// The text; empty removes the comment.
        text: String,
    },
}

impl Command {
    /// A short description for the Console and undo history.
    pub fn describe(&self) -> String {
        match self {
            Self::RenameSymbol { address, name } => format!("Rename {address} to {name}"),
            Self::RemoveLabel { address } => format!("Remove label at {address}"),
            Self::RenameVariable { name, .. } => format!("Rename variable to {name}"),
            Self::SetComment {
                address, kind, text, ..
            } if text.is_empty() => format!("Clear {} at {address}", kind.title()),
            Self::SetComment { address, kind, .. } => format!("Set {} at {address}", kind.title()),
        }
    }
}
