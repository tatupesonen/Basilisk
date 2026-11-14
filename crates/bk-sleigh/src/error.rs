//! Errors of loading a language and of decoding an instruction
//! (`features/sleigh-decode.md` 4.6).
//!
//! Decode errors print Ghidra's text, so that `pcodedump`'s `E` records can
//! be compared verbatim; each carries the address of the instruction.

use std::fmt;
use std::path::PathBuf;

use bk_core::{Address, SpaceError};
use bk_lang::{LanguageId, RegistryError};
use bk_sla::SlaError;

/// An address as Ghidra's `printRaw` writes it, captured without the space
/// manager so that an error can print itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawText {
    shortcut: char,
    offset: u64,
    form: RawForm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawForm {
    /// Plain hexadecimal (constant and `OTHER` spaces, unknown spaces).
    Plain,
    /// Zero-padded addressable units, with `+n` for a byte inside a unit.
    Padded {
        /// The space's address size in bytes.
        size: u8,
        /// Bytes per addressable unit.
        word: u32,
    },
}

impl RawText {
    pub(crate) const fn new(shortcut: char, offset: u64, form: RawForm) -> Self {
        Self {
            shortcut,
            offset,
            form,
        }
    }

    /// The text without the shortcut character (Ghidra `printRaw`).
    pub fn raw(&self) -> impl fmt::Display + '_ {
        RawOnly(self)
    }
}

struct RawOnly<'a>(&'a RawText);

impl fmt::Display for RawOnly<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = self.0.offset;
        match self.0.form {
            RawForm::Plain => write!(f, "{offset:#x}"),
            RawForm::Padded { size, word } => {
                let mut size = u32::from(size);
                if size > 4 {
                    if offset >> 32 == 0 {
                        size = 4;
                    } else if offset >> 48 == 0 {
                        size = 6;
                    }
                }
                let word = u64::from(word.max(1));
                let width = 2 * size as usize;
                write!(f, "0x{:0width$x}", offset / word, width = width)?;
                let cut = offset % word;
                if cut != 0 {
                    write!(f, "+{cut}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for RawText {
    /// The shortcut character followed by the raw text: `r0x00001002`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.shortcut, self.raw())
    }
}

/// Which table an operand failed to find an entry in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableKind {
    /// A value map (`attach values`).
    ValueTable,
    /// A name table (`attach names`).
    NameTable,
    /// A varnode list (`attach variables`).
    VarnodeList,
}

impl fmt::Display for TableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ValueTable => "valuetable",
            Self::NameTable => "nametable",
            Self::VarnodeList => "varnode list",
        })
    }
}

/// A bound the decoder enforces (ADR-009).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    /// More constructors nested than Ghidra's parser allows.
    Depth,
    /// More nodes in one instruction than the decoder allows.
    Nodes,
    /// A pattern expression evaluated more deeply than the decoder allows.
    ExpressionDepth,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Depth => "SLEIGH exceeded maximum parse depth",
            Self::Nodes => "SLEIGH parser exceeded the node limit of one instruction",
            Self::ExpressionDepth => "SLEIGH pattern expression nested too deeply",
        })
    }
}

/// How Ghidra classifies an error: the exception class it throws, which is
/// also `pcodedump`'s record kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// `BadDataError`: the bytes are not an instruction (`bad-data`).
    BadData,
    /// `UnimplError`: the instruction cannot be lifted (`unimplemented`).
    Unimplemented,
    /// `LowlevelError`: anything else (`error`).
    Lowlevel,
}

/// Why an instruction could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// No constructor of a decision-tree leaf matches.
    #[error("{at}: Unable to resolve constructor")]
    NoConstructor {
        /// The instruction's address.
        address: Address,
        /// The address as text.
        at: RawText,
    },
    /// A value-map, name or varnode-list operand selects an unusable entry.
    #[error("{at}: No corresponding entry in {table}")]
    NoTableEntry {
        /// The instruction's address.
        address: Address,
        /// The address as text.
        at: RawText,
        /// The table.
        table: TableKind,
    },
    /// A read starts at or past byte 16 of the instruction.
    #[error("Instruction is using more than 16 bytes")]
    TooLong {
        /// The instruction's address.
        address: Address,
    },
    /// A pattern expression divides by zero (undefined in Ghidra's C++,
    /// an exception in its Java; ADR-024).
    #[error("Division by zero in pattern expression")]
    DivisionByZero {
        /// The instruction's address.
        address: Address,
    },
    /// A bound of the decoder was exceeded.
    #[error("{limit}")]
    Limit {
        /// The instruction's address.
        address: Address,
        /// Which bound.
        limit: Limit,
    },
    /// `inst_next2` was needed while the instruction was being resolved.
    #[error("inst_next2 not available in this context")]
    Next2Unavailable {
        /// The instruction's address.
        address: Address,
    },
    /// A varnode-list operand prints an index past its table (Ghidra
    /// `VarnodeListSymbol::print`).
    #[error("Value out of range for varnode table")]
    VarnodeListRange {
        /// The instruction's address.
        address: Address,
    },
    /// A handle template names a space through something that is not one
    /// (Ghidra `ConstTpl::fixSpace`).
    #[error("ConstTpl is not a spaceid as expected")]
    NotASpace {
        /// The instruction's address.
        address: Address,
    },
    /// The address is not a multiple of the language's alignment (from
    /// [`Decoder::prepare`](crate::Decoder::prepare)).
    #[error("Instruction address not aligned: {}", at.raw())]
    Unaligned {
        /// The instruction's address.
        address: Address,
        /// The address as text.
        at: RawText,
    },
    /// The model refers to something it does not have. A model that passed
    /// `bk-sla`'s validation never does this; it is reported, not panicked.
    #[error("malformed language model: {what}")]
    Model {
        /// The instruction's address.
        address: Address,
        /// What was missing.
        what: &'static str,
    },
}

impl DecodeError {
    /// The address of the instruction being decoded.
    pub fn address(&self) -> Address {
        match *self {
            Self::NoConstructor { address, .. }
            | Self::NoTableEntry { address, .. }
            | Self::TooLong { address }
            | Self::DivisionByZero { address }
            | Self::Limit { address, .. }
            | Self::Next2Unavailable { address }
            | Self::VarnodeListRange { address }
            | Self::NotASpace { address }
            | Self::Unaligned { address, .. }
            | Self::Model { address, .. } => address,
        }
    }

    /// The exception class Ghidra throws for this error.
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::NoConstructor { .. }
            | Self::NoTableEntry { .. }
            | Self::TooLong { .. }
            | Self::DivisionByZero { .. } => ErrorClass::BadData,
            Self::Unaligned { .. } => ErrorClass::Unimplemented,
            Self::Limit { .. }
            | Self::Next2Unavailable { .. }
            | Self::VarnodeListRange { .. }
            | Self::NotASpace { .. }
            | Self::Model { .. } => ErrorClass::Lowlevel,
        }
    }
}

/// Why a language could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The registry does not know the language or cannot read its files.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The language has no compiled `.sla` file.
    #[error("language {language} has no compiled .sla file (expected {})", expected.display())]
    MissingSla {
        /// The language.
        language: LanguageId,
        /// Where the file was expected.
        expected: PathBuf,
    },
    /// The `.sla` file is unreadable or invalid.
    #[error("cannot read {}: {source}", path.display())]
    Sla {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: SlaError,
    },
    /// The model's address spaces cannot be built.
    #[error("address spaces: {0}")]
    Spaces(#[from] SlaError),
    /// An address-space operation failed (truncation, ranges).
    #[error(transparent)]
    Space(#[from] SpaceError),
    /// Two register symbols occupy the same varnode (Ghidra "Duplicate
    /// register pairs").
    #[error("Duplicate register pairs: {first} and {second}")]
    DuplicateRegister {
        /// The symbol registered first.
        first: String,
        /// The symbol registered second.
        second: String,
    },
    /// A context variable straddles two words.
    #[error("Context variable does not fit in one word: {0}")]
    ContextVariableTooWide(String),
    /// A context setting names a variable the language does not have.
    #[error("Non-existent context variable: {0}")]
    UnknownContextVariable(String),
    /// A tracked setting names a register the language does not have.
    #[error("Unknown register name: {0}")]
    UnknownRegister(String),
    /// A processor-specification range names an unknown space or has bad
    /// bounds.
    #[error("bad <context_data> range: space {space}")]
    BadRange {
        /// The space named.
        space: String,
    },
}
