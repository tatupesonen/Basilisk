//! The typed content of a `.ldefs` file.

use std::fmt;

use crate::{
    endian::Endian,
    id::{CompilerSpecId, LanguageId},
};

/// The content of one `.ldefs` file: its `<language>` entries in file
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LanguageDefinitions {
    /// The languages, in file order.
    pub languages: Vec<LanguageDefinition>,
}

/// The version of a language: `major.minor`.
///
/// Ghidra stores both numbers with a program. A program whose major
/// version is older than the language's needs a language upgrade; a
/// difference in the minor version alone only needs re-disassembly.
/// Versions order by major, then minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LanguageVersion {
    /// The major version.
    pub major: u32,
    /// The minor version; `0` when the file gives only a major version.
    pub minor: u32,
}

impl LanguageVersion {
    /// Parses a `version` attribute as Ghidra does: split at `.`, decode
    /// the first piece as the major and the second, if any, as the minor
    /// version (each may be decimal, `0x` hexadecimal or `0` octal); further
    /// pieces are ignored.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        // Java's `String.split` drops trailing empty pieces: "1." is "1".
        let mut pieces = text.trim_end_matches('.').split('.');
        let part =
            |piece: &str| crate::value::decode_i32(piece).and_then(|v| u32::try_from(v).ok());
        let major = part(pieces.next()?)?;
        let minor = match pieces.next() {
            Some(piece) => part(piece)?,
            None => 0,
        };
        Some(Self { major, minor })
    }
}

impl fmt::Display for LanguageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// An address space whose addresses a language truncates to fewer bytes
/// than its SLEIGH spec declares (`<truncate_space>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedSpace {
    /// The address space's name.
    pub space: String,
    /// The truncated address size in bytes.
    pub size: u32,
}

/// One compiler specification a language can be used with (`<compiler>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerDefinition {
    /// The id loaders and opinions use (`gcc`, `windows`).
    pub id: CompilerSpecId,
    /// The name shown to users.
    pub name: String,
    /// The `.cspec` file name, relative to the `.ldefs` file's directory.
    pub spec: String,
}

/// The name another tool uses for a language (`<external_name>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalName {
    /// The tool (`gnu`, `IDA-PRO`, `DWARF.register.mapping.file`, …).
    pub tool: String,
    /// The tool's name for the language.
    pub name: String,
}

/// One `<language>` entry, as written (file names are not resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageDefinition {
    /// The language id.
    pub id: LanguageId,
    /// The processor family name.
    pub processor: String,
    /// The byte order of data.
    pub endian: Endian,
    /// The byte order of instructions; equal to [`endian`](Self::endian)
    /// unless the entry has `instructionEndian`.
    pub instruction_endian: Endian,
    /// The size of an address in bits.
    pub size: u32,
    /// The processor variant.
    pub variant: String,
    /// The language version.
    pub version: LanguageVersion,
    /// The compiled SLEIGH file name (`x86-64.sla`); the source is the
    /// `.slaspec` with the same stem.
    pub sla_file: String,
    /// The processor specification file name (`x86-64.pspec`).
    pub processor_spec: String,
    /// The processor manual index file name, if any.
    pub manual_index_file: Option<String>,
    /// Whether the language is kept only for programs that already use it.
    pub deprecated: bool,
    /// Whether the language is offered only in a development environment.
    pub hidden: bool,
    /// The description text, untrimmed.
    pub description: String,
    /// Address-space truncations.
    pub truncated_spaces: Vec<TruncatedSpace>,
    /// The compiler specs; the first is the language's default. Ids are
    /// unique: a repeated id replaces the earlier entry in its place.
    pub compilers: Vec<CompilerDefinition>,
    /// Names other tools use for the language, in file order.
    pub external_names: Vec<ExternalName>,
}

impl LanguageDefinition {
    /// The names `tool` uses for this language, in file order.
    pub fn external_names_for<'a>(&'a self, tool: &'a str) -> impl Iterator<Item = &'a str> {
        self.external_names
            .iter()
            .filter(move |e| e.tool == tool)
            .map(|e| e.name.as_str())
    }
}
