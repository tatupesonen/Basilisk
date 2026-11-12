//! A tolerant ELF parser that exposes everything Ghidra's ELF loader needs.
//!
//! This crate corresponds to Ghidra's `ghidra.app.util.bin.format.elf`
//! package (`ElfHeader`, `ElfProgramHeader`, `ElfSectionHeader`,
//! `ElfStringTable`, `ElfSymbol`, `ElfSymbolTable`, `ElfDynamic`,
//! `ElfDynamicTable`, `ElfRelocation`, `ElfRelocationTable`, …) and to the
//! file-format parts of the per-processor `ElfExtension` classes. It knows
//! nothing about programs: loading is a later crate.
//!
//! [`ElfFile::parse`] is the entry point: it parses what Ghidra's
//! `ElfHeader.parse()` parses, returns the problems Ghidra would log as
//! [`Diagnostic`]s next to the result, and reads names, symbols,
//! relocations and section contents on demand.
//!
//! * [`constants`] — identification values, machines, section and segment
//!   types, dynamic tags, with Ghidra's names (generated from its sources);
//! * [`machine`] — processor-specific types and parsing hooks;
//! * [`ElfHeader`], [`ProgramHeader`], [`SectionHeader`] — the header and
//!   the header tables, one struct per concept with 64-bit fields;
//! * [`StringTable`], [`SymbolTable`], [`Symbol`], [`DynamicTable`],
//!   [`RelocationTable`], [`Relocation`] — table descriptors and entries;
//! * [`Diagnostic`] — what Ghidra logs while it carries on with a damaged
//!   file; [`ElfError`] — the few cases in which it gives up.

pub mod compress;
pub mod constants;
mod diag;
pub mod dynamic;
mod error;
mod file;
mod header;
mod limits;
pub mod machine;
mod parse;
mod program_header;
pub mod reloc;
mod section_header;
mod strtab;
pub mod symbol;
pub mod symbol_name;
mod tables;

pub use constants::{
    DynamicTag, DynamicTagInfo, DynamicValueKind, ElfType, Machine, OsAbi, SectionType,
    SegmentType, TypeInfo,
};
pub use diag::{Diagnostic, DiagnosticKind};
pub use dynamic::{DynamicEntry, DynamicTable};
pub use error::ElfError;
pub use file::ElfFile;
pub use header::{ElfClass, ElfHeader};
pub use machine::MachineExtension;
pub use program_header::ProgramHeader;
pub use reloc::{Relocation, RelocationFormat, RelocationIter, RelocationLayout, RelocationTable};
pub use section_header::SectionHeader;
pub use strtab::StringTable;
pub use symbol::{Symbol, SymbolIter, SymbolTable};
pub use tables::ElfTables;
