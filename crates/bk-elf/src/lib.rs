//! A tolerant ELF parser that exposes everything Ghidra's ELF loader needs.
//!
//! This crate corresponds to Ghidra's `ghidra.app.util.bin.format.elf`
//! package (`ElfHeader`, `ElfProgramHeader`, `ElfSectionHeader`,
//! `ElfStringTable`, `ElfSymbol`, `ElfSymbolTable`, `ElfDynamic`,
//! `ElfDynamicTable`, `ElfRelocation`, `ElfRelocationTable`, …) and to the
//! file-format parts of the per-processor `ElfExtension` classes. It knows
//! nothing about programs: loading is a later crate.
//!
//! **Status: work in progress (handover).** The building blocks below exist
//! and are unit-tested; the parser that ties them together is only partly
//! written and there is no public `ElfFile` type yet. See
//! `docs/agents/bin-elf.md`.
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
pub use header::{ElfClass, ElfHeader};
pub use machine::MachineExtension;
pub use program_header::ProgramHeader;
pub use reloc::{Relocation, RelocationFormat, RelocationIter, RelocationLayout, RelocationTable};
pub use section_header::SectionHeader;
pub use strtab::StringTable;
pub use symbol::{Symbol, SymbolIter, SymbolTable};
pub use tables::ElfTables;

/// Parses the eagerly read part of an ELF file: the header, the program
/// and section headers, the dynamic table and the string table descriptors.
///
/// **Handover state:** symbol and relocation tables are not located yet, so
/// [`ElfTables::symbol_tables`] and [`ElfTables::relocation_tables`] are
/// always empty, and this function is a temporary entry point: the plan is
/// an `ElfFile<P>` type that owns the provider, dereferences to
/// [`ElfTables`] and adds the lazy reads (names, symbols, relocations).
///
/// A file that is not ELF at all is an [`ElfError`]; everything Ghidra
/// tolerates is in [`ElfTables::diagnostics`].
pub fn parse_tables(provider: &dyn bk_bin::ByteProvider) -> Result<ElfTables, ElfError> {
    let unlimited = bk_bin::UnlimitedProvider::new(provider);
    parse::parse(&unlimited, provider)
}
