//! [`ElfFile`]: a parsed ELF file together with the bytes it was parsed
//! from, and the reads that are done on demand.

use std::borrow::Cow;
use std::ops::Deref;

use bk_bin::{BinaryReader, ByteProvider, SubProvider, UnlimitedProvider};

use crate::compress::{self, Decompressed};
use crate::constants::{DynamicTag, SHN_LORESERVE, SHN_XINDEX};
use crate::diag::Diagnostic;
use crate::error::ElfError;
use crate::parse;
use crate::program_header::ProgramHeader;
use crate::reloc::{RelocationIter, RelocationLayout, RelocationTable};
use crate::section_header::SectionHeader;
use crate::strtab::StringTable;
use crate::symbol::{FORMATTED_NO_NAME, Symbol, SymbolIter, SymbolTable};
use crate::tables::ElfTables;

/// A parsed ELF file (Ghidra's `ElfHeader` after `parse()`).
///
/// Opening a file parses the header, the program and section headers, the
/// dynamic table and the descriptors of the string, symbol and relocation
/// tables ([`ElfTables`], which this type dereferences to). Names, symbols,
/// relocations and section contents are read from the provider when they are
/// asked for, so opening a large file is cheap and nothing is copied that is
/// not used.
///
/// `P` is any [`ByteProvider`]: a borrowed one (`&MemoryProvider<&[u8]>`)
/// for a file in memory, or an owned one (`Arc<dyn ByteProvider>`,
/// `FileProvider`) when the parsed file must not borrow.
///
/// ```
/// use bk_bin::MemoryProvider;
/// use bk_elf::{ElfError, ElfFile};
///
/// let bytes = b"\x7fELF but nothing else";
/// let provider = MemoryProvider::new(&bytes[..]);
/// match ElfFile::parse(&provider) {
///     Ok(elf) => {
///         for section in elf.sections() {
///             let _name = elf.section_name(section);
///         }
///         let _problems = elf.diagnostics();
///     }
///     Err(error) => assert!(matches!(error, ElfError::UnsupportedClass { .. })),
/// }
/// ```
#[derive(Debug)]
pub struct ElfFile<P> {
    provider: UnlimitedProvider<P>,
    tables: ElfTables,
}

impl<P> Deref for ElfFile<P> {
    type Target = ElfTables;

    fn deref(&self) -> &ElfTables {
        &self.tables
    }
}

impl<P: ByteProvider> ElfFile<P> {
    /// Parses the file behind `provider`.
    ///
    /// A file that is not ELF at all, or that Ghidra also refuses (an
    /// unknown class, a wrong header-table entry size with no other table to
    /// fall back on), is an [`ElfError`]. Everything Ghidra tolerates is
    /// reported in [`diagnostics`](ElfTables::diagnostics).
    pub fn parse(provider: P) -> Result<Self, ElfError> {
        let provider = UnlimitedProvider::new(provider);
        let tables = parse::parse(&provider, provider.inner())?;
        Ok(Self { provider, tables })
    }

    /// The provider the file was parsed from.
    pub fn provider(&self) -> &P {
        self.provider.inner()
    }

    /// The eagerly parsed tables.
    pub fn tables(&self) -> &ElfTables {
        &self.tables
    }

    /// A reader over the file in which reads past the end yield zeros, in
    /// the byte order of the headers (Ghidra's `ElfHeader.getReader`). This
    /// is how Ghidra reads headers, symbols, strings and hash tables.
    pub fn reader(&self) -> BinaryReader<'_> {
        BinaryReader::new(&self.provider, self.tables.header.header_endian)
    }

    /// A reader over the file itself, in the byte order of the headers. This
    /// is how Ghidra reads relocation tables, where the end of the file must
    /// end the table.
    pub fn raw_reader(&self) -> BinaryReader<'_> {
        BinaryReader::new(self.provider.inner(), self.tables.header.header_endian)
    }

    // ---- names ----------------------------------------------------------------

    /// The name of `section`: the string at `sh_name` in the section-name
    /// string table, or `SECTION<index>` when it cannot be read or is empty
    /// (Ghidra's `getNameAsString`).
    pub fn section_name(&self, section: &SectionHeader) -> Cow<'_, str> {
        parse::section_name(&self.reader(), &self.tables, section)
    }

    /// The first section named `name`.
    ///
    /// Ghidra's `getSection(String)` throws when two sections share the
    /// name; this returns the first.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        let reader = self.reader();
        self.tables
            .sections
            .iter()
            .find(|s| parse::section_name_is(&reader, &self.tables, s, name))
    }

    /// Reads the string at `offset` in `table` (Ghidra's
    /// `ElfStringTable.readString`): the offset must lie inside the table;
    /// the string runs to its terminator, is decoded as UTF-8 and trimmed.
    /// On failure the result is the diagnostic Ghidra logs.
    pub fn string(&self, table: &StringTable, offset: u64) -> Result<Cow<'_, str>, Diagnostic> {
        table.read(&self.reader(), offset)
    }

    /// The names of the libraries the file needs (`DT_NEEDED`), in order.
    /// A name that cannot be read is `UNK_LIB_NAME_<i>`, as in Ghidra.
    pub fn dynamic_library_names(&self) -> impl Iterator<Item = Cow<'_, str>> + '_ {
        let strings = self.dynamic_string_table();
        self.dynamic_table()
            .into_iter()
            .flat_map(|d| d.entries_with(DynamicTag::DT_NEEDED))
            .enumerate()
            .map(move |(i, entry)| {
                strings
                    .and_then(|t| self.string(t, entry.value).ok())
                    .unwrap_or_else(|| Cow::Owned(format!("UNK_LIB_NAME_{i}")))
            })
    }

    // ---- symbols ----------------------------------------------------------------

    /// The symbols of `table`, decoded from the file as the iterator goes.
    pub fn symbols(&self, table: &SymbolTable) -> SymbolIter<'_> {
        SymbolIter::new(self.reader(), self.tables.header.class, table)
    }

    /// The symbol with index `index` in `table`.
    pub fn symbol(&self, table: &SymbolTable, index: u32) -> Option<Symbol> {
        self.symbols(table).get(index)
    }

    /// The name of `symbol` from `table` (Ghidra's `getNameAsString`).
    ///
    /// A section symbol (`STT_SECTION`) with `st_name` 0 is named after its
    /// section. Otherwise the name is read from the table's string table:
    /// `Ok(None)` when the table has none, `Err` with Ghidra's message when
    /// the offset is outside it.
    pub fn symbol_name(
        &self,
        table: &SymbolTable,
        symbol: &Symbol,
    ) -> Result<Option<Cow<'_, str>>, Diagnostic> {
        if symbol.st_name == 0
            && symbol.is_section()
            && symbol.st_shndx < SHN_LORESERVE
            && let Some(section) = self.section(u32::from(symbol.st_shndx))
        {
            return Ok(Some(self.section_name(section)));
        }
        let Some(strings) = table.string_table.and_then(|i| self.string_tables.get(i)) else {
            return Ok(None);
        };
        self.string(strings, u64::from(symbol.st_name)).map(Some)
    }

    /// The name of `symbol` for display (Ghidra's `getFormattedName`): its
    /// name, or `<no name>` when it is blank or cannot be read.
    pub fn formatted_symbol_name(&self, table: &SymbolTable, symbol: &Symbol) -> Cow<'_, str> {
        match self.symbol_name(table, symbol) {
            Ok(Some(name)) if !name.trim().is_empty() => name,
            _ => Cow::Borrowed(FORMATTED_NO_NAME),
        }
    }

    /// The real section index of a symbol whose `st_shndx` is `SHN_XINDEX`,
    /// from the table's `SHT_SYMTAB_SHNDX` section (Ghidra's
    /// `getExtendedSectionIndex`); 0 when there is none.
    pub fn extended_section_index(&self, table: &SymbolTable, symbol: &Symbol) -> u32 {
        let Some(indexes) = table.section_index_table else {
            return 0;
        };
        if symbol.st_shndx != SHN_XINDEX || symbol.index >= indexes.count {
            return 0;
        }
        let offset = indexes
            .file_offset
            .saturating_add(u64::from(symbol.index) * 4);
        self.reader().read_u32_at(offset).unwrap_or(0)
    }

    // ---- relocations --------------------------------------------------------------

    /// How `r_info` is split for this file: by class, and MIPS-64's own
    /// layout when the MIPS extension applies.
    pub fn relocation_layout(&self) -> RelocationLayout {
        let header = &self.tables.header;
        let mips64 = self
            .tables
            .extension
            .is_some_and(|e| e.uses_mips64_relocations(header.class));
        RelocationLayout::for_file(header.class, mips64, header.data_endian())
    }

    /// The relocations of `table`, decoded from the file as the iterator
    /// goes. Entries that are not wholly inside the file are not produced.
    pub fn relocations(&self, table: &RelocationTable) -> RelocationIter<'_> {
        table.iter(
            self.raw_reader(),
            self.tables.header.class,
            self.relocation_layout(),
        )
    }

    // ---- contents -------------------------------------------------------------------

    /// The bytes of `section` that are inside the file: none for
    /// `SHT_NOBITS` or an invalid offset, otherwise `sh_size` bytes at
    /// `sh_offset`, cut at the end of the file. Borrowed when the provider
    /// is in memory.
    ///
    /// Ghidra reads past the end of the file as zeros;
    /// [`section_provider`](Self::section_provider) gives that view.
    pub fn section_data(&self, section: &SectionHeader) -> bk_bin::Result<Cow<'_, [u8]>> {
        if section.is_no_bits() || section.is_invalid_offset() {
            return Ok(Cow::Borrowed(&[]));
        }
        self.file_bytes(section.sh_offset, section.sh_size)
    }

    /// The section's data as Ghidra sees it: `sh_size` bytes at
    /// `sh_offset`, reading as zeros past the end of the file; empty for
    /// `SHT_NOBITS`.
    pub fn section_provider(&self, section: &SectionHeader) -> SubProvider<&UnlimitedProvider<P>> {
        let len = if section.is_no_bits() {
            0
        } else {
            section.sh_size
        };
        SubProvider::new(&self.provider, section.sh_offset, len)
    }

    /// Decompresses a compressed section (`SHF_COMPRESSED` with a supported
    /// algorithm); `None` for a section that is not compressed.
    ///
    /// The result holds what could be inflated and, when that is less than
    /// `ch_size`, why. Memory is bounded by a fixed multiple of the section's
    /// size in the file.
    pub fn decompress_section(&self, section: &SectionHeader) -> Option<Decompressed> {
        let header = section.compression?;
        let skip = u64::from(header.header_size);
        let data = match self.file_bytes(
            section.sh_offset.saturating_add(skip),
            section.sh_size.saturating_sub(skip),
        ) {
            Ok(data) => data,
            Err(error) => {
                return Some(Decompressed {
                    data: Vec::new(),
                    error: Some(error.to_string()),
                });
            }
        };
        Some(compress::inflate(&data, header.ch_size))
    }

    /// The bytes of `segment` that are inside the file: `p_filesz` bytes at
    /// `p_offset`, cut at the end of the file; none for an invalid offset.
    pub fn segment_data(&self, segment: &ProgramHeader) -> bk_bin::Result<Cow<'_, [u8]>> {
        if segment.is_invalid_offset() {
            return Ok(Cow::Borrowed(&[]));
        }
        self.file_bytes(segment.p_offset, segment.p_filesz)
    }

    /// Up to `len` bytes at `offset`, cut at the end of the file.
    fn file_bytes(&self, offset: u64, len: u64) -> bk_bin::Result<Cow<'_, [u8]>> {
        let available = self.tables.file_len.saturating_sub(offset).min(len);
        let len = usize::try_from(available).unwrap_or(usize::MAX);
        self.raw_reader().read_bytes_at(offset, len)
    }
}
