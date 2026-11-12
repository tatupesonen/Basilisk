//! Everything that is parsed when a file is opened: the header, the header
//! tables, the dynamic table and the descriptors of the string, symbol and
//! relocation tables — and the lookups over them that need no further I/O.

use std::borrow::Cow;

use crate::constants::{DynamicTag, DynamicTagInfo, SectionType, SegmentType};
use crate::diag::Diagnostic;
use crate::dynamic::DynamicTable;
use crate::header::ElfHeader;
use crate::machine::MachineExtension;
use crate::program_header::ProgramHeader;
use crate::reloc::RelocationTable;
use crate::section_header::SectionHeader;
use crate::strtab::StringTable;
use crate::symbol::SymbolTable;

/// Number of program headers Ghidra looks at to find the image base.
const MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE: usize = 20;

/// The eagerly parsed part of an ELF file.
///
/// [`ElfFile`](crate::ElfFile) dereferences to this, so these methods are
/// available on it directly; what needs to read more of the file (names,
/// symbols, relocations, section contents) is on `ElfFile` itself.
///
/// Address comparisons follow Ghidra, which holds addresses in signed
/// 64-bit values: a range that straddles 2⁶³ does not contain what an
/// unsigned comparison would say it does.
#[derive(Debug, Clone)]
pub struct ElfTables {
    pub(crate) header: ElfHeader,
    pub(crate) extension: Option<&'static MachineExtension>,
    pub(crate) prelink_base: Option<u32>,
    pub(crate) file_len: u64,
    pub(crate) program_headers: Vec<ProgramHeader>,
    pub(crate) sections: Vec<SectionHeader>,
    pub(crate) dynamic_table: Option<DynamicTable>,
    pub(crate) string_tables: Vec<StringTable>,
    pub(crate) dynamic_string_table: Option<usize>,
    pub(crate) symbol_tables: Vec<SymbolTable>,
    pub(crate) dynamic_symbol_table: Option<usize>,
    pub(crate) relocation_tables: Vec<RelocationTable>,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl ElfTables {
    /// The ELF header.
    pub fn header(&self) -> &ElfHeader {
        &self.header
    }

    /// The processor extension Ghidra would select for this file, if any:
    /// processor-specific type names and parsing hooks.
    pub fn extension(&self) -> Option<&'static MachineExtension> {
        self.extension
    }

    /// Length of the file in bytes.
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// The problems found while parsing that did not stop it, in the order
    /// Ghidra reports them.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The program headers, in file order.
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers
    }

    /// The program headers of type `segment_type`, in file order.
    pub fn program_headers_of_type(
        &self,
        segment_type: SegmentType,
    ) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers
            .iter()
            .filter(move |h| h.p_type == segment_type)
    }

    /// The section headers, in file order.
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// The section header with index `index`.
    pub fn section(&self, index: u32) -> Option<&SectionHeader> {
        self.sections.get(index as usize)
    }

    /// The section headers of type `section_type`, in file order.
    pub fn sections_of_type(
        &self,
        section_type: SectionType,
    ) -> impl Iterator<Item = &SectionHeader> {
        self.sections
            .iter()
            .filter(move |s| s.sh_type == section_type)
    }

    /// The dynamic table, if the file has one that could be located.
    pub fn dynamic_table(&self) -> Option<&DynamicTable> {
        self.dynamic_table.as_ref()
    }

    /// The string tables: one per `SHT_STRTAB` section, then the dynamic
    /// string table if it was located only through `DT_STRTAB`.
    pub fn string_tables(&self) -> &[StringTable] {
        &self.string_tables
    }

    /// The dynamic string table (`DT_STRTAB`).
    pub fn dynamic_string_table(&self) -> Option<&StringTable> {
        self.string_tables.get(self.dynamic_string_table?)
    }

    /// The string table whose data is the section with index `section`
    /// (Ghidra's `getStringTable`: matched by file offset).
    pub fn string_table_for_section(&self, section: u32) -> Option<&StringTable> {
        self.string_tables
            .get(self.string_table_index_for_section(section)?)
    }

    pub(crate) fn string_table_index_for_section(&self, section: u32) -> Option<usize> {
        let offset = self.section(section)?.sh_offset;
        self.string_tables
            .iter()
            .position(|t| t.file_offset == offset)
    }

    /// The symbol tables: one per `SHT_SYMTAB` or `SHT_DYNSYM` section, then
    /// the dynamic symbol table if it was located only through `DT_SYMTAB`.
    pub fn symbol_tables(&self) -> &[SymbolTable] {
        &self.symbol_tables
    }

    /// The dynamic symbol table (`DT_SYMTAB`).
    pub fn dynamic_symbol_table(&self) -> Option<&SymbolTable> {
        self.symbol_tables.get(self.dynamic_symbol_table?)
    }

    /// The symbol table whose data is the section with index `section`
    /// (Ghidra's `getSymbolTable`: matched by file offset).
    pub fn symbol_table_for_section(&self, section: u32) -> Option<&SymbolTable> {
        self.symbol_tables
            .get(self.symbol_table_index_for_section(section)?)
    }

    pub(crate) fn symbol_table_index_for_section(&self, section: u32) -> Option<usize> {
        let offset = self.section(section)?.sh_offset;
        self.symbol_tables
            .iter()
            .position(|t| t.file_offset == offset)
    }

    /// The relocation tables, in the order Ghidra processes them: those
    /// named by the dynamic table first (`DT_REL`, `DT_RELA`, `DT_JMPREL`,
    /// the Android tables, `DT_RELR`), then the remaining relocation sections.
    pub fn relocation_tables(&self) -> &[RelocationTable] {
        &self.relocation_tables
    }

    /// The relocation table at file offset `file_offset`.
    pub fn relocation_table_at_offset(&self, file_offset: u64) -> Option<&RelocationTable> {
        self.relocation_tables
            .iter()
            .find(|t| t.file_offset == file_offset)
    }

    /// The relocation table whose data is the section with index `section`.
    pub fn relocation_table_for_section(&self, section: u32) -> Option<&RelocationTable> {
        self.relocation_table_at_offset(self.section(section)?.sh_offset)
    }

    // ---- prelink and addresses -------------------------------------------

    /// The image base recorded by `prelink` in the last eight bytes of the
    /// file (a 32-bit base followed by `PRE`), if the file has that trailer.
    pub fn prelink_base(&self) -> Option<u32> {
        self.prelink_base
    }

    /// True when the file has a prelink trailer or a `DT_GNU_PRELINKED` entry.
    pub fn is_prelinked(&self) -> bool {
        self.prelink_base.is_some()
            || self
                .dynamic_table
                .as_ref()
                .is_some_and(|d| d.contains(DynamicTag::DT_GNU_PRELINKED))
    }

    /// Adds the prelink base, if any, to `address`.
    pub fn adjust_address_for_prelink(&self, address: u64) -> u64 {
        u64::from(self.prelink_base.unwrap_or(0)).wrapping_add(address)
    }

    /// Subtracts the prelink base, if any, from `address`.
    pub fn unadjust_address_for_prelink(&self, address: u64) -> u64 {
        address.wrapping_sub(u64::from(self.prelink_base.unwrap_or(0)))
    }

    /// The entry point: `e_entry` adjusted for prelinking, or 0 if the file
    /// has none.
    pub fn entry(&self) -> u64 {
        match self.header.e_entry {
            0 => 0,
            entry => self.adjust_address_for_prelink(entry),
        }
    }

    /// The lowest virtual address of the first 20 `PT_LOAD` headers, or 0
    /// (Ghidra's `findImageBase`). In a 32-bit file addresses are cut to 32 bits.
    pub fn find_image_base(&self) -> u64 {
        self.program_headers
            .iter()
            .take(MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE)
            .filter(|h| h.p_type == SegmentType::PT_LOAD)
            .map(|h| match self.header.is_32bit() {
                true => u64::from(h.virtual_address() as u32),
                false => h.virtual_address(),
            })
            .min()
            .unwrap_or(0)
    }

    /// The image base: the prelink base if the file has one, the lowest
    /// `PT_LOAD` address otherwise (Ghidra's `getImageBase`).
    pub fn image_base(&self) -> u64 {
        self.prelink_base
            .map_or_else(|| self.find_image_base(), u64::from)
    }

    // ---- lookups ------------------------------------------------------------

    /// The allocated section whose address is exactly `address`.
    pub fn section_at(&self, address: u64) -> Option<&SectionHeader> {
        self.sections
            .iter()
            .find(|s| s.is_alloc() && s.address() == address)
    }

    /// The first allocated section whose address range contains `address`.
    pub fn section_load_header_containing(&self, address: u64) -> Option<&SectionHeader> {
        let address = address as i64;
        self.sections.iter().find(|s| {
            let start = s.address() as i64;
            let end = start.wrapping_add(s.sh_size as i64);
            s.is_alloc() && start <= address && address < end
        })
    }

    /// The first section whose data in the file contains the range of
    /// `length` bytes at `file_offset`.
    pub fn section_header_containing_file_range(
        &self,
        file_offset: u64,
        length: u64,
    ) -> Option<&SectionHeader> {
        let first = file_offset as i64;
        let last = first.wrapping_add(length as i64).wrapping_sub(1);
        self.sections.iter().find(|s| {
            if s.sh_type == SectionType::SHT_NULL || s.is_invalid_offset() || s.sh_size == 0 {
                return false;
            }
            let start = s.sh_offset as i64;
            let end = start.wrapping_add(s.sh_size as i64).wrapping_sub(1);
            first >= start && last <= end
        })
    }

    /// True when a `PT_LOAD` segment's memory range contains the whole
    /// section (Ghidra's `isSectionLoaded`).
    pub fn is_section_loaded(&self, section: &SectionHeader) -> bool {
        let start = section.address() as i64;
        if section.sh_type == SectionType::SHT_NULL || start == 0 {
            return false;
        }
        let end = (section.sh_size as i64).wrapping_sub(1).wrapping_add(start);
        self.program_headers_of_type(SegmentType::PT_LOAD)
            .any(|segment| {
                let segment_start = segment.virtual_address() as i64;
                let segment_end = (segment.p_memsz as i64)
                    .wrapping_sub(1)
                    .wrapping_add(segment_start);
                segment_start <= start && segment_end >= end
            })
    }

    /// The `PT_PHDR` header, if the file has exactly one.
    pub fn program_header_program_header(&self) -> Option<&ProgramHeader> {
        let mut headers = self.program_headers_of_type(SegmentType::PT_PHDR);
        let first = headers.next()?;
        headers.next().is_none().then_some(first)
    }

    /// The `PT_LOAD` header whose virtual address is exactly `virtual_address`.
    pub fn program_header_at(&self, virtual_address: u64) -> Option<&ProgramHeader> {
        self.program_headers_of_type(SegmentType::PT_LOAD)
            .find(|h| h.virtual_address() == virtual_address)
    }

    /// The first `PT_LOAD` header whose memory range contains
    /// `virtual_address`. This is how Ghidra turns addresses from the
    /// dynamic table into file offsets when section headers are missing.
    pub fn program_load_header_containing(&self, virtual_address: u64) -> Option<&ProgramHeader> {
        let address = virtual_address as i64;
        self.program_headers_of_type(SegmentType::PT_LOAD)
            .find(|h| {
                let start = h.virtual_address() as i64;
                let size = h.adjusted_memory_size(self.extension) as i64;
                let end = size.wrapping_sub(1).wrapping_add(start);
                address >= start && address <= end
            })
    }

    /// The first `PT_LOAD` header whose data in the file contains `file_offset`.
    pub fn program_load_header_containing_file_offset(
        &self,
        file_offset: u64,
    ) -> Option<&ProgramHeader> {
        let offset = file_offset as i64;
        self.program_headers_of_type(SegmentType::PT_LOAD)
            .find(|h| {
                let start = h.p_offset as i64;
                let end = start.wrapping_add((h.p_filesz as i64).wrapping_sub(1));
                !h.is_invalid_offset() && offset >= start && offset <= end
            })
    }

    // ---- names --------------------------------------------------------------

    /// The name of a segment type for this file's processor, or `PT_0x%08x`.
    pub fn segment_type_name(&self, segment_type: SegmentType) -> Cow<'static, str> {
        segment_type.name(self.extension)
    }

    /// Ghidra's comment for a program header: the type name, followed by
    /// " - " and the type's description when it has one.
    pub fn segment_comment(&self, header: &ProgramHeader) -> String {
        let name = self.segment_type_name(header.p_type);
        match header.p_type.info(self.extension).map(|i| i.description) {
            Some(description) if !description.is_empty() => format!("{name} - {description}"),
            _ => name.into_owned(),
        }
    }

    /// The name of a section type for this file's processor, or `SHT_0x%08x`.
    pub fn section_type_name(&self, section_type: SectionType) -> Cow<'static, str> {
        section_type.name(self.extension)
    }

    /// The name of a dynamic tag for this file's processor, or `DT_0x%08x`.
    pub fn dynamic_tag_name(&self, tag: DynamicTag) -> Cow<'static, str> {
        tag.name(self.extension)
    }

    /// The table row of a dynamic tag for this file's processor: name,
    /// description and how its value is to be read.
    pub fn dynamic_tag_info(&self, tag: DynamicTag) -> Option<&'static DynamicTagInfo> {
        tag.info(self.extension)
    }
}
