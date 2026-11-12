//! Locating the relocation tables (Ghidra's `parseRelocationTables`,
//! `parseDynamicRelocTable`, `parseJMPRelocTable`,
//! `parseSectionBasedRelocationTable` and the `ElfRelocationTable`
//! constructor).

use crate::constants::{DynamicTag, FILE_OFFSET_HARD_LIMIT, SectionType};
use crate::diag::DiagnosticKind;
use crate::limits::{constrain_count, hard_limit, has_fragment, is_negative};
use crate::parse::Parser;
use crate::parse::symbols::DOT_DYNSYM;
use crate::reloc::{RelocationFormat, RelocationTable, scan_android};

/// `DT_PLTREL`'s value when the PLT relocations are `RELA`.
const PLTREL_RELA: u64 = 7;

/// What is known about a table before it is read.
struct TableSpec {
    format: RelocationFormat,
    section: Option<u32>,
    section_link: Option<u32>,
    section_to_relocate: Option<u32>,
    file_offset: u64,
    address: u64,
    length: u64,
    /// The entry size the file gives; `None` where Ghidra passes -1 (no
    /// entry-size tag for this table).
    entry_size: Option<u64>,
    has_addend: bool,
    symbol_table: Option<usize>,
}

/// The relocation format a section type stands for, if it is a relocation
/// section at all.
fn section_format(section_type: SectionType) -> Option<RelocationFormat> {
    match section_type {
        SectionType::SHT_REL | SectionType::SHT_RELA => Some(RelocationFormat::Default),
        SectionType::SHT_ANDROID_REL | SectionType::SHT_ANDROID_RELA => {
            Some(RelocationFormat::Android)
        }
        SectionType::SHT_RELR | SectionType::SHT_ANDROID_RELR => Some(RelocationFormat::Relr),
        _ => None,
    }
}

/// Ghidra's `ElfDynamicType.toString`: `NAME(0x%08x)`.
fn tag_display(name: &str, tag: DynamicTag) -> String {
    format!("{name}(0x{:08x})", tag.0)
}

impl Parser<'_> {
    /// Ghidra's `parseRelocationTables`. The order matters: a table found
    /// twice is kept where it was found first, and Ghidra applies the
    /// tables in this order (PLT relocations late).
    pub(super) fn parse_relocation_tables(&mut self) {
        use DynamicTag as T;
        self.parse_dynamic_reloc_table(T::DT_REL, Some(T::DT_RELENT), T::DT_RELSZ, false);
        self.parse_dynamic_reloc_table(T::DT_RELA, Some(T::DT_RELAENT), T::DT_RELASZ, true);
        if let Some(pltrel) = self.dynamic_value(T::DT_PLTREL) {
            let rela = pltrel == PLTREL_RELA;
            self.parse_dynamic_reloc_table(T::DT_JMPREL, None, T::DT_PLTRELSZ, rela);
        }
        self.parse_dynamic_reloc_table(T::DT_ANDROID_REL, None, T::DT_ANDROID_RELSZ, false);
        self.parse_dynamic_reloc_table(T::DT_ANDROID_RELA, None, T::DT_ANDROID_RELASZ, true);
        self.parse_dynamic_reloc_table(T::DT_RELR, Some(T::DT_RELRENT), T::DT_RELRSZ, false);
        self.parse_dynamic_reloc_table(
            T::DT_ANDROID_RELR,
            Some(T::DT_ANDROID_RELRENT),
            T::DT_ANDROID_RELRSZ,
            false,
        );
        // parseJMPRelocTable: the PLT table again, now with an entry size.
        if let Some(pltrel) = self.dynamic_value(T::DT_PLTREL) {
            let rela = pltrel == PLTREL_RELA;
            let entry_tag = if rela { T::DT_RELAENT } else { T::DT_RELENT };
            self.parse_dynamic_reloc_table(T::DT_JMPREL, Some(entry_tag), T::DT_PLTRELSZ, rela);
        }
        for index in 0..self.t.sections.len() {
            // Section counts are below 2³¹.
            self.parse_section_reloc_table(index as u32);
        }
    }

    fn is_table_parsed(&self, file_offset: u64) -> bool {
        self.t
            .relocation_tables
            .iter()
            .any(|t| t.file_offset == file_offset)
    }

    /// Ghidra's `parseDynamicRelocTable`. Missing dynamic entries skip the
    /// table silently, as in Ghidra.
    fn parse_dynamic_reloc_table(
        &mut self,
        address_tag: DynamicTag,
        entry_tag: Option<DynamicTag>,
        size_tag: DynamicTag,
        has_addend: bool,
    ) {
        let Some(raw_address) = self.dynamic_value(address_tag) else {
            return;
        };
        let address = self.t.adjust_address_for_prelink(raw_address);
        if let Some(section) = self.t.section_load_header_containing(address) {
            // A section describes the table: it is handled as a section's
            // table (and ignored if that section is not a relocation section).
            let index = section.index;
            self.parse_section_reloc_table(index);
            return;
        }
        let tag_name = self.t.dynamic_tag_name(address_tag);
        let Some(load) = self.t.program_load_header_containing(address) else {
            self.diag(
                DiagnosticKind::UnlocatedAddress,
                format!("Failed to locate {tag_name} in memory at 0x{address:x}"),
            );
            return;
        };
        if load.is_invalid_offset() {
            return;
        }
        let segment = load.index as usize;
        let Some(offset) = self.offset_in_segment(segment, address, &tag_name) else {
            return;
        };
        if self.is_table_parsed(offset) {
            return;
        }
        if is_negative(offset) || offset > FILE_OFFSET_HARD_LIMIT || offset >= self.t.file_len {
            self.diag(
                DiagnosticKind::RelocationTable,
                format!(
                    "Invalid derived dynamic relocation table file offset: 0x{offset:x}; {}: \
                     0x{address:x}",
                    tag_display(&tag_name, address_tag)
                ),
            );
            return;
        }
        let entry_size = match entry_tag {
            Some(tag) => match self.dynamic_value(tag) {
                Some(size) => Some(size),
                None => return,
            },
            None => None,
        };
        let Some(length) = self.dynamic_value(size_tag) else {
            return;
        };
        if length == 0 || is_negative(length) {
            let size_name = self.t.dynamic_tag_name(size_tag);
            self.diag(
                DiagnosticKind::RelocationTable,
                format!(
                    "Dynamic relocation table has invalid {} (table size): 0x{length:x}",
                    tag_display(&size_name, size_tag)
                ),
            );
            return;
        }
        let format = match address_tag {
            DynamicTag::DT_ANDROID_REL | DynamicTag::DT_ANDROID_RELA => RelocationFormat::Android,
            DynamicTag::DT_RELR | DynamicTag::DT_ANDROID_RELR => RelocationFormat::Relr,
            _ => RelocationFormat::Default,
        };
        let spec = TableSpec {
            format,
            section: None,
            section_link: None,
            section_to_relocate: None,
            file_offset: offset,
            address,
            length,
            entry_size,
            has_addend,
            symbol_table: self.t.dynamic_symbol_table,
        };
        match self.build_relocation_table(spec) {
            Ok(table) => self.t.relocation_tables.push(table),
            Err(message) => self.diag(
                DiagnosticKind::RelocationTable,
                format!("Failed to process relocation table: {message}"),
            ),
        }
    }

    /// Ghidra's `parseSectionBasedRelocationTable` for the section with
    /// index `index`; sections of other types are ignored.
    fn parse_section_reloc_table(&mut self, index: u32) {
        let Some(section) = self.t.section(index).cloned() else {
            return;
        };
        let Some(format) = section_format(section.sh_type) else {
            return;
        };
        if self.is_table_parsed(section.sh_offset) || section.is_invalid_offset() {
            return;
        }
        let name = self.name(&section);
        let length = section.sh_size;
        if length == 0 || is_negative(length) {
            self.diag(
                DiagnosticKind::RelocationTable,
                format!(
                    "Relocation table section header '{name}' has invalid sh_size value (table \
                     size): 0x{length:x}"
                ),
            );
            return;
        }
        let fail = |parser: &mut Self, message: String| {
            parser.diag(
                DiagnosticKind::RelocationTable,
                format!("Failed to process relocation table {name}: {message}"),
            );
        };
        // Java holds both links in an int.
        let (link, info) = (section.sh_link as i32, section.sh_info as i32);
        let section_count = self.t.sections.len();
        let in_range = |i: i32| usize::try_from(i).is_ok_and(|i| i < section_count);
        let section_to_relocate = match info {
            0 => None,
            info if in_range(info) => Some(info as u32),
            info => return fail(self, format!("invalid linked section index {info}")),
        };
        let symbol_section = if link == 0 {
            // The dynamic symbol table is assumed when the link is 0.
            self.dynsym_section()
        } else if !in_range(link) {
            return fail(self, format!("invalid linked section index {link}"));
        } else {
            let linked = self.t.section(link as u32).map(|s| s.sh_type);
            if linked != Some(SectionType::SHT_DYNSYM) && linked != Some(SectionType::SHT_SYMTAB) {
                return fail(
                    self,
                    format!("unexpected section type for section index {link}"),
                );
            }
            Some(link as u32)
        };
        let symbol_table = symbol_section.and_then(|s| self.t.symbol_table_index_for_section(s));
        let has_addend = matches!(
            section.sh_type,
            SectionType::SHT_RELA | SectionType::SHT_ANDROID_RELA
        );
        let spec = TableSpec {
            format,
            section: Some(section.index),
            section_link: Some(section.sh_link),
            section_to_relocate,
            file_offset: section.sh_offset,
            address: section.address(),
            length,
            entry_size: Some(section.sh_entsize),
            has_addend,
            symbol_table,
        };
        match self.build_relocation_table(spec) {
            Ok(table) => self.t.relocation_tables.push(table),
            Err(message) => fail(self, message),
        }
    }

    /// The index of the first section named `.dynsym` (Ghidra's
    /// `getSection(".dynsym")`, which throws when two sections share the
    /// name), looked up once.
    fn dynsym_section(&mut self) -> Option<u32> {
        if let Some(found) = self.dynsym_section {
            return found;
        }
        let found = self
            .t
            .sections
            .iter()
            .find(|s| self.name_is(s, DOT_DYNSYM))
            .map(|s| s.index);
        self.dynsym_section = Some(found);
        found
    }

    /// Ghidra's `ElfRelocationTable` constructor: checks the entry size and
    /// works out how much of the table the file holds. `Err` is the message
    /// of the exception Ghidra throws.
    fn build_relocation_table(&mut self, spec: TableSpec) -> Result<RelocationTable, String> {
        let class = self.t.header.class;
        // `None` is Ghidra's -1; a default table whose entry size is ≤ 0
        // (as Java sees it) gets the standard size.
        let given = spec.entry_size.unwrap_or(u64::MAX);
        let entry_size =
            if spec.format == RelocationFormat::Default && (given == 0 || is_negative(given)) {
                class.relocation_size(spec.has_addend)
            } else {
                given
            };
        let supported = match spec.format {
            RelocationFormat::Default => Some(class.relocation_size(spec.has_addend)),
            RelocationFormat::Relr => Some(class.word_size()),
            RelocationFormat::Android => None,
        };
        if let Some(supported) = supported
            && entry_size != supported
        {
            return Err(format!(
                "Relocation table has unsupported entry size: 0x{entry_size:x}"
            ));
        }
        let file_len = self.t.file_len;
        let available = file_len.saturating_sub(spec.file_offset);
        let (units, truncated) = match spec.format {
            RelocationFormat::Default => {
                let expected = spec.length / entry_size;
                let limit = hard_limit(entry_size);
                let what = "Relocation Table";
                let offset = spec.file_offset;
                let diags = &mut self.diags;
                let count =
                    constrain_count(expected, offset, entry_size, limit, file_len, what, diags);
                let mut truncated =
                    has_fragment(expected, offset, entry_size, limit, file_len, what, diags)
                        || count != expected;
                // Relocation tables are read with the end of the file enforced:
                // only whole entries count.
                let complete = available / entry_size;
                let units = if count > complete {
                    truncated = true;
                    self.diag(
                        DiagnosticKind::RelocationTableTruncated,
                        "Truncated ELF Relocation table due to unexpected EOF",
                    );
                    complete
                } else {
                    count
                };
                (units, truncated)
            }
            RelocationFormat::Relr => {
                let words = spec.length.div_ceil(entry_size);
                let complete = available / entry_size;
                if words > complete {
                    self.diag(
                        DiagnosticKind::RelocationTableTruncated,
                        "Truncated ELF RELR Relocation table due to unexpected EOF",
                    );
                    (complete, true)
                } else {
                    (words, false)
                }
            }
            RelocationFormat::Android => {
                let scan = scan_android(
                    self.raw,
                    spec.file_offset,
                    class,
                    spec.has_addend,
                    &mut self.diags,
                )?;
                (scan.count, scan.truncated)
            }
        };
        Ok(RelocationTable {
            format: spec.format,
            section: spec.section,
            file_offset: spec.file_offset,
            address: spec.address,
            length: spec.length,
            entry_size: match spec.format {
                RelocationFormat::Android => spec.entry_size.unwrap_or(0),
                _ => entry_size,
            },
            has_addend: spec.has_addend,
            symbol_table: spec.symbol_table,
            section_to_relocate: spec.section_to_relocate,
            truncated,
            units,
            section_link: spec.section_link,
        })
    }
}
