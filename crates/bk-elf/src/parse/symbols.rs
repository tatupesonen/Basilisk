//! Locating the symbol tables (Ghidra's `parseSymbolTables`,
//! `parseDynamicSymbolTable`, `getExtendedSymbolSectionIndexTable` and the
//! hash-table walks that size a dynamic symbol table without a section).

use crate::constants::{DynamicTag, FILE_OFFSET_HARD_LIMIT, SectionType};
use crate::diag::DiagnosticKind;
use crate::limits::{constrain_count, hard_limit, has_fragment, is_negative};
use crate::parse::Parser;
use crate::section_header::SectionHeader;
use crate::symbol::{SectionIndexTable, SymbolTable};

/// The name of the dynamic symbol table section.
pub(crate) const DOT_DYNSYM: &str = ".dynsym";

/// A table's entry count after [`constrain_count`] and [`has_fragment`].
struct Counted {
    count: u32,
    truncated: bool,
}

impl Parser<'_> {
    /// Reduces a declared symbol count to what the file holds.
    fn count_symbols(&mut self, expected: u64, offset: u64, entry_size: u64) -> Counted {
        let limit = hard_limit(entry_size);
        let file_len = self.t.file_len;
        let count = constrain_count(
            expected,
            offset,
            entry_size,
            limit,
            file_len,
            "Symbol",
            &mut self.diags,
        );
        let fragment = has_fragment(
            expected,
            offset,
            entry_size,
            limit,
            file_len,
            "Symbol",
            &mut self.diags,
        );
        Counted {
            // Bounded by the hard limit, which is below 2³¹.
            count: u32::try_from(count).unwrap_or(0),
            truncated: fragment || count != expected,
        }
    }

    /// Ghidra's `parseSymbolTables`.
    pub(super) fn parse_symbol_tables(&mut self) {
        let mut dynamic_address = None;
        if self.t.dynamic_table.is_some() {
            match self.dynamic_value(DynamicTag::DT_SYMTAB) {
                Some(address) => dynamic_address = Some(self.t.adjust_address_for_prelink(address)),
                None => self.diag(
                    DiagnosticKind::MissingDynamicEntry,
                    "ELF does not contain a dynamic symbol table (DT_SYMTAB)",
                ),
            }
        }
        let has_shndx = self
            .t
            .sections_of_type(SectionType::SHT_SYMTAB_SHNDX)
            .next()
            .is_some();
        let mut tables = Vec::new();
        let mut dynamic_index = None;
        for index in 0..self.t.sections.len() {
            let Some(section) = self.t.sections.get(index).cloned() else {
                break;
            };
            if section.sh_type != SectionType::SHT_SYMTAB
                && section.sh_type != SectionType::SHT_DYNSYM
            {
                continue;
            }
            if let Some(table) = self.section_symbol_table(&section, has_shndx) {
                if Some(table.address) == dynamic_address {
                    dynamic_index = Some(tables.len());
                }
                tables.push(table);
            }
        }
        // The string table indexes were computed against the list built by
        // `parse_string_tables`, which is final by now.
        self.t.symbol_tables = tables;
        if dynamic_index.is_none()
            && dynamic_address.is_some()
            && let Some(table) = self.parse_dynamic_symbol_table()
        {
            dynamic_index = Some(self.t.symbol_tables.len());
            self.t.symbol_tables.push(table);
        }
        self.t.dynamic_symbol_table = dynamic_index;
    }

    /// The symbol table of one `SHT_SYMTAB` / `SHT_DYNSYM` section, or `None`
    /// (with a diagnostic) when its header is unusable.
    fn section_symbol_table(
        &mut self,
        section: &SectionHeader,
        has_shndx: bool,
    ) -> Option<SymbolTable> {
        let name = self.name(section);
        let what = format!("Symbol table section header '{name}'");
        if section.is_invalid_offset() {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!("{what} has invalid offset value: 0x{:x}", section.sh_offset),
            );
            return None;
        }
        let size = section.sh_size;
        if size == 0 || is_negative(size) {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!("{what} has invalid sh_size value (table size): 0x{size:x}"),
            );
            return None;
        }
        let entry_size = section.sh_entsize;
        if !SymbolTable::is_valid_entry_size(self.t.header.class, entry_size) {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!(
                    "{what} has unsupported sh_entsize value (table entry size): 0x{entry_size:x}"
                ),
            );
            return None;
        }
        if !size.is_multiple_of(entry_size) {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!("{what} has sh_size which is not a multiple of sh_entsize value"),
            );
        }
        let counted = self.count_symbols(size / entry_size, section.sh_offset, entry_size);

        let string_table = self.t.string_table_index_for_section(section.sh_link);
        if string_table.is_none() {
            self.diag(
                DiagnosticKind::StringTable,
                format!("String table not found for symbol table: {name}"),
            );
        }
        let section_index_table = if has_shndx {
            self.section_index_table(section.index, counted.count)
        } else {
            None
        };
        Some(SymbolTable {
            section: Some(section.index),
            file_offset: section.sh_offset,
            address: section.address(),
            // Checked against i32::MAX above.
            entry_size: entry_size as u32,
            symbol_count: counted.count,
            truncated: counted.truncated,
            string_table,
            section_index_table,
            is_dynamic: self.name_is(section, DOT_DYNSYM),
        })
    }

    /// Ghidra's `getExtendedSymbolSectionIndexTable`: the `SHT_SYMTAB_SHNDX`
    /// section linked to the symbol table in section `symbol_section`.
    fn section_index_table(
        &mut self,
        symbol_section: u32,
        symbol_count: u32,
    ) -> Option<SectionIndexTable> {
        let section_count = self.t.sections.len() as u64;
        let index_section = self
            .t
            .sections_of_type(SectionType::SHT_SYMTAB_SHNDX)
            .find(|s| {
                let link = u64::from(s.sh_link);
                // Java's int: a link of 2³¹ or more is negative.
                link > 0
                    && link < section_count
                    && i32::try_from(s.sh_link).is_ok()
                    && s.sh_link == symbol_section
            })?
            .clone();
        let name = self.name(&index_section);
        let size = index_section.sh_size;
        if size == 0 || size > i32::MAX as u64 {
            self.diag(
                DiagnosticKind::SectionIndexTable,
                format!("Symbol table section index header '{name}' has invalid size: 0x{size:x}"),
            );
            return None;
        }
        let offset = index_section.sh_offset;
        if index_section.is_invalid_offset() {
            self.diag(
                DiagnosticKind::SectionIndexTable,
                format!(
                    "Symbol table section index header '{name}' has invalid offset value: \
                     0x{offset:x}"
                ),
            );
            return None;
        }
        let (expected, limit, file_len) = (size / 4, u64::from(symbol_count), self.t.file_len);
        let what = "Symbol section index";
        let count = constrain_count(expected, offset, 4, limit, file_len, what, &mut self.diags);
        has_fragment(expected, offset, 4, limit, file_len, what, &mut self.diags);
        Some(SectionIndexTable {
            section: index_section.index,
            file_offset: offset,
            // At most the symbol count.
            count: u32::try_from(count).unwrap_or(0),
        })
    }

    /// The first hash table the dynamic table names: `DT_HASH`,
    /// `DT_GNU_HASH` or `DT_GNU_XHASH`.
    fn dynamic_hash_tag(&self) -> Option<DynamicTag> {
        [
            DynamicTag::DT_HASH,
            DynamicTag::DT_GNU_HASH,
            DynamicTag::DT_GNU_XHASH,
        ]
        .into_iter()
        .find(|&tag| self.has_dynamic(tag))
    }

    /// Ghidra's `parseDynamicSymbolTable`: the dynamic symbol table of a
    /// file whose section headers do not describe it, located through
    /// `DT_SYMTAB` and sized through the symbol hash table.
    fn parse_dynamic_symbol_table(&mut self) -> Option<SymbolTable> {
        let hash_tag = self.dynamic_hash_tag();
        let (Some(raw_address), Some(entry_size), Some(hash_tag)) = (
            self.dynamic_value(DynamicTag::DT_SYMTAB),
            self.dynamic_value(DynamicTag::DT_SYMENT),
            hash_tag,
        ) else {
            if self.t.dynamic_string_table.is_some() {
                self.diag(
                    DiagnosticKind::MissingDynamicEntry,
                    "Failed to parse DT_SYMTAB, missing dynamic dependency",
                );
            }
            return None;
        };
        if raw_address == 0 {
            self.diag(
                DiagnosticKind::MissingDynamicEntry,
                "Failed to process DT_SYMTAB with 0 value",
            );
            return None;
        }
        let address = self.t.adjust_address_for_prelink(raw_address);
        let Some(segment) = self.load_segment_containing(address) else {
            self.diag(
                DiagnosticKind::UnlocatedAddress,
                format!("Failed to locate DT_SYMTAB in memory at 0x{address:x}"),
            );
            return None;
        };
        let offset = self.offset_in_segment(segment, address, "DT_SYMTAB")?;
        if offset == 0
            || is_negative(offset)
            || offset > FILE_OFFSET_HARD_LIMIT
            || offset >= self.t.file_len
        {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!(
                    "Dynamic symbol table has invalid DT_SYMTAB value (table offset): 0x{offset:x}"
                ),
            );
            return None;
        }
        let hash_address = self
            .t
            .adjust_address_for_prelink(self.dynamic_value(hash_tag).unwrap_or(0));
        let Some(hash_segment) = self.load_segment_containing(hash_address) else {
            self.diag(
                DiagnosticKind::UnlocatedAddress,
                format!(
                    "Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at \
                     0x{hash_address:x}"
                ),
            );
            return None;
        };
        if !SymbolTable::is_valid_entry_size(self.t.header.class, entry_size) {
            self.diag(
                DiagnosticKind::SymbolTable,
                format!(
                    "Dynamic symbol table has unsupported DT_SYMENT value (table entry size): \
                     0x{entry_size:x}"
                ),
            );
            return None;
        }
        let hash_offset = self.offset_in_segment(hash_segment, hash_address, "the hash table")?;
        let expected = if hash_tag == DynamicTag::DT_GNU_HASH {
            self.gnu_hash_symbol_count(hash_offset)
        } else if hash_tag == DynamicTag::DT_GNU_XHASH {
            // ngnusyms (at +0) + symndx (at +8).
            let ngnusyms = self.read_u32_or_zero(hash_offset);
            let symndx = self.read_u32_or_zero(hash_offset.wrapping_add(8));
            u64::from(ngnusyms) + u64::from(symndx)
        } else {
            // DT_HASH: nchain is the number of symbols.
            u64::from(self.read_u32_or_zero(hash_offset.wrapping_add(4)))
        };
        if expected == 0 {
            self.diag(
                DiagnosticKind::HashTable,
                format!(
                    "Unable to determine symbol count for dynamic symbol table at address \
                     0x{address:x}"
                ),
            );
            return None;
        }
        let counted = self.count_symbols(expected, offset, entry_size);
        if self.t.dynamic_string_table.is_none() {
            self.diag(
                DiagnosticKind::StringTable,
                format!("String table not found for dynamic symbol table at address 0x{address:x}"),
            );
        }
        Some(SymbolTable {
            section: None,
            file_offset: offset,
            address,
            entry_size: entry_size as u32,
            symbol_count: counted.count,
            truncated: counted.truncated,
            string_table: self.t.dynamic_string_table,
            // Assumed absent for a table found only through DT_SYMTAB.
            section_index_table: None,
            is_dynamic: true,
        })
    }

    /// A 32-bit value through the zero-padding reader; 0 where Ghidra's read
    /// would throw (an offset Java sees as negative).
    fn read_u32_or_zero(&self, offset: u64) -> u32 {
        self.reader.read_u32_at(offset).unwrap_or(0)
    }

    /// Ghidra's `getMaxOffsetForLoadedRegionContaining`: the last file
    /// offset of the section, or else the `PT_LOAD` segment, that holds
    /// `min_size` bytes at `offset`.
    fn max_offset_of_region_containing(&self, offset: u64, min_size: u64) -> Option<u64> {
        let last = |start: u64, size: u64| start.wrapping_add(size).wrapping_sub(1);
        if !self.t.sections.is_empty()
            && let Some(section) = self
                .t
                .section_header_containing_file_range(offset, min_size)
        {
            return Some(last(section.sh_offset, section.sh_size));
        }
        if !self.t.program_headers.is_empty()
            && let Some(segment) = self.t.program_load_header_containing_file_offset(offset)
        {
            return Some(last(segment.p_offset, segment.p_filesz));
        }
        None
    }

    /// Ghidra's `deriveGnuHashDynamicSymbolCount`: walks the buckets and the
    /// chain of the GNU hash table at `hash_offset` to the last symbol. 0 when
    /// the table cannot be walked.
    ///
    /// Ghidra bounds the walk by the end of the region holding the table;
    /// here it also stops at the end of the file, because a region's size
    /// comes from the file and past the end every word reads as zero.
    fn gnu_hash_symbol_count(&mut self, hash_offset: u64) -> u64 {
        const FAILED: &str = "Error occured while inspecting GNU Hash table"; // [sic]
        let word_size = self.t.header.class.word_size() as i64;
        let start = hash_offset as i64;
        let buckets = i64::from(self.read_u32_or_zero(hash_offset));
        let symbol_base = i64::from(self.read_u32_or_zero(hash_offset.wrapping_add(4)));
        let bloom_size = i64::from(self.read_u32_or_zero(hash_offset.wrapping_add(8)));
        let Some(max_offset) = self.max_offset_of_region_containing(hash_offset, 12) else {
            self.diag(
                DiagnosticKind::HashTable,
                "Failed to idenitify loaded GNU Hash table", // [sic]
            );
            return 0;
        };
        let max_offset = (max_offset as i64).min(self.t.file_len as i64 - 1);
        if max_offset <= 0 {
            self.diag(
                DiagnosticKind::HashTable,
                "Failed to idenitify loaded GNU Hash table",
            );
            return 0;
        }
        let in_bounds = |offset: i64| offset >= start && offset <= max_offset;
        let mut bucket = start
            .wrapping_add(16)
            .wrapping_add(word_size.wrapping_mul(bloom_size));
        let mut max_symbol = 0i64;
        for _ in 0..buckets {
            if !in_bounds(bucket) {
                self.diag(DiagnosticKind::HashTable, FAILED);
                return 0;
            }
            let value = self.read_u32_or_zero(bucket as u64) as i32;
            max_symbol = max_symbol.max(i64::from(value));
            bucket += 4;
        }
        let mut chain = bucket.wrapping_add(max_symbol.wrapping_sub(symbol_base).wrapping_mul(4));
        max_symbol += 1;
        loop {
            if !in_bounds(chain) {
                self.diag(DiagnosticKind::HashTable, FAILED);
                return 0;
            }
            if self.read_u32_or_zero(chain as u64) & 1 != 0 {
                break;
            }
            max_symbol += 1;
            chain += 4;
        }
        max_symbol as u64
    }
}
