//! Locating the dynamic table and the string tables.

use crate::constants::{DynamicTag, SectionType, SegmentType};
use crate::diag::DiagnosticKind;
use crate::dynamic::DynamicTable;
use crate::parse::Parser;
use crate::strtab::StringTable;

impl Parser<'_> {
    /// Ghidra's `parseDynamicTable`.
    pub(super) fn parse_dynamic_table(&mut self) {
        let dynamic_headers: Vec<usize> = self
            .t
            .program_headers_of_type(SegmentType::PT_DYNAMIC)
            .map(|h| h.index as usize)
            .collect();
        if let [index] = dynamic_headers[..]
            && let Some(header) = self.t.program_headers.get(index)
        {
            // p_offset may not point at the start of the table, so it is
            // located by p_vaddr relative to the PT_LOAD that contains it.
            let address = header.virtual_address();
            if address == 0 || header.p_filesz == 0 {
                self.diag(
                    DiagnosticKind::DynamicTable,
                    "ELF Dynamic table appears to have been stripped from binary",
                );
                return;
            }
            // Without a PT_LOAD, p_offset is assumed reliable.
            let load = self
                .t
                .program_load_header_containing(address)
                .unwrap_or(header);
            let offset = load
                .p_offset
                .wrapping_add(address.wrapping_sub(load.virtual_address()));
            self.read_dynamic_table(offset, address);
            return;
        }
        if dynamic_headers.len() > 1 {
            self.diag(
                DiagnosticKind::DynamicTable,
                "Multiple ELF Dynamic table program headers found",
            );
        }
        // Exactly one SHT_DYNAMIC section, inside a PT_LOAD segment.
        let located = {
            let mut dynamic_sections = self.t.sections_of_type(SectionType::SHT_DYNAMIC);
            match (dynamic_sections.next(), dynamic_sections.next()) {
                (Some(section), None) => {
                    let address = section.address();
                    self.t.program_load_header_containing(address).map(|load| {
                        let delta = address.wrapping_sub(load.virtual_address());
                        (load.p_offset.wrapping_add(delta), address)
                    })
                }
                _ => None,
            }
        };
        if let Some((offset, address)) = located {
            self.read_dynamic_table(offset, address);
        }
    }

    fn read_dynamic_table(&mut self, offset: u64, address: u64) {
        match DynamicTable::parse(&self.reader, self.t.header.class, offset, address) {
            Ok(table) => self.t.dynamic_table = Some(table),
            // Ghidra lets the IOException end the whole parse here.
            Err(_) => self.diag(
                DiagnosticKind::DynamicTable,
                format!("Failed to read ELF Dynamic table at file offset 0x{offset:x}"),
            ),
        }
    }

    /// Ghidra's `parseStringTables`.
    pub(super) fn parse_string_tables(&mut self) {
        let mut dynamic_address = None;
        if self.t.dynamic_table.is_some() {
            match self.dynamic_value(DynamicTag::DT_STRTAB) {
                Some(address) => dynamic_address = Some(self.t.adjust_address_for_prelink(address)),
                None => self.diag(
                    DiagnosticKind::MissingDynamicEntry,
                    "ELF does not contain a dynamic string table (DT_STRTAB)",
                ),
            }
        }
        let mut tables = Vec::new();
        let mut dynamic_index = None;
        for section in self.t.sections_of_type(SectionType::SHT_STRTAB) {
            let table = StringTable {
                section: Some(section.index),
                file_offset: section.sh_offset,
                address: section.address(),
                length: section.sh_size,
            };
            if Some(table.address) == dynamic_address {
                dynamic_index = Some(tables.len());
            }
            tables.push(table);
        }
        if dynamic_index.is_none()
            && let Some(address) = dynamic_address
            && let Some(table) = self.parse_dynamic_string_table(address)
        {
            dynamic_index = Some(tables.len());
            tables.push(table);
        }
        self.t.string_tables = tables;
        self.t.dynamic_string_table = dynamic_index;
    }

    /// Ghidra's `parseDynamicStringTable`: the dynamic string table when no
    /// section describes it, located through the program headers.
    fn parse_dynamic_string_table(&mut self, address: u64) -> Option<StringTable> {
        let Some(length) = self.dynamic_value(DynamicTag::DT_STRSZ) else {
            self.diag(
                DiagnosticKind::MissingDynamicEntry,
                "Failed to parse DT_STRTAB, missing dynamic dependency",
            );
            return None;
        };
        if address == 0 {
            self.diag(
                DiagnosticKind::StringTable,
                format!(
                    "ELF Dynamic String Table of size {} appears to have been stripped from binary",
                    length as i64
                ),
            );
            return None;
        }
        let Some(segment) = self.load_segment_containing(address) else {
            self.diag(
                DiagnosticKind::UnlocatedAddress,
                format!("Failed to locate DT_STRTAB in memory at 0x{address:x}"),
            );
            return None;
        };
        let file_offset = self.offset_in_segment(segment, address, "DT_STRTAB")?;
        Some(StringTable {
            section: None,
            file_offset,
            address,
            length,
        })
    }
}
