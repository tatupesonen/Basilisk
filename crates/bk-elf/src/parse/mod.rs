//! Parsing a file into [`ElfTables`]: the order and the tolerance rules of
//! Ghidra's `ElfHeader.parse()`.
//!
//! The steps run in Ghidra's order, because later steps depend on earlier
//! ones and because the diagnostics are reported in that order: program
//! headers, section headers, the dynamic table, string tables, symbol
//! tables, relocation tables.

mod dynamic;
mod relocs;
mod symbols;

use std::borrow::Cow;

use bk_bin::{BinaryReader, ByteProvider, Charset};

use crate::constants::DynamicTag;
use crate::diag::{DiagnosticKind, Diagnostics};
use crate::error::ElfError;
use crate::header::ElfHeader;
use crate::machine;
use crate::program_header::ProgramHeader;
use crate::section_header::SectionHeader;
use crate::tables::ElfTables;

/// State shared by the parsing steps.
pub(crate) struct Parser<'a> {
    /// Zero-padding reader in header byte order: reads past the end of the
    /// file yield zeros (Ghidra's "unlimited" reader).
    reader: BinaryReader<'a>,
    /// Reader over the file itself, in header byte order, for the tables
    /// Ghidra reads with the end of the file enforced.
    raw: BinaryReader<'a>,
    diags: Diagnostics,
    t: ElfTables,
    /// The section named `.dynsym`, once looked up.
    dynsym_section: Option<Option<u32>>,
}

/// Parses the file behind `raw`; `unlimited` must be a zero-padding view of
/// the same bytes.
pub(crate) fn parse(
    unlimited: &dyn ByteProvider,
    raw: &dyn ByteProvider,
) -> Result<ElfTables, ElfError> {
    let mut diags = Diagnostics::default();
    let header = ElfHeader::parse(raw, &mut diags)?;
    let endian = header.header_endian;
    let reader = BinaryReader::new(unlimited, endian);
    let prelink_base = read_prelink_base(&reader);
    let tables = ElfTables {
        extension: machine::extension_for(header.e_machine, header.class),
        header,
        prelink_base,
        file_len: raw.len(),
        program_headers: Vec::new(),
        sections: Vec::new(),
        dynamic_table: None,
        string_tables: Vec::new(),
        dynamic_string_table: None,
        symbol_tables: Vec::new(),
        dynamic_symbol_table: None,
        relocation_tables: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut parser = Parser {
        reader,
        raw: BinaryReader::new(raw, endian),
        diags,
        t: tables,
        dynsym_section: None,
    };
    parser.parse_program_headers()?;
    parser.parse_section_headers()?;
    parser.parse_dynamic_table();
    parser.parse_string_tables();
    parser.parse_symbol_tables();
    parser.parse_relocation_tables();
    let Parser { diags, mut t, .. } = parser;
    t.diagnostics = diags.into_vec();
    Ok(t)
}

/// Ghidra's `getPreLinkImageBase`: `prelink` appends the original image
/// base and the tag `PRE` to the file.
fn read_prelink_base(reader: &BinaryReader<'_>) -> Option<u32> {
    let len = reader.len();
    if len < 8 {
        return None;
    }
    let base = reader.read_u32_at(len - 8).ok()?;
    let tag = reader
        .read_fixed_string_at(len - 4, 4, Charset::Ascii)
        .ok()?;
    (crate::strtab::java_trim(&tag) == "PRE").then_some(base)
}

/// Where the name of `section` starts in the file, if Ghidra would read
/// one: the section named by `e_shstrndx` must exist (and not be section 0)
/// with a valid offset, `sh_name` must be non-negative as a Java `int`, and
/// the name must start inside the file.
fn section_name_offset(
    reader: &BinaryReader<'_>,
    tables: &ElfTables,
    section: &SectionHeader,
) -> Option<u64> {
    let string_table = match tables.header.e_shstrndx {
        0 => None,
        index => tables.section(index).filter(|s| !s.is_invalid_offset()),
    }?;
    // Java holds sh_name in an int; a "negative" one is never looked up.
    i32::try_from(section.sh_name).ok()?;
    let offset = string_table
        .sh_offset
        .checked_add(u64::from(section.sh_name))?;
    (offset < reader.len()).then_some(offset)
}

/// The name of `section` (Ghidra's `ElfSectionHeader.updateName`): the
/// string at `sh_name` in the section named by `e_shstrndx`, read up to its
/// terminator and not trimmed; `SECTION<index>` when there is no usable
/// string table, the offset is outside the file, or the name is empty.
pub(crate) fn section_name<'a>(
    reader: &BinaryReader<'a>,
    tables: &ElfTables,
    section: &SectionHeader,
) -> Cow<'a, str> {
    if let Some(offset) = section_name_offset(reader, tables, section)
        && let Ok(bytes) = reader.read_terminated_bytes_at(offset, 1)
        && !bytes.is_empty()
    {
        return match bytes {
            Cow::Borrowed(bytes) => String::from_utf8_lossy(bytes),
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
        };
    }
    Cow::Owned(format!("SECTION{}", section.index))
}

/// The longest section name put into a diagnostic message.
const MAX_DIAGNOSTIC_NAME: usize = 256;

/// [`section_name`] for diagnostic messages: at most 256 bytes are read, so
/// that a file whose names all run into one long unterminated string costs
/// no more than a short name per message.
fn section_name_for_message(
    reader: &BinaryReader<'_>,
    tables: &ElfTables,
    section: &SectionHeader,
) -> String {
    if let Some(offset) = section_name_offset(reader, tables, section)
        && let Ok(bytes) = reader.read_bytes_at(offset, MAX_DIAGNOSTIC_NAME)
    {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if let Some(name) = bytes.get(..end)
            && !name.is_empty()
        {
            return String::from_utf8_lossy(name).into_owned();
        }
    }
    format!("SECTION{}", section.index)
}

/// True when the name of `section` is exactly `name`, reading no more of
/// the file than `name` is long.
pub(crate) fn section_name_is(
    reader: &BinaryReader<'_>,
    tables: &ElfTables,
    section: &SectionHeader,
    name: &str,
) -> bool {
    section_name_offset(reader, tables, section)
        .and_then(|offset| reader.read_bytes_at(offset, name.len() + 1).ok())
        .is_some_and(|bytes| {
            bytes.get(..name.len()) == Some(name.as_bytes()) && bytes.get(name.len()) == Some(&0)
        })
}

impl Parser<'_> {
    fn diag(&mut self, kind: DiagnosticKind, message: impl Into<String>) {
        self.diags.push(kind, message);
    }

    fn prelink_base(&self) -> u64 {
        u64::from(self.t.prelink_base.unwrap_or(0))
    }

    /// The name of `section` for a diagnostic message.
    fn name(&self, section: &SectionHeader) -> String {
        section_name_for_message(&self.reader, &self.t, section)
    }

    /// True when `section` is named `name`.
    fn name_is(&self, section: &SectionHeader, name: &str) -> bool {
        section_name_is(&self.reader, &self.t, section, name)
    }

    /// The value of the first dynamic entry with `tag`.
    fn dynamic_value(&self, tag: DynamicTag) -> Option<u64> {
        self.t.dynamic_table.as_ref()?.value(tag)
    }

    fn has_dynamic(&self, tag: DynamicTag) -> bool {
        self.t
            .dynamic_table
            .as_ref()
            .is_some_and(|d| d.contains(tag))
    }

    /// Turns `address` into a file offset through the `PT_LOAD` header with
    /// index `segment`. Where Ghidra's `getOffset` would throw (and abort
    /// the import), a diagnostic is recorded and `None` returned.
    fn offset_in_segment(&mut self, segment: usize, address: u64, what: &str) -> Option<u64> {
        let header = self.t.program_headers.get(segment)?;
        match header.offset_of(address, self.t.extension) {
            Ok(offset) => Some(offset),
            Err(reason) => {
                self.diag(
                    DiagnosticKind::UnlocatedAddress,
                    format!("Failed to locate {what} in file for address 0x{address:x}: {reason}"),
                );
                None
            }
        }
    }

    /// Index of the `PT_LOAD` header containing `address`.
    fn load_segment_containing(&self, address: u64) -> Option<usize> {
        self.t
            .program_load_header_containing(address)
            .map(|h| h.index as usize)
    }

    fn parse_program_headers(&mut self) -> Result<(), ElfError> {
        let header = &self.t.header;
        let (class, file_len, base) = (header.class, self.t.file_len, self.prelink_base());
        let entry_size = u64::from(header.e_phentsize);
        let mut headers = Vec::with_capacity(header.e_phnum as usize);
        for index in 0..header.e_phnum {
            let offset = header
                .e_phoff
                .wrapping_add(u64::from(index).wrapping_mul(entry_size));
            headers.push(ProgramHeader::parse(
                self.reader.at(offset),
                class,
                file_len,
                index,
                base,
            )?);
        }
        // Ghidra's hack for a malformed file made of nothing but segments:
        // if their file sizes add up to the length of the file, they are
        // taken to follow one another from offset 0.
        let total = headers
            .iter()
            .fold(0u64, |sum, h| sum.wrapping_add(h.p_filesz));
        if total == file_len {
            let mut offset = 0u64;
            for header in &mut headers {
                header.set_offset(offset, class, file_len);
                offset = offset.wrapping_add(header.p_filesz);
            }
        }
        self.t.program_headers = headers;
        Ok(())
    }

    fn parse_section_headers(&mut self) -> Result<(), ElfError> {
        let header = &self.t.header;
        let (class, file_len, base) = (header.class, self.t.file_len, self.prelink_base());
        let (e_shoff, e_shnum, data_endian) =
            (header.e_shoff, header.e_shnum, header.data_endian());
        let entry_size = u64::from(header.e_shentsize);
        let mut sections = Vec::with_capacity(e_shnum as usize);
        for index in 0..e_shnum {
            let offset = e_shoff.wrapping_add(u64::from(index).wrapping_mul(entry_size));
            sections.push(SectionHeader::parse(
                self.reader.at(offset),
                class,
                data_endian,
                file_len,
                index,
                base,
                &mut self.diags,
            )?);
        }
        self.t.sections = sections;
        Ok(())
    }
}
