//! The ELF header: identification, the fixed fields, and the counts of the
//! header tables with their extended-numbering and tolerance rules.

use bk_bin::{BinaryReader, ByteProvider, Endian, UnlimitedProvider};

use crate::constants::{
    EI_DATA, EI_NIDENT, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, ElfType,
    FILE_OFFSET_HARD_LIMIT, MAGIC, Machine, OsAbi, PN_XNUM, SHN_LORESERVE, SHN_XINDEX, SectionType,
};
use crate::diag::{DiagnosticKind, Diagnostics};
use crate::error::ElfError;
use crate::limits::{constrain_count, hard_limit, has_fragment, is_negative};
use crate::section_header::SectionHeader;

/// The file class: the width of addresses and offsets in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    /// `ELFCLASS32`.
    Elf32,
    /// `ELFCLASS64`.
    Elf64,
}

impl ElfClass {
    /// Size of the ELF header in bytes.
    pub const fn header_size(self) -> u64 {
        match self {
            Self::Elf32 => 52,
            Self::Elf64 => 64,
        }
    }

    /// Size of a program header in bytes.
    pub const fn program_header_size(self) -> u64 {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 56,
        }
    }

    /// Size of a section header in bytes.
    pub const fn section_header_size(self) -> u64 {
        match self {
            Self::Elf32 => 40,
            Self::Elf64 => 64,
        }
    }

    /// Size of a symbol table entry in bytes.
    pub const fn symbol_size(self) -> u64 {
        match self {
            Self::Elf32 => 16,
            Self::Elf64 => 24,
        }
    }

    /// Size of a dynamic table entry in bytes.
    pub const fn dynamic_size(self) -> u64 {
        match self {
            Self::Elf32 => 8,
            Self::Elf64 => 16,
        }
    }

    /// Size of an address, offset or word-sized field in bytes.
    pub const fn word_size(self) -> u64 {
        match self {
            Self::Elf32 => 4,
            Self::Elf64 => 8,
        }
    }

    /// Size of a `REL` (`with_addend` false) or `RELA` relocation entry.
    pub const fn relocation_size(self, with_addend: bool) -> u64 {
        self.word_size() * if with_addend { 3 } else { 2 }
    }
}

/// The ELF header.
///
/// Fields named `e_…` hold what Ghidra's `ElfHeader` exposes: for the table
/// offsets and counts that is the *effective* value, after the tolerance and
/// extended-numbering rules (an offset outside the file becomes 0, a count
/// the file cannot hold is reduced, `PN_XNUM` and friends are resolved). The
/// values stored in the file are kept in the `raw_…` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    /// The file class, from `e_ident[EI_CLASS]`.
    pub class: ElfClass,
    /// `e_ident[EI_DATA]` as stored: 1 little-endian, 2 big-endian.
    pub e_ident_data: u8,
    /// `e_ident[EI_VERSION]`.
    pub e_ident_version: u8,
    /// `e_ident[EI_OSABI]`.
    pub e_ident_osabi: OsAbi,
    /// `e_ident[EI_ABIVERSION]`.
    pub e_ident_abiversion: u8,
    /// The seven padding bytes that end `e_ident`.
    pub e_ident_pad: [u8; 7],
    /// The byte order the headers and tables are read in. It follows
    /// `e_ident_data`, except that Ghidra assumes little-endian when that
    /// byte is invalid, and switches a big-endian file to little-endian
    /// headers when `e_type` and `e_version` only make sense that way (some
    /// toolchains always write little-endian headers).
    pub header_endian: Endian,
    /// Object file type.
    pub e_type: ElfType,
    /// Target architecture.
    pub e_machine: Machine,
    /// Object file version.
    pub e_version: u32,
    /// Entry point as stored; [`ElfFile::entry`](crate::ElfFile::entry)
    /// applies the prelink adjustment.
    pub e_entry: u64,
    /// Program header table offset, or 0 if there is none or it is invalid.
    pub e_phoff: u64,
    /// Section header table offset, or 0 if there is none or it is invalid.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// Size of this header according to the file.
    pub e_ehsize: u16,
    /// Size of a program header according to the file.
    pub e_phentsize: u16,
    /// Number of program headers that are parsed.
    pub e_phnum: u32,
    /// Size of a section header according to the file.
    pub e_shentsize: u16,
    /// Number of section headers that are parsed.
    pub e_shnum: u32,
    /// Index of the section holding section names, or 0.
    pub e_shstrndx: u32,
    /// `e_phoff` as stored in the file.
    pub raw_e_phoff: u64,
    /// `e_shoff` as stored in the file.
    pub raw_e_shoff: u64,
    /// `e_phnum` as stored in the file (`PN_XNUM` for an extended count).
    pub raw_e_phnum: u16,
    /// `e_shnum` as stored in the file (0 for an extended count).
    pub raw_e_shnum: u16,
    /// `e_shstrndx` as stored in the file (`SHN_XINDEX` for an extended index).
    pub raw_e_shstrndx: u16,
    /// True when fewer program headers are parsed than the file declares,
    /// or the last one is only partly in the file.
    pub phnum_truncated: bool,
    /// True when fewer section headers are parsed than the file declares,
    /// or the last one is only partly in the file.
    pub shnum_truncated: bool,
}

impl ElfHeader {
    /// True for a 32-bit file.
    pub fn is_32bit(&self) -> bool {
        self.class == ElfClass::Elf32
    }

    /// True for a 64-bit file.
    pub fn is_64bit(&self) -> bool {
        self.class == ElfClass::Elf64
    }

    /// True when `e_ident[EI_DATA]` says little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.e_ident_data == ELFDATA2LSB
    }

    /// True when `e_ident[EI_DATA]` says big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.e_ident_data == ELFDATA2MSB
    }

    /// The byte order of the file's data according to `e_ident[EI_DATA]`:
    /// little-endian if it says so, big-endian otherwise. Ghidra reads
    /// section contents (compression headers, notes) in this order and the
    /// header tables in [`header_endian`](Self::header_endian).
    pub fn data_endian(&self) -> Endian {
        Endian::from_little(self.is_little_endian())
    }

    /// True for a relocatable file (`ET_REL`).
    pub fn is_relocatable(&self) -> bool {
        self.e_type == ElfType::ET_REL
    }

    /// True for a shared object (`ET_DYN`).
    pub fn is_shared_object(&self) -> bool {
        self.e_type == ElfType::ET_DYN
    }

    /// True for an executable (`ET_EXEC`).
    pub fn is_executable(&self) -> bool {
        self.e_type == ElfType::ET_EXEC
    }

    /// Ghidra's `getMachineName`: the machine number in decimal, signed as
    /// Java's `short` is.
    pub fn machine_name(&self) -> String {
        (self.e_machine.0 as i16).to_string()
    }

    /// Reads the header from `provider`.
    ///
    /// Problems Ghidra tolerates are appended to `diags`.
    pub(crate) fn parse(
        provider: &dyn ByteProvider,
        diags: &mut Diagnostics,
    ) -> Result<Self, ElfError> {
        const INITIAL_READ_LEN: usize = EI_NIDENT + 18;
        let file_len = provider.len();
        let mut magic = [0u8; 4];
        if provider.read_into(0, &mut magic).is_err() || magic != MAGIC {
            return Err(ElfError::NotElf);
        }
        if file_len < INITIAL_READ_LEN as u64 {
            return Err(ElfError::TooShort { len: file_len });
        }
        let mut start = [0u8; INITIAL_READ_LEN];
        provider.read_into(0, &mut start)?;
        let header_endian = header_endianness(&start, diags);

        // Past this point reads go through a zero-padding view, so a
        // truncated header yields zero fields instead of an error.
        let unlimited = UnlimitedProvider::new(provider);
        let mut reader = BinaryReader::new(&unlimited, header_endian).at(MAGIC.len() as u64);
        let class_byte = reader.read_u8()?;
        let e_ident_data = reader.read_u8()?;
        let e_ident_version = reader.read_u8()?;
        let e_ident_osabi = OsAbi(reader.read_u8()?);
        let e_ident_abiversion = reader.read_u8()?;
        let e_ident_pad = reader.read_array::<7>()?;
        let e_type = ElfType(reader.read_u16()?);
        let e_machine = Machine(reader.read_u16()?);
        let e_version = reader.read_u32()?;
        let class = match class_byte {
            ELFCLASS32 => ElfClass::Elf32,
            ELFCLASS64 => ElfClass::Elf64,
            class => return Err(ElfError::UnsupportedClass { class }),
        };
        let word = |reader: &mut BinaryReader<'_>| match class {
            ElfClass::Elf32 => reader.read_u32().map(u64::from),
            ElfClass::Elf64 => reader.read_u64(),
        };
        let e_entry = word(&mut reader)?;
        let raw_e_phoff = word(&mut reader)?;
        let raw_e_shoff = word(&mut reader)?;
        let valid_offset = |offset: u64| offset <= FILE_OFFSET_HARD_LIMIT && offset < file_len;
        let mut e_phoff = raw_e_phoff;
        if !valid_offset(e_phoff) {
            diags.push(
                DiagnosticKind::InvalidTableOffset,
                format!("Invalid ELF e_phoff value (program header table offset): 0x{e_phoff:x}"),
            );
            e_phoff = 0;
        }
        let mut e_shoff = raw_e_shoff;
        if !valid_offset(e_shoff) {
            diags.push(
                DiagnosticKind::InvalidTableOffset,
                format!("Invalid ELF e_shoff value (section header table offset): 0x{e_shoff:x}"),
            );
            e_shoff = 0;
        }
        let e_flags = reader.read_u32()?;
        let e_ehsize = reader.read_u16()?;
        let e_phentsize = reader.read_u16()?;
        let raw_e_phnum = reader.read_u16()?;
        let e_shentsize = reader.read_u16()?;
        let raw_e_shnum = reader.read_u16()?;
        let raw_e_shstrndx = reader.read_u16()?;

        // Section 0 carries the extended counts; it is read at most once.
        let mut section0 = Section0::new(&reader, class, e_ident_data, e_shoff, file_len);

        let mut phnum = u64::from(raw_e_phnum);
        if e_phoff == 0 {
            phnum = 0; // no program headers
        } else if raw_e_phnum == PN_XNUM {
            phnum = section0.extended_program_header_count(diags);
        }

        let mut shnum = u64::from(raw_e_shnum);
        if raw_e_shnum >= SHN_LORESERVE {
            diags.push(
                DiagnosticKind::InvalidSectionCount,
                format!("Invalid ELF e_shnum value (section header count): 0x{shnum:x}"),
            );
            shnum = 0;
        }
        if e_shoff == 0 {
            shnum = 0; // no section headers
        } else if shnum == 0 {
            // Only e_shnum == 0 should trigger this, but Ghidra also looks
            // after rejecting a reserved value.
            shnum = section0.extended_section_header_count(diags);
        }

        let mut phnum_truncated = false;
        if phnum > 0 {
            let expected = class.program_header_size();
            if u64::from(e_phentsize) != expected {
                if shnum == 0 {
                    return Err(ElfError::UnsupportedProgramHeaderSize {
                        actual: e_phentsize,
                        expected: expected as u16,
                    });
                }
                diags.push(
                    DiagnosticKind::UnsupportedEntrySize,
                    format!(
                        "Unsupported e_phentsize value (program header size): {e_phentsize} \
                         (expected {expected}), using section headers only"
                    ),
                );
                phnum = 0;
            } else {
                let limit = hard_limit(expected);
                let args = (e_phoff, expected, limit, file_len, "Program Header");
                let count = constrain_count(phnum, args.0, args.1, args.2, args.3, args.4, diags);
                phnum_truncated =
                    has_fragment(phnum, args.0, args.1, args.2, args.3, args.4, diags)
                        || count != phnum;
                phnum = count;
            }
        }

        let mut shnum_truncated = false;
        if shnum > 0 {
            let expected = class.section_header_size();
            if u64::from(e_shentsize) != expected {
                if phnum == 0 {
                    return Err(ElfError::UnsupportedSectionHeaderSize {
                        actual: e_shentsize,
                        expected: expected as u16,
                    });
                }
                diags.push(
                    DiagnosticKind::UnsupportedEntrySize,
                    format!(
                        "Unsupported e_shentsize value (section header size): {e_shentsize} \
                         (expected {expected}), using program headers only"
                    ),
                );
                shnum = 0;
            } else {
                let limit = hard_limit(expected);
                let args = (e_shoff, expected, limit, file_len, "Section Header");
                let count = constrain_count(shnum, args.0, args.1, args.2, args.3, args.4, diags);
                shnum_truncated =
                    has_fragment(shnum, args.0, args.1, args.2, args.3, args.4, diags)
                        || count != shnum;
                shnum = count;
            }
        }

        let mut e_shstrndx = u32::from(raw_e_shstrndx);
        if shnum == 0 {
            e_shstrndx = 0;
        } else if raw_e_shstrndx == SHN_XINDEX {
            e_shstrndx = section0.extended_string_table_index();
        }

        let header = Self {
            class,
            e_ident_data,
            e_ident_version,
            e_ident_osabi,
            e_ident_abiversion,
            e_ident_pad,
            header_endian,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            // Both counts are bounded by the hard limit (below 2³¹).
            e_phnum: u32::try_from(phnum).unwrap_or(0),
            e_shentsize,
            e_shnum: u32::try_from(shnum).unwrap_or(0),
            e_shstrndx,
            raw_e_phoff,
            raw_e_shoff,
            raw_e_phnum,
            raw_e_shnum,
            raw_e_shstrndx,
            phnum_truncated,
            shnum_truncated,
        };
        Ok(header)
    }
}

/// Ghidra's `determineHeaderEndianness`.
fn header_endianness(start: &[u8; EI_NIDENT + 18], diags: &mut Diagnostics) -> Endian {
    let data = start[EI_DATA];
    let mut endian = Endian::Little;
    if data == ELFDATA2MSB {
        endian = Endian::Big;
    } else if data != ELFDATA2LSB {
        // Java prints the byte sign-extended to an int.
        diags.push(
            DiagnosticKind::InvalidDataEncoding,
            format!(
                "Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x{:x})",
                i32::from(data as i8)
            ),
        );
    }
    // Sanity check for toolchains that always write little-endian headers:
    // a big-endian e_type has a zero first byte; if it does not, and the
    // first byte of e_version is 1, the headers are little-endian.
    if endian == Endian::Big && start[EI_NIDENT] != 0 && start[EI_NIDENT + 4] == 1 {
        endian = Endian::Little;
    }
    endian
}

/// Lazy access to section 0 while the header is parsed (Ghidra's
/// `getSection0`).
struct Section0<'a> {
    reader: &'a BinaryReader<'a>,
    class: ElfClass,
    data: u8,
    e_shoff: u64,
    file_len: u64,
    loaded: Option<Option<SectionHeader>>,
}

impl<'a> Section0<'a> {
    fn new(
        reader: &'a BinaryReader<'a>,
        class: ElfClass,
        data: u8,
        e_shoff: u64,
        file_len: u64,
    ) -> Self {
        Self {
            reader,
            class,
            data,
            e_shoff,
            file_len,
            loaded: None,
        }
    }

    /// Section 0, if the file holds all of it and it is `SHT_NULL`.
    fn null_section(&mut self) -> Option<&SectionHeader> {
        let (reader, class, data, e_shoff, file_len) = (
            self.reader,
            self.class,
            self.data,
            self.e_shoff,
            self.file_len,
        );
        self.loaded
            .get_or_insert_with(|| {
                let fits = e_shoff != 0
                    && e_shoff
                        .checked_add(class.section_header_size())
                        .is_some_and(|end| end <= file_len);
                if !fits {
                    return None;
                }
                let data_endian = Endian::from_little(data == ELFDATA2LSB);
                // Problems inside section 0 are reported when the section
                // table is parsed, not here.
                let mut scratch = Diagnostics::default();
                SectionHeader::parse(
                    reader.at(e_shoff),
                    class,
                    data_endian,
                    file_len,
                    0,
                    0,
                    &mut scratch,
                )
                .ok()
            })
            .as_ref()
            .filter(|section| section.sh_type == SectionType::SHT_NULL)
    }

    fn extended_program_header_count(&mut self, diags: &mut Diagnostics) -> u64 {
        let Some(section) = self.null_section() else {
            diags.push(
                DiagnosticKind::InvalidExtendedCount,
                "Failed to load Section-0 required for extended program header count",
            );
            return 0;
        };
        let value = section.sh_info;
        if value > i32::MAX as u32 {
            diags.push(
                DiagnosticKind::InvalidExtendedCount,
                format!("Invalid extended program header count: {}", value as i32),
            );
            return 0;
        }
        u64::from(value)
    }

    fn extended_section_header_count(&mut self, diags: &mut Diagnostics) -> u64 {
        let Some(section) = self.null_section() else {
            diags.push(
                DiagnosticKind::InvalidExtendedCount,
                "Failed to load Section-0 required for extended section header count",
            );
            return 0;
        };
        let value = section.sh_size;
        if is_negative(value) || value > i32::MAX as u64 {
            diags.push(
                DiagnosticKind::InvalidExtendedCount,
                format!("Invalid extended section header count: {}", value as i64),
            );
            return 0;
        }
        value
    }

    fn extended_string_table_index(&mut self) -> u32 {
        // A value Java sees as negative becomes 0.
        self.null_section().map_or(0, |s| {
            if s.sh_link > i32::MAX as u32 {
                0
            } else {
                s.sh_link
            }
        })
    }
}
