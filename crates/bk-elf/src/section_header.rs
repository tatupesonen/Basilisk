//! Section headers.

use bk_bin::{BinaryReader, Endian};

use crate::compress::CompressionHeader;
use crate::constants::{
    ELF32_INVALID_OFFSET, FILE_OFFSET_HARD_LIMIT, SHF_ALLOC, SHF_COMPRESSED, SHF_EXECINSTR,
    SHF_WRITE, SectionType,
};
use crate::diag::{DiagnosticKind, Diagnostics};
use crate::header::ElfClass;
use crate::limits::is_negative;

/// A section header (`Elf32_Shdr` / `Elf64_Shdr`; Ghidra's `ElfSectionHeader`).
///
/// One struct serves both classes: fields that are 32 bits wide in a 32-bit
/// file are zero-extended. The section's name is not stored; it is read on
/// demand with [`ElfFile::section_name`](crate::ElfFile::section_name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// Index of this header in the section header table.
    pub index: u32,
    /// File offset this header was read from.
    pub header_offset: u64,
    /// Offset of the section's name in the section-name string table.
    pub sh_name: u32,
    /// Section type.
    pub sh_type: SectionType,
    /// Section flags (`SHF_…`).
    pub sh_flags: u64,
    /// Address of the section in the loaded image as stored;
    /// [`address`](Self::address) applies the prelink adjustment.
    pub sh_addr: u64,
    /// Offset of the section's data in the file.
    pub sh_offset: u64,
    /// Size of the section's data in the file (in memory for `SHT_NOBITS`).
    pub sh_size: u64,
    /// Index of a linked section; meaning depends on the type.
    pub sh_link: u32,
    /// Extra information; meaning depends on the type.
    pub sh_info: u32,
    /// Required alignment as stored in the section header.
    pub sh_addralign: u64,
    /// Size of one entry, for sections that hold a table.
    pub sh_entsize: u64,
    /// The compression header, when the section is flagged `SHF_COMPRESSED`,
    /// its data starts with a readable header and the algorithm is one that
    /// can be decompressed. `None` otherwise — as in Ghidra, a section whose
    /// compression cannot be handled is treated as an ordinary section.
    pub compression: Option<CompressionHeader>,
    pub(crate) valid_offset: bool,
    pub(crate) prelink_base: u64,
}

impl SectionHeader {
    /// Reads a section header at the reader's position.
    pub(crate) fn parse(
        mut reader: BinaryReader<'_>,
        class: ElfClass,
        data_endian: Endian,
        file_len: u64,
        index: u32,
        prelink_base: u64,
        diags: &mut Diagnostics,
    ) -> bk_bin::Result<Self> {
        let header_offset = reader.position();
        let word = |reader: &mut BinaryReader<'_>| match class {
            ElfClass::Elf32 => reader.read_u32().map(u64::from),
            ElfClass::Elf64 => reader.read_u64(),
        };
        let sh_name = reader.read_u32()?;
        let sh_type = SectionType(reader.read_u32()?);
        let sh_flags = word(&mut reader)?;
        let sh_addr = word(&mut reader)?;
        let sh_offset = word(&mut reader)?;
        let sh_size = word(&mut reader)?;
        let sh_link = reader.read_u32()?;
        let sh_info = reader.read_u32()?;
        let sh_addralign = word(&mut reader)?;
        let sh_entsize = word(&mut reader)?;
        let valid_offset = sh_offset < FILE_OFFSET_HARD_LIMIT
            && (class == ElfClass::Elf64 || sh_offset != ELF32_INVALID_OFFSET)
            && sh_offset < file_len;
        let mut section = Self {
            index,
            header_offset,
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
            compression: None,
            valid_offset,
            prelink_base,
        };
        if sh_flags & SHF_COMPRESSED != 0 {
            section.compression =
                section.read_compression_header(&reader, class, data_endian, file_len, diags);
        }
        Ok(section)
    }

    /// Ghidra's `readCompressedSectionHeader`: the header is used only when
    /// the section is not allocated, lies inside the file, starts with a
    /// whole compression header and names a supported algorithm.
    fn read_compression_header(
        &self,
        reader: &BinaryReader<'_>,
        class: ElfClass,
        data_endian: Endian,
        file_len: u64,
        diags: &mut Diagnostics,
    ) -> Option<CompressionHeader> {
        let end = self.sh_offset.wrapping_add(self.sh_size);
        let in_file = !self.is_alloc()
            && !is_negative(self.sh_offset)
            && self.sh_size != 0
            && !is_negative(self.sh_size)
            && end != 0
            && !is_negative(end)
            && end <= file_len;
        let header_fits = self.sh_type != SectionType::SHT_NOBITS
            && self.sh_size >= u64::from(CompressionHeader::size_for(class));
        if !in_file || !header_fits {
            diags.push(
                DiagnosticKind::Compression,
                format!(
                    "Error reading compressed section information: Invalid compressed section: \
                     section {} (offset 0x{:x}, size 0x{:x})",
                    self.index, self.sh_offset, self.sh_size
                ),
            );
            return None;
        }
        let mut data_reader = reader.with_endian(data_endian).at(self.sh_offset);
        let header = CompressionHeader::read(&mut data_reader, class).ok()?;
        if !header.is_supported() {
            diags.push(
                DiagnosticKind::Compression,
                format!(
                    "Error reading compressed section information: Unknown ELF section \
                     compression type 0x{:x} for section {}",
                    header.ch_type, self.index
                ),
            );
            return None;
        }
        Some(header)
    }

    /// Address of the section in the loaded image, adjusted for prelinking
    /// (Ghidra's `getAddress`).
    pub fn address(&self) -> u64 {
        self.prelink_base.wrapping_add(self.sh_addr)
    }

    /// The section's alignment: the compression header's for a compressed
    /// section, `sh_addralign` otherwise.
    pub fn address_alignment(&self) -> u64 {
        self.compression
            .map_or(self.sh_addralign, |c| c.ch_addralign)
    }

    /// The size of the section's content once decompressed: `ch_size` for a
    /// compressed section, `sh_size` otherwise (Ghidra's `getLogicalSize`).
    pub fn logical_size(&self) -> u64 {
        self.compression.map_or(self.sh_size, |c| c.ch_size)
    }

    /// True when the section holds compressed data that can be decompressed.
    pub fn is_compressed(&self) -> bool {
        self.compression.is_some()
    }

    /// True when the section is writable (`SHF_WRITE`).
    pub fn is_writable(&self) -> bool {
        self.sh_flags & SHF_WRITE != 0
    }

    /// True when the section is executable (`SHF_EXECINSTR`).
    pub fn is_executable(&self) -> bool {
        self.sh_flags & SHF_EXECINSTR != 0
    }

    /// True when the section occupies memory during execution (`SHF_ALLOC`).
    pub fn is_alloc(&self) -> bool {
        self.sh_flags & SHF_ALLOC != 0
    }

    /// True when `sh_offset` cannot be a position in the file: it is past
    /// the end, above Ghidra's hard limit, or the 32-bit "no offset" marker.
    pub fn is_invalid_offset(&self) -> bool {
        !self.valid_offset
    }

    /// True for a section that occupies no space in the file (`SHT_NOBITS`).
    pub fn is_no_bits(&self) -> bool {
        self.sh_type == SectionType::SHT_NOBITS
    }

    /// Ghidra's `toString` for the header, given the section's name.
    pub fn describe(&self, name: &str) -> String {
        format!(
            "{name} - 0x{:x}:0x{:x} - 0x{:x}  - 0x{:x}",
            self.sh_addr,
            self.sh_addr.wrapping_add(self.sh_size).wrapping_sub(1),
            self.sh_size,
            self.sh_offset
        )
    }
}
