//! Program headers (segments).

use bk_bin::BinaryReader;

use crate::constants::{
    ELF32_INVALID_OFFSET, FILE_OFFSET_HARD_LIMIT, PF_R, PF_W, PF_X, SegmentType,
};
use crate::header::ElfClass;
use crate::machine::MachineExtension;

/// A program header (`Elf32_Phdr` / `Elf64_Phdr`; Ghidra's `ElfProgramHeader`).
///
/// One struct serves both classes: fields that are 32 bits wide in a 32-bit
/// file are zero-extended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Index of this header in the program header table.
    pub index: u32,
    /// File offset this header was read from.
    pub header_offset: u64,
    /// Segment type.
    pub p_type: SegmentType,
    /// Segment flags (`PF_…`).
    pub p_flags: u32,
    /// Offset of the segment's data in the file.
    ///
    /// For one kind of malformed file Ghidra rewrites this: when the file
    /// sizes of all segments add up to exactly the length of the file, the
    /// segments are taken to follow each other from offset 0.
    /// [`file_p_offset`](Self::file_p_offset) keeps what the file said.
    pub p_offset: u64,
    /// `p_offset` as stored in the file.
    pub file_p_offset: u64,
    /// Virtual address as stored; [`virtual_address`](Self::virtual_address)
    /// applies the prelink adjustment.
    pub p_vaddr: u64,
    /// Physical address as stored.
    pub p_paddr: u64,
    /// Size of the segment in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory.
    pub p_memsz: u64,
    /// Alignment of the segment.
    pub p_align: u64,
    pub(crate) valid_offset: bool,
    pub(crate) prelink_base: u64,
}

impl ProgramHeader {
    /// Reads a program header at the reader's position.
    pub(crate) fn parse(
        mut reader: BinaryReader<'_>,
        class: ElfClass,
        file_len: u64,
        index: u32,
        prelink_base: u64,
    ) -> bk_bin::Result<Self> {
        let header_offset = reader.position();
        let p_type = SegmentType(reader.read_u32()?);
        let (p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align);
        match class {
            ElfClass::Elf64 => {
                p_flags = reader.read_u32()?;
                p_offset = reader.read_u64()?;
                p_vaddr = reader.read_u64()?;
                p_paddr = reader.read_u64()?;
                p_filesz = reader.read_u64()?;
                p_memsz = reader.read_u64()?;
                p_align = reader.read_u64()?;
            }
            ElfClass::Elf32 => {
                p_offset = u64::from(reader.read_u32()?);
                p_vaddr = u64::from(reader.read_u32()?);
                p_paddr = u64::from(reader.read_u32()?);
                p_filesz = u64::from(reader.read_u32()?);
                p_memsz = u64::from(reader.read_u32()?);
                p_flags = reader.read_u32()?;
                p_align = u64::from(reader.read_u32()?);
            }
        }
        let mut header = Self {
            index,
            header_offset,
            p_type,
            p_flags,
            p_offset,
            file_p_offset: p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
            valid_offset: false,
            prelink_base,
        };
        header.check_offset(class, file_len);
        Ok(header)
    }

    fn check_offset(&mut self, class: ElfClass, file_len: u64) {
        self.valid_offset = self.p_offset < FILE_OFFSET_HARD_LIMIT
            && (class == ElfClass::Elf64 || self.p_offset != ELF32_INVALID_OFFSET)
            && self.p_offset < file_len;
    }

    /// Replaces `p_offset` (Ghidra's `setOffset`).
    pub(crate) fn set_offset(&mut self, offset: u64, class: ElfClass, file_len: u64) {
        self.p_offset = offset;
        self.check_offset(class, file_len);
    }

    /// Virtual address of the segment, adjusted for prelinking.
    pub fn virtual_address(&self) -> u64 {
        self.prelink_base.wrapping_add(self.p_vaddr)
    }

    /// Physical address of the segment, adjusted for prelinking.
    pub fn physical_address(&self) -> u64 {
        self.prelink_base.wrapping_add(self.p_paddr)
    }

    /// True when the segment is readable (`PF_R`).
    pub fn is_read(&self) -> bool {
        self.p_flags & PF_R != 0
    }

    /// True when the segment is writable (`PF_W`).
    pub fn is_write(&self) -> bool {
        self.p_flags & PF_W != 0
    }

    /// True when the segment is executable (`PF_X`).
    pub fn is_execute(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// True when `p_offset` cannot be a position in the file: it is past
    /// the end, above Ghidra's hard limit, or the 32-bit "no offset" marker.
    pub fn is_invalid_offset(&self) -> bool {
        !self.valid_offset
    }

    /// The memory size in addressable units (Ghidra's
    /// `getAdjustedMemorySize`): `p_memsz`, unless the processor extension
    /// scales it.
    pub fn adjusted_memory_size(&self, extension: Option<&MachineExtension>) -> u64 {
        extension.map_or(self.p_memsz, |e| {
            e.adjusted_segment_size(self.p_memsz, self.p_flags)
        })
    }

    /// The file size in addressable units (Ghidra's `getAdjustedLoadSize`):
    /// `p_filesz`, unless the processor extension scales it.
    pub fn adjusted_load_size(&self, extension: Option<&MachineExtension>) -> u64 {
        extension.map_or(self.p_filesz, |e| {
            e.adjusted_segment_size(self.p_filesz, self.p_flags)
        })
    }

    /// The file offset of `virtual_address` inside this segment (Ghidra's
    /// `getOffset(long)`).
    ///
    /// Ghidra throws an unchecked exception — which aborts the import — when
    /// the segment is not a `PT_LOAD` with bytes in the file, or when the
    /// processor extension scales its size; here that is an `Err` naming the
    /// reason.
    pub fn offset_of(
        &self,
        virtual_address: u64,
        extension: Option<&MachineExtension>,
    ) -> Result<u64, &'static str> {
        if self.p_type != SegmentType::PT_LOAD || self.p_filesz == 0 || self.p_memsz == 0 {
            return Err("virtualAddress not loaded by this segment");
        }
        if self.p_memsz != self.adjusted_memory_size(extension) {
            return Err("unsupported use of filtered load segment");
        }
        // Java divides and multiplies signed longs, wrapping silently.
        let load_size = self.adjusted_load_size(extension) as i64;
        let unit = (self.p_filesz as i64)
            .checked_div(load_size)
            .ok_or("segment has no load size")?;
        let delta = virtual_address.wrapping_sub(self.virtual_address()) as i64;
        Ok((unit.wrapping_mul(delta) as u64).wrapping_add(self.p_offset))
    }

    /// Ghidra's `compareTo`: orders `PT_LOAD` headers by `p_vaddr`, with
    /// 0xffffffff sorted last; everything else compares equal.
    pub fn load_order(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if self.p_type != SegmentType::PT_LOAD {
            return Ordering::Equal;
        }
        // Java compares signed longs against the int -1 (0xffffffff as an
        // int literal), so "last" is an address of all ones.
        let (a, b) = (self.p_vaddr as i64, other.p_vaddr as i64);
        match a.cmp(&b) {
            Ordering::Less if a == -1 => Ordering::Greater,
            Ordering::Greater if b == -1 => Ordering::Less,
            ordering => ordering,
        }
    }
}
