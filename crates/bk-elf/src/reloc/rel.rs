//! `REL` and `RELA` tables: arrays of fixed-size entries.

use bk_bin::BinaryReader;

use crate::header::ElfClass;
use crate::reloc::{Relocation, RelocationLayout, RelocationTable};

/// Iterator over the entries of a `REL` or `RELA` table.
///
/// Only entries that lie wholly inside the file are produced (Ghidra reads
/// relocation tables without zero padding, to enforce the end of the file).
#[derive(Debug, Clone)]
pub struct StandardIter<'a> {
    reader: BinaryReader<'a>,
    class: ElfClass,
    layout: RelocationLayout,
    has_addend: bool,
    file_offset: u64,
    entry_size: u64,
    next: u64,
    count: u64,
}

impl<'a> StandardIter<'a> {
    pub(crate) fn new(
        reader: BinaryReader<'a>,
        table: &RelocationTable,
        class: ElfClass,
        layout: RelocationLayout,
    ) -> Self {
        Self {
            reader,
            class,
            layout,
            has_addend: table.has_addend,
            file_offset: table.file_offset,
            entry_size: table.entry_size,
            next: 0,
            count: table.units,
        }
    }

    fn read(&self, index: u64) -> Option<Relocation> {
        let offset = self
            .file_offset
            .checked_add(index.checked_mul(self.entry_size)?)?;
        let r = self.reader;
        let (r_offset, r_info, r_addend) = match self.class {
            ElfClass::Elf32 => (
                u64::from(r.read_u32_at(offset).ok()?),
                u64::from(r.read_u32_at(offset + 4).ok()?),
                if self.has_addend {
                    i64::from(r.read_i32_at(offset + 8).ok()?)
                } else {
                    0
                },
            ),
            ElfClass::Elf64 => (
                r.read_u64_at(offset).ok()?,
                r.read_u64_at(offset + 8).ok()?,
                if self.has_addend {
                    r.read_i64_at(offset + 16).ok()?
                } else {
                    0
                },
            ),
        };
        Some(Relocation {
            r_offset,
            r_info,
            r_addend,
            // The count is below 2³¹ (the hard limit), so the index fits.
            index: index as u32,
            layout: self.layout,
            has_addend: self.has_addend,
        })
    }
}

impl Iterator for StandardIter<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Relocation> {
        if self.next >= self.count {
            return None;
        }
        let relocation = self.read(self.next)?;
        self.next += 1;
        Some(relocation)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.count - self.next).unwrap_or(usize::MAX);
        (0, Some(remaining))
    }
}
