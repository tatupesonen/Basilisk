//! `RELR`: a compact encoding of relative relocations.
//!
//! The table is a sequence of words. A word with the low bit clear is an
//! address: it yields one relocation there and sets the base to the next
//! word-sized slot. A word with the low bit set is a bitmap: bit *n*
//! (1 ≤ *n* < word bits) yields a relocation at `base + (n − 1) · word`, and
//! the base then advances by `word bits − 1` slots. The first word is always
//! taken as an address, as in Ghidra.

use bk_bin::BinaryReader;

use crate::header::ElfClass;
use crate::reloc::{Relocation, RelocationTable};

/// Iterator over the relocations a `RELR` table encodes.
#[derive(Debug, Clone)]
pub struct RelrIter<'a> {
    reader: BinaryReader<'a>,
    class: ElfClass,
    has_addend: bool,
    /// Offset of the next word to read.
    position: u64,
    /// Words still to be read.
    words_left: u64,
    word_size: u64,
    first: bool,
    /// The base for the next bitmap.
    base: u64,
    /// The bitmap being expanded (already shifted) and the offset its next
    /// bit stands for.
    bitmap: u64,
    bitmap_offset: u64,
    index: u32,
}

impl<'a> RelrIter<'a> {
    pub(crate) fn new(reader: BinaryReader<'a>, table: &RelocationTable, class: ElfClass) -> Self {
        Self {
            reader,
            class,
            has_addend: table.has_addend,
            position: table.file_offset,
            words_left: table.units,
            word_size: table.entry_size,
            first: true,
            base: 0,
            bitmap: 0,
            bitmap_offset: 0,
            index: 0,
        }
    }

    fn emit(&mut self, offset: u64) -> Relocation {
        let relocation =
            Relocation::from_values(self.class, self.index, self.has_addend, offset, 0, 0);
        self.index = self.index.wrapping_add(1);
        relocation
    }

    fn read_word(&mut self) -> Option<u64> {
        if self.words_left == 0 {
            return None;
        }
        let word = if self.word_size == 8 {
            self.reader.read_u64_at(self.position).ok()?
        } else {
            u64::from(self.reader.read_u32_at(self.position).ok()?)
        };
        self.words_left -= 1;
        self.position = self.position.wrapping_add(self.word_size);
        Some(word)
    }
}

impl Iterator for RelrIter<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Relocation> {
        loop {
            // Drain the current bitmap first.
            while self.bitmap != 0 {
                self.bitmap >>= 1;
                let offset = self.bitmap_offset;
                self.bitmap_offset = offset.wrapping_add(self.word_size);
                if self.bitmap & 1 != 0 {
                    return Some(self.emit(offset));
                }
            }
            let word = self.read_word()?;
            if self.first || word & 1 == 0 {
                self.first = false;
                self.base = word.wrapping_add(self.word_size);
                return Some(self.emit(word));
            }
            self.bitmap = word;
            self.bitmap_offset = self.base;
            let bits = self.word_size * 8 - 1;
            self.base = self.base.wrapping_add(bits.wrapping_mul(self.word_size));
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Every word yields at most (word bits − 1) relocations.
        let per_word = self.word_size.saturating_mul(8);
        let upper = self.words_left.saturating_add(1).saturating_mul(per_word);
        (0, usize::try_from(upper).ok())
    }
}
