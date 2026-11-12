//! The relocation table descriptor and the relocation entry.

use bk_bin::{BinaryReader, Endian};

use crate::header::ElfClass;
use crate::reloc::{AndroidIter, RelrIter, StandardIter};

/// How a relocation table is encoded (Ghidra's `TableFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationFormat {
    /// An array of `Elf_Rel` or `Elf_Rela` entries.
    Default,
    /// Android's packed format (`APS2`): groups of LEB128-encoded deltas.
    Android,
    /// `RELR`: addresses and bitmaps describing relative relocations.
    Relr,
}

/// How `r_info` splits into symbol index and type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationLayout {
    /// 32-bit: symbol in the upper 24 bits, type in the low 8.
    Elf32,
    /// 64-bit: symbol in the upper 32 bits, type in the low 32.
    Elf64,
    /// MIPS-64: `r_sym` (32 bits), `r_ssym`, `r_type3`, `r_type2`, `r_type`
    /// (8 bits each), in file order (Ghidra's `MIPS_Elf64Relocation`).
    Mips64 {
        /// True when the file's data encoding is little-endian.
        little_endian: bool,
    },
}

impl RelocationLayout {
    /// The layout Ghidra uses for entries read from a table of a file with
    /// this class; `mips64` is true when the MIPS extension applies.
    pub(crate) fn for_file(class: ElfClass, mips64: bool, data_endian: Endian) -> Self {
        match class {
            ElfClass::Elf32 => Self::Elf32,
            ElfClass::Elf64 if mips64 => Self::Mips64 {
                little_endian: data_endian.is_little(),
            },
            ElfClass::Elf64 => Self::Elf64,
        }
    }
}

/// One relocation (`Elf_Rel` / `Elf_Rela`, or an entry decoded from a `RELR`
/// or Android table; Ghidra's `ElfRelocation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Relocation {
    /// Where the relocation applies.
    pub r_offset: u64,
    /// Symbol index and relocation type, packed as the layout says.
    pub r_info: u64,
    /// The addend; 0 when the table has none.
    pub r_addend: i64,
    /// Index of the relocation in its table.
    pub index: u32,
    /// How `r_info` is split.
    pub layout: RelocationLayout,
    /// True when the table carries addends (`RELA`).
    pub has_addend: bool,
}

impl Relocation {
    /// Builds a relocation from decoded values, as Ghidra does for `RELR`
    /// and Android entries: in a 32-bit file the offset and info are cut to
    /// 32 bits, and the addend is kept only if the table has addends.
    pub(crate) fn from_values(
        class: ElfClass,
        index: u32,
        has_addend: bool,
        offset: u64,
        info: u64,
        addend: i64,
    ) -> Self {
        let (r_offset, r_info, layout) = match class {
            ElfClass::Elf32 => (
                u64::from(offset as u32),
                u64::from(info as u32),
                RelocationLayout::Elf32,
            ),
            ElfClass::Elf64 => (offset, info, RelocationLayout::Elf64),
        };
        Self {
            r_offset,
            r_info,
            r_addend: if has_addend { addend } else { 0 },
            index,
            layout,
            has_addend,
        }
    }

    /// `r_info` with its bytes in file order, most significant first — the
    /// form the MIPS-64 fields are cut from.
    fn mips_info(self, little_endian: bool) -> u64 {
        if little_endian {
            self.r_info.swap_bytes()
        } else {
            self.r_info
        }
    }

    /// Index of the symbol the relocation refers to.
    pub fn symbol_index(&self) -> u32 {
        match self.layout {
            RelocationLayout::Elf32 => (self.r_info >> 8) as u32,
            RelocationLayout::Elf64 => (self.r_info >> 32) as u32,
            RelocationLayout::Mips64 { little_endian } => {
                // The first four bytes of r_info, in the file's byte order.
                let first = (self.mips_info(little_endian) >> 32) as u32;
                if little_endian {
                    first.swap_bytes()
                } else {
                    first
                }
            }
        }
    }

    /// The relocation type. For MIPS-64 this packs up to three one-byte
    /// types: `r_type3 << 16 | r_type2 << 8 | r_type`.
    pub fn relocation_type(&self) -> u32 {
        match self.layout {
            RelocationLayout::Elf32 => (self.r_info & 0xff) as u32,
            RelocationLayout::Elf64 => self.r_info as u32,
            RelocationLayout::Mips64 { little_endian } => {
                (self.mips_info(little_endian) & 0xff_ffff) as u32
            }
        }
    }

    /// MIPS-64's special symbol index (`r_ssym`), used by the second of a
    /// compound relocation; `None` for every other layout.
    pub fn special_symbol_index(&self) -> Option<u8> {
        match self.layout {
            RelocationLayout::Mips64 { little_endian } => {
                Some((self.mips_info(little_endian) >> 24) as u8)
            }
            _ => None,
        }
    }

    /// Ghidra's `toString`.
    pub fn describe(&self) -> String {
        let mut text = format!(
            "Offset: 0x{:x} - Type: 0x{:x} - Symbol: 0x{:x}",
            self.r_offset,
            self.relocation_type(),
            self.symbol_index()
        );
        if self.has_addend {
            text.push_str(&format!(" - Addend: 0x{:x}", self.r_addend));
        }
        text
    }
}

/// A relocation table: where it is and how it is encoded (Ghidra's
/// `ElfRelocationTable`). Relocations are decoded on demand with
/// [`ElfFile::relocations`](crate::ElfFile::relocations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationTable {
    /// Encoding of the table.
    pub format: RelocationFormat,
    /// Index of the section the table was found through, or `None` for a
    /// table located only through the dynamic table.
    pub section: Option<u32>,
    /// File offset of the table.
    pub file_offset: u64,
    /// Address of the table in the loaded image.
    pub address: u64,
    /// Length of the table in bytes, as the file declares it.
    pub length: u64,
    /// Size of one entry: of a `REL`/`RELA` entry, or of a `RELR` word. For
    /// an Android table this is whatever the file says and is not used.
    pub entry_size: u64,
    /// True when entries carry addends (`RELA`, Android `RELA`).
    pub has_addend: bool,
    /// Index into [`ElfFile::symbol_tables`](crate::ElfFile::symbol_tables)
    /// of the symbol table the relocations refer to, if one was found.
    pub symbol_table: Option<usize>,
    /// Index of the section the relocations apply to (`sh_info`), if any.
    pub section_to_relocate: Option<u32>,
    /// True when fewer relocations can be read than the table declares.
    pub truncated: bool,
    /// How many units are read: entries of a default table, words of a
    /// `RELR` table, relocations of an Android table.
    pub(crate) units: u64,
    /// `sh_link` of the table's section, if it has one.
    pub(crate) section_link: Option<u32>,
}

impl RelocationTable {
    /// True for a `RELR` table.
    pub fn is_relr(&self) -> bool {
        self.format == RelocationFormat::Relr
    }

    /// True when the table needs a symbol table and none was found
    /// (Ghidra's `isMissingRequiredSymbolTable`): a dynamic table always
    /// needs one, a section's table when its `sh_link` is not 0.
    pub fn is_missing_required_symbol_table(&self) -> bool {
        self.symbol_table.is_none() && self.section_link.is_none_or(|link| link != 0)
    }

    /// The number of relocations, when it is known without decoding: the
    /// entries of a default table and the relocations of an Android table.
    /// `None` for `RELR`, whose relocations must be counted by iterating.
    pub fn relocation_count(&self) -> Option<u64> {
        match self.format {
            RelocationFormat::Default | RelocationFormat::Android => Some(self.units),
            RelocationFormat::Relr => None,
        }
    }

    /// Starts decoding the table. `reader` must read the file itself (not
    /// the zero-padding view) in the header byte order.
    pub(crate) fn iter<'a>(
        &self,
        reader: BinaryReader<'a>,
        class: ElfClass,
        layout: RelocationLayout,
    ) -> RelocationIter<'a> {
        match self.format {
            RelocationFormat::Default => {
                RelocationIter::Standard(StandardIter::new(reader, self, class, layout))
            }
            RelocationFormat::Relr => RelocationIter::Relr(RelrIter::new(reader, self, class)),
            RelocationFormat::Android => {
                RelocationIter::Android(AndroidIter::new(reader, self, class))
            }
        }
    }
}

/// Iterator over the relocations of a table, whatever its encoding.
#[derive(Debug, Clone)]
pub enum RelocationIter<'a> {
    /// `REL` / `RELA` entries.
    Standard(StandardIter<'a>),
    /// `RELR` addresses and bitmaps.
    Relr(RelrIter<'a>),
    /// Android packed relocations.
    Android(AndroidIter<'a>),
}

impl Iterator for RelocationIter<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Relocation> {
        match self {
            Self::Standard(iter) => iter.next(),
            Self::Relr(iter) => iter.next(),
            Self::Android(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Standard(iter) => iter.size_hint(),
            Self::Relr(iter) => iter.size_hint(),
            Self::Android(iter) => iter.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reloc(info: u64, layout: RelocationLayout) -> Relocation {
        Relocation {
            r_offset: 0x1000,
            r_info: info,
            r_addend: -8,
            index: 0,
            layout,
            has_addend: true,
        }
    }

    #[test]
    fn info_splits_by_class() {
        let r = reloc(0x0012_3407, RelocationLayout::Elf32);
        assert_eq!((r.symbol_index(), r.relocation_type()), (0x1234, 7));
        assert_eq!(r.special_symbol_index(), None);
        let r = reloc(0x0000_0005_0000_0101, RelocationLayout::Elf64);
        assert_eq!((r.symbol_index(), r.relocation_type()), (5, 0x101));
        // The whole upper half is the symbol index, even when it looks negative.
        let r = reloc(0xffff_fffe_ffff_ffff, RelocationLayout::Elf64);
        assert_eq!(
            (r.symbol_index(), r.relocation_type()),
            (0xffff_fffe, 0xffff_ffff)
        );
    }

    #[test]
    fn mips64_layout_in_both_byte_orders() {
        // File bytes: r_sym = 0x00000102, r_ssym = 0x05, types 3/2/1 = 0x12, 0x03, 0x18.
        // Big-endian file: the bytes read as one big-endian u64.
        let be_bytes = [0x00, 0x00, 0x01, 0x02, 0x05, 0x12, 0x03, 0x18];
        let r = reloc(
            u64::from_be_bytes(be_bytes),
            RelocationLayout::Mips64 {
                little_endian: false,
            },
        );
        assert_eq!(r.symbol_index(), 0x102);
        assert_eq!(r.special_symbol_index(), Some(5));
        assert_eq!(r.relocation_type(), 0x12_0318);
        // Little-endian file: r_sym is stored little-endian, the type bytes
        // keep their order; r_info was read as one little-endian u64.
        let le_bytes = [0x02, 0x01, 0x00, 0x00, 0x05, 0x12, 0x03, 0x18];
        let r = reloc(
            u64::from_le_bytes(le_bytes),
            RelocationLayout::Mips64 {
                little_endian: true,
            },
        );
        assert_eq!(r.symbol_index(), 0x102);
        assert_eq!(r.special_symbol_index(), Some(5));
        assert_eq!(r.relocation_type(), 0x12_0318);
    }

    #[test]
    fn layout_selection() {
        use Endian::{Big, Little};
        assert_eq!(
            RelocationLayout::for_file(ElfClass::Elf32, false, Little),
            RelocationLayout::Elf32
        );
        assert_eq!(
            RelocationLayout::for_file(ElfClass::Elf32, true, Little),
            RelocationLayout::Elf32
        );
        assert_eq!(
            RelocationLayout::for_file(ElfClass::Elf64, false, Big),
            RelocationLayout::Elf64
        );
        assert_eq!(
            RelocationLayout::for_file(ElfClass::Elf64, true, Big),
            RelocationLayout::Mips64 {
                little_endian: false
            }
        );
    }

    #[test]
    fn values_are_cut_to_the_class() {
        let r = Relocation::from_values(ElfClass::Elf32, 4, false, 0x1_0000_0010, 0x2_0000_0305, 9);
        assert_eq!(
            (r.r_offset, r.r_info, r.r_addend, r.index),
            (0x10, 0x305, 0, 4)
        );
        assert_eq!((r.symbol_index(), r.relocation_type()), (3, 5));
        let r = Relocation::from_values(ElfClass::Elf64, 0, true, 0x1_0000_0010, 0x2_0000_0305, -9);
        assert_eq!(
            (r.r_offset, r.r_info, r.r_addend),
            (0x1_0000_0010, 0x2_0000_0305, -9)
        );
    }

    #[test]
    fn describe_matches_ghidra() {
        let r = reloc(0x0000_0005_0000_0007, RelocationLayout::Elf64);
        assert_eq!(
            r.describe(),
            "Offset: 0x1000 - Type: 0x7 - Symbol: 0x5 - Addend: 0xfffffffffffffff8"
        );
        let r = Relocation {
            has_addend: false,
            ..r
        };
        assert_eq!(r.describe(), "Offset: 0x1000 - Type: 0x7 - Symbol: 0x5");
    }

    #[test]
    fn required_symbol_table() {
        let table = |section_link, symbol_table| RelocationTable {
            format: RelocationFormat::Default,
            section: None,
            file_offset: 0,
            address: 0,
            length: 0,
            entry_size: 8,
            has_addend: false,
            symbol_table,
            section_to_relocate: None,
            truncated: false,
            units: 3,
            section_link,
        };
        assert!(
            table(None, None).is_missing_required_symbol_table(),
            "dynamic tables need one"
        );
        assert!(table(Some(5), None).is_missing_required_symbol_table());
        assert!(!table(Some(0), None).is_missing_required_symbol_table());
        assert!(!table(None, Some(0)).is_missing_required_symbol_table());
        assert_eq!(table(None, None).relocation_count(), Some(3));
        let relr = RelocationTable {
            format: RelocationFormat::Relr,
            ..table(None, None)
        };
        assert!(relr.is_relr());
        assert_eq!(relr.relocation_count(), None);
    }
}
