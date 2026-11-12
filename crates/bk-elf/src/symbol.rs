//! Symbols and symbol tables.

use bk_bin::{BinaryReader, Endian};

use crate::constants::{SHN_ABS, SHN_COMMON, SHN_HIPROC, SHN_LOPROC, SHN_UNDEF, SHN_XINDEX};
use crate::header::ElfClass;

/// Symbol binding: local.
pub const STB_LOCAL: u8 = 0;
/// Symbol binding: global.
pub const STB_GLOBAL: u8 = 1;
/// Symbol binding: weak.
pub const STB_WEAK: u8 = 2;
/// Symbol binding: unique (GNU extension).
pub const STB_GNU_UNIQUE: u8 = 10;

/// Symbol type: unspecified.
pub const STT_NOTYPE: u8 = 0;
/// Symbol type: data object.
pub const STT_OBJECT: u8 = 1;
/// Symbol type: function.
pub const STT_FUNC: u8 = 2;
/// Symbol type: section.
pub const STT_SECTION: u8 = 3;
/// Symbol type: source file.
pub const STT_FILE: u8 = 4;
/// Symbol type: common data object.
pub const STT_COMMON: u8 = 5;
/// Symbol type: thread-local storage.
pub const STT_TLS: u8 = 6;
/// Symbol type: complex relocation expression.
pub const STT_RELC: u8 = 8;
/// Symbol type: signed complex relocation expression.
pub const STT_SRELC: u8 = 9;

/// Symbol visibility: default.
pub const STV_DEFAULT: u8 = 0;
/// Symbol visibility: internal.
pub const STV_INTERNAL: u8 = 1;
/// Symbol visibility: hidden.
pub const STV_HIDDEN: u8 = 2;
/// Symbol visibility: protected.
pub const STV_PROTECTED: u8 = 3;

/// What Ghidra shows for a symbol without a name.
pub const FORMATTED_NO_NAME: &str = "<no name>";

/// A symbol table entry (`Elf32_Sym` / `Elf64_Sym`; Ghidra's `ElfSymbol`).
///
/// The name is not stored; it is read on demand with
/// [`ElfFile::symbol_name`](crate::ElfFile::symbol_name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Symbol {
    /// Value: usually an address.
    pub st_value: u64,
    /// Size of the object the symbol names.
    pub st_size: u64,
    /// Index of the symbol in its table.
    pub index: u32,
    /// Offset of the name in the table's string table.
    pub st_name: u32,
    /// Index of the section the symbol is defined in, or a reserved value.
    pub st_shndx: u16,
    /// Binding (upper four bits) and type (lower four bits).
    pub st_info: u8,
    /// Visibility in the lower two bits.
    pub st_other: u8,
}

impl Symbol {
    /// Decodes one entry from the first 16 (32-bit) or 24 (64-bit) bytes of
    /// `bytes`; bytes that are missing are taken as zero.
    pub(crate) fn decode(bytes: &[u8], class: ElfClass, endian: Endian, index: u32) -> Self {
        let mut raw = [0u8; 24];
        let len = bytes.len().min(raw.len());
        if let (Some(dst), Some(src)) = (raw.get_mut(..len), bytes.get(..len)) {
            dst.copy_from_slice(src);
        }
        let r = BinaryReader::from_slice(&raw, endian);
        let u32_at = |i| r.read_u32_at(i).unwrap_or(0);
        let u64_at = |i| r.read_u64_at(i).unwrap_or(0);
        let u16_at = |i| r.read_u16_at(i).unwrap_or(0);
        match class {
            ElfClass::Elf32 => Self {
                index,
                st_name: u32_at(0),
                st_value: u64::from(u32_at(4)),
                st_size: u64::from(u32_at(8)),
                st_info: raw[12],
                st_other: raw[13],
                st_shndx: u16_at(14),
            },
            ElfClass::Elf64 => Self {
                index,
                st_name: u32_at(0),
                st_info: raw[4],
                st_other: raw[5],
                st_shndx: u16_at(6),
                st_value: u64_at(8),
                st_size: u64_at(16),
            },
        }
    }

    /// The binding (`STB_…`): the upper four bits of `st_info`.
    ///
    /// Ghidra computes this with a signed shift, which turns bindings of 8
    /// and above — `STB_GNU_UNIQUE` among them — into negative numbers; here
    /// they keep their value.
    pub const fn bind(&self) -> u8 {
        self.st_info >> 4
    }

    /// The type (`STT_…`): the lower four bits of `st_info`.
    pub const fn symbol_type(&self) -> u8 {
        self.st_info & 0xf
    }

    /// The visibility (`STV_…`): the lower two bits of `st_other`.
    pub const fn visibility(&self) -> u8 {
        self.st_other & 0x3
    }

    /// True for a local symbol.
    pub const fn is_local(&self) -> bool {
        self.bind() == STB_LOCAL
    }

    /// True for a global symbol.
    pub const fn is_global(&self) -> bool {
        self.bind() == STB_GLOBAL
    }

    /// True for a weak symbol.
    pub const fn is_weak(&self) -> bool {
        self.bind() == STB_WEAK
    }

    /// True for a global or weak symbol that is not defined in this file.
    pub const fn is_external(&self) -> bool {
        (self.is_global() || self.is_weak()) && self.st_shndx == SHN_UNDEF
    }

    /// True for a symbol without a type.
    pub const fn is_no_type(&self) -> bool {
        self.symbol_type() == STT_NOTYPE
    }

    /// True for a section symbol.
    pub const fn is_section(&self) -> bool {
        self.symbol_type() == STT_SECTION
    }

    /// True for a function symbol.
    pub const fn is_function(&self) -> bool {
        self.symbol_type() == STT_FUNC
    }

    /// True for a data object symbol.
    pub const fn is_object(&self) -> bool {
        self.symbol_type() == STT_OBJECT
    }

    /// True for a source file symbol.
    pub const fn is_file(&self) -> bool {
        self.symbol_type() == STT_FILE
    }

    /// True for a thread-local storage symbol.
    pub const fn is_tls(&self) -> bool {
        self.symbol_type() == STT_TLS
    }

    /// True when the symbol's value is absolute (`SHN_ABS`).
    pub const fn is_absolute(&self) -> bool {
        self.st_shndx == SHN_ABS
    }

    /// True for a common symbol (`SHN_COMMON`).
    pub const fn is_common(&self) -> bool {
        self.st_shndx == SHN_COMMON
    }

    /// True when `st_shndx` lies in the processor-specific reserved range.
    pub const fn has_processor_specific_section_index(&self) -> bool {
        self.st_shndx >= SHN_LOPROC && self.st_shndx <= SHN_HIPROC
    }

    /// True when the real section index is in the table's extended section
    /// index table (`st_shndx` is `SHN_XINDEX`).
    pub const fn has_extended_section_index(&self) -> bool {
        self.st_shndx == SHN_XINDEX
    }

    /// Ghidra's `toString`, given the symbol's name.
    pub fn describe(&self, name: &str) -> String {
        format!(
            "{name} - st_value: 0x{:x} - st_size: 0x{:x} - st_info: 0x{:x} - st_other: 0x{:x} - \
             st_shndx: 0x{:x}",
            self.st_value, self.st_size, self.st_info, self.st_other, self.st_shndx
        )
    }
}

/// Where a symbol table's extended section indexes are (`SHT_SYMTAB_SHNDX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionIndexTable {
    /// Index of the `SHT_SYMTAB_SHNDX` section.
    pub section: u32,
    /// File offset of the first 32-bit index.
    pub file_offset: u64,
    /// Number of indexes that can be read.
    pub count: u32,
}

/// A symbol table: where it is and how many symbols it has (Ghidra's
/// `ElfSymbolTable`). Symbols are decoded on demand with
/// [`ElfFile::symbols`](crate::ElfFile::symbols).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTable {
    /// Index of the `SHT_SYMTAB` or `SHT_DYNSYM` section, or `None` for a
    /// dynamic symbol table located through `DT_SYMTAB`.
    pub section: Option<u32>,
    /// File offset of the first symbol.
    pub file_offset: u64,
    /// Address of the table in the loaded image.
    pub address: u64,
    /// Size of one entry in bytes; at least the size the class requires.
    pub entry_size: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// True when the table declares more symbols than the file holds, or
    /// its last symbol is only partly in the file.
    pub truncated: bool,
    /// Index into [`ElfFile::string_tables`](crate::ElfTables::string_tables)
    /// of the table holding the names, if one was found.
    pub string_table: Option<usize>,
    /// The extended section index table linked to this table, if any.
    pub section_index_table: Option<SectionIndexTable>,
    /// True for the dynamic symbol table: a section named `.dynsym`, or the
    /// table located through `DT_SYMTAB`.
    pub is_dynamic: bool,
}

impl SymbolTable {
    /// Size of the table in bytes.
    pub fn length(&self) -> u64 {
        u64::from(self.entry_size) * u64::from(self.symbol_count)
    }

    /// True when `entry_size` is usable for a file of class `class`: at
    /// least the standard size, and small enough for a Java `int`.
    pub(crate) fn is_valid_entry_size(class: ElfClass, entry_size: u64) -> bool {
        entry_size >= class.symbol_size() && i32::try_from(entry_size).is_ok()
    }
}

/// Iterator over the symbols of a table, decoding from the file as it goes.
///
/// Created by [`ElfFile::symbols`](crate::ElfFile::symbols). A symbol that
/// is only partly in the file is completed with zero bytes, as in Ghidra.
#[derive(Debug, Clone)]
pub struct SymbolIter<'a> {
    reader: BinaryReader<'a>,
    class: ElfClass,
    file_offset: u64,
    entry_size: u64,
    next: u32,
    count: u32,
}

impl<'a> SymbolIter<'a> {
    pub(crate) fn new(reader: BinaryReader<'a>, class: ElfClass, table: &SymbolTable) -> Self {
        Self {
            reader,
            class,
            file_offset: table.file_offset,
            entry_size: u64::from(table.entry_size),
            next: 0,
            count: table.symbol_count,
        }
    }

    /// Decodes the symbol with index `index`, if the table has it.
    pub(crate) fn get(&self, index: u32) -> Option<Symbol> {
        if index >= self.count {
            return None;
        }
        let offset = self
            .file_offset
            .checked_add(u64::from(index).checked_mul(self.entry_size)?)?;
        let endian = self.reader.endian();
        let symbol = match self.class {
            ElfClass::Elf32 => {
                let bytes = self.reader.read_array_at::<16>(offset).ok()?;
                Symbol::decode(&bytes, self.class, endian, index)
            }
            ElfClass::Elf64 => {
                let bytes = self.reader.read_array_at::<24>(offset).ok()?;
                Symbol::decode(&bytes, self.class, endian, index)
            }
        };
        Some(symbol)
    }
}

impl Iterator for SymbolIter<'_> {
    type Item = Symbol;

    fn next(&mut self) -> Option<Symbol> {
        let symbol = self.get(self.next)?;
        self.next += 1;
        Some(symbol)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.next) as usize;
        (remaining, Some(remaining))
    }

    fn nth(&mut self, n: usize) -> Option<Symbol> {
        let skip = u32::try_from(n).unwrap_or(u32::MAX);
        self.next = self.next.saturating_add(skip).min(self.count);
        self.next()
    }
}

impl ExactSizeIterator for SymbolIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_both_layouts() {
        // Elf32_Sym: name, value, size, info, other, shndx.
        let mut b = Vec::new();
        b.extend(0x11u32.to_le_bytes());
        b.extend(0x0804_8000u32.to_le_bytes());
        b.extend(0x40u32.to_le_bytes());
        b.extend([0x12, 0x02]);
        b.extend(7u16.to_le_bytes());
        let s = Symbol::decode(&b, ElfClass::Elf32, Endian::Little, 3);
        assert_eq!(
            s,
            Symbol {
                index: 3,
                st_name: 0x11,
                st_value: 0x804_8000,
                st_size: 0x40,
                st_info: 0x12,
                st_other: 2,
                st_shndx: 7
            }
        );
        // Elf64_Sym: name, info, other, shndx, value, size — big-endian.
        let mut b = Vec::new();
        b.extend(0x11u32.to_be_bytes());
        b.extend([0xa1, 0x03]);
        b.extend(0xfff1u16.to_be_bytes());
        b.extend(0xffff_ffff_8000_0000u64.to_be_bytes());
        b.extend(0x1_0000_0000u64.to_be_bytes());
        let s = Symbol::decode(&b, ElfClass::Elf64, Endian::Big, 0);
        assert_eq!(
            s,
            Symbol {
                index: 0,
                st_name: 0x11,
                st_value: 0xffff_ffff_8000_0000,
                st_size: 0x1_0000_0000,
                st_info: 0xa1,
                st_other: 3,
                st_shndx: 0xfff1
            }
        );
        // Missing bytes are zero.
        let s = Symbol::decode(&b[..6], ElfClass::Elf64, Endian::Big, 1);
        assert_eq!(
            (s.st_name, s.st_info, s.st_other, s.st_shndx, s.st_value),
            (0x11, 0xa1, 3, 0, 0)
        );
        assert_eq!(
            Symbol::decode(&[], ElfClass::Elf32, Endian::Little, 9),
            Symbol {
                index: 9,
                ..Symbol::default()
            }
        );
    }

    #[test]
    fn info_accessors() {
        let sym = |info: u8, other: u8, shndx: u16| Symbol {
            st_info: info,
            st_other: other,
            st_shndx: shndx,
            ..Symbol::default()
        };
        let s = sym((STB_GLOBAL << 4) | STT_FUNC, STV_HIDDEN, SHN_UNDEF);
        assert_eq!(
            (s.bind(), s.symbol_type(), s.visibility()),
            (STB_GLOBAL, STT_FUNC, STV_HIDDEN)
        );
        assert!(s.is_global() && s.is_function() && s.is_external());
        assert!(!s.is_local() && !s.is_weak() && !s.is_object() && !s.is_section());
        let s = sym((STB_WEAK << 4) | STT_OBJECT, 0xff, 5);
        assert!(s.is_weak() && s.is_object() && !s.is_external());
        assert_eq!(s.visibility(), STV_PROTECTED);
        let s = sym((STB_LOCAL << 4) | STT_SECTION, 0, 1);
        assert!(s.is_local() && s.is_section() && !s.is_external());
        assert!(sym(STT_FILE, 0, SHN_ABS).is_file() && sym(STT_FILE, 0, SHN_ABS).is_absolute());
        assert!(sym(STT_TLS, 0, 0).is_tls());
        assert!(sym(STT_NOTYPE, 0, SHN_COMMON).is_no_type() && sym(0, 0, SHN_COMMON).is_common());
        // A binding of 10 stays 10 (Ghidra's signed shift makes it negative).
        assert_eq!(
            sym((STB_GNU_UNIQUE << 4) | STT_OBJECT, 0, 1).bind(),
            STB_GNU_UNIQUE
        );
        assert!(sym(0, 0, 0xff00).has_processor_specific_section_index());
        assert!(sym(0, 0, 0xff1f).has_processor_specific_section_index());
        assert!(!sym(0, 0, 0xff20).has_processor_specific_section_index());
        assert!(sym(0, 0, SHN_XINDEX).has_extended_section_index());
    }

    #[test]
    fn describe_matches_ghidra() {
        let s = Symbol {
            st_value: 0x1000,
            st_size: 0x20,
            st_info: 0x12,
            st_other: 0,
            st_shndx: 0xfff1,
            ..Symbol::default()
        };
        assert_eq!(
            s.describe("main"),
            "main - st_value: 0x1000 - st_size: 0x20 - st_info: 0x12 - st_other: 0x0 - st_shndx: 0xfff1"
        );
    }

    #[test]
    fn entry_size_rules() {
        assert!(SymbolTable::is_valid_entry_size(ElfClass::Elf32, 16));
        assert!(
            SymbolTable::is_valid_entry_size(ElfClass::Elf32, 20),
            "larger entries are allowed"
        );
        assert!(!SymbolTable::is_valid_entry_size(ElfClass::Elf32, 15));
        assert!(SymbolTable::is_valid_entry_size(ElfClass::Elf64, 24));
        assert!(!SymbolTable::is_valid_entry_size(ElfClass::Elf64, 16));
        assert!(!SymbolTable::is_valid_entry_size(ElfClass::Elf64, 1 << 31));
        assert!(!SymbolTable::is_valid_entry_size(ElfClass::Elf64, u64::MAX));
    }

    #[test]
    fn iteration_reads_entries_of_any_size_and_pads_the_last() {
        // Three 20-byte entries (4 bytes of padding each); the file ends in
        // the middle of the third.
        let mut data = vec![0u8; 8];
        for i in 0..3u32 {
            data.extend((i + 1).to_le_bytes());
            data.extend((0x100 * (i + 1)).to_le_bytes());
            data.extend(4u32.to_le_bytes());
            data.extend([0x12, 0]);
            data.extend(1u16.to_le_bytes());
            data.extend([0xee; 4]);
        }
        data.truncate(8 + 20 + 20 + 6);
        let memory = bk_bin::MemoryProvider::new(data);
        let unlimited = bk_bin::UnlimitedProvider::new(&memory);
        let table = SymbolTable {
            section: None,
            file_offset: 8,
            address: 0,
            entry_size: 20,
            symbol_count: 3,
            truncated: true,
            string_table: None,
            section_index_table: None,
            is_dynamic: false,
        };
        assert_eq!(table.length(), 60);
        let iter = SymbolIter::new(
            BinaryReader::new(&unlimited, Endian::Little),
            ElfClass::Elf32,
            &table,
        );
        assert_eq!(iter.len(), 3);
        let symbols: Vec<Symbol> = iter.clone().collect();
        assert_eq!(
            symbols.iter().map(|s| s.st_name).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            symbols.iter().map(|s| s.st_value).collect::<Vec<_>>(),
            [0x100, 0x200, 0x300 & 0xffff]
        );
        assert_eq!(
            symbols[2].st_size, 0,
            "bytes past the end of the file read as zero"
        );
        assert_eq!(
            symbols.iter().map(|s| s.index).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(iter.get(1), Some(symbols[1]));
        assert_eq!(iter.get(3), None);
        let mut skipping = iter.clone();
        assert_eq!(skipping.nth(2).map(|s| s.index), Some(2));
        assert_eq!(skipping.next(), None);
        assert_eq!(iter.clone().nth(7), None);
    }
}
