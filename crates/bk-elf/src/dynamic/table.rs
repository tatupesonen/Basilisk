//! Dynamic table entries and lookups by tag.

use bk_bin::BinaryReader;

use crate::constants::DynamicTag;
use crate::header::ElfClass;

/// One entry of the dynamic table (`Elf32_Dyn` / `Elf64_Dyn`; Ghidra's
/// `ElfDynamic`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicEntry {
    /// The tag. In a 64-bit file only the low 32 bits of `d_tag` are kept,
    /// as in Ghidra.
    pub tag: DynamicTag,
    /// The value (`d_val` / `d_ptr`); how to read it is the tag's
    /// [`DynamicValueKind`](crate::DynamicValueKind).
    pub value: u64,
}

/// The dynamic table (Ghidra's `ElfDynamicTable`): the entries up to and
/// including the first `DT_NULL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicTable {
    /// File offset of the first entry.
    pub file_offset: u64,
    /// Address of the table in the loaded image.
    pub address: u64,
    /// Size of one entry in bytes: 8 in a 32-bit file, 16 in a 64-bit one.
    pub entry_size: u32,
    entries: Vec<DynamicEntry>,
}

impl DynamicTable {
    /// Reads entries at `file_offset` until `DT_NULL`.
    ///
    /// `reader` must be the file's zero-padding reader: a table that runs
    /// off the end of the file is ended by the padding, so the number of
    /// entries is bounded by the size of the file.
    pub(crate) fn parse(
        reader: &BinaryReader<'_>,
        class: ElfClass,
        file_offset: u64,
        address: u64,
    ) -> bk_bin::Result<Self> {
        let mut reader = reader.at(file_offset);
        let mut entries = Vec::new();
        loop {
            let entry = match class {
                ElfClass::Elf32 => DynamicEntry {
                    tag: DynamicTag(reader.read_u32()?),
                    value: u64::from(reader.read_u32()?),
                },
                ElfClass::Elf64 => DynamicEntry {
                    tag: DynamicTag(reader.read_u64()? as u32),
                    value: reader.read_u64()?,
                },
            };
            entries.push(entry);
            if entry.tag == DynamicTag::DT_NULL {
                break;
            }
        }
        Ok(Self {
            file_offset,
            address,
            entry_size: class.dynamic_size() as u32,
            entries,
        })
    }

    /// All entries, in file order; the last one is `DT_NULL`.
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    /// The entries with tag `tag`, in file order.
    pub fn entries_with(&self, tag: DynamicTag) -> impl Iterator<Item = &DynamicEntry> {
        self.entries.iter().filter(move |entry| entry.tag == tag)
    }

    /// The value of the first entry with tag `tag` (Ghidra's
    /// `getDynamicValue`, with `None` for its `NotFoundException`).
    pub fn value(&self, tag: DynamicTag) -> Option<u64> {
        self.entries_with(tag).next().map(|entry| entry.value)
    }

    /// True when the table has an entry with tag `tag`.
    pub fn contains(&self, tag: DynamicTag) -> bool {
        self.entries_with(tag).next().is_some()
    }

    /// Size of the table in bytes.
    pub fn length(&self) -> u64 {
        self.entries.len() as u64 * u64::from(self.entry_size)
    }
}

#[cfg(test)]
mod tests {
    use bk_bin::{Endian, MemoryProvider, UnlimitedProvider};

    use super::*;

    fn parse(
        bytes: &[u8],
        class: ElfClass,
        endian: Endian,
        offset: u64,
    ) -> bk_bin::Result<DynamicTable> {
        let memory = MemoryProvider::new(bytes);
        let unlimited = UnlimitedProvider::new(&memory);
        DynamicTable::parse(
            &BinaryReader::new(&unlimited, endian),
            class,
            offset,
            0x1000,
        )
    }

    #[test]
    fn reads_until_null_in_both_classes() {
        let mut bytes = vec![0xaa; 4];
        for (tag, value) in [(1u32, 0x10u32), (5, 0x2000), (1, 0x20), (0, 0), (99, 99)] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(value.to_le_bytes());
        }
        let t = parse(&bytes, ElfClass::Elf32, Endian::Little, 4).unwrap();
        assert_eq!(t.entries().len(), 4);
        assert_eq!(
            (t.file_offset, t.address, t.entry_size, t.length()),
            (4, 0x1000, 8, 32)
        );
        assert_eq!(
            t.value(DynamicTag::DT_NEEDED),
            Some(0x10),
            "the first entry wins"
        );
        assert_eq!(
            t.entries_with(DynamicTag::DT_NEEDED)
                .map(|e| e.value)
                .collect::<Vec<_>>(),
            [0x10, 0x20]
        );
        assert_eq!(t.value(DynamicTag::DT_STRTAB), Some(0x2000));
        assert!(t.contains(DynamicTag::DT_NULL));
        assert!(!t.contains(DynamicTag(99)));
        assert_eq!(t.value(DynamicTag::DT_SYMTAB), None);

        let mut bytes = Vec::new();
        for (tag, value) in [(0x6fff_fef5u64, 0xffff_ffff_0000_0001u64), (0, 0)] {
            bytes.extend(tag.to_be_bytes());
            bytes.extend(value.to_be_bytes());
        }
        let t = parse(&bytes, ElfClass::Elf64, Endian::Big, 0).unwrap();
        assert_eq!(t.entries().len(), 2);
        assert_eq!(t.entry_size, 16);
        assert_eq!(
            t.value(DynamicTag::DT_GNU_HASH),
            Some(0xffff_ffff_0000_0001)
        );
    }

    #[test]
    fn end_of_file_terminates_the_table() {
        // No DT_NULL: the zero padding supplies one; a partial last entry
        // is zero-extended.
        let mut bytes = Vec::new();
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(7u32.to_le_bytes());
        bytes.extend(14u32.to_le_bytes());
        bytes.extend([9u8, 0]); // half a value
        let t = parse(&bytes, ElfClass::Elf32, Endian::Little, 0).unwrap();
        assert_eq!(
            t.entries(),
            [
                DynamicEntry {
                    tag: DynamicTag::DT_NEEDED,
                    value: 7
                },
                DynamicEntry {
                    tag: DynamicTag::DT_SONAME,
                    value: 9
                },
                DynamicEntry {
                    tag: DynamicTag::DT_NULL,
                    value: 0
                },
            ]
        );
        // Entirely past the end: a single DT_NULL.
        let t = parse(&bytes, ElfClass::Elf64, Endian::Little, 1 << 40).unwrap();
        assert_eq!(t.entries().len(), 1);
    }

    #[test]
    fn upper_half_of_a_64_bit_tag_is_dropped() {
        let mut bytes = Vec::new();
        bytes.extend(0x1_0000_0001u64.to_le_bytes());
        bytes.extend(5u64.to_le_bytes());
        // 2³² as a tag truncates to DT_NULL and ends the table.
        bytes.extend(0x1_0000_0000u64.to_le_bytes());
        bytes.extend(6u64.to_le_bytes());
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(7u64.to_le_bytes());
        let t = parse(&bytes, ElfClass::Elf64, Endian::Little, 0).unwrap();
        assert_eq!(t.entries().len(), 2);
        assert_eq!(t.value(DynamicTag::DT_NEEDED), Some(5));
    }

    #[test]
    fn offsets_java_sees_as_negative_fail() {
        assert!(parse(&[0u8; 16], ElfClass::Elf32, Endian::Little, u64::MAX - 3).is_err());
    }
}
