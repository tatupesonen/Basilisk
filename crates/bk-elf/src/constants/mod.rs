//! ELF constants: identification values, file types, machines, section and
//! segment types and flags, dynamic tags.
//!
//! Values that select behaviour or names are newtypes over the raw integer
//! with associated constants ([`SectionType::SHT_SYMTAB`],
//! [`Machine::EM_ARM`], …), not closed enums: a value this crate has no
//! name for is preserved, never rejected. Which values have names, and the
//! names and descriptions themselves, are Ghidra's (`ElfConstants`,
//! `ElfSectionHeaderType`, `ElfProgramHeaderType`, `ElfDynamicType` and the
//! processor extensions); the tables are generated from its sources by
//! `gen/gen_tables.py`.

use std::borrow::Cow;
use std::fmt;

use crate::machine::MachineExtension;

mod generated;
mod machines;

/// The ELF magic number: `\x7fELF`.
pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// Size of the identification area (`e_ident`).
pub const EI_NIDENT: usize = 16;
/// Index of the file class in `e_ident`.
pub const EI_CLASS: usize = 4;
/// Index of the data encoding in `e_ident`.
pub const EI_DATA: usize = 5;
/// Index of the file version in `e_ident`.
pub const EI_VERSION: usize = 6;
/// Index of the OS/ABI identification in `e_ident`.
pub const EI_OSABI: usize = 7;
/// Index of the ABI version in `e_ident`.
pub const EI_ABIVERSION: usize = 8;
/// Index of the first padding byte in `e_ident`.
pub const EI_PAD: usize = 9;

/// `e_ident[EI_CLASS]`: invalid class.
pub const ELFCLASSNONE: u8 = 0;
/// `e_ident[EI_CLASS]`: 32-bit objects.
pub const ELFCLASS32: u8 = 1;
/// `e_ident[EI_CLASS]`: 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// `e_ident[EI_DATA]`: invalid byte order.
pub const ELFDATANONE: u8 = 0;
/// `e_ident[EI_DATA]`: little-endian.
pub const ELFDATA2LSB: u8 = 1;
/// `e_ident[EI_DATA]`: big-endian.
pub const ELFDATA2MSB: u8 = 2;
/// File version: invalid.
pub const EV_NONE: u8 = 0;
/// File version: current.
pub const EV_CURRENT: u8 = 1;

/// `e_phnum` value meaning the real count is in section 0's `sh_info`.
pub const PN_XNUM: u16 = 0xffff;
/// In a 32-bit file, an offset of all ones marks "no offset".
pub const ELF32_INVALID_OFFSET: u64 = 0xffff_ffff;
/// The largest file offset Ghidra accepts anywhere (2⁴⁷ − 1).
pub const FILE_OFFSET_HARD_LIMIT: u64 = 0x0000_7fff_ffff_ffff;

/// Name of the global offset table symbol.
pub const GOT_SYMBOL_NAME: &str = "_GLOBAL_OFFSET_TABLE_";

/// Segment flag: executable.
pub const PF_X: u32 = 1 << 0;
/// Segment flag: writable.
pub const PF_W: u32 = 1 << 1;
/// Segment flag: readable.
pub const PF_R: u32 = 1 << 2;
/// Segment flag bits reserved for the operating system.
pub const PF_MASKOS: u32 = 0x0ff0_0000;
/// Segment flag bits reserved for the processor.
pub const PF_MASKPROC: u32 = 0xf000_0000;

/// Section flag: writable.
pub const SHF_WRITE: u64 = 0x1;
/// Section flag: occupies memory during execution.
pub const SHF_ALLOC: u64 = 0x2;
/// Section flag: executable.
pub const SHF_EXECINSTR: u64 = 0x4;
/// Section flag: may be merged.
pub const SHF_MERGE: u64 = 0x10;
/// Section flag: contains NUL-terminated strings.
pub const SHF_STRINGS: u64 = 0x20;
/// Section flag: `sh_info` holds a section index.
pub const SHF_INFO_LINK: u64 = 0x40;
/// Section flag: preserve order after combining.
pub const SHF_LINK_ORDER: u64 = 0x80;
/// Section flag: non-standard OS-specific handling required.
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
/// Section flag: member of a group.
pub const SHF_GROUP: u64 = 0x200;
/// Section flag: holds thread-local data.
pub const SHF_TLS: u64 = 0x400;
/// Section flag: holds compressed data.
pub const SHF_COMPRESSED: u64 = 0x800;
/// Section flag: excluded unless referenced or allocated.
pub const SHF_EXCLUDE: u64 = 0x8000_0000;
/// Section flag bits reserved for the operating system.
pub const SHF_MASKOS: u64 = 0x0ff0_0000;
/// Section flag bits reserved for the processor.
pub const SHF_MASKPROC: u64 = 0xf000_0000;

/// Section index: undefined.
pub const SHN_UNDEF: u16 = 0x0000;
/// Section index: start of the reserved range.
pub const SHN_LORESERVE: u16 = 0xff00;
/// Section index: start of the processor-specific range.
pub const SHN_LOPROC: u16 = 0xff00;
/// Section index: end of the processor-specific range.
pub const SHN_HIPROC: u16 = 0xff1f;
/// Section index: start of the OS-specific range.
pub const SHN_LOOS: u16 = 0xff20;
/// Section index: end of the OS-specific range.
pub const SHN_HIOS: u16 = 0xff3f;
/// Section index: absolute value.
pub const SHN_ABS: u16 = 0xfff1;
/// Section index: common symbol.
pub const SHN_COMMON: u16 = 0xfff2;
/// Section index: the real index is in the `SHT_SYMTAB_SHNDX` table.
pub const SHN_XINDEX: u16 = 0xffff;
/// Section index: end of the reserved range.
pub const SHN_HIRESERVE: u16 = 0xffff;

/// `DT_FLAGS` bit: `$ORIGIN` processing required.
pub const DF_ORIGIN: u64 = 0x1;
/// `DT_FLAGS` bit: symbolic symbol resolution required.
pub const DF_SYMBOLIC: u64 = 0x2;
/// `DT_FLAGS` bit: text relocations exist.
pub const DF_TEXTREL: u64 = 0x4;
/// `DT_FLAGS` bit: non-lazy binding required.
pub const DF_BIND_NOW: u64 = 0x8;
/// `DT_FLAGS` bit: object uses the static TLS scheme.
pub const DF_STATIC_TLS: u64 = 0x10;
/// `DT_FLAGS_1` bit: perform complete relocation processing.
pub const DF_1_NOW: u64 = 0x1;
/// `DT_FLAGS_1` bit: unused.
pub const DF_1_GLOBAL: u64 = 0x2;
/// `DT_FLAGS_1` bit: member of a group.
pub const DF_1_GROUP: u64 = 0x4;
/// `DT_FLAGS_1` bit: cannot be deleted from a process.
pub const DF_1_NODELETE: u64 = 0x8;
/// `DT_FLAGS_1` bit: ensure immediate loading of filtees.
pub const DF_1_LOADFLTR: u64 = 0x10;
/// `DT_FLAGS_1` bit: initialise first.
pub const DF_1_INITFIRST: u64 = 0x20;
/// `DT_FLAGS_1` bit: cannot be used with `dlopen`.
pub const DF_1_NOOPEN: u64 = 0x40;
/// `DT_FLAGS_1` bit: `$ORIGIN` processing required.
pub const DF_1_ORIGIN: u64 = 0x80;
/// `DT_FLAGS_1` bit: direct bindings enabled.
pub const DF_1_DIRECT: u64 = 0x100;
/// `DT_FLAGS_1` bit: object is an interposer.
pub const DF_1_INTERPOSE: u64 = 0x400;
/// `DT_FLAGS_1` bit: ignore the default library search path.
pub const DF_1_NODEFLIB: u64 = 0x800;

/// A named type value: one row of Ghidra's `ElfSectionHeaderType` or
/// `ElfProgramHeaderType` tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeInfo {
    /// The value.
    pub value: u32,
    /// Its name, for example `SHT_PROGBITS`.
    pub name: &'static str,
    /// A one-line description; may be empty.
    pub description: &'static str,
}

/// How the value of a dynamic entry is to be read (Ghidra's
/// `ElfDynamicValueType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicValueKind {
    /// A plain number.
    Value,
    /// An address in the loaded image.
    Address,
    /// An offset into the dynamic string table.
    String,
}

/// A named dynamic tag: one row of Ghidra's `ElfDynamicType` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicTagInfo {
    /// The tag value.
    pub value: u32,
    /// Its name, for example `DT_NEEDED`.
    pub name: &'static str,
    /// A one-line description; may be empty.
    pub description: &'static str,
    /// How the entry's value is to be read.
    pub kind: DynamicValueKind,
}

macro_rules! newtype {
    ($(#[$meta:meta])* $name:ident($inner:ty), $width:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub $inner);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:#0", $width, "x})"), self.0)
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

newtype!(
    /// The target architecture, `e_machine`.
    Machine(u16),
    6
);
newtype!(
    /// The object file type, `e_type`.
    ElfType(u16),
    6
);
newtype!(
    /// The operating system / ABI identification, `e_ident[EI_OSABI]`.
    OsAbi(u8),
    4
);
newtype!(
    /// A section type, `sh_type`.
    SectionType(u32),
    10
);
newtype!(
    /// A segment type, `p_type`.
    SegmentType(u32),
    10
);
newtype!(
    /// A dynamic table tag, `d_tag`.
    ///
    /// Ghidra keeps the tag as a 32-bit value; in a 64-bit file the upper
    /// half of `d_tag` is dropped when the entry is read.
    DynamicTag(u32),
    10
);

impl ElfType {
    /// No file type.
    pub const ET_NONE: Self = Self(0);
    /// Relocatable file.
    pub const ET_REL: Self = Self(1);
    /// Executable file.
    pub const ET_EXEC: Self = Self(2);
    /// Shared object file.
    pub const ET_DYN: Self = Self(3);
    /// Core file.
    pub const ET_CORE: Self = Self(4);
    /// Start of the processor-specific range.
    pub const ET_LOPROC: Self = Self(0xff00);
    /// End of the processor-specific range.
    pub const ET_HIPROC: Self = Self(0xffff);
}

impl Machine {
    /// Ghidra's name for this machine (for example `EM_X86_64`), if it has one.
    pub fn name(self) -> Option<&'static str> {
        machines::MACHINES
            .iter()
            .find(|m| m.0 == self.0)
            .map(|m| m.1)
    }

    /// Ghidra's description of this machine (for example "AMD x86-64
    /// architecture"), if it has one.
    pub fn description(self) -> Option<&'static str> {
        machines::MACHINES
            .iter()
            .find(|m| m.0 == self.0)
            .map(|m| m.2)
    }

    /// Every machine Ghidra names, as `(value, name, description)`.
    pub fn all() -> impl Iterator<Item = (Self, &'static str, &'static str)> {
        machines::MACHINES
            .iter()
            .map(|&(value, name, description)| (Self(value), name, description))
    }
}

fn find_type(
    value: u32,
    defaults: &'static [TypeInfo],
    extension: &'static [TypeInfo],
) -> Option<&'static TypeInfo> {
    // Ghidra registers the defaults first and refuses an extension type
    // whose value is already taken, so the defaults win.
    defaults
        .iter()
        .chain(extension)
        .find(|info| info.value == value)
}

impl SectionType {
    /// The table row for this type: Ghidra's defaults, then the processor
    /// extension's types.
    pub fn info(self, extension: Option<&'static MachineExtension>) -> Option<&'static TypeInfo> {
        find_type(
            self.0,
            generated::SECTION_TYPES,
            extension.map_or(&[], |e| e.section_types),
        )
    }

    /// The type's name, or `SHT_0x%08x` for a value without one (Ghidra's
    /// `getTypeAsString`).
    pub fn name(self, extension: Option<&'static MachineExtension>) -> Cow<'static, str> {
        self.info(extension).map_or_else(
            || Cow::Owned(format!("SHT_0x{:08x}", self.0)),
            |i| Cow::Borrowed(i.name),
        )
    }

    /// The types Ghidra names for every machine.
    pub fn defaults() -> &'static [TypeInfo] {
        generated::SECTION_TYPES
    }
}

impl SegmentType {
    /// The table row for this type: Ghidra's defaults, then the processor
    /// extension's types.
    pub fn info(self, extension: Option<&'static MachineExtension>) -> Option<&'static TypeInfo> {
        find_type(
            self.0,
            generated::SEGMENT_TYPES,
            extension.map_or(&[], |e| e.segment_types),
        )
    }

    /// The type's name, or `PT_0x%08x` for a value without one (Ghidra's
    /// `getTypeAsString`).
    pub fn name(self, extension: Option<&'static MachineExtension>) -> Cow<'static, str> {
        self.info(extension).map_or_else(
            || Cow::Owned(format!("PT_0x{:08x}", self.0)),
            |i| Cow::Borrowed(i.name),
        )
    }

    /// The types Ghidra names for every machine.
    pub fn defaults() -> &'static [TypeInfo] {
        generated::SEGMENT_TYPES
    }
}

impl DynamicTag {
    /// The table row for this tag: Ghidra's defaults, then the processor
    /// extension's tags.
    pub fn info(
        self,
        extension: Option<&'static MachineExtension>,
    ) -> Option<&'static DynamicTagInfo> {
        generated::DYNAMIC_TAGS
            .iter()
            .chain(extension.map_or(&[][..], |e| e.dynamic_tags))
            .find(|info| info.value == self.0)
    }

    /// The tag's name, or `DT_0x%08x` for a value without one (Ghidra's
    /// `getTagAsString`).
    pub fn name(self, extension: Option<&'static MachineExtension>) -> Cow<'static, str> {
        self.info(extension).map_or_else(
            || Cow::Owned(format!("DT_0x{:08x}", self.0)),
            |i| Cow::Borrowed(i.name),
        )
    }

    /// The tags Ghidra names for every machine.
    pub fn defaults() -> &'static [DynamicTagInfo] {
        generated::DYNAMIC_TAGS
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::machine;

    #[test]
    fn generated_tables_have_the_expected_shape() {
        // Counts taken from Ghidra 42db038f3c; a change here means the
        // generator or the pinned Ghidra changed.
        assert_eq!(Machine::all().count(), 197);
        assert_eq!(SectionType::defaults().len(), 29);
        assert_eq!(SegmentType::defaults().len(), 11);
        assert_eq!(DynamicTag::defaults().len(), 76);
    }

    #[test]
    fn default_tables_have_unique_values_and_names() {
        // Ghidra enforces this at class-initialisation time.
        fn check(rows: impl Iterator<Item = (u32, &'static str)>) {
            let (mut values, mut names) = (HashSet::new(), HashSet::new());
            for (value, name) in rows {
                assert!(values.insert(value), "duplicate value {value:#x} ({name})");
                assert!(
                    names.insert(name.to_ascii_lowercase()),
                    "duplicate name {name}"
                );
            }
        }
        check(SectionType::defaults().iter().map(|i| (i.value, i.name)));
        check(SegmentType::defaults().iter().map(|i| (i.value, i.name)));
        check(DynamicTag::defaults().iter().map(|i| (i.value, i.name)));
    }

    #[test]
    fn well_known_values() {
        assert_eq!(Machine::EM_386.0, 3);
        assert_eq!(Machine::EM_ARM.0, 40);
        assert_eq!(Machine::EM_X86_64.0, 62);
        assert_eq!(Machine::EM_AARCH64.0, 183);
        assert_eq!(Machine::EM_RISCV.0, 243);
        assert_eq!(Machine::EM_AVR32_UNOFFICIAL.0, 0x18ad);
        assert_eq!(Machine::EM_X86_64.name(), Some("EM_X86_64"));
        assert_eq!(Machine::EM_M32.description(), Some("AT&T WE 32100"));
        assert_eq!(Machine(0x7777).name(), None);
        assert_eq!(Machine(0x7777).description(), None);
        assert_eq!(SectionType::SHT_SYMTAB.0, 2);
        assert_eq!(SectionType::SHT_RELR.0, 19);
        assert_eq!(SectionType::SHT_GNU_VERSYM.0, 0x6fff_ffff);
        assert_eq!(SegmentType::PT_GNU_RELRO.0, 0x6474_e552);
        assert_eq!(DynamicTag::DT_NEEDED.0, 1);
        assert_eq!(DynamicTag::DT_GNU_HASH.0, 0x6fff_fef5);
        assert_eq!(DynamicTag::DT_ANDROID_RELA.0, 0x6000_0011);
        assert_eq!(OsAbi::ELFOSABI_LINUX.0, 3);
        assert_eq!(OsAbi::ELFOSABI_STANDALONE.0, 255);
        assert_eq!(ElfType::ET_DYN.0, 3);
    }

    #[test]
    fn names_fall_back_to_hex() {
        assert_eq!(SectionType::SHT_PROGBITS.name(None), "SHT_PROGBITS");
        assert_eq!(SectionType::SHT_GNU_VERDEF.name(None), "SHT_GNU_verdef");
        // Ghidra has a constant for SHT_RELR but no named type.
        assert_eq!(SectionType::SHT_RELR.name(None), "SHT_0x00000013");
        assert_eq!(SectionType(0x7000_0001).name(None), "SHT_0x70000001");
        assert_eq!(SegmentType::PT_LOAD.name(None), "PT_LOAD");
        assert_eq!(SegmentType(0x6474_e553).name(None), "PT_0x6474e553");
        // PT_SUNWBSS is a constant without a named type.
        assert_eq!(SegmentType::PT_SUNWBSS.name(None), "PT_0x6ffffffa");
        assert_eq!(DynamicTag::DT_SONAME.name(None), "DT_SONAME");
        assert_eq!(DynamicTag(0x7000_0001).name(None), "DT_0x70000001");
        assert_eq!(
            SegmentType::PT_LOAD.info(None).unwrap().description,
            "Loadable segment"
        );
        let needed = DynamicTag::DT_NEEDED.info(None).unwrap();
        assert_eq!(needed.kind, DynamicValueKind::String);
        assert_eq!(
            DynamicTag::DT_SYMTAB.info(None).unwrap().kind,
            DynamicValueKind::Address
        );
        assert_eq!(
            DynamicTag::DT_STRSZ.info(None).unwrap().kind,
            DynamicValueKind::Value
        );
    }

    #[test]
    fn processor_types_are_named_only_for_their_machine() {
        let arm = machine::extension_for(Machine::EM_ARM, crate::ElfClass::Elf32);
        let mips = machine::extension_for(Machine::EM_MIPS, crate::ElfClass::Elf32);
        assert_eq!(SectionType(0x7000_0001).name(arm), "SHT_ARM_EXIDX");
        assert_eq!(SegmentType(0x7000_0000).name(arm), "PT_ARM_EXIDX");
        assert_eq!(SegmentType(0x7000_0000).name(mips), "PT_MIPS_REGINFO");
        assert_eq!(DynamicTag(0x7000_0001).name(mips), "DT_MIPS_RLD_VERSION");
        assert_eq!(DynamicTag(0x7000_0001).name(arm), "DT_0x70000001");
        // Defaults stay visible with an extension.
        assert_eq!(SectionType::SHT_NOTE.name(mips), "SHT_NOTE");
    }

    #[test]
    fn debug_and_conversions() {
        assert_eq!(format!("{:?}", Machine::EM_X86_64), "Machine(0x003e)");
        assert_eq!(
            format!("{:?}", SectionType::SHT_NOTE),
            "SectionType(0x00000007)"
        );
        assert_eq!(format!("{:?}", OsAbi(3)), "OsAbi(0x03)");
        assert_eq!(u32::from(SectionType::from(9)), 9);
        assert_eq!(u16::from(Machine::from(62)), 62);
        assert_eq!(SegmentType::default(), SegmentType::PT_NULL);
    }
}
