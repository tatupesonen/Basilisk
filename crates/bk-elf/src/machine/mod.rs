//! Processor-specific parts of the ELF format.
//!
//! Ghidra lets each processor module contribute an `ElfExtension` (a
//! subclass of `ElfLoadAdapter`). Most of what those classes do is building
//! a program and belongs to the loader; what belongs to the *file format* is
//! here, as static data keyed by `e_machine` (and, for some, the class):
//!
//! * the processor-specific segment types, section types and dynamic tags
//!   and their names (one module per processor, generated from Ghidra's
//!   sources by `gen/gen_tables.py`);
//! * the suffix Ghidra appends to data type names for the processor;
//! * the two hooks that change how the file is parsed: MIPS-64's relocation
//!   entry layout, and dsPIC30's halved sizes for data segments.

use crate::constants::{DynamicTagInfo, Machine, PF_X, TypeInfo};
use crate::header::ElfClass;

pub mod aarch64;
pub mod arm;
pub mod avr8;
pub mod ebpf;
pub mod hcs12;
pub mod hexagon;
pub mod mips;
pub mod msp430;
pub mod pic30;
pub mod ppc;
pub mod ppc64;
pub mod riscv;
pub mod x86;

/// What a processor adds to the ELF format: the file-format part of one of
/// Ghidra's `ElfExtension` classes.
#[derive(Debug, PartialEq, Eq)]
pub struct MachineExtension {
    /// Name of the Ghidra class this was taken from.
    pub name: &'static str,
    /// The `e_machine` value the extension handles.
    pub machine: Machine,
    /// The class the extension requires, if it handles only one.
    pub class: Option<ElfClass>,
    /// Suffix for the names of data types that depend on the extension's
    /// types (Ghidra's `getDataTypeSuffix`), for example `_ARM`.
    pub data_type_suffix: &'static str,
    /// Processor-specific segment types.
    pub segment_types: &'static [TypeInfo],
    /// Processor-specific section types.
    pub section_types: &'static [TypeInfo],
    /// Processor-specific dynamic tags.
    pub dynamic_tags: &'static [DynamicTagInfo],
}

static EXTENSIONS: [&MachineExtension; 13] = [
    &aarch64::EXTENSION,
    &arm::EXTENSION,
    &avr8::EXTENSION,
    &ebpf::EXTENSION,
    &hcs12::EXTENSION,
    &hexagon::EXTENSION,
    &mips::EXTENSION,
    &msp430::EXTENSION,
    &pic30::EXTENSION,
    &ppc::EXTENSION,
    &ppc64::EXTENSION,
    &riscv::EXTENSION,
    &x86::EXTENSION,
];

/// The extension Ghidra would select for a file with this machine and class
/// (`ElfExtensionFactory.getLoadAdapter`), if any processor claims it.
pub fn extension_for(machine: Machine, class: ElfClass) -> Option<&'static MachineExtension> {
    EXTENSIONS
        .iter()
        .copied()
        .find(|e| e.machine == machine && e.class.is_none_or(|required| required == class))
}

/// Every extension, in a fixed order.
pub fn extensions() -> &'static [&'static MachineExtension] {
    &EXTENSIONS
}

impl MachineExtension {
    /// True when relocation entries of a file of class `class` use the
    /// MIPS-64 layout of `r_info` (Ghidra's `MIPS_Elf64Relocation`).
    pub fn uses_mips64_relocations(&self, class: ElfClass) -> bool {
        self.machine == Machine::EM_MIPS && class == ElfClass::Elf64
    }

    /// The size a segment size has in addressable units (Ghidra's
    /// `getAdjustedLoadSize` and `getAdjustedMemorySize`): the size itself,
    /// except that dsPIC30 halves the sizes of segments that are not
    /// executable, because its data space is addressed in 16-bit words.
    pub fn adjusted_segment_size(&self, size: u64, p_flags: u32) -> u64 {
        if self.machine == Machine::EM_DSPIC30F && p_flags & PF_X == 0 {
            // Ghidra divides a signed long.
            ((size as i64) / 2) as u64
        } else {
            size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_follows_ghidra_can_handle() {
        let name = |m, c| extension_for(m, c).map(|e| e.name);
        assert_eq!(
            name(Machine::EM_ARM, ElfClass::Elf32),
            Some("ARM_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_ARM, ElfClass::Elf64),
            Some("ARM_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_AARCH64, ElfClass::Elf64),
            Some("AARCH64_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_MIPS, ElfClass::Elf64),
            Some("MIPS_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_RISCV, ElfClass::Elf64),
            Some("RISCV_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_PPC64, ElfClass::Elf64),
            Some("PowerPC64_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_HEXAGON, ElfClass::Elf32),
            Some("Hexagon_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_MSP430, ElfClass::Elf32),
            Some("MSP430_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_AVR, ElfClass::Elf32),
            Some("AVR8_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_68HC12, ElfClass::Elf32),
            Some("HCS12X_ElfExtension")
        );
        assert_eq!(
            name(Machine::EM_DSPIC30F, ElfClass::Elf32),
            Some("PIC30_ElfExtension")
        );
        // Extensions that require a class.
        assert_eq!(
            name(Machine::EM_PPC, ElfClass::Elf32),
            Some("PowerPC_ElfExtension")
        );
        assert_eq!(name(Machine::EM_PPC, ElfClass::Elf64), None);
        assert_eq!(
            name(Machine::EM_386, ElfClass::Elf32),
            Some("X86_32_ElfExtension")
        );
        assert_eq!(name(Machine::EM_386, ElfClass::Elf64), None);
        assert_eq!(
            name(Machine::EM_BPF, ElfClass::Elf64),
            Some("eBPF_ElfExtension")
        );
        assert_eq!(name(Machine::EM_BPF, ElfClass::Elf32), None);
        // x86-64 and SPARC have no extension in Ghidra.
        assert_eq!(name(Machine::EM_X86_64, ElfClass::Elf64), None);
        assert_eq!(name(Machine::EM_SPARC, ElfClass::Elf32), None);
    }

    #[test]
    fn every_extension_is_reachable_and_consistent() {
        assert_eq!(extensions().len(), 13);
        for ext in extensions() {
            let class = ext.class.unwrap_or(ElfClass::Elf32);
            assert_eq!(
                extension_for(ext.machine, class),
                Some(*ext),
                "{}",
                ext.name
            );
            assert!(!ext.data_type_suffix.is_empty(), "{}", ext.name);
            for info in ext.segment_types.iter().chain(ext.section_types) {
                assert!(
                    (0x7000_0000..=0x7fff_ffff).contains(&info.value),
                    "{}",
                    info.name
                );
            }
            for info in ext.dynamic_tags {
                assert!(info.name.starts_with("DT_"), "{}", info.name);
            }
        }
    }

    #[test]
    fn table_sizes_match_ghidra() {
        let sizes = |m, c| {
            let e = extension_for(m, c).unwrap();
            (
                e.segment_types.len(),
                e.section_types.len(),
                e.dynamic_tags.len(),
            )
        };
        assert_eq!(sizes(Machine::EM_MIPS, ElfClass::Elf32), (6, 40, 46));
        assert_eq!(sizes(Machine::EM_ARM, ElfClass::Elf32), (1, 5, 0));
        assert_eq!(sizes(Machine::EM_AARCH64, ElfClass::Elf64), (1, 1, 0));
        assert_eq!(sizes(Machine::EM_HEXAGON, ElfClass::Elf32), (1, 5, 3));
        assert_eq!(sizes(Machine::EM_PPC, ElfClass::Elf32), (0, 0, 2));
        assert_eq!(sizes(Machine::EM_PPC64, ElfClass::Elf64), (0, 0, 4));
        assert_eq!(sizes(Machine::EM_MSP430, ElfClass::Elf32), (0, 3, 0));
        assert_eq!(sizes(Machine::EM_68HC12, ElfClass::Elf32), (1, 1, 0));
        assert_eq!(arm::SHT_ARM_EXIDX.0, 0x7000_0001);
        assert_eq!(mips::DT_MIPS_GOTSYM.0, 0x7000_0013);
        assert_eq!(aarch64::PT_AARCH64_ARCHEXT.0, 0x7000_0000);
    }

    #[test]
    fn hooks() {
        let mips = extension_for(Machine::EM_MIPS, ElfClass::Elf64).unwrap();
        assert!(mips.uses_mips64_relocations(ElfClass::Elf64));
        assert!(!mips.uses_mips64_relocations(ElfClass::Elf32));
        let arm = extension_for(Machine::EM_ARM, ElfClass::Elf32).unwrap();
        assert!(!arm.uses_mips64_relocations(ElfClass::Elf64));
        assert_eq!(arm.adjusted_segment_size(0x100, 0), 0x100);
        let pic = extension_for(Machine::EM_DSPIC30F, ElfClass::Elf32).unwrap();
        assert_eq!(
            pic.adjusted_segment_size(0x100, 0),
            0x80,
            "data segments are halved"
        );
        assert_eq!(
            pic.adjusted_segment_size(0x100, PF_X),
            0x100,
            "code segments are not"
        );
    }
}
