//! Differential check against the `object` crate (ADR-007): everything both
//! parsers expose on a well-formed file must agree.

use bk_bin::ByteProvider;
use bk_elf::{DynamicTag, ElfClass, ElfFile, RelocationLayout, SectionType};
use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, Sym};

/// What a comparison covered, for the caller to assert on.
#[derive(Debug, Default, Clone, Copy)]
pub struct Covered {
    pub sections: usize,
    pub symbols: usize,
    pub relocations: usize,
    pub relr_relocations: usize,
    pub versions: usize,
}

/// Compares `elf` (parsed from `data`) with `object`'s view of the same bytes.
pub fn check<P: ByteProvider>(data: &[u8], elf: &ElfFile<P>) -> Covered {
    match elf.header().class {
        ElfClass::Elf32 => check_class::<elf::FileHeader32<object::Endianness>, P>(data, elf),
        ElfClass::Elf64 => check_class::<elf::FileHeader64<object::Endianness>, P>(data, elf),
    }
}

fn check_class<Elf: FileHeader<Endian = object::Endianness>, P: ByteProvider>(
    data: &[u8],
    elf: &ElfFile<P>,
) -> Covered {
    let mut covered = Covered::default();
    let header = Elf::parse(data).unwrap();
    let endian = header.endian().unwrap();
    let ours = elf.header();
    assert_eq!(ours.e_type.0, header.e_type(endian).0);
    assert_eq!(ours.e_machine.0, header.e_machine(endian).0);
    assert_eq!(ours.e_version, header.e_version(endian));
    assert_eq!(ours.e_entry, header.e_entry(endian).into());
    assert_eq!(ours.e_phoff, header.e_phoff(endian).into());
    assert_eq!(ours.e_shoff, header.e_shoff(endian).into());
    assert_eq!(ours.e_flags, header.e_flags(endian).0);
    assert_eq!(ours.e_ehsize, header.e_ehsize(endian));
    assert_eq!(ours.e_shstrndx, header.shstrndx(endian, data).unwrap());
    assert_eq!(
        ours.is_little_endian(),
        endian == object::Endianness::Little
    );

    let segments = header.program_headers(endian, data).unwrap();
    assert_eq!(elf.program_headers().len(), segments.len());
    for (ours, theirs) in elf.program_headers().iter().zip(segments) {
        assert_eq!(ours.p_type.0, theirs.p_type(endian).0);
        assert_eq!(ours.p_flags, theirs.p_flags(endian).0);
        assert_eq!(ours.p_offset, theirs.p_offset(endian).into());
        assert_eq!(ours.p_vaddr, theirs.p_vaddr(endian).into());
        assert_eq!(ours.p_paddr, theirs.p_paddr(endian).into());
        assert_eq!(ours.p_filesz, theirs.p_filesz(endian).into());
        assert_eq!(ours.p_memsz, theirs.p_memsz(endian).into());
        assert_eq!(ours.p_align, theirs.p_align(endian).into());
    }

    let sections = header.sections(endian, data).unwrap();
    assert_eq!(elf.sections().len(), sections.len());
    for (ours, theirs) in elf.sections().iter().zip(sections.iter()) {
        assert_eq!(ours.sh_name, theirs.sh_name(endian));
        assert_eq!(ours.sh_type.0, theirs.sh_type(endian).0);
        assert_eq!(ours.sh_flags, u64::from(theirs.sh_flags(endian).0));
        assert_eq!(ours.sh_addr, theirs.sh_addr(endian).into());
        assert_eq!(ours.sh_offset, theirs.sh_offset(endian).into());
        assert_eq!(ours.sh_size, theirs.sh_size(endian).into());
        assert_eq!(ours.sh_link, theirs.sh_link(endian));
        assert_eq!(ours.sh_info, theirs.sh_info(endian));
        assert_eq!(ours.sh_addralign, theirs.sh_addralign(endian).into());
        assert_eq!(ours.sh_entsize, theirs.sh_entsize(endian).into());
        let name = sections.section_name(endian, theirs).unwrap();
        if !name.is_empty() {
            assert_eq!(elf.section_name(ours).as_bytes(), name);
        }
        covered.sections += 1;
    }

    // The dynamic table: `object` returns the whole segment, Ghidra stops
    // at (and includes) the first DT_NULL.
    let theirs = segments
        .iter()
        .find_map(|s| s.dynamic(endian, data).unwrap());
    match (elf.dynamic_table(), theirs) {
        (Some(ours), Some(theirs)) => {
            let expected: Vec<(u32, u64)> = theirs
                .iter()
                .map(|d| (d.d_tag(endian).0 as u32, d.d_val(endian).into()))
                .scan(false, |done, entry| {
                    let take = !*done;
                    *done = entry.0 == elf::DT_NULL.0 as u32;
                    take.then_some(entry)
                })
                .collect();
            let actual: Vec<(u32, u64)> =
                ours.entries().iter().map(|e| (e.tag.0, e.value)).collect();
            assert_eq!(actual, expected);
            assert_eq!(
                ours.entries().last().map(|e| e.tag),
                Some(DynamicTag::DT_NULL)
            );
        }
        (None, None) => {}
        (ours, theirs) => panic!(
            "dynamic table: ours {} / object {}",
            ours.is_some(),
            theirs.is_some()
        ),
    }

    // DT_NEEDED names through the dynamic section's string table.
    for (index, section) in sections.iter().enumerate() {
        let Some((entries, link)) = section.dynamic(endian, data).unwrap() else {
            continue;
        };
        let strings = sections.strings(endian, data, link).unwrap();
        let expected: Vec<String> = entries
            .iter()
            .take_while(|d| d.d_tag(endian).0 != elf::DT_NULL.0)
            .filter(|d| d.d_tag(endian).0 == elf::DT_NEEDED.0)
            .map(|d| {
                let offset: u64 = d.d_val(endian).into();
                String::from_utf8_lossy(strings.get(offset as u32).unwrap()).into_owned()
            })
            .collect();
        let actual: Vec<String> = elf
            .dynamic_library_names()
            .map(|n| n.into_owned())
            .collect();
        assert_eq!(actual, expected, "DT_NEEDED of section {index}");
    }

    // One string table per SHT_STRTAB section, at that section's offset.
    let string_sections: Vec<u64> = elf
        .sections_of_type(SectionType::SHT_STRTAB)
        .map(|s| s.sh_offset)
        .collect();
    let string_tables: Vec<u64> = elf
        .string_tables()
        .iter()
        .filter(|t| t.section.is_some())
        .map(|t| t.file_offset)
        .collect();
    assert_eq!(string_tables, string_sections);

    // Symbols of every symbol table section.
    for (index, section) in sections.iter().enumerate() {
        let sh_type = section.sh_type(endian);
        if sh_type != elf::SHT_SYMTAB && sh_type != elf::SHT_DYNSYM {
            continue;
        }
        let theirs = sections
            .symbol_table_by_index(endian, data, object::SectionIndex(index))
            .unwrap();
        let table = elf
            .symbol_table_for_section(index as u32)
            .unwrap_or_else(|| panic!("no symbol table for section {index}"));
        assert_eq!(table.symbol_count as usize, theirs.symbols().len());
        assert!(!table.truncated);
        let ours: Vec<_> = elf.symbols(table).collect();
        assert_eq!(ours.len(), theirs.symbols().len());
        for (ours, sym) in ours.iter().zip(theirs.symbols()) {
            assert_eq!(ours.st_name, sym.st_name(endian));
            assert_eq!(ours.st_value, sym.st_value(endian).into());
            assert_eq!(ours.st_size, sym.st_size(endian).into());
            assert_eq!(ours.st_info, sym.st_info().0);
            assert_eq!(ours.st_other, sym.st_other().0);
            assert_eq!(ours.st_shndx, sym.st_shndx(endian).0);
            assert_eq!(ours.bind(), sym.st_bind().0);
            assert_eq!(ours.symbol_type(), sym.st_type().0);
            assert_eq!(ours.visibility(), sym.st_visibility().0);
            let name = sym.name(endian, theirs.strings()).unwrap();
            let name = String::from_utf8_lossy(name);
            let ours_name = elf.symbol_name(table, ours).unwrap().unwrap();
            if ours.st_name == 0 && ours.is_section() {
                // Ghidra names these after their section.
                let section = elf.section(u32::from(ours.st_shndx)).unwrap();
                assert_eq!(ours_name, elf.section_name(section));
            } else {
                assert_eq!(ours_name, name.trim());
            }
            covered.symbols += 1;
        }
    }

    // Relocations of every REL, RELA and RELR section.
    let mips64el = header.is_mips64el(endian);
    for (index, section) in sections.iter().enumerate() {
        let table = || {
            elf.relocation_table_for_section(index as u32)
                .unwrap_or_else(|| panic!("no relocation table for section {index}"))
        };
        if let Some((rels, _)) = section.rel(endian, data).unwrap() {
            let table = table();
            assert!(!table.has_addend);
            let ours: Vec<_> = elf.relocations(table).collect();
            assert_eq!(ours.len(), rels.len());
            for (ours, theirs) in ours.iter().zip(rels) {
                assert_eq!(ours.r_offset, theirs.r_offset(endian).into());
                assert_eq!(ours.r_info, theirs.r_info(endian).into());
                assert_eq!(ours.symbol_index(), theirs.r_sym(endian));
                assert_eq!(ours.relocation_type(), theirs.r_type(endian).0);
                assert_eq!(ours.r_addend, 0);
                covered.relocations += 1;
            }
        }
        if let Some((relas, _)) = section.rela(endian, data).unwrap() {
            let table = table();
            assert!(table.has_addend);
            let ours: Vec<_> = elf.relocations(table).collect();
            assert_eq!(ours.len(), relas.len());
            for (ours, theirs) in ours.iter().zip(relas) {
                assert_eq!(ours.r_offset, theirs.r_offset(endian).into());
                assert_eq!(ours.symbol_index(), theirs.r_sym(endian, mips64el));
                if !matches!(ours.layout, RelocationLayout::Mips64 { .. }) {
                    assert_eq!(ours.relocation_type(), theirs.r_type(endian, mips64el).0);
                }
                assert_eq!(ours.r_addend, theirs.r_addend(endian).into());
                covered.relocations += 1;
            }
        }
        if let Some(relrs) = section.relr(endian, data).unwrap() {
            let table = table();
            let expected: Vec<u64> = relrs.map(Into::into).collect();
            let actual: Vec<u64> = elf.relocations(table).map(|r| r.r_offset).collect();
            assert_eq!(actual, expected, "RELR section {index}");
            covered.relr_relocations += expected.len();
        }
    }
    // GNU symbol versioning.
    for (index, section) in sections.iter().enumerate() {
        let ours = &elf.sections()[index];
        if let Some((versyms, _)) = section.gnu_versym(endian, data).unwrap() {
            let expected: Vec<u16> = versyms.iter().map(|v| v.0.get(endian).0).collect();
            assert_eq!(elf.symbol_versions(ours), expected);
            covered.versions += expected.len();
        }
        if let Some((mut defs, _)) = section.gnu_verdef(endian, data).unwrap() {
            let ours = elf.version_definitions(ours);
            let mut i = 0;
            while let Some((def, mut auxs)) = defs.next().unwrap() {
                let o = &ours[i];
                assert_eq!(o.vd_version, def.vd_version.get(endian));
                assert_eq!(o.vd_flags, def.vd_flags.get(endian).0);
                assert_eq!(o.vd_ndx, def.vd_ndx.get(endian).0);
                assert_eq!(o.vd_cnt, def.vd_cnt.get(endian));
                assert_eq!(o.vd_hash, def.vd_hash.get(endian));
                let mut names = Vec::new();
                while let Some(aux) = auxs.next().unwrap() {
                    names.push(aux.vda_name.get(endian));
                }
                let ours_names: Vec<u32> = o.aux.iter().map(|a| a.vda_name).collect();
                assert_eq!(ours_names, names);
                i += 1;
                covered.versions += 1;
            }
            assert_eq!(ours.len(), i);
        }
        if let Some((mut needs, _)) = section.gnu_verneed(endian, data).unwrap() {
            let ours = elf.version_needs(ours);
            let mut i = 0;
            while let Some((need, mut auxs)) = needs.next().unwrap() {
                let o = &ours[i];
                assert_eq!(o.vn_version, need.vn_version.get(endian));
                assert_eq!(o.vn_cnt, need.vn_cnt.get(endian));
                assert_eq!(o.vn_file, need.vn_file.get(endian));
                let mut entries = Vec::new();
                while let Some(aux) = auxs.next().unwrap() {
                    entries.push((
                        aux.vna_hash.get(endian),
                        aux.vna_flags.get(endian).0,
                        aux.vna_other.get(endian).0,
                        aux.vna_name.get(endian),
                    ));
                }
                let ours_entries: Vec<_> = o
                    .aux
                    .iter()
                    .map(|a| (a.vna_hash, a.vna_flags, a.vna_other, a.vna_name))
                    .collect();
                assert_eq!(ours_entries, entries);
                i += 1;
                covered.versions += 1;
            }
            assert_eq!(ours.len(), i);
        }
    }
    covered
}
