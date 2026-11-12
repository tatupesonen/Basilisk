//! Smoke test of the part of the parser that exists at handover: the ELF
//! files in the Ghidra tree parse without diagnostics, and the header, the
//! program and section headers and the dynamic table agree with the `object`
//! crate.
//!
//! The files are referenced in place (`BASILISK_GHIDRA_DIR`, default
//! `<workspace>/../ghidra`); the test skips with a message when the tree is
//! absent. The helper below is local because `bk-testkit` belongs to another
//! track in this wave.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

use bk_bin::MemoryProvider;
use bk_elf::{DynamicTag, ElfClass, SectionType};
use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader};

fn ghidra_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("BASILISK_GHIDRA_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
        PathBuf::from,
    );
    if dir.is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "skipping: Ghidra tree not found at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

/// Every file with the ELF magic under the two directories the spec names.
fn elf_files(ghidra: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![
        ghidra.join("GPL/GnuDisassembler/data"),
        ghidra.join("GhidraDocs/GhidraClass/ExerciseFiles"),
    ];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if std::fs::read(&path).is_ok_and(|b| b.starts_with(b"\x7fELF")) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn check_against_object<Elf: FileHeader<Endian = object::Endianness>>(
    data: &[u8],
    tables: &bk_elf::ElfTables,
) {
    let header = Elf::parse(data).unwrap();
    let endian = header.endian().unwrap();
    let ours = tables.header();
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
    assert_eq!(tables.program_headers().len(), segments.len());
    for (ours, theirs) in tables.program_headers().iter().zip(segments) {
        assert_eq!(ours.p_type.0, theirs.p_type(endian).0);
        assert_eq!(ours.p_flags, theirs.p_flags(endian).0);
        assert_eq!(ours.p_offset, theirs.p_offset(endian).into());
        assert_eq!(ours.p_vaddr, theirs.p_vaddr(endian).into());
        assert_eq!(ours.p_paddr, theirs.p_paddr(endian).into());
        assert_eq!(ours.p_filesz, theirs.p_filesz(endian).into());
        assert_eq!(ours.p_memsz, theirs.p_memsz(endian).into());
        assert_eq!(ours.p_align, theirs.p_align(endian).into());
    }

    let sections = header.section_headers(endian, data).unwrap();
    assert_eq!(tables.sections().len(), sections.len());
    for (ours, theirs) in tables.sections().iter().zip(sections) {
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
    }

    // The dynamic table: `object` returns the whole segment, Ghidra stops
    // at (and includes) the first DT_NULL.
    let theirs = segments
        .iter()
        .find_map(|s| s.dynamic(endian, data).unwrap());
    match (tables.dynamic_table(), theirs) {
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

    // One string table per SHT_STRTAB section, at that section's offset.
    let string_sections: Vec<u64> = tables
        .sections_of_type(SectionType::SHT_STRTAB)
        .map(|s| s.sh_offset)
        .collect();
    let string_tables: Vec<u64> = tables
        .string_tables()
        .iter()
        .filter(|t| t.section.is_some())
        .map(|t| t.file_offset)
        .collect();
    assert_eq!(string_tables, string_sections);
    if tables
        .dynamic_table()
        .is_some_and(|d| d.contains(DynamicTag::DT_STRTAB))
    {
        assert!(tables.dynamic_string_table().is_some());
    }
}

#[test]
fn ghidra_tree_elf_files_parse_cleanly_and_agree_with_object() {
    let Some(ghidra) = ghidra_dir() else { return };
    let files = elf_files(&ghidra);
    assert!(
        files.len() >= 4,
        "expected little.elf, big.elf and the exercise files, got {files:?}"
    );
    for path in &files {
        let data = std::fs::read(path).unwrap();
        let provider = MemoryProvider::new(&data[..]);
        let tables =
            bk_elf::parse_tables(&provider).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(tables.diagnostics(), [], "{}", path.display());
        assert_eq!(tables.file_len(), data.len() as u64);
        match tables.header().class {
            ElfClass::Elf32 => {
                check_against_object::<elf::FileHeader32<object::Endianness>>(&data, &tables)
            }
            ElfClass::Elf64 => {
                check_against_object::<elf::FileHeader64<object::Endianness>>(&data, &tables)
            }
        }
    }
    eprintln!(
        "checked {} ELF files from {}",
        files.len(),
        ghidra.display()
    );
}

#[test]
fn not_elf_and_short_files_are_fatal() {
    use bk_elf::ElfError;
    let parse = |bytes: &[u8]| bk_elf::parse_tables(&MemoryProvider::new(bytes));
    assert!(matches!(parse(b""), Err(ElfError::NotElf)));
    assert!(matches!(
        parse(b"MZ\x90\x00 not an ELF file at all, but long enough"),
        Err(ElfError::NotElf)
    ));
    assert!(matches!(
        parse(b"\x7fELF\x02\x01\x01"),
        Err(ElfError::TooShort { len: 7 })
    ));
    let mut bad_class = b"\x7fELF\x03\x01\x01".to_vec();
    bad_class.resize(64, 0);
    assert!(matches!(
        parse(&bad_class),
        Err(ElfError::UnsupportedClass { class: 3 })
    ));
}
