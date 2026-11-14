//! Notes, informational sections and GNU symbol versioning on real lld
//! output (notes cross-checked with `object`'s note iterator) and on
//! builder files.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

#[allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses part of the support code"
)]
mod common;

use bk_bin::MemoryProvider;
use bk_elf::{ElfFile, SectionType, SegmentType};
use common::builder::{ElfBuilder, Enc, Section, Segment, sht};
use object::read::elf::{FileHeader, ProgramHeader};

type Elf = ElfFile<MemoryProvider<Vec<u8>>>;

fn parse(bytes: &[u8]) -> Elf {
    ElfFile::parse(MemoryProvider::new(bytes.to_vec())).unwrap()
}

#[test]
fn lld_build_id_and_pt_note_agree_with_object() {
    let data = common::files::fixture("plain-x86_64.so");
    let elf = parse(&data);
    let id = elf.build_id().unwrap().unwrap();
    assert_eq!(id.id().len(), 20, "sha1");

    let header = object::elf::FileHeader64::<object::Endianness>::parse(&data[..]).unwrap();
    let endian = header.endian().unwrap();
    let mut expected = Vec::new();
    for segment in header.program_headers(endian, &data[..]).unwrap() {
        if let Some(mut notes) = segment.notes(endian, &data[..]).unwrap() {
            while let Some(note) = notes.next().unwrap() {
                expected.push((
                    note.name().to_vec(),
                    note.n_type(endian).0,
                    note.desc().to_vec(),
                ));
            }
        }
    }
    let ours: Vec<_> = elf
        .program_notes()
        .into_iter()
        .map(|n| n.unwrap())
        .map(|n| (n.name.into_bytes(), n.vendor_type, n.description))
        .collect();
    assert_ne!(expected, []);
    assert_eq!(ours, expected);
    assert_eq!(ours[0].2, id.id());
    assert_eq!(elf.program_headers_of_type(SegmentType::PT_NOTE).count(), 1);
}

#[test]
fn toolchain_comments() {
    let elf = parse(&common::files::fixture("plain-x86_64.so"));
    let comment = elf.comment().unwrap();
    assert!(
        comment.strings.iter().any(|s| s.starts_with("Linker: LLD")),
        "{comment:?}"
    );
    assert!(
        comment.strings.iter().any(|s| s.contains("clang version")),
        "{comment:?}"
    );
    let total: u32 = comment.lengths.iter().sum();
    let section = elf.section_by_name(".comment").unwrap();
    assert_eq!(u64::from(total), section.sh_size);
}

/// The names behind the version structures of `libdep-x86_64.so` (which
/// defines `DEP_1.0` and `DEP_2.0`) and of `plain-x86_64.so` (which needs
/// both from `libdep.so`). Field-by-field agreement with `object` is in
/// `real_files.rs`.
#[test]
fn version_names() {
    let elf = parse(&common::files::fixture("libdep-x86_64.so"));
    let section = elf
        .sections_of_type(SectionType::SHT_GNU_VERDEF)
        .next()
        .unwrap();
    let strings = elf.string_table_for_section(section.sh_link).unwrap();
    let defs = elf.version_definitions(section);
    let names: Vec<Vec<String>> = defs
        .iter()
        .map(|d| {
            d.aux
                .iter()
                .map(|a| elf.string(strings, a.vda_name.into()).unwrap().into_owned())
                .collect()
        })
        .collect();
    // lld records no parent version in `vd_aux`.
    assert_eq!(names, [["libdep.so"], ["DEP_1.0"], ["DEP_2.0"]]);
    assert_eq!(defs[0].vd_flags & bk_elf::version::VER_FLG_BASE, 1);
    let versym = elf
        .sections_of_type(SectionType::SHT_GNU_VERSYM)
        .next()
        .unwrap();
    let dynsym = elf.dynamic_symbol_table().unwrap();
    let versions = elf.symbol_versions(versym);
    assert_eq!(versions.len(), dynsym.symbol_count as usize);
    for (symbol, version) in elf.symbols(dynsym).zip(&versions).skip(1) {
        let name = elf.symbol_name(dynsym, &symbol).unwrap().unwrap();
        let expected = match name.as_ref() {
            "ext_func" => 2,
            "ext_value" => 3,
            _ => 1,
        };
        assert_eq!(
            *version & !bk_elf::version::VERSYM_HIDDEN,
            expected,
            "{name}"
        );
    }

    let elf = parse(&common::files::fixture("plain-x86_64.so"));
    let section = elf
        .sections_of_type(SectionType::SHT_GNU_VERNEED)
        .next()
        .unwrap();
    let strings = elf.string_table_for_section(section.sh_link).unwrap();
    let needs = elf.version_needs(section);
    assert_eq!(needs.len(), 1);
    assert_eq!(
        elf.string(strings, needs[0].vn_file.into()).unwrap(),
        "libdep.so"
    );
    let mut names: Vec<_> = needs[0]
        .aux
        .iter()
        .map(|a| elf.string(strings, a.vna_name.into()).unwrap().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["DEP_1.0", "DEP_2.0"]);
}

/// Notes and informational sections that lld does not write, from the
/// builder, in both byte orders.
#[test]
fn builder_notes_and_links() {
    for enc in Enc::ALL {
        let note = |name: &[u8], ty: u32, desc: &[u8]| {
            let mut out = Vec::new();
            enc.u32(&mut out, name.len() as u32);
            enc.u32(&mut out, desc.len() as u32);
            enc.u32(&mut out, ty);
            out.extend_from_slice(name);
            out.resize(out.len().next_multiple_of(4), 0);
            out.extend_from_slice(desc);
            out
        };
        let words = |values: &[u32]| {
            let mut out = Vec::new();
            for &v in values {
                enc.u32(&mut out, v);
            }
            out
        };
        let mut b = ElfBuilder::new(enc);
        let abi = b.add(
            Section::new(
                ".note.ABI-tag",
                sht::NOTE,
                note(b"GNU\0", 1, &words(&[0, 3, 2, 0])),
            )
            .alloc()
            .align(4),
        );
        let mut prop = words(&[1, enc.word_size() as u32]);
        enc.word(&mut prop, 0x20_0000);
        b.add(Section::new(".note.gnu.property", sht::NOTE, note(b"GNU\0", 5, &prop)).align(8));
        let mut link = b"libsample.so.debug\0\0".to_vec();
        link.extend_from_slice(&words(&[0xcafe_f00d]));
        b.add(Section::new(".gnu_debuglink", sht::PROGBITS, link));
        b.add(Section::new(
            ".gnu_debugaltlink",
            sht::PROGBITS,
            b"/usr/lib/debug/.dwz/x\0\xab\xcd".to_vec(),
        ));
        b.extra_segments.push(Segment {
            p_type: 4,
            ..Segment::default()
        });
        let mut built = b.build();
        // Point the PT_NOTE segment (header 1) at the ABI tag.
        built.set_ph(1, common::builder::Ph::Offset, built.offsets[abi as usize]);
        built.set_ph(1, common::builder::Ph::Filesz, 32);
        let elf = parse(&built.bytes);
        assert_eq!(elf.diagnostics(), []);

        let tag = elf.abi_tag().unwrap().unwrap();
        assert_eq!(tag.required_kernel_version_string(), "Linux 3.2.0");
        let property = elf.gnu_property().unwrap().unwrap();
        assert_eq!(property.elements.len(), 1);
        assert_eq!(property.elements[0].type_name, "stack_size");
        assert_eq!(property.elements[0].value, "2097152 (0x00200000)");
        let link = elf.debug_link().unwrap();
        assert_eq!(
            (link.filename.as_str(), link.filename_len, link.crc),
            ("libsample.so.debug", 20, 0xcafe_f00d)
        );
        let alt = elf.debug_alt_link().unwrap();
        assert_eq!(
            (alt.filename.as_str(), alt.hash_hex()),
            ("/usr/lib/debug/.dwz/x", "abcd".to_owned())
        );
        assert!(elf.build_id().is_none());
        let notes = elf.program_notes();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].as_ref().unwrap().vendor_type, 1);
    }
}
