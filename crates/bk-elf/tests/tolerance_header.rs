//! Ghidra's tolerance rules for the ELF header and the header tables
//! (`ElfHeader` constructor, `parseProgramHeaders`, `parseSectionHeaders`,
//! prelink, section names, compression headers): one deliberately damaged
//! fixture per rule, with the diagnostic Ghidra logs.
//!
//! Rule numbers refer to the list in `docs/agents/bin-elf.md`.

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

use bk_bin::{Endian, MemoryProvider};
use bk_elf::{DiagnosticKind, ElfError, ElfFile};
use common::builder::{Built, Enc, Field, Section, Segment, Sh, sample, sht};

type Elf = ElfFile<MemoryProvider<Vec<u8>>>;

fn parse(bytes: &[u8]) -> Elf {
    ElfFile::parse(MemoryProvider::new(bytes.to_vec())).unwrap()
}

fn messages(elf: &Elf) -> Vec<&str> {
    elf.diagnostics()
        .iter()
        .map(|d| d.message.as_str())
        .collect()
}

fn built(enc: Enc) -> Built {
    sample(enc).0.build()
}

/// Rule 3: an invalid `EI_DATA` is a warning; little-endian is assumed.
#[test]
fn invalid_ei_data_assumes_little_endian() {
    for (value, shown) in [(0u8, "0x0"), (0xff, "0xffffffff")] {
        let mut b = built(Enc::LE64);
        b.bytes[5] = value;
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Invalid EI_DATA, assuming little-endian headers (EI_DATA={shown})"
            )]
        );
        assert_eq!(
            elf.diagnostics()[0].kind,
            DiagnosticKind::InvalidDataEncoding
        );
        assert_eq!(elf.header().header_endian, Endian::Little);
        assert_eq!(elf.sections().len(), sample(Enc::LE64).0.sections.len() + 3);
        assert!(elf.dynamic_symbol_table().is_some());
    }
}

/// Rule 4: a big-endian ident with little-endian headers reads the headers
/// little-endian, silently.
#[test]
fn big_endian_ident_with_little_endian_headers() {
    let mut b = built(Enc::LE64);
    b.bytes[5] = 2;
    let elf = parse(&b.bytes);
    assert_eq!(messages(&elf), Vec::<&str>::new());
    assert!(elf.header().is_big_endian());
    assert_eq!(elf.header().header_endian, Endian::Little);
    assert_eq!(elf.header().data_endian(), Endian::Big);
    assert_eq!(elf.dynamic_library_names().count(), 2);
}

/// Rule 5: a truncated header reads as zeros instead of failing.
#[test]
fn truncated_header_reads_as_zeros() {
    let b = built(Enc::LE64);
    let elf = parse(&b.bytes[..40]);
    let h = elf.header();
    assert_eq!((h.e_shoff, h.e_flags, h.e_shnum, h.e_phnum), (0, 0, 0, 0));
    assert_eq!(
        messages(&elf),
        ["Invalid ELF e_phoff value (program header table offset): 0x40"]
    );
}

/// Rules 1, 2, 6: what is fatal.
#[test]
fn fatal_cases() {
    let fail = |bytes: &[u8]| ElfFile::parse(MemoryProvider::new(bytes.to_vec())).unwrap_err();
    assert!(matches!(fail(b"\x7fELG\x02\x01"), ElfError::NotElf));
    assert!(matches!(
        fail(&built(Enc::LE64).bytes[..33]),
        ElfError::TooShort { len: 33 }
    ));
    let mut b = built(Enc::LE32);
    b.bytes[4] = 0;
    assert!(matches!(
        fail(&b.bytes),
        ElfError::UnsupportedClass { class: 0 }
    ));
}

/// Rule 7: table offsets outside the file are ignored with a warning.
#[test]
fn table_offsets_outside_the_file() {
    for enc in Enc::ALL {
        let mut b = built(enc);
        let len = b.bytes.len() as u64;
        b.set(Field::Phoff, len);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf)[0],
            format!("Invalid ELF e_phoff value (program header table offset): 0x{len:x}")
        );
        assert_eq!(elf.program_headers().len(), 0);
        assert_eq!(elf.header().e_phoff, 0);
        assert_eq!(elf.header().raw_e_phoff, len);
        // Without a PT_LOAD the `.dynamic` section cannot be placed, so there
        // is no dynamic table (as in Ghidra); the symbol tables come from
        // their sections.
        assert!(elf.dynamic_table().is_none());
        assert_eq!(elf.symbol_tables().len(), 2);

        let mut b = built(enc);
        let bad = if enc.is64 {
            0x8000_0000_0000_0000
        } else {
            len + 7
        };
        b.set(Field::Shoff, bad);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Invalid ELF e_shoff value (section header table offset): 0x{bad:x}"
            )]
        );
        assert_eq!(elf.sections().len(), 0);
        // Everything dynamic is still found through the program headers.
        assert_eq!(elf.dynamic_symbol_table().unwrap().symbol_count, 5);
        assert_eq!(elf.relocation_tables().len(), 3);
    }
}

/// Rule 8: `PN_XNUM` takes the program header count from section 0.
#[test]
fn extended_program_header_count() {
    for enc in Enc::ALL {
        let mut b = built(enc);
        b.set(Field::Phnum, 0xffff);
        b.set_sh(0, Sh::Info, 2);
        let elf = parse(&b.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.header().e_phnum, 2);
        assert_eq!(elf.header().raw_e_phnum, 0xffff);

        b.set_sh(0, Sh::Info, 0x8000_0000);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Invalid extended program header count: -2147483648"
        );
        assert_eq!(elf.header().e_phnum, 0);

        b.set_sh(0, Sh::Type, u64::from(sht::PROGBITS));
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Failed to load Section-0 required for extended program header count"
        );
    }
}

/// Rules 9 and 10: a reserved `e_shnum` is rejected, then — as in Ghidra —
/// the extended count in section 0 is used; `e_shnum` = 0 uses it directly.
#[test]
fn extended_and_reserved_section_counts() {
    for enc in Enc::ALL {
        let intact = parse(&built(enc).bytes);
        let count = intact.sections().len() as u64;

        let mut b = built(enc);
        b.set(Field::Shnum, 0);
        b.set_sh(0, Sh::Size, count);
        let elf = parse(&b.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.sections()[1..], intact.sections()[1..]);
        assert_eq!(elf.header().raw_e_shnum, 0);

        b.set(Field::Shnum, 0xff00);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf),
            ["Invalid ELF e_shnum value (section header count): 0xff00"]
        );
        assert_eq!(elf.sections().len() as u64, count);

        b.set(Field::Shnum, 0);
        b.set_sh(0, Sh::Size, if enc.is64 { u64::MAX } else { 0x8000_0000 });
        let elf = parse(&b.bytes);
        let shown = if enc.is64 { "-1" } else { "2147483648" };
        assert_eq!(
            messages(&elf)[0],
            format!("Invalid extended section header count: {shown}")
        );
        assert_eq!(elf.sections().len(), 0);

        b.set_sh(0, Sh::Type, u64::from(sht::PROGBITS));
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Failed to load Section-0 required for extended section header count"
        );
    }
}

/// Rules 11 and 13: a wrong entry size drops that table if the other one
/// exists, and is fatal otherwise.
#[test]
fn wrong_header_entry_sizes() {
    for enc in Enc::ALL {
        let (ph, sh) = if enc.is64 { (56, 64) } else { (32, 40) };
        let mut b = built(enc);
        b.set(Field::Phentsize, ph + 1);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Unsupported e_phentsize value (program header size): {} (expected {ph}), using \
                 section headers only",
                ph + 1
            )]
        );
        assert_eq!(elf.program_headers().len(), 0);
        assert!(elf.dynamic_table().is_none());
        assert_eq!(elf.symbol_tables().len(), 2);

        let mut b = built(enc);
        b.set(Field::Shentsize, 1);
        let elf = parse(&b.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Unsupported e_shentsize value (section header size): 1 (expected {sh}), using \
                 program headers only"
            )]
        );
        assert_eq!(elf.sections().len(), 0);
        assert!(elf.dynamic_symbol_table().is_some());

        // No other table to fall back on: fatal.
        b.set(Field::Phentsize, 3);
        let error = ElfFile::parse(MemoryProvider::new(b.bytes.clone())).unwrap_err();
        assert!(matches!(
            error,
            ElfError::UnsupportedSectionHeaderSize { actual: 1, .. }
        ));
        let mut b = built(enc);
        b.set(Field::Phentsize, 3);
        b.set(Field::Shoff, 0);
        let error = ElfFile::parse(MemoryProvider::new(b.bytes.clone())).unwrap_err();
        assert!(matches!(
            error,
            ElfError::UnsupportedProgramHeaderSize { actual: 3, .. }
        ));
    }
}

/// Rules 12 and 13: counts beyond the file are cut, with one partial entry
/// kept and zero-padded.
#[test]
fn header_counts_beyond_the_file() {
    for enc in Enc::ALL {
        let (ph, sh) = if enc.is64 { (56u64, 64u64) } else { (32, 40) };
        let mut b = built(enc);
        b.set(Field::Phnum, 1000);
        let elf = parse(&b.bytes);
        let available = b.bytes.len() as u64 - b.phoff;
        let fit = available / ph + u64::from(!available.is_multiple_of(ph));
        assert_eq!(
            messages(&elf)[0],
            format!("Program Header count 1000 exceeds file capacity {fit}; truncating")
        );
        assert_eq!(
            messages(&elf).contains(&"Program Header has partial entry"),
            !available.is_multiple_of(ph)
        );
        assert_eq!(u64::from(elf.header().e_phnum), fit);
        assert!(elf.header().phnum_truncated);

        // The file ends half way through the last section header.
        let b = built(enc);
        let intact = parse(&b.bytes);
        let cut = &b.bytes[..b.bytes.len() - (sh / 2) as usize];
        let elf = parse(cut);
        assert_eq!(messages(&elf)[0], "Section Header has partial entry");
        assert!(elf.header().shnum_truncated);
        assert_eq!(elf.sections().len(), intact.sections().len());
        let last = elf.sections().last().unwrap();
        let intact_last = intact.sections().last().unwrap();
        assert_eq!(last.sh_name, intact_last.sh_name);
        assert_eq!(last.sh_entsize, 0, "zero-padded");

        let mut b = built(enc);
        b.set(Field::Shnum, 0xfeff);
        let elf = parse(&b.bytes);
        let fit = intact.sections().len();
        assert_eq!(
            messages(&elf)[0],
            format!("Section Header count 65279 exceeds file capacity {fit}; truncating")
        );
        assert_eq!(elf.sections().len(), fit);
    }
}

/// Rule 14: `SHN_XINDEX` takes the string-table index from section 0.
#[test]
fn extended_section_name_table_index() {
    for enc in Enc::ALL {
        let mut b = built(enc);
        let shstrndx = b.shstrndx;
        b.set(Field::Shstrndx, 0xffff);
        b.set_sh(0, Sh::Link, u64::from(shstrndx));
        let elf = parse(&b.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.header().e_shstrndx, shstrndx);
        assert_eq!(elf.section_name(&elf.sections()[1]), ".text");

        b.set_sh(0, Sh::Link, 0x8000_0000);
        let elf = parse(&b.bytes);
        assert_eq!(elf.header().e_shstrndx, 0);
    }
}

/// Rule 18: names fall back to `SECTION<index>`.
#[test]
fn section_name_fallbacks() {
    let mut b = built(Enc::LE64);
    let len = b.bytes.len() as u64;
    b.set_sh(1, Sh::Name, len);
    b.set_sh(2, Sh::Name, 0);
    b.set_sh(3, Sh::Name, 0x8000_0000);
    let elf = parse(&b.bytes);
    assert_eq!(elf.section_name(&elf.sections()[1]), "SECTION1");
    assert_eq!(elf.section_name(&elf.sections()[2]), "SECTION2");
    assert_eq!(elf.section_name(&elf.sections()[3]), "SECTION3");
    assert_eq!(elf.section_name(&elf.sections()[4]), ".hash");

    let mut b = built(Enc::LE64);
    let count = elf.sections().len() as u64;
    b.set(Field::Shstrndx, count);
    let elf = parse(&b.bytes);
    assert_eq!(elf.section_name(&elf.sections()[1]), "SECTION1");
    assert!(elf.section_by_name(".text").is_none());
    // The dynamic symbol table section is no longer called `.dynsym`.
    assert!(!elf.dynamic_symbol_table().unwrap().is_dynamic);
}

/// Rule 17: offsets that cannot be in the file are flagged, not errors.
#[test]
fn invalid_offsets_are_flags() {
    let mut b = built(Enc::LE32);
    b.set_sh(1, Sh::Offset, 0xffff_ffff);
    let len = b.bytes.len() as u64;
    b.set_sh(2, Sh::Offset, len);
    b.set_ph(0, common::builder::Ph::Offset, 0xffff_ffff);
    let elf = parse(&b.bytes);
    assert!(elf.sections()[1].is_invalid_offset());
    assert!(elf.sections()[2].is_invalid_offset());
    assert!(!elf.sections()[3].is_invalid_offset());
    assert!(elf.program_headers()[0].is_invalid_offset());
    assert_eq!(elf.section_data(&elf.sections()[1]).unwrap().len(), 0);
}

/// Rule 15: the prelink trailer adjusts every address.
#[test]
fn prelinked_file() {
    for enc in Enc::ALL {
        let b = built(enc);
        let intact = parse(&b.bytes);
        let mut bytes = b.bytes.clone();
        let base: u32 = 0x4000_0000;
        bytes.extend_from_slice(&if enc.le {
            base.to_le_bytes()
        } else {
            base.to_be_bytes()
        });
        bytes.extend_from_slice(b"PRE ");
        let elf = parse(&bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.prelink_base(), Some(base));
        assert!(elf.is_prelinked());
        assert_eq!(elf.image_base(), u64::from(base));
        let text = &elf.sections()[1];
        assert_eq!(text.address(), text.sh_addr + u64::from(base));
        assert_eq!(
            elf.program_headers()[0].virtual_address(),
            intact.program_headers()[0].p_vaddr + u64::from(base)
        );
        // The tables named by the (adjusted) dynamic entries are the same.
        assert_eq!(
            elf.dynamic_symbol_table(),
            intact
                .dynamic_symbol_table()
                .map(|t| {
                    let mut t = t.clone();
                    t.address += u64::from(base);
                    t
                })
                .as_ref()
        );
        assert_eq!(
            elf.relocation_tables().len(),
            intact.relocation_tables().len()
        );
        assert_eq!(
            elf.dynamic_string_table().unwrap().section,
            intact.dynamic_string_table().unwrap().section
        );
    }
}

/// Rule 16: segments whose file sizes add up to the file length are taken
/// to follow one another from offset 0.
#[test]
fn segments_adding_up_to_the_file_are_laid_end_to_end() {
    let mut builder = common::builder::ElfBuilder::new(Enc::LE64);
    builder.load_segment = false;
    builder.section_headers = false;
    builder.add(Section::new(".data", sht::PROGBITS, vec![1; 100]));
    builder.extra_segments = vec![
        Segment {
            p_type: 1,
            offset: 0x5000,
            filesz: 76,
            memsz: 76,
            ..Segment::default()
        },
        Segment {
            p_type: 1,
            offset: 0x9000,
            ..Segment::default()
        },
    ];
    let mut b = builder.build();
    let total = b.bytes.len() as u64;
    b.set_ph(1, common::builder::Ph::Filesz, total - 76);
    let bytes = b.bytes;
    let elf = parse(&bytes);
    let offsets: Vec<_> = elf
        .program_headers()
        .iter()
        .map(|p| (p.p_offset, p.file_p_offset))
        .collect();
    assert_eq!(offsets, [(0, 0x5000), (76, 0x9000)]);
    assert!(!elf.program_headers()[1].is_invalid_offset());
}

/// Rule 19: compression headers are used only where Ghidra uses them.
#[test]
fn compressed_sections() {
    use std::io::Write;
    let plain: Vec<u8> = (0..4000u32).flat_map(|i| (i % 251).to_le_bytes()).collect();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&plain).unwrap();
    let compressed = encoder.finish().unwrap();
    for enc in Enc::ALL {
        let chdr = |ch_type: u32| {
            let mut data = Vec::new();
            enc.u32(&mut data, ch_type);
            if enc.is64 {
                enc.u32(&mut data, 0);
            }
            enc.word(&mut data, plain.len() as u64);
            enc.word(&mut data, 16);
            data.extend_from_slice(&compressed);
            data
        };
        let mut builder = common::builder::ElfBuilder::new(enc);
        let good = builder.add(Section::new(".debug_info", sht::PROGBITS, chdr(1)).flags(0x800));
        let zstd = builder.add(Section::new(".debug_line", sht::PROGBITS, chdr(2)).flags(0x800));
        let alloc = builder.add(
            Section::new(".data", sht::PROGBITS, chdr(1))
                .flags(0x800)
                .alloc(),
        );
        let b = builder.build();
        let elf = parse(&b.bytes);
        let s = |i: u32| &elf.sections()[i as usize];
        assert_eq!(
            messages(&elf),
            [
                format!(
                    "Error reading compressed section information: Unknown ELF section \
                     compression type 0x2 for section {zstd}"
                ),
                format!(
                    "Error reading compressed section information: Invalid compressed section: \
                     section {alloc} (offset 0x{:x}, size 0x{:x})",
                    s(alloc).sh_offset,
                    s(alloc).sh_size
                ),
            ]
        );
        assert!(
            elf.diagnostics()
                .iter()
                .all(|d| d.kind == DiagnosticKind::Compression)
        );
        assert!(s(good).is_compressed());
        assert_eq!(s(good).logical_size(), plain.len() as u64);
        assert_eq!(s(good).address_alignment(), 16);
        let out = elf.decompress_section(s(good)).unwrap();
        assert_eq!(out.error, None);
        assert_eq!(out.data, plain);
        assert!(elf.decompress_section(s(zstd)).is_none());
        assert!(elf.decompress_section(s(alloc)).is_none());

        // Damaged data: what was inflated plus the error.
        let mut bytes = b.bytes.clone();
        let start = (s(good).sh_offset + if enc.is64 { 24 } else { 12 }) as usize;
        let mid = start + compressed.len() / 2;
        bytes[mid..start + compressed.len()].fill(0xff);
        let elf = parse(&bytes);
        let out = elf
            .decompress_section(&elf.sections()[good as usize])
            .unwrap();
        assert!(out.error.is_some());
        assert!(out.data.len() < plain.len());
        assert_eq!(out.data[..200], plain[..200]);
    }
}

/// The clang fixture's `-gz=zlib` debug sections decompress completely.
#[test]
fn clang_compressed_debug_sections() {
    let bytes = common::files::fixture("zdebug-x86_64.o");
    let elf = parse(&bytes);
    let compressed: Vec<_> = elf
        .sections()
        .iter()
        .filter(|s| s.is_compressed())
        .collect();
    assert!(compressed.len() >= 3);
    for section in compressed {
        let out = elf.decompress_section(section).unwrap();
        assert_eq!(out.error, None, "{}", elf.section_name(section));
        assert_eq!(out.data.len() as u64, section.logical_size());
    }
    let info = elf.section_by_name(".debug_str").unwrap();
    let text = elf.decompress_section(info).unwrap().data;
    assert!(text.windows(8).any(|w| w == b"call_ext"));
}
