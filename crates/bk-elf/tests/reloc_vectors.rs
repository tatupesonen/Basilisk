//! `RELR`, Android `APS2` and MIPS-64 relocations against vectors computed
//! by hand (spec §6). The encoded bytes below are written out literally —
//! not produced by an encoder — and each expected value was worked out from
//! the format description, independently of the decoders.

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
use bk_elf::{ElfFile, RelocationFormat, RelocationLayout};
use common::builder::{ElfBuilder, Enc, Section, Sh, sht};

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

/// A file with one relocation section holding `data`. With `at_end`, the
/// data is appended to the file and the section points there, so a table
/// cut short really ends at the end of the file.
fn file_with(enc: Enc, sh_type: u32, entsize: u64, data: &[u8], at_end: bool) -> (Elf, u32) {
    let mut b = ElfBuilder::new(enc);
    let section = b.add(Section::new(".reloc", sh_type, data.to_vec()).entsize(entsize));
    let mut built = b.build();
    if at_end {
        let offset = built.bytes.len() as u64;
        built.bytes.extend_from_slice(data);
        built.set_sh(section, Sh::Offset, offset);
    }
    (parse(&built.bytes), section)
}

fn words(enc: Enc, values: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for &v in values {
        enc.word(&mut out, v);
    }
    out
}

// ---- RELR ---------------------------------------------------------------------

/// 64-bit: address 0x1000; bitmap 0b111 (bits 1, 2 → base 0x1008 + 0, + 8;
/// base becomes 0x1008 + 63·8 = 0x1200); bitmap with only bit 63 (→ 0x1200 +
/// 62·8 = 0x13f0); address 0x3000; bitmap 0b11 (→ 0x3008).
#[test]
fn relr_64_bit() {
    let expected = [0x1000, 0x1008, 0x1010, 0x13f0, 0x3000, 0x3008];
    for enc in [Enc::LE64, Enc::BE64] {
        let data = words(enc, &[0x1000, 0x7, 0x8000_0000_0000_0001, 0x3000, 0x3]);
        let (elf, section) = file_with(enc, sht::RELR, 8, &data, false);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        let table = elf.relocation_table_for_section(section).unwrap();
        assert_eq!(table.format, RelocationFormat::Relr);
        let decoded: Vec<_> = elf.relocations(table).collect();
        let offsets: Vec<u64> = decoded.iter().map(|r| r.r_offset).collect();
        assert_eq!(offsets, expected);
        let indexes: Vec<u32> = decoded.iter().map(|r| r.index).collect();
        assert_eq!(indexes, [0, 1, 2, 3, 4, 5]);
        assert!(decoded.iter().all(|r| r.r_info == 0 && r.r_addend == 0));
    }
}

/// 32-bit: the same shape with 4-byte words (a bitmap covers 31 slots):
/// 0x1000; 0b111 → 0x1004, 0x1008 (base becomes 0x1004 + 31·4 = 0x1080);
/// bit 31 → 0x1080 + 30·4 = 0x10f8; 0x3000; 0b11 → 0x3004.
#[test]
fn relr_32_bit() {
    let expected = [0x1000, 0x1004, 0x1008, 0x10f8, 0x3000, 0x3004];
    for enc in [Enc::LE32, Enc::BE32] {
        let data = words(enc, &[0x1000, 0x7, 0x8000_0001, 0x3000, 0x3]);
        let (elf, section) = file_with(enc, sht::RELR, 4, &data, false);
        let table = elf.relocation_table_for_section(section).unwrap();
        let offsets: Vec<u64> = elf.relocations(table).map(|r| r.r_offset).collect();
        assert_eq!(offsets, expected);
    }
}

/// Ghidra takes the first word as an address even when its low bit is
/// set, and a bitmap of just the marker bit yields nothing.
#[test]
fn relr_first_word_and_empty_bitmap() {
    let enc = Enc::LE64;
    let data = words(enc, &[0x1001, 0x1, 0x2000]);
    let (elf, section) = file_with(enc, sht::RELR, 8, &data, false);
    let table = elf.relocation_table_for_section(section).unwrap();
    let offsets: Vec<u64> = elf.relocations(table).map(|r| r.r_offset).collect();
    assert_eq!(offsets, [0x1001, 0x2000]);
}

/// A table cut by the end of the file keeps the whole words before the cut.
#[test]
fn relr_cut_by_the_end_of_the_file() {
    let enc = Enc::LE64;
    let mut data = words(enc, &[0x1000, 0x7, 0x3000]);
    data.truncate(20);
    let (elf, section) = file_with(enc, sht::RELR, 8, &data, true);
    assert_eq!(
        messages(&elf),
        ["Truncated ELF RELR Relocation table due to unexpected EOF"]
    );
    let table = elf.relocation_table_for_section(section).unwrap();
    assert!(table.truncated);
    let offsets: Vec<u64> = elf.relocations(table).map(|r| r.r_offset).collect();
    assert_eq!(offsets, [0x1000, 0x1008, 0x1010]);
}

// ---- Android APS2 ----------------------------------------------------------------

/// Four `RELA` relocations in two groups.
///
/// ```text
/// 04          count 4
/// 80 20       base offset 0x1000
/// 02 0b       group: size 2, flags INFO|OFFSET_DELTA|HAS_ADDEND (1|2|8)
/// 08          group offset delta 8
/// 83 08       group info 0x403
/// 20          addend += 0x20  → (0x1008, 0x403, 0x20)
/// 10          addend += 0x10  → (0x1010, 0x403, 0x30)
/// 02 0c       group: size 2, flags ADDEND|HAS_ADDEND (4|8)
/// 50          group addend delta -0x30 → addend 0
/// 10 81 08    delta 0x10, info 0x401      → (0x1020, 0x401, 0)
/// 08 82 88 80 80 10   delta 8, info 0x1_0000_0402 → (0x1028, sym 1 type 0x402, 0)
/// ```
const APS2_RELA: &[u8] =
    b"APS2\x04\x80\x20\x02\x0b\x08\x83\x08\x20\x10\x02\x0c\x50\x10\x81\x08\x08\x82\x88\x80\x80\x10";

#[test]
fn aps2_rela_vector() {
    for enc in [Enc::LE64, Enc::BE64] {
        let (elf, section) = file_with(enc, sht::ANDROID_RELA, 0, APS2_RELA, false);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        let table = elf.relocation_table_for_section(section).unwrap();
        assert_eq!(table.format, RelocationFormat::Android);
        assert!(table.has_addend);
        assert_eq!(table.relocation_count(), Some(4));
        let decoded: Vec<_> = elf
            .relocations(table)
            .map(|r| {
                (
                    r.r_offset,
                    r.r_info,
                    r.r_addend,
                    r.symbol_index(),
                    r.relocation_type(),
                )
            })
            .collect();
        assert_eq!(
            decoded,
            [
                (0x1008, 0x403, 0x20, 0, 0x403),
                (0x1010, 0x403, 0x30, 0, 0x403),
                (0x1020, 0x401, 0, 0, 0x401),
                (0x1028, 0x1_0000_0402, 0, 1, 0x402),
            ]
        );
    }
}

/// A group grouped by addend in a `REL` table: Ghidra drops every
/// relocation of the table, including those decoded before it.
///
/// ```text
/// 02 00          count 2, base 0
/// 01 00 08 07    group of 1, no flags: delta 8, info 7 → (8, 7)
/// 01 0c 05       group of 1, flags ADDEND|HAS_ADDEND, addend 5 → rejected
/// ```
#[test]
fn aps2_rel_with_an_addend_group_is_emptied() {
    let data = b"APS2\x02\x00\x01\x00\x08\x07\x01\x0c\x05\x08\x07";
    let (elf, section) = file_with(Enc::LE32, sht::ANDROID_REL, 0, data, false);
    assert_eq!(
        messages(&elf),
        [
            "ELF Android APS2 Relocation processing failed.  Unexpected r_addend in android.rel section"
        ]
    );
    let table = elf.relocation_table_for_section(section).unwrap();
    assert_eq!(table.relocation_count(), Some(0));
    assert_eq!(elf.relocations(table).count(), 0);
}

/// The `RELA` vector read as a `REL` table: a group flagged as having
/// addends (but not grouped by addend) reads none, so the decoder falls out
/// of step exactly as Ghidra's does and stops at the next group header.
#[test]
fn aps2_rela_bytes_read_as_rel() {
    let (elf, section) = file_with(Enc::LE32, sht::ANDROID_REL, 0, APS2_RELA, false);
    assert_eq!(
        messages(&elf),
        ["ELF Android APS2 Group relocation count 32 exceeded total count 2"]
    );
    let table = elf.relocation_table_for_section(section).unwrap();
    let decoded: Vec<_> = elf
        .relocations(table)
        .map(|r| (r.r_offset, r.r_info, r.r_addend))
        .collect();
    assert_eq!(decoded, [(0x1008, 0x403, 0), (0x1010, 0x403, 0)]);
}

/// A `REL` table: 3 relocations, one group sharing the info (R_ARM_RELATIVE
/// 0x17) with per-relocation deltas 4, 4, 0x7c from base 0x2000.
///
/// ```text
/// 03 80 c0 00   count 3, base 0x2000
/// 03 01 17      group: size 3, flags INFO, info 0x17
/// 04 04 fc 00   deltas 4, 4, 0x7c
/// ```
#[test]
fn aps2_rel_vector() {
    let data = b"APS2\x03\x80\xc0\x00\x03\x01\x17\x04\x04\xfc\x00";
    for enc in [Enc::LE32, Enc::BE32] {
        let (elf, section) = file_with(enc, sht::ANDROID_REL, 0, data, false);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        let table = elf.relocation_table_for_section(section).unwrap();
        assert!(!table.has_addend);
        let decoded: Vec<_> = elf
            .relocations(table)
            .map(|r| (r.r_offset, r.relocation_type(), r.r_addend))
            .collect();
        assert_eq!(
            decoded,
            [(0x2004, 0x17, 0), (0x2008, 0x17, 0), (0x2084, 0x17, 0)]
        );
    }
}

#[test]
fn aps2_errors() {
    let enc = Enc::LE64;
    let cases: [(&[u8], &str, usize); 5] = [
        (
            b"APS2\x00",
            "Unexpected ELF Android APS2 relocation count 0",
            0,
        ),
        (
            b"APS2\x7f",
            "Unexpected ELF Android APS2 relocation count -1",
            0,
        ),
        // count 2, base 0, group size 0.
        (
            b"APS2\x02\x00\x00",
            "Unexpected ELF Android APS2 Group relocation count 0",
            0,
        ),
        // count 1, base 0, group size 2.
        (
            b"APS2\x01\x00\x02",
            "ELF Android APS2 Group relocation count 2 exceeded total count 1",
            0,
        ),
        // count 2, base 0, group of 1 (info 7, delta 8), then an 11-byte LEB128.
        (
            b"APS2\x02\x00\x01\x00\x08\x07\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01",
            "Error reading Android relocation table: Unsupported LEB128 value, too large to fit in 64bit java long variable",
            1,
        ),
    ];
    for (data, message, count) in cases {
        let (elf, section) = file_with(enc, sht::ANDROID_RELA, 0, data, false);
        assert_eq!(messages(&elf), [message]);
        let table = elf.relocation_table_for_section(section).unwrap();
        assert_eq!(table.relocation_count(), Some(count as u64));
        assert_eq!(elf.relocations(table).count(), count);
        assert!(!table.truncated);
    }
}

/// A table cut by the end of the file keeps the relocations decoded before
/// the cut.
#[test]
fn aps2_cut_by_the_end_of_the_file() {
    let cut = &APS2_RELA[..APS2_RELA.len() - 3];
    let (elf, section) = file_with(Enc::LE64, sht::ANDROID_RELA, 0, cut, true);
    assert_eq!(
        messages(&elf),
        ["Truncated Android relocation table due to unexpected EOF"]
    );
    let table = elf.relocation_table_for_section(section).unwrap();
    assert!(table.truncated);
    let offsets: Vec<u64> = elf.relocations(table).map(|r| r.r_offset).collect();
    assert_eq!(offsets, [0x1008, 0x1010, 0x1020]);
}

/// A declared count beyond the length of the file is capped (a group
/// sharing delta and info costs no bytes per relocation).
#[test]
fn aps2_count_is_capped_by_the_file_length() {
    // count 2^40, base 0, one group of 2^40 sharing delta 8 and info 7.
    let data = b"APS2\x80\x80\x80\x80\x80\x20\x00\x80\x80\x80\x80\x80\x20\x03\x08\x07";
    let (elf, section) = file_with(Enc::LE64, sht::ANDROID_RELA, 0, data, false);
    let len = elf.file_len();
    assert_eq!(
        messages(&elf)[0],
        format!("Android relocation count 1099511627776 exceeds file capacity {len}; truncating")
    );
    let table = elf.relocation_table_for_section(section).unwrap();
    // The group is larger than the capped remaining count.
    assert_eq!(
        messages(&elf)[1],
        format!("ELF Android APS2 Group relocation count 1099511627776 exceeded total count {len}")
    );
    assert_eq!(table.relocation_count(), Some(0));
}

// ---- MIPS-64 ------------------------------------------------------------------------

/// MIPS-64 `r_info`: r_sym (4 bytes in the file's order), r_ssym, r_type3,
/// r_type2, r_type, in that byte order in the file.
#[test]
fn mips64_relocation_layout() {
    for enc in [Enc::LE64, Enc::BE64] {
        let mut data = Vec::new();
        enc.u64(&mut data, 0x1234); // r_offset
        // r_info bytes as stored: sym 0x00000102 in file order, ssym 5, types 0x12, 0x03, 0x18.
        let sym = if enc.le {
            [0x02, 0x01, 0x00, 0x00]
        } else {
            [0x00, 0x00, 0x01, 0x02]
        };
        data.extend_from_slice(&sym);
        data.extend_from_slice(&[0x05, 0x12, 0x03, 0x18]);
        enc.u64(&mut data, (-8i64) as u64); // r_addend
        let mut b = ElfBuilder::new(enc);
        b.machine = 8; // EM_MIPS
        let section = b.add(Section::new(".rela.text", sht::RELA, data).entsize(24));
        let elf = parse(&b.build().bytes);
        assert!(matches!(
            elf.relocation_layout(),
            RelocationLayout::Mips64 { .. }
        ));
        let table = elf.relocation_table_for_section(section).unwrap();
        let r = elf.relocations(table).next().unwrap();
        assert_eq!(r.r_offset, 0x1234);
        assert_eq!(r.symbol_index(), 0x102);
        assert_eq!(r.special_symbol_index(), Some(5));
        assert_eq!(r.relocation_type(), 0x12_0318);
        assert_eq!(r.r_addend, -8);
    }
}
