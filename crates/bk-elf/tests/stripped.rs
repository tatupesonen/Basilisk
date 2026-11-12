//! Files without section headers: the dynamic symbol table, the dynamic
//! string table and the dynamic relocation tables are found through the
//! dynamic table and the program headers (Ghidra's `parseDynamicSymbolTable`
//! and `parseDynamicRelocTable`), sized through `DT_HASH` or `DT_GNU_HASH`.
//!
//! Each lld fixture is parsed twice, intact and with `e_shoff` zeroed; the
//! second parse must find the same dynamic symbols, names and relocations.

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
use bk_elf::{DynamicTag, ElfClass, ElfFile};
use rstest::rstest;

fn strip_section_headers(bytes: &mut [u8]) {
    let (offset, len) = match bytes[4] {
        1 => (0x20, 4),
        _ => (0x28, 8),
    };
    bytes[offset..offset + len].fill(0);
}

/// (name, value, info, shndx) of every dynamic symbol, then the relocations
/// as (file offset of table, `r_offset`, `r_info`, `r_addend`).
type Summary = (
    Vec<(String, u64, u8, u16)>,
    Vec<(u64, u64, u64, i64)>,
    Vec<String>,
);

fn summary(bytes: &[u8]) -> (Summary, ElfFile<MemoryProvider<Vec<u8>>>) {
    let elf = ElfFile::parse(MemoryProvider::new(bytes.to_vec())).unwrap();
    let table = elf.dynamic_symbol_table().expect("dynamic symbol table");
    let symbols = elf
        .symbols(table)
        .map(|s| {
            let name = elf.symbol_name(table, &s).unwrap().unwrap().into_owned();
            (name, s.st_value, s.st_info, s.st_shndx)
        })
        .collect();
    let relocations = elf
        .relocation_tables()
        .iter()
        .flat_map(|t| {
            elf.relocations(t)
                .map(move |r| (t.file_offset, r.r_offset, r.r_info, r.r_addend))
        })
        .collect();
    let libraries = elf
        .dynamic_library_names()
        .map(std::borrow::Cow::into_owned)
        .collect();
    ((symbols, relocations, libraries), elf)
}

#[rstest]
#[case::gnu_hash_x86_64("plain-x86_64.so", DynamicTag::DT_GNU_HASH)]
#[case::gnu_hash_relr("relr-x86_64.so", DynamicTag::DT_GNU_HASH)]
#[case::sysv_hash_i686("plain-i686.so", DynamicTag::DT_HASH)]
#[case::sysv_hash_relr_i686("relr-i686.so", DynamicTag::DT_HASH)]
#[case::both_hashes_aarch64("plain-aarch64.so", DynamicTag::DT_HASH)]
#[case::android_aarch64("aps2-aarch64.so", DynamicTag::DT_HASH)]
#[case::android_relr_aarch64("aps2-relr-aarch64.so", DynamicTag::DT_GNU_HASH)]
#[case::sysv_hash_arm("aps2-arm.so", DynamicTag::DT_HASH)]
#[case::gnu_hash_big_endian("plain-aarch64be.so", DynamicTag::DT_GNU_HASH)]
#[case::sysv_hash_big_endian("aps2-armbe.so", DynamicTag::DT_HASH)]
#[case::versioned_library("libdep-x86_64.so", DynamicTag::DT_GNU_HASH)]
fn stripped_file_resolves_through_the_dynamic_table(#[case] name: &str, #[case] hash: DynamicTag) {
    let intact = common::files::fixture(name);
    let mut stripped = intact.clone();
    strip_section_headers(&mut stripped);

    let (expected, intact_elf) = summary(&intact);
    let (actual, elf) = summary(&stripped);
    assert!(intact_elf.dynamic_table().unwrap().contains(hash));
    assert_eq!(elf.sections(), []);
    assert_eq!(elf.diagnostics(), []);
    let table = elf.dynamic_symbol_table().unwrap();
    assert_eq!(table.section, None);
    assert!(table.is_dynamic);
    assert_eq!(
        u64::from(table.entry_size),
        match elf.header().class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        }
    );
    assert!(expected.0.len() >= 3, "{:?}", expected.0);
    assert_eq!(actual, expected);
}
