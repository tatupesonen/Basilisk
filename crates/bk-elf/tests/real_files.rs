//! Real files parse without diagnostics and agree with the `object` crate
//! on everything both expose: the ELF files in the Ghidra tree (referenced
//! in place through `BASILISK_GHIDRA_DIR`, default `<workspace>/../ghidra`;
//! skipped with a message when absent) and the clang/lld fixtures in
//! `tests/fixtures`.

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

use std::path::Path;

use bk_bin::MemoryProvider;
use bk_elf::{ElfError, ElfFile};

fn check_file(path: &Path) -> common::oracle::Covered {
    let data = std::fs::read(path).unwrap();
    let provider = MemoryProvider::new(&data[..]);
    let elf = ElfFile::parse(&provider).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(elf.diagnostics(), [], "{}", path.display());
    assert_eq!(elf.file_len(), data.len() as u64);
    common::oracle::check(&data, &elf)
}

#[test]
fn ghidra_tree_elf_files_parse_cleanly_and_agree_with_object() {
    let Some(ghidra) = common::files::ghidra_dir() else {
        return;
    };
    let files = common::files::ghidra_elf_files(&ghidra);
    assert!(
        files.len() >= 4,
        "expected little.elf, big.elf and the exercise files, got {files:?}"
    );
    let mut symbols = 0;
    for path in &files {
        symbols += check_file(path).symbols;
    }
    assert!(symbols > 100);
    eprintln!(
        "checked {} ELF files from {}",
        files.len(),
        ghidra.display()
    );
}

#[test]
fn fixtures_parse_cleanly_and_agree_with_object() {
    let files = common::files::fixture_files();
    assert!(files.len() >= 17, "{files:?}");
    let mut total = common::oracle::Covered::default();
    for path in &files {
        let covered = check_file(path);
        total.symbols += covered.symbols;
        total.relocations += covered.relocations;
        total.relr_relocations += covered.relr_relocations;
    }
    assert!(total.symbols > 200, "{total:?}");
    assert!(total.relocations > 50, "{total:?}");
    assert!(total.relr_relocations > 20, "{total:?}");
}

#[test]
fn not_elf_and_short_files_are_fatal() {
    let parse = |bytes: &[u8]| ElfFile::parse(MemoryProvider::new(bytes.to_vec())).map(|_| ());
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
