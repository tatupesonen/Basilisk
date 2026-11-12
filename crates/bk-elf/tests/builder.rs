//! The fixture builder against the `object` crate: what the builder writes
//! is read the same way by `object` and by `bk-elf`, in both classes and
//! byte orders. This anchors the builder to an independent reader before
//! the tolerance tests damage its output.

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
use bk_elf::ElfFile;
use common::builder::{Enc, sample};

#[test]
fn sample_agrees_with_object_in_every_class_and_byte_order() {
    for enc in Enc::ALL {
        let (builder, index) = sample(enc);
        let built = builder.build();
        let provider = MemoryProvider::new(&built.bytes[..]);
        let elf = ElfFile::parse(&provider).unwrap();
        assert_eq!(elf.diagnostics(), [], "{enc:?}");
        let covered = common::oracle::check(&built.bytes, &elf);
        assert_eq!(covered.symbols, 5 + 5, "{enc:?}");
        assert_eq!(covered.relocations, 4 + 2, "{enc:?}");
        assert_eq!(covered.relr_relocations, 4, "{enc:?}");

        let names: Vec<_> = elf.dynamic_library_names().collect();
        assert_eq!(names, ["libc.so.6", "libm.so.6"]);
        let dynsym = elf.dynamic_symbol_table().unwrap();
        assert_eq!(dynsym.section, Some(index.dynsym));
        assert!(dynsym.is_dynamic);
        let relr = elf.relocation_table_for_section(index.relr).unwrap();
        let offsets: Vec<u64> = elf.relocations(relr).map(|r| r.r_offset).collect();
        let w = enc.word_size();
        assert_eq!(offsets, [0x10600, 0x10600 + w, 0x10600 + 3 * w, 0x10800]);
        // The order Ghidra processes tables in: DT_REL(A), DT_JMPREL, DT_RELR.
        let order: Vec<_> = elf.relocation_tables().iter().map(|t| t.section).collect();
        assert_eq!(
            order,
            [Some(index.reladyn), Some(index.relplt), Some(index.relr)]
        );
        assert_eq!(
            elf.relocation_tables()[1].section_to_relocate,
            Some(index.text)
        );
    }
}
