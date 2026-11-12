//! Property tests: no input makes the parser or any on-demand read panic —
//! arbitrary bytes behind an ELF identification, and builder files and real
//! fixtures with bytes overwritten at random.

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

#[allow(dead_code, unreachable_pub, reason = "each test crate uses part of the support code")]
mod common;

#[allow(dead_code, unreachable_pub, reason = "shared with the fuzz target")]
#[path = "../../../fuzz/fuzz_targets/bin_elf/mod.rs"]
mod bin_elf;

use common::builder::{Enc, sample};
use proptest::prelude::*;

/// An ELF identification for one of the four encodings, then `rest`.
fn with_ident(class: u8, data: u8, rest: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x7f, b'E', b'L', b'F', class, data, 1, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(rest);
    bytes
}

/// Overwrites `bytes` at the given (position, value) pairs.
fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8)]) -> Vec<u8> {
    let len = bytes.len();
    for &(at, value) in edits {
        bytes[at % len] = value;
    }
    bytes
}

/// Mutations that hit header fields more often than uniform positions
/// would: positions are drawn from the first 256 bytes half the time.
fn edits() -> impl Strategy<Value = Vec<(usize, u8)>> {
    prop::collection::vec(
        (prop_oneof![0usize..256, 0usize..1 << 20], any::<u8>()),
        1..16,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(
        class in 0u8..4,
        data in 0u8..4,
        rest in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        bin_elf::elf_parse(&with_ident(class, data, &rest));
    }

    #[test]
    fn mutated_builder_files_never_panic(enc in 0usize..4, edits in edits()) {
        let bytes = sample(Enc::ALL[enc]).0.build().bytes;
        bin_elf::elf_parse(&mutate(bytes, &edits));
    }

    #[test]
    fn mutated_fixtures_never_panic(file in 0usize..17, edits in edits()) {
        let files = common::files::fixture_files();
        let bytes = std::fs::read(&files[file % files.len()]).unwrap();
        bin_elf::elf_parse(&mutate(bytes, &edits));
    }

    #[test]
    fn truncated_files_never_panic(enc in 0usize..4, keep in 0usize..2048) {
        let bytes = sample(Enc::ALL[enc]).0.build().bytes;
        bin_elf::elf_parse(&bytes[..keep.min(bytes.len())]);
    }
}
