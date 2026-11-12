//! Allocation is bounded by the input (spec §6, ADR-009): parsing a file
//! and reading everything from it never holds more than a fixed multiple of
//! its size on the heap, measured with `dhat`'s heap statistics.
//!
//! Decompression is the one exception by design: `SHF_COMPRESSED` data may
//! legitimately inflate up to zlib's maximum ratio, so its output is
//! bounded by 1040 times the compressed size instead (`compress.rs`); the
//! walk here skips it.
//!
//! This is its own test binary because `dhat` replaces the global
//! allocator and allows one profiler at a time.

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

use bk_bin::MemoryProvider;
use bk_elf::ElfFile;
use common::builder::{Enc, sample};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Bytes of heap allowed per byte of input, and a constant for the small
/// fixed costs (vectors' first allocations, diagnostics).
const PER_BYTE: u64 = 32;
const FIXED: u64 = 64 * 1024;

/// Everything the fuzz target reads, except decompression.
fn walk(data: &[u8]) {
    let provider = MemoryProvider::new(data);
    let Ok(elf) = ElfFile::parse(&provider) else {
        return;
    };
    for section in elf.sections() {
        drop(elf.section_name(section));
        drop(elf.section_notes(section));
        drop(elf.version_definitions(section));
        drop(elf.version_needs(section));
        drop(elf.symbol_versions(section));
    }
    drop(elf.program_notes());
    for name in elf.dynamic_library_names() {
        drop(name);
    }
    for table in elf.symbol_tables() {
        for symbol in elf.symbols(table) {
            drop(elf.formatted_symbol_name(table, &symbol));
        }
    }
    for table in elf.relocation_tables() {
        for relocation in elf.relocations(table) {
            std::hint::black_box(relocation);
        }
    }
    drop((elf.abi_tag(), elf.build_id(), elf.gnu_property()));
    drop((elf.debug_link(), elf.debug_alt_link(), elf.comment()));
}

/// The peak heap use of `walk(data)` beyond what was in use before.
fn peak(data: &[u8]) -> u64 {
    let before = dhat::HeapStats::get();
    walk(data);
    let after = dhat::HeapStats::get();
    // `max_bytes` is the peak since the profiler started; it only grows, so
    // measure each input against the heap in use at its start.
    (after.max_bytes as u64).saturating_sub(before.curr_bytes as u64)
}

#[test]
fn heap_use_is_a_fixed_multiple_of_the_input() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let check = |data: &[u8]| {
        let limit = PER_BYTE * data.len() as u64 + FIXED;
        let used = peak(data);
        assert!(used <= limit, "{used} bytes of heap for {} bytes of input", data.len());
    };

    // Real files and the builder sample.
    for path in common::files::fixture_files() {
        check(&std::fs::read(path).unwrap());
    }
    for enc in Enc::ALL {
        check(&sample(enc).0.build().bytes);
    }

    // Hostile counts: every count and size field of the sample set to large
    // values, then random damage.
    let mut runner = TestRunner::new(Config::with_cases(256));
    let strategy = (
        0usize..4,
        prop::collection::vec((0usize..1 << 16, any::<u8>()), 1..24),
    );
    runner
        .run(&strategy, |(enc, edits)| {
            let mut bytes = sample(Enc::ALL[enc]).0.build().bytes;
            let len = bytes.len();
            for (at, value) in edits {
                bytes[at % len] = value;
            }
            check(&bytes);
            Ok(())
        })
        .unwrap();
}
