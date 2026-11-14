//! Heap held by the x86-64 model (`features/sla.md` acceptance 3), measured
//! with `dhat` as `bk-elf` does. Run as an ignored release test:
//!
//! ```text
//! BASILISK_REFERENCE_DIR=../reference cargo test --release -p bk-sla --test bench_heap -- --ignored --nocapture
//! ```
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

use bk_sla::{Limits, Sla, inflate};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
#[ignore = "benchmark"]
fn x86_64_model_heap() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let limits = Limits::default();
    let path = reference.sla_file("x86", "x86-64");
    let stream = inflate(&std::fs::read(&path).unwrap(), &limits).unwrap();
    let _profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    let sla = Sla::decode_packed(&stream, &limits).unwrap();
    let after = dhat::HeapStats::get();
    let held = after.curr_bytes - before.curr_bytes;
    eprintln!(
        "x86-64 model: {:.2} MB held ({:.2}x the {:.2} MB stream; arenas report {:.2} MB); peak during decode {:.2} MB; {} allocations",
        held as f64 / 1e6,
        held as f64 / stream.len() as f64,
        stream.len() as f64 / 1e6,
        sla.heap_bytes() as f64 / 1e6,
        after.max_bytes.saturating_sub(before.curr_bytes) as f64 / 1e6,
        after.total_blocks - before.total_blocks
    );
    assert!(
        held <= 8 * stream.len(),
        "heap budget: at most 8x the inflated stream"
    );
}
