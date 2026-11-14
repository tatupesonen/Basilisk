//! No method allocates (spec 5): every method is called on a spread of
//! inputs under `dhat`'s heap profiler, and the number of allocations made
//! meanwhile must be zero. `Display` is excluded: it writes into the
//! caller's formatter. Its own test binary because `dhat` replaces the
//! global allocator.

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

use bk_decomp_range::CircleRange;
use bk_pcode::OpCode;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn methods_do_not_allocate() {
    let ranges = [
        CircleRange::empty(),
        CircleRange::full(1),
        CircleRange::new(0x10, 0x30, 4, 4),
        CircleRange::new(0xfff0, 0x10, 2, 1),
        CircleRange::single(7, 8),
        CircleRange::from_bool(true),
        CircleRange::from_parts(5, 9, u64::MAX, 0, false),
        CircleRange::from_parts(u64::MAX, 1, 0xff, -4, false),
    ];
    let _profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    let mut sink = 0u64;
    for a in &ranges {
        sink = sink
            .wrapping_add(a.count())
            .wrapping_add(a.max())
            .wrapping_add(a.max_info() as u64);
        let _ = a.translate_2op();
        for b in &ranges {
            let mut c = *a;
            let _ = c.intersect(b);
            let mut c = *a;
            let _ = c.circle_union(b);
            let mut c = *a;
            let _ = c.minimal_container(b, 32);
            let mut c = *a;
            c.widen(b, true);
            let _ = a.contains(b);
            for op in OpCode::ALL {
                let mut c = *a;
                let _ = c.pull_back_unary(op, 1, 4);
                let mut c = *a;
                let _ = c.pull_back_binary(op, 3, 1, 4, 4);
                let mut c = CircleRange::empty();
                let _ = c.push_forward_unary(op, a, 4, 8);
                let mut c = CircleRange::empty();
                let _ = c.push_forward_binary(op, a, b, 4, 4, 32);
                let mut c = CircleRange::empty();
                let _ = c.push_forward_trinary(op, [a, b, a], 4, 4, 32);
            }
        }
        let mut c = *a;
        c.set_stride(8, 1);
        let mut c = *a;
        let _ = c.set_nz_mask(0xf0, 1);
        let mut c = *a;
        let _ = c.invert();
    }
    let after = dhat::HeapStats::get();
    assert_eq!(
        after.total_blocks, before.total_blocks,
        "a method allocated"
    );
    assert_ne!(sink, 1);
}
