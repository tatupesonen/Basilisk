//! Benchmarks of spec 5.8, `#[ignore]` release tests (numbers in
//! `docs/PERF.md`):
//!
//!     cargo test -p bk-decomp-symbols --release --test bench -- --ignored --nocapture --test-threads=1
//!
//! 100,000 global symbols inserted, then 1,000,000 `query_by_addr` and
//! `query_container` calls over them; `print_entries` of a 10,000-entry
//! scope; the context look-up. Each prints the best of five runs.
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

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use bk_core::Address;
use bk_decomp_symbols::{ContextNames, Database};
use bk_decomp_types::{Metatype, TypeFactory};
use common::small::{self, RAM};

const RUNS: usize = 5;

fn best(mut f: impl FnMut() -> Duration) -> Duration {
    (0..RUNS).map(|_| f()).min().unwrap()
}

/// A small pseudo-random sequence (xorshift), so runs are repeatable.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// 100,000 symbols of 1–16 bytes at 16-byte steps from `ram:0x10000`, a
/// tenth of them overlapping the next.
fn populated(types: &mut TypeFactory) -> (Database, Vec<Address>) {
    let (mut db, _) = small::db();
    let global = db.global().unwrap();
    let sizes: Vec<_> = [1, 2, 4, 8, 16, 24]
        .iter()
        .map(|s| types.base(*s, Metatype::Unknown).unwrap())
        .collect();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut addrs = Vec::with_capacity(100_000);
    for i in 0..100_000u64 {
        let addr = Address::new(RAM, 0x10000 + i * 16);
        let pick = if i % 10 == 0 {
            5
        } else {
            (rng.next() % 5) as usize
        };
        db.add_symbol_at(
            global,
            &format!("s{i}"),
            sizes[pick],
            addr,
            Address::INVALID,
            types,
        )
        .unwrap();
        addrs.push(addr);
    }
    (db, addrs)
}

#[test]
#[ignore = "benchmark"]
fn bench_global_symbols() {
    let m = small::spaces(false);
    let mut types = small::types(&m);
    let insert = best(|| {
        let start = Instant::now();
        black_box(populated(&mut types));
        start.elapsed()
    });
    eprintln!(
        "insert 100,000 global symbols: {:.1} ms ({:.0} ns/symbol)",
        insert.as_secs_f64() * 1e3,
        insert.as_nanos() as f64 / 1e5
    );
    let (db, _) = populated(&mut types);
    let global = db.global().unwrap();
    let mut rng = Rng(42);
    let probes: Vec<Address> = (0..1_000_000)
        .map(|_| Address::new(RAM, 0x10000 + rng.next() % (100_000 * 16 + 64)))
        .collect();
    let by_addr = best(|| {
        let start = Instant::now();
        let mut hits = 0usize;
        for a in &probes {
            hits += usize::from(
                db.query_by_addr(global, *a, Address::INVALID)
                    .unwrap()
                    .is_some(),
            );
        }
        black_box(hits);
        start.elapsed()
    });
    let container = best(|| {
        let start = Instant::now();
        let mut hits = 0usize;
        for a in &probes {
            hits += usize::from(
                db.query_container(global, *a, 4, Address::INVALID)
                    .unwrap()
                    .is_some(),
            );
        }
        black_box(hits);
        start.elapsed()
    });
    eprintln!(
        "1,000,000 query_by_addr: {:.1} ms ({:.0} ns/call)",
        by_addr.as_secs_f64() * 1e3,
        by_addr.as_nanos() as f64 / 1e6
    );
    eprintln!(
        "1,000,000 query_container (size 4): {:.1} ms ({:.0} ns/call)",
        container.as_secs_f64() * 1e3,
        container.as_nanos() as f64 / 1e6
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_print_entries() {
    let m = small::spaces(false);
    let mut types = small::types(&m);
    let (mut db, _) = small::db();
    let global = db.global().unwrap();
    let ty = types.base(4, Metatype::Int).unwrap();
    for i in 0..10_000u64 {
        db.add_symbol_at(
            global,
            &format!("v{i}"),
            ty,
            Address::new(RAM, 0x1000 + i * 4),
            Address::INVALID,
            &types,
        )
        .unwrap();
    }
    let mut len = 0;
    let t = best(|| {
        let start = Instant::now();
        len = black_box(db.print_entries(global, &types).unwrap()).len();
        start.elapsed()
    });
    eprintln!(
        "print_entries, 10,000 entries ({len} bytes): {:.2} ms",
        t.as_secs_f64() * 1e3
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_context_lookup() {
    let m = small::spaces(false);
    let mut ctx = ContextNames::new();
    ctx.set_space_limits(&m);
    ctx.register_variable("mode", 0, 3).unwrap();
    ctx.register_variable("wide", 30, 33).unwrap();
    // 10,000 split points.
    for i in 0..10_000u64 {
        ctx.set_variable("mode", Address::new(RAM, i * 64), (i % 16) as u32)
            .unwrap();
    }
    let mut rng = Rng(7);
    let probes: Vec<Address> = (0..1_000_000)
        .map(|_| Address::new(RAM, rng.next() % (10_000 * 64)))
        .collect();
    let t = best(|| {
        let start = Instant::now();
        let mut sum = 0u64;
        for a in &probes {
            sum += u64::from(ctx.variable_at("mode", *a).unwrap());
            sum += ctx.context(*a).0.len() as u64;
        }
        black_box(sum);
        start.elapsed()
    });
    eprintln!(
        "1,000,000 context look-ups (variable_at + context) over 10,000 split points: {:.1} ms ({:.0} ns/look-up)",
        t.as_secs_f64() * 1e3,
        t.as_nanos() as f64 / 1e6
    );
}
