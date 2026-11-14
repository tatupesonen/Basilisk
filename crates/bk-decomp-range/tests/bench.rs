//! Benchmarks (`docs/features/decomp-range.md` 6.4), as `#[ignore]` tests
//! that print nanoseconds per call. Run them in release mode:
//!
//! ```text
//! cargo test -p bk-decomp-range --release --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Numbers are recorded in `docs/PERF.md` under `bk-decomp-range`.

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

use std::hint::black_box;
use std::time::Instant;

use bk_decomp_range::CircleRange;
use bk_pcode::OpCode;

/// splitmix64, so runs are comparable.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

const N: usize = 4096;
const ROUNDS: usize = 500;

/// 4,096 well-formed ranges of 1, 2, 4 and 8 bytes with steps 1–8.
fn ranges() -> Vec<CircleRange> {
    let mut rng = Rng(42);
    (0..N)
        .map(|_| {
            let size = [1, 2, 4, 8][(rng.next() % 4) as usize];
            let step = [1, 1, 2, 4, 8][(rng.next() % 5) as usize];
            let s = step as u64;
            let left = rng.next() & !(s - 1);
            let len = rng.next() % 64;
            CircleRange::new(left, left.wrapping_add(len * s), size, step)
        })
        .collect()
}

fn report(name: &str, start: Instant, calls: usize) {
    let ns = start.elapsed().as_nanos() as f64 / calls as f64;
    eprintln!("{name}: {ns:.2} ns/call ({calls} calls)");
}

#[test]
#[ignore = "benchmark"]
fn intersect() {
    let rs = ranges();
    let start = Instant::now();
    for _ in 0..ROUNDS {
        for w in rs.windows(2) {
            let mut c = w[0];
            let _ = black_box(c.intersect(black_box(&w[1])));
            black_box(c);
        }
    }
    report("intersect", start, ROUNDS * (N - 1));
}

#[test]
#[ignore = "benchmark"]
fn pull_back_binary() {
    let rs = ranges();
    let ops = [
        OpCode::IntAdd,
        OpCode::IntSub,
        OpCode::IntLess,
        OpCode::IntEqual,
        OpCode::IntRight,
        OpCode::IntSRight,
    ];
    let start = Instant::now();
    for round in 0..ROUNDS {
        for (i, r) in rs.iter().enumerate() {
            let mut c = *r;
            let op = ops[(i + round) % ops.len()];
            black_box(c.pull_back_binary(black_box(op), black_box(i as u64 & 7), 0, 4, 4));
            black_box(c);
        }
    }
    report("pull_back_binary", start, ROUNDS * N);
}

#[test]
#[ignore = "benchmark"]
fn push_forward_binary() {
    let rs = ranges();
    let ops = [
        OpCode::IntAdd,
        OpCode::IntMult,
        OpCode::IntLeft,
        OpCode::IntRight,
        OpCode::SubPiece,
        OpCode::IntEqual,
    ];
    let consts: Vec<CircleRange> = (0..8).map(|v| CircleRange::single(v, 4)).collect();
    let start = Instant::now();
    for round in 0..ROUNDS {
        for (i, w) in rs.windows(2).enumerate() {
            let op = ops[(i + round) % ops.len()];
            let in2 = if op == OpCode::IntAdd {
                &w[1]
            } else {
                &consts[i & 7]
            };
            let mut c = CircleRange::empty();
            black_box(c.push_forward_binary(
                black_box(op),
                black_box(&w[0]),
                black_box(in2),
                4,
                4,
                32,
            ));
            black_box(c);
        }
    }
    report("push_forward_binary", start, ROUNDS * (N - 1));
}
