//! Benchmarks, as `#[ignore]` tests that print nanoseconds per operation.
//! Run them in release mode:
//!
//! ```text
//! CARGO_BUILD_JOBS=2 cargo test -p bk-pcode --release --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Numbers are recorded in `docs/PERF.md` under `bk-pcode`.

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

use bk_pcode::behavior::{evaluate_binary, wide};
use bk_pcode::{FloatFormat, FloatFormats, OpCode, Wide};

/// A small deterministic generator (splitmix64), so runs are comparable.
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
const ROUNDS: usize = 2000;

/// Runs `body` over the inputs `ROUNDS` times and prints ns per call.
fn measure(name: &str, calls_per_round: usize, mut body: impl FnMut() -> u64) -> f64 {
    // Warm up.
    for _ in 0..ROUNDS / 10 {
        black_box(body());
    }
    let start = Instant::now();
    let mut sink = 0u64;
    for _ in 0..ROUNDS {
        sink = sink.wrapping_add(body());
    }
    black_box(sink);
    let ns = start.elapsed().as_secs_f64() * 1e9 / (ROUNDS * calls_per_round) as f64;
    eprintln!("{name:<52} {ns:>8.2} ns/op");
    ns
}

const MIX: [OpCode; 12] = [
    OpCode::IntAdd,
    OpCode::IntSub,
    OpCode::IntMult,
    OpCode::IntAnd,
    OpCode::IntXor,
    OpCode::IntLeft,
    OpCode::IntSRight,
    OpCode::IntLess,
    OpCode::IntSLess,
    OpCode::IntCarry,
    OpCode::IntDiv,
    OpCode::IntSRem,
];

/// The same mix in native arithmetic, as a baseline with the same dispatch
/// shape (a `match` per operation and a size mask).
fn native(op: OpCode, size: u32, a: u64, b: u64) -> u64 {
    let mask = u64::MAX >> (64 - 8 * size);
    let shift = 64 - 8 * size;
    let sa = ((a << shift) as i64) >> shift;
    let sb = ((b << shift) as i64) >> shift;
    match op {
        OpCode::IntAdd => a.wrapping_add(b) & mask,
        OpCode::IntSub => a.wrapping_sub(b) & mask,
        OpCode::IntMult => a.wrapping_mul(b) & mask,
        OpCode::IntAnd => a & b,
        OpCode::IntXor => a ^ b,
        OpCode::IntLeft => a.checked_shl(b as u32).unwrap_or(0) & mask,
        OpCode::IntSRight => (sa >> b.min(63)) as u64 & mask,
        OpCode::IntLess => u64::from(a < b),
        OpCode::IntSLess => u64::from(sa < sb),
        OpCode::IntCarry => u64::from(a.wrapping_add(b) & mask < a),
        OpCode::IntDiv => a.checked_div(b).unwrap_or(0),
        OpCode::IntSRem => sa.checked_rem(sb).unwrap_or(0) as u64 & mask,
        _ => 0,
    }
}

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_evaluate_binary_mix() {
    let mut rng = Rng(1);
    let sizes = [1u32, 2, 4, 8];
    let cases: Vec<(OpCode, u32, u64, u64)> = (0..N)
        .map(|i| {
            let op = MIX[i % MIX.len()];
            let size = sizes[(rng.next() % 4) as usize];
            let mask = u64::MAX >> (64 - 8 * size);
            let b = if matches!(op, OpCode::IntLeft | OpCode::IntSRight) {
                rng.next() % (8 * u64::from(size) + 4)
            } else {
                (rng.next() & mask) | 1
            };
            (op, size, rng.next() & mask, b)
        })
        .collect();
    let formats = FloatFormats::DEFAULT;
    let ours = measure("evaluate_binary, 12-op integer mix, sizes 1-8", N, || {
        cases.iter().fold(0u64, |acc, &(op, size, a, b)| {
            acc ^ evaluate_binary(black_box(op), size, size, a, b, &formats).unwrap_or(0)
        })
    });
    let base = measure("native baseline, same mix", N, || {
        cases.iter().fold(0u64, |acc, &(op, size, a, b)| {
            acc ^ native(black_box(op), size, a, b)
        })
    });
    eprintln!("ratio evaluate_binary / native: {:.2}", ours / base);
}

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_float_encode_decode() {
    let mut rng = Rng(2);
    let doubles: Vec<f64> = (0..N)
        .map(|_| f64::from_bits(rng.next()))
        .map(|x| if x.is_finite() { x } else { 1.5 })
        .collect();
    let singles: Vec<u64> = doubles
        .iter()
        .map(|&x| u64::from((x as f32).to_bits()))
        .collect();
    let encodings: Vec<u64> = doubles.iter().map(|x| x.to_bits()).collect();
    for (name, format) in [
        ("binary32", FloatFormat::SINGLE),
        ("binary64", FloatFormat::DOUBLE),
    ] {
        measure(&format!("encoding (f64 -> {name})"), N, || {
            doubles
                .iter()
                .fold(0, |acc, &x| acc ^ format.encoding(black_box(x)))
        });
        let inputs = if format.size() == 4 {
            &singles
        } else {
            &encodings
        };
        measure(&format!("host_float ({name} -> f64)"), N, || {
            inputs.iter().fold(0, |acc, &e| {
                acc ^ format.host_float(black_box(e)).0.to_bits()
            })
        });
        measure(&format!("op_add host level ({name})"), N, || {
            inputs
                .windows(2)
                .fold(0, |acc, w| acc ^ format.op_add(black_box(w[0]), w[1]))
        });
    }
    measure("native f64 add + to_bits (baseline)", N, || {
        doubles
            .windows(2)
            .fold(0, |acc, w| acc ^ (black_box(w[0]) + w[1]).to_bits())
    });
}

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_exact_level() {
    let mut rng = Rng(3);
    for format in [FloatFormat::DOUBLE, FloatFormat::QUAD] {
        let size = format.size();
        let values: Vec<Wide> = (0..256)
            .map(|_| {
                let x = 1.0 + (rng.next() % 1_000_000) as f64 / 7.0;
                let bf = format.big_float_from_f64(x).unwrap();
                format.encode_big_float(&bf)
            })
            .collect();
        for (name, op) in [
            ("add", OpCode::FloatAdd),
            ("mult", OpCode::FloatMult),
            ("div", OpCode::FloatDiv),
        ] {
            let ieee = FloatFormats::IEEE;
            let ns = measure_n(
                &format!("wide::evaluate_binary FLOAT_{name} ({size} bytes, exact)"),
                &values,
                |a, b| {
                    wide::evaluate_binary(op, size, size, a, b, &ieee)
                        .unwrap()
                        .low_u64()
                },
            );
            black_box(ns);
        }
    }
}

fn measure_n(name: &str, values: &[Wide], f: impl Fn(&Wide, &Wide) -> u64) -> f64 {
    const R: usize = 200;
    let start = Instant::now();
    let mut sink = 0u64;
    for _ in 0..R {
        for w in values.windows(2) {
            sink ^= f(black_box(&w[0]), &w[1]);
        }
    }
    black_box(sink);
    let ns = start.elapsed().as_secs_f64() * 1e9 / (R * (values.len() - 1)) as f64;
    eprintln!("{name:<52} {ns:>8.2} ns/op");
    ns
}

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_wide_integer() {
    let mut rng = Rng(4);
    let ieee = FloatFormats::IEEE;
    for size in [16u32, 64] {
        let values: Vec<Wide> = (0..N)
            .map(|_| {
                let bytes: Vec<u8> = (0..64).map(|_| rng.next() as u8).collect();
                Wide::from_le_bytes(&bytes).unwrap().truncate(size) | Wide::ONE
            })
            .collect();
        for (name, op) in [
            ("INT_ADD", OpCode::IntAdd),
            ("INT_MULT", OpCode::IntMult),
            ("INT_DIV", OpCode::IntDiv),
            ("INT_SLESS", OpCode::IntSLess),
        ] {
            measure_n(
                &format!("wide::evaluate_binary {name} ({size} bytes)"),
                &values,
                |a, b| {
                    wide::evaluate_binary(op, size, size, a, b, &ieee)
                        .unwrap()
                        .low_u64()
                },
            );
        }
    }
}
