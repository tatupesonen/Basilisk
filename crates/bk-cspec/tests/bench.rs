//! Benchmarks, as `#[ignore]` tests that print the time per operation
//! (kind G: they read the real `.cspec` files). Run them in release mode:
//!
//! ```text
//! BASILISK_GHIDRA_DIR=../ghidra CARGO_BUILD_JOBS=2 cargo test -p bk-cspec --release --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Numbers are recorded in `docs/PERF.md` under `bk-cspec`.

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
mod oracle_common;

use std::hint::black_box;
use std::time::Instant;

use bk_cspec::proto::PrototypePieces;
use bk_cspec::{CompilerSpec, ReadOptions};
use common::cparse;

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_decode_largest_cspec() {
    let Some(ghidra) = bk_testkit::require_ghidra() else { return };
    let table = oracle_common::table();
    let (pairs, _) = oracle_common::pairs(&table);
    let pair = pairs.iter().find(|p| p.id == "x86:LE:64:default:golang").unwrap();
    let files = oracle_common::cspec_files(&ghidra.processors_dir());
    let text = std::fs::read_to_string(&files[&pair.cspec]).unwrap();
    let n = 2000;
    let mut total = std::time::Duration::ZERO;
    for _ in 0..n {
        // A fresh manager each time: reading adds the stack space.
        let mut m = oracle_common::manager(pair);
        let start = Instant::now();
        let spec = CompilerSpec::read(&text, &mut m, ReadOptions::default()).unwrap();
        total += start.elapsed();
        black_box(spec);
    }
    eprintln!(
        "decode {} ({} bytes): {:.1} µs per read ({n} reads)",
        pair.cspec,
        text.len(),
        total.as_secs_f64() * 1e6 / f64::from(n)
    );
}

#[test]
#[ignore = "benchmark; run in release with --ignored"]
fn bench_one_million_assignments_x86_64_gcc() {
    let Some(ghidra) = bk_testkit::require_ghidra() else { return };
    let (spec, m, mut types) = oracle_common::arch(&ghidra, "x86:LE:64:default:gcc");
    let model = spec.model_by_name("__stdcall").unwrap();
    cparse::structure(&mut types, "struct sld { int8 a; float8 b; };");
    let sigs: Vec<PrototypePieces> = [
        "void f(int4 a,int4 b);",
        "int8 f(int4 a,float8 b,int4 *c,float4 d);",
        "float8 f(int4 a,int4 b,int4 c,int4 d,int4 e,int4 f,int4 g,int4 h);",
        "void f(sld a,int4 b);",
    ]
    .iter()
    .map(|s| cparse::proto(&mut types, "__stdcall", s))
    .collect();
    let mut res = Vec::with_capacity(16);
    let n = 1_000_000;
    let start = Instant::now();
    for i in 0..n {
        res.clear();
        model
            .assign_parameter_storage(&m, &mut types, &sigs[i % sigs.len()], &mut res, false)
            .unwrap();
        black_box(&res);
    }
    let t = start.elapsed();
    eprintln!(
        "assign x86-64 gcc __stdcall: {n} assignments in {:.1} ms ({:.0} ns each)",
        t.as_secs_f64() * 1e3,
        t.as_secs_f64() * 1e9 / n as f64
    );
}
