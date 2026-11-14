//! Benchmarks (ignored by default; numbers in `docs/PERF.md`).
//!
//! ```text
//! BASILISK_GHIDRA_DIR=../ghidra cargo test --release -p bk-sleigh-syntax \
//!     --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Peak memory per specification: run one benchmark under `/usr/bin/time -l`
//! (macOS) or `/usr/bin/time -v` (Linux) with `--exact bench_x86_64` etc.

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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bk_sleigh_syntax::{FsLoader, parse_file, preprocess};

/// Median of `runs` timings of `f`.
fn median(runs: usize, mut f: impl FnMut()) -> Duration {
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let started = Instant::now();
            f();
            started.elapsed()
        })
        .collect();
    times.sort();
    times[runs / 2]
}

fn bench_specs(label: &str, specs: &[PathBuf], runs: usize) {
    let defines = common::build_defines();
    let mut lines = 0usize;
    let mut bytes = 0usize;
    let mut tokens = 0u64;
    let mut nodes = 0usize;
    for spec in specs {
        let parsed = parse_file(spec, &defines, &mut FsLoader);
        assert_eq!(parsed.diagnostics, []);
        lines += parsed.sources.line_count();
        bytes += parsed.sources.text().len();
        tokens += parsed.token_count;
        nodes += parsed.spec.nodes.expr_count()
            + parsed.spec.nodes.pat_expr_count()
            + parsed.spec.nodes.equation_count();
    }
    let pre = median(runs, || {
        for spec in specs {
            let _ = preprocess(spec, &defines, &mut FsLoader);
        }
    });
    let all = median(runs, || {
        for spec in specs {
            let _ = parse_file(spec, &defines, &mut FsLoader);
        }
    });
    let secs = all.as_secs_f64();
    eprintln!(
        "bench {label}: {} spec(s), {lines} lines, {:.1} MB, {tokens} tokens, {nodes} arena nodes; \
         preprocess {:.1} ms, preprocess+parse {:.1} ms (median of {runs}); \
         {:.2} M lines/s, {:.1} MB/s, {:.1} M tokens/s",
        specs.len(),
        bytes as f64 / 1e6,
        pre.as_secs_f64() * 1e3,
        secs * 1e3,
        lines as f64 / secs / 1e6,
        bytes as f64 / secs / 1e6,
        tokens as f64 / secs / 1e6,
    );
}

fn spec(ghidra: &Path, relative: &str) -> Vec<PathBuf> {
    vec![ghidra.join("Ghidra/Processors").join(relative)]
}

#[test]
#[ignore = "benchmark"]
fn bench_x86_64() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    bench_specs(
        "x86-64",
        &spec(&ghidra, "x86/data/languages/x86-64.slaspec"),
        11,
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_aarch64() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    bench_specs(
        "AARCH64",
        &spec(&ghidra, "AARCH64/data/languages/AARCH64.slaspec"),
        11,
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_powerpc() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    bench_specs(
        "PowerPC (ppc_64_isa_altivec_vle_be)",
        &spec(
            &ghidra,
            "PowerPC/data/languages/ppc_64_isa_altivec_vle_be.slaspec",
        ),
        11,
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_corpus() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    bench_specs("all 150 specs", &common::slaspec_files(&ghidra), 5);
}
