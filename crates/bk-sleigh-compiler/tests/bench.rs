//! Benchmarks (spec 6.4, `docs/PERF.md`): parse and elaborate x86-64,
//! AARCH64 and all shipped specifications, one at a time on one thread.
//! Run with
//! `BASILISK_REFERENCE_DIR=../reference cargo test --release -p bk-sleigh-compiler --test bench -- --ignored --nocapture --test-threads=1`.

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

use std::time::{Duration, Instant};

use bk_sleigh_compiler::{Options, elaborate};

/// Best of `runs` timings of parse and of elaboration.
fn time(spec: &common::Spec, runs: usize) -> (Duration, Duration) {
    let mut best = (Duration::MAX, Duration::MAX);
    for _ in 0..runs {
        let start = Instant::now();
        let parsed = common::parse(&spec.slaspec);
        let parse = start.elapsed();
        let start = Instant::now();
        let outcome = elaborate(&parsed, Options::default());
        let elab = start.elapsed();
        assert!(outcome.spec.is_some(), "{}", spec.name);
        best = (best.0.min(parse), best.1.min(elab));
    }
    best
}

#[test]
#[ignore = "benchmark"]
fn bench_largest_and_all() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    let specs = common::reference_specs(&reference);
    for name in ["x86-64", "AARCH64"] {
        let spec = specs.iter().find(|s| s.name == name).unwrap();
        let (parse, elab) = time(spec, 5);
        eprintln!(
            "{name}: parse {:.1} ms, elaborate {:.1} ms",
            parse.as_secs_f64() * 1e3,
            elab.as_secs_f64() * 1e3
        );
    }
    let start = Instant::now();
    let (mut parse, mut elab) = (Duration::ZERO, Duration::ZERO);
    for spec in &specs {
        let (p, e) = time(spec, 1);
        parse += p;
        elab += e;
    }
    eprintln!(
        "all {}: parse {:.0} ms, elaborate {:.0} ms, total {:.0} ms",
        specs.len(),
        parse.as_secs_f64() * 1e3,
        elab.as_secs_f64() * 1e3,
        start.elapsed().as_secs_f64() * 1e3
    );
}

/// Spec 6.5: the whole compile (parse to written bytes) against the
/// reference compiler, timed in the same session. Prints a table; asserts
/// nothing about timing (the machine may be shared).
#[test]
#[ignore = "benchmark"]
fn bench_compile_against_reference() {
    let Some(reference) = bk_testkit::skip::require_tool(bk_testkit::Tool::Sleigh) else {
        return;
    };
    let specs = common::reference_specs(&reference);
    let out_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("bench-sla");
    std::fs::create_dir_all(&out_dir).unwrap();
    let ours = |spec: &common::Spec| {
        let options = Options::from_switches(
            reference
                .module_options(&spec.module)
                .iter()
                .map(String::as_str),
        );
        let start = Instant::now();
        let parsed = common::parse(&spec.slaspec);
        let compiled = bk_sleigh_compiler::compile_parsed(&parsed, options);
        let bytes = compiled.sla.unwrap().write().unwrap();
        std::fs::write(out_dir.join("ours.sla"), bytes).unwrap();
        start.elapsed()
    };
    let theirs = |spec: &common::Spec| {
        let mut sleigh = reference.sleigh();
        for s in reference.module_options(&spec.module) {
            if let Some(c) = s.strip_prefix('-').and_then(|s| s.chars().next()) {
                sleigh = sleigh.switch(c);
            }
        }
        let start = Instant::now();
        sleigh
            .compile(&spec.slaspec, &out_dir.join("theirs.sla"))
            .unwrap();
        start.elapsed()
    };
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    for name in ["x86-64", "AARCH64", "andestar_v5"] {
        let spec = specs.iter().find(|s| s.name == name).unwrap();
        let a = (0..3).map(|_| ours(spec)).min().unwrap();
        let b = (0..3).map(|_| theirs(spec)).min().unwrap();
        eprintln!(
            "{name}: Basilisk {:.0} ms, reference {:.0} ms (best of 3)",
            ms(a),
            ms(b)
        );
    }
    let a: Duration = specs.iter().map(ours).sum();
    let b: Duration = specs.iter().map(theirs).sum();
    eprintln!(
        "all {}: Basilisk {:.2} s, reference {:.2} s (one after another)",
        specs.len(),
        a.as_secs_f64(),
        b.as_secs_f64()
    );
}
