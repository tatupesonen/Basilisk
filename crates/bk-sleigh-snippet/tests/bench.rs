//! Benchmarks (ADR-012), `#[ignore]`d; run in release:
//!
//! `cargo test -p bk-sleigh-snippet --release --test bench -- --ignored --nocapture --test-threads=1`
//!
//! The hot paths: preparing a compiler for a language (once per program)
//! and compiling a snippet (once per payload; the decompiler compiles a
//! language's payloads when it loads it). Numbers in `docs/PERF.md`.

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
use std::time::Instant;

use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};

const TYPICAL: &str = "tmp:4 = *:4 ESP; ESP = ESP + 4; EAX = tmp;\n\
if (EAX == 0) goto <done>; EBX = zext(AL) << 2; in1 = in2 + EBX;\n\
segment(ES, EAX); <done> return [tmp];";

#[test]
#[ignore = "benchmark"]
fn bench_compile_fixture() {
    let sla = common::fixture::sla();
    let compiler = SnippetCompiler::new(&sla, &Options::default());
    let params = [Parameter::new("in1", 0), Parameter::new("in2", 1)];
    let n = 200_000;
    let start = Instant::now();
    for _ in 0..n {
        let mut temps = TempAllocator::new(0x1000);
        black_box(
            compiler
                .compile(black_box(TYPICAL), &params, &mut temps)
                .unwrap(),
        );
    }
    let per = start.elapsed().as_secs_f64() / f64::from(n) * 1e9;
    eprintln!(
        "compile a 10-statement snippet (fixture language): {per:.0} ns per compile ({n} runs)"
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_x86_64_language() {
    let Some((ghidra, reference)) = common::roots() else {
        return;
    };
    let registry = common::registry(ghidra.root(), reference.root());
    let sla = common::load_sla(&registry, "x86:LE:64:default").unwrap();
    let runs = 200;
    let start = Instant::now();
    for _ in 0..runs {
        black_box(SnippetCompiler::new(&sla, &Options::default()));
    }
    let prepare = start.elapsed().as_secs_f64() / f64::from(runs) * 1e3;

    let compiler = SnippetCompiler::new(&sla, &Options::default());
    let cspec = ghidra.language_dir("x86").join("x86-64-gcc.cspec");
    let snippets: Vec<_> = common::corpus::snippets_of(&cspec)
        .into_iter()
        .filter_map(|s| s.body.map(|b| (b, s.params)))
        .collect();
    let rounds = 2_000;
    let start = Instant::now();
    for _ in 0..rounds {
        let mut temps = TempAllocator::for_injection(sla.header().unique_base);
        for (body, params) in &snippets {
            black_box(compiler.compile(body, params, &mut temps).unwrap());
        }
    }
    let all = start.elapsed().as_secs_f64() / f64::from(rounds) * 1e6;
    eprintln!(
        "x86-64: SnippetCompiler::new {prepare:.2} ms; the {} snippets of x86-64-gcc.cspec \
         {all:.1} µs together",
        snippets.len()
    );
}
