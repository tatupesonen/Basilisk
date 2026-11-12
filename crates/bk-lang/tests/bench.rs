//! Benchmarks (ADR-012), as ignored tests. Run in release mode:
//!
//! ```text
//! BASILISK_GHIDRA_DIR=… cargo test -p bk-lang --release --test bench -- --ignored --nocapture
//! ```
//!
//! Numbers are recorded in `docs/PERF.md`.

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

use bk_lang::LanguageRegistry;

/// The budget for scanning the whole spec root (`docs/features/lang.md`).
const SCAN_BUDGET: Duration = Duration::from_millis(50);

/// Runs `work` `runs` times and returns the fastest and the median time.
fn measure<T>(runs: usize, mut work: impl FnMut() -> T) -> (Duration, Duration) {
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            std::hint::black_box(work());
            start.elapsed()
        })
        .collect();
    times.sort();
    (times[0], times[times.len() / 2])
}

fn ms(duration: Duration) -> String {
    format!("{:.2} ms", duration.as_secs_f64() * 1e3)
}

#[test]
#[ignore = "benchmark; run in release mode with --ignored"]
fn bench_registry() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let scan = || LanguageRegistry::from_ghidra_root(&ghidra).unwrap();
    scan(); // warm the file cache

    let (fastest, median) = measure(30, scan);
    eprintln!(
        "registry scan (whole Ghidra tree: 52 .ldefs, 202 languages): fastest {}, median {}",
        ms(fastest),
        ms(median)
    );

    let (fastest_opinions, median_opinions) = measure(30, || {
        let registry = scan();
        registry.opinions().loaders().count()
    });
    eprintln!(
        "scan + opinion database (32 .opinion, 339 constraints): fastest {}, median {}",
        ms(fastest_opinions),
        ms(median_opinions)
    );

    let (fastest_pspecs, median_pspecs) = measure(30, || {
        let registry = scan();
        for language in registry.languages() {
            registry.processor_spec(language.id()).unwrap();
        }
    });
    eprintln!(
        "scan + all 87 .pspec files: fastest {}, median {}",
        ms(fastest_pspecs),
        ms(median_pspecs)
    );

    let registry = scan();
    // Build the opinion database once, outside the timed loop.
    assert!(registry.opinions().order_is_exact());
    let (fastest_query, median_query) = measure(1000, || {
        registry.query_opinions(
            "Executable and Linking Format (ELF)",
            Some("8"),
            Some("821047567"),
        )
    });
    eprintln!(
        "opinion query (ELF MIPS, binary-pattern match): fastest {:.1} µs, median {:.1} µs",
        fastest_query.as_secs_f64() * 1e6,
        median_query.as_secs_f64() * 1e6
    );

    if cfg!(debug_assertions) {
        eprintln!("debug build: budget not enforced");
    } else {
        assert!(
            median < SCAN_BUDGET,
            "registry scan took {}, over the 50 ms budget",
            ms(median)
        );
    }
}
