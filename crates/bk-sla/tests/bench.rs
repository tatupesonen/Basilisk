//! Benchmarks (`features/sla.md` section 6), run as ignored release tests:
//!
//! ```text
//! BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 cargo test --release -p bk-sla \
//!     --test bench -- --ignored --nocapture --test-threads 1
//! ```
//!
//! The reference loader to compare with is `tests/reference_loader/slaload.cc`.
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

use std::path::Path;
use std::time::{Duration, Instant};

use bk_sla::{Limits, Sla, inflate};

fn best_of(runs: usize, mut f: impl FnMut()) -> Duration {
    (0..runs)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed()
        })
        .min()
        .unwrap()
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn one_file(path: &Path, label: &str) {
    let limits = Limits::default();
    let read = best_of(20, || {
        std::hint::black_box(Sla::read_file(path, &limits).unwrap());
    });
    let bytes = std::fs::read(path).unwrap();
    let inflate_time = best_of(20, || {
        std::hint::black_box(inflate(&bytes, &limits).unwrap());
    });
    let stream = inflate(&bytes, &limits).unwrap();
    let decode = best_of(20, || {
        std::hint::black_box(Sla::decode_packed(&stream, &limits).unwrap());
    });
    let sla = Sla::read_file(path, &limits).unwrap();
    let encode = best_of(20, || {
        std::hint::black_box(sla.encode_packed().unwrap());
    });
    let write = best_of(5, || {
        std::hint::black_box(sla.write().unwrap());
    });
    let xml = best_of(5, || {
        std::hint::black_box(sla.encode_xml().unwrap());
    });
    eprintln!(
        "{label}: read_file {:.2} ms (inflate {:.2}, decode+validate {:.2}); encode_packed {:.2} ms; write {:.2} ms; encode_xml {:.2} ms; stream {:.2} MB",
        ms(read),
        ms(inflate_time),
        ms(decode),
        ms(encode),
        ms(write),
        ms(xml),
        stream.len() as f64 / 1e6
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_read_and_encode() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    one_file(&reference.sla_file("x86", "x86-64"), "x86-64");
    one_file(&reference.sla_file("AARCH64", "AARCH64BE"), "AARCH64BE");
    let files = reference.sla_files().unwrap();
    let limits = Limits::default();
    let all_read = best_of(3, || {
        for file in &files {
            std::hint::black_box(Sla::read_file(&file.path, &limits).unwrap());
        }
    });
    let models: Vec<Sla> = files
        .iter()
        .map(|file| Sla::read_file(&file.path, &limits).unwrap())
        .collect();
    let all_encode = best_of(3, || {
        for sla in &models {
            std::hint::black_box(sla.encode_packed().unwrap());
        }
    });
    eprintln!(
        "all {} files: read_file {:.1} ms; encode_packed {:.1} ms",
        files.len(),
        ms(all_read),
        ms(all_encode)
    );
}

#[test]
#[ignore = "profiling loop"]
fn profile_decode_loop() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let limits = Limits::default();
    let bytes = std::fs::read(reference.sla_file("x86", "x86-64")).unwrap();
    let stream = inflate(&bytes, &limits).unwrap();
    for _ in 0..300 {
        std::hint::black_box(Sla::decode_packed(&stream, &limits).unwrap());
    }
}
