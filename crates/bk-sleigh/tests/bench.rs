//! Benchmarks (`features/sleigh-decode.md` 6.6), `#[ignore]` release tests:
//!
//!     crates/bk-sleigh/tests/reference_bench/build.sh ../reference
//!     BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
//!       cargo test --release -p bk-sleigh --test bench -- --ignored --nocapture --test-threads=1
//!
//! Input: `target/bench/x86-64-code.bin` (built by `build.sh`). The reference
//! figures come from `target/bench/slabench` run in the same session.
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

use std::sync::Arc;
use std::time::Instant;

use bk_core::Address;
use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::{ContextDb, Decoder, Language, SliceBytes};

const RUNS: usize = 5;

fn code() -> Option<Vec<u8>> {
    let path = bk_testkit::workspace_root().join("target/bench/x86-64-code.bin");
    let data = std::fs::read(&path).ok();
    if data.is_none() {
        eprintln!(
            "SKIPPED: {} missing; run crates/bk-sleigh/tests/reference_bench/build.sh",
            path.display()
        );
    }
    data
}

fn x86_registry(reference: &bk_testkit::ReferenceDir) -> LanguageRegistry {
    LanguageRegistry::builder()
        .module(reference.root().join("Ghidra/Processors/x86"))
        .build()
        .unwrap()
}

/// Sweeps the code; returns (instructions, errors).
fn sweep(
    decoder: &mut Decoder,
    lang: &Language,
    db: &ContextDb,
    code: &[u8],
    text: bool,
    out: &mut String,
) -> (u64, u64) {
    let bytes = SliceBytes::new(0, code);
    let space = lang.default_space();
    let (mut n, mut e) = (0u64, 0u64);
    let mut pos = 0usize;
    while pos < code.len() {
        let addr = Address::new(space, pos as u64);
        if let Ok(parse) = decoder.decode(addr, &bytes, db) {
            let len = parse.length() as usize;
            if text {
                out.clear();
                let _ = decoder.mnemonic(out);
                let _ = decoder.body(out);
            }
            n += 1;
            pos += len.max(1);
        } else {
            e += 1;
            pos += 1;
        }
    }
    (n, e)
}

fn best<T>(runs: usize, mut f: impl FnMut() -> T) -> (f64, T) {
    let mut best = f64::MAX;
    let mut last = None;
    for _ in 0..runs {
        let t = Instant::now();
        let value = f();
        best = best.min(t.elapsed().as_secs_f64());
        last = Some(value);
    }
    (best, last.unwrap())
}

#[test]
#[ignore = "benchmark"]
fn bench_x86_64() {
    let Some(reference) = common::reference() else {
        return;
    };
    let Some(code) = code() else { return };
    let id = LanguageId::new("x86:LE:64:default").unwrap();
    let (load, lang) = best(RUNS, || {
        let registry = x86_registry(&reference);
        Language::load(&registry, &id).unwrap()
    });
    let (read_only, _) = best(RUNS, || {
        let path = reference
            .root()
            .join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        bk_sla::Sla::read_file(&path, &bk_sla::Limits::default()).unwrap()
    });
    let lang = Arc::new(lang);
    let db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let mut out = String::new();
    let (decode, (count, undecodable)) = best(RUNS, || {
        sweep(&mut decoder, &lang, &db, &code, false, &mut out)
    });
    let (text, _) = best(RUNS, || {
        sweep(&mut decoder, &lang, &db, &code, true, &mut out)
    });
    let m = |secs: f64| count as f64 / secs / 1e6;
    eprintln!(
        "x86-64 code: {} bytes, {count} instructions, {undecodable} undecodable positions",
        code.len()
    );
    eprintln!(
        "Language::load x86-64 (registry of the x86 module + .sla + .ldefs + .pspec): {:.1} ms (Sla::read_file alone {:.1} ms)",
        load * 1e3,
        read_only * 1e3
    );
    eprintln!(
        "decode only: {:.2} M instructions/s ({:.0} ns)",
        m(decode),
        decode / count as f64 * 1e9
    );
    eprintln!(
        "decode + text: {:.2} M instructions/s ({:.0} ns)",
        m(text),
        text / count as f64 * 1e9
    );

    // Threads sharing one language, each sweeping the whole code.
    let one = decode;
    for threads in [2usize, 4, 8] {
        let (wall, ()) = best(3, || {
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    let lang = Arc::clone(&lang);
                    let db = &db;
                    let code = &code;
                    scope.spawn(move || {
                        let mut d = Decoder::new(Arc::clone(&lang));
                        let mut s = String::new();
                        sweep(&mut d, &lang, db, code, false, &mut s);
                    });
                }
            });
        });
        eprintln!(
            "{threads} threads: {:.2}x the throughput of one",
            threads as f64 * one / wall
        );
    }

    let slabench = bk_testkit::workspace_root().join("target/bench/slabench");
    if slabench.is_file() {
        let dir = reference
            .root()
            .join("Ghidra/Processors/x86/data/languages");
        let output = std::process::Command::new(&slabench)
            .arg(dir.join("x86-64.sla"))
            .arg(dir.join("x86-64.pspec"))
            .arg(bk_testkit::workspace_root().join("target/bench/x86-64-code.bin"))
            .arg(RUNS.to_string())
            .output()
            .unwrap();
        eprintln!(
            "reference (slabench, same session):\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
