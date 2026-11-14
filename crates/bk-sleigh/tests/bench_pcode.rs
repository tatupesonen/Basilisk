//! Benchmarks of p-code generation (`features/sleigh-pcode.md` 6.6),
//! `#[ignore]` release tests:
//!
//!     crates/bk-sleigh/tests/reference_bench/build.sh ../reference
//!     CARGO_BUILD_JOBS=2 cargo build --release -p basilisk
//!     BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
//!       cargo test --release -p bk-sleigh --test bench_pcode -- --ignored --nocapture --test-threads=1
//!
//! Input: `target/bench/x86-64-code.bin` and `x86-64-code-778k.bin` (built by
//! `build.sh`). The reference figures come from `target/bench/slabench` and
//! `pcodedump`, run in the same session.
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

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use bk_core::Address;
use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::{ContextDb, Decoder, Language, PcodeCounter, SliceBytes};

const RUNS: usize = 5;

fn input(name: &str) -> Option<Vec<u8>> {
    let path = bk_testkit::workspace_root().join("target/bench").join(name);
    let data = std::fs::read(&path).ok();
    if data.is_none() {
        eprintln!(
            "SKIPPED: {} missing; run crates/bk-sleigh/tests/reference_bench/build.sh",
            path.display()
        );
    }
    data
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

/// What a sweep does per position.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Decode,
    Text,
    Lift,
    TextLift,
}

/// Sweeps the code as `slabench` does; returns (instructions, ops).
fn sweep(decoder: &mut Decoder, initial: &ContextDb, code: &[u8], mode: Mode) -> (u64, u64) {
    let lang = Arc::clone(decoder.language());
    let mut db = initial.clone();
    let bytes = SliceBytes::new(0, code);
    let space = lang.default_space();
    let mut counter = PcodeCounter::default();
    let mut text = String::new();
    let mut n = 0u64;
    let mut pos = 0usize;
    while pos < code.len() {
        let addr = Address::new(space, pos as u64);
        let len = match mode {
            Mode::Decode => decoder
                .decode(addr, &bytes, &db)
                .map(bk_sleigh::Parse::length)
                .ok(),
            Mode::Text => {
                let len = decoder
                    .decode(addr, &bytes, &db)
                    .map(bk_sleigh::Parse::length)
                    .ok();
                if len.is_some() {
                    text.clear();
                    let _ = decoder.mnemonic(&mut text);
                    let _ = decoder.body(&mut text);
                }
                len
            }
            Mode::Lift => match decoder.lift(addr, &bytes, &mut db, &mut counter) {
                Ok(_) => Some(decoder.parse().length()),
                Err(_) => decoder
                    .decode(addr, &bytes, &db)
                    .map(bk_sleigh::Parse::length)
                    .ok(),
            },
            Mode::TextLift => {
                let len = decoder
                    .decode(addr, &bytes, &db)
                    .map(bk_sleigh::Parse::length)
                    .ok();
                if len.is_some() {
                    text.clear();
                    let _ = decoder.mnemonic(&mut text);
                    let _ = decoder.body(&mut text);
                    let _ = decoder.lift_decoded(addr, &bytes, &mut db, &mut counter, &mut ());
                }
                len
            }
        };
        match len {
            Some(len) => {
                n += 1;
                pos += (len as usize).max(1);
            }
            None => pos += 1,
        }
    }
    (n, counter.ops)
}

fn scaling(lang: &Arc<Language>, db: &ContextDb, code: &[u8], mode: Mode, one: f64) -> String {
    let mut out = String::new();
    for threads in [2usize, 4, 8] {
        let (wall, ()) = best(3, || {
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    scope.spawn(|| {
                        let mut d = Decoder::new(Arc::clone(lang));
                        sweep(&mut d, db, code, mode);
                    });
                }
            });
        });
        let _ = write!(out, " {threads}: {:.2}x", threads as f64 * one / wall);
    }
    out
}

/// Best wall-clock time of `cmd` over `RUNS` runs, output discarded.
fn time_command(program: &Path, args: &[&std::ffi::OsStr], stdin: &Path) -> f64 {
    let (t, ()) = best(RUNS, || {
        let status = Command::new(program)
            .args(args)
            .stdin(std::fs::File::open(stdin).unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "{} failed", program.display());
    });
    t
}

fn load_average() -> String {
    if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
        return s.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
    }
    Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// `BK_BENCH_SINGLE` set: only the single-thread sweeps, for
/// `reference_bench/compare.sh`, which runs the reference itself.
fn single_only() -> bool {
    std::env::var_os("BK_BENCH_SINGLE").is_some()
}

#[test]
#[ignore = "benchmark"]
fn bench_pcode_x86_64() {
    let Some(reference) = common::reference() else {
        return;
    };
    let (Some(code), Some(big)) = (input("x86-64-code.bin"), input("x86-64-code-778k.bin")) else {
        return;
    };
    eprintln!("load average before: {}", load_average());
    let registry = LanguageRegistry::builder()
        .module(reference.root().join("Ghidra/Processors/x86"))
        .build()
        .unwrap();
    let id = LanguageId::new("x86:LE:64:default").unwrap();
    let lang = Arc::new(Language::load(&registry, &id).unwrap());
    let db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let (decode, (count, _)) = best(RUNS, || sweep(&mut decoder, &db, &code, Mode::Decode));
    let (text, _) = best(RUNS, || sweep(&mut decoder, &db, &code, Mode::Text));
    let (lift, (_, ops)) = best(RUNS, || sweep(&mut decoder, &db, &code, Mode::Lift));
    let (text_lift, _) = best(RUNS, || sweep(&mut decoder, &db, &code, Mode::TextLift));
    let m = |secs: f64| count as f64 / secs / 1e6;
    eprintln!(
        "x86-64 code: {} bytes, {count} instructions, {ops} ops",
        code.len()
    );
    eprintln!("decode only: {:.2} M instructions/s", m(decode));
    eprintln!("decode + text: {:.2} M instructions/s", m(text));
    eprintln!(
        "decode + lift (counting emitter): {:.2} M instructions/s, {:.2} M ops/s ({:.0} ns)",
        m(lift),
        ops as f64 / lift / 1e6,
        lift / count as f64 * 1e9
    );
    eprintln!("decode + text + lift: {:.2} M instructions/s", m(text_lift));
    if single_only() {
        return;
    }
    eprintln!(
        "scaling, decode:{}",
        scaling(&lang, &db, &code, Mode::Decode, decode)
    );
    eprintln!(
        "scaling, decode + lift:{}",
        scaling(&lang, &db, &code, Mode::Lift, lift)
    );

    let root = bk_testkit::workspace_root();
    let slabench = root.join("target/bench/slabench");
    if slabench.is_file() {
        let dir = reference
            .root()
            .join("Ghidra/Processors/x86/data/languages");
        let output = Command::new(&slabench)
            .arg(dir.join("x86-64.sla"))
            .arg(dir.join("x86-64.pspec"))
            .arg(root.join("target/bench/x86-64-code.bin"))
            .arg(RUNS.to_string())
            .output()
            .unwrap();
        eprintln!(
            "reference (slabench, same session):\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    // End to end on the 778 kB input.
    let basilisk = root.join("target/release/basilisk");
    if !basilisk.is_file() {
        eprintln!("SKIPPED end to end: build `cargo build --release -p basilisk` first");
        return;
    }
    let file = root.join("target/bench/x86-64-code-778k.bin");
    let pcodedump = reference.tool_path(bk_testkit::Tool::Pcodedump);
    let r = reference.root().as_os_str();
    let ours_quiet = [
        "disasm".as_ref(),
        "--root".as_ref(),
        r,
        "--language".as_ref(),
        "x86:LE:64:default".as_ref(),
        "--quiet".as_ref(),
    ];
    let theirs_quiet = [
        r,
        "x86:LE:64:default".as_ref(),
        "0".as_ref(),
        "--quiet".as_ref(),
    ];
    let a = time_command(&basilisk, &ours_quiet, &file);
    let b = time_command(&pcodedump, &theirs_quiet, &file);
    eprintln!(
        "end to end --quiet, {} bytes: basilisk disasm {:.3} s, pcodedump {:.3} s",
        big.len(),
        a,
        b
    );
    let a = time_command(&basilisk, &ours_quiet[..5], &file);
    let b = time_command(&pcodedump, &theirs_quiet[..3], &file);
    eprintln!(
        "end to end, full listing to a null device: basilisk disasm {a:.3} s, pcodedump {b:.3} s"
    );
    eprintln!("load average after: {}", load_average());
}

/// Lifts the x86-64 code over and over for `BK_PROFILE_SECONDS` (default
/// 8): a steady load for a sampling profiler. `BK_PROFILE_MODE=decode`
/// (or `text`) sweeps with that mode instead.
#[test]
#[ignore = "profiling aid"]
fn profile_lift_x86_64() {
    let Some(reference) = common::reference() else {
        return;
    };
    let Some(code) = input("x86-64-code.bin") else {
        return;
    };
    let registry = LanguageRegistry::builder()
        .module(reference.root().join("Ghidra/Processors/x86"))
        .build()
        .unwrap();
    let id = LanguageId::new("x86:LE:64:default").unwrap();
    let lang = Arc::new(Language::load(&registry, &id).unwrap());
    let db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let seconds: f64 = std::env::var("BK_PROFILE_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8.0);
    let mode = match std::env::var("BK_PROFILE_MODE").as_deref() {
        Ok("decode") => Mode::Decode,
        Ok("text") => Mode::Text,
        _ => Mode::Lift,
    };
    let start = Instant::now();
    let mut instructions = 0u64;
    while start.elapsed().as_secs_f64() < seconds {
        instructions += sweep(&mut decoder, &db, &code, mode).0;
    }
    eprintln!("profiled {instructions} instructions");
}
