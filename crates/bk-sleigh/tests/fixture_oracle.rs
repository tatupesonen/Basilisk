//! The self-contained differential check: the `bkfix` language (built in
//! Rust, `tests/fixture/mod.rs`) decoded by basilisk and compared with
//! `pcodedump`'s output for it, recorded once in
//! `tests/data/fixture-oracle.txt`. The replay needs nothing outside the
//! repository, so it runs on every platform in CI; the recording needs the
//! reference tools (`record_fixture_oracle`, ignored).
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
mod fixture;

use std::fmt::Write as _;
use std::sync::Arc;

use bk_lang::Mode;
use bk_sleigh::Language;
use wait_timeout::ChildExt as _;

const DATA: &str = "tests/data/fixture-oracle.txt";

fn language() -> Arc<Language> {
    let mut lang = Language::from_sla(Arc::new(fixture::build())).unwrap();
    let pspec = bk_lang::pspec::parse(fixture::PSPEC, Mode::Strict)
        .unwrap()
        .value;
    lang.apply_processor_spec(&pspec).unwrap();
    Arc::new(lang)
}

/// The streams: directed samples per root pair, hand-written sequences and
/// random bytes. (base, configuration, bytes)
fn streams(lang: &Arc<Language>) -> Vec<(u64, common::directed::Config, Vec<u8>)> {
    let mut rng = common::directed::Rng::new(common::directed::seed(fixture::ID));
    let plan = common::directed::plan(lang, 8, &mut rng);
    let mut out: Vec<(u64, common::directed::Config, Vec<u8>)> =
        common::directed::pack(lang, &plan, 0x1000, 50, 1 << 16)
            .into_iter()
            .map(|s| (0x1000, s.config, s.bytes))
            .collect();
    let hand: &[&[u8]] = &[
        // setmode; m1op; clrmode; m1op-encoding again (now clrmode)
        &[0x60, 0x00, 0x75, 0x00, 0x70, 0x00, 0x75, 0x00],
        // bd with a plain delay slot, then bd whose delay slot is another bd
        &[0xa0, 0x10, 0x20, 0x05, 0xa0, 0x02, 0xa0, 0x04, 0x00, 0x00],
        // setnf 5; shownf; shownf (noflow: back to 2)
        &[0xd5, 0x00, 0xe0, 0x00, 0xe0, 0x00],
        // unusable table entries, flow-through, ext, le16, many, halt
        &[
            0x12, 0x00, 0x30, 0x50, 0x43, 0x00, 0x47, 0x00, 0x90, 0x00, 0x91, 0x20, 0x80, 0x12,
            0x34, 0xc0, 0, 0x34, 0x12, 0xb3, 0x00, 0xf0, 0x00,
        ],
    ];
    for bytes in hand {
        out.push((0x2000, Vec::new(), bytes.to_vec()));
    }
    out.push((0x2001, Vec::new(), vec![0x20, 0x01, 0x00, 0x00]));
    out.push((
        0x3000,
        vec![("mode".to_owned(), 1)],
        vec![0x71, 0x00, 0x70, 0x00],
    ));
    let mut random = vec![0u8; 8192];
    rng.fill(&mut random);
    out.push((0x4000, Vec::new(), random));
    out
}

/// Runs `pcodedump` on the fixture directory, killed after 60 s.
fn run_pcodedump(
    program: &std::path::Path,
    root: &std::path::Path,
    base: u64,
    config: &[(String, u32)],
    bytes: &[u8],
) -> Option<String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.arg(root).arg(fixture::ID).arg(format!("{base:#x}"));
    for (name, value) in config {
        cmd.arg("--context").arg(format!("{name}={value}"));
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        text
    });
    let Some(status) = child
        .wait_timeout(std::time::Duration::from_mins(1))
        .unwrap()
    else {
        let _ = child.kill();
        panic!("pcodedump timed out");
    };
    let text = reader.join().unwrap();
    // A crash of Ghidra's engine is `None` (see `common::recording::record`).
    status.success().then_some(text)
}

/// Regenerates `tests/data/fixture-oracle.txt` with the reference
/// `pcodedump` (run with `--ignored` after changing the fixture).
#[test]
#[ignore = "regenerates checked-in data with the reference tools"]
fn record_fixture_oracle() {
    let Some(reference) = common::reference() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    fixture::write_language_dir(dir.path());
    let lang = language();
    let program = reference.tool_path(bk_testkit::Tool::Pcodedump);
    let mut out = String::new();
    out.push_str("# pcodedump output for the bkfix fixture language (tests/fixture/mod.rs).\n");
    out.push_str("# Recorded by `cargo test -p bk-sleigh --test fixture_oracle -- --ignored record_fixture_oracle`\n");
    let stamp = std::fs::read_to_string(reference.stamp_file()).unwrap_or_default();
    let commit = stamp
        .lines()
        .find(|l| l.contains("commit"))
        .unwrap_or("ghidra commit unknown");
    let _ = writeln!(
        out,
        "# tool: {} ({commit})",
        reference.tool_path(bk_testkit::Tool::Pcodedump).display()
    );
    let _ = writeln!(
        out,
        "# host: {} {}, compiler: Apple clang 17 (the reference build)",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for (base, config, bytes) in streams(&lang) {
        let run = |base: u64, config: &[(String, u32)], bytes: &[u8]| {
            run_pcodedump(&program, dir.path(), base, config, bytes)
        };
        common::recording::record(&mut out, &run, base, &config, &bytes);
    }
    std::fs::write(DATA, out).unwrap();
}

/// Replays the recorded oracle output against basilisk.
#[test]
fn fixture_matches_recorded_oracle() {
    let text = std::fs::read_to_string(DATA).unwrap();
    let seen = common::recording::replay(&text, &language());
    assert!(seen.streams >= 8, "{seen:?}");
    assert!(seen.instructions > 1000, "{seen:?}");
    // The 21-operand constructor is in the streams; Ghidra's C++ cannot
    // decode it, basilisk does (the harness fails as Ghidra does).
    assert!(seen.tolerated.over_20_operands > 0, "{seen:?}");
    assert_eq!(seen.tolerated.next2_and_commit, 0);
}
