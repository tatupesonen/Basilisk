//! The self-contained differential check: the `bkfix` language (built in
//! Rust, `tests/fixture/mod.rs`) decoded by basilisk and compared with
//! `pcodedump`'s output for it, recorded once in
//! `tests/data/fixture-oracle.txt`. The replay needs nothing outside the
//! repository, so it runs on every platform in CI; the recording needs the
//! reference tools (`record_fixture_oracle`, ignored).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;
mod fixture;

use std::fmt::Write as _;
use std::sync::Arc;

use bk_lang::Mode;
use bk_sleigh::Language;

const DATA: &str = "tests/data/fixture-oracle.txt";

fn language() -> Arc<Language> {
    let mut lang = Language::from_sla(Arc::new(fixture::build())).unwrap();
    let pspec = bk_lang::pspec::parse(fixture::PSPEC, Mode::Strict).unwrap().value;
    lang.apply_processor_spec(&pspec).unwrap();
    Arc::new(lang)
}

/// The streams: directed samples per root pair, hand-written sequences and
/// random bytes. (base, configuration, bytes)
fn streams(lang: &Arc<Language>) -> Vec<(u64, Vec<(String, u32)>, Vec<u8>)> {
    let mut rng = common::directed::Rng::new(common::directed::seed(fixture::ID));
    let plan = common::directed::plan(lang, 8, &mut rng);
    let mut out: Vec<(u64, Vec<(String, u32)>, Vec<u8>)> = common::directed::pack(lang, &plan, 0x1000, 50, 1 << 16)
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
        &[0x12, 0x00, 0x30, 0x50, 0x43, 0x00, 0x47, 0x00, 0x90, 0x00, 0x91, 0x20, 0x80, 0x12, 0x34, 0xc0, 0, 0x34, 0x12, 0xb3, 0x00, 0xf0, 0x00],
    ];
    for bytes in hand {
        out.push((0x2000, Vec::new(), bytes.to_vec()));
    }
    out.push((0x2001, Vec::new(), vec![0x20, 0x01, 0x00, 0x00]));
    out.push((0x3000, vec![("mode".to_owned(), 1)], vec![0x71, 0x00, 0x70, 0x00]));
    let mut random = vec![0u8; 8192];
    rng.fill(&mut random);
    out.push((0x4000, Vec::new(), random));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// Runs `pcodedump` on the fixture directory, killed after 60 s.
fn run_pcodedump(program: &std::path::Path, root: &std::path::Path, base: u64, config: &[(String, u32)], bytes: &[u8]) -> Option<String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.arg(root).arg(fixture::ID).arg(format!("{base:#x}"));
    for (name, value) in config {
        cmd.arg("--context").arg(format!("{name}={value}"));
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        text
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            if !status.success() {
                // A crash of Ghidra's engine (see `record`).
                let _ = reader.join();
                return None;
            }
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("pcodedump timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Some(reader.join().unwrap())
}

/// Records one stream; where Ghidra's engine crashes on an instruction (an
/// `unimpl` body in a delay slot makes its error path use a dangling
/// walker), the stream is split around that instruction.
fn record(out: &mut String, program: &std::path::Path, root: &std::path::Path, base: u64, config: &[(String, u32)], bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let Some(text) = run_pcodedump(program, root, base, config, bytes) else {
        let crashes = |len: usize| run_pcodedump(program, root, base, config, &bytes[..len]).is_none();
        let (mut ok, mut bad) = (0usize, bytes.len());
        while bad - ok > 1 {
            let mid = ok + (bad - ok) / 2;
            if crashes(mid) { bad = mid } else { ok = mid }
        }
        let before = common::parse_oracle(&run_pcodedump(program, root, base, config, &bytes[..bad - 1]).unwrap_or_default());
        let start = before
            .lines
            .last()
            .filter(|l| l.contains("\ttruncated\t"))
            .map_or(bad - 1, |l| (u64::from_str_radix(l.split('\t').nth(1).unwrap().trim_start_matches("0x"), 16).unwrap() - base) as usize);
        let _ = writeln!(out, "# oracle crash at {:#x}: {}", base + start as u64, hex(&bytes[start..bad]));
        record(out, program, root, base, config, &bytes[..start]);
        record(out, program, root, base + bad as u64, config, &bytes[bad..]);
        return;
    };
    let names: Vec<String> = config.iter().map(|(n, v)| format!("{n}={v}")).collect();
    let _ = writeln!(out, "stream\t{base:#x}\t{}", names.join(","));
    let _ = writeln!(out, "bytes\t{}", hex(bytes));
    for line in text.lines().filter(|l| !l.starts_with('H')) {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("end\n");
}

/// Regenerates `tests/data/fixture-oracle.txt` with the reference
/// `pcodedump` (run with `--ignored` after changing the fixture).
#[test]
#[ignore = "regenerates checked-in data with the reference tools"]
fn record_fixture_oracle() {
    let Some(reference) = common::reference() else { return };
    let dir = tempfile::tempdir().unwrap();
    fixture::write_language_dir(dir.path());
    let lang = language();
    let program = reference.tool_path(bk_testkit::Tool::Pcodedump);
    let mut out = String::new();
    out.push_str("# pcodedump output for the bkfix fixture language (tests/fixture/mod.rs).\n");
    out.push_str("# Recorded by `cargo test -p bk-sleigh --test fixture_oracle -- --ignored record_fixture_oracle`\n");
    let stamp = std::fs::read_to_string(reference.stamp_file()).unwrap_or_default();
    let commit = stamp.lines().find(|l| l.contains("commit")).unwrap_or("ghidra commit unknown");
    let _ = writeln!(out, "# tool: {} ({commit})", reference.tool_path(bk_testkit::Tool::Pcodedump).display());
    let _ = writeln!(out, "# host: {} {}, compiler: Apple clang 17 (the reference build)", std::env::consts::OS, std::env::consts::ARCH);
    for (base, config, bytes) in streams(&lang) {
        record(&mut out, &program, dir.path(), base, &config, &bytes);
    }
    std::fs::write(DATA, out).unwrap();
}

/// Replays the recorded oracle output against basilisk.
#[test]
fn fixture_matches_recorded_oracle() {
    let text = std::fs::read_to_string(DATA).unwrap();
    let lang = language();
    let mut lines = text.lines().filter(|l| !l.starts_with('#'));
    let mut streams = 0;
    let mut tolerated = common::Tolerated::default();
    let mut instructions = 0;
    while let Some(head) = lines.next() {
        let mut fields = head.split('\t');
        assert_eq!(fields.next(), Some("stream"));
        let base = u64::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
        let config: Vec<(String, u32)> = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|c| !c.is_empty())
            .map(|c| {
                let (n, v) = c.split_once('=').unwrap();
                (n.to_owned(), v.parse().unwrap())
            })
            .collect();
        let bytes = unhex(lines.next().unwrap().strip_prefix("bytes\t").unwrap());
        let mut recorded = String::new();
        for line in lines.by_ref() {
            if line == "end" {
                break;
            }
            recorded.push_str(line);
            recorded.push('\n');
        }
        let theirs = common::parse_oracle(&recorded);
        let ours = common::sweep(&lang, base, &bytes, &config);
        let cmp = common::compare(&theirs, &ours);
        for f in &cmp.failures {
            eprintln!("stream at {base:#x} {config:?}: {f}");
        }
        assert!(cmp.failures.is_empty());
        tolerated.add(&cmp.tolerated);
        instructions += theirs.instructions;
        streams += 1;
    }
    assert!(streams >= 8, "{streams} streams");
    assert!(instructions > 1000, "{instructions} instructions");
    // The 21-operand constructor is in the streams; Ghidra's C++ cannot
    // decode it, basilisk does.
    assert!(tolerated.over_20_operands > 0, "{tolerated:?}");
    assert_eq!(tolerated.next2_and_commit, 0);
}
