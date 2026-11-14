//! The self-contained differential check of p-code generation: the `bkpc`
//! language (`tests/fixture/pcode.rs`) lifted by basilisk and compared with
//! `pcodedump`'s output for it, recorded once in
//! `tests/data/pcode-fixture-oracle.txt`. The replay needs nothing outside
//! the repository and runs on every platform in CI; the recording needs
//! the reference tools (`record_pcode_fixture_oracle`, ignored).
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
use fixture::pcode;

const DATA: &str = "tests/data/pcode-fixture-oracle.txt";

pub(crate) fn language() -> Arc<Language> {
    let mut lang = Language::from_sla(Arc::new(pcode::build_sla())).unwrap();
    let pspec = bk_lang::pspec::parse(pcode::PSPEC, Mode::Strict)
        .unwrap()
        .value;
    lang.apply_processor_spec(&pspec).unwrap();
    Arc::new(lang)
}

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| (c as char).to_digit(16).unwrap() as u8)
        .collect();
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// Hand-written sequences: (base, bytes).
pub(crate) const HAND: &[(u64, &str)] = &[
    // add; crossbuild of it; ld (implied section in mem); crossbuild
    (0x2000, "0112 0a00 0231 0a00"),
    // nest (implied section through inner); crossbuild
    (0x2010, "0f21 0a00 0f12"),
    // crossbuild of itself; crossbuild inside a section; crossbuild before
    // anything was decoded
    (0x2020, "0b00 1300"),
    (0x2030, "0a00 0112"),
    // delay slot of one and of two instructions; a delay slot that is a
    // delayed branch itself (its own delay slot was not decoded)
    (0x2040, "0802 0112 0904 0123 0130 0802 0802 0100 0112"),
    // constants, constant pointer, missing label, unique temps, labels,
    // user op, every opcode
    (0x2060, "0d12 abcd 1185 1200 1410 0612 0720 0c12"),
    // dynamic operands
    (0x2080, "0221 0321 0421 0521 1021 0233"),
    // unaligned crossbuild target and alignment errors
    (0x2091, "0112 0a00"),
];

/// The streams: directed samples per root pair, the hand-written
/// sequences and random bytes. (base, configuration, bytes)
fn streams(lang: &Arc<Language>) -> Vec<(u64, common::directed::Config, Vec<u8>)> {
    let mut rng = common::directed::Rng::new(common::directed::seed(pcode::ID));
    let plan = common::directed::plan(lang, 8, &mut rng);
    let mut out: Vec<(u64, common::directed::Config, Vec<u8>)> =
        common::directed::pack(lang, &plan, 0x1000, 50, 1 << 16)
            .into_iter()
            .map(|s| (0x1000, s.config, s.bytes))
            .collect();
    for (base, bytes) in HAND {
        out.push((*base, Vec::new(), hex(bytes)));
    }
    // Random bytes with a valid opcode in every other byte.
    let mut random = vec![0u8; 8192];
    rng.fill(&mut random);
    for (i, b) in random.iter_mut().enumerate() {
        if i % 2 == 0 {
            *b = 1 + *b % 0x14;
        }
    }
    out.push((0x4000, Vec::new(), random));
    out
}

/// Regenerates `tests/data/pcode-fixture-oracle.txt` with the reference
/// `pcodedump` (run with `--ignored` after changing the fixture).
#[test]
#[ignore = "regenerates checked-in data with the reference tools"]
fn record_pcode_fixture_oracle() {
    let Some(reference) = common::reference() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    pcode::write_language_dir(dir.path());
    let lang = language();
    let program = reference.tool_path(bk_testkit::Tool::Pcodedump);
    let mut out = String::new();
    out.push_str("# pcodedump output for the bkpc fixture language (tests/fixture/pcode.rs).\n");
    out.push_str("# Recorded by `cargo test -p bk-sleigh --test pcode_fixture -- --ignored record_pcode_fixture_oracle`\n");
    let stamp = std::fs::read_to_string(reference.stamp_file()).unwrap_or_default();
    let commit = stamp
        .lines()
        .find(|l| l.contains("commit"))
        .unwrap_or("ghidra commit unknown");
    let _ = writeln!(out, "# tool: pcodedump of the reference build ({commit})");
    let _ = writeln!(
        out,
        "# host: {} {} (the reference build)",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for (base, config, bytes) in streams(&lang) {
        let run = |base: u64, config: &[(String, u32)], bytes: &[u8]| {
            common::recording::run_pcodedump(&program, dir.path(), pcode::ID, base, config, bytes)
        };
        common::recording::record(&mut out, &run, base, &config, &bytes);
    }
    std::fs::write(DATA, out).unwrap();
}

/// Replays the recorded oracle output against basilisk: every record, `P`
/// and `U` included.
#[test]
fn pcode_fixture_matches_recorded_oracle() {
    let text = std::fs::read_to_string(DATA).unwrap();
    let lang = language();
    let seen = common::recording::replay(&text, &lang);
    assert!(seen.streams >= 8, "{seen:?}");
    assert!(seen.instructions > 1000, "{seen:?}");
    // Every construct of the fixture was met in a confirmed record.
    let missing = seen.templates.missing();
    assert!(missing.is_empty(), "never built: {missing:?}");
    // Every op template was built; the two main templates never built are
    // `mem`'s and `cmem`'s, which only export (nothing BUILDs them).
    assert_eq!(
        seen.templates.ops_built.len(),
        seen.templates.op_templates,
        "{}",
        seen.templates.columns()
    );
    assert!(seen.templates.rate() >= 0.9, "{}", seen.templates.columns());
}
