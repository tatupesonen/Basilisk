//! Recorded `pcodedump` output for real languages (`features/sleigh-decode.md`
//! 6.4): the directed samples of Toy, 200 instructions each of x86-64,
//! ARM/Thumb with a mode switch and MIPS with delay slots, in
//! `tests/data/recorded-oracle.txt`; and basilisk-only snapshots of the
//! PowerPC `AltiVec` instructions Ghidra's C++ cannot decode.
//!
//! The replay needs nothing but the languages' `.sla`, `.ldefs` and `.pspec`,
//! which it takes from the reference directory: those files are Ghidra's and
//! are not copied into this repository (ADR-002), so without the reference
//! directory the replay is skipped (it is in CI). The self-contained
//! counterpart is `fixture_oracle.rs`.
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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use bk_core::Address;
use bk_sleigh::{Decoder, SliceBytes};

const DATA: &str = "tests/data/recorded-oracle.txt";

/// (language, base, configuration, bytes) of every recorded stream.
fn streams(
    reference: &bk_testkit::ReferenceDir,
) -> Vec<(String, u64, common::directed::Config, Vec<u8>)> {
    let mut out = Vec::new();
    // Toy: the directed samples.
    let toy = common::load(reference, "Toy:BE:32:default");
    let mut rng = common::directed::Rng::new(common::directed::seed("Toy:BE:32:default"));
    let plan = common::directed::plan(&toy, 8, &mut rng);
    for s in common::directed::pack(&toy, &plan, 0x1000, 50, 1 << 16) {
        out.push(("Toy:BE:32:default".to_owned(), 0x1000, s.config, s.bytes));
    }
    // 200 instructions of real x86-64 code: the benchmark input (Ghidra's
    // own C++ built by clang) when it has been built, else the fixtures.
    let bench = bk_testkit::workspace_root().join("target/bench/x86-64-code.bin");
    let (base, text) = match std::fs::read(&bench) {
        Ok(code) => (0x10000, code),
        Err(_) => common::real_code::text_section("plain-x86_64.so").unwrap(),
    };
    let x86 = common::load(reference, "x86:LE:64:default");
    let n = bytes_for(&x86, base, &text, &[], 200);
    out.push((
        "x86:LE:64:default".to_owned(),
        base,
        Vec::new(),
        text[..n].to_vec(),
    ));
    // ARM: blx to Thumb code (a flowing TMode commit at the target), then
    // Thumb instructions, then real Thumb code.
    let mut arm = Vec::new();
    arm.extend_from_slice(&[0x00, 0x00, 0x00, 0xfa]); // blx #+8 (Thumb)
    arm.extend_from_slice(&[0x00, 0x00, 0xa0, 0xe1]); // mov r0, r0
    arm.extend_from_slice(&[0x01, 0x20, 0x08, 0x44, 0x70, 0x47]); // movs r0,#1; add r0,r1; bx lr
    let (arm_base, mut arm_text) = common::real_code::text_section("plain-arm.so").unwrap();
    arm_text.extend_from_slice(&common::real_code::text_section("aps2-arm.so").unwrap().1);
    let mut thumb_random = vec![0u8; 400];
    common::directed::Rng::new(78).fill(&mut thumb_random);
    arm_text.extend_from_slice(&thumb_random);
    let armlang = common::load(reference, "ARM:LE:32:v8");
    let n = bytes_for(
        &armlang,
        arm_base,
        &arm_text,
        &[("TMode".to_owned(), 1)],
        190,
    );
    out.push(("ARM:LE:32:v8".to_owned(), 0x1000, Vec::new(), arm));
    out.push((
        "ARM:LE:32:v8".to_owned(),
        arm_base,
        vec![("TMode".to_owned(), 1)],
        arm_text[..n].to_vec(),
    ));
    // MIPS: branches with delay slots, a branch in a delay slot, then random
    // words.
    let mut mips: Vec<u8> = [
        0x1000_0003u32, // b +3
        0x2402_0001,    // li v0,1 (delay slot)
        0x0c00_0400,    // jal 0x1000
        0x2403_0002,    // li v1,2 (delay slot)
        0x03e0_0008,    // jr ra
        0x0000_0000,    // nop (delay slot)
        0x1000_0001,    // b +1
        0x1000_0001,    // b +1 in the delay slot
        0x0000_0000,
        0x5440_0002, // bnezl v0,+2 (likely: delay slot annulled)
        0x2404_0003,
    ]
    .iter()
    .flat_map(|w| w.to_be_bytes())
    .collect();
    let mut rng = common::directed::Rng::new(77);
    let mut random = vec![0u8; 760];
    rng.fill(&mut random);
    mips.extend_from_slice(&random);
    out.push(("MIPS:BE:32:default".to_owned(), 0x40_0000, Vec::new(), mips));
    out
}

/// The number of bytes holding the first `count` instructions.
fn bytes_for(
    lang: &Arc<bk_sleigh::Language>,
    base: u64,
    code: &[u8],
    config: &[(String, u32)],
    count: usize,
) -> usize {
    let sweep = common::sweep(lang, base, code, config);
    sweep
        .records
        .iter()
        .filter(|r| r.line.starts_with('I'))
        .nth(count)
        .map_or(code.len(), |r| (r.address - base) as usize)
}

/// Regenerates `tests/data/recorded-oracle.txt` (run with `--ignored`).
#[test]
#[ignore = "regenerates checked-in data with the reference tools"]
fn record_real_languages() {
    let Some(reference) = common::reference() else {
        return;
    };
    let mut out = String::new();
    out.push_str("# pcodedump output for real languages (tests/recorded.rs).\n");
    out.push_str("# Recorded by `cargo test -p bk-sleigh --test recorded -- --ignored record_real_languages`\n");
    let stamp = std::fs::read_to_string(reference.stamp_file()).unwrap_or_default();
    let commit = stamp
        .lines()
        .find(|l| l.contains("commit"))
        .unwrap_or("ghidra commit unknown");
    let _ = writeln!(
        out,
        "# tool: reference pcodedump ({commit}); host: {} {}; compiler: Apple clang 17",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for (id, base, config, bytes) in streams(&reference) {
        let _ = writeln!(out, "language\t{id}");
        let run = |base: u64, config: &[(String, u32)], bytes: &[u8]| {
            let mut tool = reference.pcodedump();
            for (n, v) in config {
                tool = tool.context(n, *v);
            }
            tool.dump_text(&id, base, bytes).ok()
        };
        common::recording::record(&mut out, &run, base, &config, &bytes);
    }
    std::fs::write(DATA, out).unwrap();
}

/// Replays the recording; needs the languages' files from the reference
/// directory.
#[test]
fn real_languages_match_recorded_oracle() {
    let Some(reference) = common::reference() else {
        return;
    };
    let text = std::fs::read_to_string(DATA).unwrap();
    let mut by_language: BTreeMap<String, String> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(id) = line.strip_prefix("language\t") {
            current = id.to_owned();
        } else if !line.starts_with('#') {
            let entry = by_language.entry(current.clone()).or_default();
            entry.push_str(line);
            entry.push('\n');
        }
    }
    assert_eq!(by_language.len(), 4, "{:?}", by_language.keys());
    for (id, recording) in by_language {
        let lang = common::load(&reference, &id);
        let seen = common::recording::replay(&recording, &lang);
        eprintln!("{id}: {seen:?}");
        assert!(seen.instructions >= 10, "{id}");
    }
}

/// basilisk decodes and lifts the `AltiVec` constructors with more than 20
/// operands (p-code checked by this snapshot alone; `features/sleigh-pcode.md`).
#[test]
fn altivec_beyond_ghidras_operand_limit() {
    let Some(reference) = common::reference() else {
        return;
    };
    let lang = common::load(&reference, "PowerPC:BE:32:default");
    let db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let mut text = String::new();
    for word in [0x1022_1840u32, 0x1022_1c40, 0x13ff_f840, 0x1000_0440] {
        let bytes = word.to_be_bytes();
        let addr = Address::new(lang.default_space(), 0x1000);
        let source = SliceBytes::new(0x1000, &bytes);
        let parse = decoder.decode(addr, &source, &db).unwrap();
        let max = parse.max_operands();
        let mut line = String::new();
        decoder.mnemonic(&mut line).unwrap();
        line.push(' ');
        decoder.body(&mut line).unwrap();
        let _ = writeln!(text, "{word:08x}\t{line}\tlargest operand count {max}");
        // Its p-code (basilisk only: the oracle cannot decode it).
        let mut ctx = db.clone();
        let mut records = bk_sleigh::PcodeRecords::new(&lang, &mut text);
        decoder.lift(addr, &source, &mut ctx, &mut records).unwrap();
        decoder.set_operand_limit(Some(20));
        let err = decoder.decode(addr, &source, &db).unwrap_err();
        assert_eq!(err.to_string(), "SLEIGH parser out of state space");
        decoder.set_operand_limit(None);
    }
    insta::assert_snapshot!("altivec", text);
}
