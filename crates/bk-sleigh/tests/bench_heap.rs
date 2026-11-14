//! No allocation per instruction in steady state (`features/sleigh-decode.md`
//! 6.6), measured with `dhat` over 100,000 instructions: the `bkfix` fixture
//! everywhere, x86-64 code when the reference directory and the benchmark
//! input are present.
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

use std::sync::Arc;

use bk_core::Address;
use bk_sleigh::{Decoder, Language, SliceBytes};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Decodes and prints `count` instructions from `code` (wrapping around),
/// returning the number decoded.
fn run(
    decoder: &mut Decoder,
    lang: &Language,
    code: &[u8],
    count: usize,
    out: &mut String,
) -> usize {
    let db = lang.initial_context();
    let bytes = SliceBytes::new(0, code);
    let mut pos = 0usize;
    let mut done = 0usize;
    while done < count {
        if pos >= code.len() {
            pos = 0;
        }
        let addr = Address::new(lang.default_space(), pos as u64);
        match decoder.decode(addr, &bytes, &db) {
            Ok(parse) => {
                pos += (parse.length() as usize).max(1);
                out.clear();
                let _ = decoder.mnemonic(out);
                let _ = decoder.body(out);
                done += 1;
            }
            Err(_) => pos += 1,
        }
    }
    done
}

fn allocations_during(f: impl FnOnce()) -> u64 {
    let before = dhat::HeapStats::get().total_blocks;
    f();
    dhat::HeapStats::get().total_blocks - before
}

#[test]
fn steady_state_decoding_allocates_nothing() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let mut cases: Vec<(String, Arc<Language>, Vec<u8>)> = Vec::new();
    let fixture_lang = Arc::new(Language::from_sla(Arc::new(fixture::build())).unwrap());
    // Valid instructions only, so that errors (which carry text) are not
    // what is measured.
    let fixture_code: Vec<u8> = (0..4096u32)
        .flat_map(|i| {
            [
                0x10 | (i % 4) as u8,
                (i * 7) as u8,
                0x20,
                (i * 13) as u8,
                0x50,
                i as u8,
                0x92,
                0x10,
            ]
        })
        .collect();
    cases.push(("bkfix".into(), fixture_lang, fixture_code));
    if let Some(reference) = common::reference() {
        let path = bk_testkit::workspace_root().join("target/bench/x86-64-code.bin");
        if let Ok(code) = std::fs::read(&path) {
            cases.push((
                "x86-64".into(),
                common::load(&reference, "x86:LE:64:default"),
                code,
            ));
        } else {
            eprintln!(
                "SKIPPED x86-64 part: {} missing (reference_bench/build.sh)",
                path.display()
            );
        }
    }
    for (name, lang, code) in cases {
        let mut decoder = Decoder::new(Arc::clone(&lang));
        let mut out = String::with_capacity(256);
        run(&mut decoder, &lang, &code, 100_000, &mut out);
        // The context database is built once per run; count it apart.
        let setup = allocations_during(|| drop(lang.initial_context()));
        let blocks = allocations_during(|| {
            assert_eq!(run(&mut decoder, &lang, &code, 100_000, &mut out), 100_000);
        });
        eprintln!(
            "{name}: {blocks} allocations over 100,000 instructions ({setup} for the context database)"
        );
        assert!(
            blocks <= setup,
            "{name}: {blocks} allocations in steady state"
        );
    }
    steady_state_lifting_allocates_nothing();
}

/// Lifts `count` instructions from `code` (wrapping around) with a counting
/// emitter; returns (instructions lifted, unimplemented errors, whose
/// message is the only text lifting builds).
fn lift_run(decoder: &mut Decoder, lang: &Language, code: &[u8], count: usize) -> (usize, usize) {
    let mut db = lang.initial_context();
    let bytes = SliceBytes::new(0, code);
    let mut counter = bk_sleigh::PcodeCounter::default();
    let mut pos = 0usize;
    let (mut done, mut unimplemented) = (0usize, 0usize);
    while done < count {
        if pos >= code.len() {
            pos = 0;
        }
        let addr = Address::new(lang.default_space(), pos as u64);
        match decoder.lift(addr, &bytes, &mut db, &mut counter) {
            Ok(_) => {
                pos += (decoder.parse().length() as usize).max(1);
                done += 1;
            }
            Err(bk_sleigh::LiftError::Unimplemented { .. }) => {
                pos += (decoder.parse().length() as usize).max(1);
                unimplemented += 1;
                done += 1;
            }
            Err(_) => pos += 1,
        }
    }
    (done, unimplemented)
}

/// Lifting in steady state allocates nothing either (one profiler per
/// process, so called from the decoding test).
fn steady_state_lifting_allocates_nothing() {
    let mut cases: Vec<(String, Arc<Language>, Vec<u8>)> = Vec::new();
    let lang = Arc::new(Language::from_sla(Arc::new(fixture::pcode::build_sla())).unwrap());
    // Valid instructions of every kind that lifts: plain, dynamic,
    // truncated, labels, user op, delay slots, crossbuild, constants,
    // nesting.
    let unit: &[u8] = &[
        0x01, 0x12, 0x0a, 0x00, 0x02, 0x21, 0x03, 0x21, 0x04, 0x21, 0x05, 0x21, 0x06, 0x12, 0x07,
        0x20, 0x08, 0x02, 0x01, 0x12, 0x09, 0x04, 0x01, 0x23, 0x01, 0x30, 0x0b, 0x00, 0x0c, 0x12,
        0x0d, 0x12, 0xab, 0xcd, 0x0f, 0x21, 0x10, 0x21, 0x11, 0x85, 0x14, 0x10,
    ];
    cases.push(("bkpc".into(), lang, unit.repeat(512)));
    if let Some(reference) = common::reference() {
        let path = bk_testkit::workspace_root().join("target/bench/x86-64-code.bin");
        if let Ok(code) = std::fs::read(&path) {
            cases.push((
                "x86-64".into(),
                common::load(&reference, "x86:LE:64:default"),
                code,
            ));
        }
    }
    for (name, lang, code) in cases {
        let mut decoder = Decoder::new(Arc::clone(&lang));
        lift_run(&mut decoder, &lang, &code, 100_000);
        let setup = allocations_during(|| drop(lang.initial_context()));
        let mut unimplemented = 0;
        let blocks = allocations_during(|| {
            let (done, u) = lift_run(&mut decoder, &lang, &code, 100_000);
            assert_eq!(done, 100_000);
            unimplemented = u;
        });
        eprintln!(
            "{name}: {blocks} allocations lifting 100,000 instructions ({setup} for the context database, {unimplemented} unimplemented)"
        );
        assert!(
            blocks <= setup + unimplemented as u64,
            "{name}: {blocks} allocations in steady state"
        );
    }
}
