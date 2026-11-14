//! No allocation per instruction in steady state (`features/sleigh-decode.md`
//! 6.6), measured with `dhat` over 100,000 instructions: the `bkfix` fixture
//! everywhere, x86-64 code when the reference directory and the benchmark
//! input are present.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;
mod fixture;

use std::sync::Arc;

use bk_core::Address;
use bk_sleigh::{Decoder, Language, SliceBytes};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Decodes and prints `count` instructions from `code` (wrapping around),
/// returning the number decoded.
fn run(decoder: &mut Decoder, lang: &Language, code: &[u8], count: usize, out: &mut String) -> usize {
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
        .flat_map(|i| [0x10 | (i % 4) as u8, (i * 7) as u8, 0x20, (i * 13) as u8, 0x50, i as u8, 0x92, 0x10])
        .collect();
    cases.push(("bkfix".into(), fixture_lang, fixture_code));
    if let Some(reference) = common::reference() {
        let path = bk_testkit::workspace_root().join("target/bench/x86-64-code.bin");
        if let Ok(code) = std::fs::read(&path) {
            cases.push(("x86-64".into(), common::load(&reference, "x86:LE:64:default"), code));
        } else {
            eprintln!("SKIPPED x86-64 part: {} missing (reference_bench/build.sh)", path.display());
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
        eprintln!("{name}: {blocks} allocations over 100,000 instructions ({setup} for the context database)");
        assert!(blocks <= setup, "{name}: {blocks} allocations in steady state");
    }
}
