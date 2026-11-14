//! Property tests (`features/sleigh-decode.md` 6.5): arbitrary bytes and
//! context never make decoding, printing or `prepare` panic; decoding is
//! deterministic; lengths are bounded; eight threads sharing one language
//! produce identical output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;
mod fixture;

use std::sync::{Arc, OnceLock};

use bk_core::Address;
use bk_sleigh::{Decoder, Language, SliceBytes};
use proptest::prelude::*;

fn fixture_language() -> Arc<Language> {
    static LANG: OnceLock<Arc<Language>> = OnceLock::new();
    Arc::clone(LANG.get_or_init(|| Arc::new(Language::from_sla(Arc::new(fixture::build())).unwrap())))
}

/// Decodes, prints and prepares at `offset`; returns what was seen.
fn exercise(lang: &Arc<Language>, offset: u64, bytes: &[u8], words: &[u32]) -> String {
    let mut db = lang.empty_context();
    for (i, &w) in words.iter().enumerate().take(lang.context_words()) {
        db.set_default(i, u32::MAX, w);
    }
    let mut decoder = Decoder::new(Arc::clone(lang));
    let source = SliceBytes::new(offset, bytes);
    let addr = Address::new(lang.default_space(), offset);
    let mut out = String::new();
    match decoder.decode(addr, &source, &db) {
        Ok(parse) => {
            let length = parse.length();
            out.push_str(&format!("len {length} "));
            let _ = decoder.mnemonic(&mut out);
            out.push(' ');
            let _ = decoder.body(&mut out);
            match decoder.prepare(addr, &source, &mut db) {
                Ok(p) => out.push_str(&format!(" flow {}", p.flow_length)),
                Err(e) => out.push_str(&format!(" prepare {e}")),
            }
        }
        Err(e) => out.push_str(&e.to_string()),
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn fixture_never_panics_and_is_deterministic(
        offset in any::<u32>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..24),
        words in proptest::collection::vec(any::<u32>(), 0..3),
    ) {
        let lang = fixture_language();
        let a = exercise(&lang, u64::from(offset), &bytes, &words);
        let b = exercise(&lang, u64::from(offset), &bytes, &words);
        prop_assert_eq!(&a, &b);
        if let Some(len) = a.strip_prefix("len ").and_then(|r| r.split(' ').next()).and_then(|l| l.parse::<u32>().ok()) {
            prop_assert!(len > 0 && len <= 16, "{}", a);
        }
    }
}

/// Real languages from the reference directory, when present.
#[test]
fn reference_languages_never_panic_on_random_bytes() {
    let Some(reference) = common::reference() else { return };
    for id in ["x86:LE:64:default", "ARM:LE:32:v8", "MIPS:BE:32:default", "PowerPC:BE:32:default", "Toy:BE:32:default"] {
        let lang = common::load(&reference, id);
        let mut rng = common::directed::Rng::new(common::directed::seed(id));
        let mut longest = 0u32;
        for i in 0..20_000u64 {
            let mut bytes = [0u8; 20];
            rng.fill(&mut bytes);
            let words: Vec<u32> = (0..lang.context_words()).map(|_| rng.next() as u32).collect();
            let seen = exercise(&lang, i * 4, &bytes, &words);
            if let Some(len) = seen.strip_prefix("len ").and_then(|r| r.split(' ').next()).and_then(|l| l.parse::<u32>().ok()) {
                assert!(len > 0, "{id}: {seen}");
                longest = longest.max(len);
            }
        }
        // Lengths beyond the window come only from operands placed past it.
        assert!(longest <= 32, "{id}: {longest}");
    }
}

#[test]
fn eight_threads_sharing_a_language_agree() {
    let lang = fixture_language();
    let mut rng = common::directed::Rng::new(42);
    let mut bytes = vec![0u8; 1 << 16];
    rng.fill(&mut bytes);
    let expected = common::sweep(&lang, 0x1000, &bytes, &[]);
    let lines: Vec<String> = expected.records.iter().map(|r| r.line.clone()).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let lang = Arc::clone(&lang);
                let bytes = &bytes;
                scope.spawn(move || common::sweep(&lang, 0x1000, bytes, &[]).records.into_iter().map(|r| r.line).collect::<Vec<_>>())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), lines);
        }
    });
}
