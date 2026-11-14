//! Corpus check (kind G): every `.cspec` under `Ghidra/Processors` decodes
//! (one pair per file, spaces and registers from the oracle table), and the
//! models, entries and rules decoded equal what the files contain (180
//! `<prototype>`, 6 `<resolveprototype>`, 1,558 `<pentry>`, 230 `<rule>`
//! over the 107 files at the pinned commit).

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
mod oracle_common;

use bk_cspec::{CompilerSpec, ReadOptions};

fn count(text: &str, pat: &str) -> usize {
    text.matches(pat).count()
}

/// The text without XML comments (some files comment out entries).
fn uncommented(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some((before, after)) = rest.split_once("<!--") {
        out.push_str(before);
        rest = after.split_once("-->").map_or("", |(_, r)| r);
    }
    out.push_str(rest);
    out
}

/// `pointermax` attributes with a positive value: each appends a rule.
fn pointermax_rules(text: &str) -> usize {
    text.split("pointermax=\"")
        .skip(1)
        .filter(|r| {
            r.split('"')
                .next()
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|v| v > 0)
        })
        .count()
}

#[test]
fn every_cspec_decodes_with_the_counts_of_the_files() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let files = oracle_common::cspec_files(&ghidra.processors_dir());
    let all: String = files
        .values()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect();
    assert_eq!(files.len(), 107);
    assert_eq!(count(&all, "<prototype"), 180);
    assert_eq!(count(&all, "<resolveprototype"), 6);
    assert_eq!(count(&all, "<pentry"), 1558);
    assert_eq!(count(&all, "<rule"), 230);

    let table = oracle_common::table();
    let (pairs, failing) = oracle_common::pairs(&table);
    let mut read = std::collections::BTreeSet::new();
    for pair in pairs.iter().filter(|p| p.heavy) {
        let raw = std::fs::read_to_string(&files[&pair.cspec]).unwrap();
        let text = uncommented(&raw);
        let mut m = oracle_common::manager(pair);
        let spec = CompilerSpec::read(&raw, &mut m, ReadOptions::default())
            .unwrap_or_else(|e| panic!("{}: {e}", pair.cspec));
        let own: Vec<_> = spec
            .models()
            .iter()
            .filter(|x| x.alias_of().is_none())
            .collect();
        let protos = own.iter().filter(|x| !x.is_merged()).count();
        let merged = own.iter().filter(|x| x.is_merged()).count();
        let entries: usize = own
            .iter()
            .filter(|x| !x.is_merged())
            .map(|x| x.input().entries().len() + x.output().entries().len())
            .sum();
        let rules: usize = own
            .iter()
            .filter(|x| !x.is_merged())
            .map(|x| x.input().rules().len() + x.output().rules().len())
            .sum();
        assert_eq!(protos, count(&text, "<prototype"), "{}", pair.cspec);
        assert_eq!(merged, count(&text, "<resolveprototype"), "{}", pair.cspec);
        assert_eq!(entries, count(&text, "<pentry"), "{}", pair.cspec);
        assert_eq!(
            rules,
            count(&text, "<rule") + pointermax_rules(&text),
            "{}",
            pair.cspec
        );
        read.insert(pair.cspec.clone());
    }
    // V850's file names a register its language lacks; Ghidra fails on it too.
    let unread: Vec<_> = files.keys().filter(|f| !read.contains(*f)).collect();
    eprintln!(
        "{} files decoded; not decoded: {unread:?}; failing in Ghidra: {failing:?}",
        read.len()
    );
    assert_eq!(read.len(), 106);
    assert_eq!(unread, ["V850.cspec"]);
}
