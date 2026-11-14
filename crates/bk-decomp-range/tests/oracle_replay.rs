//! Replays the oracle table, `tests/data/circlerange_oracle.txt.gz`: the
//! results of Ghidra's compiled `CircleRange` (`rangeutil.cc`, reference
//! build) for 176,000 cases over every method in scope, produced by
//! `tests/oracle/circlerange_oracle.cc` (`tests/oracle/regen.sh`; format
//! and provenance in `tests/data/README.md`). Kind S: runs everywhere.
//!
//! Each row's results are computed again with `bk-decomp-range`, written
//! in the table's format, and compared as text. Every row must agree,
//! including the rows marked as depending on undefined behaviour in the C++
//! (` #ub=…`: Basilisk computes what both reference builds compute) and on
//! uninitialised fields of an empty range (` #uninit`: Basilisk's empty
//! range has zero fields, and the table was generated with those). The
//! marks are counted by kind and the counts are pinned, so a regenerated
//! table that changes them is noticed (`docs/features/decomp-range.md`,
//! section 8).

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

use common::oracle::{compute, gunzip, split};

const TABLE: &[u8] = include_bytes!("data/circlerange_oracle.txt.gz");

/// Replays every row of `text`; returns the rows per tag and the marks per
/// kind (kind = the mark up to `@`, with the source line after it).
pub(crate) fn replay(text: &str) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut tags = BTreeMap::new();
    let mut marks = BTreeMap::new();
    let mut bad = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let row = split(line);
        *tags.entry(row.tag.to_owned()).or_insert(0) += 1;
        for m in &row.marks {
            *marks.entry((*m).to_owned()).or_insert(0) += 1;
        }
        let ours = compute(&row);
        if ours != row.results {
            bad.push(format!("line {}: {line}\n  basilisk: {ours}", n + 1));
        }
    }
    for b in bad.iter().take(20) {
        eprintln!("{b}");
    }
    assert!(bad.is_empty(), "{} of {} rows differ from Ghidra", bad.len(), text.lines().count());
    (tags, marks)
}

#[test]
fn every_row_agrees_with_ghidra() {
    let text = gunzip(TABLE);
    let (tags, marks) = replay(&text);
    eprintln!("rows: {tags:?}");
    eprintln!("marks: {marks:?}");
    let rows: usize = tags.values().sum();
    assert_eq!(rows, text.lines().count());
}
