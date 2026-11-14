//! Replays the oracle tables: the results of Ghidra's compiled
//! `CircleRange` (`rangeutil.cc`, reference build) for the cases of
//! every method in scope (152,913 rows), produced by `tests/oracle/circlerange_oracle.cc`
//! (`tests/oracle/regen.sh`; format and provenance in
//! `tests/data/README.md`). Kind S: runs everywhere.
//!
//! There are two tables, one per reference host: x86-64 Linux (g++,
//! libstdc++), which Basilisk follows, and macOS AArch64 (Apple clang,
//! libc++). Each row's results are computed again with `bk-decomp-range`,
//! written in the table's format, and compared as text:
//!
//! - every row of the x86-64 table must agree, including the rows marked
//!   as depending on undefined behaviour in the C++ (` #ub=…`: Basilisk
//!   computes what the reference builds compute) or on the uninitialised
//!   fields of an empty range (` #uninit`: Basilisk's empty range has zero
//!   fields, and the table was generated with those); the marks are
//!   counted by kind and the counts pinned;
//! - a row of the macOS table equals the x86-64 row, or differs for a
//!   cause `common/host.rs` recognises; those are counted and pinned.
//!
//! `docs/features/decomp-range.md`, section 8, lists both.

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

use common::host::{Cause, recognise};
use common::oracle::{compute, gunzip, second_inputs, split};

const X86_64: &[u8] = include_bytes!("data/circlerange_oracle.libstdcxx.txt.gz");
const AARCH64: &[u8] = include_bytes!("data/circlerange_oracle.libcxx.txt.gz");

/// Marks of the x86-64 table by kind (`ub=<check>@<file>:<line>`,
/// `uninit`), as `regen.sh --marks` wrote them.
const MARKS: &[(&str, usize)] = &[
    ("ub=add_overflow@rangeutil.cc:1331", 184),
    ("ub=mul_overflow@rangeutil.cc:1283", 1500),
    ("ub=shift_out_of_bounds@address.cc:1003", 5364),
    ("ub=shift_out_of_bounds@address.hh:605", 396),
    ("ub=shift_out_of_bounds@rangeutil.cc:1269", 1227),
    ("ub=shift_out_of_bounds@rangeutil.cc:1270", 1227),
    ("ub=shift_out_of_bounds@rangeutil.cc:1288", 1424),
    ("ub=shift_out_of_bounds@rangeutil.cc:1292", 1424),
    ("ub=shift_out_of_bounds@rangeutil.cc:1293", 1424),
    ("ub=shift_out_of_bounds@rangeutil.cc:1308", 776),
    ("ub=shift_out_of_bounds@rangeutil.cc:1309", 776),
    ("ub=shift_out_of_bounds@rangeutil.cc:1313", 724),
    ("ub=shift_out_of_bounds@rangeutil.cc:1334", 1500),
    ("ub=shift_out_of_bounds@rangeutil.cc:1335", 1500),
    ("ub=shift_out_of_bounds@rangeutil.cc:696", 570),
    ("ub=shift_out_of_bounds@rangeutil.cc:949", 712),
    ("ub=shift_out_of_bounds@rangeutil.cc:975", 712),
    ("ub=shift_out_of_bounds@rangeutil.cc:pullBackBinary", 2716),
    ("uninit", 2777),
];

/// Rows of the macOS table that differ, by cause.
const HOST_ROWS: &[(Cause, usize)] = &[(Cause::NeonShiftLeft, 834)];

#[test]
fn every_x86_64_row_agrees_with_basilisk() {
    let text = gunzip(X86_64);
    let mut tags = BTreeMap::new();
    let mut marks: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let row = split(line);
        *tags.entry(row.tag).or_insert(0usize) += 1;
        for m in &row.marks {
            *marks.entry((*m).to_owned()).or_default() += 1;
        }
        let ours = compute(&row);
        if ours != row.results {
            bad.push(format!("line {}: {line}\n  basilisk: {ours}", n + 1));
        }
    }
    eprintln!("rows: {tags:?}");
    eprintln!("marks: {marks:?}");
    for b in bad.iter().take(20) {
        eprintln!("{b}");
    }
    assert!(bad.is_empty(), "{} of {} rows differ from Ghidra", bad.len(), text.lines().count());
    let pinned: BTreeMap<String, usize> = MARKS.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
    assert_eq!(marks, pinned, "the marks of the table changed: update MARKS and section 8");
}

#[test]
fn the_macos_table_differs_only_for_known_causes() {
    let x86 = gunzip(X86_64);
    let arm = gunzip(AARCH64);
    assert_eq!(x86.lines().count(), arm.lines().count(), "the tables have different row counts");
    let mut causes: BTreeMap<Cause, usize> = BTreeMap::new();
    let mut unexplained = Vec::new();
    for (n, (x, a)) in x86.lines().zip(arm.lines()).enumerate() {
        let (x, a) = (split(x), split(a));
        assert_eq!((x.tag, &x.inputs), (a.tag, &a.inputs), "line {}: the inputs differ", n + 1);
        if x.results == a.results {
            continue;
        }
        match recognise(&a, &second_inputs(&a)) {
            Some(cause) => *causes.entry(cause).or_default() += 1,
            None => unexplained.push(format!("line {}\n  x86-64:  {}\n  aarch64: {}", n + 1, x.results, a.results)),
        }
    }
    for u in unexplained.iter().take(10) {
        eprintln!("{u}");
    }
    assert!(unexplained.is_empty(), "{} rows differ for no known cause", unexplained.len());
    for (cause, count) in &causes {
        eprintln!("{}: {count} rows", cause.name());
    }
    let pinned: BTreeMap<Cause, usize> = HOST_ROWS.iter().copied().filter(|(_, n)| *n > 0).collect();
    assert_eq!(causes, pinned, "the host differences changed: update HOST_ROWS and section 8");
}
