//! Regenerates the oracle with `tests/oracle/regen.sh --extended` from the
//! reference build (kind L) and
//!
//! 1. requires the base table to equal the checked-in table of the C++
//!    library the host's compiler uses (libc++ on macOS, libstdc++ on
//!    Linux), ignoring the marks: proves the table current and the
//!    generator deterministic on this host;
//! 2. replays the extended case set (the full counts of
//!    `docs/features/decomp-range.md` 6.2: a 300-range sample of the 1-byte
//!    ranges against itself, 200,000 random pairs, 12,000 ranges through
//!    the unary operations, …; about 590,000 rows, not checked in) against
//!    `bk-decomp-range`: every row must agree, except, on the libc++ host,
//!    rows of a cause `common/host.rs` recognises.
//!
//! Needs `BASILISK_REFERENCE_DIR` (or `../reference`) with the objects of
//! `scripts/build-reference.sh`, a C++ compiler and bash; skipped with a
//! printed reason otherwise.

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
use std::path::Path;
use std::process::Command;

use common::host::recognise;
use common::oracle::{compute, gunzip, second_inputs, split};

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The table body without its marks.
fn bare(line: &str) -> &str {
    line.split_once(" #").map_or(line, |(body, _)| body)
}

#[test]
fn regenerated_tables_agree() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    if !reference.root().join("src/cpp/com_opt").is_dir() {
        eprintln!(
            "SKIPPED: {} has no src/cpp/com_opt objects (scripts/build-reference.sh builds them)",
            reference.root().display()
        );
        return;
    }
    if !have("bash") || !have("c++") {
        eprintln!("SKIPPED: regenerating the oracle table needs bash and a C++ compiler (c++)");
        return;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bk-decomp-range-oracle-regen");
    let _ = std::fs::remove_dir_all(&out);
    let status = Command::new("bash")
        .arg(manifest.join("tests/oracle/regen.sh"))
        .arg("--extended")
        .arg(reference.root())
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "regen.sh failed: {status}");
    let lib = ["libcxx", "libstdcxx"]
        .into_iter()
        .find(|l| out.join(format!("circlerange_oracle.{l}.txt.gz")).is_file());
    let Some(lib) = lib else {
        eprintln!("SKIPPED: regen.sh wrote a table for a C++ library with no checked-in table");
        return;
    };

    // 1. The base table equals the checked-in one.
    let fresh =
        gunzip(&std::fs::read(out.join(format!("circlerange_oracle.{lib}.txt.gz"))).unwrap());
    let checked_in = gunzip(
        &std::fs::read(manifest.join(format!("tests/data/circlerange_oracle.{lib}.txt.gz")))
            .unwrap(),
    );
    assert_eq!(
        fresh.lines().count(),
        checked_in.lines().count(),
        "line counts differ"
    );
    for (i, (f, c)) in fresh.lines().zip(checked_in.lines()).enumerate() {
        assert_eq!(
            f,
            bare(c),
            "line {} of the {lib} table differs from a fresh generation",
            i + 1
        );
    }

    // 2. The extended case set agrees with Basilisk.
    let extended = gunzip(
        &std::fs::read(out.join(format!("circlerange_oracle_extended.{lib}.txt.gz"))).unwrap(),
    );
    let mut causes = BTreeMap::new();
    let mut bad = Vec::new();
    let mut rows = 0usize;
    for (n, line) in extended.lines().enumerate() {
        rows += 1;
        let row = split(line);
        let ours = compute(&row);
        if ours == row.results {
            continue;
        }
        match (lib, recognise(&row, &second_inputs(&row))) {
            ("libcxx", Some(cause)) => *causes.entry(cause).or_insert(0usize) += 1,
            _ => bad.push(format!("line {}: {line}\n  basilisk: {ours}", n + 1)),
        }
    }
    for b in bad.iter().take(20) {
        eprintln!("{b}");
    }
    eprintln!("extended {lib}: {rows} rows, host differences {causes:?}");
    assert!(
        bad.is_empty(),
        "{} of {rows} extended rows differ from Ghidra",
        bad.len()
    );
    let _ = std::fs::remove_dir_all(&out);
}
