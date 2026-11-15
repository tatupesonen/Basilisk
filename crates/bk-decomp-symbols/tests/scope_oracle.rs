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
//! Replays the scope oracle (spec 6.2): Ghidra's `ScopeInternal` and
//! `Database` over 2,000 generated cases (`tests/oracle/scope.cc`, seed 1,
//! data test `elseif.xml`). The generator's port draws the same random
//! numbers and drives Basilisk with the same operations; every row must be
//! equal.

mod common;

use common::oracle::{arch_from_header, read_table, split_row};
use common::scope_gen::Gen;

fn replay(table: &str) {
    let text = read_table(table);
    let rows: Vec<(i64, &str, &str)> = text.lines().map(split_row).collect();
    let header: Vec<_> = rows.iter().copied().filter(|r| r.0 < 0).collect();
    let h = header.iter().find(|r| r.1 == "H").unwrap().2;
    let fields: Vec<&str> = h.split(' ').collect();
    let seed: u64 = fields[2].parse().unwrap();
    let cases: i64 = fields[3].parse().unwrap();
    let mut arch = arch_from_header(&header);
    let mut expected: Vec<String> = vec![String::new(); cases as usize];
    for line in text.lines() {
        let (case, _, _) = split_row(line);
        if case >= 0 {
            let slot = &mut expected[case as usize];
            slot.push_str(line);
            slot.push('\n');
        }
    }
    let mut driver = Gen::new(&mut arch, seed);
    let mut bad = Vec::new();
    for case in 0..cases {
        driver.kase = case;
        driver.out.clear();
        driver.one_case();
        if driver.out != expected[case as usize] {
            let want: Vec<&str> = expected[case as usize].lines().collect();
            let got: Vec<&str> = driver.out.lines().collect();
            let at = want
                .iter()
                .zip(&got)
                .position(|(a, b)| a != b)
                .unwrap_or(want.len().min(got.len()));
            bad.push(format!(
                "case {case}, row {at}:\n  want: {}\n  got:  {}",
                want.get(at).unwrap_or(&"<end>"),
                got.get(at).unwrap_or(&"<end>")
            ));
            if bad.len() >= 8 {
                break;
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} mismatching cases (first shown):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn scope_table_libcxx_replays() {
    replay("scope.libcxx.txt.gz");
}
