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
//! Replays the context oracle (spec 6.2): Ghidra's `ContextInternal` over
//! 2,000 generated cases (`tests/oracle/context.cc`, seed 1). Every row
//! must be equal; the table is identical on both reference builds.

mod common;

use common::context_gen::ContextGen;
use common::oracle::{arch_from_header, read_table, split_row};
use common::scope_gen::Rng;

#[test]
fn context_table_replays() {
    let text = read_table("context.txt.gz");
    assert_eq!(
        format!("{:016x}", common::oracle::fnv64(text.as_bytes())),
        "c982c1416148eb7b",
        "table changed"
    );
    let rows: Vec<(i64, &str, &str)> = text.lines().map(split_row).collect();
    let mut header: Vec<_> = rows.iter().copied().filter(|r| r.0 < 0).collect();
    // The context generator has no type rows; reuse the scope table's.
    let scope_text = read_table("scope.txt.gz");
    header.extend(
        scope_text
            .lines()
            .map(split_row)
            .filter(|r| r.0 < 0 && (r.1 == "C")),
    );
    let h = header.iter().find(|r| r.1 == "H").unwrap().2;
    let fields: Vec<&str> = h.split(' ').collect();
    let seed: u64 = fields[2].parse().unwrap();
    let cases: i64 = fields[3].parse().unwrap();
    let arch = arch_from_header(&header);
    let mut expected = vec![String::new(); cases as usize];
    for line in text.lines() {
        let (case, _, _) = split_row(line);
        if case >= 0 {
            expected[case as usize].push_str(line);
            expected[case as usize].push('\n');
        }
    }
    let mut driver = ContextGen {
        spaces: &arch.env.spaces,
        ram: arch.ram,
        reg: arch.register.unwrap(),
        rng: Rng(seed | 1),
        out: String::new(),
        kase: 0,
    };
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
        "{} mismatching cases:\n{}",
        bad.len(),
        bad.join("\n")
    );
}
