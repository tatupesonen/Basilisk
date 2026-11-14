//! Hand-written snippets for every statement and expression form, every
//! error and the lexer's quirks (`tests/cases/fixture.txt`), compiled
//! against the fixture language. The results are an `insta` snapshot (runs
//! everywhere) and, when the reference build has `snippetdump`, must equal
//! Ghidra's: same template XML, same base after, same first ignored error,
//! or the same failure and message.

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

use std::fmt::Write as _;

use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler};
use bk_testkit::tools::snippetdump::{escape, unescape};
use common::oracle::{Base, Outcome, Record, run_basilisk, run_oracle};

const BASE: u32 = 0x1_0000;

fn cases() -> Vec<String> {
    include_str!("cases/fixture.txt")
        .lines()
        .filter(|l| !l.starts_with("//"))
        .map(unescape)
        .collect()
}

fn records(bodies: &[String]) -> Vec<Record> {
    let params = vec![
        Parameter::new("in1", 0),
        Parameter::new("in2", 1),
        Parameter::new("out1", 2),
    ];
    bodies
        .iter()
        .enumerate()
        .map(|(i, body)| Record {
            source: format!("case{i}"),
            base: Base::Start(BASE),
            body: body.clone(),
            params: params.clone(),
        })
        .collect()
}

fn render(bodies: &[String], outcomes: &[Outcome]) -> String {
    let mut out = String::new();
    for (body, outcome) in bodies.iter().zip(outcomes) {
        writeln!(out, "=== {}", escape(body)).unwrap();
        match outcome {
            Outcome::Ok {
                next,
                first_error,
                xml,
                ..
            } => {
                writeln!(out, "ok, next {next:#x}").unwrap();
                if let Some(e) = first_error {
                    writeln!(out, "ignored error: {e}").unwrap();
                }
                out.push_str(xml);
            }
            Outcome::Rejected { message, .. } => writeln!(out, "rejected: {message}").unwrap(),
            Outcome::Exception { message, .. } => writeln!(out, "exception: {message}").unwrap(),
        }
    }
    out
}

/// Whether `body` has a number token starting with `0` (not `0x`) that
/// holds an 8 or a 9.
fn has_bad_octal(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let starts = bytes[i] == b'0'
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'));
        if starts {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if bytes[i + 1..j].iter().any(|&c| c == b'8' || c == b'9') {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

#[test]
fn hand_written_cases_match_ghidra() {
    let sla = common::fixture::sla();
    let compiler = SnippetCompiler::new(&sla, &Options::default());
    let bodies = cases();
    let recs = records(&bodies);
    let actual = run_basilisk(&compiler, BASE, &recs);
    insta::assert_snapshot!("fixture_cases", render(&bodies, &actual));

    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Snippetdump) else {
        return;
    };
    let root = common::fixture::write_root(
        &std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("snippet-fixture"),
    );
    let expected = run_oracle(&reference, &root, common::fixture::LANGUAGE_ID, &recs);
    // ADR-021: Basilisk follows the x86-64 Linux reference (libstdc++). A
    // reference built on macOS reads numbers with libc++, whose `num_get`
    // fails on an octal literal holding an 8 or a 9 (stage 2 collects every
    // digit, then `strtoull` stops early and the stream sets failbit), so
    // Ghidra's lexer returns BADINTEGER there (`pcodeparse.y`,
    // `PcodeLexer::getNextToken`, `s1 >> curnum`). Such cases are counted,
    // not compared, on that host only.
    let libcxx = std::fs::read_to_string(reference.stamp_file())
        .is_ok_and(|stamp| stamp.lines().any(|l| l.starts_with("host: Darwin")));
    let mut tolerated = 0;
    let mut differences = Vec::new();
    for ((body, exp), act) in bodies.iter().zip(&expected).zip(&actual) {
        if exp != act
            && libcxx
            && has_bad_octal(body)
            && matches!(exp, Outcome::Ok { first_error: Some(m), .. }
                if m == "Parsed integer is too big (overflow)")
        {
            tolerated += 1;
            continue;
        }
        if exp != act {
            differences.push(format!(
                "{}\n  ghidra:   {exp:?}\n  basilisk: {act:?}",
                escape(body)
            ));
        }
    }
    eprintln!(
        "cases: {} compared with snippetdump, {} differ, {} host-dependent octal cases \
         tolerated (libc++ reference)",
        bodies.len(),
        differences.len(),
        tolerated
    );
    for d in &differences {
        eprintln!("{d}");
    }
    assert_eq!(differences, Vec::<String>::new());
}
