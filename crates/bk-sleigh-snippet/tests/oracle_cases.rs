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
use common::oracle::{Base, Outcome, Record, escape, run_basilisk, run_oracle, unescape};

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

#[test]
fn hand_written_cases_match_ghidra() {
    let sla = common::fixture::sla();
    let compiler = SnippetCompiler::new(&sla, &Options::default());
    let bodies = cases();
    let recs = records(&bodies);
    let actual = run_basilisk(&compiler, BASE, &recs);
    insta::assert_snapshot!("fixture_cases", render(&bodies, &actual));

    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    let Some(tool) = common::snippetdump(&reference) else {
        return;
    };
    let root = common::fixture::write_root(
        &std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("snippet-fixture"),
    );
    let expected = run_oracle(&tool, &root, common::fixture::LANGUAGE_ID, &recs);
    let mut differences = Vec::new();
    for ((body, exp), act) in bodies.iter().zip(&expected).zip(&actual) {
        if exp != act {
            differences.push(format!(
                "{}\n  ghidra:   {exp:?}\n  basilisk: {act:?}",
                escape(body)
            ));
        }
    }
    eprintln!(
        "cases: {} compared with snippetdump, {} differ",
        bodies.len(),
        differences.len()
    );
    for d in &differences {
        eprintln!("{d}");
    }
    assert_eq!(differences, Vec::<String>::new());
}
