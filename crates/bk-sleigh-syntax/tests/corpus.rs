//! The corpus test: every `.slaspec` Ghidra ships must preprocess and parse
//! with no diagnostics, and spans must resolve to the right place in the
//! original files, through includes and `$(NAME)` expansions.
//!
//! The specifications are read in place from the Ghidra tree (ADR-002); the
//! test skips when the tree is absent.

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

use std::collections::BTreeSet;
use std::time::Instant;

use bk_sleigh_syntax::ast::{ConstructorBody, Item};
use bk_sleigh_syntax::{FsLoader, Parsed, Span, parse_file};

#[derive(Default)]
struct Totals {
    specs: usize,
    inclusions: usize,
    lines: usize,
    bytes: usize,
    tokens: u64,
    constructors: usize,
    unimpl: usize,
    macros: usize,
    with_blocks: usize,
    definitions: usize,
    statements: usize,
    exprs: usize,
    equations: usize,
    spans_checked: usize,
    spans_in_expansions: usize,
    spans_after_expansions: usize,
}

/// Checks that `span` starts, in its original file, with `expected`.
fn check_span(parsed: &Parsed, span: Span, expected: &str, totals: &mut Totals) {
    let loc = parsed.sources.locate(span.start).expect("span resolves");
    let file = parsed.sources.file(loc.file).expect("file exists");
    assert!(
        loc.line >= 1 && loc.line <= file.line_count(),
        "line in range"
    );
    if loc.in_expansion {
        totals.spans_in_expansions += 1;
        return;
    }
    let line = file.line(loc.line).unwrap();
    let rest: String = line.chars().skip(loc.column as usize - 1).collect();
    // A token after a `$(NAME)` reference on the same line is mapped back
    // past the reference, so the original line has it at that column.
    if line.contains("$(") {
        totals.spans_after_expansions += 1;
    }
    assert!(
        rest.starts_with(expected),
        "{}:{}:{}: expected {expected:?}, found {rest:?}",
        file.path().display(),
        loc.line,
        loc.column
    );
    totals.spans_checked += 1;
}

fn walk(parsed: &Parsed, items: &[Item], totals: &mut Totals) {
    for item in items {
        match item {
            Item::Definition(_) => totals.definitions += 1,
            Item::Macro(m) => {
                totals.macros += 1;
                totals.statements += m.body.statements.len();
                check_span(parsed, m.span, "macro", totals);
                check_span(
                    parsed,
                    m.name.span,
                    parsed.names.resolve(m.name.name),
                    totals,
                );
            }
            Item::With(w) => {
                totals.with_blocks += 1;
                check_span(parsed, w.span, "with", totals);
                walk(parsed, &w.items, totals);
            }
            Item::Constructor(c) => {
                totals.constructors += 1;
                let start = match c.table {
                    Some(table) => parsed.names.resolve(table.name),
                    None => ":",
                };
                check_span(parsed, c.span, start, totals);
                check_span(parsed, c.colon, ":", totals);
                match &c.body {
                    ConstructorBody::Unimpl(span) => {
                        totals.unimpl += 1;
                        check_span(parsed, *span, "unimpl", totals);
                    }
                    ConstructorBody::Semantic(body) => {
                        totals.statements += body.statements.len();
                        check_span(parsed, body.span, "{", totals);
                    }
                }
            }
        }
    }
}

#[test]
fn every_shipped_slaspec_parses_cleanly() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let specs = common::slaspec_files(&ghidra);
    assert_eq!(specs.len(), 150, "Ghidra ships 150 .slaspec files");
    let defines = common::build_defines();

    let mut totals = Totals::default();
    let mut unique_files = BTreeSet::new();
    let mut failures = Vec::new();
    let started = Instant::now();
    for path in &specs {
        let parsed = parse_file(path, &defines, &mut FsLoader);
        totals.specs += 1;
        totals.inclusions += parsed.sources.inclusion_count();
        totals.lines += parsed.sources.line_count();
        totals.bytes += parsed.sources.text().len();
        totals.tokens += parsed.token_count;
        totals.exprs += parsed.spec.nodes.expr_count();
        totals.equations += parsed.spec.nodes.equation_count();
        for file in parsed.sources.files() {
            unique_files.insert(file.path().to_path_buf());
        }
        if !parsed.diagnostics.is_empty() {
            let shown: Vec<String> = parsed.rendered_diagnostics().into_iter().take(5).collect();
            failures.push(format!(
                "{}: {} diagnostics\n  {}",
                path.display(),
                parsed.diagnostics.len(),
                shown.join("\n  ")
            ));
            continue;
        }
        assert!(parsed.spec.endian.is_some(), "{}", path.display());
        walk(&parsed, &parsed.spec.items, &mut totals);
    }
    let elapsed = started.elapsed();

    eprintln!(
        "corpus: {} specs, {} unique source files, {} inclusions, {} preprocessed lines, \
         {:.1} MB preprocessed, {} tokens",
        totals.specs,
        unique_files.len(),
        totals.inclusions,
        totals.lines,
        totals.bytes as f64 / 1e6,
        totals.tokens
    );
    eprintln!(
        "corpus: {} constructors ({} unimpl), {} macros, {} with blocks, {} definitions, \
         {} statements, {} expression nodes, {} pattern equation nodes",
        totals.constructors,
        totals.unimpl,
        totals.macros,
        totals.with_blocks,
        totals.definitions,
        totals.statements,
        totals.exprs,
        totals.equations
    );
    eprintln!(
        "corpus: {} spans checked against the original files ({} of them on a line with a \
         $(NAME) reference; {} more lie inside an expanded value); {:.2} s in this build profile",
        totals.spans_checked,
        totals.spans_after_expansions,
        totals.spans_in_expansions,
        elapsed.as_secs_f64()
    );
    assert!(
        failures.is_empty(),
        "{} of {} specs have diagnostics:\n{}",
        failures.len(),
        specs.len(),
        failures.join("\n")
    );
    assert!(
        totals.constructors > 100_000,
        "the corpus holds well over 100,000 constructors"
    );
    assert!(totals.spans_checked > 100_000);
}
