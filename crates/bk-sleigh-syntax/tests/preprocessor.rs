//! The preprocessor end to end: each directive, nested and skipped
//! conditionals, definitions from outside, and every error it reports, each
//! at the right file and line (`SleighPreprocessor.java`,
//! `ConditionalHelper.java`).

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

use std::path::Path;

use bk_sleigh_syntax::{Defines, MemoryLoader, Preprocessed, preprocess};

/// Preprocesses the first of `files` with the others available to include.
fn run_with(files: &[(&str, &str)], defines: &Defines) -> Preprocessed {
    let mut loader = MemoryLoader::new();
    for (name, text) in files {
        loader.add(*name, *text);
    }
    preprocess(Path::new(files[0].0), defines, &mut loader)
}

fn run(files: &[(&str, &str)]) -> Preprocessed {
    run_with(files, &Defines::new())
}

/// The non-empty output lines, without expansion marks.
fn output(p: &Preprocessed) -> Vec<String> {
    p.sources
        .text()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.replace('\u{8}', ""))
        .collect()
}

/// The diagnostics as (file name, line, message).
fn errors(p: &Preprocessed) -> Vec<(String, u32, String)> {
    p.diagnostics
        .iter()
        .map(|d| {
            let loc = p.sources.locate(d.span.start).unwrap();
            let file = p.sources.file(loc.file).unwrap().name().to_owned();
            (file, loc.line, d.message.clone())
        })
        .collect()
}

fn err(file: &str, line: u32, message: &str) -> (String, u32, String) {
    (file.to_owned(), line, message.to_owned())
}

#[test]
fn define_forms_and_expansion() {
    let p = run(&[(
        "a.slaspec",
        "@define Q \"two words\"\n\
         @define B bare-value.1\n\
         @define E\n\
         @define H \"a#b\"\n\
         @define R \"$(Q)\"\n\
         x $(Q) y $(B)$(E)z $(R)\n",
    )]);
    assert!(p.diagnostics.is_empty(), "{:?}", errors(&p));
    assert_eq!(p.defines.get("Q"), Some("two words"));
    assert_eq!(p.defines.get("B"), Some("bare-value.1"));
    assert_eq!(p.defines.get("E"), Some(""));
    // Everything from `#` on is a comment, even inside quotes.
    assert_eq!(p.defines.get("H"), Some("\"a"));
    // Values are not expanded, at definition or at use.
    assert_eq!(p.defines.get("R"), Some("$(Q)"));
    assert_eq!(output(&p), ["x two words y bare-value.1z $(Q)"]);
}

#[test]
fn undef_and_ifdef_ifndef() {
    let p = run(&[(
        "a.slaspec",
        "@define X\n\
         @ifdef X\nyes1\n@endif\n\
         @ifndef X\nno1\n@endif\n\
         @undef X\n\
         @ifdef X\nno2\n@else\nyes2\n@endif\n\
         @ifndef X\nyes3\n@endif\n",
    )]);
    assert!(p.diagnostics.is_empty(), "{:?}", errors(&p));
    assert_eq!(output(&p), ["yes1", "yes2", "yes3"]);
}

#[test]
fn if_elif_else_chains_take_the_first_true_branch() {
    let source =
        "@if V == \"a\"\nA\n@elif V == \"b\"\nB\n@elif defined(V)\nOTHER\n@else\nNONE\n@endif\n";
    for (value, expected) in [
        (Some("a"), "A"),
        (Some("b"), "B"),
        (Some("c"), "OTHER"),
        (None, "NONE"),
    ] {
        let mut defines = Defines::new();
        if let Some(value) = value {
            defines.set("V", value);
        }
        let p = run_with(&[("a.slaspec", source)], &defines);
        assert_eq!(output(&p), [expected], "V = {value:?}");
        // With V undefined, the comparisons report it (Ghidra does too).
        let undefined = errors(&p)
            .iter()
            .filter(|e| e.2 == "Macro: V is undefined")
            .count();
        assert_eq!(undefined, if value.is_none() { 2 } else { 0 });
    }
}

#[test]
fn nested_conditionals_and_skipped_regions() {
    let p = run(&[
        (
            "a.slaspec",
            "@define OUTER\n\
             @ifdef OUTER\n\
             @ifdef INNER\nno1\n@else\nyes1\n@endif\n\
             @endif\n\
             @ifdef MISSING\n\
             @define SET_IN_SKIP\n\
             @undef OUTER\n\
             @include \"does-not-exist.sinc\"\n\
             @ifdef OUTER\nno2\n@else\nno3\n@endif\n\
             @if UNDEFINED_IN_SKIP == \"x\"\n@endif\n\
             no4\n\
             @endif\n\
             @ifdef OUTER\nyes2\n@endif\n\
             @if defined(OUTER)\nyes3\n@elif NOT_EVALUATED == \"x\"\nno5\n@endif\n",
        ),
        ("does-not-exist.sinc", "@error"),
    ]);
    assert_eq!(output(&p), ["yes1", "yes2", "yes3"]);
    assert!(!p.defines.is_defined("SET_IN_SKIP"));
    assert!(p.defines.is_defined("OUTER"));
    // `@if` expressions are evaluated even in a skipped region; `@elif`
    // after a taken branch is not.
    assert_eq!(
        errors(&p),
        [err(
            "a.slaspec",
            18,
            "Macro: UNDEFINED_IN_SKIP is undefined"
        )]
    );
    // The skipped `@include` was never read.
    assert_eq!(p.sources.inclusion_count(), 1);
}

#[test]
fn boolean_expressions_in_if() {
    let p = run_with(
        &[(
            "a.slaspec",
            "@if defined(A) && (B == \"1\" || B == \"2\")\nyes1\n@endif\n\
             @if !(defined(C))\nyes2\n@endif\n\
             @if defined(A) ^^ defined(B)\nno1\n@endif\n\
             @if A != B\nyes3\n@endif\n",
        )],
        &Defines::new().with("A", "x").with("B", "2"),
    );
    assert!(p.diagnostics.is_empty(), "{:?}", errors(&p));
    assert_eq!(output(&p), ["yes1", "yes2", "yes3"]);
}

#[test]
fn directives_only_in_column_one_and_comment_lines_are_blank() {
    let p = run(&[(
        "a.slaspec",
        " @define X 1\n# a comment\n  # indented comment\nkeep # trailing\n",
    )]);
    assert!(p.diagnostics.is_empty());
    assert!(!p.defines.is_defined("X"));
    // The indented directive is ordinary text; the comment lines are blank.
    assert_eq!(output(&p), [" @define X 1", "keep # trailing"]);
    assert_eq!(p.sources.line_count(), 4);
}

#[test]
fn includes_definitions_cross_files_but_conditionals_do_not() {
    let p = run(&[
        (
            "dir/a.slaspec",
            "@define F \"sub\"\n\
             @include \"$(F)/b.sinc\"\n\
             after $(FROM_B)\n\
             @endif\n",
        ),
        (
            "dir/sub/b.sinc",
            "@define FROM_B \"b\"\n\
             @ifdef F\ninside\n",
        ),
    ]);
    assert_eq!(output(&p), ["inside", "after b"]);
    // b.sinc's open `@ifdef` closed silently at its end, so a.slaspec's
    // `@endif` has nothing to close.
    assert_eq!(errors(&p), [err("a.slaspec", 4, "not in IF* directive")]);
    assert_eq!(p.sources.inclusion_count(), 2);
}

#[test]
fn definitions_from_outside_name_module_directories() {
    let p = run_with(
        &[
            ("lang/a.slaspec", "@include \"$(MIPS)/m.sinc\"\n"),
            ("/proc/MIPS/m.sinc", "from mips\n"),
        ],
        &Defines::new().with("MIPS", "/proc/MIPS"),
    );
    assert!(p.diagnostics.is_empty(), "{:?}", errors(&p));
    assert_eq!(output(&p), ["from mips"]);
}

#[test]
fn every_conditional_misuse_is_reported_at_its_line() {
    let p = run(&[(
        "a.slaspec",
        "@else\n\
         @elif defined(X)\n\
         @endif\n\
         @ifdef X\n@else\n@else\n@elif defined(Y)\n@endif\n\
         @pragma once\n\
         @define\n\
         @if defined(X\n@endif\n\
         @if !defined(X)\n@endif\n",
    )]);
    assert_eq!(
        errors(&p),
        [
            err("a.slaspec", 1, "else outside of IF* directive"),
            err("a.slaspec", 2, "elif outside of IF* directive"),
            err("a.slaspec", 3, "not in IF* directive"),
            err("a.slaspec", 6, "duplicate else directive"),
            err("a.slaspec", 7, "already saw else directive"),
            err("a.slaspec", 9, "unrecognized preprocessor directive"),
            err("a.slaspec", 10, "unrecognized preprocessor directive"),
            err(
                "a.slaspec",
                11,
                "malformed preprocessor expression: expected ')' at column 10 of the expression"
            ),
            err(
                "a.slaspec",
                13,
                "malformed preprocessor expression: expected '(' after '!' at column 2 of the expression"
            ),
        ]
    );
}

#[test]
fn unknown_variables_are_reported_and_expand_to_nothing() {
    let p = run(&[(
        "a.slaspec",
        "ok\nx $(NOPE) y $(ALSO)\n@include \"$(MISSING).sinc\"\n",
    )]);
    assert_eq!(output(&p), ["ok", "x  y "]);
    let found = errors(&p);
    assert_eq!(
        found,
        [
            err("a.slaspec", 2, "unknown variable: NOPE"),
            err("a.slaspec", 2, "unknown variable: ALSO"),
            err("a.slaspec", 3, "unknown variable: MISSING"),
        ]
    );
    // The reference itself is located at its `$`.
    let loc = p.sources.locate(p.diagnostics[1].span.start).unwrap();
    assert_eq!((loc.line, loc.column), (2, 13));
}

#[test]
fn missing_files_and_include_cycles() {
    let p = run(&[
        (
            "a.slaspec",
            "@include \"missing.sinc\"\n@include \"b.sinc\"\nend\n",
        ),
        ("b.sinc", "in b\n@include \"c.sinc\"\n"),
        ("c.sinc", "in c\n@include \"b.sinc\"\n"),
    ]);
    assert_eq!(output(&p), ["in b", "in c", "end"]);
    assert_eq!(
        errors(&p),
        [
            err(
                "a.slaspec",
                1,
                "included file \"missing.sinc\": file not found"
            ),
            err("c.sinc", 2, "included file \"b.sinc\": includes itself"),
        ]
    );
    let missing_root = run(&[("x.slaspec", "")]);
    let mut loader = MemoryLoader::new();
    let p = preprocess(Path::new("nope.slaspec"), &Defines::new(), &mut loader);
    assert!(missing_root.diagnostics.is_empty());
    assert_eq!(p.diagnostics.len(), 1);
    assert_eq!(
        p.diagnostics[0].message,
        "cannot read \"nope.slaspec\": file not found"
    );
}

#[test]
fn include_depth_is_bounded() {
    let names: Vec<String> = (0..80).map(|i| format!("f{i}.sinc")).collect();
    let texts: Vec<String> = (0..80)
        .map(|i| format!("line {i}\n@include \"f{}.sinc\"\n", i + 1))
        .collect();
    let files: Vec<(&str, &str)> = names
        .iter()
        .zip(&texts)
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    let p = run(&files);
    let found = errors(&p);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0],
        err(
            "f63.sinc",
            2,
            "included file \"f64.sinc\": includes nested deeper than 64"
        )
    );
    assert_eq!(p.sources.inclusion_count(), 64);
}

#[test]
fn inclusion_count_is_bounded() {
    // Each level includes the next twice: 2^15 inclusions if unbounded.
    let names: Vec<String> = (0..16).map(|i| format!("f{i}.sinc")).collect();
    let texts: Vec<String> = (0..16)
        .map(|i| {
            if i == 15 {
                "leaf\n".to_owned()
            } else {
                format!("@include \"f{0}.sinc\"\n@include \"f{0}.sinc\"\n", i + 1)
            }
        })
        .collect();
    let files: Vec<(&str, &str)> = names
        .iter()
        .zip(&texts)
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    let p = run(&files);
    let found = errors(&p);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2, "more than 10000 files included");
    assert_eq!(p.sources.inclusion_count(), 10_000);
}

#[test]
fn line_kinds_and_origins_through_includes() {
    let p = run(&[
        (
            "a.slaspec",
            "one\n@include \"b.sinc\"\n# note\n@ifdef X\nskip\n@endif\ntwo\n",
        ),
        ("b.sinc", "b1\nb2\n"),
    ]);
    // Output lines: one, b1, b2, (comment), (directive), (skipped), (directive), two.
    let text = p.sources.text();
    let starts: Vec<u32> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(i, _)| i as u32 + 1))
        .take(p.sources.line_count())
        .collect();
    let origin: Vec<(String, u32)> = starts
        .iter()
        .map(|&s| {
            let loc = p.sources.locate(s).unwrap();
            (
                p.sources.file(loc.file).unwrap().name().to_owned(),
                loc.line,
            )
        })
        .collect();
    let expected = [
        ("a.slaspec", 1),
        ("b.sinc", 1),
        ("b.sinc", 2),
        ("a.slaspec", 3),
        ("a.slaspec", 4),
        ("a.slaspec", 5),
        ("a.slaspec", 6),
        ("a.slaspec", 7),
    ];
    assert_eq!(origin, expected.map(|(f, l)| (f.to_owned(), l)).to_vec());
}
