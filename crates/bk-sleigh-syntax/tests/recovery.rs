//! Error recovery and limits: one run reports many errors, each at the
//! right file and line, without cascades; absurd input ends in diagnostics,
//! never in a panic, a stack overflow or a hang (ADR-009).

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

use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use bk_sleigh_syntax::ast::Item;
use bk_sleigh_syntax::{
    Defines, MAX_DEPTH, MAX_ERRORS, MemoryLoader, Parsed, parse_file, parse_semantic_body,
    parse_str,
};

fn parse(files: &[(&str, &str)]) -> Parsed {
    let mut loader = MemoryLoader::new();
    for (name, text) in files {
        loader.add(*name, *text);
    }
    parse_file(Path::new(files[0].0), &Defines::new(), &mut loader)
}

/// (file, line, message) of each diagnostic.
fn errors(parsed: &Parsed) -> Vec<(String, u32, String)> {
    parsed
        .diagnostics
        .iter()
        .map(|d| {
            let loc = parsed.sources.locate(d.span.start).unwrap();
            let file = parsed.sources.file(loc.file).unwrap().name().to_owned();
            (file, loc.line, d.message.clone())
        })
        .collect()
}

fn lines(parsed: &Parsed) -> Vec<(String, u32)> {
    errors(parsed).into_iter().map(|(f, l, _)| (f, l)).collect()
}

fn at(file: &str, line: u32) -> (String, u32) {
    (file.to_owned(), line)
}

fn constructor_count(items: &[Item]) -> usize {
    items
        .iter()
        .map(|i| match i {
            Item::Constructor(_) => 1,
            Item::With(w) => constructor_count(&w.items),
            _ => 0,
        })
        .sum()
}

#[test]
fn several_errors_across_includes_each_at_its_line() {
    let parsed = parse(&[
        (
            "a.slaspec",
            "define endian=big;\n\
             :ok1 is epsilon { x = 1; }\n\
             :bad1 is epsilon { x = ; }\n\
             @include \"b.sinc\"\n\
             define space ram type= size=4;\n\
             :ok2 is epsilon { y = 2; }\n",
        ),
        (
            "b.sinc",
            "# b\n\
             :ok3 is a=1 unimpl\n\
             :bad2 is a=1 { if x goto ; }\n\
             with t : { :bad3 is ( unimpl\n\
             :ok4 is epsilon unimpl }\n\
             :ok5 is epsilon { z = 3 }\n",
        ),
    ]);
    assert_eq!(
        lines(&parsed),
        [
            at("a.slaspec", 3),
            at("b.sinc", 3),
            // The unclosed `(` is reported at the token that cannot follow it.
            at("b.sinc", 5),
            at("b.sinc", 6),
            at("a.slaspec", 5),
        ],
        "{:#?}",
        parsed.rendered_diagnostics()
    );
    // Constructors with statement errors stay in the tree. `bad3` is skipped
    // to the end of its item, which is the `with` block's `}`, so `ok4`
    // goes with it (as in Ghidra's own `constructorlike: error '}'`).
    assert_eq!(constructor_count(&parsed.spec.items), 6);
}

#[test]
fn errors_stop_after_the_limit() {
    let mut text = String::from("define endian=big;\n");
    for i in 0..(MAX_ERRORS + 100) {
        writeln!(text, ":c{i} is epsilon {{ x = ; }}").unwrap();
    }
    let parsed = parse_str("a.slaspec", &text, &Defines::new());
    assert_eq!(parsed.diagnostics.len(), MAX_ERRORS + 1);
    assert_eq!(
        parsed.diagnostics.last().unwrap().message,
        "too many errors; giving up"
    );
    let found = lines(&parsed);
    assert_eq!(found[0], at("a.slaspec", 2));
    assert_eq!(
        found[MAX_ERRORS - 1],
        at("a.slaspec", MAX_ERRORS as u32 + 1)
    );
}

#[test]
fn nesting_is_bounded_everywhere() {
    let depth = 10_000;
    let open = "(".repeat(depth);
    let close = ")".repeat(depth);
    let cases = [
        format!(":a is epsilon {{ x = {open}1{close}; }}"),
        format!(":a is epsilon {{ x = {}1; }}", "-".repeat(depth)),
        format!(":a is epsilon {{ x = {}1; }}", "~ ".repeat(depth)),
        format!(":a is epsilon {{ x = {}r; }}", "*".repeat(depth)),
        format!(":a is epsilon {{ x = {}r; }}", "& ".repeat(depth)),
        format!(":a is {open}b{close} unimpl"),
        format!(":a is a = {open}1{close} unimpl"),
        format!(":a is a [ x = {open}1{close}; ] unimpl"),
        format!(":a is a = {}1 unimpl", "-".repeat(depth)),
        format!(
            "{}:a is b unimpl{}",
            "with : {".repeat(depth),
            "}".repeat(depth)
        ),
        format!(
            ":a is epsilon {{ x = f({}1{}); }}",
            "f(".repeat(depth),
            ")".repeat(depth)
        ),
    ];
    for case in cases {
        let started = Instant::now();
        let parsed = parse_str(
            "a.slaspec",
            &format!("define endian=big;\n{case}\n"),
            &Defines::new(),
        );
        let found = errors(&parsed);
        assert!(
            found
                .iter()
                .any(|e| e.2 == format!("nesting deeper than {MAX_DEPTH} levels")),
            "{}: {found:?}",
            case.get(..40).unwrap_or(&case)
        );
        assert!(
            found.len() < 10,
            "{}: {} errors",
            case.get(..40).unwrap_or(&case),
            found.len()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    // Just under the limit is fine.
    let ok = format!(
        "define endian=big;\n:a is epsilon {{ x = {}1{}; }}\n",
        "(".repeat(MAX_DEPTH as usize - 2),
        ")".repeat(MAX_DEPTH as usize - 2)
    );
    let parsed = parse_str("a.slaspec", &ok, &Defines::new());
    assert!(parsed.diagnostics.is_empty(), "{:?}", errors(&parsed));
}

#[test]
fn unbalanced_and_unterminated_input() {
    let cases: [(&str, &[(u32, &str)]); 7] = [
        (
            "define endian=big;\n:a is epsilon { x = 1;\n",
            &[(2, "this `{` is never closed")],
        ),
        (
            "define endian=big;\n}\n:a is epsilon unimpl\n",
            &[(2, "unexpected `}`")],
        ),
        (
            "define endian=big;\nwith t : {\n:a is epsilon unimpl\n",
            &[(3, "expected `}`, found end of input")],
        ),
        (
            "define endian=big;\n:a is epsilon { x = \"abc; }\n",
            // The string runs to the end of the input (Java's strings may
            // span lines), taking the rest of the body with it.
            &[
                (2, "unterminated string"),
                (2, "expected an expression, found end of input"),
                (2, "this `{` is never closed"),
            ],
        ),
        (
            "define endian=big;\n:a is epsilon { x = 1; // c\n }\n",
            &[(
                2,
                "`//` comments are not supported; comments start with `#`",
            )],
        ),
        (
            ":a is epsilon unimpl\n",
            &[(
                1,
                "missing `define endian = big;` or `define endian = little;` (it must be the first statement)",
            )],
        ),
        (
            "define alignment=1;\ndefine endian=big;\n",
            &[(2, "`define endian` must be the first statement")],
        ),
    ];
    for (source, expected) in cases {
        let parsed = parse_str("a.slaspec", source, &Defines::new());
        let found: Vec<(u32, String)> = errors(&parsed)
            .into_iter()
            .map(|(_, l, m)| (l, m))
            .collect();
        let expected: Vec<(u32, String)> = expected
            .iter()
            .map(|(l, m)| (*l, (*m).to_owned()))
            .collect();
        assert_eq!(found, expected, "{source:?}");
    }
}

#[test]
fn empty_statements_are_errors_and_parsing_continues() {
    let parsed = parse_semantic_body("x = 1; ; y = 2;");
    assert_eq!(parsed.diagnostics.len(), 1);
    assert_eq!(parsed.body.statements.len(), 2);
}

#[test]
fn garbage_ends_in_diagnostics_quickly() {
    let inputs = [
        "\0\u{1}\u{2}@@@ $$$ \"".repeat(2000),
        "{".repeat(100_000),
        "}".repeat(100_000),
        ":".repeat(100_000),
        "define ".repeat(50_000),
        "with : { ".repeat(50_000),
        ":a is ".repeat(50_000),
        "[[[[".repeat(50_000),
    ];
    for input in inputs {
        let started = Instant::now();
        let parsed = parse_str("a.slaspec", &input, &Defines::new());
        assert!(!parsed.diagnostics.is_empty());
        assert!(parsed.diagnostics.len() <= MAX_ERRORS + 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}: {:?}",
            input.get(..10),
            started.elapsed()
        );
    }
}
