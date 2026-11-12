//! Spans resolve to the right file, line and column through `@include` and
//! `$(NAME)` expansion (acceptance item 3 of the spec), and the source map's
//! queries (`locate`, `include_chain`, `source_range`, `render`) agree.

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

use bk_sleigh_syntax::ast::{ConstructorBody, Expr, Item, Statement};
use bk_sleigh_syntax::{Defines, Location, MemoryLoader, Parsed, Span, parse_file};

fn parse(files: &[(&str, &str)]) -> Parsed {
    let mut loader = MemoryLoader::new();
    for (name, text) in files {
        loader.add(*name, *text);
    }
    parse_file(Path::new(files[0].0), &Defines::new(), &mut loader)
}

/// (file name, line, column, in expansion) of a span's start.
fn at(parsed: &Parsed, span: Span) -> (String, u32, u32, bool) {
    let loc: Location = parsed.sources.locate(span.start).unwrap();
    let name = parsed.sources.file(loc.file).unwrap().name().to_owned();
    (name, loc.line, loc.column, loc.in_expansion)
}

fn place(file: &str, line: u32, column: u32, expansion: bool) -> (String, u32, u32, bool) {
    (file.to_owned(), line, column, expansion)
}

/// The identifiers of the first constructor's body, in source order, with
/// their spans (enough to follow tokens through the preprocessor).
fn body_idents(parsed: &Parsed, index: usize) -> Vec<(String, Span)> {
    let constructors: Vec<_> = parsed
        .spec
        .items
        .iter()
        .filter_map(|i| match i {
            Item::Constructor(c) => Some(c),
            _ => None,
        })
        .collect();
    let ConstructorBody::Semantic(body) = &constructors[index].body else {
        panic!("no body");
    };
    let mut out = Vec::new();
    for statement in &body.statements {
        if let Statement::Assign { value, .. } = statement {
            collect(parsed, *value, &mut out);
        }
    }
    out.sort_by_key(|(_, s)| s.start);
    out
}

fn collect(parsed: &Parsed, id: bk_sleigh_syntax::ast::ExprId, out: &mut Vec<(String, Span)>) {
    match &parsed.spec.nodes[id] {
        Expr::Ident(i) => out.push((parsed.names.resolve(i.name).to_owned(), i.span)),
        Expr::Binary { lhs, rhs, .. } => {
            collect(parsed, *lhs, out);
            collect(parsed, *rhs, out);
        }
        Expr::Paren { inner, .. } => collect(parsed, *inner, out),
        _ => {}
    }
}

#[test]
fn spans_in_included_files_name_the_file_and_its_include_chain() {
    let parsed = parse(&[
        (
            "lang/a.slaspec",
            "define endian=big;\n\n@include \"sub/b.sinc\"\n:A is epsilon { x = y; }\n",
        ),
        (
            "lang/sub/b.sinc",
            "# b\n  :B is epsilon {\n    x = y;\n  }\n@include \"c.sinc\"\n",
        ),
        ("lang/sub/c.sinc", "\t:C is epsilon { z = w; }\n"),
    ]);
    assert!(
        parsed.diagnostics.is_empty(),
        "{:?}",
        parsed.rendered_diagnostics()
    );
    let spans: Vec<Span> = parsed.spec.items.iter().map(Item::span).collect();
    assert_eq!(at(&parsed, spans[0]), place("b.sinc", 2, 3, false));
    assert_eq!(at(&parsed, spans[1]), place("c.sinc", 1, 2, false));
    assert_eq!(at(&parsed, spans[2]), place("a.slaspec", 4, 1, false));
    // Body tokens of B, on its third line.
    let idents = body_idents(&parsed, 0);
    assert_eq!(at(&parsed, idents[0].1), place("b.sinc", 3, 9, false));

    // The include chain of c.sinc: b.sinc line 5, then a.slaspec line 3.
    let loc = parsed.sources.locate(spans[1].start).unwrap();
    let chain: Vec<(String, u32)> = parsed
        .sources
        .include_chain(loc.include)
        .into_iter()
        .map(|(f, l)| (parsed.sources.file(f).unwrap().name().to_owned(), l))
        .collect();
    assert_eq!(
        chain,
        [("b.sinc".to_owned(), 5), ("a.slaspec".to_owned(), 3)]
    );
    let root = parsed.sources.locate(spans[2].start).unwrap();
    assert!(parsed.sources.include_chain(root.include).is_empty());
}

#[test]
fn a_file_included_twice_has_one_file_and_two_inclusions() {
    let parsed = parse(&[
        (
            "a.slaspec",
            "define endian=big;\n@include \"t.sinc\"\n@include \"t.sinc\"\n",
        ),
        ("t.sinc", ":T is epsilon unimpl\n"),
    ]);
    // The duplicate constructor is not a syntax error.
    assert!(parsed.diagnostics.is_empty());
    let first = parsed
        .sources
        .locate(parsed.spec.items[0].span().start)
        .unwrap();
    let second = parsed
        .sources
        .locate(parsed.spec.items[1].span().start)
        .unwrap();
    assert_eq!(first.file, second.file);
    assert_ne!(first.include, second.include);
    assert_eq!((first.line, second.line), (1, 1));
    assert_eq!(parsed.sources.include_chain(first.include)[0].1, 2);
    assert_eq!(parsed.sources.include_chain(second.include)[0].1, 3);
    assert_eq!(parsed.sources.files().len(), 2);
    assert_eq!(parsed.sources.inclusion_count(), 3);
}

#[test]
fn tokens_inside_and_after_an_expansion() {
    let source = "define endian=big;\n\
                  @define REG \"r1\"\n\
                  @define SUM \"a + bb\"\n\
                  :X is epsilon { x = $(REG) + r2; y = $(SUM) * c; }\n";
    let parsed = parse(&[("a.slaspec", source)]);
    assert!(
        parsed.diagnostics.is_empty(),
        "{:?}",
        parsed.rendered_diagnostics()
    );
    let idents = body_idents(&parsed, 0);
    let names: Vec<&str> = idents.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["r1", "r2", "a", "bb", "c"]);
    let line = source.lines().nth(3).unwrap();
    let col = |needle: &str| line.find(needle).unwrap() as u32 + 1;
    // Inside an expansion: the column of the `$`, flagged.
    assert_eq!(
        at(&parsed, idents[0].1),
        place("a.slaspec", 4, col("$(REG)"), true)
    );
    assert_eq!(
        at(&parsed, idents[2].1),
        place("a.slaspec", 4, col("$(SUM)"), true)
    );
    assert_eq!(
        at(&parsed, idents[3].1),
        place("a.slaspec", 4, col("$(SUM)"), true)
    );
    // After one: the original column.
    assert_eq!(
        at(&parsed, idents[1].1),
        place("a.slaspec", 4, col("r2"), false)
    );
    assert_eq!(
        at(&parsed, idents[4].1),
        place("a.slaspec", 4, col("c;"), false)
    );
    // `source_range` gives the original bytes, and nothing inside expansions.
    let (file, range) = parsed.sources.source_range(idents[1].1).unwrap();
    assert_eq!(
        parsed.sources.file(file).unwrap().text().get(range),
        Some("r2")
    );
    assert_eq!(parsed.sources.source_range(idents[0].1), None);
    // The snippet is the preprocessed text.
    assert_eq!(parsed.sources.snippet(idents[3].1), "bb");
}

#[test]
fn an_expansion_starts_a_token_but_does_not_end_one() {
    // The end of a value joins the text after it: `abcd` is one name.
    let parsed = parse(&[(
        "a.slaspec",
        "define endian=big;\n@define V \"ab\"\n:X is epsilon { y = $(V)cd; }\n",
    )]);
    assert!(
        parsed.diagnostics.is_empty(),
        "{:?}",
        parsed.rendered_diagnostics()
    );
    let names: Vec<String> = body_idents(&parsed, 0)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, ["abcd"]);
    // The start of a value is a token boundary: `q` and `ab` are two names,
    // which is a syntax error here, located at the reference.
    let parsed = parse(&[(
        "a.slaspec",
        "define endian=big;\n@define V \"ab\"\n:X is epsilon { x = q$(V); }\n",
    )]);
    assert_eq!(
        parsed.rendered_diagnostics(),
        ["a.slaspec:3:22: error: expected `;` after the statement, found `ab`"]
    );
}

#[test]
fn spans_through_an_expanded_include_path_and_in_included_expansions() {
    let parsed = parse(&[
        (
            "a.slaspec",
            "define endian=big;\n@define DIR \"inc\"\n@define R \"reg\"\n@include \"$(DIR)/b.sinc\"\n",
        ),
        ("inc/b.sinc", "\n:B is epsilon { x = $(R) + tail; }\n"),
    ]);
    assert!(
        parsed.diagnostics.is_empty(),
        "{:?}",
        parsed.rendered_diagnostics()
    );
    let idents = body_idents(&parsed, 0);
    assert_eq!(at(&parsed, idents[0].1), place("b.sinc", 2, 21, true));
    assert_eq!(at(&parsed, idents[1].1), place("b.sinc", 2, 28, false));
}

#[test]
fn diagnostics_after_expansions_and_in_includes_render_with_their_chain() {
    let parsed = parse(&[
        (
            "a.slaspec",
            "define endian=big;\n@define V \"long_value\"\n@include \"b.sinc\"\n",
        ),
        ("b.sinc", ":B is epsilon { x = $(V) + ; }\n"),
    ]);
    let rendered = parsed.rendered_diagnostics();
    assert_eq!(
        rendered,
        ["b.sinc:1:28: error: expected an expression, found `;`\n    included from a.slaspec:3"]
    );
}

#[test]
fn line_endings_and_multibyte_columns() {
    let parsed = parse(&[(
        "a.slaspec",
        "define endian=big;\r\n# é comment\r:A is epsilon { x = y; }\r\n:\"é\" B is epsilon { x = z; }\n",
    )]);
    assert!(
        parsed.diagnostics.is_empty(),
        "{:?}",
        parsed.rendered_diagnostics()
    );
    let a = at(&parsed, parsed.spec.items[0].span());
    assert_eq!(a, place("a.slaspec", 3, 1, false));
    let idents = body_idents(&parsed, 1);
    let line = ":\"é\" B is epsilon { x = z; }";
    let z_col = line.chars().position(|c| c == 'z').unwrap() as u32 + 1;
    assert_eq!(
        at(&parsed, idents[0].1),
        place("a.slaspec", 4, z_col, false)
    );
}
