//! Property tests: arbitrary input never panics, and generated expression
//! trees survive printing and re-parsing.

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

use bk_sleigh_syntax::ast::dump::{self, Dumper};
use bk_sleigh_syntax::ast::print::Printer;
use bk_sleigh_syntax::ast::{BinaryOp, Item, Statement};
use bk_sleigh_syntax::lex::{Lexer, Mode, TokenKind};
use bk_sleigh_syntax::{
    Defines, Interner, MemoryLoader, parse_file, parse_semantic_body, parse_str,
};
use proptest::prelude::*;

/// Text biased towards SLEIGH's own characters and words.
fn sleigh_text() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "define ",
        "endian=big;",
        "@define X \"1\"\n",
        "@if X == \"1\"\n",
        "@endif\n",
        "@include \"b\"\n",
        "$(X)",
        ":",
        " is ",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        ";",
        ",",
        "=",
        "&",
        "|",
        "...",
        "with t : ",
        "macro m(a) ",
        "attach names ",
        "token ",
        "\"s\"",
        "0x1f",
        "0n3",
        "0b",
        "_",
        "#c\n",
        "\n",
        " ",
        "a",
        "r0",
        "<l>",
        "<<s>>",
        "s<",
        "f+",
        "*[ram]:4 ",
        "^",
        "unimpl",
        "local ",
        "goto ",
        "export ",
        "\u{8}",
        "\u{e9}",
        "//",
    ]);
    prop::collection::vec(pieces, 0..60).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn parsing_never_panics(text in sleigh_text(), other in sleigh_text()) {
        let mut loader = MemoryLoader::new().with("a", text.as_str()).with("b", other.as_str());
        let parsed = parse_file(Path::new("a"), &Defines::new(), &mut loader);
        for d in &parsed.diagnostics {
            let _ = parsed.sources.render(d);
            let _ = parsed.sources.source_range(d.span);
        }
        let _ = dump::spec(&parsed.spec, &parsed.names, Some(&parsed.sources));
        let _ = parse_semantic_body(&text);
    }

    #[test]
    fn arbitrary_strings_never_panic(text in any::<String>()) {
        let _ = parse_str("a", &text, &Defines::new());
        let _ = parse_semantic_body(&text);
    }

    #[test]
    fn the_lexer_covers_its_input_in_every_mode(text in any::<String>()) {
        for mode in [Mode::Base, Mode::Display, Mode::Semantic] {
            let mut names = Interner::new();
            let mut lexer = Lexer::new(&text);
            let mut end = 0;
            loop {
                let token = lexer.next_token(mode, &mut names);
                prop_assert!(token.span.start >= end);
                end = token.span.end;
                if token.kind == TokenKind::Eof {
                    prop_assert_eq!(end as usize, text.len());
                    break;
                }
                prop_assert!(!token.span.is_empty());
                prop_assert!(text.get(token.span.range()).is_some());
            }
        }
    }
}

/// A semantic expression, generated independently of the parser.
#[derive(Clone, Debug)]
enum Gen {
    Name(&'static str),
    Int(u64, bool),
    Unary(&'static str, &'static str, Box<Gen>),
    Binary(BinaryOp, Box<Gen>, Box<Gen>),
    Call(&'static str, Vec<Gen>),
}

const OPS: [BinaryOp; 36] = [
    BinaryOp::BoolOr,
    BinaryOp::BoolAnd,
    BinaryOp::BoolXor,
    BinaryOp::Or,
    BinaryOp::Xor,
    BinaryOp::And,
    BinaryOp::Equal,
    BinaryOp::NotEqual,
    BinaryOp::FEqual,
    BinaryOp::FNotEqual,
    BinaryOp::Less,
    BinaryOp::GreatEqual,
    BinaryOp::LessEqual,
    BinaryOp::Great,
    BinaryOp::SLess,
    BinaryOp::SGreatEqual,
    BinaryOp::SLessEqual,
    BinaryOp::SGreat,
    BinaryOp::FLess,
    BinaryOp::FGreatEqual,
    BinaryOp::FLessEqual,
    BinaryOp::FGreat,
    BinaryOp::Left,
    BinaryOp::Right,
    BinaryOp::SRight,
    BinaryOp::Add,
    BinaryOp::Sub,
    BinaryOp::FAdd,
    BinaryOp::FSub,
    BinaryOp::Mult,
    BinaryOp::Div,
    BinaryOp::Rem,
    BinaryOp::SDiv,
    BinaryOp::SRem,
    BinaryOp::FMult,
    BinaryOp::FDiv,
];

fn gen_expr() -> impl Strategy<Value = Gen> {
    let leaf = prop_oneof![
        prop::sample::select(vec!["a", "b2", "r0", "x.y", "_t"]).prop_map(Gen::Name),
        (any::<u64>(), any::<bool>()).prop_map(|(v, hex)| Gen::Int(v, hex)),
    ];
    leaf.prop_recursive(6, 48, 4, |inner| {
        prop_oneof![
            (
                prop::sample::select(vec![
                    ("-", "neg"),
                    ("~", "inv"),
                    ("!", "not"),
                    ("f-", "fneg")
                ]),
                inner.clone()
            )
                .prop_map(|((op, name), e)| Gen::Unary(op, name, Box::new(e))),
            (
                prop::sample::select(OPS.to_vec()),
                inner.clone(),
                inner.clone()
            )
                .prop_map(|(op, l, r)| Gen::Binary(op, Box::new(l), Box::new(r))),
            (
                prop::sample::select(vec!["zext", "carry", "f"]),
                prop::collection::vec(inner, 0..3)
            )
                .prop_map(|(name, args)| Gen::Call(name, args)),
        ]
    })
}

/// Binding strength from `slghparse.y`, loosest first, written out here
/// rather than taken from the crate.
fn level(op: BinaryOp) -> u8 {
    let groups: [&[&str]; 10] = [
        &["||"],
        &["&&", "^^"],
        &["|"],
        &["^"],
        &["&"],
        &["==", "!=", "f==", "f!="],
        &[
            "<", ">=", "<=", ">", "s<", "s>=", "s<=", "s>", "f<", "f>=", "f<=", "f>",
        ],
        &["<<", ">>", "s>>"],
        &["+", "-", "f+", "f-"],
        &["*", "/", "%", "s/", "s%", "f*", "f/"],
    ];
    groups
        .iter()
        .position(|g| g.contains(&op.as_str()))
        .unwrap() as u8
}

/// Writes `e` with the fewest parentheses that keep its shape, and returns
/// the dump the parser should produce for that text.
fn render(e: &Gen, out: &mut String) -> String {
    match e {
        Gen::Name(n) => {
            out.push_str(n);
            (*n).to_owned()
        }
        Gen::Int(v, hex) => {
            let text = if *hex {
                format!("0x{v:x}")
            } else {
                v.to_string()
            };
            out.push_str(&text);
            text
        }
        Gen::Unary(op, name, inner) => {
            out.push_str(op);
            out.push(' ');
            let wrap = matches!(**inner, Gen::Binary(..));
            format!("({name} {})", paren(inner, wrap, out))
        }
        Gen::Binary(op, l, r) => {
            let mine = level(*op);
            let wrap_l = matches!(**l, Gen::Binary(o, ..) if level(o) < mine);
            let wrap_r = matches!(**r, Gen::Binary(o, ..) if level(o) <= mine);
            let left = paren(l, wrap_l, out);
            out.push(' ');
            out.push_str(op.as_str());
            out.push(' ');
            let right = paren(r, wrap_r, out);
            format!("({} {left} {right})", op.as_str())
        }
        Gen::Call(name, args) => {
            out.push_str(name);
            out.push('(');
            let mut dumped = format!("(apply {name}");
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dumped.push(' ');
                dumped.push_str(&render(arg, out));
            }
            out.push(')');
            dumped.push(')');
            dumped
        }
    }
}

fn paren(e: &Gen, wrap: bool, out: &mut String) -> String {
    if wrap {
        out.push('(');
        let inner = render(e, out);
        out.push(')');
        format!("(paren {inner})")
    } else {
        render(e, out)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn generated_expressions_parse_to_their_tree_and_print_back(e in gen_expr()) {
        let mut text = String::from("x = ");
        let expected = render(&e, &mut text);
        text.push(';');
        let parsed = parse_semantic_body(&text);
        prop_assert!(parsed.diagnostics.is_empty(), "{text}: {:?}", parsed.diagnostics);
        let Statement::Assign { value, .. } = &parsed.body.statements[0] else {
            panic!("not an assignment");
        };
        let dumper = Dumper::new(&parsed.nodes, &parsed.names);
        prop_assert_eq!(dumper.expr_string(*value), expected.clone(), "{}", text);

        // Printing the tree and parsing again gives the same tree.
        let printed = Printer::new(&parsed.nodes, &parsed.names).body(&parsed.body);
        let again = parse_semantic_body(&printed);
        prop_assert!(again.diagnostics.is_empty(), "{printed}");
        prop_assert_eq!(
            dump::body(&again.body, &again.nodes, &again.names),
            dump::body(&parsed.body, &parsed.nodes, &parsed.names)
        );
    }

    #[test]
    fn printed_constructors_reparse_to_the_same_tree(
        e in gen_expr(),
        disp in prop::sample::select(vec!["a, b", "^x", "\"q\" r", "  s  "]),
    ) {
        let mut text = String::from("define endian=big;\n:m ");
        text.push_str(disp);
        text.push_str(" is epsilon { x = ");
        let _ = render(&e, &mut text);
        text.push_str("; }\n");
        let parsed = parse_str("a", &text, &Defines::new());
        prop_assert!(parsed.diagnostics.is_empty(), "{text}");
        let Some(Item::Constructor(_)) = parsed.spec.items.first() else {
            panic!("no constructor");
        };
        prop_assert_eq!(parsed.spec.items.len(), 1);
    }
}
