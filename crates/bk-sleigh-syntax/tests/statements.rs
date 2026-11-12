//! Every statement and operand form of the semantic section
//! (`SemanticParser.g`), and the places where a keyword is an ordinary
//! identifier.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

mod common;

use bk_sleigh_syntax::ast::Statement;
use bk_sleigh_syntax::parse_semantic_body;
use common::{body_ok, expr, statements};
use rstest::rstest;

#[rstest]
// assignment: `lvalue = expr`
#[case("x = y;", "(= x y)")]
#[case("x:4 = y;", "(= x:4 y)")]
#[case("x[0,8] = y;", "(= x[0,8] y)")]
#[case("*x = y;", "(= (deref x) y)")]
#[case("*:4 x = y;", "(= (deref:4 x) y)")]
#[case("*[ram] x = y;", "(= (deref[ram] x) y)")]
#[case("*[ram]:4 x + 4 = y;", "(= (deref[ram]:4 (+ x 4)) y)")]
#[case("local x = y;", "(local= x y)")]
#[case("local x:4 = y;", "(local= x:4 y)")]
#[case("local x[0,8] = y;", "(local= x[0,8] y)")]
#[case("local *:4 x = y;", "(local= (deref:4 x) y)")]
// declaration
#[case("local x;", "(local x)")]
#[case("local x:4;", "(local x:4)")]
// funcall as a statement
#[case("foo();", "(apply foo)")]
#[case("foo(a, b + 1, *:4 c);", "(apply foo a (+ b 1) (deref:4 c))")]
#[case("delayslot(1);", "(apply delayslot 1)")]
// build, crossbuild
#[case("build op1;", "(build op1)")]
#[case("crossbuild addr, sect;", "(crossbuild addr sect)")]
#[case("crossbuild 0x10:4, sect;", "(crossbuild 0x10:4 sect)")]
#[case("crossbuild &r, sect;", "(crossbuild (addr r) sect)")]
// goto with each jump destination
#[case("goto dest;", "(goto dest)")]
#[case("goto [x + 1];", "(goto (dynamic (+ x 1)))")]
#[case("goto 0x1000;", "(goto 0x1000)")]
#[case("goto 0x1000[ram];", "(goto (in-space 0x1000 ram))")]
#[case("goto <done>;", "(goto <done>)")]
// conditional branch
#[case("if (a == b) goto dest;", "(if (paren (== a b)) (goto dest))")]
#[case("if a goto <skip>;", "(if a (goto <skip>))")]
#[case("if !a && b goto [c];", "(if (&& (not a) b) (goto (dynamic c)))")]
// call, return
#[case("call dest;", "(call dest)")]
#[case("call [x];", "(call (dynamic x))")]
#[case("call 0x20[ram];", "(call (in-space 0x20 ram))")]
#[case("return [x];", "(return x)")]
#[case("return [*:4 sp];", "(return (deref:4 sp))")]
// export
#[case("export x;", "(export x)")]
#[case("export 1:4;", "(export 1:4)")]
#[case("export x:2;", "(export x:2)")]
#[case("export &x;", "(export (addr x))")]
#[case("export &:4 x;", "(export (addr:4 x))")]
#[case("export *x;", "(export (deref x))")]
#[case("export *:4 x;", "(export (deref:4 x))")]
#[case("export *[ram]:4 x;", "(export (deref[ram]:4 x))")]
// labels and section markers take no semicolon
#[case("<loop>", "(label loop)")]
#[case("<<part2>>", "(section part2)")]
fn statement_forms(#[case] source: &str, #[case] expected: &str) {
    assert_eq!(statements(source), [expected], "{source}");
}

#[rstest]
#[case("1", "1")]
#[case("0x1F", "0x1f")]
#[case("0b1010", "0b1010")]
#[case("0n42", "42")]
#[case("r", "r")]
#[case("1:4", "1:4")]
#[case("0xff:1", "0xff:1")]
#[case("0n7:2", "7:2")]
#[case("r:4", "r:4")]
#[case("r[4,8]", "r[4,8]")]
#[case("&r", "(addr r)")]
#[case("&:8 r", "(addr:8 r)")]
#[case("& &r", "(addr (addr r))")]
#[case("&r:4", "(addr r:4)")]
#[case("(r)", "(paren r)")]
#[case("f()", "(apply f)")]
#[case("zext(r)", "(apply zext r)")]
#[case("carry(a, b)", "(apply carry a b)")]
#[case("r(2)", "(apply r 2)")]
#[case("f(g(a, b), c)", "(apply f (apply g a b) c)")]
#[case("f(g(h(i(a))))", "(apply f (apply g (apply h (apply i a))))")]
#[case("f(a)(b)", "")]
fn operand_forms(#[case] source: &str, #[case] expected: &str) {
    if expected.is_empty() {
        let parsed = parse_semantic_body(&format!("x = {source};"));
        assert!(
            !parsed.diagnostics.is_empty(),
            "{source} is not an expression"
        );
    } else {
        assert_eq!(expr(source), expected, "{source}");
    }
}

/// `key_as_id` in `SleighParser.g`: every keyword may be used as a name.
/// At the start of a statement a keyword is a name when what follows can
/// only continue an assignment or a call.
#[rstest]
#[case("local = 1;", "(= local 1)")]
#[case("local:4 = 1;", "(= local:4 1)")]
#[case("local[0,1] = 1;", "(= local[0,1] 1)")]
#[case("local(1);", "(apply local 1)")]
#[case("local local = local;", "(local= local local)")]
#[case("build = build + 1;", "(= build (+ build 1))")]
#[case("build build;", "(build build)")]
#[case("goto = 1;", "(= goto 1)")]
#[case("goto goto;", "(goto goto)")]
#[case("goto[0,4] = 1;", "(= goto[0,4] 1)")]
#[case("goto [0];", "(goto (dynamic 0))")]
#[case("goto [x, 4];", "")]
#[case("call(x);", "(apply call x)")]
#[case("call:1 = 0;", "(= call:1 0)")]
#[case("return = x;", "(= return x)")]
#[case("return[0,4] = 1;", "(= return[0,4] 1)")]
#[case("export = x;", "(= export x)")]
#[case("export export;", "(export export)")]
#[case("crossbuild = 0;", "(= crossbuild 0)")]
#[case(
    "x = define + attach + macro + token + size + offset + unimpl + is + default;",
    "(= x (+ (+ (+ (+ (+ (+ (+ (+ define attach) macro) token) size) offset) unimpl) is) default))"
)]
#[case("goto unimpl;", "(goto unimpl)")]
fn keywords_as_names_in_statements(#[case] source: &str, #[case] expected: &str) {
    if expected.is_empty() {
        assert!(
            !parse_semantic_body(source).diagnostics.is_empty(),
            "{source}"
        );
    } else {
        assert_eq!(statements(source), [expected], "{source}");
    }
}

/// `if` (semantic sections) and `with` (everywhere) are reserved.
#[rstest]
#[case("if = 1;")]
#[case("x = if;")]
#[case("with = 1;")]
#[case("x = with + 1;")]
#[case("goto with;")]
#[case("local if;")]
#[case("build with;")]
#[case("<if>")]
fn reserved_words_are_not_names(#[case] source: &str) {
    assert!(
        !parse_semantic_body(source).diagnostics.is_empty(),
        "{source}"
    );
}

/// Statements Ghidra's grammars reject.
#[rstest]
#[case(";", "Empty statement")]
#[case("x = 1;;", "Empty statement")]
#[case("x = 1", "expected `;` after the statement")]
#[case("return;", "expected `[`")]
#[case("return x;", "expected `[`")]
#[case("x;", "expected `=`")]
#[case("1 = x;", "expected a statement")]
#[case("x = ;", "expected an expression")]
#[case("x = (1;", "expected `)`")]
#[case("x = f(1,);", "expected an expression")]
#[case("goto 0n5;", "`0n` integers")]
#[case("x = y:0n4;", "`0n` integers")]
#[case("goto;", "expected a jump destination")]
#[case("if a goto;", "expected a jump destination")]
#[case("if a b;", "expected `goto`")]
#[case("build 1;", "expected identifier")]
#[case("crossbuild a b;", "expected `,`")]
#[case("export;", "expected an expression")]
#[case("x[1] = 2;", "expected `,`")]
#[case("x[a,2] = 2;", "expected integer")]
#[case("*[1] x = 2;", "expected identifier")]
#[case("<a b>", "expected `>`")]
#[case("<<a>", "expected `>>`")]
#[case("x = a ? b;", "unexpected character `?`")]
#[case("x = 1; }", "unexpected `}`")]
fn rejected_statements(#[case] source: &str, #[case] message: &str) {
    let parsed = parse_semantic_body(source);
    let messages: Vec<&str> = parsed
        .diagnostics
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains(message)),
        "{source}: got {messages:?}"
    );
}

#[test]
fn a_body_keeps_its_statements_in_order_and_splits_into_sections() {
    let parsed = body_ok(
        "local t:4 = a + b;\n<top>\nt = t - 1;\nif (t != 0) goto <top>;\n\
         <<second>>\nexport t;\n<<third>>\n",
    );
    let names = &parsed.names;
    let sections: Vec<(Option<&str>, usize)> = parsed
        .body
        .sections()
        .map(|(name, stmts)| (name.map(|n| names.resolve(n.name)), stmts.len()))
        .collect();
    assert_eq!(
        sections,
        [(None, 4), (Some("second"), 1), (Some("third"), 0)]
    );
    assert!(matches!(parsed.body.statements[1], Statement::Label { .. }));

    let empty = body_ok("");
    assert_eq!(empty.body.sections().count(), 1);
    assert!(empty.body.statements.is_empty());
}

#[test]
fn signed_and_float_operator_tokens_shadow_the_names_s_and_f() {
    // `s<` and `f+` are single tokens in a semantic section, as in both of
    // Ghidra's lexers, so the operands are `a` and `b`, not `s`/`f`.
    assert_eq!(expr("a s< b"), "(s< a b)");
    assert_eq!(expr("a f+ b"), "(f+ a b)");
    // With a space the same letters are plain identifiers.
    assert_eq!(expr("s < b"), "(< s b)");
    assert_eq!(expr("f + b"), "(+ f b)");
    assert_eq!(expr("f- a"), "(fneg a)");
    assert_eq!(expr("a s>> 2 s/ 3 s% 4"), "(s>> a (s% (s/ 2 3) 4))");
}
