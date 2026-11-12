//! Ports of `ghidra.sleigh.grammar.BooleanExpressionTest` (31 tests) and
//! `BooleanExpressionDefTest` (3 tests).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use bk_sleigh_syntax::preprocess::expr::evaluate;
use rstest::rstest;

/// The environment of `BooleanExpressionTest`: every name is defined and
/// its value is the name itself.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the environment signature returns Option"
)]
fn identity(name: &str) -> Option<String> {
    Some(name.to_owned())
}

/// The environment of `BooleanExpressionDefTest`: only names starting with
/// `A` are defined.
fn starts_with_a(name: &str) -> Option<String> {
    name.starts_with('A').then(|| name.to_owned())
}

#[rstest]
#[case::equals1(r#"FOO == "FOO""#, true)]
#[case::equals2(r"FOO == FOO", true)]
#[case::equals3(r#""FOO" == "FOO""#, true)]
#[case::equals4(r#""FOO" == FOO"#, true)]
#[case::equals_inv1(r#"FOO == "BAR""#, false)]
#[case::equals_inv2(r"FOO == BAR", false)]
#[case::equals_inv3(r#""FOO" == "BAR""#, false)]
#[case::equals_inv4(r#""FOO" == BAR"#, false)]
#[case::not_equals1(r#"FOO != "FOO""#, false)]
#[case::not_equals2(r"FOO != FOO", false)]
#[case::not_equals3(r#""FOO" != "FOO""#, false)]
#[case::not_equals4(r#""FOO" != FOO"#, false)]
#[case::not_equals_inv1(r#"FOO != "BAR""#, true)]
#[case::not_equals_inv2(r"FOO != BAR", true)]
#[case::not_equals_inv3(r#""FOO" != "BAR""#, true)]
#[case::not_equals_inv4(r#""FOO" != BAR"#, true)]
#[case::simple_parens(r"(FOO == FOO)", true)]
#[case::more_parens(r"((((FOO == FOO))))", true)]
#[case::not(r"!(FOO == FOO)", false)]
#[case::not_inv(r"!(FOO != FOO)", true)]
#[case::more_nots(r"!(!(!(FOO == FOO)))", false)]
#[case::even_more_nots(r"!(!(!(!(FOO == FOO))))", true)]
#[case::or1(r#"FOO == "FOO" || BAR == "BAR""#, true)]
#[case::or2(r#"FOO == "BAR" || BAR == "BAR""#, true)]
#[case::or3(r#"FOO == "FOO" || BAR == "FOO""#, true)]
#[case::or4(r#"FOO == "BAR" || BAR == "FOO""#, false)]
#[case::and1(r#"FOO == "FOO" && BAR == "BAR""#, true)]
#[case::and2(r#"FOO == "BAR" && BAR == "BAR""#, false)]
#[case::and3(r#"FOO == "FOO" && BAR == "FOO""#, false)]
#[case::and4(r#"FOO == "BAR" && BAR == "FOO""#, false)]
#[case::complicated(r#"!(A!="A" || B=="B" ^^ (C!="C" || D=="D") && E!="E")"#, false)]
fn boolean_expression_test(#[case] expression: &str, #[case] expected: bool) {
    let result = evaluate(expression, &identity).unwrap();
    assert_eq!(result.value, expected, "{expression}");
    assert!(result.undefined.is_empty());
}

#[rstest]
#[case::simple_positive("defined(Astar)", true)]
#[case::simple_negative("defined(Bstar)", false)]
#[case::precedence("defined(Afoo) && !(defined(Bfoo))", true)]
fn boolean_expression_def_test(#[case] expression: &str, #[case] expected: bool) {
    let result = evaluate(expression, &starts_with_a).unwrap();
    assert_eq!(result.value, expected, "{expression}");
    assert!(
        result.undefined.is_empty(),
        "defined() never reports an undefined name"
    );
}
