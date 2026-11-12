//! Operator precedence and associativity.
//!
//! The expected trees are computed from precedence tables transcribed here
//! from the `%left`/`%right` declarations of Ghidra's `slghparse.y` (which
//! agree with the rule nesting of `SemanticParser.g` and `SleighParser.g`),
//! independently of the tables in the parser.

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

use common::{context, equation, expr};

/// `slghparse.y`, loosest first:
///
/// ```text
/// %left OP_BOOL_OR
/// %left OP_BOOL_AND OP_BOOL_XOR
/// %left '|' OP_OR
/// %left ';'
/// %left '^' OP_XOR
/// %left '&' OP_AND
/// %left OP_EQUAL OP_NOTEQUAL OP_FEQUAL OP_FNOTEQUAL
/// %nonassoc '<' '>' OP_GREATEQUAL OP_LESSEQUAL OP_SLESS OP_SGREATEQUAL OP_SLESSEQUAL OP_SGREAT
///           OP_FLESS OP_FGREAT OP_FLESSEQUAL OP_FGREATEQUAL
/// %left OP_LEFT OP_RIGHT OP_SRIGHT
/// %left '+' '-' OP_FADD OP_FSUB
/// %left '*' '/' '%' OP_SDIV OP_SREM OP_FMULT OP_FDIV
/// %right '!' '~'
/// ```
const SEMANTIC_LEVELS: &[&[&str]] = &[
    &["||"],
    &["&&", "^^"],
    &["|"],
    &["^"],
    &["&"],
    &["==", "!=", "f==", "f!="],
    &[
        "<", ">", ">=", "<=", "s<", "s>=", "s<=", "s>", "f<", "f>", "f<=", "f>=",
    ],
    &["<<", ">>", "s>>"],
    &["+", "-", "f+", "f-"],
    &["*", "/", "%", "s/", "s%", "f*", "f/"],
];

fn operators(levels: &[&[&'static str]]) -> Vec<(usize, &'static str)> {
    levels
        .iter()
        .enumerate()
        .flat_map(|(level, ops)| ops.iter().map(move |op| (level, *op)))
        .collect()
}

/// The expected tree of `a op1 b op2 c`: the tighter operator groups
/// first, and equal precedence groups to the left.
fn expected(level1: usize, op1: &str, level2: usize, op2: &str) -> String {
    if level1 >= level2 {
        format!("({op2} ({op1} a b) c)")
    } else {
        format!("({op1} a ({op2} b c))")
    }
}

#[test]
fn every_pair_of_semantic_binary_operators() {
    let ops = operators(SEMANTIC_LEVELS);
    assert_eq!(
        ops.len(),
        36,
        "all 36 binary operators of the semantic section"
    );
    let mut checked = 0;
    for &(level1, op1) in &ops {
        for &(level2, op2) in &ops {
            let source = format!("a {op1} b {op2} c");
            assert_eq!(
                expr(&source),
                expected(level1, op1, level2, op2),
                "{source}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 36 * 36);
}

#[test]
fn semantic_operators_are_left_associative() {
    for (_, op) in operators(SEMANTIC_LEVELS) {
        let source = format!("a {op} b {op} c {op} d");
        assert_eq!(
            expr(&source),
            format!("({op} ({op} ({op} a b) c) d)"),
            "{source}"
        );
    }
}

#[test]
fn a_long_mixed_expression_groups_by_precedence() {
    assert_eq!(
        expr("a || b && c | d ^ e & f == g < h << i + j * k"),
        "(|| a (&& b (| c (^ d (& e (== f (< g (<< h (+ i (* j k))))))))))"
    );
    assert_eq!(
        expr("a * b + c << d < e == f & g ^ h | i && j || k"),
        "(|| (&& (| (^ (& (== (< (<< (+ (* a b) c) d) e) f) g) h) i) j) k)"
    );
    assert_eq!(expr("a + b * c - d / e"), "(- (+ a (* b c)) (/ d e))");
    assert_eq!(expr("a ^^ b && c ^^ d"), "(^^ (&& (^^ a b) c) d)");
}

#[test]
fn parentheses_override_precedence_and_are_kept() {
    assert_eq!(expr("(a + b) * c"), "(* (paren (+ a b)) c)");
    assert_eq!(expr("a * (b + c)"), "(* a (paren (+ b c)))");
    assert_eq!(expr("((a))"), "(paren (paren a))");
    assert_eq!(expr("a - (b - c)"), "(- a (paren (- b c)))");
}

#[test]
fn unary_operators_bind_tighter_than_every_binary_operator() {
    let unary = [("!", "not"), ("~", "inv"), ("-", "neg"), ("f-", "fneg")];
    for (_, op) in operators(SEMANTIC_LEVELS) {
        for (spelling, name) in unary {
            let before = format!("{spelling} a {op} b");
            assert_eq!(expr(&before), format!("({op} ({name} a) b)"), "{before}");
            let after = format!("a {op} {spelling} b");
            assert_eq!(expr(&after), format!("({op} a ({name} b))"), "{after}");
        }
        let load = format!("*:4 a {op} b");
        assert_eq!(expr(&load), format!("({op} (deref:4 a) b)"), "{load}");
        let load_after = format!("a {op} *[ram]:4 b");
        assert_eq!(
            expr(&load_after),
            format!("({op} a (deref[ram]:4 b))"),
            "{load_after}"
        );
    }
}

#[test]
fn unary_operators_nest_and_apply_to_calls_and_parentheses() {
    // slghparse.y allows any nesting (`'-' expr %prec '!'`); SemanticParser.g
    // allows one operator in front of a call or term. Nesting is accepted.
    assert_eq!(expr("- - a"), "(neg (neg a))");
    assert_eq!(expr("!~a"), "(not (inv a))");
    assert_eq!(expr("~ * a"), "(inv (deref a))");
    assert_eq!(expr("* * a"), "(deref (deref a))");
    assert_eq!(expr("*:8 -a"), "(deref:8 (neg a))");
    assert_eq!(expr("-zext(a)"), "(neg (apply zext a))");
    assert_eq!(expr("!(a == b)"), "(not (paren (== a b)))");
    assert_eq!(expr("-a:4"), "(neg a:4)");
    assert_eq!(expr("- 1:4 + 2"), "(+ (neg 1:4) 2)");
    assert_eq!(expr("a - -b"), "(- a (neg b))");
    assert_eq!(expr("a f- f- b"), "(f- a (fneg b))");
}

#[test]
fn multiplication_and_dereference_share_the_star() {
    assert_eq!(expr("a * b"), "(* a b)");
    assert_eq!(expr("a * *b"), "(* a (deref b))");
    assert_eq!(expr("*a * *:2 b"), "(* (deref a) (deref:2 b))");
    assert_eq!(expr("*[ram] a + 1"), "(+ (deref[ram] a) 1)");
    assert_eq!(expr("*(a + 1)"), "(deref (paren (+ a 1)))");
}

/// `slghparse.y`: `%left '|'`, `%left ';'`, `%left '&'`, loosest first;
/// `SleighParser.g`: `pequation_or` over `pequation_seq` over
/// `pequation_and`.
const EQUATION_LEVELS: &[&[&str]] = &[&["|"], &[";"], &["&"]];

#[test]
fn every_pair_of_equation_operators() {
    let ops = operators(EQUATION_LEVELS);
    for &(level1, op1) in &ops {
        for &(level2, op2) in &ops {
            let source = format!("a {op1} b {op2} c");
            assert_eq!(
                equation(&source),
                expected(level1, op1, level2, op2),
                "{source}"
            );
        }
    }
    assert_eq!(equation("a | b ; c & d"), "(| a (; b (& c d)))");
    assert_eq!(equation("a & b ; c | d"), "(| (; (& a b) c) d)");
    assert_eq!(equation("a ; b ; c"), "(; (; a b) c)");
    assert_eq!(equation("(a | b) & c"), "(& (paren (| a b)) c)");
    assert_eq!(
        equation("a=1 & b=2 | c=3 ; d"),
        "(| (& (= a 1) (= b 2)) (; (= c 3) d))"
    );
}

#[test]
fn ellipses_bind_to_one_atomic_equation() {
    assert_eq!(equation("... a"), "(ellipsis-left a)");
    assert_eq!(equation("a ..."), "(ellipsis-right a)");
    assert_eq!(equation("... a ..."), "(ellipsis-left (ellipsis-right a))");
    assert_eq!(equation("a ... & b"), "(& (ellipsis-right a) b)");
    assert_eq!(equation("... a & b"), "(& (ellipsis-left a) b)");
    assert_eq!(equation("a & ... b"), "(& a (ellipsis-left b))");
    assert_eq!(equation("(a & b) ..."), "(ellipsis-right (paren (& a b)))");
    assert_eq!(equation("... (a ; b)"), "(ellipsis-left (paren (; a b)))");
    assert_eq!(equation("a=1 ... ; b"), "(; (ellipsis-right (= a 1)) b)");
}

#[test]
fn constraints_take_each_comparison() {
    assert_eq!(equation("a = 1"), "(= a 1)");
    assert_eq!(equation("a != 0x1F"), "(!= a 0x1f)");
    assert_eq!(equation("a < 0b11"), "(< a 0b11)");
    assert_eq!(equation("a <= b"), "(<= a b)");
    assert_eq!(equation("a > -1"), "(> a (neg 1))");
    assert_eq!(equation("a >= ~b"), "(>= a (inv b))");
    assert_eq!(equation("a"), "a");
    assert_eq!(equation("a = (1)"), "(= a (paren 1))");
}

/// `slghparse.y` for `pexpression`: `OP_OR`, then `OP_XOR`, then `OP_AND`,
/// then shifts, then `+ -`, then `* /`, loosest first.
const PATTERN_LEVELS: &[&[&str]] = &[
    &["$or"],
    &["$xor"],
    &["$and"],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/"],
];

#[test]
fn every_pair_of_pattern_expression_operators_in_a_constraint() {
    let ops = operators(PATTERN_LEVELS);
    for &(level1, op1) in &ops {
        for &(level2, op2) in &ops {
            let source = format!("f = a {op1} b {op2} c");
            let tree = expected(level1, op1, level2, op2);
            assert_eq!(equation(&source), format!("(= f {tree})"), "{source}");
        }
    }
}

#[test]
fn equation_operators_end_a_constraint_value() {
    // In a constraint `&` and `|` combine equations; only `$and` and `$or`
    // operate on values.
    assert_eq!(equation("a = b & c"), "(& (= a b) c)");
    assert_eq!(
        equation("a = b $and c"),
        "(= a (& b c))".replace('&', "$and")
    );
    assert_eq!(equation("a = 1 | b = 2"), "(| (= a 1) (= b 2))");
    assert_eq!(equation("a = b + 1 ; c"), "(; (= a (+ b 1)) c)");
    assert_eq!(
        equation("a = b << 2 & c = d $or e"),
        "(& (= a (<< b 2)) (= c ($or d e)))"
    );
}

#[test]
fn context_blocks_accept_both_spellings_of_the_bitwise_operators() {
    assert_eq!(
        context("c = a | b ^ d & e;"),
        "(context (= c ($or a ($xor b ($and d e)))))"
    );
    assert_eq!(
        context("c = a $or b $xor d $and e;"),
        "(context (= c ($or a ($xor b ($and d e)))))"
    );
    assert_eq!(
        context("c = a & b | d;"),
        "(context (= c ($or ($and a b) d)))"
    );
    assert_eq!(
        context("c = a + b * d << 1;"),
        "(context (= c (<< (+ a (* b d)) 1)))"
    );
    assert_eq!(
        context("c = (a | b) & 1;"),
        "(context (= c ($and (paren ($or a b)) 1)))"
    );
    let ops = operators(&[
        &["|"],
        &["^"],
        &["&"],
        &["<<", ">>"],
        &["+", "-"],
        &["*", "/"],
    ]);
    let name = |op: &str| match op {
        "|" => "$or".to_owned(),
        "^" => "$xor".to_owned(),
        "&" => "$and".to_owned(),
        other => other.to_owned(),
    };
    for &(level1, op1) in &ops {
        for &(level2, op2) in &ops {
            let source = format!("t = a {op1} b {op2} c;");
            let tree = expected(level1, &name(op1), level2, &name(op2));
            assert_eq!(
                context(&source),
                format!("(context (= t {tree}))"),
                "{source}"
            );
        }
    }
}

#[test]
fn pattern_unary_operators_bind_tightest_and_nest() {
    assert_eq!(context("c = -a * b;"), "(context (= c (* (neg a) b)))");
    assert_eq!(context("c = a - -b;"), "(context (= c (- a (neg b))))");
    assert_eq!(context("c = ~-a;"), "(context (= c (inv (neg a))))");
    assert_eq!(
        context("c = -(a + b);"),
        "(context (= c (neg (paren (+ a b)))))"
    );
    assert_eq!(context("c = ~f(a);"), "(context (= c (inv (apply f a))))");
}
