//! Property tests (spec 6.4): generated semantic bodies never panic the
//! elaborator, and straight-line bodies over fixed-size registers compile
//! to templates without a zero-size varnode.

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

use bk_sla::ConstTpl;
use bk_sleigh_compiler::Options;
use proptest::prelude::*;

const PRELUDE: &str = "define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 r2 r3 ];
define register offset=0x40 size=2 [ h0 h1 ];
define register offset=0x80 size=1 [ c0 c1 ];
define token instr(16) op=(8,15) reg=(0,1) imm=(0,7);
define pcodeop sync;
macro m(a, b) { a = b; }
sub: r0 is reg=0 & r0 { export r0; }
sub: imm is reg=1 & imm { export *[ram]:4 imm; }
";

/// Words and punctuation a semantic body is made of, valid or not.
fn token() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "r0",
        "r1",
        "h0",
        "c0",
        "imm",
        "sub",
        "tmp",
        "x",
        "inst_next",
        "inst_start",
        "ram",
        "sync",
        "m",
        "0",
        "1",
        "0x10",
        "4",
        "=",
        "+",
        "-",
        "*",
        "/",
        "<<",
        ">>",
        "s>>",
        "&",
        "|",
        "^",
        "==",
        "!=",
        "<",
        ">",
        "s<",
        "&&",
        "||",
        "!",
        "~",
        "f+",
        "(",
        ")",
        "[",
        "]",
        ",",
        ":",
        ";",
        ";",
        ";",
        "*[ram]",
        "local",
        "goto",
        "call",
        "if",
        "return",
        "build",
        "export",
        "<",
        ">",
        "<lab>",
        "zext",
        "sext",
        "carry",
        "cpool",
        "delayslot",
        "crossbuild",
        "&:2",
    ])
}

/// A random constructor body.
fn body() -> impl Strategy<Value = String> {
    prop::collection::vec(token(), 0..40).prop_map(|t| t.join(" "))
}

/// A register of four bytes.
fn reg() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["r0", "r1", "r2", "r3"])
}

/// A four-byte expression over registers and constants.
fn expr() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        reg().prop_map(str::to_owned),
        (0_u32..1000).prop_map(|v| v.to_string())
    ];
    leaf.prop_recursive(4, 24, 2, |inner| {
        (
            inner.clone(),
            prop::sample::select(vec!["+", "-", "*", "&", "|", "^", "<<", ">>"]),
            inner,
        )
            .prop_map(|(a, op, b)| format!("({a} {op} {b})"))
    })
}

/// A straight-line statement over fixed-size registers.
fn statement() -> impl Strategy<Value = String> {
    prop_oneof![
        (reg(), expr()).prop_map(|(r, e)| format!("{r} = {e};")),
        (reg(), expr()).prop_map(|(r, b)| format!("c0 = {r} == {b};")),
        (reg(), expr(), expr()).prop_map(|(r, a, b)| format!("*[ram]:4 ({r} + {a}) = {b};")),
        (reg(), reg(), expr()).prop_map(|(r, s, e)| format!("{r} = *[ram]:4 ({s} + {e});")),
        (reg(), reg()).prop_map(|(r, s)| format!("{r} = zext({s}:2);")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn generated_bodies_never_panic(body in body(), sub_body in body(), options in any::<u8>()) {
        let text = format!("{PRELUDE}:a r0, sub is op=1 & r0 & sub {{ {body} }}\nsub: is reg=2 {{ {sub_body} }}\n");
        let switches: Vec<&str> = ["-u", "-l", "-c", "-n", "-t", "-e", "-s"]
            .iter()
            .enumerate()
            .filter(|(i, _)| options & (1 << i) != 0)
            .map(|(_, s)| *s)
            .collect();
        let _ = common::elaborate_text(&text, Options::from_switches(switches));
    }

    #[test]
    fn straight_line_bodies_have_no_zero_sizes(statements in prop::collection::vec(statement(), 1..8)) {
        let text = format!("{PRELUDE}:a r0, sub is op=1 & r0 & sub {{ {} }}\n", statements.join(" "));
        let (parsed, outcome) = common::elaborate_text(&text, Options::default());
        prop_assert!(!parsed.has_errors(), "{:?}", parsed.rendered_diagnostics());
        let errors: Vec<_> = outcome.diagnostics.iter().filter(|d| d.is_error()).collect();
        prop_assert!(errors.is_empty(), "{errors:?}\n{text}");
        let spec = outcome.spec.unwrap();
        for ctor in &spec.constructors {
            for tpl in ctor.main.iter().chain(ctor.sections.iter().flatten()) {
                for op in &tpl.ops {
                    for vn in op.output.iter().chain(op.inputs.iter()) {
                        prop_assert!(vn.size != ConstTpl::Real(0), "zero size in {op:?}\n{text}");
                    }
                }
            }
        }
    }
}
