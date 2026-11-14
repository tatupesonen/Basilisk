//! Property tests (spec 6.3) on the fixture language: arbitrary text and
//! token soups never panic; a failure takes no temporaries, a success takes
//! whole steps; every compiled template is a valid lone template whose XML
//! form reads back to the same template. `PROPTEST_CASES` sets the count.

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

use std::sync::OnceLock;

use bk_sla::{ConstTpl, Limits, Template};
use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};
use proptest::prelude::*;

fn compiler() -> &'static SnippetCompiler {
    static COMPILER: OnceLock<SnippetCompiler> = OnceLock::new();
    COMPILER.get_or_init(|| SnippetCompiler::new(&common::fixture::sla(), &Options::default()))
}

const TOKENS: &[&str] = &[
    "EAX",
    "AX",
    "AL",
    "ES",
    "R64",
    "XMM0",
    "in1",
    "in2",
    "out1",
    "inst_start",
    "inst_next",
    "inst_next2",
    "inst_dest",
    "inst_ref",
    "ram",
    "register",
    "io",
    "const",
    "unique",
    "TMode",
    "sub",
    "foo",
    "t",
    "segment",
    "syscall",
    "zext",
    "carry",
    "abs",
    "borrow",
    "local",
    "goto",
    "call",
    "return",
    "if",
    "0",
    "1",
    "4",
    "8",
    "0x10",
    "010",
    "09",
    "0x",
    "0x1ffffffffffffffff",
    "=",
    "==",
    "!=",
    "+",
    "-",
    "*",
    "/",
    "%",
    "&",
    "|",
    "^",
    "<<",
    ">>",
    "s>>",
    "<",
    ">",
    "<=",
    ">=",
    "s<",
    "f+",
    "f-",
    "&&",
    "||",
    "!",
    "~",
    "(",
    ")",
    "[",
    "]",
    ",",
    ":",
    ";",
    "<L>",
    "<M>",
    "#",
    "\n",
    "@",
    "\0",
];

fn soup() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(TOKENS), 0..40).prop_map(|t| t.join(" "))
}

fn params() -> [Parameter; 3] {
    [
        Parameter::new("in1", 0),
        Parameter::new("in2", 1),
        Parameter::new("out1", 2),
    ]
}

fn check(text: &str) {
    let c = compiler();
    let start = 0x1000;
    let mut temps = TempAllocator::new(start);
    match c.compile(text, &params(), &mut temps) {
        Ok(compiled) => {
            assert_eq!((temps.next - start) % temps.step, 0);
            let xml = compiled.template.encode_xml(c.space_table());
            // Ghidra compiles a branch to a label that is never placed (no
            // label check in snippets); `bk_sla` refuses to read such a
            // template, and the runtime fails on it when it is expanded.
            let t = compiled.template.as_ref();
            let labels = u64::from(t.header().labels.unsigned_abs());
            let dangling = t.ops().iter().any(|op| {
                t.inputs(op)
                    .iter()
                    .any(|v| matches!(v.offset, ConstTpl::Relative(l) if l >= labels))
            });
            if dangling {
                return;
            }
            let back = Template::decode_xml(&xml, c.space_table(), &Limits::default())
                .unwrap_or_else(|e| panic!("{text:?}: {e}\n{xml}"));
            assert_eq!(back, compiled.template, "{text:?}");
        }
        Err(e) => {
            assert_eq!(temps.next, start, "a failure takes no temporaries");
            assert_ne!(e.messages(), Vec::<String>::new());
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in any::<String>()) {
        check(&text);
    }

    #[test]
    fn token_soup_never_panics(text in soup()) {
        check(&text);
    }

    #[test]
    fn statement_soup_never_panics(
        parts in prop::collection::vec(soup().prop_map(|s| format!("{s};")), 1..6)
    ) {
        check(&parts.concat());
    }
}
