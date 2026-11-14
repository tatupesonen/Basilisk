//! The public API on the fixture language: temporaries, parameters, what is
//! visible, options, the error forms, line endings and thread safety.

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
use bk_sleigh_snippet::{
    Compiled, ExtraSpace, Options, Parameter, SnippetCompiler, SnippetError, TempAllocator, compile,
};

fn compiler() -> (bk_sla::Sla, SnippetCompiler) {
    let sla = common::fixture::sla();
    let compiler = SnippetCompiler::new(&sla, &Options::default());
    (sla, compiler)
}

fn first_message(e: &SnippetError) -> String {
    e.messages().first().cloned().unwrap_or_default()
}

#[test]
fn temporaries_continue_across_snippets_and_only_on_success() {
    let (sla, c) = compiler();
    let start = sla.header().unique_base + 0x200;
    let mut temps = TempAllocator::for_injection(sla.header().unique_base);
    assert_eq!(temps.next, start);
    assert_eq!(temps.step, 16);
    c.compile("a:4 = EAX + 1;", &[], &mut temps).unwrap();
    assert_eq!(temps.next, start + 2 * 16);
    let err = c.compile("b:4 = EAX + foo;", &[], &mut temps).unwrap_err();
    assert_eq!(first_message(&err), "Unknown varnode parameter: foo");
    assert_eq!(temps.next, start + 2 * 16, "a failure takes no temporaries");
    let next = c.compile("b:4 = EAX;", &[], &mut temps).unwrap();
    assert_eq!(temps.next, start + 3 * 16);
    let xml = next.template.encode_xml(c.space_table());
    assert!(xml.contains(&format!("{:#x}", start + 2 * 16)), "{xml}");
    assert_eq!(TempAllocator::for_executable().next, 0x2000);
}

#[test]
fn parameters_are_operands_with_their_indices() {
    let (_, c) = compiler();
    let mut temps = TempAllocator::new(0x1000);
    let params = [Parameter::new("dst", 5), Parameter::new("src", 3)];
    let compiled = c.compile("dst = src;", &params, &mut temps).unwrap();
    let t = compiled.template.as_ref();
    let op = &t.ops()[0];
    let out = t.output(op).unwrap();
    assert!(matches!(out.offset, ConstTpl::Handle { index: 5, .. }));
    assert!(matches!(
        t.inputs(op)[0].offset,
        ConstTpl::Handle { index: 3, .. }
    ));
}

#[test]
fn duplicate_parameters_warn_and_the_first_wins() {
    let (_, c) = compiler();
    let mut temps = TempAllocator::new(0x1000);
    let params = [
        Parameter::new("x", 0),
        Parameter::new("x", 1),
        Parameter::new("ram", 2),
    ];
    let compiled = c.compile("x = 1:4;", &params, &mut temps).unwrap();
    assert_eq!(
        compiled.warnings,
        ["Duplicate symbol name: x", "Duplicate symbol name: ram"]
    );
    let t = compiled.template.as_ref();
    assert!(matches!(
        t.output(&t.ops()[0]).unwrap().offset,
        ConstTpl::Handle { index: 0, .. }
    ));
}

#[test]
fn language_symbols_other_than_ops_registers_and_addresses_are_invisible() {
    let (_, c) = compiler();
    for name in ["TMode", "op", "reg", "mode", "sub", "instruction", "m1"] {
        let mut temps = TempAllocator::new(0x1000);
        let err = c
            .compile(&format!("EAX = {name};"), &[], &mut temps)
            .unwrap_err();
        assert_eq!(
            first_message(&err),
            format!("Unknown varnode parameter: {name}")
        );
    }
    for body in [
        "EAX = inst_start;",
        "EAX = inst_next;",
        "EAX = inst_next2;",
        "EAX = inst_dest;",
        "EAX = inst_ref;",
        "segment(EAX);",
        "EAX = *[io]:4 0:4;",
        "EAX = *[OTHER]:4 0:4;",
        "EAX = *[unique]:4 0:4;",
        "EAX = *[const]:4 0:4;",
    ] {
        let mut temps = TempAllocator::new(0x1000);
        c.compile(body, &[], &mut temps)
            .unwrap_or_else(|e| panic!("{body}: {e}"));
    }
}

#[test]
fn names_that_are_keywords_of_sleigh_but_not_of_snippets() {
    let (_, c) = compiler();
    let mut temps = TempAllocator::new(0x1000);
    let params = [Parameter::new("build", 0), Parameter::new("export", 1)];
    c.compile(
        "build = export; cpool:4 = 1; EAX = cpool;",
        &params,
        &mut temps,
    )
    .unwrap();
    let err = c
        .compile("local build = 1;", &params, &mut temps)
        .unwrap_err();
    assert_eq!(first_message(&err), "Redefinition of symbol: build");
}

#[test]
fn extra_spaces_and_truncations() {
    let sla = common::fixture::sla();
    let mut temps = TempAllocator::new(0x1000);
    let plain = SnippetCompiler::new(&sla, &Options::default());
    let err = plain
        .compile("*[stack]:4 0:4 = 1:4;", &[], &mut temps)
        .unwrap_err();
    assert_eq!(first_message(&err), "syntax error");
    let stack = ExtraSpace {
        name: "stack".to_owned(),
        index: 9,
        addr_size: 4,
        word_size: 1,
        big_endian: false,
    };
    let with_stack = SnippetCompiler::new(&sla, &Options::default().with_space(stack));
    let compiled = with_stack
        .compile("*[stack]:4 0:4 = 1:4;", &[], &mut temps)
        .unwrap();
    let xml = compiled.template.encode_xml(with_stack.space_table());
    assert!(xml.contains("space=\"stack\""), "{xml}");

    let size_of = |c: &SnippetCompiler| {
        let mut temps = TempAllocator::new(0x1000);
        let t = c.compile("goto 0x10[ram];", &[], &mut temps).unwrap();
        let r = t.template.as_ref();
        r.inputs(&r.ops()[0])[0].size
    };
    assert_eq!(size_of(&plain), ConstTpl::Real(4));
    let truncated = SnippetCompiler::new(&sla, &Options::default().truncate_space("ram", 2));
    assert_eq!(size_of(&truncated), ConstTpl::Real(2));
}

#[test]
fn error_forms_and_ghidras_message() {
    let (sla, c) = compiler();
    let mut temps = TempAllocator::new(0x1000);
    let rejected = c.compile("EAX = 1 +;", &[], &mut temps).unwrap_err();
    assert!(matches!(rejected, SnippetError::Rejected { .. }));
    assert_eq!(
        rejected.ghidra_message("cspec"),
        "cspec: Unable to compile pcode: syntax error"
    );
    let first = c
        .compile("x = 0x1ffffffffffffffff; y = foo;", &[], &mut temps)
        .unwrap_err();
    assert_eq!(
        first.messages(),
        [
            "Parsed integer is too big (overflow)",
            "Unknown varnode parameter: foo"
        ]
    );
    let aborted = c.compile("AL = EAX[0,72];", &[], &mut temps).unwrap_err();
    assert_eq!(
        aborted,
        SnippetError::Aborted {
            message: "Requested bit range out of bounds".to_owned(),
            earlier: Vec::new()
        }
    );
    assert_eq!(
        aborted.ghidra_message("cspec"),
        "Requested bit range out of bounds"
    );
    let small = Options::default().with_max_text_len(4);
    let too_long = compile("EAX = 1;", &sla, &[], &mut temps, &small).unwrap_err();
    assert!(matches!(
        too_long,
        SnippetError::TooLong { len: 8, limit: 4 }
    ));
    let deep = Options::default().with_max_depth(50);
    let body = format!("EAX = {}1{};", "(".repeat(100), ")".repeat(100));
    let nested = compile(&body, &sla, &[], &mut temps, &deep).unwrap_err();
    assert_eq!(first_message(&nested), "memory exhausted");
    assert_eq!(temps.next, 0x1000);
}

#[test]
fn line_endings_do_not_change_the_result() {
    let (_, c) = compiler();
    let lf = "x:4 = EAX; # comment\nif (x == 0) goto <l>;\nEBX = x;\n<l>\n";
    let crlf = lf.replace('\n', "\r\n");
    let mut a = TempAllocator::new(0x1000);
    let mut b = TempAllocator::new(0x1000);
    assert_eq!(
        c.compile(lf, &[], &mut a).unwrap(),
        c.compile(&crlf, &[], &mut b).unwrap()
    );
}

#[test]
fn one_shot_compile_equals_the_compiler() {
    let (sla, c) = compiler();
    let mut a = TempAllocator::new(0x1000);
    let mut b = TempAllocator::new(0x1000);
    let one = compile("EAX = EBX * 2;", &sla, &[], &mut a, &Options::default()).unwrap();
    let two = c.compile("EAX = EBX * 2;", &[], &mut b).unwrap();
    assert_eq!(one, two.template);
    assert_eq!(a, b);
}

#[test]
fn results_are_send_and_sync() {
    fn check<T: Send + Sync + 'static>() {}
    check::<SnippetCompiler>();
    check::<Compiled>();
    check::<SnippetError>();
    check::<TempAllocator>();
    check::<Options>();
}
