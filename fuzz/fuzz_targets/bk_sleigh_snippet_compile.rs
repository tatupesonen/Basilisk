//! Fuzz target for `bk-sleigh-snippet`: the bytes are a snippet body
//! (invalid UTF-8 replaced), compiled against the crate's fixture language
//! (`crates/bk-sleigh-snippet/tests/fixture/fixture.slaspec`) with three
//! parameters. Nothing may panic, hang or allocate without bound (ADR-009).

#![no_main]

use std::sync::OnceLock;

use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};
use libfuzzer_sys::fuzz_target;

const SPEC: &str = include_str!("../../crates/bk-sleigh-snippet/tests/fixture/fixture.slaspec");

fn compiler() -> &'static SnippetCompiler {
    static COMPILER: OnceLock<SnippetCompiler> = OnceLock::new();
    COMPILER.get_or_init(|| {
        let parsed = bk_sleigh_syntax::parse_str(
            "fixture.slaspec",
            SPEC,
            &bk_sleigh_syntax::Defines::new(),
        );
        let compiled =
            bk_sleigh_compiler::compile_parsed(&parsed, bk_sleigh_compiler::Options::default());
        let Some(sla) = compiled.sla else {
            panic!("the fixture language compiles");
        };
        SnippetCompiler::new(&sla, &Options::default())
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let params = [
        Parameter::new("in1", 0),
        Parameter::new("in2", 1),
        Parameter::new("out1", 2),
    ];
    let mut temps = TempAllocator::new(0x1000);
    if let Ok(compiled) = compiler().compile(&text, &params, &mut temps) {
        let _ = compiled.template.encode_xml(compiler().space_table());
    }
});
