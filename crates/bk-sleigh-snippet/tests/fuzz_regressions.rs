//! Replays every saved input of the `bk_sleigh_snippet_compile` fuzz target
//! (`fuzz/regressions/bk_sleigh_snippet_compile/`) against the fixture
//! language: none may panic. The directory is absent while no run has found
//! anything.

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

use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};

#[test]
fn saved_fuzz_inputs_do_not_panic() {
    let dir = bk_testkit::workspace_root().join("fuzz/regressions/bk_sleigh_snippet_compile");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no saved inputs in {}", dir.display());
        return;
    };
    let compiler = SnippetCompiler::new(&common::fixture::sla(), &Options::default());
    let params = [
        Parameter::new("in1", 0),
        Parameter::new("in2", 1),
        Parameter::new("out1", 2),
    ];
    for e in entries.flatten() {
        let bytes = std::fs::read(e.path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let mut temps = TempAllocator::new(0x1000);
        let _ = compiler.compile(&text, &params, &mut temps);
    }
}
