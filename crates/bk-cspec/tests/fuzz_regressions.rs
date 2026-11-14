//! Replays every saved input of the `bk_cspec_decode` fuzz target
//! (`fuzz/regressions/bk_cspec_decode/`): none may panic. The 60 s run of
//! 2026-11-15 found nothing, so the directory may be absent.

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

use bk_cspec::{CompilerSpec, ReadOptions};

#[test]
fn saved_fuzz_inputs_do_not_panic() {
    let dir = bk_testkit::workspace_root().join("fuzz/regressions/bk_cspec_decode");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no saved inputs in {}", dir.display());
        return;
    };
    for e in entries.flatten() {
        let bytes = std::fs::read(e.path()).unwrap();
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let mut m = common::toy_manager();
            let _ = CompilerSpec::read(text, &mut m, ReadOptions::default());
        }
    }
}
