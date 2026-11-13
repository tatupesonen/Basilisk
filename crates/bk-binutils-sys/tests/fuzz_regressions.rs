//! Replays every saved input of the fuzz target
//! `bk_binutils_sys_disassemble` (`fuzz/regressions/<target>/`) through the
//! same code the target runs. Each must complete; one that made binutils
//! abort must still be trapped (a handled error, as it is for the fuzzer).

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
#![cfg(any(unix, windows))]

mod fuzz_input;

use std::path::PathBuf;

use bk_binutils_sys::{architecture_names, scan_architecture};

#[test]
fn saved_fuzz_inputs_replay() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/regressions/bk_binutils_sys_disassemble");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no saved inputs in {}", dir.display());
        return;
    };
    let architectures: Vec<_> = architecture_names()
        .unwrap()
        .iter()
        .filter_map(|name| scan_architecture(name).unwrap())
        .collect();
    let mut replayed = 0;
    for entry in entries {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        if let Err((arch, message)) = fuzz_input::run(&data, &architectures) {
            eprintln!(
                "{}: binutils aborted on {arch} (trapped): {message}",
                path.display()
            );
        }
        replayed += 1;
    }
    eprintln!("replayed {replayed} saved inputs");
}
