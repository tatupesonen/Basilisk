//! Replays every input under `fuzz/regressions/elf_parse/` through the fuzz
//! target's body, so a crash once found stays fixed (docs/LOOP.md).

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

#[allow(dead_code, unreachable_pub, reason = "shared with the fuzz target")]
#[path = "../../../fuzz/fuzz_targets/bin_elf/mod.rs"]
mod bin_elf;

#[test]
fn elf_parse_regressions_do_not_panic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions/elf_parse");
    let mut replayed = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() && path.file_name().is_some_and(|n| n != ".gitkeep") {
            bin_elf::elf_parse(&std::fs::read(&path).unwrap());
            replayed += 1;
        }
    }
    eprintln!("replayed {replayed} inputs from {}", dir.display());
}
