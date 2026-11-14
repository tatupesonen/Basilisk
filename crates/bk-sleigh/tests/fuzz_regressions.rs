//! Replays the inputs saved under `fuzz/regressions/bk_sleigh_*` through the
//! fuzz targets' bodies (`fuzz/fuzz_targets/bk_sleigh_shared/mod.rs`), and a
//! few fixed inputs so the bodies are exercised even with no saved input.
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

#[path = "../../../fuzz/fuzz_targets/bk_sleigh_shared/mod.rs"]
mod bk_sleigh_shared;

fn saved(target: &str) -> Vec<Vec<u8>> {
    let dir = bk_testkit::workspace_root()
        .join("fuzz")
        .join("regressions")
        .join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect()
}

#[test]
fn decode_regressions() {
    for input in saved("bk_sleigh_decode") {
        bk_sleigh_shared::decode(&input);
    }
    for selector in 0..4u8 {
        let mut input = vec![selector, 0xff, 0, 0, 0, 0x80, 0, 0, 1];
        input.extend((0..32u8).map(|b| b.wrapping_mul(37)));
        bk_sleigh_shared::decode(&input);
    }
    bk_sleigh_shared::decode(&[]);
}

#[test]
fn lift_regressions() {
    for input in saved("bk_sleigh_lift") {
        bk_sleigh_shared::lift(&input);
    }
    for selector in 0..8u8 {
        let mut input = vec![selector, 0, 0, 0, 0, 0, 0, 0, 0];
        input.extend((1..=0x14u8).flat_map(|op| [op, op.wrapping_mul(29)]));
        bk_sleigh_shared::lift(&input);
    }
    bk_sleigh_shared::lift(&[]);
}

#[test]
fn hostile_sla_regressions() {
    for input in saved("bk_sleigh_hostile_sla") {
        bk_sleigh_shared::hostile_sla(&input);
    }
    bk_sleigh_shared::hostile_sla(b"not a model");
}
