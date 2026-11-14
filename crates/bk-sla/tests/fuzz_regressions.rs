//! Replays every saved fuzz input through the fuzz targets' own code
//! (`fuzz/fuzz_targets/bk_sla_shared`), plus the small reference seeds.
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

#[path = "../../../fuzz/fuzz_targets/bk_sla_shared/mod.rs"]
mod shared;

use std::path::Path;

fn replay(target: &str, run: fn(&[u8])) -> usize {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz")
        .join("regressions")
        .join(target);
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_file() {
                run(&std::fs::read(&path).unwrap());
                count += 1;
            }
        }
    }
    count
}

#[test]
fn saved_inputs_replay() {
    replay("bk_sla_read", shared::read);
    replay("bk_sla_decode_packed", shared::decode_packed);
}

#[test]
fn the_targets_accept_a_valid_model() {
    // The fixture exercises the targets' round-trip assertions.
    let sla = common::full_model();
    shared::read(&sla.write().unwrap());
    shared::decode_packed(&sla.encode_packed().unwrap());
}
