//! Replays every input the fuzzer found for this crate's targets
//! (`fuzz/regressions/bk_decomp_symbols_*`) through the targets' own code
//! (`fuzz/fuzz_targets/bk_decomp_symbols_shared`), plus each target's
//! built-in sample and a few edits of it: none may panic or take long.
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

#[path = "../../../fuzz/fuzz_targets/bk_decomp_symbols_shared/mod.rs"]
mod shared;

use std::path::PathBuf;
use std::time::{Duration, Instant};

fn regressions(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/regressions")
        .join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Vec<u8>)> = entries
        .map(|e| e.unwrap().path())
        .map(|p| (p.display().to_string(), std::fs::read(&p).unwrap()))
        .collect();
    out.sort();
    out
}

#[test]
fn every_target_survives_its_samples_and_regressions() {
    for (target, name) in shared::Target::ALL {
        let mut inputs = regressions(name);
        // The sample itself (first byte 1, no edits) and some edits of it.
        inputs.push(("sample".into(), vec![1]));
        for k in 0u8..64 {
            inputs.push((
                format!("edit {k}"),
                vec![1, k % 6, k, k.wrapping_mul(7), k ^ 0x5a],
            ));
        }
        for (input, data) in inputs {
            let started = Instant::now();
            shared::run(target, &data);
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{name} {input} took {:?}",
                started.elapsed()
            );
        }
    }
}
