//! Replays the saved inputs of the `packed_decode` and `xml_decode` fuzz
//! targets (`fuzz/regressions/<target>/`) through the targets' own code, so
//! a fixed crash stays fixed (docs/LOOP.md, Testing rules; `fuzz/README.md`).

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

#[path = "../../../fuzz/fuzz_targets/marshal/mod.rs"]
mod marshal;

use std::path::Path;

fn replay(target: &str, run: fn(&[u8])) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/regressions")
        .join(target);
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_file() && path.file_name().is_some_and(|name| name != ".gitkeep") {
                run(&std::fs::read(&path).unwrap());
                count += 1;
            }
        }
    }
    eprintln!(
        "{target}: replayed {count} saved inputs from {}",
        dir.display()
    );
}

#[test]
fn packed_decode_regressions() {
    replay("packed_decode", marshal::packed_decode);
}

#[test]
fn xml_decode_regressions() {
    replay("xml_decode", marshal::xml_decode);
}

/// A few hand-made inputs, so the replay path itself is exercised even while
/// no regression is saved.
#[test]
fn hand_made_inputs() {
    let packed_addr = [0x4b, 0xd4, 0x51, 0x82, 0xd0, 0x42, 0xa0, 0x80, 0x8b];
    for ops in [&[][..], &[0x01, 0x06, 0x4b, 0x0c][..]] {
        let mut input = vec![ops.len() as u8];
        input.extend_from_slice(ops);
        input.extend_from_slice(&packed_addr);
        marshal::packed_decode(&input);
        let mut input = vec![ops.len() as u8];
        input.extend_from_slice(ops);
        input.extend_from_slice(
            br#"<addr space="join" piece1="ram:0x10:4" piece2="register:0x0:4"/>"#,
        );
        marshal::xml_decode(&input);
    }
    marshal::packed_decode(&[]);
    marshal::xml_decode(&[0xff]);
}
