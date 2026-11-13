//! Differential tests against Ghidra's reference build (`features/sla.md`
//! section 6, tests 1–3). They need `BASILISK_REFERENCE_DIR` (default
//! `../reference`) and skip with a printed reason when it is absent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

use bk_sla::{Limits, PackedReader, Sla, inflate};

/// Test 1: for every reference `.sla`, the packed stream re-encoded from the
/// model equals the inflated file byte for byte, through both packed
/// decoders, and the two decoders give equal models.
#[test]
fn packed_round_trip_is_byte_exact() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let files = reference.sla_files().unwrap();
    assert_eq!(files.len(), 150, "expected the 150 reference languages");
    let limits = Limits::default();
    let mut failures = Vec::new();
    for file in &files {
        let bytes = std::fs::read(&file.path).unwrap();
        let stream = inflate(&bytes, &limits).unwrap();
        let sla = match Sla::decode_packed(&stream, &limits) {
            Ok(sla) => sla,
            Err(error) => {
                failures.push(format!("{}/{}: {error}", file.module, file.name));
                continue;
            }
        };
        let encoded = sla.encode_packed().unwrap();
        if encoded != stream {
            let at = encoded.iter().zip(&stream).position(|(a, b)| a != b);
            failures.push(format!(
                "{}/{}: re-encoded stream differs (lengths {} vs {}, first difference at {at:?})",
                file.module,
                file.name,
                encoded.len(),
                stream.len()
            ));
            continue;
        }
        let other = Sla::decode_packed_using(&stream, &limits, PackedReader::Marshal).unwrap();
        if other != sla {
            failures.push(format!("{}/{}: the two packed decoders disagree", file.module, file.name));
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}
