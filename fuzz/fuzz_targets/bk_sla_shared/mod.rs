//! Bodies of the `bk_sla_*` fuzz targets, shared with the regression replay
//! test in `crates/bk-sla/tests/fuzz_regressions.rs`.

#![allow(
    dead_code,
    reason = "shared between the fuzz targets and a replay test"
)]

use bk_sla::{Limits, Sla};

/// Limits small enough that the fuzzer cannot ask for huge allocations.
fn limits() -> Limits {
    Limits {
        inflated_size: 1 << 22,
        ..Limits::default()
    }
}

/// Whatever decodes must encode, and decode again to an equal model.
fn round_trip(sla: &Sla, limits: &Limits) {
    let packed = sla.encode_packed().expect("a decoded model encodes");
    let again = match Sla::decode_packed(&packed, limits) {
        Ok(again) => again,
        Err(error) => panic!("an encoded model does not decode: {error}"),
    };
    assert!(again == *sla, "decode(encode(m)) != m");
    let xml = sla.encode_xml().expect("a decoded model encodes as XML");
    let from_xml = match Sla::decode_xml(&xml, limits) {
        Ok(model) => model,
        Err(error) => panic!("the XML form does not decode: {error}"),
    };
    assert!(from_xml == *sla, "decode_xml(encode_xml(m)) != m");
}

/// `Sla::read` on a whole file (header and zlib container).
pub(crate) fn read(data: &[u8]) {
    let limits = limits();
    if let Ok(sla) = Sla::read(data, &limits) {
        round_trip(&sla, &limits);
    }
}

/// `Sla::decode_packed` on an inflated stream, so the fuzzer is not
/// fighting zlib.
pub(crate) fn decode_packed(data: &[u8]) {
    let limits = limits();
    if let Ok(sla) = Sla::decode_packed(data, &limits) {
        round_trip(&sla, &limits);
    }
}
