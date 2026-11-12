//! The packed decoder and the address-model decoders built on it, on
//! arbitrary bytes (track `core-marshal`; body in `marshal/mod.rs`).

#![no_main]

mod marshal;

libfuzzer_sys::fuzz_target!(|data: &[u8]| marshal::packed_decode(data));
