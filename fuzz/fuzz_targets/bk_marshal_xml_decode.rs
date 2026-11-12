//! The XML parser, the XML decoder and the address-model decoders built on
//! it, on arbitrary bytes (track `core-marshal`; body in `bk_marshal_shared/mod.rs`).

#![no_main]

mod bk_marshal_shared;

libfuzzer_sys::fuzz_target!(|data: &[u8]| bk_marshal_shared::xml_decode(data));
