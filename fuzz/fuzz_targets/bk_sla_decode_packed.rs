//! `bk_sla::Sla::decode_packed` on arbitrary inflated streams (track `sla`;
//! body in `bk_sla_shared/mod.rs`).

#![no_main]

mod bk_sla_shared;

libfuzzer_sys::fuzz_target!(|data: &[u8]| bk_sla_shared::decode_packed(data));
