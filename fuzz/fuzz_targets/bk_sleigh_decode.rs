//! `bk_sleigh` decoding, text and `prepare` on arbitrary bytes and context
//! (track `sleigh-decode`; body in `bk_sleigh_shared/mod.rs`).

#![no_main]

mod bk_sleigh_shared;

libfuzzer_sys::fuzz_target!(|data: &[u8]| bk_sleigh_shared::decode(data));
