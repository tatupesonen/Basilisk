//! `bk_sleigh` p-code generation on arbitrary bytes and context, on the
//! fixture languages and (with `BASILISK_REFERENCE_DIR`) some reference
//! languages (track `sleigh-pcode`; body in `bk_sleigh_shared/mod.rs`).

#![no_main]

mod bk_sleigh_shared;

libfuzzer_sys::fuzz_target!(|data: &[u8]| bk_sleigh_shared::lift(data));
