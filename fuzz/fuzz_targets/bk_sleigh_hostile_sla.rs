//! A `.sla` model that passed `bk_sla`'s validation must never make the
//! decoder panic or loop (track `sleigh-decode`; body in
//! `bk_sleigh_shared/mod.rs`).

#![no_main]

mod bk_sleigh_shared;

libfuzzer_sys::fuzz_target!(|data: &[u8]| bk_sleigh_shared::hostile_sla(data));
