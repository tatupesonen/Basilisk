//! `bk-decomp-symbols`: see `bk_decomp_symbols_shared` (target `BinaryImage`).
//! The process must not panic, overflow the stack or hang.

#![no_main]

mod bk_decomp_symbols_shared;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    bk_decomp_symbols_shared::run(bk_decomp_symbols_shared::Target::BinaryImage, data);
});
