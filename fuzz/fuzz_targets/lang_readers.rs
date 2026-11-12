//! The `.ldefs`, `.pspec` and `.opinion` readers on arbitrary bytes, in
//! both modes, and the values they hand on: addresses and opinion
//! secondary-key patterns. Nothing may panic (ADR-009).
//!
//! Seed with Ghidra's files, for example
//! `find ../ghidra/Ghidra -name '*.pspec' -o -name '*.ldefs' -o -name '*.opinion' | xargs -I{} cp {} corpus/lang_readers/`.

#![no_main]

use bk_lang::{Mode, ldefs, opinion, pspec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The readers take text; files are refused unless they are UTF-8.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for mode in [Mode::Strict, Mode::Lenient] {
        let _ = ldefs::parse(text, mode);
        if let Ok(parsed) = pspec::parse(text, mode) {
            for block in &parsed.value.default_memory_blocks {
                let _ = block.start_address.offset();
            }
        }
        if let Ok(parsed) = opinion::parse(text, mode) {
            for constraint in parsed.value.resolved() {
                if let Some(secondary) = &constraint.secondary {
                    let _ = opinion::secondary_attribute_matches("-1", secondary);
                    let _ = opinion::secondary_attribute_matches("12345", secondary);
                }
            }
        }
    }
});
