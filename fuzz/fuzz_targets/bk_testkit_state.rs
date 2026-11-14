//! Arbitrary bytes read as a state dump (`bkstate 1`) by `bk-testkit`'s
//! oracle reader. It may not panic, and whatever it accepts must be written
//! back byte for byte.

#![no_main]

use bk_testkit::oracle::StateDump;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(dump) = StateDump::parse(text) {
        assert_eq!(dump.write(), text);
        for v in &dump.varnodes {
            let _ = dump.varnode(v.id);
        }
    }
});
