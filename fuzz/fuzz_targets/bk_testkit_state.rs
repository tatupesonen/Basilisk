//! Arbitrary bytes read as a state dump (`bkstate 1`) by `bk-testkit`'s
//! oracle reader. It may not panic, and whatever it accepts must be written
//! back byte for byte.

#![no_main]

mod bk_testkit_shared;

use bk_testkit::oracle::{StateDump, gunzip};
use libfuzzer_sys::fuzz_target;

const SAMPLE: &[u8] = include_bytes!("../../crates/bk-testkit/tests/data/oracle/switchind.end.state.gz");

fuzz_target!(|data: &[u8]| {
    let sample = gunzip(SAMPLE).unwrap_or_default();
    let Some(text) = bk_testkit_shared::text(data, &sample) else {
        return;
    };
    if let Ok(dump) = StateDump::parse(&text) {
        assert_eq!(dump.write(), text);
        for v in &dump.varnodes {
            let _ = dump.varnode(v.id);
        }
    }
});
