//! Arbitrary bytes read as console output holding a decompiler trace
//! (`DEBUG n: name` records) by `bk-testkit`. Extraction may not panic, and
//! the records written back must extract to the same records.

#![no_main]

mod bk_testkit_shared;

use bk_testkit::oracle::Trace;
use libfuzzer_sys::fuzz_target;

const SAMPLE: &str = "Decompiling f\nDEBUG 0: constbase\n0x001006ca:287: **\n   0x001006ca:287: DF(0x001006ca:287) = #0x0:1\n\n\
DEBUG 1: extrapopsetup\n0x00100708:288: **\n   0x00100708:288: RSP(0x00100708:288) = RSP(free) + #0x8\n\nDecompilation complete\n";

fuzz_target!(|data: &[u8]| {
    let Some(text) = bk_testkit_shared::text(data, SAMPLE) else {
        return;
    };
    if let Ok(trace) = Trace::extract(&text) {
        let written = trace.write();
        assert_eq!(Trace::extract(&written).ok(), Some(trace));
    }
});
