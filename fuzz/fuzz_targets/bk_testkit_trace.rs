//! Arbitrary bytes read as console output holding a decompiler trace
//! (`DEBUG n: name` records) by `bk-testkit`. Extraction may not panic, and
//! the records written back must extract to the same records.

#![no_main]

use bk_testkit::oracle::Trace;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(trace) = Trace::extract(text) {
        let written = trace.write();
        assert_eq!(Trace::extract(&written).ok(), Some(trace));
    }
});
