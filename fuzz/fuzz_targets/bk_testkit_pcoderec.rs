//! Arbitrary bytes read as a p-code recording (`pcoderec 1`) by
//! `bk-testkit`, then every address looked up as the replay does. Nothing may
//! panic, and an accepted recording must be written back byte for byte.

#![no_main]

use bk_testkit::oracle::{RecordedPcode, Recording};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(recording) = Recording::parse(text) {
        assert_eq!(recording.write(), text);
        let addrs: Vec<_> = recording.events.iter().map(|e| e.addr().clone()).collect();
        let replay = RecordedPcode::new(recording);
        for a in &addrs {
            let _ = replay.instruction(a);
            let _ = replay.length(a);
        }
    }
});
