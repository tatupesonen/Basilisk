//! Arbitrary bytes read as a structure dump (`bkstruct 1`) and as an action
//! list (`bkactions 1`) by `bk-testkit`'s oracle readers. Neither may panic,
//! and whatever is accepted must be written back byte for byte.

#![no_main]

use bk_testkit::oracle::{ActionList, StructureDump};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(dump) = StructureDump::parse(text) {
        assert_eq!(dump.write(), text);
    }
    if let Ok(list) = ActionList::parse(text) {
        assert_eq!(list.write(), text);
        for entry in &list.entries {
            let _ = (entry.position(), entry.name(), entry.depth());
        }
    }
});
