//! Arbitrary bytes read as a structure dump (`bkstruct 1`) and as an action
//! list (`bkactions 1`) by `bk-testkit`'s oracle readers. Neither may panic,
//! and whatever is accepted must be written back byte for byte.

#![no_main]

mod bk_testkit_shared;

use bk_testkit::oracle::{ActionList, StructureDump};
use libfuzzer_sys::fuzz_target;

const STRUCT: &str = include_str!("../../crates/bk-testkit/tests/data/oracle/random.trace.bks");
const ACTIONS: &str = include_str!("../../crates/bk-testkit/tests/data/oracle/decompile.actions");

fuzz_target!(|data: &[u8]| {
    let pick = data.get(1).copied().unwrap_or(0) % 2;
    let Some(text) = bk_testkit_shared::text(data, if pick == 0 { STRUCT } else { ACTIONS }) else {
        return;
    };
    if let Ok(dump) = StructureDump::parse(&text) {
        assert_eq!(dump.write(), text);
    }
    if let Ok(list) = ActionList::parse(&text) {
        assert_eq!(list.write(), text);
        for entry in &list.entries {
            let _ = (entry.position(), entry.name(), entry.depth());
        }
    }
});
