//! Arbitrary bytes read as a state dump and loaded into `bk-decomp-ir`'s IR
//! (spec 6, test 11). Loading may refuse the dump but may not panic;
//! whatever loads keeps the IR's invariants, writes back, and the written
//! dump loads to a state that writes back the same.

#![no_main]

mod bk_testkit_shared;

use std::sync::Arc;

use bk_core::NoRegisters;
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_testkit::oracle::{StateDump, gunzip};
use libfuzzer_sys::fuzz_target;

const SAMPLE: &[u8] = include_bytes!("../../crates/bk-testkit/tests/data/oracle/switchind.end.state.gz");

fuzz_target!(|data: &[u8]| {
    let sample = gunzip(SAMPLE).unwrap_or_default();
    let Some(text) = bk_testkit_shared::text(data, &sample) else {
        return;
    };
    let Ok(dump) = StateDump::parse(&text) else {
        return;
    };
    let Ok(spaces) = spaces_from_dump(&dump, Arc::new(NoRegisters)) else {
        return;
    };
    let spaces = Arc::new(spaces);
    let Ok(ssa) = load(&dump, Arc::clone(&spaces)) else {
        return;
    };
    let bad = ssa.invariant_violations();
    assert!(bad.is_empty(), "{bad:?}");
    let names = DumpNames::from_dump(&dump, &spaces);
    let _ = ssa.print_raw(&names);
    let Ok(once) = write(&ssa, &dump, &names, &CanonicalCalls::Identity) else {
        return;
    };
    let again = StateDump::parse(&once).expect("written dump parses");
    let reloaded = load(&again, Arc::clone(&spaces)).expect("written dump loads");
    let names2 = DumpNames::from_dump(&again, &spaces);
    let twice = write(&reloaded, &again, &names2, &CanonicalCalls::Identity).expect("writes");
    assert!(once == twice, "dump → load → dump is not the identity");
});
