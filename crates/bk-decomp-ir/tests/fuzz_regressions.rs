#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]
//! Replays every input the fuzzer found for `bk_decomp_ir_state`
//! (`fuzz/regressions/bk_decomp_ir_state/`) through the target's own input
//! transformation and checks: no panic; a loaded state keeps the
//! invariants; dump → load → dump is the identity.

#[path = "../../../fuzz/fuzz_targets/bk_testkit_shared/mod.rs"]
mod shared;

use std::sync::Arc;

use bk_core::NoRegisters;
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_testkit::oracle::{StateDump, read_text, sample_dir};
use bk_testkit::workspace_root;

fn check(text: &str) {
    let Ok(dump) = StateDump::parse(text) else {
        return;
    };
    let Ok(spaces) = spaces_from_dump(&dump, Arc::new(NoRegisters)) else {
        return;
    };
    let spaces = Arc::new(spaces);
    let Ok(ssa) = load(&dump, Arc::clone(&spaces)) else {
        return;
    };
    assert_eq!(ssa.invariant_violations(), Vec::<String>::new());
    let names = DumpNames::from_dump(&dump, &spaces);
    let _ = ssa.print_raw(&names);
    let Ok(once) = write(&ssa, &dump, &names, &CanonicalCalls::Identity) else {
        return;
    };
    let again = StateDump::parse(&once).unwrap();
    let reloaded = load(&again, Arc::clone(&spaces)).unwrap();
    let names2 = DumpNames::from_dump(&again, &spaces);
    assert_eq!(
        write(&reloaded, &again, &names2, &CanonicalCalls::Identity).unwrap(),
        once
    );
}

#[test]
fn fuzz_regressions_replay() {
    let sample = read_text(&sample_dir().join("switchind.end.state.gz")).unwrap();
    let dir = workspace_root().join("fuzz/regressions/bk_decomp_ir_state");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let data = std::fs::read(e.unwrap().path()).unwrap();
        if let Some(text) = shared::text(&data, &sample) {
            check(&text);
        }
        n += 1;
    }
    assert!(n > 0);
}
