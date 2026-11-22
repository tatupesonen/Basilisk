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
//! Spec 6, test 6 (the dump half): on any state reachable by mutation
//! calls from a loaded dump, dump → load → dump is the identity, and the
//! invariants hold after every call. The calls are those that never leave
//! an op with an empty input slot: `bkstate` writes such a slot as `-`
//! (`tools/reference/consoleext/bk_ids.cc:42`) but `bk-testkit` reads an
//! op's inputs as a plain list, so those states are not expressible yet
//! (a follow-up for the dump reader); the in-memory property test in
//! `src/mutate/tests/props.rs` covers the other calls.

mod support;

use std::sync::Arc;

use bk_core::NoRegisters;
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_decomp_ir::{OpId, Ssa, TableEnv, VarnodeId};
use bk_pcode::OpCode;
use bk_testkit::oracle::{StateDump, read_text, sample_dir};
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum Act {
    Const(u8),
    SetInput(u16, u16, u8),
    SetOutput(u16, u16),
    UnsetOutput(u16),
    Uninsert(u16),
    InsertBegin(u16, u16),
    NewCopy(u16, u16),
    SetOpcode(u16, bool),
    ClearDead,
}

fn act() -> impl Strategy<Value = Act> {
    let id = any::<u16>;
    prop_oneof![
        any::<u8>().prop_map(Act::Const),
        (id(), id(), 0..3u8).prop_map(|(o, v, s)| Act::SetInput(o, v, s)),
        (id(), id()).prop_map(|(o, v)| Act::SetOutput(o, v)),
        id().prop_map(Act::UnsetOutput),
        id().prop_map(Act::Uninsert),
        (id(), id()).prop_map(|(o, b)| Act::InsertBegin(o, b)),
        (id(), id()).prop_map(|(v, b)| Act::NewCopy(v, b)),
        (id(), any::<bool>()).prop_map(|(o, c)| Act::SetOpcode(o, c)),
        Just(Act::ClearDead),
    ]
}

fn pick<T: Copy>(list: &[T], i: u16) -> Option<T> {
    (!list.is_empty()).then(|| list[usize::from(i) % list.len()])
}

fn apply(ssa: &mut Ssa, env: &mut TableEnv, a: &Act) {
    let vns: Vec<VarnodeId> = ssa.loc_order().collect();
    let ops: Vec<OpId> = ssa.ops_main().chain(ssa.ops_alt()).collect();
    let blocks: Vec<_> = ssa.blocks().collect();
    // Refusals are fine here; only consistency and the round trip count.
    let _ = (|| -> Option<()> {
        match *a {
            Act::Const(v) => drop(ssa.new_constant(env, 4, u64::from(v))),
            Act::SetInput(o, v, s) => {
                let o = pick(&ops, o)?;
                drop(ssa.op_set_input(env, o, pick(&vns, v)?, usize::from(s)));
            }
            Act::SetOutput(o, v) => drop(ssa.op_set_output(env, pick(&ops, o)?, pick(&vns, v)?)),
            Act::UnsetOutput(o) => drop(ssa.op_unset_output(pick(&ops, o)?)),
            Act::Uninsert(o) => drop(ssa.op_uninsert(pick(&ops, o)?)),
            Act::InsertBegin(o, b) => drop(ssa.op_insert_begin(pick(&ops, o)?, pick(&blocks, b)?)),
            Act::NewCopy(v, b) => {
                let (v, b) = (pick(&vns, v)?, pick(&blocks, b)?);
                let at = ssa.block_start(b);
                let op = ssa.new_op(1, at).ok()?;
                ssa.op_set_opcode(op, OpCode::Copy).ok()?;
                if ssa.op_set_input(env, op, v, 0).is_err() {
                    // Retire the half-built op (a free `v` with a reader).
                    ssa.op_destroy_raw(op).unwrap();
                    return None;
                }
                let size = ssa.varnode_size(v);
                ssa.new_unique_out(env, size, op).ok()?;
                drop(ssa.op_insert_begin(op, b));
            }
            Act::SetOpcode(o, c) => {
                let opc = if c { OpCode::IntAdd } else { OpCode::Copy };
                drop(ssa.op_set_opcode(pick(&ops, o)?, opc));
            }
            Act::ClearDead => drop(ssa.clear_dead_varnodes()),
        }
        Some(())
    })();
}

proptest! {
    #[test]
    fn reachable_states_round_trip_through_the_dump(acts in proptest::collection::vec(act(), 1..40)) {
        let text = read_text(&sample_dir().join("switchind.p3.state.gz")).unwrap();
        let dump = StateDump::parse(&text).unwrap();
        let spaces = Arc::new(spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap());
        let names = DumpNames::from_dump(&dump, &spaces);
        let mut ssa = load(&dump, Arc::clone(&spaces)).unwrap();
        let mut env = TableEnv::default();
        for a in &acts {
            apply(&mut ssa, &mut env, a);
            let bad = ssa.invariant_violations();
            prop_assert!(bad.is_empty(), "after {:?}: {:#?}", a, bad);
        }
        let once = write(&ssa, &dump, &names, &CanonicalCalls::Identity).unwrap();
        let reparsed = StateDump::parse(&once).unwrap();
        let again = load(&reparsed, Arc::clone(&spaces)).unwrap();
        prop_assert!(again.invariant_violations().is_empty());
        let names2 = DumpNames::from_dump(&reparsed, &spaces);
        let twice = write(&again, &reparsed, &names2, &CanonicalCalls::Identity).unwrap();
        prop_assert!(once == twice, "dump → load → dump differs");
    }
}
