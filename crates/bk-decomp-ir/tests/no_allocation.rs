//! The borrowed accessors do not allocate, and a cover rebuild through a
//! wide join block allocates for the cover it builds, not per in-edge
//! visited (review step B, item 1). Its own test binary because `dhat`
//! replaces the global allocator.

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

use std::sync::Arc;

use bk_core::{Address, Space, SpaceManager};
use bk_decomp_ir::{NodeId, Ssa, TableEnv, VarnodeId, VnClass};
use bk_pcode::OpCode;

const W: usize = 1_000;

/// An entry block defining a value, `W` blocks between it and one join
/// block, and a tail block reading the value twice.
fn wide_join() -> (Ssa, VarnodeId, NodeId) {
    let mut m = SpaceManager::new();
    for s in [
        Space::constant(),
        Space::processor("ram", false, 8, 1, 1, true, 0, 0).unwrap(),
        Space::processor("register", false, 4, 1, 2, false, 0, 0).unwrap(),
        Space::unique(3, false).unwrap(),
        Space::fspec(4).unwrap(),
        Space::iop(5).unwrap(),
        Space::join(6, false).unwrap(),
    ] {
        m.insert_space(s).unwrap();
    }
    let ram = m.space_by_name("ram").unwrap().id();
    let pc = Address::new(ram, 0x1000);
    let mut ssa = Ssa::new(Arc::new(m), 0x1000_0000).unwrap();
    let mut env = TableEnv::default();
    let entry = ssa.add_block(0).unwrap();
    let cases: Vec<_> = (0..W).map(|_| ssa.add_block(0).unwrap()).collect();
    let join = ssa.add_block(0).unwrap();
    let tail = ssa.add_block(0).unwrap();
    let order = std::iter::once(entry)
        .chain(cases.iter().copied())
        .chain([join, tail]);
    for (index, b) in (0..).zip(order) {
        ssa.cfg_mut().set_index(b, index).unwrap();
    }
    for &c in &cases {
        ssa.cfg_mut().add_edge(entry, c).unwrap();
        ssa.cfg_mut().add_edge(c, join).unwrap();
    }
    ssa.cfg_mut().add_edge(join, tail).unwrap();
    let def = ssa.new_op(1, pc).unwrap();
    ssa.op_set_opcode(def, OpCode::Copy).unwrap();
    let c = ssa.new_constant(&mut env, 4, 7).unwrap();
    ssa.op_set_input(&mut env, def, c, 0).unwrap();
    let vn = ssa.new_unique_out(&mut env, 4, def).unwrap();
    ssa.op_insert(def, entry, None).unwrap();
    for i in 0..2 {
        let read = ssa.new_op(2, pc.add(ssa.spaces(), 0x100 + i)).unwrap();
        ssa.op_set_opcode(read, OpCode::IntAdd).unwrap();
        ssa.op_set_input(&mut env, read, vn, 0).unwrap();
        ssa.op_set_input(&mut env, read, vn, 1).unwrap();
        ssa.new_unique_out(&mut env, 4, read).unwrap();
        ssa.op_insert(read, tail, None).unwrap();
    }
    (ssa, vn, tail)
}

#[test]
fn borrowed_accessors_do_not_allocate_and_covers_do_not_allocate_per_edge() {
    let (ssa, vn, tail) = wide_join();
    let space = ssa.varnode_addr(vn).space().unwrap();
    let _profiler = dhat::Profiler::builder().testing().build();

    let before = dhat::HeapStats::get();
    let mut sink = 0usize;
    for op in ssa.block_ops(tail) {
        sink += ssa.op_inputs(op).flatten().count();
        sink += ssa.reader(vn, 1).map_or(0, bk_decomp_ir::OpId::index);
    }
    sink += ssa.readers(vn).len();
    sink += ssa.loc_in_space(space).count();
    sink += ssa.loc_at(ssa.varnode_addr(vn)).count();
    sink += ssa.loc_sized(4, ssa.varnode_addr(vn)).count();
    sink += ssa
        .loc_class(4, ssa.varnode_addr(vn), VnClass::Written)
        .count();
    sink += ssa.def_class(VnClass::Written).count();
    sink += ssa.cfg().ins(tail).len() + ssa.cfg().in_len(tail);
    let after = dhat::HeapStats::get();
    assert_eq!(after.total_blocks, before.total_blocks, "sink {sink}");

    let before = dhat::HeapStats::get();
    let cover = ssa.compute_cover(vn).unwrap();
    let after = dhat::HeapStats::get();
    assert_eq!(cover.iter().count(), W + 3);
    // The cover's own map takes about W / 5 nodes; the walk used to
    // allocate an in-edge list on every one of its W + 1 steps through the
    // join block.
    let blocks = after.total_blocks - before.total_blocks;
    assert!(blocks < (W / 2) as u64, "{blocks} allocations");
}
