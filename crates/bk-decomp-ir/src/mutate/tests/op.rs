//! Unit tests of the op half of the mutation interface. Each test follows
//! the C++ lines it names (`funcdata_op.cc` unless said otherwise); the
//! expected state is written from them.

use std::sync::{Arc, Mutex};

use bk_pcode::OpCode;

use super::Log;
use crate::error::IrError;
use crate::flags::{oflags, vflags};
use crate::ids::OpId;
use crate::ssa::CodeList;
use crate::testing::fx;

#[test]
fn new_op_is_dead_unplaced_and_numbered_by_time() {
    // newOp (322–327) → PcodeOpBank::create (op.cc:983): a dead op in the
    // dead list, the next uniq, no parent.
    let mut fix = fx(1);
    let a = fix.op(OpCode::Copy, 1, 0x100);
    let b = fix.op(OpCode::Copy, 1, 0x100);
    assert_eq!(fix.ssa.op_time(b), fix.ssa.op_time(a) + 1);
    assert!(fix.ssa.op_flags(a) & oflags::DEAD != 0);
    assert_eq!(fix.ssa.ops_dead(), vec![a, b]);
    assert_eq!(fix.ssa.op_parent(a), None);
    // newOp(inputs, seq) (332–337): the given sequence number; a taken one
    // is an error (Basilisk; Ghidra would insert a duplicate key).
    let c = fix.ssa.new_op_at(1, fix.ram(0x200), 7).unwrap();
    assert_eq!(fix.ssa.op_time(c), 7);
    assert!(fix.ssa.new_op_at(1, fix.ram(0x200), 7).is_err());
    fix.ok();
}

#[test]
fn new_indirect_goes_to_alttree_with_an_iop_input() {
    // newIndirect (343–349): createIndirect at the target's address, opcode
    // INDIRECT, input 1 = newVarnodeIop(target).
    let mut fix = fx(1);
    let call = fix.op(OpCode::Call, 1, 0x100);
    let ind = fix.ssa.new_indirect(&mut fix.env, call).unwrap();
    assert_eq!(fix.ssa.op_opcode(ind), Some(OpCode::Indirect));
    assert_eq!(fix.ssa.ops_alt().collect::<Vec<_>>(), vec![ind]);
    assert_eq!(fix.ssa.op_addr(ind), fix.ram(0x100));
    let iop = fix.ssa.op_input(ind, 1).unwrap();
    assert_eq!(fix.ssa.op_from_iop(iop), Some(call));
    assert_eq!(fix.ssa.op_input(ind, 0), None);
    fix.ok();
}

#[test]
fn set_opcode_moves_lists_and_reports_the_change() {
    // opSetOpcode (25–33) → changeOpcode (op.cc:1066): leaves the old
    // opcode's list, joins the new one's; debugModCheck first.
    let mut fix = fx(1);
    let log = Arc::new(Mutex::new(Vec::new()));
    let op = fix.op(OpCode::Load, 2, 0x100);
    assert_eq!(fix.ssa.ops_of(CodeList::Load), vec![op]);
    fix.ssa.set_recorder(Some(Box::new(Log(Arc::clone(&log)))));
    fix.ssa.op_set_opcode(op, OpCode::Store).unwrap();
    assert_eq!(fix.ssa.ops_of(CodeList::Load), [] as [OpId; 0]);
    assert_eq!(fix.ssa.ops_of(CodeList::Store), vec![op]);
    assert_eq!(*log.lock().unwrap(), vec![op]);
    fix.ok();
}

#[test]
fn mark_halt_only_on_return_and_only_halt_bits() {
    // opMarkHalt (37–48).
    let mut fix = fx(1);
    let ret = fix.op(OpCode::Return, 1, 0x100);
    let copy = fix.op(OpCode::Copy, 1, 0x104);
    assert!(matches!(
        fix.ssa.op_mark_halt(copy, oflags::HALT_BITS),
        Err(IrError::HaltNotReturn(_))
    ));
    assert!(matches!(
        fix.ssa.op_mark_halt(ret, oflags::MARK),
        Err(IrError::BadHaltFlag(_))
    ));
    fix.ssa
        .op_mark_halt(ret, oflags::HALT_BITS | oflags::MARK)
        .unwrap();
    assert_eq!(
        fix.ssa.op_flags(ret) & (oflags::HALT_BITS | oflags::MARK),
        oflags::HALT_BITS
    );
}

#[test]
fn set_output_frees_previous_outputs_and_unset_output_frees() {
    // opSetOutput (70–86): unset the op's output, unset vn's def, setDef,
    // setVarnodeProperties, set the output. opUnsetOutput (52–65): the
    // output becomes free, its cover cleared.
    let mut fix = fx(1);
    let a = fix.op(OpCode::Copy, 1, 0x100);
    let b = fix.op(OpCode::Copy, 1, 0x104);
    let x = fix.regvn(0, 4);
    let y = fix.regvn(4, 4);
    assert_eq!(fix.ssa.op_set_output(&mut fix.env, a, x).unwrap(), x);
    assert_eq!(fix.ssa.varnode_def(x), Some(a));
    assert!(fix.ssa.varnode_flags(x) & vflags::WRITTEN != 0);
    // Same output again: nothing happens.
    assert_eq!(fix.ssa.op_set_output(&mut fix.env, a, x).unwrap(), x);
    // x moves to b: a loses its output.
    fix.ssa.op_set_output(&mut fix.env, b, x).unwrap();
    assert_eq!(fix.ssa.op_output(a), None);
    assert_eq!(fix.ssa.varnode_def(x), Some(b));
    // b takes y: x becomes free.
    fix.ssa.op_set_output(&mut fix.env, b, y).unwrap();
    assert_eq!(
        fix.ssa.varnode_flags(x) & (vflags::WRITTEN | vflags::INPUT),
        0
    );
    fix.ssa.op_unset_output(b).unwrap();
    assert_eq!(fix.ssa.varnode_def(y), None);
    // Unset with no output is a no-op.
    fix.ssa.op_unset_output(b).unwrap();
    fix.ok();
}

#[test]
fn set_output_refuses_inputs_and_constants() {
    // VarnodeBank::setDef throws for a varnode that is not free
    // (varnode.cc:1384–1388), Varnode::setDef for a constant (varnode.cc:427–431);
    // Basilisk checks before changing anything.
    let mut fix = fx(1);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    let c = fix.cst(4, 1);
    assert!(matches!(
        fix.ssa.op_set_output(&mut fix.env, op, c),
        Err(IrError::AssignToConstant { .. })
    ));
    let r = fix.regvn(0, 4);
    let r = fix.ssa.set_input_varnode(&mut fix.env, r).unwrap();
    assert!(matches!(
        fix.ssa.op_set_output(&mut fix.env, op, r),
        Err(IrError::DefineNotFree { .. })
    ));
    assert_eq!(fix.ssa.op_output(op), None);
    fix.ok();
}

#[test]
fn set_input_adds_the_reader_and_clones_a_shared_constant() {
    // opSetInput (104–125): a constant with a reader (not a space base) is
    // replaced by a new constant; the old input is unset; addDescend then
    // setInput.
    let mut fix = fx(1);
    let a = fix.op(OpCode::IntAdd, 2, 0x100);
    let c = fix.cst(4, 5);
    fix.ssa.op_set_input(&mut fix.env, a, c, 0).unwrap();
    assert_eq!(fix.ssa.readers(c).collect::<Vec<_>>(), vec![a]);
    fix.ssa.op_set_input(&mut fix.env, a, c, 1).unwrap();
    let c2 = fix.ssa.op_input(a, 1).unwrap();
    assert_ne!(c2, c);
    assert_eq!(fix.ssa.varnode_offset(c2), 5);
    assert_eq!(fix.ssa.readers(c).collect::<Vec<_>>(), vec![a]);
    // Replacing slot 0 unsets the old reader.
    let r = fix.regvn(0, 4);
    let r = fix.ssa.set_input_varnode(&mut fix.env, r).unwrap();
    fix.ssa.op_set_input(&mut fix.env, a, r, 0).unwrap();
    assert_eq!(fix.ssa.readers(c).collect::<Vec<_>>(), [] as [OpId; 0]);
    // A free varnode may have one reader only (Varnode::addDescend,
    // varnode.cc:330–336).
    let b = fix.op(OpCode::Copy, 1, 0x104);
    let free = fix.regvn(8, 4);
    fix.ssa.op_set_input(&mut fix.env, b, free, 0).unwrap();
    assert!(matches!(
        fix.ssa.op_set_input(&mut fix.env, a, free, 1),
        Err(IrError::FreeMultipleDescendants(_))
    ));
    assert_eq!(fix.ssa.op_input(a, 1), Some(c2));
    fix.ok();
}

#[test]
fn unset_and_swap_inputs() {
    // opUnsetInput (92–99); opSwapInput (131–141): the slots exchange, the
    // reader lists stay.
    let mut fix = fx(1);
    let x = fix.cst(4, 1);
    let y = fix.cst(4, 2);
    let a = fix.op(OpCode::IntSub, 2, 0x100);
    fix.ssa.op_set_input(&mut fix.env, a, x, 0).unwrap();
    fix.ssa.op_set_input(&mut fix.env, a, y, 1).unwrap();
    fix.ssa.op_swap_input(a, 0, 1).unwrap();
    assert_eq!(
        fix.ssa.op_inputs(a).collect::<Vec<_>>(),
        vec![Some(y), Some(x)]
    );
    fix.ssa.op_unset_input(a, 0).unwrap();
    assert_eq!(fix.ssa.readers(y).collect::<Vec<_>>(), [] as [OpId; 0]);
    assert_eq!(fix.ssa.op_input(a, 0), None);
    assert!(matches!(
        fix.ssa.op_unset_input(a, 0),
        Err(IrError::EmptySlot { .. })
    ));
    assert!(matches!(
        fix.ssa.op_swap_input(a, 0, 2),
        Err(IrError::NoSuchSlot { .. })
    ));
}

#[test]
fn insert_and_uninsert() {
    // opInsert (150–158): markAlive, BlockBasic::insert. opUninsert
    // (164–173): markDead, removeOp.
    let mut fix = fx(1);
    let b0 = fix.blocks[0];
    let a = fix.op(OpCode::Copy, 1, 0x100);
    let b = fix.op(OpCode::Copy, 1, 0x104);
    fix.ssa.op_insert(a, b0, None).unwrap();
    fix.ssa.op_insert(b, b0, Some(a)).unwrap();
    assert_eq!(fix.ssa.block_ops(b0).collect::<Vec<_>>(), vec![b, a]);
    assert_eq!(fix.ssa.ops_alive(), vec![a, b]);
    assert!(fix.ssa.op_order(b) < fix.ssa.op_order(a));
    assert!(fix.ssa.op_insert(a, b0, None).is_err());
    fix.ssa.op_uninsert(a).unwrap();
    assert_eq!(fix.ssa.block_ops(b0).collect::<Vec<_>>(), vec![b]);
    assert_eq!(fix.ssa.ops_dead(), vec![a]);
    assert!(fix.ssa.op_uninsert(a).is_err());
    fix.ok();
}

#[test]
fn unlink_detaches_everything_and_keeps_the_op() {
    // opUnlink (179–195).
    let mut fix = fx(1);
    let x = fix.cst(4, 1);
    let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[x]);
    let out = fix.ssa.op_output(a).unwrap();
    fix.ssa.op_unlink(a).unwrap();
    assert_eq!(fix.ssa.op_output(a), None);
    assert!(fix.ssa.varnode_exists(out));
    assert_eq!(fix.ssa.readers(x).collect::<Vec<_>>(), [] as [OpId; 0]);
    assert_eq!(fix.ssa.op_parent(a), None);
    assert!(!fix.ssa.op_is_retired(a));
    fix.ok();
}

#[test]
fn destroy_deletes_the_output_and_destroy_raw_retires() {
    // opDestroy (203–221): destroyVarnode(out), unset inputs, markDead and
    // removeOp — the op stays in the dead list. opDestroyRaw (253–260):
    // destroys inputs and output, then PcodeOpBank::destroy.
    let mut fix = fx(1);
    let src1 = fix.cst(4, 1);
    let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[src1]);
    let out = fix.ssa.op_output(a).unwrap();
    fix.ssa.op_destroy(a).unwrap();
    assert!(!fix.ssa.varnode_exists(out));
    assert!(fix.ssa.varnode_exists(src1));
    assert_eq!(fix.ssa.ops_dead(), vec![a]);
    assert!(!fix.ssa.op_is_retired(a));
    fix.ok();
    let src2 = fix.cst(4, 2);
    let b = fix.op(OpCode::Copy, 1, 0x104);
    fix.ssa.op_set_input(&mut fix.env, b, src2, 0).unwrap();
    fix.ssa.op_destroy_raw(b).unwrap();
    assert!(!fix.ssa.varnode_exists(src2));
    assert!(fix.ssa.op_is_retired(b));
    assert_eq!(fix.ssa.ops_retired(), &[b]);
    fix.ok();
    // An op in a block cannot be retired.
    let c = fix.emit(0, OpCode::Copy, 0x108, None, &[]);
    assert!(matches!(
        fix.ssa.op_destroy_raw(c),
        Err(IrError::IntegratedOp(_))
    ));
}

#[test]
fn destroy_recursive_follows_lone_reader_defs_but_not_calls() {
    // opDestroyRecursive (228–249): breadth first over inputs that are
    // written, not autolive, with a lone descendant, whose def is neither
    // a call nor an indirect source.
    let mut fix = fx(1);
    let k = fix.cst(4, 3);
    let d1 = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[k]);
    let v1 = fix.ssa.op_output(d1).unwrap();
    let call = fix.emit(0, OpCode::Call, 0x104, Some(4), &[]);
    let v2 = fix.ssa.op_output(call).unwrap();
    let k2 = fix.cst(4, 4);
    let shared = fix.emit(0, OpCode::Copy, 0x108, Some(8), &[k2]);
    let v3 = fix.ssa.op_output(shared).unwrap();
    let other = fix.emit(0, OpCode::Copy, 0x10c, Some(12), &[v3]);
    let top = fix.emit(0, OpCode::IntAdd, 0x110, Some(16), &[v1, v2]);
    let top2 = fix.emit(
        0,
        OpCode::IntAdd,
        0x114,
        Some(20),
        &[fix.ssa.op_output(top).unwrap(), v3],
    );
    fix.ssa.op_destroy_recursive(top2).unwrap();
    // top (lone reader of its output) and d1 go; the call stays; `shared`
    // stays because v3 has another reader.
    let b0 = fix.blocks[0];
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![call, shared, other]
    );
    fix.ok();
}

#[test]
fn set_all_remove_and_insert_input() {
    // opSetAllInput (267–285), opRemoveInput (291–300), opInsertInput
    // (308–316).
    let mut fix = fx(1);
    let (x, y, z) = (fix.cst(4, 1), fix.cst(4, 2), fix.cst(4, 3));
    let a = fix.op(OpCode::MultiEqual, 1, 0x100);
    fix.ssa.op_set_input(&mut fix.env, a, x, 0).unwrap();
    fix.ssa.op_set_all_input(&mut fix.env, a, &[y, z]).unwrap();
    assert_eq!(
        fix.ssa.op_inputs(a).collect::<Vec<_>>(),
        vec![Some(y), Some(z)]
    );
    assert_eq!(fix.ssa.readers(x).collect::<Vec<_>>(), [] as [OpId; 0]);
    fix.ssa.op_remove_input(a, 0).unwrap();
    assert_eq!(fix.ssa.op_inputs(a).collect::<Vec<_>>(), vec![Some(z)]);
    assert_eq!(fix.ssa.readers(y).collect::<Vec<_>>(), [] as [OpId; 0]);
    fix.ssa.op_insert_input(&mut fix.env, a, x, 0).unwrap();
    assert_eq!(
        fix.ssa.op_inputs(a).collect::<Vec<_>>(),
        vec![Some(x), Some(z)]
    );
    fix.ssa.op_insert_input(&mut fix.env, a, y, 2).unwrap();
    assert_eq!(
        fix.ssa.op_inputs(a).collect::<Vec<_>>(),
        vec![Some(x), Some(z), Some(y)]
    );
    assert!(fix.ssa.op_insert_input(&mut fix.env, a, y, 9).is_err());
    fix.ok();
}

#[test]
fn clone_op_copies_marks_and_clones_varnodes() {
    // cloneOp (630–643): new op at seq, same opcode, startmark|startbasic,
    // output and inputs cloned (cloneVarnode, funcdata_varnode.cc:266).
    let mut fix = fx(1);
    let r = fix.regvn(0, 4);
    let a = fix.emit(0, OpCode::Copy, 0x100, Some(4), &[r]);
    fix.ssa
        .op_set_flags(a, oflags::STARTMARK | oflags::MARK)
        .unwrap();
    let at200 = fix.ram(0x200);
    let c = fix.ssa.clone_op(&mut fix.env, a, at200, 9).unwrap();
    assert_eq!(fix.ssa.op_opcode(c), Some(OpCode::Copy));
    assert_eq!(
        fix.ssa.op_flags(c) & (oflags::STARTMARK | oflags::MARK),
        oflags::STARTMARK
    );
    let ci = fix.ssa.op_input(c, 0).unwrap();
    assert_ne!(ci, r);
    assert_eq!(fix.ssa.varnode_addr(ci), fix.ssa.varnode_addr(r));
    let co = fix.ssa.op_output(c).unwrap();
    assert_eq!(fix.ssa.varnode_addr(co), fix.reg(4));
    fix.ok();
}

#[test]
fn new_op_before_makes_a_unique_output_of_in1s_size() {
    // newOpBefore (670–687).
    let mut fix = fx(1);
    let follow = fix.emit(0, OpCode::Return, 0x100, None, &[]);
    let (x, y) = (fix.cst(2, 1), fix.cst(2, 2));
    let op = fix
        .ssa
        .new_op_before(&mut fix.env, follow, OpCode::IntAdd, (x, y, None))
        .unwrap();
    let out = fix.ssa.op_output(op).unwrap();
    assert_eq!(fix.ssa.varnode_size(out), 2);
    assert_eq!(
        fix.ssa.varnode_addr(out).space(),
        fix.ssa.spaces().unique_space().map(bk_core::Space::id)
    );
    assert_eq!(
        fix.ssa.block_ops(fix.blocks[0]).collect::<Vec<_>>(),
        vec![op, follow]
    );
    assert_eq!(fix.ssa.op_addr(op), fix.ram(0x100));
    fix.ok();
}

#[test]
fn indirect_op_and_indirect_creation() {
    // newIndirectOp (697–711) and newIndirectCreation (722–739); then
    // markIndirectCreation (746–757).
    let mut fix = fx(1);
    let call = fix.emit(0, OpCode::Call, 0x100, None, &[]);
    let at = fix.reg(0x20);
    let ind = fix
        .ssa
        .new_indirect_op(&mut fix.env, call, at, 4, oflags::NOCOLLAPSE)
        .unwrap();
    assert!(fix.ssa.op_flags(ind) & oflags::NOCOLLAPSE != 0);
    assert_eq!(fix.ssa.varnode_addr(fix.ssa.op_input(ind, 0).unwrap()), at);
    assert_eq!(fix.ssa.varnode_addr(fix.ssa.op_output(ind).unwrap()), at);
    let cr = fix
        .ssa
        .new_indirect_creation(&mut fix.env, call, at, 4, false)
        .unwrap();
    let cin = fix.ssa.op_input(cr, 0).unwrap();
    assert!(fix.ssa.is_constant(cin));
    assert!(fix.ssa.varnode_flags(cin) & vflags::INDIRECT_CREATION != 0);
    assert!(fix.ssa.op_flags(cr) & oflags::INDIRECT_CREATION != 0);
    assert_eq!(
        fix.ssa.block_ops(fix.blocks[0]).collect::<Vec<_>>(),
        vec![ind, cr, call]
    );
    fix.ok();
    // markIndirectCreation on the plain INDIRECT: input 0 is not a
    // constant, an error before anything changes (Ghidra sets the op flag
    // first, 751).
    assert!(matches!(
        fix.ssa.mark_indirect_creation(ind, true),
        Err(IrError::IndirectCreation(_))
    ));
    assert_eq!(fix.ssa.op_flags(ind) & oflags::INDIRECT_CREATION, 0);
}

#[test]
fn negate_condition_flips_both_bits() {
    // BlockBasic::negateCondition's op half (block.cc:2369–2374): boolean_flip
    // and fallthru_true toggle.
    let mut fix = fx(1);
    let op = fix.op(OpCode::CBranch, 2, 0x100);
    fix.ssa.op_negate_condition(op).unwrap();
    assert_eq!(
        fix.ssa.op_flags(op) & (oflags::BOOLEAN_FLIP | oflags::FALLTHRU_TRUE),
        oflags::BOOLEAN_FLIP | oflags::FALLTHRU_TRUE
    );
    fix.ssa.op_negate_condition(op).unwrap();
    assert_eq!(
        fix.ssa.op_flags(op) & (oflags::BOOLEAN_FLIP | oflags::FALLTHRU_TRUE),
        0
    );
}
