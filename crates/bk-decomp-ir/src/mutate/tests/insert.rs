//! Unit tests of the placement methods (`funcdata_op.cc:359`–`460`).

use bk_pcode::OpCode;

use crate::testing::fx;

#[test]
fn insert_before_steps_back_over_indirects() {
    // opInsertBefore (359–378): unless op is an INDIRECT, it goes before the
    // run of INDIRECTs immediately preceding follow.
    let mut fix = fx(1);
    let b0 = fix.blocks[0];
    let first = fix.emit(0, OpCode::Copy, 0x100, None, &[]);
    let call = fix.emit(0, OpCode::Call, 0x104, None, &[]);
    let at = fix.reg(0x20);
    let ind = fix
        .ssa
        .new_indirect_op(&mut fix.env, call, at, 4, 0)
        .unwrap();
    let op = fix.op(OpCode::Copy, 1, 0x104);
    fix.ssa.op_insert_before(op, call).unwrap();
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![first, op, ind, call]
    );
    // An INDIRECT goes immediately before follow.
    let ind2 = fix.ssa.new_indirect(&mut fix.env, call).unwrap();
    fix.ssa.op_insert_before(ind2, call).unwrap();
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![first, op, ind, ind2, call]
    );
}

#[test]
fn insert_after_an_indirect_goes_after_its_live_target_and_past_multiequals() {
    // opInsertAfter (387–419): prev an INDIRECT whose iop names a live op →
    // after that op; unless op is a MULTIEQUAL, past the MULTIEQUALs after
    // the point.
    let mut fix = fx(1);
    let b0 = fix.blocks[0];
    let call = fix.emit(0, OpCode::Call, 0x100, None, &[]);
    let at20 = fix.reg(0x20);
    let ind = fix
        .ssa
        .new_indirect_op(&mut fix.env, call, at20, 4, 0)
        .unwrap();
    let last = fix.emit(0, OpCode::Copy, 0x104, None, &[]);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    fix.ssa.op_insert_after(op, ind).unwrap();
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![ind, call, op, last]
    );

    let mut fix2 = fx(1);
    let b0 = fix2.blocks[0];
    let m1 = fix2.emit(0, OpCode::MultiEqual, 0x100, None, &[]);
    let m2 = fix2.emit(0, OpCode::MultiEqual, 0x100, None, &[]);
    let x = fix2.emit(0, OpCode::Copy, 0x104, None, &[]);
    let op = fix2.op(OpCode::Copy, 1, 0x100);
    fix2.ssa.op_insert_after(op, m1).unwrap();
    assert_eq!(
        fix2.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![m1, m2, op, x]
    );
    let m3 = fix2.op(OpCode::MultiEqual, 0, 0x100);
    fix2.ssa.op_insert_after(m3, m1).unwrap();
    assert_eq!(
        fix2.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![m1, m3, m2, op, x]
    );
    fix2.ok();
}

#[test]
fn insert_begin_after_multiequals_and_insert_end_before_a_flow_break() {
    // opInsertBegin (427–440); opInsertEnd (449–460).
    let mut fix = fx(1);
    let b0 = fix.blocks[0];
    let m = fix.emit(0, OpCode::MultiEqual, 0x100, None, &[]);
    let br = fix.emit(0, OpCode::Branch, 0x104, None, &[]);
    let a = fix.op(OpCode::Copy, 1, 0x100);
    fix.ssa.op_insert_begin(a, b0).unwrap();
    assert_eq!(fix.ssa.block_ops(b0).collect::<Vec<_>>(), vec![m, a, br]);
    let m2 = fix.op(OpCode::MultiEqual, 0, 0x100);
    fix.ssa.op_insert_begin(m2, b0).unwrap();
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![m2, m, a, br]
    );
    let e = fix.op(OpCode::Copy, 1, 0x104);
    fix.ssa.op_insert_end(e, b0).unwrap();
    assert_eq!(
        fix.ssa.block_ops(b0).collect::<Vec<_>>(),
        vec![m2, m, a, e, br]
    );
    // An empty block, and a block not ending in a flow break.
    let mut fix2 = fx(1);
    let b0 = fix2.blocks[0];
    let a = fix2.op(OpCode::Copy, 1, 0x100);
    fix2.ssa.op_insert_end(a, b0).unwrap();
    let b = fix2.op(OpCode::Copy, 1, 0x104);
    fix2.ssa.op_insert_end(b, b0).unwrap();
    assert_eq!(fix2.ssa.block_ops(b0).collect::<Vec<_>>(), vec![a, b]);
    fix2.ok();
}

#[test]
fn block_insert_numbers_between_neighbours_and_renumbers_when_full() {
    // BlockBasic::insert (block.cc:2276–2307) gives a new op an order
    // between its neighbours and calls setOrder (block.cc:2700) when there
    // is no room; setOrder spaces n ops by 0xffffffff / n - 1.
    let mut fix = fx(1);
    let b0 = fix.blocks[0];
    let a = fix.emit(0, OpCode::Copy, 0x100, None, &[]);
    let mut before = a;
    for i in 0..40 {
        let op = fix.op(OpCode::Copy, 1, 0x200 + i);
        fix.ssa.op_insert(op, b0, Some(before)).unwrap();
        before = op;
    }
    fix.ok();
    let ops = fix.ssa.block_ops(b0).collect::<Vec<_>>();
    assert_eq!(ops.len(), 41);
    fix.ssa.set_order(b0);
    let step = u32::MAX / 41 - 1;
    for (i, op) in ops.iter().enumerate() {
        assert_eq!(fix.ssa.op_order(*op), step * (i as u32 + 1));
    }
}
