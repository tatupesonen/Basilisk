//! Block surgery through the `Ssa` (`BlockGraph::removeBlock`,
//! `Funcdata::spliceBlockBasic`, `funcdata_block.cc:927`–`967`).

use bk_pcode::OpCode;

use crate::IrError;
use crate::flags::oflags;
use crate::testing::fx;

#[test]
fn a_block_holding_ops_is_not_removed() {
    let mut fix = fx(3);
    let op = fix.emit(1, OpCode::Copy, 0x200, Some(0), &[]);
    let b1 = fix.blocks[1];
    let before = fix.ssa.cfg().len();
    assert_eq!(
        fix.ssa.remove_block(b1),
        Err(IrError::BlockHasOps {
            method: "removeBlock",
            block: b1.get(),
        })
    );
    assert_eq!(fix.ssa.cfg().len(), before);
    fix.ssa.op_destroy(op).unwrap();
    fix.ssa.remove_block(b1).unwrap();
    assert!(!fix.ssa.is_block(b1));
    assert_eq!(fix.ssa.cfg().len(), before - 1);
    assert_eq!(fix.ssa.block_ops(b1).count(), 0);
    fix.ok();
}

#[test]
fn splicing_moves_the_successors_ops_and_drops_the_branch() {
    // 0 → 1: block 0 ends in a BRANCH, which is destroyed; block 1's ops
    // move to the end of block 0, the first loses startbasic, and the
    // block is renumbered (funcdata_block.cc:939–962).
    let mut fix = fx(2);
    let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let tgt = fix.cst(4, 0x200);
    let br = fix.emit(0, OpCode::Branch, 0x104, None, &[tgt]);
    let vn = fix.ssa.op_output(a).unwrap();
    let b = fix.emit(1, OpCode::Copy, 0x200, Some(4), &[vn]);
    let c = fix.emit(1, OpCode::Copy, 0x204, Some(8), &[]);
    fix.ssa.opd_mut(b).unwrap().flags |= oflags::STARTBASIC;
    let (b0, b1) = (fix.blocks[0], fix.blocks[1]);
    fix.ssa.splice_block_basic(b0).unwrap();
    assert_eq!(fix.ssa.block_ops(b0).collect::<Vec<_>>(), [a, b, c]);
    assert!(!fix.ssa.op_exists(br) || fix.ssa.op_parent(br).is_none());
    assert_eq!(fix.ssa.op_flags(b) & oflags::STARTBASIC, 0);
    assert_eq!(fix.ssa.op_parent(c), Some(b0));
    assert!(!fix.ssa.is_block(b1));
    let orders: Vec<_> = [a, b, c].map(|o| fix.ssa.op_order(o)).into();
    assert!(orders.windows(2).all(|w| w[0] < w[1]));
    fix.ok();
}

#[test]
fn splicing_refusals_change_nothing() {
    let mut fix = fx(3);
    let (b0, b1, b2) = (fix.blocks[0], fix.blocks[1], fix.blocks[2]);
    // Two successors.
    fix.ssa.cfg_mut().add_edge(b0, b2).unwrap();
    assert_eq!(
        fix.ssa.splice_block_basic(b0),
        Err(IrError::CannotSplice(b0.get()))
    );
    // A successor with two predecessors.
    assert_eq!(
        fix.ssa.splice_block_basic(b1),
        Err(IrError::CannotSplice(b1.get()))
    );
    // A successor starting with a MULTIEQUAL.
    let mut fix = fx(2);
    let tgt = fix.cst(4, 0x200);
    let br = fix.emit(0, OpCode::Branch, 0x104, None, &[tgt]);
    let x = fix.regvn(0x10, 4);
    fix.emit(1, OpCode::MultiEqual, 0x200, Some(4), &[x]);
    let b0 = fix.blocks[0];
    assert_eq!(
        fix.ssa.splice_block_basic(b0),
        Err(IrError::SpliceMultiequal(b0.get()))
    );
    assert_eq!(fix.ssa.op_parent(br), Some(b0));
}
