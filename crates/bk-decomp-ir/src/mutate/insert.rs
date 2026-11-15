//! Placing ops relative to others (funcdata_op.cc:352–460): `MULTIEQUAL`s
//! stay first in a block, `INDIRECT`s stay right before the op they are
//! for, and a branch stays last.

use bk_decomp_cfg::NodeId;
use bk_pcode::OpCode;

use crate::error::{IrError, IrResult};
use crate::ids::OpId;
use crate::ssa::Ssa;

impl Ssa {
    fn parent_of(&self, method: &'static str, op: OpId) -> IrResult<NodeId> {
        self.op_parent(op).ok_or(IrError::NotInBlock { method, op })
    }

    /// `opInsertBefore`: before `follow`, stepping back over `INDIRECT`s
    /// right before it unless `op` is an `INDIRECT`.
    pub fn op_insert_before(&mut self, op: OpId, follow: OpId) -> IrResult<()> {
        let parent = self.parent_of("opInsertBefore", follow)?;
        let mut before = follow;
        if self.op_opcode(op) != Some(OpCode::Indirect) {
            while let Some(prev) = self.op_prev_in_block(before) {
                if self.op_opcode(prev) != Some(OpCode::Indirect) {
                    break;
                }
                before = prev;
            }
        }
        self.op_insert(op, parent, Some(before))
    }

    /// `opInsertAfter`: after `prev` — after the op an `INDIRECT` `prev` is
    /// for, if that op is alive — stepping over `MULTIEQUAL`s unless `op`
    /// is a `MULTIEQUAL`.
    pub fn op_insert_after(&mut self, op: OpId, prev: OpId) -> IrResult<()> {
        let mut prev = prev;
        if self.op_is_marker(prev)
            && self.op_opcode(prev) == Some(OpCode::Indirect)
            && let Some(targ) = self.op_input(prev, 1).and_then(|v| self.op_from_iop(v))
            && !self.op_is_dead(targ)
        {
            prev = targ;
        }
        let parent = self.parent_of("opInsertAfter", prev)?;
        let mut next = self.op_next_in_block(prev);
        if self.op_opcode(op) != Some(OpCode::MultiEqual) {
            while let Some(n) = next {
                if self.op_opcode(n) != Some(OpCode::MultiEqual) {
                    break;
                }
                next = self.op_next_in_block(n);
            }
        }
        self.op_insert(op, parent, next)
    }

    /// `opInsertBegin`: first in `block`, after its `MULTIEQUAL`s unless
    /// `op` is one.
    pub fn op_insert_begin(&mut self, op: OpId, block: NodeId) -> IrResult<()> {
        let mut at = self.first_op(block);
        if self.op_opcode(op) != Some(OpCode::MultiEqual) {
            while let Some(a) = at {
                if self.op_opcode(a) != Some(OpCode::MultiEqual) {
                    break;
                }
                at = self.op_next_in_block(a);
            }
        }
        self.op_insert(op, block, at)
    }

    /// `opInsertEnd`: last in `block`, or before its last op if that op
    /// breaks flow.
    pub fn op_insert_end(&mut self, op: OpId, block: NodeId) -> IrResult<()> {
        let at = self.last_op(block).filter(|&l| self.op_is_flow_break(l));
        self.op_insert(op, block, at)
    }
}
