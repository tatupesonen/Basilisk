//! Queries of `BlockBasic` and the block-relative queries of `PcodeOp`.

use bk_core::Address;
use bk_decomp_cfg::{NodeId, edge_labels, node_flags};
use bk_pcode::OpCode;

use crate::error::IrResult;
use crate::flags::{oaddl, oflags};
use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

impl Ssa {
    /// `BlockBasic::getStart`: the first address of the first range.
    pub fn block_start(&self, b: NodeId) -> Address {
        self.block_ranges(b)
            .and_then(bk_core::RangeList::first_range)
            .map_or(Address::INVALID, |r| r.first_addr())
    }

    /// `BlockBasic::getStop`: the last address of the last range.
    pub fn block_stop(&self, b: NodeId) -> Address {
        self.block_ranges(b)
            .and_then(bk_core::RangeList::last_range)
            .map_or(Address::INVALID, |r| r.last_addr())
    }

    /// `BlockBasic::getEntryAddr` (block.cc:2320).
    pub fn block_entry_addr(&self, b: NodeId) -> Address {
        let Some(cover) = self.block_ranges(b) else {
            return Address::INVALID;
        };
        if cover.len() == 1 {
            return cover
                .first_range()
                .map_or(Address::INVALID, |r| r.first_addr());
        }
        let Some(first) = self.first_op(b) else {
            return Address::INVALID;
        };
        let addr = self
            .ops
            .get(first.index())
            .map_or(Address::INVALID, |d| d.pc);
        match addr.space().and_then(|s| cover.get_range(s, addr.offset())) {
            Some(r) => r.first_addr(),
            None => addr,
        }
    }

    /// `BlockBasic::contains`.
    pub fn block_contains(&self, b: NodeId, addr: Address) -> bool {
        self.block_ranges(b).is_some_and(|c| c.in_range(addr, 1))
    }

    /// `BlockBasic::hasOnlyMarkers`: only `MULTIEQUAL`, `INDIRECT` and
    /// branches.
    pub fn has_only_markers(&self, b: NodeId) -> bool {
        self.block_ops(b).into_iter().all(|op| {
            self.ops
                .get(op.index())
                .is_some_and(|d| d.flags & (oflags::MARKER | oflags::BRANCH) != 0)
        })
    }

    /// `BlockBasic::isDoNothing` (block.cc:2658).
    pub fn is_do_nothing(&self, b: NodeId) -> bool {
        let outs = self.outs(b);
        if outs.len() != 1 {
            return false;
        }
        let ins = self.ins(b);
        if ins.is_empty() {
            return false;
        }
        for e in &ins {
            let switchbl = e.node;
            if self.cfg.flags(switchbl).unwrap_or(0) & node_flags::SWITCH_OUT == 0 {
                continue;
            }
            if self.outs(switchbl).len() > 1
                && outs.first().is_some_and(|o| self.ins(o.node).len() > 1)
            {
                return false;
            }
        }
        if let Some(last) = self.last_op(b)
            && self
                .ops
                .get(last.index())
                .and_then(crate::data::OpData::opcode)
                == Some(OpCode::BranchInd)
        {
            return false;
        }
        self.has_only_markers(b)
    }

    /// `BlockBasic::unblockedMulti` (block.cc:2575).
    pub fn unblocked_multi(&self, b: NodeId, outslot: usize) -> bool {
        let Some(blout) = self.outs(b).get(outslot).map(|e| e.node) else {
            return true;
        };
        let mut redund = Vec::new();
        for e in self.ins(b) {
            for o in self.outs(e.node) {
                if o.node == blout {
                    redund.push(e.node);
                }
            }
        }
        if redund.is_empty() {
            return true;
        }
        let Some(in_to_this) = self.cfg.in_index(blout, b) else {
            return true;
        };
        for multiop in self.block_ops(blout) {
            if self.op_opcode(multiop) != Some(OpCode::MultiEqual) {
                continue;
            }
            for &bl in &redund {
                let Some(slot) = self.cfg.in_index(blout, bl) else {
                    continue;
                };
                let vnredund = self.op_input(multiop, slot);
                let mut vnremove = self.op_input(multiop, in_to_this);
                if let Some(rm) = vnremove
                    && let Some(other) = self.varnode_def(rm)
                    && self.op_opcode(other) == Some(OpCode::MultiEqual)
                    && self.op_parent(other) == Some(b)
                    && let Some(ix) = self.cfg.in_index(b, bl)
                {
                    vnremove = self.op_input(other, ix);
                }
                if vnremove != vnredund {
                    return false;
                }
            }
        }
        true
    }

    /// `BlockBasic::hasNoImmediateCopy` (block.cc:2619).
    pub fn has_no_immediate_copy(&self, b: NodeId, outslot: usize) -> bool {
        let outs = self.outs(b);
        let Some(e) = outs.get(outslot) else {
            return true;
        };
        if e.label & edge_labels::IMMED_COPY == 0 {
            return true;
        }
        let blout = e.node;
        let Some(in_to_this) = self.cfg.in_index(blout, b) else {
            return true;
        };
        !self.block_ops(blout).into_iter().any(|m| {
            self.op_opcode(m) == Some(OpCode::MultiEqual) && self.has_copy_immed(m, in_to_this)
        })
    }

    /// `PcodeOp::hasCopyImmed`.
    pub fn has_copy_immed(&self, op: OpId, slot: usize) -> bool {
        let Ok(d) = self.opd(op) else { return false };
        if d.addl & oaddl::IMMED_COPY == 0 {
            return false;
        }
        let Some(parent) = self.op_parent(op) else {
            return false;
        };
        let ins = self.ins(parent);
        let Some(e) = ins.get(slot) else { return false };
        self.outs(e.node)
            .get(e.rev as usize)
            .is_some_and(|o| o.label & edge_labels::IMMED_COPY != 0)
    }

    /// `BlockBasic::noInterveningStatement` (block.cc:2774).
    pub fn no_intervening_statement(&self, b: NodeId) -> bool {
        for op in self.block_ops(b) {
            let Ok(d) = self.opd(op) else { return false };
            if d.flags & (oflags::MARKER | oflags::BRANCH) != 0 {
                continue;
            }
            let opc = d.opcode();
            if d.flags & oflags::SPECIAL != 0
                && d.flags & (oflags::UNARY | oflags::BINARY | oflags::TERNARY) == 0
            {
                if d.flags & oflags::CALL != 0 {
                    return false;
                }
                if matches!(opc, Some(OpCode::Store | OpCode::New)) {
                    return false;
                }
            } else if matches!(opc, Some(OpCode::Copy | OpCode::SubPiece)) {
                continue;
            }
            let Some(out) = d.output() else { return false };
            if self.is_addr_tied(out) {
                return false;
            }
            if self
                .readers(out)
                .iter()
                .any(|&r| self.op_parent(r) != Some(b))
            {
                return false;
            }
        }
        true
    }

    /// `BlockBasic::findMultiequal`: the `MULTIEQUAL` of this block reading
    /// exactly `vars`.
    pub fn find_multiequal(&self, b: NodeId, vars: &[VarnodeId]) -> Option<OpId> {
        let first = *vars.first()?;
        let op = self.readers(first).into_iter().find(|&op| {
            self.op_opcode(op) == Some(OpCode::MultiEqual) && self.op_parent(op) == Some(b)
        })?;
        let ins = self.op_inputs(op);
        (ins.len() >= vars.len() && vars.iter().zip(&ins).all(|(v, i)| Some(*v) == *i))
            .then_some(op)
    }

    /// `BlockBasic::earliestUse`.
    pub fn earliest_use(&self, b: NodeId, vn: VarnodeId) -> Option<OpId> {
        let mut res: Option<OpId> = None;
        for op in self.readers(vn) {
            if self.op_parent(op) != Some(b) {
                continue;
            }
            match res {
                None => res = Some(op),
                Some(r) if self.op_order(op) < self.op_order(r) => res = Some(op),
                Some(_) => {}
            }
        }
        res
    }

    /// `BlockBasic::liftVerifyUnroll`: each varnode is written by the same
    /// opcode with the same constant in the other slot; on success the
    /// array holds the inputs in `slot`.
    pub fn lift_verify_unroll(&self, vars: &mut [VarnodeId], slot: usize) -> bool {
        let Some(&first) = vars.first() else {
            return false;
        };
        let Some(op) = self.varnode_def(first) else {
            return false;
        };
        let opc = self.op_opcode(op);
        let cvn = if self.op_num_inputs(op) == 2 {
            let Some(c) = self.op_input(op, 1 - slot.min(1)) else {
                return false;
            };
            if !self.is_constant(c) {
                return false;
            }
            Some(c)
        } else {
            None
        };
        let Some(in0) = self.op_input(op, slot) else {
            return false;
        };
        if let Some(v) = vars.first_mut() {
            *v = in0;
        }
        for v in vars.iter_mut().skip(1) {
            let Some(op) = self.varnode_def(*v) else {
                return false;
            };
            if self.op_opcode(op) != opc {
                return false;
            }
            if let Some(c) = cvn {
                let Some(c2) = self.op_input(op, 1 - slot.min(1)) else {
                    return false;
                };
                if !self.is_constant(c2)
                    || self.varnode_size(c) != self.varnode_size(c2)
                    || self.varnode_offset(c) != self.varnode_offset(c2)
                {
                    return false;
                }
            }
            let Some(i) = self.op_input(op, slot) else {
                return false;
            };
            *v = i;
        }
        true
    }

    /// `PcodeOp::nextOp`: the next op in flow, following a block's first
    /// out-edge while the block ends and has one or two out-edges.
    pub fn next_op(&self, op: OpId) -> IrResult<Option<OpId>> {
        let d = self.opd(op)?;
        if let Some(n) = self.op_next_in_block(op) {
            return Ok(Some(n));
        }
        let Some(mut p) = d.parent_raw().map(NodeId::new) else {
            return Ok(None);
        };
        for _ in 0..=self.cfg.len() {
            let outs = self.outs(p);
            if outs.len() != 1 && outs.len() != 2 {
                return Ok(None);
            }
            let Some(next) = outs.first().map(|e| e.node) else {
                return Ok(None);
            };
            p = next;
            if let Some(f) = self.first_op(p) {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    /// The nearest common dominator of two blocks
    /// (`FlowBlock::findCommonBlock`, by immediate dominators).
    pub fn common_dominator(&self, a: NodeId, b: NodeId) -> Option<NodeId> {
        let bound = self.cfg.id_bound() + 1;
        let mut ancestors = Vec::new();
        let mut cur = Some(a);
        while let Some(n) = cur {
            if ancestors.len() > bound {
                break;
            }
            ancestors.push(n);
            cur = self.cfg.idom(n);
        }
        let mut cur = Some(b);
        let mut steps = 0;
        while let Some(n) = cur {
            if ancestors.contains(&n) {
                return Some(n);
            }
            steps += 1;
            if steps > bound {
                break;
            }
            cur = self.cfg.idom(n);
        }
        None
    }

    /// `PcodeOp::compareOrder`: -1 if `a` executes before `b`, 1 if after,
    /// 0 if neither dominates.
    pub fn compare_order(&self, a: OpId, b: OpId) -> i32 {
        let (pa, pb) = (self.op_parent(a), self.op_parent(b));
        if pa == pb {
            return if self.op_order(a) < self.op_order(b) {
                -1
            } else {
                1
            };
        }
        let (Some(pa), Some(pb)) = (pa, pb) else {
            return 0;
        };
        match self.common_dominator(pa, pb) {
            Some(c) if c == pa => -1,
            Some(c) if c == pb => 1,
            _ => 0,
        }
    }
}
