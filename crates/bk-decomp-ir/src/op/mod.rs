//! Queries of ops (Ghidra `PcodeOp`'s public getters, op.hh:155–259, and
//! the queries of op.cc).

mod nzmask;
mod piece;

pub use piece::PieceNode;

use bk_core::{Address, SeqNum};
use bk_decomp_cfg::NodeId;
use bk_pcode::OpCode;

use crate::data::{OpData, Tree};
use crate::flags::{oaddl, oflags};
use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

macro_rules! op_flag_getters {
    ($( $(#[$m:meta])* $name:ident => $test:expr ;)*) => {
        impl Ssa {
            $(
                $(#[$m])*
                pub fn $name(&self, op: OpId) -> bool {
                    self.ops.get(op.index()).is_some_and(|d| {
                        let f: fn(&OpData) -> bool = $test;
                        f(d)
                    })
                }
            )*
        }
    };
}

const fn has(d: &OpData, bits: u32) -> bool {
    d.flags & bits != 0
}

op_flag_getters! {
    /// `isDead`.
    op_is_dead => |d| has(d, oflags::DEAD);
    /// `isAssignment`: has an output.
    op_is_assignment => |d| d.output().is_some();
    /// `isCall`.
    op_is_call => |d| has(d, oflags::CALL);
    /// `isCallWithoutSpec`.
    op_is_call_without_spec => |d| d.flags & (oflags::CALL | oflags::HAS_CALLSPEC) == oflags::CALL;
    /// `isMarker`.
    op_is_marker => |d| has(d, oflags::MARKER);
    /// `isIndirectCreation`.
    op_is_indirect_creation => |d| has(d, oflags::INDIRECT_CREATION);
    /// `isIndirectStore`.
    op_is_indirect_store => |d| has(d, oflags::INDIRECT_STORE);
    /// `notPrinted`.
    op_not_printed => |d| has(d, oflags::MARKER | oflags::NONPRINTING | oflags::NORETURN);
    /// `isBoolOutput`.
    op_is_bool_output => |d| has(d, oflags::BOOLOUTPUT);
    /// `isBranch`.
    op_is_branch => |d| has(d, oflags::BRANCH);
    /// `isCallOrBranch`.
    op_is_call_or_branch => |d| has(d, oflags::BRANCH | oflags::CALL);
    /// `isFlowBreak`.
    op_is_flow_break => |d| has(d, oflags::BRANCH | oflags::RETURNS);
    /// `isBooleanFlip`.
    op_is_boolean_flip => |d| has(d, oflags::BOOLEAN_FLIP);
    /// `isFallthruTrue`.
    op_is_fallthru_true => |d| has(d, oflags::FALLTHRU_TRUE);
    /// `isCodeRef`.
    op_is_code_ref => |d| has(d, oflags::CODEREF);
    /// `isInstructionStart`.
    op_is_instruction_start => |d| has(d, oflags::STARTMARK);
    /// `isBlockStart`.
    op_is_block_start => |d| has(d, oflags::STARTBASIC);
    /// `isMark`.
    op_is_mark => |d| has(d, oflags::MARK);
    /// `isWarning`.
    op_is_warning => |d| d.addl & oaddl::WARNING != 0;
    /// `isIndirectSource`.
    op_is_indirect_source => |d| has(d, oflags::INDIRECT_SOURCE);
    /// `isPtrFlow`.
    op_is_ptr_flow => |d| has(d, oflags::PTRFLOW);
    /// `doesSpecialPropagation`.
    op_does_special_propagation => |d| d.addl & oaddl::SPECIAL_PROP != 0;
    /// `doesSpecialPrinting`.
    op_does_special_printing => |d| d.addl & oaddl::SPECIAL_PRINT != 0;
    /// `isIncidentalCopy`.
    op_is_incidental_copy => |d| d.addl & oaddl::INCIDENTAL_COPY != 0;
    /// `isCalculatedBool`.
    op_is_calculated_bool => |d| has(d, oflags::CALCULATED_BOOL | oflags::BOOLOUTPUT);
    /// `isCpoolTransformed`.
    op_is_cpool_transformed => |d| d.addl & oaddl::IS_CPOOL_TRANSFORMED != 0;
    /// `stopsTypePropagation`.
    op_stops_type_propagation => |d| d.addl & oaddl::STOP_TYPE_PROPAGATION != 0;
    /// `holdOutput`.
    op_hold_output => |d| d.addl & oaddl::HOLD_OUTPUT != 0;
    /// `isPartialRoot`.
    op_is_partial_root => |d| d.addl & oaddl::CONCAT_ROOT != 0;
    /// `isReturnCopy`.
    op_is_return_copy => |d| has(d, oflags::RETURN_COPY);
    /// `noIndirectCollapse`.
    op_no_indirect_collapse => |d| d.addl & oaddl::NO_INDIRECT_COLLAPSE != 0;
    /// `isStoreUnmapped`.
    op_is_store_unmapped => |d| d.addl & oaddl::STORE_UNMAPPED != 0;
    /// `hasAliasUpdate`.
    op_has_alias_update => |d| d.addl & oaddl::STORE_ALIASUPDATE != 0;
    /// `usesSpacebasePtr`.
    op_uses_spacebase_ptr => |d| has(d, oflags::SPACEBASE_PTR);
    /// `isCommutative`.
    op_is_commutative => |d| has(d, oflags::COMMUTATIVE);
}

impl Ssa {
    /// Whether `op` exists and is not retired.
    pub fn op_exists(&self, op: OpId) -> bool {
        self.opd(op).is_ok()
    }

    /// Whether `op` was retired.
    pub fn op_is_retired(&self, op: OpId) -> bool {
        self.ops
            .get(op.index())
            .is_some_and(|d| d.tree == Tree::Retired)
    }

    /// Whether the op is in `alttree`.
    pub fn op_in_alt_tree(&self, op: OpId) -> bool {
        self.ops
            .get(op.index())
            .is_some_and(|d| d.tree == Tree::Alt)
    }

    /// `code()`; `None` before the first `op_set_opcode`.
    pub fn op_opcode(&self, op: OpId) -> Option<OpCode> {
        self.ops.get(op.index()).and_then(OpData::opcode)
    }

    /// `flags`.
    pub fn op_flags(&self, op: OpId) -> u32 {
        self.ops.get(op.index()).map_or(0, |d| d.flags)
    }

    /// `addlflags`.
    pub fn op_addl(&self, op: OpId) -> u32 {
        self.ops.get(op.index()).map_or(0, |d| d.addl)
    }

    /// `getSeqNum`, with the op's `order`.
    pub fn op_seq(&self, op: OpId) -> SeqNum {
        self.ops.get(op.index()).map_or(SeqNum::MINIMAL, |d| {
            let mut s = SeqNum::new(d.pc, d.time);
            s.set_order(d.order);
            s
        })
    }

    /// `getAddr`.
    pub fn op_addr(&self, op: OpId) -> Address {
        self.ops.get(op.index()).map_or(Address::INVALID, |d| d.pc)
    }

    /// `getTime`.
    pub fn op_time(&self, op: OpId) -> u32 {
        self.ops.get(op.index()).map_or(0, |d| d.time)
    }

    /// `getSeqNum().getOrder()`.
    pub fn op_order(&self, op: OpId) -> u32 {
        self.ops.get(op.index()).map_or(0, |d| d.order)
    }

    /// `getParent`.
    pub fn op_parent(&self, op: OpId) -> Option<NodeId> {
        self.ops
            .get(op.index())
            .and_then(OpData::parent_raw)
            .map(NodeId::new)
    }

    /// `getOut`.
    pub fn op_output(&self, op: OpId) -> Option<VarnodeId> {
        self.ops.get(op.index()).and_then(OpData::output)
    }

    /// `numInput`.
    pub fn op_num_inputs(&self, op: OpId) -> usize {
        self.ops.get(op.index()).map_or(0, |d| d.inputs.len())
    }

    /// `getIn(slot)`; `None` for an empty slot or one out of range.
    pub fn op_input(&self, op: OpId, slot: usize) -> Option<VarnodeId> {
        self.ops
            .get(op.index())
            .and_then(|d| d.inputs.get(&self.pool, slot))
            .and_then(VarnodeId::from_packed)
    }

    /// Every input slot in order, borrowed; `.collect()` a snapshot to
    /// change the IR while walking.
    pub fn op_inputs(
        &self,
        op: OpId,
    ) -> impl DoubleEndedIterator<Item = Option<VarnodeId>> + ExactSizeIterator + Clone + '_ {
        let list: &[u32] = self
            .ops
            .get(op.index())
            .map_or(&[], |d| d.inputs.as_slice(&self.pool));
        list.iter().map(|&v| VarnodeId::from_packed(v))
    }

    /// The input slots as a snapshot, for loops that change the IR.
    pub fn op_inputs_vec(&self, op: OpId) -> Vec<Option<VarnodeId>> {
        self.op_inputs(op).collect()
    }

    /// `getSlot`: the first slot holding `vn` (`numInput` if none).
    pub fn op_slot(&self, op: OpId, vn: VarnodeId) -> usize {
        self.ops.get(op.index()).map_or(0, |d| {
            d.inputs
                .position(&self.pool, vn.0)
                .unwrap_or(d.inputs.len())
        })
    }

    /// `getRepeatSlot`: for the `nth` occurrence of `op` in `vn`'s reader
    /// list (0-based), the slot it corresponds to (op.cc:93).
    pub fn op_repeat_slot(&self, op: OpId, vn: VarnodeId, nth: usize) -> Option<usize> {
        self.op_inputs(op)
            .enumerate()
            .filter(|(_, v)| *v == Some(vn))
            .nth(nth)
            .map(|(i, _)| i)
    }

    /// `getEvalType`: the unary, binary, special and ternary bits.
    pub fn op_eval_type(&self, op: OpId) -> u32 {
        self.op_flags(op) & (oflags::UNARY | oflags::BINARY | oflags::SPECIAL | oflags::TERNARY)
    }

    /// `getHaltType`.
    pub fn op_halt_type(&self, op: OpId) -> u32 {
        self.op_flags(op) & oflags::HALT_BITS
    }

    /// `getOpName`: the `TypeOp` name `print raw` uses.
    pub fn op_name(&self, op: OpId) -> &'static str {
        self.op_opcode(op)
            .map_or("", |o| crate::props::props(o).name)
    }

    /// `isCollapsible`: an assignment whose inputs are all constants and
    /// whose output fits in 8 bytes, not `nocollapse`.
    pub fn op_is_collapsible(&self, op: OpId) -> bool {
        let Some(d) = self.ops.get(op.index()) else {
            return false;
        };
        if d.flags & oflags::NOCOLLAPSE != 0 {
            return false;
        }
        let Some(out) = d.output() else { return false };
        let mut ins = self.op_inputs(op);
        if ins.len() == 0 {
            return false;
        }
        if !ins.all(|v| v.is_some_and(|v| self.is_constant(v))) {
            return false;
        }
        self.varnode_size(out) <= 8
    }

    /// `getCseHash`: a hash of output size, opcode and input identities, 0
    /// when the op is not a candidate.
    pub fn op_cse_hash(&self, op: OpId) -> u32 {
        if self.op_eval_type(op) & (oflags::UNARY | oflags::BINARY) == 0 {
            return 0;
        }
        let Some(opc) = self.op_opcode(op) else {
            return 0;
        };
        if opc == OpCode::Copy {
            return 0;
        }
        let Some(out) = self.op_output(op) else {
            return 0;
        };
        let mut hash = ((self.varnode_size(out) as u32) << 8) | u32::from(opc.value());
        for vn in self.op_inputs(op) {
            hash = hash.rotate_left(8);
            if let Some(vn) = vn {
                if self.is_constant(vn) {
                    hash ^= self.varnode_offset(vn) as u32;
                } else {
                    hash ^= self.varnode_create_index(vn);
                }
            }
        }
        hash
    }

    /// `isCseMatch`.
    pub fn op_is_cse_match(&self, a: OpId, b: OpId) -> bool {
        let ub = oflags::UNARY | oflags::BINARY;
        if self.op_eval_type(a) & ub == 0 || self.op_eval_type(b) & ub == 0 {
            return false;
        }
        let (Some(oa), Some(ob)) = (self.op_output(a), self.op_output(b)) else {
            return false;
        };
        if self.varnode_size(oa) != self.varnode_size(ob) {
            return false;
        }
        if self.op_opcode(a) != self.op_opcode(b) || self.op_opcode(a) == Some(OpCode::Copy) {
            return false;
        }
        let (ia, ib) = (self.op_inputs(a), self.op_inputs(b));
        if ia.len() != ib.len() {
            return false;
        }
        ia.zip(ib).all(|(x, y)| {
            x == y
                || matches!((x, y), (Some(x), Some(y))
                    if self.is_constant(x) && self.is_constant(y)
                        && self.varnode_offset(x) == self.varnode_offset(y))
        })
    }

    /// `verifyMultNegOne`.
    pub fn op_verify_mult_neg_one(&self, op: OpId) -> bool {
        if self.op_opcode(op) != Some(OpCode::IntMult) {
            return false;
        }
        let Some(c) = self.op_input(op, 1) else {
            return false;
        };
        self.is_constant(c)
            && self.varnode_offset(c)
                == bk_pcode::mask::calc_mask(self.varnode_size(c).max(0) as u32)
    }

    /// `getOpFromConst`: the op an `iop` varnode names.
    pub fn op_from_iop(&self, vn: VarnodeId) -> Option<OpId> {
        match self.varnode_offset_kind(vn) {
            crate::varnode::OffsetKind::Op(op) if self.ops.get(op.index()).is_some() => Some(op),
            _ => None,
        }
    }

    /// `isMoveable`: `op` can move to right after `point` in its block
    /// without changing data-flow (op.cc:201).
    pub fn op_is_moveable(&self, op: OpId, point: OpId) -> bool {
        if op == point {
            return true;
        }
        let special = self.op_eval_type(op) == oflags::SPECIAL;
        let mut moving_load = false;
        if special {
            if self.op_opcode(op) == Some(OpCode::Load) {
                moving_load = true;
            } else {
                return false;
            }
        }
        let parent = self.op_parent(op);
        if parent.is_none() || parent != self.op_parent(point) {
            return false;
        }
        let out = self.op_output(op);
        if let Some(out) = out {
            let point_order = self.op_order(point);
            for r in self.readers(out) {
                if self.op_parent(r) != parent {
                    continue;
                }
                if self.op_order(r) <= point_order {
                    return false;
                }
            }
        }
        let ins: Vec<VarnodeId> = self.op_inputs(op).flatten().collect();
        let mut cross_calls = false;
        if !special
            && let Some(out) = out
            && !self.is_addr_tied(out)
            && !self.is_persist(out)
            && !ins
                .iter()
                .any(|&v| self.is_addr_tied(v) || self.is_persist(v))
        {
            cross_calls = true;
        }
        let tied: Vec<VarnodeId> = ins
            .iter()
            .copied()
            .filter(|&v| self.is_addr_tied(v))
            .collect();
        let mut cur = op;
        for _ in 0..=self.block_len(parent.unwrap_or(NodeId::new(0))) {
            let Some(next) = self.op_next_in_block(cur) else {
                return false;
            };
            cur = next;
            if self.op_eval_type(cur) == oflags::SPECIAL {
                match self.op_opcode(cur) {
                    Some(OpCode::Load) => {
                        if out.is_some_and(|o| self.is_addr_tied(o)) {
                            return false;
                        }
                    }
                    Some(OpCode::Store) => {
                        if moving_load
                            || !tied.is_empty()
                            || out.is_some_and(|o| self.is_addr_tied(o))
                        {
                            return false;
                        }
                    }
                    Some(OpCode::Indirect | OpCode::SegmentOp | OpCode::CPoolRef) => {}
                    Some(OpCode::Call | OpCode::CallInd | OpCode::New) => {
                        if !cross_calls {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            if let Some(o) = self.op_output(cur) {
                if moving_load && self.is_addr_tied(o) {
                    return false;
                }
                for &vn in &tied {
                    if self.overlap(vn, o) >= 0 || self.overlap(o, vn) >= 0 {
                        return false;
                    }
                }
            }
            if cur == point {
                return true;
            }
        }
        false
    }
}
