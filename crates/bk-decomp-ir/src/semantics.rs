//! What each op means at a unit boundary (ADR-025 3a, ADR-028; spec 4.5
//! "Evaluation"), as data for D07's evaluator.
//!
//! A free varnode denotes its storage (the latest value written there by
//! an executed op), an input varnode its value at entry, a written varnode
//! the value its defining op produced.

use bk_pcode::OpCode;

use crate::flags::oflags;
use crate::ids::OpId;
use crate::props::props;
use crate::ssa::Ssa;

/// What the environment must supply for a `special` op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnvOp {
    /// `BRANCH`, `CBRANCH`, `BRANCHIND`: control flow.
    Branch,
    /// `CALL`, `CALLIND`, `CALLOTHER`, `NEW`: the callee's effect.
    Call,
    /// `RETURN`.
    Return,
    /// `LOAD`: memory.
    Load,
    /// `STORE`: memory.
    Store,
    /// `SEGMENTOP`: the segment model.
    Segment,
    /// `CPOOLREF`: the constant pool.
    ConstantPool,
}

/// The meaning of an op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Semantics {
    /// `bk_pcode::behavior` on the input values (unary, binary or ternary
    /// evaluation: `COPY`, `PTRADD` = `in0 + in1 * in2`, `PTRSUB` = `in0 +
    /// in1`, `PIECE`, `SUBPIECE`, `INSERT`, `ZPULL`, `SPULL`, arithmetic).
    Ordinary,
    /// `CAST`: a copy of input 0, although Ghidra flags it `special`.
    Copy,
    /// `MULTIEQUAL`: the input whose slot is the index of the in-edge
    /// control arrived by.
    MultiEqual,
    /// `INDIRECT`: input 0, unless the op its `iop` input names changes that
    /// storage, then the value the environment reports after that op.
    Indirect,
    /// `INDIRECT` with `indirect_creation`: the value the environment
    /// reports.
    IndirectCreation,
    /// Needs the environment.
    Environment(EnvOp),
}

/// The meaning of an opcode, ignoring per-op flags.
pub const fn opcode_semantics(opcode: OpCode) -> Semantics {
    match opcode {
        OpCode::MultiEqual => Semantics::MultiEqual,
        OpCode::Indirect => Semantics::Indirect,
        OpCode::Cast => Semantics::Copy,
        OpCode::Branch | OpCode::CBranch | OpCode::BranchInd => {
            Semantics::Environment(EnvOp::Branch)
        }
        OpCode::Call | OpCode::CallInd | OpCode::CallOther | OpCode::New => {
            Semantics::Environment(EnvOp::Call)
        }
        OpCode::Return => Semantics::Environment(EnvOp::Return),
        OpCode::Load => Semantics::Environment(EnvOp::Load),
        OpCode::Store => Semantics::Environment(EnvOp::Store),
        OpCode::SegmentOp => Semantics::Environment(EnvOp::Segment),
        OpCode::CPoolRef => Semantics::Environment(EnvOp::ConstantPool),
        _ => {
            if props(opcode).flags & oflags::SPECIAL != 0 {
                // Unreachable with the table: every special opcode is named
                // above (checked by a test).
                Semantics::Environment(EnvOp::Call)
            } else {
                Semantics::Ordinary
            }
        }
    }
}

impl Ssa {
    /// `op_semantics`: the meaning of `op` (spec 4.5); `None` before the op
    /// has an opcode.
    pub fn op_semantics(&self, op: OpId) -> Option<Semantics> {
        let opc = self.op_opcode(op)?;
        let s = opcode_semantics(opc);
        if s == Semantics::Indirect && self.op_is_indirect_creation(op) {
            return Some(Semantics::IndirectCreation);
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_over_the_opcodes_and_special_means_environment() {
        let mut special = 0;
        for op in OpCode::ALL {
            let s = opcode_semantics(op);
            let is_special = props(op).flags & oflags::SPECIAL != 0;
            if is_special {
                special += 1;
                assert_ne!(s, Semantics::Ordinary, "{op:?}");
            } else {
                assert_eq!(s, Semantics::Ordinary, "{op:?}");
            }
        }
        assert_eq!(special, 15);
    }
}
