//! The four per-block facts the structurer takes (decomp-cfg.md 4.1,
//! ADR-042) computed from the function's blocks.

use bk_decomp_cfg::{BlockFacts, Fact, NodeId, node_flags};
use bk_pcode::OpCode;

use crate::flags::oflags;
use crate::ssa::Ssa;

impl Ssa {
    /// `BlockBasic::isComplex` (block.cc:2417): more than two statements,
    /// counting the branch of a block with two or more out-edges, calls,
    /// output-less ops that do not break flow, and outputs that are unread,
    /// address-tied, read outside the block or by a marker, or read more
    /// than `max_implied_ref` times.
    pub fn is_complex(&self, b: NodeId, max_implied_ref: i32) -> bool {
        let mut statement = i32::from(self.outs(b).len() >= 2);
        for op in self.block_ops(b) {
            let Some(d) = self.ops.get(op.index()) else {
                continue;
            };
            if d.flags & oflags::MARKER != 0 {
                continue;
            }
            if d.flags & oflags::CALL != 0 {
                statement += 1;
            } else if let Some(vn) = d.output() {
                let readers = self.readers(vn);
                let mut yes = readers.len() == 0 || self.is_addr_tied(vn);
                if !yes {
                    let mut total = 0;
                    for r in readers {
                        let marker = self
                            .ops
                            .get(r.index())
                            .is_some_and(|rd| rd.flags & oflags::MARKER != 0);
                        if marker || self.op_parent(r) != Some(b) {
                            yes = true;
                            break;
                        }
                        total += 1;
                        if total > max_implied_ref {
                            yes = true;
                            break;
                        }
                    }
                }
                if yes {
                    statement += 1;
                }
            } else {
                if d.flags & (oflags::BRANCH | oflags::RETURNS) != 0 {
                    continue;
                }
                statement += 1;
            }
            if statement > 2 {
                return true;
            }
        }
        false
    }

    /// The facts of one block: `complex` (`isComplex`), `switch_out` (the
    /// `f_switch_out` flag), `ends_in_return` (last op is `RETURN`), and
    /// `negation_changes_dataflow` (always, for a basic block).
    pub fn block_fact(&self, b: NodeId, max_implied_ref: i32) -> Fact {
        Fact {
            complex: self.is_complex(b, max_implied_ref),
            switch_out: self.cfg.flags(b).unwrap_or(0) & node_flags::SWITCH_OUT != 0,
            ends_in_return: self
                .last_op(b)
                .is_some_and(|op| self.op_opcode(op) == Some(OpCode::Return)),
            negation_changes_dataflow: true,
        }
    }

    /// The facts of every basic block, indexed by node id, for
    /// `bk_decomp_cfg::structure`.
    pub fn block_facts(&self, max_implied_ref: i32) -> BlockFacts {
        let mut facts = BlockFacts::neutral(self.cfg.id_bound());
        for b in self.blocks() {
            facts.set(b.index(), self.block_fact(b, max_implied_ref));
        }
        facts
    }
}
