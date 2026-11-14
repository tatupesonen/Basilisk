//! Negating the condition of a node.
//!
//! Ghidra: `FlowBlock::negateCondition` (block.cc:298), `BlockCopy`'s
//! (block.hh:557), `BlockList`'s (block.cc:3029) and `BlockCondition`'s
//! (3085). A copy negates its original basic block: here that is a *flip
//! event* recorded for the leaf, whose result is the leaf's
//! `negation_changes_dataflow` fact (ADR-028, ADR-042). Only the top node's
//! own out-edges are swapped: every inner call passes `false`.

use crate::error::CfgError;
use crate::facts::BlockFacts;
use crate::flags::Kind;
use crate::graph::{Graph, KindData, NodeId};

impl Graph {
    /// `negateCondition(true)` on `top`: records the flip events of the
    /// leaves reached (in Ghidra's call order) in `flips`, toggles the
    /// opcode of every condition reached, swaps `top`'s out-edges, and
    /// returns whether data-flow changed.
    pub(crate) fn negate_condition(
        &mut self,
        top: NodeId,
        facts: &BlockFacts,
        flips: &mut Vec<NodeId>,
        stack: &mut Vec<NodeId>,
    ) -> Result<bool, CfgError> {
        let mut changed = false;
        stack.clear();
        stack.push(top);
        while let Some(bl) = stack.pop() {
            let kind = self.node(bl).kind;
            match kind {
                Kind::Copy => {
                    flips.push(bl);
                    changed |= facts.get(bl.index()).negation_changes_dataflow;
                }
                Kind::List => {
                    if let Some(&last) = self.node(bl).comps.last() {
                        stack.push(last);
                    }
                }
                Kind::Condition => {
                    let node = self.node_mut(bl);
                    if let KindData::Condition(op) = &mut node.data {
                        *op = op.negated();
                    }
                    let c0 = node.comps.first().copied();
                    let c1 = node.comps.get(1).copied();
                    // Component 0 is negated before component 1.
                    if let Some(c1) = c1 {
                        stack.push(c1);
                    }
                    if let Some(c0) = c0 {
                        stack.push(c0);
                    }
                }
                _ => {}
            }
        }
        stack.clear();
        self.swap_edges(top)?;
        Ok(changed)
    }
}
