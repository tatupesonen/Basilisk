//! `print tree block`: the hierarchy as indented text.
//!
//! Ghidra: `FlowBlock::printTree` (block.cc:620), `BlockGraph::printTree`
//! (1304), `BlockCopy::printTree` (2904) and the `printHeader` of every
//! kind (block.cc:608, 2897, 2954, 2986, 3045, 3103, 3136, 3162, 3193,
//! 3244, 3452, 3564, 3592, 3755). A copy prints through its original basic
//! block, whose line the caller supplies.

use std::fmt::Write as _;

use crate::flags::{Kind, node_flags};
use crate::graph::{KindData, NodeId};
use crate::hierarchy::Hierarchy;

/// The `printHeader` line of a structured node (without indentation).
fn header(h: &Hierarchy, n: NodeId, out: &mut String) {
    let node = h.g.node(n);
    let name = match node.kind {
        Kind::List => "List block ",
        Kind::Condition => match node.data {
            KindData::Condition(op) => {
                let _ = write!(out, "Condition block({}) ", op.symbol());
                ""
            }
            _ => "Condition block(||) ",
        },
        Kind::If => "If block ",
        Kind::IfElse => "If/else block ",
        Kind::IfNoExit => "If (no exit) block ",
        Kind::IfGoto => "If goto block ",
        Kind::WhileDo => {
            if node.flags & node_flags::WHILEDO_OVERFLOW != 0 {
                "Whiledo block (overflow) "
            } else {
                "Whiledo block "
            }
        }
        Kind::DoWhile => "Dowhile block ",
        Kind::InfLoop => "Infinite loop block ",
        Kind::Switch => "Switch block ",
        Kind::Goto => "Plain goto block ",
        Kind::MultiGoto => "Multi goto block ",
        Kind::Copy => "Basic(copy) block ",
        Kind::Plain => "",
    };
    out.push_str(name);
    let _ = write!(out, "{}", node.index);
}

impl Hierarchy {
    /// `printTree` of the top-level graph's components, two spaces per
    /// level. `leaf(out, node, level)` writes the whole line of a leaf (a
    /// copy prints as its basic block: `Basic Block <index> <start>-<stop>`,
    /// indented and with its newline).
    pub fn print_tree(&self, out: &mut String, leaf: &dyn Fn(&mut String, NodeId, usize)) {
        let mut stack: Vec<(NodeId, usize)> = self.g.list.iter().rev().map(|&n| (n, 0)).collect();
        while let Some((n, level)) = stack.pop() {
            let node = self.g.node(n);
            if node.kind.is_structured() {
                for _ in 0..level {
                    out.push_str("  ");
                }
                header(self, n, out);
                out.push('\n');
                stack.extend(node.comps.iter().rev().map(|&c| (c, level + 1)));
            } else {
                leaf(out, n, level);
            }
        }
    }

    /// The `printHeader` line of node `n`, as Ghidra prints it for a
    /// structured node or a copy (`Basic(copy) block <index>`).
    pub fn header(&self, n: NodeId) -> String {
        let mut s = String::new();
        if n.index() < self.g.nodes.len() {
            header(self, n, &mut s);
        }
        s
    }

    /// Writes the top-level graph as `structure blocks` does
    /// (`BlockGraph::encode`); a copy's `altindex` is its input node's
    /// index in the input graph.
    pub fn encode(&self, enc: &mut dyn bk_marshal::Encoder) -> Result<(), crate::CfgError> {
        let orig = |n: NodeId| self.input_index.get(n.index()).copied().unwrap_or(0);
        super::xml::encode_hierarchy(self, &orig, enc)
    }
}
