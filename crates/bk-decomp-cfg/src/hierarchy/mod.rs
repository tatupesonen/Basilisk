//! The structured-block hierarchy.
//!
//! Ghidra: the structured kinds of `block.hh` (`BlockCopy` … `BlockSwitch`)
//! and the `BlockGraph` methods that build them. A [`Hierarchy`] is the
//! result of one structuring run: an arena in which the input nodes are
//! copies with their input ids, the structured nodes follow, and the
//! top-level list holds what remained uncollapsed.

pub(crate) mod factories;
pub(crate) mod identify;
pub(crate) mod negate;
pub(crate) mod query;
pub(crate) mod switch;

use crate::flags::{CondOp, Kind, node_flags};
use crate::graph::{Edge, Graph, KindData, NodeId};
pub use switch::CaseOrder;

/// One half of an edge as seen from a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EdgeView {
    /// The node at the other end.
    pub node: NodeId,
    /// The position of the other half in that node's opposite list.
    pub rev: u32,
    /// The edge label ([`edge_labels`](crate::edge_labels)).
    pub label: u32,
}

impl From<&Edge> for EdgeView {
    fn from(e: &Edge) -> Self {
        Self {
            node: e.other,
            rev: e.rev,
            label: e.label,
        }
    }
}

/// The structured hierarchy produced by [`structure`](crate::structure).
///
/// Owns its data and is immutable apart from [`finish`](crate::finish);
/// node ids are stable within one result.
#[derive(Clone, Debug)]
pub struct Hierarchy {
    pub(crate) g: Graph,
    /// The number of input nodes (ids `0..inputs` are leaves or unused).
    pub(crate) inputs: usize,
    /// The out-degree of each input node in the input graph
    /// (`BlockBasic::getSplitPoint` asks it).
    pub(crate) input_out_degree: Vec<u32>,
    /// The index each input node had in the input graph (a copy's
    /// `altindex`).
    pub(crate) input_index: Vec<i32>,
}

impl Hierarchy {
    fn valid(&self, n: NodeId) -> bool {
        n.index() < self.g.nodes.len()
    }

    /// The top-level nodes in list order (the root graph's components).
    pub fn top_level(&self) -> &[NodeId] {
        &self.g.list
    }

    /// The number of nodes in the arena (input nodes plus structured nodes).
    pub fn node_count(&self) -> usize {
        self.g.nodes.len()
    }

    /// The number of input nodes; their ids are `0..input_count()`.
    pub fn input_count(&self) -> usize {
        self.inputs
    }

    /// The index the top-level graph carries (`BlockGraph::addBlock`'s
    /// minimum over everything added to it).
    pub fn root_index(&self) -> i32 {
        self.g.root_index.unwrap_or(0)
    }

    /// The kind of node `n`.
    pub fn kind(&self, n: NodeId) -> Option<Kind> {
        self.valid(n).then(|| self.g.node(n).kind)
    }

    /// The components of node `n` (`getBlock(i)`), empty for a leaf.
    pub fn components(&self, n: NodeId) -> &[NodeId] {
        if self.valid(n) {
            &self.g.node(n).comps
        } else {
            &[]
        }
    }

    /// The node containing `n`, or `None` on the top level.
    pub fn parent(&self, n: NodeId) -> Option<NodeId> {
        self.valid(n).then(|| self.g.node(n).parent).flatten()
    }

    /// `getIndex()`.
    pub fn index(&self, n: NodeId) -> i32 {
        if self.valid(n) {
            self.g.node(n).index
        } else {
            0
        }
    }

    /// The node's flag word ([`node_flags`](crate::node_flags)).
    pub fn flags(&self, n: NodeId) -> u32 {
        if self.valid(n) {
            self.g.node(n).flags
        } else {
            0
        }
    }

    /// `getStructureDepth()`.
    pub fn structure_depth(&self, n: NodeId) -> i32 {
        if self.valid(n) {
            self.g.node(n).depth
        } else {
            0
        }
    }

    /// `getBasicCount()`.
    pub fn leaf_count(&self, n: NodeId) -> i32 {
        if self.valid(n) {
            self.g.node(n).leaf_count
        } else {
            0
        }
    }

    /// The out-edges of `n`, in order.
    pub fn out_edges(&self, n: NodeId) -> Vec<EdgeView> {
        if !self.valid(n) {
            return Vec::new();
        }
        self.g.node(n).outs.iter().map(EdgeView::from).collect()
    }

    /// The in-edges of `n`, in order.
    pub fn in_edges(&self, n: NodeId) -> Vec<EdgeView> {
        if !self.valid(n) {
            return Vec::new();
        }
        self.g.node(n).ins.iter().map(EdgeView::from).collect()
    }

    /// The target and goto type of a goto or if-goto node.
    pub fn goto_target(&self, n: NodeId) -> Option<(NodeId, u32)> {
        if !self.valid(n) {
            return None;
        }
        match self.g.node(n).data {
            KindData::Goto { target, goto_type } => Some((target, goto_type)),
            _ => None,
        }
    }

    /// The goto targets of a multigoto node and whether one is the switch
    /// default.
    pub fn multi_goto(&self, n: NodeId) -> Option<(&[NodeId], bool)> {
        if !self.valid(n) {
            return None;
        }
        match &self.g.node(n).data {
            KindData::MultiGoto { targets, default } => Some((targets.as_slice(), *default)),
            _ => None,
        }
    }

    /// The stored opcode of a condition node.
    pub fn condition_op(&self, n: NodeId) -> Option<CondOp> {
        if !self.valid(n) {
            return None;
        }
        match self.g.node(n).data {
            KindData::Condition(op) => Some(op),
            _ => None,
        }
    }

    /// `BlockWhileDo::hasOverflowSyntax`.
    pub fn has_overflow_syntax(&self, n: NodeId) -> bool {
        self.flags(n) & node_flags::WHILEDO_OVERFLOW != 0
    }

    /// The cases of a switch node, in `caseblocks` order.
    pub fn cases(&self, n: NodeId) -> &[CaseOrder] {
        if !self.valid(n) {
            return &[];
        }
        match &self.g.node(n).data {
            KindData::Switch(cases) => cases,
            _ => &[],
        }
    }

    /// `getExitLeaf()`.
    pub fn exit_leaf(&self, n: NodeId) -> Option<NodeId> {
        self.valid(n).then(|| self.g.exit_leaf(n)).flatten()
    }

    /// `getFrontLeaf()`.
    pub fn front_leaf(&self, n: NodeId) -> Option<NodeId> {
        self.valid(n).then(|| self.g.front_leaf(n)).flatten()
    }

    /// `getSplitPoint()`: the deepest component deciding `n`'s two-way
    /// branch (block.hh:558, 655; block.cc:2379, 3038).
    pub fn split_point(&self, n: NodeId) -> Option<NodeId> {
        let mut bl = n;
        let mut guard = self.g.nodes.len();
        loop {
            if !self.valid(bl) || guard == 0 {
                return None;
            }
            guard -= 1;
            let node = self.g.node(bl);
            match node.kind {
                Kind::Copy => {
                    let degree = self.input_out_degree.get(bl.index()).copied().unwrap_or(0);
                    return (degree == 2).then_some(bl);
                }
                Kind::List => bl = *node.comps.last()?,
                Kind::Condition => return Some(bl),
                _ => return None,
            }
        }
    }

    /// `nextFlowAfter` of `n`'s container: the leaf that runs after `n`
    /// falls through, if unique.
    pub fn next_flow_after(&self, n: NodeId) -> Option<NodeId> {
        self.valid(n).then(|| self.g.next_flow_after(n)).flatten()
    }

    /// `isUnstructuredTarget()`.
    pub fn is_unstructured_target(&self, n: NodeId) -> bool {
        self.flags(n) & node_flags::UNSTRUCTURED_TARG != 0
    }

    /// `isLabelBumpUp()`.
    pub fn is_label_bump_up(&self, n: NodeId) -> bool {
        self.flags(n) & node_flags::LABEL_BUMPUP != 0
    }

    /// `BlockGoto::gotoPrints`: whether a goto node's goto is printed.
    pub fn goto_prints(&self, n: NodeId) -> bool {
        self.valid(n) && self.g.node(n).kind == Kind::Goto && self.g.goto_prints(n)
    }

    /// Checks `checkEdges` on every node of the arena (both halves of each
    /// edge agree).
    pub fn edges_consistent(&self) -> bool {
        (0..self.g.nodes.len()).all(|i| self.g.edges_consistent(NodeId::new(i as u32)))
    }
}

#[cfg(test)]
mod tests;
