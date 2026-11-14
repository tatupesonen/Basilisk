//! The arena behind every graph of this crate.
//!
//! Ghidra: `BlockEdge`, `FlowBlock` and the component list of `BlockGraph`
//! (block.hh:60–462). A [`Graph`] holds every node ever created in one
//! arena (nothing is freed while a structuring run lasts, so ids never
//! dangle) and the top-level node list in Ghidra's `BlockGraph::list` order.
//! A node on the top level has no parent: it belongs to the graph itself.
//! Structured nodes keep their components in [`Node::comps`].
//!
//! Edge lists keep Ghidra's order and its shifting deletion, because the
//! rules read edge positions (out-edge 0 is the false branch, 1 the true
//! branch).

pub(crate) mod ops;
pub(crate) mod surgery;

use crate::error::CfgError;
use crate::flags::{CondOp, Kind, edge_labels, node_flags};
use crate::hierarchy::switch::CaseOrder;

/// A node of a graph: an index into its arena. Input nodes keep their ids
/// in the structured hierarchy; structured nodes are appended after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// The node with arena index `index`.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The arena index.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The arena index as a `usize`.
    #[inline]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    pub(crate) fn from_usize(i: usize) -> Result<Self, CfgError> {
        u32::try_from(i)
            .map(Self)
            .map_err(|_err| CfgError::Internal("node id overflow"))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One half of an edge (`BlockEdge`): its label, the node at the other end,
/// and the position of the other half in that node's opposite list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Edge {
    pub(crate) label: u32,
    pub(crate) other: NodeId,
    pub(crate) rev: u32,
}

/// Data that only some kinds carry.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) enum KindData {
    /// Nothing beyond the common fields.
    #[default]
    None,
    /// `BlockGoto` and `BlockIfGoto`: the target and the goto type.
    Goto { target: NodeId, goto_type: u32 },
    /// `BlockMultiGoto`: the goto targets and whether one is the switch
    /// default.
    MultiGoto { targets: Vec<NodeId>, default: bool },
    /// `BlockCondition`: the stored opcode.
    Condition(CondOp),
    /// `BlockSwitch`: the cases (`caseblocks`).
    Switch(Vec<CaseOrder>),
}

/// A node (`FlowBlock` and its subclasses' data).
#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    pub(crate) data: KindData,
    pub(crate) flags: u32,
    pub(crate) index: i32,
    pub(crate) visit: i32,
    pub(crate) numdesc: i32,
    pub(crate) leaf_count: i32,
    pub(crate) depth: i32,
    pub(crate) parent: Option<NodeId>,
    pub(crate) idom: Option<NodeId>,
    pub(crate) copymap: Option<NodeId>,
    pub(crate) ins: Vec<Edge>,
    pub(crate) outs: Vec<Edge>,
    pub(crate) comps: Vec<NodeId>,
    /// Taken out of its graph by `removeBlock` (Ghidra deletes the object).
    pub(crate) removed: bool,
}

impl Node {
    /// A node as `FlowBlock`'s constructor makes it (block.cc:61), with the
    /// `leafCount` of 0 that `BlockGraph`'s constructor gives structured
    /// kinds (block.hh:395).
    pub(crate) fn new(kind: Kind) -> Self {
        Self {
            kind,
            data: KindData::None,
            flags: 0,
            index: 0,
            visit: 0,
            numdesc: 0,
            leaf_count: i32::from(!kind.is_structured()),
            depth: 0,
            parent: None,
            idom: None,
            copymap: None,
            ins: Vec::new(),
            outs: Vec::new(),
            comps: Vec::new(),
            removed: false,
        }
    }

    #[inline]
    pub(crate) fn is_mark(&self) -> bool {
        self.flags & node_flags::MARK != 0
    }

    #[inline]
    pub(crate) fn is_switch_out(&self) -> bool {
        self.flags & node_flags::SWITCH_OUT != 0
    }

    #[inline]
    pub(crate) fn is_interior_goto_target(&self) -> bool {
        self.flags & node_flags::INTERIOR_GOTOIN != 0
    }
}

/// An arena of nodes and the top-level list.
#[derive(Clone, Debug, Default)]
pub(crate) struct Graph {
    pub(crate) nodes: Vec<Node>,
    pub(crate) list: Vec<NodeId>,
    /// The graph's own index, kept as `BlockGraph::addBlock` keeps it for
    /// the top-level graph (the minimum over everything ever added).
    pub(crate) root_index: Option<i32>,
}

impl Graph {
    /// The node `id`. Ids are made by this arena and never freed; ids from
    /// outside are checked by [`Graph::check`] at the public API.
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "NodeIds are created by this arena and never freed; public entry points validate foreign ids with Graph::check"
    )]
    pub(crate) fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.index()]
    }

    /// The node `id`, mutably. See [`Graph::node`].
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "NodeIds are created by this arena and never freed; public entry points validate foreign ids with Graph::check"
    )]
    pub(crate) fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id.index()]
    }

    /// Checks that `id` belongs to this arena.
    pub(crate) fn check(&self, id: NodeId) -> Result<NodeId, CfgError> {
        if id.index() < self.nodes.len() {
            Ok(id)
        } else {
            Err(CfgError::NoSuchNode(id.get()))
        }
    }

    /// Appends a node to the arena (not to any list).
    pub(crate) fn push(&mut self, node: Node) -> Result<NodeId, CfgError> {
        let id = NodeId::from_usize(self.nodes.len())?;
        self.nodes.push(node);
        Ok(id)
    }

    /// The `i`-th out-edge of `id`.
    #[inline]
    pub(crate) fn out_edge(&self, id: NodeId, i: usize) -> Result<Edge, CfgError> {
        self.node(id)
            .outs
            .get(i)
            .copied()
            .ok_or(CfgError::Internal("out-edge slot"))
    }

    /// The `i`-th in-edge of `id`.
    #[inline]
    pub(crate) fn in_edge(&self, id: NodeId, i: usize) -> Result<Edge, CfgError> {
        self.node(id)
            .ins
            .get(i)
            .copied()
            .ok_or(CfgError::Internal("in-edge slot"))
    }

    /// `getOut(i)`.
    #[inline]
    pub(crate) fn out(&self, id: NodeId, i: usize) -> Result<NodeId, CfgError> {
        self.out_edge(id, i).map(|e| e.other)
    }

    /// `getIn(i)`.
    #[inline]
    pub(crate) fn in_(&self, id: NodeId, i: usize) -> Result<NodeId, CfgError> {
        self.in_edge(id, i).map(|e| e.other)
    }

    /// `sizeOut()`.
    #[inline]
    pub(crate) fn size_out(&self, id: NodeId) -> usize {
        self.node(id).outs.len()
    }

    /// `sizeIn()`.
    #[inline]
    pub(crate) fn size_in(&self, id: NodeId) -> usize {
        self.node(id).ins.len()
    }

    /// `isGotoOut(i)`.
    #[inline]
    pub(crate) fn is_goto_out(&self, id: NodeId, i: usize) -> Result<bool, CfgError> {
        Ok(self.out_edge(id, i)?.label & edge_labels::ANY_GOTO != 0)
    }

    /// `isGotoIn(i)`.
    #[inline]
    pub(crate) fn is_goto_in(&self, id: NodeId, i: usize) -> Result<bool, CfgError> {
        Ok(self.in_edge(id, i)?.label & edge_labels::ANY_GOTO != 0)
    }

    /// `isDecisionOut(i)`.
    #[inline]
    pub(crate) fn is_decision_out(&self, id: NodeId, i: usize) -> Result<bool, CfgError> {
        Ok(self.out_edge(id, i)?.label & edge_labels::NOT_DECISION == 0)
    }

    /// `isBackEdgeOut(i)`.
    #[inline]
    pub(crate) fn is_back_edge_out(&self, id: NodeId, i: usize) -> Result<bool, CfgError> {
        Ok(self.out_edge(id, i)?.label & edge_labels::BACK != 0)
    }

    /// `isDefaultBranch(i)`.
    #[inline]
    pub(crate) fn is_default_branch(&self, id: NodeId, i: usize) -> Result<bool, CfgError> {
        Ok(self.out_edge(id, i)?.label & edge_labels::DEFAULT_SWITCH != 0)
    }

    /// `getInIndex(bl)`: the first in-edge slot from `from`.
    pub(crate) fn in_index(&self, id: NodeId, from: NodeId) -> Option<usize> {
        self.node(id).ins.iter().position(|e| e.other == from)
    }

    /// `getOutIndex(bl)`: the first out-edge slot to `to`.
    pub(crate) fn out_index(&self, id: NodeId, to: NodeId) -> Option<usize> {
        self.node(id).outs.iter().position(|e| e.other == to)
    }

    /// `getBlock(i)` of a structured node.
    #[inline]
    pub(crate) fn comp(&self, id: NodeId, i: usize) -> Result<NodeId, CfgError> {
        self.node(id)
            .comps
            .get(i)
            .copied()
            .ok_or(CfgError::Internal("component slot"))
    }

    /// Sets the mark flag of `id`.
    #[inline]
    pub(crate) fn set_mark(&mut self, id: NodeId) {
        self.node_mut(id).flags |= node_flags::MARK;
    }

    /// Clears the mark flag of `id`.
    #[inline]
    pub(crate) fn clear_mark(&mut self, id: NodeId) {
        self.node_mut(id).flags &= !node_flags::MARK;
    }

    /// Clears the mark of every node in `body` (`LoopBody::clearMarks`).
    pub(crate) fn clear_marks(&mut self, body: &[NodeId]) {
        for &b in body {
            self.clear_mark(b);
        }
    }

    /// The total number of out-edges of the top-level nodes.
    pub(crate) fn edge_count(&self) -> usize {
        self.list.iter().map(|&n| self.node(n).outs.len()).sum()
    }

    /// `clearVisitCount` (block.cc:1958).
    pub(crate) fn clear_visit_count(&mut self) {
        for i in 0..self.list.len() {
            if let Some(&n) = self.list.get(i) {
                self.node_mut(n).visit = 0;
            }
        }
    }

    /// `checkEdges` (block.cc:549, debug builds only in Ghidra): both halves
    /// of every edge of `id` point at each other. Labels are not compared:
    /// `eliminateInDups`/`eliminateOutDups` OR labels into one half only
    /// (block.cc:463, 492), so the halves can differ, as in Ghidra.
    pub(crate) fn edges_consistent(&self, id: NodeId) -> bool {
        let node = self.node(id);
        let ins_ok = node.ins.iter().enumerate().all(|(i, e)| {
            self.nodes
                .get(e.other.index())
                .and_then(|o| o.outs.get(e.rev as usize))
                .is_some_and(|r| r.other == id && r.rev as usize == i)
        });
        let outs_ok = node.outs.iter().enumerate().all(|(i, e)| {
            self.nodes
                .get(e.other.index())
                .and_then(|o| o.ins.get(e.rev as usize))
                .is_some_and(|r| r.other == id && r.rev as usize == i)
        });
        ins_ok && outs_ok
    }
}

/// Bytes of one node of a graph or hierarchy, without its edge and
/// component lists (each edge half is [`EDGE_HALF_BYTES`], each component
/// 4 bytes).
pub const NODE_BYTES: usize = size_of::<Node>();
/// Bytes of one half of an edge; an edge has two.
pub const EDGE_HALF_BYTES: usize = size_of::<Edge>();

/// Converts a slot or count to Ghidra's `int4`.
#[inline]
pub(crate) fn to_i32(v: usize) -> Result<i32, CfgError> {
    i32::try_from(v).map_err(|_err| CfgError::Internal("count overflow"))
}

/// Converts a slot to the `u32` stored in an edge.
#[inline]
pub(crate) fn to_u32(v: usize) -> Result<u32, CfgError> {
    u32::try_from(v).map_err(|_err| CfgError::Internal("slot overflow"))
}
