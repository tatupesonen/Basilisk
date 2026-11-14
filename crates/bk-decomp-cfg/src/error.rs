//! Errors of the block graph and the structurer.
//!
//! One variant per Ghidra `LowlevelError` this code can raise, with Ghidra's
//! message as its `Display`, plus Basilisk's own for limits and for the
//! places where Ghidra's behaviour is undefined (ADR-009, ADR-024).

use thiserror::Error;

/// What a [`CfgError::LimitExceeded`] ran out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// Nodes of the input graph.
    Nodes,
    /// Edges of the input graph.
    Edges,
    /// Work steps (rule attempts, trace steps, analysis visits).
    Steps,
}

impl LimitKind {
    /// A short name for messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::Steps => "work steps",
        }
    }
}

/// An error of the block graph, its analyses, the structurer or the codec.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CfgError {
    /// `CollapseStructure::selectGoto` found no edge to make a goto
    /// (blockaction.cc:1275).
    #[error("Could not finish collapsing block structure")]
    CouldNotFinish,
    /// `BlockGraph::findSpanningTree` needed extra roots twice
    /// (block.cc:1124).
    #[error("Could not generate spanning tree")]
    SpanningTree,
    /// `BlockGraph::calcForwardDominator` found no usable root
    /// (block.cc:1998).
    #[error("Problems finding root node of graph")]
    RootNode,
    /// `BlockGraph::forceOutputNum` (block.cc:897; a debug-build check in
    /// Ghidra, raised by Basilisk only at its public API).
    #[error("Bad block output force")]
    OutputForce,
    /// `BlockGraph::forceFalseEdge` on a node without two out-edges
    /// (block.cc:1221).
    #[error("Can only preserve binary condition")]
    BinaryCondition,
    /// `BlockGraph::forceFalseEdge` could not put the given node at out-edge
    /// 0 (block.cc:1229).
    #[error("Unable to preserve condition")]
    PreserveCondition,
    /// `BlockGraph::newBlockSwitch`: the switch root has no exit leaf that is
    /// a copy (block.cc:1928).
    #[error("Could not get switch leaf")]
    SwitchLeaf,
    /// `BlockSwitch::addCase`: a case's first basic block has no edge from
    /// the switch block (block.cc:3631).
    #[error("Case block has become detached from switch")]
    CaseDetached,
    /// `BlockGraph::newBlockIfGoto` on a node whose true edge is not a goto
    /// (block.cc:1808).
    #[error("Building ifgoto where true branch is not the goto")]
    IfGotoTrueBranch,
    /// `FlowBlock::swapEdges` on a node without two out-edges
    /// (block.cc:227; a debug-build check in Ghidra).
    #[error("Swapping edges for block that doesn't have two edges")]
    SwapEdges,
    /// `FlowBlock::setGotoBranch` with an out-edge slot that does not exist
    /// (block.cc:314).
    #[error("Could not find block edge to mark unstructured")]
    GotoBranch,
    /// `BlockGraph::identifyInternal` with a node not in the graph
    /// (block.cc:960).
    #[error("Bad block identify")]
    BlockIdentify,
    /// `BlockGraph::addEdge` with a node not in the graph (block.cc:1449).
    #[error("Bad edge create")]
    EdgeCreate,
    /// `BlockGraph::removeEdge` with a node not in the graph or an edge that
    /// does not exist (block.cc:1479).
    #[error("Bad edge remove")]
    EdgeRemove,
    /// `BlockGraph::moveOutEdge` with a node not in the graph (block.cc:1512).
    #[error("Bad edge move")]
    EdgeMove,
    /// `BlockGraph::removeBlock` with a node not in the graph
    /// (block.cc:1527).
    #[error("Bad block remove")]
    BlockRemove,
    /// `BlockGraph::removeFromFlow` with a node not in the graph
    /// (block.cc:1555).
    #[error("Bad remove from flow")]
    RemoveFromFlow,
    /// `BlockGraph::removeFromFlow` on a node with inputs and more than one
    /// output (block.cc:1557).
    #[error("Illegal remove from flow")]
    IllegalRemoveFromFlow,
    /// `BlockGraph::removeFromFlowSplit` with a node not in the graph
    /// (block.cc:1585).
    #[error("Bad remove from flow split")]
    RemoveFromFlowSplit,
    /// `BlockGraph::removeFromFlowSplit` on a node without two inputs and
    /// two outputs (block.cc:1587).
    #[error("Illegal remove from flow split")]
    IllegalRemoveFromFlowSplit,
    /// `BlockGraph::spliceBlock` (block.cc:1612).
    #[error("Can only splice a block with 1 output to a block with 1 input")]
    Splice,
    /// `BlockGraph::setStartBlock` with a node not in the graph
    /// (block.cc:1635).
    #[error("Bad set start")]
    SetStart,
    /// `BlockGraph::getStartBlock` without an entry point (block.cc:1658).
    #[error("No start block registered")]
    NoStart,
    /// `BlockEdge::decode` naming a block that does not exist (block.cc:56).
    #[error("Bad serialized edge in block graph")]
    SerializedEdge,
    /// A limit of [`Limits`](crate::Limits) was reached (Basilisk; Ghidra has
    /// none).
    #[error("structuring limit exceeded: more than {limit} {}", what.name())]
    LimitExceeded {
        /// What ran out.
        what: LimitKind,
        /// The limit that was exceeded.
        limit: u64,
    },
    /// `BlockGraph::structureLoops` asked to rebuild the spanning tree more
    /// than once (Basilisk; in Ghidra the loop would never end,
    /// `docs/GHIDRA-BUGS.md` entry 24).
    #[error("spanning tree rebuild requested again (irreducible tree edge)")]
    SpanningTreeRebuild,
    /// `TraceDAG::selectBadEdge` with no candidate trace (Basilisk; Ghidra
    /// dereferences an empty list, `docs/GHIDRA-BUGS.md` entry 25).
    #[error("no candidate edge to mark as a goto (empty bad-edge list)")]
    NoBadEdge,
    /// A block document whose out-edge slots are not each named exactly
    /// once by an in-edge (Basilisk; Ghidra leaves them uninitialised,
    /// `docs/GHIDRA-BUGS.md` entry 26).
    #[error("bad edge slots in block graph: out-edge {slot} of block {block}")]
    BadEdgeSlots {
        /// The index of the block whose out-edge is missing or doubled.
        block: i64,
        /// The out-edge slot.
        slot: i64,
    },
    /// A block document with two blocks of one index, or a nested graph or
    /// copy block, which Ghidra cannot structure either (Basilisk).
    #[error("unsupported block document: {0}")]
    BadDocument(String),
    /// The XML could not be decoded.
    #[error("block document: {0}")]
    Decode(String),
    /// Indices that are not a reverse post-order of the node list where the
    /// dominator calculation needs one (Basilisk; Ghidra reads out of
    /// bounds).
    #[error("dominator calculation: node index {index} is not a list position")]
    BadIndex {
        /// The offending index.
        index: i64,
    },
    /// A node id that does not belong to the graph (Basilisk API misuse).
    #[error("node {0} is not in the graph")]
    NoSuchNode(u32),
    /// An internal consistency check failed; this is a bug in Basilisk.
    #[error("internal error in the structurer: {0}")]
    Internal(&'static str),
}
