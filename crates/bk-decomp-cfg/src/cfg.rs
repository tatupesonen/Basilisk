//! The control-flow graph of a function as a value.
//!
//! Ghidra: a `BlockGraph` of basic blocks (`Funcdata::bblocks`) with the
//! graph-only methods of `FlowBlock` and `BlockGraph` (block.hh:76–462):
//! edge surgery, queries and the analyses the IR passes run on it. Ops are
//! not here (D05 attaches them to the nodes).

use crate::error::CfgError;
use crate::facts::BlockFacts;
use crate::graph::{Graph, NodeId, to_i32};
use crate::hierarchy::EdgeView;
use crate::limits::{Budget, Limits};

/// A flat control-flow graph: nodes in list order (Ghidra's
/// `BlockGraph::list`, whose order is behaviour) with ordered in- and
/// out-edges. Node ids are stable; the list order changes when
/// [`Cfg::structure_loops`] puts the nodes in reverse post-order. Cloning
/// is a few vector copies.
#[derive(Clone, Debug, Default)]
pub struct Cfg {
    pub(crate) g: Graph,
}

impl Cfg {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    fn live(&self, n: NodeId) -> Result<NodeId, CfgError> {
        if self.g.is_member(n) {
            Ok(n)
        } else {
            Err(CfgError::NoSuchNode(n.get()))
        }
    }

    /// `BlockGraph::newBlock` (block.cc:1664): a node with flag word
    /// `flags`, appended to the list. Its index is 0 until set.
    pub fn add_node(&mut self, flags: u32) -> Result<NodeId, CfgError> {
        self.g.new_plain(flags)
    }

    /// `BlockGraph::addEdge` (block.cc:1444): an edge `from -> to`, last in
    /// both lists, labelled 0.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId) -> Result<(), CfgError> {
        self.g.add_edge(from, to)
    }

    /// `BlockGraph::removeEdge` (block.cc:1474): the first edge
    /// `from -> to`.
    pub fn remove_edge(&mut self, from: NodeId, to: NodeId) -> Result<(), CfgError> {
        self.live(from).map_err(|_err| CfgError::EdgeRemove)?;
        self.live(to).map_err(|_err| CfgError::EdgeRemove)?;
        self.g.remove_edge(from, to)
    }

    /// `BlockGraph::switchEdge` (block.cc:1494).
    pub fn switch_edge(
        &mut self,
        from: NodeId,
        before: NodeId,
        after: NodeId,
    ) -> Result<(), CfgError> {
        self.live(from)?;
        self.live(before)?;
        self.live(after)?;
        self.g.switch_edge(from, before, after)
    }

    /// `BlockGraph::moveOutEdge` (block.cc:1507).
    pub fn move_out_edge(&mut self, old: NodeId, slot: usize, new: NodeId) -> Result<(), CfgError> {
        self.g.move_out_edge(old, slot, new)
    }

    /// `BlockGraph::removeBlock` (block.cc:1522). The id is not reused.
    pub fn remove_node(&mut self, n: NodeId) -> Result<(), CfgError> {
        self.g.remove_block(n)
    }

    /// `BlockGraph::removeFromFlow` (block.cc:1550).
    pub fn remove_from_flow(&mut self, n: NodeId) -> Result<(), CfgError> {
        self.g.remove_from_flow(n)
    }

    /// `BlockGraph::removeFromFlowSplit` (block.cc:1580).
    pub fn remove_from_flow_split(&mut self, n: NodeId, flipflow: bool) -> Result<(), CfgError> {
        self.g.remove_from_flow_split(n, flipflow)
    }

    /// `BlockGraph::spliceBlock` (block.cc:1602).
    pub fn splice_node(&mut self, n: NodeId) -> Result<(), CfgError> {
        self.g.splice_block(n)
    }

    /// `BlockGraph::setStartBlock` (block.cc:1630).
    pub fn set_start(&mut self, n: NodeId) -> Result<(), CfgError> {
        self.g.set_start_block(n)
    }

    /// `BlockGraph::getStartBlock` (block.cc:1654).
    pub fn start(&self) -> Result<NodeId, CfgError> {
        self.g.start_block()
    }

    /// `FlowBlock::setGotoBranch` (block.cc:309).
    pub fn set_goto_branch(&mut self, n: NodeId, slot: usize) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.set_goto_branch(n, slot)
    }

    /// `FlowBlock::setDefaultSwitch` (block.cc:322).
    pub fn set_default_switch(&mut self, n: NodeId, slot: usize) -> Result<(), CfgError> {
        self.live(n)?;
        if slot >= self.g.size_out(n) {
            return Err(CfgError::GotoBranch);
        }
        self.g.set_default_switch(n, slot)
    }

    /// `FlowBlock::swapEdges` (block.cc:222): swaps out-edges 0 and 1.
    pub fn swap_out_edges(&mut self, n: NodeId) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.swap_edges(n)
    }

    /// `FlowBlock::setOutEdgeFlag` (block.cc:244): ORs `label` into both
    /// halves of out-edge `slot`.
    pub fn set_out_edge_label(
        &mut self,
        n: NodeId,
        slot: usize,
        label: u32,
    ) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.set_out_edge_flag(n, slot, label)
    }

    /// `FlowBlock::clearOutEdgeFlag` (block.cc:254).
    pub fn clear_out_edge_label(
        &mut self,
        n: NodeId,
        slot: usize,
        label: u32,
    ) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.clear_out_edge_flag(n, slot, label)
    }

    /// The nodes in list order.
    pub fn nodes(&self) -> &[NodeId] {
        &self.g.list
    }

    /// The number of nodes in the list.
    pub fn len(&self) -> usize {
        self.g.list.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.g.list.is_empty()
    }

    /// The number of node ids ever allocated (the size facts are indexed by).
    pub fn id_bound(&self) -> usize {
        self.g.nodes.len()
    }

    /// The number of edges.
    pub fn edge_count(&self) -> usize {
        self.g.edge_count()
    }

    /// The out-edges of `n` in order.
    pub fn out_edges(&self, n: NodeId) -> Vec<EdgeView> {
        match self.live(n) {
            Ok(n) => self.g.node(n).outs.iter().map(EdgeView::from).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The in-edges of `n` in order.
    pub fn in_edges(&self, n: NodeId) -> Vec<EdgeView> {
        match self.live(n) {
            Ok(n) => self.g.node(n).ins.iter().map(EdgeView::from).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// `getIndex()`.
    pub fn index(&self, n: NodeId) -> Option<i32> {
        self.live(n).ok().map(|n| self.g.node(n).index)
    }

    /// Sets `index` (as given by the pipeline's own analysis).
    pub fn set_index(&mut self, n: NodeId, index: i32) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.node_mut(n).index = index;
        Ok(())
    }

    /// `getImmedDom()`.
    pub fn idom(&self, n: NodeId) -> Option<NodeId> {
        self.live(n).ok().and_then(|n| self.g.node(n).idom)
    }

    /// Sets the immediate dominator.
    pub fn set_idom(&mut self, n: NodeId, idom: Option<NodeId>) -> Result<(), CfgError> {
        self.live(n)?;
        if let Some(d) = idom {
            self.live(d)?;
        }
        self.g.node_mut(n).idom = idom;
        Ok(())
    }

    /// The number of spanning-tree descendants (`numdesc`).
    pub fn numdesc(&self, n: NodeId) -> Option<i32> {
        self.live(n).ok().map(|n| self.g.node(n).numdesc)
    }

    /// Sets `numdesc`.
    pub fn set_numdesc(&mut self, n: NodeId, numdesc: i32) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.node_mut(n).numdesc = numdesc;
        Ok(())
    }

    /// The flag word ([`node_flags`](crate::node_flags)).
    pub fn flags(&self, n: NodeId) -> Option<u32> {
        self.live(n).ok().map(|n| self.g.node(n).flags)
    }

    /// Replaces the flag word.
    pub fn set_flags(&mut self, n: NodeId, flags: u32) -> Result<(), CfgError> {
        self.live(n)?;
        self.g.node_mut(n).flags = flags;
        Ok(())
    }

    /// Adds an edge whose out-half is placed at out-slot `slot` of `from`
    /// and whose in-half is appended to `to` (how graph files list edges:
    /// per target, in in-edge order, each naming its out-slot). Slots must
    /// be filled exactly once; see [`Cfg::check_slots`].
    pub fn add_edge_at(
        &mut self,
        from: NodeId,
        slot: usize,
        to: NodeId,
        label: u32,
    ) -> Result<(), CfgError> {
        use crate::graph::{Edge, to_u32};
        self.live(from)?;
        self.live(to)?;
        let inslot = to_u32(self.g.size_in(to))?;
        let rev = to_u32(slot)?;
        self.g.node_mut(to).ins.push(Edge {
            label,
            other: from,
            rev,
        });
        let outs = &mut self.g.node_mut(from).outs;
        while outs.len() <= slot {
            outs.push(Edge {
                label: 0,
                other: NodeId::new(u32::MAX),
                rev: u32::MAX,
            });
        }
        match outs.get_mut(slot) {
            Some(e) if e.other == NodeId::new(u32::MAX) => {
                *e = Edge {
                    label,
                    other: to,
                    rev: inslot,
                };
                Ok(())
            }
            _ => Err(CfgError::BadEdgeSlots {
                block: i64::from(self.g.node(from).index),
                slot: slot as i64,
            }),
        }
    }

    /// Checks that every out-slot was filled by [`Cfg::add_edge_at`].
    pub fn check_slots(&self) -> Result<(), CfgError> {
        for &n in &self.g.list {
            if let Some(slot) = self
                .g
                .node(n)
                .outs
                .iter()
                .position(|e| e.other == NodeId::new(u32::MAX))
            {
                return Err(CfgError::BadEdgeSlots {
                    block: i64::from(self.g.node(n).index),
                    slot: slot as i64,
                });
            }
        }
        Ok(())
    }

    fn budget(&self) -> Result<Budget, CfgError> {
        Limits::default().budget(self.g.list.len(), self.g.edge_count())
    }

    /// `BlockGraph::structureLoops` (block.cc:2212): spanning tree, reverse
    /// post-order (the list is reordered and indices set), edge kinds,
    /// irreducible and loop edges. Returns the root list.
    pub fn structure_loops(&mut self) -> Result<Vec<NodeId>, CfgError> {
        let mut budget = self.budget()?;
        self.g.structure_loops(&mut budget)
    }

    /// `BlockGraph::calcForwardDominator` (block.cc:1972) with the roots of
    /// [`Cfg::structure_loops`].
    pub fn forward_dominators(&mut self, roots: &[NodeId]) -> Result<(), CfgError> {
        for &r in roots {
            self.live(r)?;
        }
        let mut budget = self.budget()?;
        self.g.calc_forward_dominator(roots, &mut budget)
    }

    /// `BlockGraph::buildDomTree` (block.cc:2054).
    pub fn dom_tree(&self) -> Result<Vec<Vec<NodeId>>, CfgError> {
        self.g.build_dom_tree()
    }

    /// `BlockGraph::buildDomDepth` (block.cc:2074).
    pub fn dom_depth(&self) -> Result<(Vec<i32>, i32), CfgError> {
        self.g.build_dom_depth()
    }

    /// `BlockGraph::buildDomSubTree` (block.cc:2098).
    pub fn dom_sub_tree(&self, root: NodeId) -> Result<Vec<NodeId>, CfgError> {
        Ok(self.g.build_dom_sub_tree(self.live(root)?))
    }

    /// `collectReachable(…, false)` (block.cc:2172).
    pub fn reachable(&mut self, from: NodeId) -> Result<Vec<NodeId>, CfgError> {
        let from = self.live(from)?;
        Ok(self.g.collect_reachable(from, false))
    }

    /// `collectReachable(…, true)`.
    pub fn unreachable(&mut self, from: NodeId) -> Result<Vec<NodeId>, CfgError> {
        let from = self.live(from)?;
        Ok(self.g.collect_reachable(from, true))
    }

    /// `FlowBlock::dominates` (block.cc:390).
    pub fn dominates(&self, a: NodeId, b: NodeId) -> Result<bool, CfgError> {
        Ok(self.g.dominates(self.live(a)?, self.live(b)?))
    }

    /// `FlowBlock::restrictedByConditional` (block.cc:409).
    pub fn restricted_by_conditional(&self, n: NodeId, cond: NodeId) -> Result<bool, CfgError> {
        Ok(self
            .g
            .restricted_by_conditional(self.live(n)?, self.live(cond)?))
    }

    /// `FlowBlock::findCommonBlock(bl1, bl2)` (block.cc:745).
    pub fn find_common_block(&mut self, a: NodeId, b: NodeId) -> Result<Option<NodeId>, CfgError> {
        let (a, b) = (self.live(a)?, self.live(b)?);
        Ok(self.g.find_common_block(a, b))
    }

    /// `FlowBlock::findCommonBlock(blockSet)` (block.cc:805).
    pub fn find_common_block_set(&mut self, set: &[NodeId]) -> Result<Option<NodeId>, CfgError> {
        for &n in set {
            self.live(n)?;
        }
        Ok(self.g.find_common_block_set(set))
    }

    /// `FlowBlock::findCondition` (block.cc:848).
    pub fn find_condition(
        &self,
        bl1: NodeId,
        edge1: usize,
        bl2: NodeId,
        edge2: usize,
    ) -> Result<Option<(NodeId, usize)>, CfgError> {
        self.g
            .find_condition(self.live(bl1)?, edge1, self.live(bl2)?, edge2)
    }

    /// `BlockGraph::orderBlocks` (block.hh:447) on this flat graph, sorted
    /// stably (ADR-040).
    pub fn order_by_final(&mut self, facts: &BlockFacts) {
        crate::finish::order_blocks(&mut self.g, facts);
    }

    /// `BlockGraph::decode` of a bare graph (what `structure blocks` reads),
    /// within `limits`.
    pub fn decode_xml(xml: &str, limits: &Limits) -> Result<Self, CfgError> {
        crate::codec::xml::decode_cfg(xml, limits)
    }

    /// `BlockGraph::encode` of this graph as a document of plain blocks.
    pub fn encode(&self, enc: &mut dyn bk_marshal::Encoder) -> Result<(), CfgError> {
        crate::codec::xml::encode_cfg(self, enc)
    }

    /// Numbers the nodes `0..n` in list order (a fresh graph's indices).
    pub fn number_in_list_order(&mut self) -> Result<(), CfgError> {
        for k in 0..self.g.list.len() {
            let Some(&n) = self.g.list.get(k) else {
                continue;
            };
            self.g.node_mut(n).index = to_i32(k)?;
        }
        Ok(())
    }

    /// Whether both halves of every edge agree (`checkEdges`).
    pub fn edges_consistent(&self) -> bool {
        self.g.list.iter().all(|&n| self.g.edges_consistent(n))
    }
}
