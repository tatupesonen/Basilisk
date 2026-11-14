//! Collapsing components into a structured node.
//!
//! Ghidra: `BlockGraph::addBlock` (block.cc:871), `forceOutputNum` (893),
//! `selfIdentify` (908), `identifyInternal` (953), `forceFalseEdge`
//! (1217). The edge order these produce decides which edge is "false"
//! later, so every scan is Ghidra's.

use crate::error::CfgError;
use crate::flags::{edge_labels, node_flags};
use crate::graph::{Graph, NodeId};

impl Graph {
    /// `BlockGraph::addBlock` (block.cc:871) on a structured node: `bl`
    /// becomes the last component of `ident`.
    pub(crate) fn add_block(&mut self, ident: NodeId, bl: NodeId) {
        let (min, leaves, depth) = {
            let b = self.node(bl);
            (b.index, b.leaf_count, b.depth.saturating_add(1))
        };
        self.node_mut(bl).parent = Some(ident);
        let node = self.node_mut(ident);
        if node.comps.is_empty() || min < node.index {
            node.index = min;
        }
        node.comps.push(bl);
        node.leaf_count = node.leaf_count.saturating_add(leaves);
        if depth > node.depth {
            node.depth = depth;
        }
    }

    /// `BlockGraph::forceOutputNum` (block.cc:893): adds self-edges labelled
    /// loop and back until `ident` has `i` out-edges. (Ghidra checks for
    /// more outputs than `i` only in debug builds; the release build, and
    /// this port, do nothing then.)
    pub(crate) fn force_output_num(&mut self, ident: NodeId, i: usize) -> Result<(), CfgError> {
        while self.size_out(ident) < i {
            self.add_in_edge(ident, ident, edge_labels::LOOP | edge_labels::BACK)?;
        }
        Ok(())
    }

    /// `BlockGraph::selfIdentify` (block.cc:908): `ident` inherits every
    /// edge between a component and the outside, then the duplicates are
    /// merged.
    pub(crate) fn self_identify(
        &mut self,
        ident: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<(), CfgError> {
        let ncomps = self.node(ident).comps.len();
        for c in 0..ncomps {
            let mybl = self.comp(ident, c)?;
            let mut i = 0;
            while i < self.size_in(mybl) {
                let otherbl = self.in_(mybl, i)?;
                if self.node(otherbl).parent == Some(ident) {
                    i += 1;
                    continue;
                }
                for j in 0..self.size_out(otherbl) {
                    if self.out(otherbl, j)? == mybl {
                        self.replace_out_edge(otherbl, j, ident)?;
                    }
                }
                // Do not advance: slot i now holds the next in-edge.
            }
            let mut i = 0;
            while i < self.size_out(mybl) {
                let otherbl = self.out(mybl, i)?;
                if self.node(otherbl).parent == Some(ident) {
                    i += 1;
                    continue;
                }
                for j in 0..self.size_in(otherbl) {
                    if self.in_(otherbl, j)? == mybl {
                        self.replace_in_edge(otherbl, j, ident)?;
                    }
                }
                if self.node(mybl).is_switch_out() {
                    self.node_mut(ident).flags |= node_flags::SWITCH_OUT;
                }
            }
        }
        self.dedup(ident, scratch)
    }

    /// `BlockGraph::identifyInternal` (block.cc:953): moves `nodes` (in
    /// order) from the top-level list into `ident` and lets `ident` take
    /// over their outside edges. The caller appends `ident` to the list.
    pub(crate) fn identify_internal(
        &mut self,
        ident: NodeId,
        nodes: &[NodeId],
        scratch: &mut Vec<NodeId>,
    ) -> Result<(), CfgError> {
        for &n in nodes {
            if self.node(n).parent.is_some() || self.node(n).removed {
                return Err(CfgError::BlockIdentify);
            }
        }
        for &n in nodes {
            self.set_mark(n);
            self.add_block(ident, n);
            let fl =
                self.node(n).flags & (node_flags::INTERIOR_GOTOOUT | node_flags::INTERIOR_GOTOIN);
            self.node_mut(ident).flags |= fl;
        }
        let nodes_arena = &mut self.nodes;
        self.list.retain(|&n| match nodes_arena.get_mut(n.index()) {
            Some(node) if node.flags & node_flags::MARK != 0 => {
                node.flags &= !node_flags::MARK;
                false
            }
            _ => true,
        });
        self.self_identify(ident, scratch)
    }

    /// `BlockGraph::forceFalseEdge` (block.cc:1217): out-edge 0 of `ident`
    /// must go to `out0` (or to `ident` itself when `out0` was absorbed);
    /// swaps the two out-edges if needed.
    pub(crate) fn force_false_edge(
        &mut self,
        ident: NodeId,
        out0: Option<NodeId>,
    ) -> Result<(), CfgError> {
        if self.size_out(ident) != 2 {
            return Err(CfgError::BinaryCondition);
        }
        // Ghidra dereferences a null `out0`; no out-edge can match it.
        let Some(mut out0) = out0 else {
            return Err(CfgError::PreserveCondition);
        };
        if self.node(out0).parent == Some(ident) {
            out0 = ident;
        }
        if self.out(ident, 0)? != out0 {
            self.swap_edges(ident)?;
        }
        if self.out(ident, 0)? != out0 {
            return Err(CfgError::PreserveCondition);
        }
        Ok(())
    }
}
