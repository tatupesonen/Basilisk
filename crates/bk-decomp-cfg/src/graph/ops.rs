//! Graph-level edits of a flat graph.
//!
//! Ghidra: the public editing methods of `BlockGraph` (block.cc:1444–1670).
//! The membership checks that Ghidra makes only in debug builds
//! (`BLOCKCONSISTENT_DEBUG`) are made always here, since these are public
//! entry points.

use super::{Graph, Node, NodeId};
use crate::error::CfgError;
use crate::flags::{Kind, edge_labels, node_flags};

impl Graph {
    /// Whether `id` is a live top-level node of this graph.
    pub(crate) fn is_member(&self, id: NodeId) -> bool {
        self.nodes
            .get(id.index())
            .is_some_and(|n| n.parent.is_none() && !n.removed)
    }

    fn member(&self, id: NodeId, err: CfgError) -> Result<NodeId, CfgError> {
        if self.is_member(id) { Ok(id) } else { Err(err) }
    }

    /// `BlockGraph::newBlock` (block.cc:1664): a plain node appended to the
    /// list.
    pub(crate) fn new_plain(&mut self, flags: u32) -> Result<NodeId, CfgError> {
        let mut node = Node::new(Kind::Plain);
        node.flags = flags;
        let id = self.push(node)?;
        self.add_block_root(id);
        Ok(id)
    }

    /// `BlockGraph::addBlock` (block.cc:871) on the top-level graph: appends
    /// `id` to the list and keeps the graph's index the minimum.
    pub(crate) fn add_block_root(&mut self, id: NodeId) {
        let index = self.node(id).index;
        self.root_index = Some(self.root_index.map_or(index, |r| r.min(index)));
        self.node_mut(id).parent = None;
        self.list.push(id);
    }

    /// `BlockGraph::addEdge` (block.cc:1444).
    pub(crate) fn add_edge(&mut self, begin: NodeId, end: NodeId) -> Result<(), CfgError> {
        self.member(begin, CfgError::EdgeCreate)?;
        self.member(end, CfgError::EdgeCreate)?;
        self.add_in_edge(end, begin, 0)
    }

    /// `BlockGraph::addLoopEdge` (block.cc:1456).
    pub(crate) fn add_loop_edge(&mut self, begin: NodeId, outindex: usize) -> Result<(), CfgError> {
        self.set_out_edge_flag(begin, outindex, edge_labels::LOOP)
    }

    /// `BlockGraph::removeEdge` (block.cc:1474): the first edge
    /// `begin -> end`.
    pub(crate) fn remove_edge(&mut self, begin: NodeId, end: NodeId) -> Result<(), CfgError> {
        let i = self.in_index(end, begin).ok_or(CfgError::EdgeRemove)?;
        self.remove_in_edge(end, i)
    }

    /// `BlockGraph::switchEdge` (block.cc:1494): every edge
    /// `inn -> outbefore` goes to `outafter` instead, in place.
    pub(crate) fn switch_edge(
        &mut self,
        inn: NodeId,
        outbefore: NodeId,
        outafter: NodeId,
    ) -> Result<(), CfgError> {
        let mut i = 0;
        while i < self.size_out(inn) {
            if self.out(inn, i)? == outbefore {
                self.replace_out_edge(inn, i, outafter)?;
            }
            i += 1;
        }
        Ok(())
    }

    /// `BlockGraph::moveOutEdge` (block.cc:1507): out-edge `slot` of `blold`
    /// leaves from `blnew` instead.
    pub(crate) fn move_out_edge(
        &mut self,
        blold: NodeId,
        slot: usize,
        blnew: NodeId,
    ) -> Result<(), CfgError> {
        self.member(blold, CfgError::EdgeMove)?;
        self.member(blnew, CfgError::EdgeMove)?;
        let e = self.out_edge(blold, slot)?;
        self.replace_in_edge(e.other, e.rev as usize, blnew)
    }

    /// `BlockGraph::removeBlock` (block.cc:1522): removes every edge of `bl`
    /// and takes it out of the list. The arena keeps the node, so other ids
    /// stay valid.
    pub(crate) fn remove_block(&mut self, bl: NodeId) -> Result<(), CfgError> {
        self.member(bl, CfgError::BlockRemove)?;
        while self.size_in(bl) > 0 {
            let from = self.in_(bl, 0)?;
            self.remove_edge(from, bl)?;
        }
        while self.size_out(bl) > 0 {
            let to = self.out(bl, 0)?;
            self.remove_edge(bl, to)?;
        }
        if let Some(pos) = self.list.iter().position(|&n| n == bl) {
            self.list.remove(pos);
        }
        self.node_mut(bl).removed = true;
        Ok(())
    }

    /// `BlockGraph::removeFromFlow` (block.cc:1550).
    pub(crate) fn remove_from_flow(&mut self, bl: NodeId) -> Result<(), CfgError> {
        self.member(bl, CfgError::RemoveFromFlow)?;
        if self.size_in(bl) > 0 && self.size_out(bl) > 1 {
            return Err(CfgError::IllegalRemoveFromFlow);
        }
        while self.size_out(bl) > 0 {
            let last = self.size_out(bl) - 1;
            let bbout = self.out(bl, last)?;
            self.remove_out_edge(bl, last)?;
            while self.size_in(bl) > 0 {
                let e = self.in_edge(bl, 0)?;
                self.replace_out_edge(e.other, e.rev as usize, bbout)?;
            }
        }
        Ok(())
    }

    /// `BlockGraph::removeFromFlowSplit` (block.cc:1580).
    pub(crate) fn remove_from_flow_split(
        &mut self,
        bl: NodeId,
        flipflow: bool,
    ) -> Result<(), CfgError> {
        self.member(bl, CfgError::RemoveFromFlowSplit)?;
        if self.size_in(bl) != 2 || self.size_out(bl) != 2 {
            return Err(CfgError::IllegalRemoveFromFlowSplit);
        }
        if flipflow {
            self.replace_edges_thru(bl, 0, 1)?;
        } else {
            self.replace_edges_thru(bl, 1, 1)?;
        }
        self.replace_edges_thru(bl, 0, 0)
    }

    /// `BlockGraph::spliceBlock` (block.cc:1602).
    pub(crate) fn splice_block(&mut self, bl: NodeId) -> Result<(), CfgError> {
        self.member(bl, CfgError::Splice)?;
        let outbl = if self.size_out(bl) == 1 {
            let o = self.out(bl, 0)?;
            (self.size_in(o) == 1).then_some(o)
        } else {
            None
        };
        let outbl = outbl.ok_or(CfgError::Splice)?;
        let fl1 = self.node(bl).flags & (node_flags::UNSTRUCTURED_TARG | node_flags::ENTRY_POINT);
        let fl2 = self.node(outbl).flags & node_flags::SWITCH_OUT;
        self.remove_out_edge(bl, 0)?;
        let szout = self.size_out(outbl);
        for _ in 0..szout {
            self.move_out_edge(outbl, 0, bl)?;
        }
        self.remove_block(outbl)?;
        self.node_mut(bl).flags = fl1 | fl2;
        Ok(())
    }

    /// `BlockGraph::setStartBlock` (block.cc:1630).
    pub(crate) fn set_start_block(&mut self, bl: NodeId) -> Result<(), CfgError> {
        self.member(bl, CfgError::SetStart)?;
        let first = *self.list.first().ok_or(CfgError::SetStart)?;
        if self.node(first).flags & node_flags::ENTRY_POINT != 0 {
            if first == bl {
                return Ok(());
            }
            self.node_mut(first).flags &= !node_flags::ENTRY_POINT;
        }
        if let Some(pos) = self.list.iter().position(|&n| n == bl) {
            self.list.remove(pos);
            self.list.insert(0, bl);
        }
        self.node_mut(bl).flags |= node_flags::ENTRY_POINT;
        Ok(())
    }

    /// `BlockGraph::getStartBlock` (block.cc:1654).
    pub(crate) fn start_block(&self) -> Result<NodeId, CfgError> {
        match self.list.first() {
            Some(&f) if self.node(f).flags & node_flags::ENTRY_POINT != 0 => Ok(f),
            _ => Err(CfgError::NoStart),
        }
    }
}
