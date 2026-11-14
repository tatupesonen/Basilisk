//! Edge surgery on single nodes.
//!
//! Ghidra: the private edge methods of `FlowBlock` (block.cc:77–330,
//! 450–543). Each function says which method it is; the order of every
//! list mutation is Ghidra's, since later rules read edge positions.

use super::{Edge, Graph, NodeId, to_u32};
use crate::error::CfgError;
use crate::flags::{edge_labels, node_flags};

const SLOT: CfgError = CfgError::Internal("edge slot");

impl Graph {
    fn in_slot_mut(&mut self, id: NodeId, slot: usize) -> Result<&mut Edge, CfgError> {
        self.node_mut(id).ins.get_mut(slot).ok_or(SLOT)
    }

    fn out_slot_mut(&mut self, id: NodeId, slot: usize) -> Result<&mut Edge, CfgError> {
        self.node_mut(id).outs.get_mut(slot).ok_or(SLOT)
    }

    /// `FlowBlock::addInEdge` (block.cc:77): an edge `b -> this` with label
    /// `lab`, appended to both lists.
    pub(crate) fn add_in_edge(
        &mut self,
        this: NodeId,
        b: NodeId,
        lab: u32,
    ) -> Result<(), CfgError> {
        let ourrev = to_u32(self.size_out(b))?;
        let brev = to_u32(self.size_in(this))?;
        self.node_mut(this).ins.push(Edge {
            label: lab,
            other: b,
            rev: ourrev,
        });
        self.node_mut(b).outs.push(Edge {
            label: lab,
            other: this,
            rev: brev,
        });
        Ok(())
    }

    /// `FlowBlock::halfDeleteInEdge` (block.cc:104): removes in-slot `slot`
    /// of `this`, sliding later entries down and correcting the reverse
    /// indices of their other halves.
    pub(crate) fn half_delete_in_edge(
        &mut self,
        this: NodeId,
        mut slot: usize,
    ) -> Result<(), CfgError> {
        let len = self.size_in(this);
        if slot >= len {
            return Err(SLOT);
        }
        while slot + 1 < len {
            let next = *self.node(this).ins.get(slot + 1).ok_or(SLOT)?;
            *self.in_slot_mut(this, slot)? = next;
            let r = self.out_slot_mut(next.other, next.rev as usize)?;
            r.rev = r.rev.wrapping_sub(1);
            slot += 1;
        }
        self.node_mut(this).ins.pop();
        Ok(())
    }

    /// `FlowBlock::halfDeleteOutEdge` (block.cc:119).
    pub(crate) fn half_delete_out_edge(
        &mut self,
        this: NodeId,
        mut slot: usize,
    ) -> Result<(), CfgError> {
        let len = self.size_out(this);
        if slot >= len {
            return Err(SLOT);
        }
        while slot + 1 < len {
            let next = *self.node(this).outs.get(slot + 1).ok_or(SLOT)?;
            *self.out_slot_mut(this, slot)? = next;
            let r = self.in_slot_mut(next.other, next.rev as usize)?;
            r.rev = r.rev.wrapping_sub(1);
            slot += 1;
        }
        self.node_mut(this).outs.pop();
        Ok(())
    }

    /// `FlowBlock::removeInEdge` (block.cc:134).
    pub(crate) fn remove_in_edge(&mut self, this: NodeId, slot: usize) -> Result<(), CfgError> {
        let e = self.in_edge(this, slot)?;
        self.half_delete_in_edge(this, slot)?;
        self.half_delete_out_edge(e.other, e.rev as usize)
    }

    /// `FlowBlock::removeOutEdge` (block.cc:148).
    pub(crate) fn remove_out_edge(&mut self, this: NodeId, slot: usize) -> Result<(), CfgError> {
        let e = self.out_edge(this, slot)?;
        self.half_delete_out_edge(this, slot)?;
        self.half_delete_in_edge(e.other, e.rev as usize)
    }

    /// `FlowBlock::replaceInEdge` (block.cc:164): in-slot `num` of `this`
    /// comes from `b` instead; the slot stays, the new out half is appended
    /// to `b`.
    pub(crate) fn replace_in_edge(
        &mut self,
        this: NodeId,
        num: usize,
        b: NodeId,
    ) -> Result<(), CfgError> {
        let old = self.in_edge(this, num)?;
        self.half_delete_out_edge(old.other, old.rev as usize)?;
        let rev = to_u32(self.size_out(b))?;
        let label = {
            let e = self.in_slot_mut(this, num)?;
            e.other = b;
            e.rev = rev;
            e.label
        };
        let num = to_u32(num)?;
        self.node_mut(b).outs.push(Edge {
            label,
            other: this,
            rev: num,
        });
        Ok(())
    }

    /// `FlowBlock::replaceOutEdge` (block.cc:182).
    pub(crate) fn replace_out_edge(
        &mut self,
        this: NodeId,
        num: usize,
        b: NodeId,
    ) -> Result<(), CfgError> {
        let old = self.out_edge(this, num)?;
        self.half_delete_in_edge(old.other, old.rev as usize)?;
        let rev = to_u32(self.size_in(b))?;
        let label = {
            let e = self.out_slot_mut(this, num)?;
            e.other = b;
            e.rev = rev;
            e.label
        };
        let num = to_u32(num)?;
        self.node_mut(b).ins.push(Edge {
            label,
            other: this,
            rev: num,
        });
        Ok(())
    }

    /// `FlowBlock::replaceEdgesThru` (block.cc:202): removes in-slot `inn`
    /// and out-slot `out` of `this`, joining their far ends in place.
    pub(crate) fn replace_edges_thru(
        &mut self,
        this: NodeId,
        inn: usize,
        out: usize,
    ) -> Result<(), CfgError> {
        let ie = self.in_edge(this, inn)?;
        let oe = self.out_edge(this, out)?;
        {
            let e = self.out_slot_mut(ie.other, ie.rev as usize)?;
            e.other = oe.other;
            e.rev = oe.rev;
        }
        {
            let e = self.in_slot_mut(oe.other, oe.rev as usize)?;
            e.other = ie.other;
            e.rev = ie.rev;
        }
        self.half_delete_in_edge(this, inn)?;
        self.half_delete_out_edge(this, out)
    }

    /// `FlowBlock::swapEdges` (block.cc:222): swaps out-edges 0 and 1 and
    /// toggles `f_flip_path`.
    pub(crate) fn swap_edges(&mut self, this: NodeId) -> Result<(), CfgError> {
        if self.size_out(this) != 2 {
            return Err(CfgError::SwapEdges);
        }
        self.node_mut(this).outs.swap(0, 1);
        let e0 = self.out_edge(this, 0)?;
        self.in_slot_mut(e0.other, e0.rev as usize)?.rev = 0;
        let e1 = self.out_edge(this, 1)?;
        self.in_slot_mut(e1.other, e1.rev as usize)?.rev = 1;
        self.node_mut(this).flags ^= node_flags::FLIP_PATH;
        Ok(())
    }

    /// `FlowBlock::setOutEdgeFlag` (block.cc:244): sets `lab` on both halves.
    pub(crate) fn set_out_edge_flag(
        &mut self,
        this: NodeId,
        i: usize,
        lab: u32,
    ) -> Result<(), CfgError> {
        let e = {
            let e = self.out_slot_mut(this, i)?;
            e.label |= lab;
            *e
        };
        self.in_slot_mut(e.other, e.rev as usize)?.label |= lab;
        Ok(())
    }

    /// `FlowBlock::clearOutEdgeFlag` (block.cc:254).
    pub(crate) fn clear_out_edge_flag(
        &mut self,
        this: NodeId,
        i: usize,
        lab: u32,
    ) -> Result<(), CfgError> {
        let e = {
            let e = self.out_slot_mut(this, i)?;
            e.label &= !lab;
            *e
        };
        self.in_slot_mut(e.other, e.rev as usize)?.label &= !lab;
        Ok(())
    }

    /// `FlowBlock::setGotoBranch` (block.cc:309): labels out-edge `i` a goto
    /// and sets `f_interior_gotoout` here and `f_interior_gotoin` on the
    /// target.
    pub(crate) fn set_goto_branch(&mut self, this: NodeId, i: usize) -> Result<(), CfgError> {
        if i >= self.size_out(this) {
            return Err(CfgError::GotoBranch);
        }
        self.set_out_edge_flag(this, i, edge_labels::GOTO)?;
        self.node_mut(this).flags |= node_flags::INTERIOR_GOTOOUT;
        let target = self.out(this, i)?;
        self.node_mut(target).flags |= node_flags::INTERIOR_GOTOIN;
        Ok(())
    }

    /// `FlowBlock::setDefaultSwitch` (block.cc:322): out-edge `pos` becomes
    /// the only default edge.
    pub(crate) fn set_default_switch(&mut self, this: NodeId, pos: usize) -> Result<(), CfgError> {
        for i in 0..self.size_out(this) {
            if self.is_default_branch(this, i)? {
                self.clear_out_edge_flag(this, i, edge_labels::DEFAULT_SWITCH)?;
            }
        }
        self.set_out_edge_flag(this, pos, edge_labels::DEFAULT_SWITCH)
    }

    /// `FlowBlock::eliminateInDups` (block.cc:450): merges every in-edge from
    /// `bl` into the first, OR-ing labels into the kept in half only.
    fn eliminate_in_dups(&mut self, this: NodeId, bl: NodeId) -> Result<(), CfgError> {
        let mut indval: Option<usize> = None;
        let mut i = 0;
        while i < self.size_in(this) {
            let e = self.in_edge(this, i)?;
            if e.other != bl {
                i += 1;
                continue;
            }
            match indval {
                None => {
                    indval = Some(i);
                    i += 1;
                }
                Some(k) => {
                    self.in_slot_mut(this, k)?.label |= e.label;
                    self.half_delete_in_edge(this, i)?;
                    self.half_delete_out_edge(bl, e.rev as usize)?;
                }
            }
        }
        Ok(())
    }

    /// `FlowBlock::eliminateOutDups` (block.cc:479).
    fn eliminate_out_dups(&mut self, this: NodeId, bl: NodeId) -> Result<(), CfgError> {
        let mut indval: Option<usize> = None;
        let mut i = 0;
        while i < self.size_out(this) {
            let e = self.out_edge(this, i)?;
            if e.other != bl {
                i += 1;
                continue;
            }
            match indval {
                None => {
                    indval = Some(i);
                    i += 1;
                }
                Some(k) => {
                    self.out_slot_mut(this, k)?.label |= e.label;
                    self.half_delete_out_edge(this, i)?;
                    self.half_delete_in_edge(bl, e.rev as usize)?;
                }
            }
        }
        Ok(())
    }

    /// `FlowBlock::findDups` (block.cc:511) over the in-list (`ins`) or the
    /// out-list: the nodes at the end of more than one edge, in order of
    /// their second occurrence. Uses and clears `f_mark`/`f_mark2`.
    fn find_dups(&mut self, this: NodeId, ins: bool, dups: &mut Vec<NodeId>) {
        let len = if ins {
            self.size_in(this)
        } else {
            self.size_out(this)
        };
        for i in 0..len {
            let other = {
                let n = self.node(this);
                let list = if ins { &n.ins } else { &n.outs };
                match list.get(i) {
                    Some(e) => e.other,
                    None => continue,
                }
            };
            let f = &mut self.node_mut(other).flags;
            if *f & node_flags::MARK2 != 0 {
                continue;
            }
            if *f & node_flags::MARK != 0 {
                dups.push(other);
                *f |= node_flags::MARK2;
            } else {
                *f |= node_flags::MARK;
            }
        }
        for i in 0..len {
            let other = {
                let n = self.node(this);
                let list = if ins { &n.ins } else { &n.outs };
                match list.get(i) {
                    Some(e) => e.other,
                    None => continue,
                }
            };
            self.node_mut(other).flags &= !(node_flags::MARK | node_flags::MARK2);
        }
    }

    /// `FlowBlock::dedup` (block.cc:529): duplicate in-edges, then duplicate
    /// out-edges, merged into the first. `scratch` is reused storage.
    pub(crate) fn dedup(
        &mut self,
        this: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<(), CfgError> {
        scratch.clear();
        self.find_dups(this, true, scratch);
        for k in 0..scratch.len() {
            if let Some(&d) = scratch.get(k) {
                self.eliminate_in_dups(this, d)?;
            }
        }
        scratch.clear();
        self.find_dups(this, false, scratch);
        for k in 0..scratch.len() {
            if let Some(&d) = scratch.get(k) {
                self.eliminate_out_dups(this, d)?;
            }
        }
        scratch.clear();
        Ok(())
    }
}
