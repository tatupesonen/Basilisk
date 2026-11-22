//! Block surgery: the edge edits of the graph through a guard that cannot
//! add or remove nodes, and the node edits that must keep the op lists in
//! step (`BlockGraph::removeBlock` and `Funcdata::spliceBlockBasic`,
//! `funcdata_block.cc:927`–`967`, the parts below `structureReset`).

use std::ops::Deref;

use bk_decomp_cfg::{BlockFacts, Cfg, CfgError, NodeId};
use bk_pcode::OpCode;

use crate::data::BasicData;
use crate::error::{IrError, IrResult};
use crate::flags::oflags;
use crate::list::Thread;
use crate::ssa::Ssa;

/// The block graph for edits that leave the set of nodes alone (edges,
/// labels, flags, indexes, dominators, structuring). It reads as a
/// [`Cfg`]. Nodes are added with [`Ssa::add_block`] and leave with
/// [`Ssa::remove_block`] or [`Ssa::splice_block_basic`], which keep each
/// node's op list and ranges in step; the guard has no `add_node`,
/// `remove_node` or `splice_node`, so a block holding ops cannot be
/// dropped from the graph by mistake.
#[derive(Debug)]
pub struct CfgMut<'a> {
    cfg: &'a mut Cfg,
}

impl Deref for CfgMut<'_> {
    type Target = Cfg;

    fn deref(&self) -> &Cfg {
        self.cfg
    }
}

macro_rules! forward {
    ($( $(#[$m:meta])* fn $name:ident(&mut self $(, $a:ident: $t:ty)*) -> $r:ty; )*) => {$(
        $(#[$m])*
        #[doc = ""]
        #[doc = concat!("Forwards to [`Cfg::", stringify!($name), "`].")]
        pub fn $name(&mut self $(, $a: $t)*) -> $r {
            self.cfg.$name($($a),*)
        }
    )*};
}

impl CfgMut<'_> {
    forward! {
        /// `BlockGraph::addEdge`.
        fn add_edge(&mut self, from: NodeId, to: NodeId) -> Result<(), CfgError>;
        /// An edge inserted at an out slot with a label.
        fn add_edge_at(&mut self, from: NodeId, slot: usize, to: NodeId, label: u32) -> Result<(), CfgError>;
        /// `BlockGraph::removeEdge`.
        fn remove_edge(&mut self, from: NodeId, to: NodeId) -> Result<(), CfgError>;
        /// `BlockGraph::switchEdge`.
        fn switch_edge(&mut self, from: NodeId, before: NodeId, after: NodeId) -> Result<(), CfgError>;
        /// `BlockGraph::moveOutEdge`.
        fn move_out_edge(&mut self, old: NodeId, slot: usize, new: NodeId) -> Result<(), CfgError>;
        /// `BlockGraph::removeFromFlow` (the node stays; remove it with
        /// [`Ssa::remove_block`]).
        fn remove_from_flow(&mut self, n: NodeId) -> Result<(), CfgError>;
        /// `BlockGraph::removeFromFlowSplit` (the node stays).
        fn remove_from_flow_split(&mut self, n: NodeId, flipflow: bool) -> Result<(), CfgError>;
        /// `BlockGraph::setStartBlock`.
        fn set_start(&mut self, n: NodeId) -> Result<(), CfgError>;
        /// `FlowBlock::setGotoBranch`.
        fn set_goto_branch(&mut self, n: NodeId, slot: usize) -> Result<(), CfgError>;
        /// `FlowBlock::setDefaultSwitch`.
        fn set_default_switch(&mut self, n: NodeId, slot: usize) -> Result<(), CfgError>;
        /// `FlowBlock::swapEdges`.
        fn swap_out_edges(&mut self, n: NodeId) -> Result<(), CfgError>;
        /// `FlowBlock::setOutEdgeFlag`.
        fn set_out_edge_label(&mut self, n: NodeId, slot: usize, label: u32) -> Result<(), CfgError>;
        /// `FlowBlock::clearOutEdgeFlag`.
        fn clear_out_edge_label(&mut self, n: NodeId, slot: usize, label: u32) -> Result<(), CfgError>;
        /// Sets `index`.
        fn set_index(&mut self, n: NodeId, index: i32) -> Result<(), CfgError>;
        /// Sets `immed_dom`.
        fn set_idom(&mut self, n: NodeId, idom: Option<NodeId>) -> Result<(), CfgError>;
        /// Sets `numdesc`.
        fn set_numdesc(&mut self, n: NodeId, numdesc: i32) -> Result<(), CfgError>;
        /// Sets the flag word.
        fn set_flags(&mut self, n: NodeId, flags: u32) -> Result<(), CfgError>;
        /// `BlockGraph::structureLoops`.
        fn structure_loops(&mut self) -> Result<Vec<NodeId>, CfgError>;
        /// `BlockGraph::calcForwardDominator`.
        fn forward_dominators(&mut self, roots: &[NodeId]) -> Result<(), CfgError>;
        /// The nodes reachable from `from`.
        fn reachable(&mut self, from: NodeId) -> Result<Vec<NodeId>, CfgError>;
        /// The nodes not reachable from `from`.
        fn unreachable(&mut self, from: NodeId) -> Result<Vec<NodeId>, CfgError>;
        /// `FlowBlock::findCommonBlock`.
        fn find_common_block(&mut self, a: NodeId, b: NodeId) -> Result<Option<NodeId>, CfgError>;
        /// `FlowBlock::findCommonBlock` over a set.
        fn find_common_block_set(&mut self, set: &[NodeId]) -> Result<Option<NodeId>, CfgError>;
        /// Clears edge labels everywhere.
        fn clear_edge_labels(&mut self, labels: u32) -> ();
        /// Orders the list by the final facts.
        fn order_by_final(&mut self, facts: &BlockFacts) -> ();
        /// Numbers the nodes in list order.
        fn number_in_list_order(&mut self) -> Result<(), CfgError>;
    }
}

impl Ssa {
    /// The block graph for edge surgery ([`CfgMut`]).
    pub fn cfg_mut(&mut self) -> CfgMut<'_> {
        CfgMut { cfg: &mut self.cfg }
    }

    /// `BlockGraph::removeBlock` for a basic block: drops `b` and its
    /// edges from the graph. Refused while `b` holds ops (Ghidra destroys
    /// them first, `blockRemoveInternal`, `funcdata_block.cc:319`–`341`).
    pub fn remove_block(&mut self, b: NodeId) -> IrResult<()> {
        let n = self.bdata(b)?.ops.len();
        if n != 0 {
            return Err(IrError::BlockHasOps {
                method: "removeBlock",
                block: b.get(),
            });
        }
        self.cfg.remove_node(b)?;
        if let Some(d) = self.blocks.get_mut(b.index()) {
            *d = BasicData::default();
        }
        Ok(())
    }

    /// `Funcdata::spliceBlockBasic` without its `structureReset`
    /// (`funcdata_block.cc:927`–`967`): `bl`'s single successor, which has `bl`
    /// as its single predecessor, is merged into `bl`. A branch ending `bl`
    /// is destroyed, the successor's ops move to the end of `bl` (the first
    /// loses `startbasic`), `bl` is renumbered, its ranges take the
    /// successor's, and the graph splices the successor out.
    pub fn splice_block_basic(&mut self, bl: NodeId) -> IrResult<()> {
        self.bdata(bl)?;
        let outbl = match (self.cfg.out_len(bl), self.cfg.out_edge(bl, 0)) {
            (1, Some(e)) if self.cfg.in_len(e.node) == 1 && self.is_block(e.node) => e.node,
            _ => return Err(IrError::CannotSplice(bl.get())),
        };
        let first = self.first_op(outbl);
        if first.is_some_and(|f| self.op_opcode(f) == Some(OpCode::MultiEqual)) {
            return Err(IrError::SpliceMultiequal(bl.get()));
        }
        if let Some(jump) = self
            .last_op(bl)
            .filter(|&j| self.op_flags(j) & oflags::BRANCH != 0)
        {
            self.op_destroy(jump)?;
        }
        if let Some(f) = first {
            self.opd_mut(f)?.flags &= !oflags::STARTBASIC;
            let moved: Vec<_> = self.block_ops(outbl).collect();
            for op in moved {
                let links = &mut self.links;
                if let Some(d) = self.blocks.get_mut(outbl.index()) {
                    d.ops.remove(links, Thread::Block, op);
                }
                if let Some(d) = self.blocks.get_mut(bl.index()) {
                    d.ops.push_back(links, Thread::Block, op);
                }
                if let Some(d) = self.ops.get_mut(op.index()) {
                    d.parent = bl.get();
                }
            }
            self.set_order(bl);
        }
        self.merge_range(bl, outbl)?;
        self.cfg.splice_node(bl)?;
        if let Some(d) = self.blocks.get_mut(outbl.index()) {
            *d = BasicData::default();
        }
        Ok(())
    }
}
