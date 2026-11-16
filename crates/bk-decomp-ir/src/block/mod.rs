//! Basic blocks: `bk-decomp-cfg` nodes plus, here, their op lists and
//! original address ranges (Ghidra `BlockBasic`, block.hh:470–531,
//! block.cc:2270–2900).

mod facts;
mod query;

use bk_core::{Address, RangeList};
use bk_decomp_cfg::{EdgeView, NodeId, node_flags};
use bk_pcode::OpCode;

use crate::data::BasicData;
use crate::error::{IrError, IrResult};
use crate::flags::oflags;
use crate::ids::{NONE, OpId};
use crate::list::Thread;
use crate::ssa::Ssa;

impl Ssa {
    /// Adds a basic block to the graph (`BlockGraph::newBlockBasic`): a new
    /// node with the flag word `flags`, no ops, no ranges.
    pub fn add_block(&mut self, flags: u32) -> IrResult<NodeId> {
        let n = self.cfg.add_node(flags)?;
        if self.blocks.len() <= n.index() {
            self.blocks.resize_with(n.index() + 1, BasicData::default);
        }
        if let Some(b) = self.blocks.get_mut(n.index()) {
            *b = BasicData {
                present: true,
                ..BasicData::default()
            };
        }
        Ok(n)
    }

    /// The block graph, for edge surgery (`bk-decomp-cfg`'s methods). Ops
    /// stay attached to their nodes; removing a node that still has ops is
    /// the caller's error to avoid (D07 combines both).
    pub fn cfg_mut(&mut self) -> &mut bk_decomp_cfg::Cfg {
        &mut self.cfg
    }

    pub(crate) fn bdata(&self, b: NodeId) -> IrResult<&BasicData> {
        self.blocks
            .get(b.index())
            .filter(|d| d.present)
            .ok_or_else(|| IrError::NoSuchBlock(b.get()))
    }

    fn bdata_mut(&mut self, b: NodeId) -> IrResult<&mut BasicData> {
        self.blocks
            .get_mut(b.index())
            .filter(|d| d.present)
            .ok_or_else(|| IrError::NoSuchBlock(b.get()))
    }

    /// Whether `b` is a basic block of this function.
    pub fn is_block(&self, b: NodeId) -> bool {
        self.bdata(b).is_ok()
    }

    /// The block's ops in order (`beginOp`..`endOp`).
    pub fn block_ops(&self, b: NodeId) -> Vec<OpId> {
        self.bdata(b)
            .map(|d| d.ops.collect(&self.links, Thread::Block))
            .unwrap_or_default()
    }

    /// The number of ops in the block.
    pub fn block_len(&self, b: NodeId) -> usize {
        self.bdata(b).map_or(0, |d| d.ops.len())
    }

    /// `BlockBasic::firstOp`.
    pub fn first_op(&self, b: NodeId) -> Option<OpId> {
        self.bdata(b).ok()?.ops.first()
    }

    /// `BlockBasic::lastOp`.
    pub fn last_op(&self, b: NodeId) -> Option<OpId> {
        self.bdata(b).ok()?.ops.last()
    }

    /// The op after `op` in its block.
    pub fn op_next_in_block(&self, op: OpId) -> Option<OpId> {
        self.links.get(op.index())?.next(Thread::Block)
    }

    /// The op before `op` in its block (`PcodeOp::previousOp`).
    pub fn op_prev_in_block(&self, op: OpId) -> Option<OpId> {
        self.links.get(op.index())?.prev(Thread::Block)
    }

    /// The out-edges of a block.
    pub(crate) fn outs(&self, b: NodeId) -> Vec<EdgeView> {
        self.cfg.out_edges(b)
    }

    /// The in-edges of a block.
    pub(crate) fn ins(&self, b: NodeId) -> Vec<EdgeView> {
        self.cfg.in_edges(b)
    }

    /// `BlockBasic::insert`: puts `op` before `before` (`None`: at the end)
    /// and gives it an `order` between its neighbours, renumbering the block
    /// when there is no room; a `BRANCHIND` sets the block's `f_switch_out`.
    pub(crate) fn block_insert(
        &mut self,
        b: NodeId,
        before: Option<OpId>,
        op: OpId,
    ) -> IrResult<()> {
        if let Some(bf) = before
            && self.opd(bf)?.parent != b.get()
        {
            return Err(IrError::NotInBlock {
                method: "insert",
                op: bf,
            });
        }
        let links = &mut self.links;
        let data = self
            .blocks
            .get_mut(b.index())
            .filter(|d| d.present)
            .ok_or_else(|| IrError::NoSuchBlock(b.get()))?;
        data.ops.insert_before(links, Thread::Block, op, before);
        if let Some(d) = self.ops.get_mut(op.index()) {
            d.parent = b.get();
        }
        let prev = self.op_prev_in_block(op);
        let ordbefore = prev
            .and_then(|p| self.ops.get(p.index()))
            .map_or(2, |d| d.order);
        let ordafter = match before {
            None => {
                let a = ordbefore.wrapping_add(0x100_0000);
                if a <= ordbefore { u32::MAX } else { a }
            }
            Some(bf) => self.ops.get(bf.index()).map_or(0, |d| d.order),
        };
        if ordafter.wrapping_sub(ordbefore) <= 1 {
            self.set_order(b);
        } else if let Some(d) = self.ops.get_mut(op.index()) {
            d.order = ordafter / 2 + ordbefore / 2;
        }
        let d = self.opd(op)?;
        if d.flags & oflags::BRANCH != 0 && d.opcode() == Some(OpCode::BranchInd) {
            let f = self.cfg.flags(b).unwrap_or(0);
            self.cfg.set_flags(b, f | node_flags::SWITCH_OUT)?;
        }
        Ok(())
    }

    /// `BlockBasic::removeOp`.
    pub(crate) fn block_remove_op(&mut self, op: OpId) -> IrResult<()> {
        let parent = self.opd(op)?.parent;
        if parent == NONE {
            return Err(IrError::NotInBlock {
                method: "removeOp",
                op,
            });
        }
        let links = &mut self.links;
        if let Some(data) = self.blocks.get_mut(parent as usize) {
            data.ops.remove(links, Thread::Block, op);
        }
        if let Some(d) = self.ops.get_mut(op.index()) {
            d.parent = NONE;
        }
        Ok(())
    }

    /// `BlockBasic::setOrder`: renumbers the block's ops `step, 2*step, …`
    /// with `step = 0xffffffff / n - 1` (block.cc:2700). Ghidra divides by
    /// zero for an empty block; here an empty block has nothing to number.
    pub fn set_order(&mut self, b: NodeId) {
        let ops = self.block_ops(b);
        let n = ops.len().max(1) as u32;
        let step = (u32::MAX / n).wrapping_sub(1);
        let mut count = 0u32;
        for op in ops {
            count = count.wrapping_add(step);
            if let Some(d) = self.ops.get_mut(op.index()) {
                d.order = count;
            }
        }
    }

    /// `BlockBasic::setInitialRange`.
    pub fn set_initial_range(&mut self, b: NodeId, beg: Address, end: Address) -> IrResult<()> {
        let d = self.bdata_mut(b)?;
        d.cover.clear();
        if let Some(space) = beg.space() {
            d.cover.insert_range(space, beg.offset(), end.offset());
        }
        Ok(())
    }

    /// `BlockBasic::copyRange`.
    pub fn copy_range(&mut self, b: NodeId, from: NodeId) -> IrResult<()> {
        let c = self.bdata(from)?.cover.clone();
        self.bdata_mut(b)?.cover = c;
        Ok(())
    }

    /// `BlockBasic::mergeRange`.
    pub fn merge_range(&mut self, b: NodeId, from: NodeId) -> IrResult<()> {
        let c = self.bdata(from)?.cover.clone();
        self.bdata_mut(b)?.cover.merge(&c);
        Ok(())
    }

    /// Replaces the block's ranges (`decodeBody`).
    pub fn set_block_ranges(&mut self, b: NodeId, ranges: RangeList) -> IrResult<()> {
        self.bdata_mut(b)?.cover = ranges;
        Ok(())
    }

    /// The block's original address ranges (`BlockBasic::cover`).
    pub fn block_ranges(&self, b: NodeId) -> Option<&RangeList> {
        self.bdata(b).ok().map(|d| &d.cover)
    }

    /// The basic blocks in graph list order.
    pub fn blocks(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.cfg
            .nodes()
            .iter()
            .copied()
            .filter(|&n| self.is_block(n))
    }

    /// The block with Ghidra index `index` (`getBlock(i)` after
    /// `structureReset`, where index equals list position).
    pub fn block_by_index(&self, index: i32) -> Option<NodeId> {
        self.blocks().find(|&n| self.cfg.index(n) == Some(index))
    }
}
