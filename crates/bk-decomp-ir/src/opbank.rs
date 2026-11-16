//! The op bank (Ghidra `PcodeOpBank`, op.cc:920–1307): the two sequence
//! trees, the alive and dead lists, the per-opcode lists and the retired
//! ops.

use std::ops::Bound;

use bk_core::Address;
use bk_pcode::OpCode;

use crate::data::{OpData, Tree};
use crate::error::{IrError, IrResult};
use crate::flags::{oaddl, oflags};
use crate::ids::{NONE, OpId};
use crate::list::{OpLinks, Thread};
use crate::pool::IdList;
use crate::props::props;
use crate::ssa::{CodeList, Ssa};

/// The most ops one function may create.
pub const MAX_OPS: usize = 0x7fff_ffff;

impl Ssa {
    fn alloc_op(&mut self, inputs: usize, pc: Address, time: u32, tree: Tree) -> IrResult<OpId> {
        if self.ops.len() >= MAX_OPS || inputs > 0xffff {
            return Err(IrError::Limit {
                what: "op",
                limit: MAX_OPS as u64,
            });
        }
        let id = OpId(self.ops.len() as u32);
        let mut list = IdList::default();
        list.reset(&mut self.pool, inputs, NONE);
        self.ops.push(OpData {
            pc,
            time,
            order: 0,
            flags: oflags::DEAD,
            addl: 0,
            parent: NONE,
            output: NONE,
            inputs: list,
            opcode: 0,
            tree,
        });
        self.links.push(OpLinks::default());
        match tree {
            Tree::Alt => {
                self.alttree.insert((pc, time), id);
            }
            _ => {
                self.optree.insert((pc, time), id);
            }
        }
        self.dead.push_back(&mut self.links, Thread::Life, id);
        Ok(id)
    }

    /// The op holding sequence number `(pc, time)` in either tree.
    pub(crate) fn seq_taken(&self, pc: Address, time: u32) -> Option<OpId> {
        self.optree
            .get(&(pc, time))
            .or_else(|| self.alttree.get(&(pc, time)))
            .copied()
    }

    /// `PcodeOpBank::create(inputs, pc)`: a dead op with the next time.
    pub(crate) fn bank_create_op(&mut self, inputs: usize, pc: Address) -> IrResult<OpId> {
        let time = self.op_time;
        if let Some(existing) = self.seq_taken(pc, time) {
            return Err(IrError::DuplicateSeqNum { existing });
        }
        let id = self.alloc_op(inputs, pc, time, Tree::Main)?;
        self.op_time = self.op_time.wrapping_add(1);
        Ok(id)
    }

    /// `PcodeOpBank::create(inputs, sq)`: a dead op with the given sequence
    /// number; the time counter moves past it.
    pub(crate) fn bank_create_op_at(
        &mut self,
        inputs: usize,
        pc: Address,
        time: u32,
    ) -> IrResult<OpId> {
        if let Some(existing) = self.seq_taken(pc, time) {
            return Err(IrError::DuplicateSeqNum { existing });
        }
        let id = self.alloc_op(inputs, pc, time, Tree::Main)?;
        if time >= self.op_time {
            self.op_time = time.wrapping_add(1);
        }
        Ok(id)
    }

    /// `PcodeOpBank::createIndirect`: a dead op with two input slots in
    /// `alttree`.
    pub(crate) fn bank_create_indirect(&mut self, pc: Address) -> IrResult<OpId> {
        let time = self.op_time;
        if let Some(existing) = self.seq_taken(pc, time) {
            return Err(IrError::DuplicateSeqNum { existing });
        }
        let id = self.alloc_op(2, pc, time, Tree::Alt)?;
        self.op_time = self.op_time.wrapping_add(1);
        Ok(id)
    }

    fn remove_from_code_list(&mut self, op: OpId) {
        let Some(l) = self.links.get_mut(op.index()) else {
            return;
        };
        let Some(list) = CodeList::from_u8(l.code_list) else {
            return;
        };
        l.code_list = 0;
        if let Some(head) = self.code.get_mut(list.slot()) {
            head.remove(&mut self.links, Thread::Code, op);
        }
    }

    fn add_to_code_list(&mut self, op: OpId, opcode: OpCode) {
        let Some(list) = CodeList::of(opcode) else {
            return;
        };
        if let Some(head) = self.code.get_mut(list.slot()) {
            head.push_back(&mut self.links, Thread::Code, op);
        }
        if let Some(l) = self.links.get_mut(op.index()) {
            l.code_list = list as u8;
        }
    }

    /// `PcodeOpBank::changeOpcode`: the op leaves its opcode list; an op
    /// whose current opcode is `INDIRECT` moves from `alttree` to `optree`;
    /// `PcodeOp::setOpcode` replaces the opcode bits of the flags.
    pub(crate) fn bank_change_opcode(&mut self, op: OpId, opcode: OpCode) -> IrResult<()> {
        let d = self.opd(op)?;
        let current = d.opcode();
        let key = (d.pc, d.time);
        if let Some(cur) = current {
            self.remove_from_code_list(op);
            if cur == OpCode::Indirect {
                if self.alttree.get(&key) == Some(&op) {
                    self.alttree.remove(&key);
                }
                self.optree.insert(key, op);
                if let Some(d) = self.ops.get_mut(op.index()) {
                    d.tree = Tree::Main;
                }
            }
        }
        let d = self.opd_mut(op)?;
        d.flags = (d.flags & !oflags::OPCODE_BITS) | props(opcode).flags;
        d.opcode = opcode.value();
        self.add_to_code_list(op, opcode);
        Ok(())
    }

    /// `PcodeOpBank::markAlive`: from the dead list to the end of the alive
    /// list.
    pub(crate) fn bank_mark_alive(&mut self, op: OpId) -> IrResult<()> {
        let d = self.opd(op)?;
        if d.flags & oflags::DEAD == 0 {
            return Err(IrError::AlreadyInBlock {
                method: "markAlive",
                op,
            });
        }
        self.dead.remove(&mut self.links, Thread::Life, op);
        self.alive.push_back(&mut self.links, Thread::Life, op);
        self.opd_mut(op)?.flags &= !oflags::DEAD;
        Ok(())
    }

    /// `PcodeOpBank::markDead`.
    pub(crate) fn bank_mark_dead(&mut self, op: OpId) -> IrResult<()> {
        let d = self.opd(op)?;
        if d.flags & oflags::DEAD != 0 {
            return Err(IrError::WrongOp {
                method: "markDead",
                op,
                what: "alive",
            });
        }
        self.alive.remove(&mut self.links, Thread::Life, op);
        self.dead.push_back(&mut self.links, Thread::Life, op);
        self.opd_mut(op)?.flags |= oflags::DEAD;
        Ok(())
    }

    /// `PcodeOpBank::destroy`: a dead op is retired — out of its tree, the
    /// dead list and its opcode list, onto `deadandgone`. Its slot and time
    /// are never reused. Basilisk removes it from the tree it is in (Ghidra
    /// picks the tree by the current opcode; spec 10.2).
    pub(crate) fn bank_destroy_op(&mut self, op: OpId) -> IrResult<()> {
        let d = self.opd(op)?;
        if d.flags & oflags::DEAD == 0 {
            return Err(IrError::IntegratedOp(op));
        }
        let key = (d.pc, d.time);
        match d.tree {
            Tree::Alt => {
                self.alttree.remove(&key);
            }
            Tree::Main => {
                self.optree.remove(&key);
            }
            Tree::Retired => {}
        }
        self.dead.remove(&mut self.links, Thread::Life, op);
        self.remove_from_code_list(op);
        self.gone.push(op);
        if let Some(d) = self.ops.get_mut(op.index()) {
            d.tree = Tree::Retired;
        }
        Ok(())
    }

    /// `PcodeOpBank::destroyDead`: retires every op of the dead list.
    pub fn destroy_dead_ops(&mut self) -> IrResult<()> {
        for op in self.dead.collect(&self.links, Thread::Life) {
            self.bank_destroy_op(op)?;
        }
        Ok(())
    }

    /// `PcodeOpBank::insertAfterDead`: moves `op` right after `prev` in the
    /// dead list.
    pub fn insert_after_dead(&mut self, op: OpId, prev: OpId) -> IrResult<()> {
        let dead = |d: &OpData| d.flags & oflags::DEAD != 0;
        if !dead(self.opd(op)?) || !dead(self.opd(prev)?) || op == prev {
            return Err(IrError::DeadMove(op));
        }
        self.dead.remove(&mut self.links, Thread::Life, op);
        let next = self
            .links
            .get(prev.index())
            .and_then(|l| l.next(Thread::Life));
        self.dead
            .insert_before(&mut self.links, Thread::Life, op, next);
        Ok(())
    }

    /// `PcodeOpBank::moveSequenceDead`: splices the run `first..=last` of
    /// the dead list to after `prev`.
    pub fn move_sequence_dead(&mut self, first: OpId, last: OpId, prev: OpId) -> IrResult<()> {
        let run = self.dead_run(first, last)?;
        if run.contains(&prev) || self.opd(prev)?.flags & oflags::DEAD == 0 {
            return Err(IrError::DeadMove(prev));
        }
        let after_prev = self
            .links
            .get(prev.index())
            .and_then(|l| l.next(Thread::Life));
        if after_prev == Some(first) {
            return Ok(());
        }
        for &op in &run {
            self.dead.remove(&mut self.links, Thread::Life, op);
        }
        for &op in &run {
            self.dead
                .insert_before(&mut self.links, Thread::Life, op, after_prev);
        }
        Ok(())
    }

    /// The run of the dead list from `first` to `last`, both dead.
    fn dead_run(&self, first: OpId, last: OpId) -> IrResult<Vec<OpId>> {
        for op in [first, last] {
            if self.opd(op)?.flags & oflags::DEAD == 0 {
                return Err(IrError::DeadMove(op));
            }
        }
        let mut run = Vec::new();
        let mut cur = Some(first);
        while let Some(op) = cur {
            run.push(op);
            if op == last {
                return Ok(run);
            }
            if run.len() > self.dead.len() {
                break;
            }
            cur = self
                .links
                .get(op.index())
                .and_then(|l| l.next(Thread::Life));
        }
        Err(IrError::DeadMove(last))
    }

    /// `PcodeOpBank::markIncidentalCopy`: marks the `COPY`s of the run
    /// `first..=last` of the dead list incidental.
    pub fn mark_incidental_copy(&mut self, first: OpId, last: OpId) -> IrResult<()> {
        for op in self.dead_run(first, last)? {
            if let Some(d) = self.ops.get_mut(op.index())
                && d.opcode() == Some(OpCode::Copy)
            {
                d.addl |= oaddl::INCIDENTAL_COPY;
            }
        }
        Ok(())
    }

    // ----- queries -----

    /// The ops of `optree` in sequence order (`beginMain`..`endMain`).
    pub fn ops_main(&self) -> impl Iterator<Item = OpId> + '_ {
        self.optree.values().copied()
    }

    /// The ops of `alttree` (`beginIndirect`..`endIndirect`).
    pub fn ops_alt(&self) -> impl Iterator<Item = OpId> + '_ {
        self.alttree.values().copied()
    }

    /// The `optree` ops at one address (`beginMain(addr)`..`endMain(addr)`).
    pub fn ops_main_at(&self, addr: Address) -> impl Iterator<Item = OpId> + '_ {
        self.optree
            .range((addr, 0)..=(addr, u32::MAX))
            .map(|(_, &o)| o)
    }

    /// The `alttree` ops at one address.
    pub fn ops_alt_at(&self, addr: Address) -> impl Iterator<Item = OpId> + '_ {
        self.alttree
            .range((addr, 0)..=(addr, u32::MAX))
            .map(|(_, &o)| o)
    }

    /// The alive list in order.
    pub fn ops_alive(&self) -> Vec<OpId> {
        self.alive.collect(&self.links, Thread::Life)
    }

    /// The dead list in order.
    pub fn ops_dead(&self) -> Vec<OpId> {
        self.dead.collect(&self.links, Thread::Life)
    }

    /// An opcode list in order (`begin(opc)`..`end(opc)`).
    pub fn ops_of(&self, list: CodeList) -> Vec<OpId> {
        self.code
            .get(list.slot())
            .map_or_else(Vec::new, |h| h.collect(&self.links, Thread::Code))
    }

    /// The retired ops (`deadandgone`) in order.
    pub fn ops_retired(&self) -> &[OpId] {
        &self.gone
    }

    /// `PcodeOpBank::findOp`: the `optree` op with this sequence number.
    pub fn find_op(&self, pc: Address, time: u32) -> Option<OpId> {
        self.optree.get(&(pc, time)).copied()
    }

    /// `PcodeOpBank::findLastOp`: the `optree` op at `addr` with the
    /// largest time.
    pub fn find_last_op(&self, addr: Address) -> Option<OpId> {
        let (&(pc, _), &op) = self
            .optree
            .range((Bound::Unbounded, Bound::Included((addr, u32::MAX))))
            .next_back()?;
        (pc == addr).then_some(op)
    }

    /// `PcodeOp::target`: the first op of the instruction holding `op`,
    /// walking back over the dead list or the block's list.
    pub fn op_target(&self, op: OpId) -> IrResult<OpId> {
        let d = self.opd(op)?;
        let thread = if d.flags & oflags::DEAD != 0 {
            Thread::Life
        } else {
            Thread::Block
        };
        let mut cur = op;
        for _ in 0..=self.ops.len() {
            let cd = self.opd_any(cur)?;
            if cd.flags & oflags::STARTMARK != 0 {
                return Ok(cur);
            }
            match self.links.get(cur.index()).and_then(|l| l.prev(thread)) {
                Some(p) => cur = p,
                None => break,
            }
        }
        Err(IrError::WrongOp {
            method: "target",
            op,
            what: "preceded by an instruction start",
        })
    }

    /// `PcodeOpBank::target`: the first executing op for `addr`, before
    /// basic blocks exist.
    pub fn target_op(&self, addr: Address) -> IrResult<Option<OpId>> {
        match self.optree.range((addr, 0)..).next() {
            None => Ok(None),
            Some((_, &op)) => self.op_target(op).map(Some),
        }
    }

    /// `PcodeOpBank::fallthru`: the op `op` falls through to.
    pub fn op_fallthru(&self, op: OpId) -> IrResult<Option<OpId>> {
        let d = self.opd(op)?;
        if d.flags & oflags::DEAD == 0 {
            return self.next_op(op);
        }
        if let Some(n) = self
            .links
            .get(op.index())
            .and_then(|l| l.next(Thread::Life))
            && self.opd_any(n)?.flags & oflags::STARTMARK == 0
        {
            return Ok(Some(n));
        }
        let mut max = (d.pc, d.time);
        let start = self.op_target(op)?;
        let mut cur = Some(start);
        let mut steps = 0;
        while let Some(c) = cur {
            if c == op || steps > self.ops.len() {
                break;
            }
            let cd = self.opd_any(c)?;
            if (cd.pc, cd.time) > max {
                max = (cd.pc, cd.time);
            }
            steps += 1;
            cur = self.links.get(c.index()).and_then(|l| l.next(Thread::Life));
        }
        Ok(self
            .optree
            .range((Bound::Excluded(max), Bound::Unbounded))
            .next()
            .map(|(_, &o)| o))
    }
}
