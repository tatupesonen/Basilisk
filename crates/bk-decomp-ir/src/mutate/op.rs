//! The op half of the mutation interface (`funcdata_op.cc:25–350`,
//! 625–758). Each method that Ghidra instruments with `debugModCheck` tells
//! the recorder before it changes the op. Checks come first; a method that
//! returns an error has changed nothing (except where noted).

use bk_core::Address;
use bk_decomp_cfg::NodeId;
use bk_pcode::OpCode;

use super::env::FunctionEnv;
use crate::error::{IrError, IrResult};
use crate::flags::{oflags, vflags};
use crate::ids::{NONE, OpId, VarnodeId};
use crate::ssa::Ssa;

impl Ssa {
    fn check_slot(&self, method: &'static str, op: OpId, slot: usize) -> IrResult<()> {
        if slot >= self.opd(op)?.inputs.len() {
            return Err(IrError::NoSuchSlot { method, op, slot });
        }
        Ok(())
    }

    /// `newOp(inputs, pc)`: a dead op with the next time and no opcode.
    pub fn new_op(&mut self, inputs: usize, pc: Address) -> IrResult<OpId> {
        self.bank_create_op(inputs, pc)
    }

    /// `newOp(inputs, seq)`: a dead op with the given sequence number.
    pub fn new_op_at(&mut self, inputs: usize, pc: Address, time: u32) -> IrResult<OpId> {
        self.bank_create_op_at(inputs, pc, time)
    }

    /// `newIndirect`: an `INDIRECT` in `alttree` at `target`'s address, its
    /// input 1 naming `target`.
    pub fn new_indirect(&mut self, env: &mut dyn FunctionEnv, target: OpId) -> IrResult<OpId> {
        let pc = self.opd(target)?.pc;
        self.spaces
            .iop_space()
            .ok_or(IrError::MissingSpace("iop"))?;
        let op = self.bank_create_indirect(pc)?;
        self.bank_change_opcode(op, OpCode::Indirect)?;
        let iop = self.new_varnode_iop(env, target)?;
        self.op_set_input(env, op, iop, 1)?;
        Ok(op)
    }

    /// `opSetOpcode` (`PcodeOpBank::changeOpcode`).
    pub fn op_set_opcode(&mut self, op: OpId, opcode: OpCode) -> IrResult<()> {
        self.opd(op)?;
        self.note_change(op);
        self.bank_change_opcode(op, opcode)
    }

    /// `opMarkHalt`: sets halt bits on a `RETURN`.
    pub fn op_mark_halt(&mut self, op: OpId, flag: u32) -> IrResult<()> {
        if self.opd(op)?.opcode() != Some(OpCode::Return) {
            return Err(IrError::HaltNotReturn(op));
        }
        let flag = flag & oflags::HALT_BITS;
        if flag == 0 {
            return Err(IrError::BadHaltFlag(op));
        }
        self.opd_mut(op)?.flags |= flag;
        Ok(())
    }

    /// `opUnsetOutput`: the output becomes free (not deleted).
    pub fn op_unset_output(&mut self, op: OpId) -> IrResult<()> {
        let Some(vn) = self.opd(op)?.output() else {
            return Ok(());
        };
        self.note_change(op);
        self.opd_mut(op)?.output = NONE;
        self.bank_make_free(vn)?;
        self.clear_cover(vn)
    }

    /// `opSetOutput`: `vn` (free, or another op's output, which is unset
    /// first) becomes `op`'s output; `xref` may substitute an equal
    /// varnode, which is returned.
    pub fn op_set_output(
        &mut self,
        env: &mut dyn FunctionEnv,
        op: OpId,
        vn: VarnodeId,
    ) -> IrResult<VarnodeId> {
        let d = self.opd(op)?;
        if d.output == vn.0 {
            return Ok(vn);
        }
        let pc = d.pc;
        let f = self.vnd(vn)?.flags;
        if f & vflags::INPUT != 0 {
            return Err(IrError::DefineNotFree {
                vn,
                at: self.shortcut_addr(pc),
            });
        }
        if f & vflags::CONSTANT != 0 {
            return Err(IrError::AssignToConstant {
                vn,
                at: self.shortcut_addr(pc),
            });
        }
        self.note_change(op);
        if self.opd(op)?.output().is_some() {
            self.op_unset_output(op)?;
        }
        if let Some(def) = self.varnode_def(vn) {
            self.op_unset_output(def)?;
        }
        let vn = self.bank_set_def(vn, op)?;
        self.set_varnode_properties(env, vn)?;
        self.opd_mut(op)?.output = vn.0;
        Ok(vn)
    }

    /// `opUnsetInput`: `eraseDescend`, then clear the slot.
    pub fn op_unset_input(&mut self, op: OpId, slot: usize) -> IrResult<()> {
        self.check_slot("opUnsetInput", op, slot)?;
        let vn = self.op_input(op, slot).ok_or(IrError::EmptySlot {
            method: "opUnsetInput",
            op,
            slot,
        })?;
        self.erase_descend(vn, op)?;
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.set(pool, slot, NONE);
        }
        Ok(())
    }

    /// `opSetInput`: `vn` goes into `slot`. A constant that already has a
    /// reader (and is not a space base) is replaced by a new constant with
    /// its symbol copied. The reader is added before the slot is written.
    pub fn op_set_input(
        &mut self,
        env: &mut dyn FunctionEnv,
        op: OpId,
        vn: VarnodeId,
        slot: usize,
    ) -> IrResult<()> {
        self.check_slot("opSetInput", op, slot)?;
        if self.op_input(op, slot) == Some(vn) {
            return Ok(());
        }
        let d = self.vnd(vn)?;
        let mut vn = vn;
        if d.flags & vflags::CONSTANT != 0 {
            if !d.readers.is_empty() && d.flags & vflags::SPACEBASE == 0 {
                let (size, off) = (d.size, d.loc.offset());
                let space_const = self.vstate(vn).space_const;
                let cvn = self.new_constant(env, size, off)?;
                if let Some(s) = self.vstate.get_mut(cvn.index()) {
                    s.space_const = space_const;
                }
                self.copy_symbol(cvn, vn)?;
                vn = cvn;
            }
        } else {
            let free = d.flags & (vflags::INPUT | vflags::WRITTEN) == 0;
            if free && d.flags & vflags::SPACEBASE == 0 && !d.readers.is_empty() {
                return Err(IrError::FreeMultipleDescendants(vn));
            }
        }
        self.note_change(op);
        if self.op_input(op, slot).is_some() {
            self.op_unset_input(op, slot)?;
        }
        self.add_descend(vn, op)?;
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.set(pool, slot, vn.0);
        }
        Ok(())
    }

    /// `opSwapInput`: exchanges two slots (reader lists are untouched).
    pub fn op_swap_input(&mut self, op: OpId, slot1: usize, slot2: usize) -> IrResult<()> {
        self.check_slot("opSwapInput", op, slot1)?;
        self.check_slot("opSwapInput", op, slot2)?;
        self.note_change(op);
        let a = self.opd(op)?.inputs.get(&self.pool, slot1).unwrap_or(NONE);
        let b = self.opd(op)?.inputs.get(&self.pool, slot2).unwrap_or(NONE);
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.set(pool, slot1, b);
            o.inputs.set(pool, slot2, a);
        }
        Ok(())
    }

    /// `opInsert`: marks `op` alive and puts it in `block` before `before`
    /// (`None`: at the end).
    pub fn op_insert(&mut self, op: OpId, block: NodeId, before: Option<OpId>) -> IrResult<()> {
        let d = self.opd(op)?;
        if d.parent != NONE || d.flags & oflags::DEAD == 0 {
            return Err(IrError::AlreadyInBlock {
                method: "opInsert",
                op,
            });
        }
        self.bdata(block)?;
        if let Some(b) = before
            && self.opd(b)?.parent != block.get()
        {
            return Err(IrError::NotInBlock {
                method: "opInsert",
                op: b,
            });
        }
        self.note_change(op);
        self.bank_mark_alive(op)?;
        self.block_insert(block, before, op)
    }

    /// `opUninsert`: marks `op` dead and takes it out of its block.
    pub fn op_uninsert(&mut self, op: OpId) -> IrResult<()> {
        let d = self.opd(op)?;
        if d.parent == NONE || d.flags & oflags::DEAD != 0 {
            return Err(IrError::NotInBlock {
                method: "opUninsert",
                op,
            });
        }
        self.note_change(op);
        self.bank_mark_dead(op)?;
        self.block_remove_op(op)
    }

    /// `opUnlink`: unsets the output and every input and uninserts the op
    /// if it is in a block (it stays in the dead list).
    pub fn op_unlink(&mut self, op: OpId) -> IrResult<()> {
        self.opd(op)?;
        self.note_change(op);
        self.op_unset_output(op)?;
        for slot in 0..self.op_num_inputs(op) {
            if self.op_input(op, slot).is_some() {
                self.op_unset_input(op, slot)?;
            }
        }
        if self.opd(op)?.parent != NONE {
            self.op_uninsert(op)?;
        }
        Ok(())
    }

    /// `opDestroy`: deletes the output varnode, unsets every input, and if
    /// the op is in a block marks it dead and removes it (not retired).
    pub fn op_destroy(&mut self, op: OpId) -> IrResult<()> {
        self.opd(op)?;
        self.note_change(op);
        if let Some(out) = self.op_output(op) {
            self.destroy_varnode(out)?;
        }
        for slot in 0..self.op_num_inputs(op) {
            if self.op_input(op, slot).is_some() {
                self.op_unset_input(op, slot)?;
            }
        }
        if self.opd(op)?.parent != NONE {
            self.bank_mark_dead(op)?;
            self.block_remove_op(op)?;
        }
        Ok(())
    }

    /// `opDestroyRecursive`: destroys `op` and, breadth first, the
    /// definitions of its inputs that are written, not auto-live, read only
    /// by it, and neither a call nor an indirect source.
    pub fn op_destroy_recursive(&mut self, op: OpId) -> IrResult<()> {
        self.opd(op)?;
        let mut scratch = vec![op];
        let mut pos = 0;
        while let Some(&cur) = scratch.get(pos) {
            pos += 1;
            for vn in self.op_inputs(cur).flatten() {
                if !self.is_written(vn) || self.is_auto_live(vn) {
                    continue;
                }
                if self.lone_descend(vn).is_none() {
                    continue;
                }
                let Some(def) = self.varnode_def(vn) else {
                    continue;
                };
                if self.op_is_call(def) || self.op_is_indirect_source(def) {
                    continue;
                }
                scratch.push(def);
            }
            self.op_destroy(cur)?;
        }
        Ok(())
    }

    /// `opDestroyRaw`: deletes every input and the output varnode, then
    /// retires the op (`PcodeOpBank::destroy`).
    pub fn op_destroy_raw(&mut self, op: OpId) -> IrResult<()> {
        if self.opd(op)?.flags & oflags::DEAD == 0 {
            return Err(IrError::IntegratedOp(op));
        }
        for vn in self.op_inputs_vec(op).into_iter().flatten() {
            if self.varnode_exists(vn) {
                self.destroy_varnode(vn)?;
            }
        }
        if let Some(out) = self.op_output(op) {
            self.destroy_varnode(out)?;
        }
        self.bank_destroy_op(op)
    }

    /// `opSetAllInput`: unsets every input, resizes, sets each of `vns`.
    pub fn op_set_all_input(
        &mut self,
        env: &mut dyn FunctionEnv,
        op: OpId,
        vns: &[VarnodeId],
    ) -> IrResult<()> {
        self.opd(op)?;
        for &v in vns {
            self.vnd(v)?;
        }
        self.note_change(op);
        for slot in 0..self.op_num_inputs(op) {
            if self.op_input(op, slot).is_some() {
                self.op_unset_input(op, slot)?;
            }
        }
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.reset(pool, vns.len(), NONE);
        }
        for (slot, &v) in vns.iter().enumerate() {
            self.op_set_input(env, op, v, slot)?;
        }
        Ok(())
    }

    /// `opRemoveInput`: unsets the slot and removes it; later slots move
    /// down.
    pub fn op_remove_input(&mut self, op: OpId, slot: usize) -> IrResult<()> {
        self.check_slot("opRemoveInput", op, slot)?;
        self.note_change(op);
        if self.op_input(op, slot).is_some() {
            self.op_unset_input(op, slot)?;
        }
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.remove(pool, slot);
        }
        Ok(())
    }

    /// `opInsertInput`: opens a slot at `slot` and sets `vn` there.
    pub fn op_insert_input(
        &mut self,
        env: &mut dyn FunctionEnv,
        op: OpId,
        vn: VarnodeId,
        slot: usize,
    ) -> IrResult<()> {
        if slot > self.opd(op)?.inputs.len() {
            return Err(IrError::NoSuchSlot {
                method: "opInsertInput",
                op,
                slot,
            });
        }
        self.vnd(vn)?;
        self.note_change(op);
        let pool = &mut self.pool;
        if let Some(o) = self.ops.get_mut(op.index()) {
            o.inputs.insert(pool, slot, NONE);
        }
        self.op_set_input(env, op, vn, slot)
    }

    /// `cloneOp`: a new op at the given sequence number with `op`'s opcode,
    /// `startmark | startbasic`, and clones of its output and inputs.
    pub fn clone_op(
        &mut self,
        env: &mut dyn FunctionEnv,
        op: OpId,
        pc: Address,
        time: u32,
    ) -> IrResult<OpId> {
        let d = self.opd(op)?;
        let opc = d.opcode().ok_or(IrError::NoOpcode {
            method: "cloneOp",
            op,
        })?;
        let fl = d.flags & (oflags::STARTMARK | oflags::STARTBASIC);
        let n = d.inputs.len();
        let out = d.output();
        if let Some(slot) = self.op_inputs(op).position(|v| v.is_none()) {
            return Err(IrError::EmptySlot {
                method: "cloneOp",
                op,
                slot,
            });
        }
        let ins: Vec<_> = self.op_inputs(op).collect();
        let new = self.new_op_at(n, pc, time)?;
        self.op_set_opcode(new, opc)?;
        self.opd_mut(new)?.flags |= fl;
        if let Some(out) = out {
            let c = self.clone_varnode(out)?;
            self.op_set_output(env, new, c)?;
        }
        for (slot, vn) in ins.into_iter().enumerate() {
            if let Some(vn) = vn {
                let c = self.clone_varnode(vn)?;
                self.op_set_input(env, new, c, slot)?;
            }
        }
        Ok(new)
    }

    /// `newOpBefore`: a new op with a `unique` output of `in1`'s size and
    /// two or three inputs, inserted before `follow`.
    pub fn new_op_before(
        &mut self,
        env: &mut dyn FunctionEnv,
        follow: OpId,
        opcode: OpCode,
        inputs: (VarnodeId, VarnodeId, Option<VarnodeId>),
    ) -> IrResult<OpId> {
        let (in1, in2, in3) = inputs;
        let pc = self.opd(follow)?.pc;
        if self.opd(follow)?.parent == NONE {
            return Err(IrError::NotInBlock {
                method: "newOpBefore",
                op: follow,
            });
        }
        self.vnd(in1)?;
        self.vnd(in2)?;
        let n = if in3.is_some() { 3 } else { 2 };
        let op = self.new_op(n, pc)?;
        self.op_set_opcode(op, opcode)?;
        self.new_unique_out(env, self.varnode_size(in1), op)?;
        self.op_set_input(env, op, in1, 0)?;
        self.op_set_input(env, op, in2, 1)?;
        if let Some(in3) = in3 {
            self.op_set_input(env, op, in3, 2)?;
        }
        self.op_insert_before(op, follow)?;
        Ok(op)
    }

    /// `newIndirectOp`: an `INDIRECT` protecting `size` bytes at `addr`
    /// across `effect`, with `extra_flags`, inserted before `effect`.
    pub fn new_indirect_op(
        &mut self,
        env: &mut dyn FunctionEnv,
        effect: OpId,
        addr: Address,
        size: i32,
        extra_flags: u32,
    ) -> IrResult<OpId> {
        if self.opd(effect)?.parent == NONE {
            return Err(IrError::NotInBlock {
                method: "newIndirectOp",
                op: effect,
            });
        }
        let newin = self.new_varnode(env, size, addr, None)?;
        let op = self.new_indirect(env, effect)?;
        self.opd_mut(op)?.flags |= extra_flags;
        self.new_varnode_out(env, size, addr, op)?;
        self.op_set_input(env, op, newin, 0)?;
        self.op_insert_before(op, effect)?;
        Ok(op)
    }

    /// `newIndirectCreation`: an `INDIRECT` that creates `size` bytes at
    /// `addr` across `effect`; its input is a zero constant.
    pub fn new_indirect_creation(
        &mut self,
        env: &mut dyn FunctionEnv,
        effect: OpId,
        addr: Address,
        size: i32,
        possible_out: bool,
    ) -> IrResult<OpId> {
        if self.opd(effect)?.parent == NONE {
            return Err(IrError::NotInBlock {
                method: "newIndirectCreation",
                op: effect,
            });
        }
        let newin = self.new_constant(env, size, 0)?;
        let op = self.new_indirect(env, effect)?;
        self.opd_mut(op)?.flags |= oflags::INDIRECT_CREATION;
        let newout = self.new_varnode_out(env, size, addr, op)?;
        if !possible_out {
            self.vnd_mut(newin)?.flags |= vflags::INDIRECT_CREATION;
        }
        self.vnd_mut(newout)?.flags |= vflags::INDIRECT_CREATION;
        self.op_set_input(env, op, newin, 0)?;
        self.op_insert_before(op, effect)?;
        Ok(op)
    }

    /// `markIndirectCreation`: marks the `INDIRECT`'s output as indirectly
    /// created. Ghidra sets the op flag before it finds input 0 is not a
    /// constant; Basilisk checks first.
    pub fn mark_indirect_creation(&mut self, op: OpId, possible_output: bool) -> IrResult<()> {
        let in0 = self.op_input(op, 0).ok_or(IrError::IndirectCreation(op))?;
        if !self.is_constant(in0) {
            return Err(IrError::IndirectCreation(op));
        }
        let out = self.op_output(op).ok_or(IrError::IndirectCreation(op))?;
        self.opd_mut(op)?.flags |= oflags::INDIRECT_CREATION;
        if !possible_output {
            self.vnd_mut(in0)?.flags |= vflags::INDIRECT_CREATION;
        }
        self.vnd_mut(out)?.flags |= vflags::INDIRECT_CREATION;
        Ok(())
    }

    /// The op half of `BlockBasic::negateCondition`: flips `boolean_flip`
    /// and `fallthru_true` on the block's last op (the edge swap is
    /// `Cfg::swap_out_edges`).
    pub fn op_negate_condition(&mut self, op: OpId) -> IrResult<()> {
        self.opd_mut(op)?.flags ^= oflags::BOOLEAN_FLIP | oflags::FALLTHRU_TRUE;
        Ok(())
    }
}
