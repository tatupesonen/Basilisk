//! The varnode half of the mutation interface (`funcdata_varnode.cc:25–310`,
//! 354–394, 860–883, 1544–1609).

use bk_core::{Address, SpaceId};
use bk_decomp_types::TypeId;

use super::env::{Effect, FunctionEnv, PropertiesAnswer};
use crate::error::{IrError, IrResult};
use crate::flags::{vaddl, vflags};
use crate::ids::{CallSpecId, NONE, OpId, VarnodeId};
use crate::ssa::Ssa;

/// The varnode flags `cloneVarnode` copies (`funcdata_varnode.cc:274`).
pub const CLONE_FLAGS: u32 = vflags::ANNOTATION
    | vflags::EXTERNREF
    | vflags::READONLY
    | vflags::PERSIST
    | vflags::ADDRTIED
    | vflags::ADDRFORCE
    | vflags::INDIRECT_CREATION
    | vflags::INCIDENTAL_COPY
    | vflags::VOLATILE
    | vflags::MAPPED;

impl Ssa {
    fn valid_range(&self, addr: Address, size: i32) -> bool {
        addr.is_valid_range(&self.spaces, size as u64)
    }

    /// Applies a properties answer: `Varnode::setSymbolProperties` for an
    /// entry, else `setFlags(vflags & ~typelock)`.
    fn apply_properties(&mut self, vn: VarnodeId, answer: PropertiesAnswer) -> IrResult<()> {
        match answer {
            PropertiesAnswer::Flags(f) => {
                self.vnd_mut(vn)?.flags |= f & !vflags::TYPELOCK;
            }
            PropertiesAnswer::Entry {
                entry,
                locked_type,
                symbol_type_locked,
                flags,
            } => {
                if let Some(lt) = locked_type {
                    self.update_type_locked(vn, lt.ty, !lt.unknown, true)?;
                }
                if symbol_type_locked {
                    let idx = self.intern_entry(entry);
                    self.vnd_mut(vn)?.entry = idx;
                }
                self.vnd_mut(vn)?.flags |= flags & !vflags::TYPELOCK;
            }
        }
        Ok(())
    }

    /// `newConstant`: a constant of the default type.
    pub fn new_constant(
        &mut self,
        env: &mut dyn FunctionEnv,
        size: i32,
        val: u64,
    ) -> IrResult<VarnodeId> {
        let ct = env.default_type(size);
        let vn = self.bank_create(size, Address::constant(val), Some(ct))?;
        env.assign_high(self, vn);
        Ok(vn)
    }

    /// `newUnique`: a temporary in the `unique` space.
    pub fn new_unique(
        &mut self,
        env: &mut dyn FunctionEnv,
        size: i32,
        ty: Option<TypeId>,
    ) -> IrResult<VarnodeId> {
        let ct = ty.unwrap_or_else(|| env.default_type(size));
        let vn = self.bank_create_unique(size, Some(ct))?;
        env.assign_high(self, vn);
        env.laned_register(size, self.varnode_addr(vn));
        Ok(vn)
    }

    /// `newVarnodeOut`: a varnode written by `op` (the op's output is set
    /// directly, as Ghidra does), with symbol properties for the op's
    /// address.
    pub fn new_varnode_out(
        &mut self,
        env: &mut dyn FunctionEnv,
        size: i32,
        addr: Address,
        op: OpId,
    ) -> IrResult<VarnodeId> {
        let pc = self.opd(op)?.pc;
        let ct = env.default_type(size);
        let place = if self.valid_range(addr, size) {
            addr
        } else {
            env.wrapping_address(addr, size)
        };
        let vn = self.bank_create_def(size, place, Some(ct), op)?;
        self.opd_mut(op)?.output = vn.0;
        env.assign_high(self, vn);
        env.laned_register(size, addr);
        let answer = env.symbol_properties(addr, size, Some(pc));
        self.apply_properties(vn, answer)?;
        Ok(vn)
    }

    /// `newUniqueOut`: a temporary written by `op`.
    pub fn new_unique_out(
        &mut self,
        env: &mut dyn FunctionEnv,
        size: i32,
        op: OpId,
    ) -> IrResult<VarnodeId> {
        let ct = env.default_type(size);
        let vn = self.bank_create_def_unique(size, Some(ct), op)?;
        self.opd_mut(op)?.output = vn.0;
        env.assign_high(self, vn);
        env.laned_register(size, self.varnode_addr(vn));
        Ok(vn)
    }

    /// `newVarnode`: a free varnode, with symbol properties for no use
    /// point.
    pub fn new_varnode(
        &mut self,
        env: &mut dyn FunctionEnv,
        size: i32,
        addr: Address,
        ty: Option<TypeId>,
    ) -> IrResult<VarnodeId> {
        let ct = ty.unwrap_or_else(|| env.default_type(size));
        let place = if self.valid_range(addr, size) {
            addr
        } else {
            env.wrapping_address(addr, size)
        };
        let vn = self.bank_create(size, place, Some(ct))?;
        env.assign_high(self, vn);
        env.laned_register(size, addr);
        let answer = env.symbol_properties(self.varnode_addr(vn), size, None);
        self.apply_properties(vn, answer)?;
        Ok(vn)
    }

    /// `newVarnodeIop`: an annotation naming `op` (size 8 on every host).
    pub fn new_varnode_iop(&mut self, env: &mut dyn FunctionEnv, op: OpId) -> IrResult<VarnodeId> {
        self.opd_any(op)?;
        let space = self
            .spaces
            .iop_space()
            .ok_or(IrError::MissingSpace("iop"))?
            .id();
        let ct = env.default_type(8);
        let vn = self.bank_create(8, Address::new(space, u64::from(op.0)), Some(ct))?;
        env.assign_high(self, vn);
        Ok(vn)
    }

    /// `newVarnodeSpace`: the constant naming a space (size 8; its offset
    /// and `nzm` are the space index).
    pub fn new_varnode_space(
        &mut self,
        env: &mut dyn FunctionEnv,
        space: SpaceId,
    ) -> IrResult<VarnodeId> {
        let ct = env.default_type(8);
        let vn = self.alloc_varnode(8, Address::const_from_space(space), Some(ct))?;
        if let Some(s) = self.vstate.get_mut(vn.index()) {
            s.space_const = true;
        }
        self.bank_insert_plain(vn);
        env.assign_high(self, vn);
        Ok(vn)
    }

    /// `newVarnodeCallSpecs`: an annotation naming a call spec.
    pub fn new_varnode_callspecs(
        &mut self,
        env: &mut dyn FunctionEnv,
        call: CallSpecId,
    ) -> IrResult<VarnodeId> {
        let space = self
            .spaces
            .fspec_space()
            .ok_or(IrError::MissingSpace("fspec"))?
            .id();
        let ct = env.default_type(8);
        let vn = self.bank_create(8, Address::new(space, u64::from(call.0)), Some(ct))?;
        env.assign_high(self, vn);
        Ok(vn)
    }

    /// `newCodeRef`: a one-byte annotation holding a code address.
    pub fn new_coderef(&mut self, env: &mut dyn FunctionEnv, addr: Address) -> IrResult<VarnodeId> {
        let ct = env.code_type();
        let vn = self.bank_create(1, addr, Some(ct))?;
        self.vnd_mut(vn)?.flags |= vflags::ANNOTATION;
        env.assign_high(self, vn);
        Ok(vn)
    }

    /// `cloneVarnode`: a free varnode with the same storage and type and
    /// only the flags of [`CLONE_FLAGS`].
    pub fn clone_varnode(&mut self, vn: VarnodeId) -> IrResult<VarnodeId> {
        let d = self.vnd(vn)?;
        let (size, addr, ty, flags) = (d.size, d.loc, d.ty, d.flags);
        let space_const = self.vstate(vn).space_const;
        let ty = (ty != NONE).then(|| TypeId::from_raw(ty));
        let new = self.alloc_varnode(size, addr, ty)?;
        if let Some(s) = self.vstate.get_mut(new.index()) {
            s.space_const = space_const;
        }
        self.bank_insert_plain(new);
        self.vnd_mut(new)?.flags |= flags & CLONE_FLAGS;
        Ok(new)
    }

    /// `destroyVarnode`: clears every reader's slot (the readers' own lists
    /// are untouched; each reader is reported to the recorder), detaches
    /// the definition, and deletes the varnode.
    pub fn destroy_varnode(&mut self, vn: VarnodeId) -> IrResult<()> {
        self.vnd(vn)?;
        for op in self.readers_vec(vn) {
            self.note_change(op);
            let pool = &mut self.pool;
            if let Some(o) = self.ops.get_mut(op.index())
                && let Some(slot) = o.inputs.position(pool, vn.0)
            {
                o.inputs.set(pool, slot, NONE);
            }
        }
        // Out of the orders while the key still names the def (Ghidra
        // erases through the stored iterators, `VarnodeBank::destroy`).
        self.bank_remove(vn);
        if let Some(def) = self.varnode_def(vn)
            && let Some(o) = self.ops.get_mut(def.index())
        {
            o.output = NONE;
        }
        let pool = &mut self.pool;
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.def = NONE;
            d.readers.clear(pool);
        }
        self.bank_destroy(vn)
    }

    /// `setVarnodeProperties`: symbol properties at the use point unless
    /// already mapped; a cover when high variables are on.
    pub fn set_varnode_properties(
        &mut self,
        env: &mut dyn FunctionEnv,
        vn: VarnodeId,
    ) -> IrResult<()> {
        let before_entry = self.before_entry();
        if !self.is_mapped(vn) {
            let use_point = self.use_point(vn, before_entry);
            let answer = env.symbol_properties(
                self.varnode_addr(vn),
                self.varnode_size(vn),
                (!use_point.is_invalid()).then_some(use_point),
            );
            self.apply_properties(vn, answer)?;
        }
        if self.vnd(vn)?.cover.is_none() && env.cover_on() {
            self.calc_cover(vn)?;
        }
        Ok(())
    }

    /// `setInputVarnode`: makes `vn` an input. An existing input with the
    /// same storage is returned instead; one that overlaps differently is
    /// Ghidra's error.
    pub fn set_input_varnode(
        &mut self,
        env: &mut dyn FunctionEnv,
        vn: VarnodeId,
    ) -> IrResult<VarnodeId> {
        if self.is_input(vn) {
            return Ok(vn);
        }
        let (addr, size) = (self.varnode_addr(vn), self.varnode_size(vn));
        let after = addr.add(&self.spaces, i64::from(size));
        let lo = crate::bank::keys::DefKey {
            class: crate::bank::keys::INPUT_CLASS,
            seq: crate::bank::keys::SEQ_MIN,
            addr: after,
            size: 0,
            create: 0,
        };
        let prev = self.def.range(..lo).next_back().map(|(_, &v)| v);
        if let Some(invn) = prev
            && self.is_input(invn)
            && (self.overlap(vn, invn) != -1 || self.overlap(invn, vn) != -1)
        {
            if self.varnode_size(invn) == size && self.varnode_addr(invn) == addr {
                return Ok(invn);
            }
            return Err(IrError::OverlappingInputs(vn));
        }
        let vn = self.bank_set_input(vn)?;
        self.set_varnode_properties(env, vn)?;
        match env.input_effect(addr, size) {
            Effect::Unaffected => self.vnd_mut(vn)?.flags |= vflags::UNAFFECTED,
            Effect::ReturnAddress => {
                self.vnd_mut(vn)?.flags |= vflags::UNAFFECTED | vflags::RETURN_ADDRESS;
            }
            Effect::KilledByCall | Effect::Unknown => {}
        }
        Ok(vn)
    }

    /// `totalReplace`: every read of `vn` reads `new` instead.
    pub fn total_replace(
        &mut self,
        env: &mut dyn FunctionEnv,
        vn: VarnodeId,
        new: VarnodeId,
    ) -> IrResult<()> {
        self.vnd(new)?;
        for op in self.readers_vec(vn) {
            let slot = self.op_slot(op, vn);
            self.op_set_input(env, op, new, slot)?;
        }
        Ok(())
    }

    /// `totalReplaceConstant`: every read of `vn` reads a new constant;
    /// markers share one `COPY` of the constant, placed after `vn`'s
    /// definition or at the start of the first block.
    pub fn total_replace_constant(
        &mut self,
        env: &mut dyn FunctionEnv,
        vn: VarnodeId,
        val: u64,
    ) -> IrResult<()> {
        let size = self.varnode_size(vn);
        let mut copy_out: Option<VarnodeId> = None;
        for op in self.readers_vec(vn) {
            let slot = self.op_slot(op, vn);
            let rep = if self.op_is_marker(op) {
                if let Some(r) = copy_out {
                    r
                } else {
                    let r = if let Some(def) = self.varnode_def(vn) {
                        let copy = self.new_op(1, self.op_addr(def))?;
                        self.op_set_opcode(copy, bk_pcode::OpCode::Copy)?;
                        let r = self.new_unique_out(env, size, copy)?;
                        let c = self.new_constant(env, size, val)?;
                        self.op_set_input(env, copy, c, 0)?;
                        self.op_insert_after(copy, def)?;
                        r
                    } else {
                        let bb = *self
                            .cfg
                            .nodes()
                            .first()
                            .ok_or(IrError::NoBlocks("totalReplaceConstant"))?;
                        let copy = self.new_op(1, self.block_start(bb))?;
                        self.op_set_opcode(copy, bk_pcode::OpCode::Copy)?;
                        let r = self.new_unique_out(env, size, copy)?;
                        let c = self.new_constant(env, size, val)?;
                        self.op_set_input(env, copy, c, 0)?;
                        self.op_insert_begin(copy, bb)?;
                        r
                    };
                    copy_out = Some(r);
                    r
                }
            } else {
                self.new_constant(env, size, val)?
            };
            self.op_set_input(env, op, rep, slot)?;
        }
        Ok(())
    }

    /// `clearDeadVarnodes`: in loc order, an unread input that is not a
    /// locked input becomes free, and an unread free varnode is deleted.
    pub fn clear_dead_varnodes(&mut self) -> IrResult<()> {
        let mut cur = self.loc_cursor();
        while let Some(vn) = cur.next(self) {
            if !self.has_no_descend(vn) {
                continue;
            }
            if self.is_input(vn) && self.varnode_addl(vn) & vaddl::LOCKED_INPUT == 0 {
                self.bank_make_free(vn)?;
                self.clear_cover(vn)?;
            }
            if self.is_free(vn) {
                self.bank_destroy(vn)?;
            }
        }
        Ok(())
    }
}
