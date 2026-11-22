//! The varnode bank (Ghidra `VarnodeBank`, varnode.cc:1219–1440): creating,
//! defining, freeing and destroying varnodes while keeping both orders.

pub(crate) mod keys;
pub mod range;

use bk_core::Address;
use bk_decomp_types::TypeId;

use crate::data::{VState, VarnodeData};
use crate::error::{IrError, IrResult};
use crate::flags::vflags;
use crate::ids::{NONE, OpId, VarnodeId};
use crate::pool::IdList;
use crate::ssa::Ssa;

/// The most varnodes one function may create.
pub const MAX_VARNODES: u32 = 0x7fff_ffff;

impl Ssa {
    /// A new varnode record, not yet in either order. Consumes a create
    /// index.
    pub(crate) fn alloc_varnode(
        &mut self,
        size: i32,
        addr: Address,
        ty: Option<TypeId>,
    ) -> IrResult<VarnodeId> {
        if self.create_index >= MAX_VARNODES || self.vns.len() >= MAX_VARNODES as usize {
            return Err(IrError::Limit {
                what: "varnode",
                limit: u64::from(MAX_VARNODES),
            });
        }
        // An `iop` key is the named op's time; an offset naming no op
        // would change key when that op is created later.
        if self.is_space(addr, crate::ssa::SpecialSpace::Iop)
            && usize::try_from(addr.offset()).map_or(true, |i| i >= self.ops.len())
        {
            return Err(IrError::IopNamesNoOp {
                offset: addr.offset(),
            });
        }
        let flags = self.initial_flags(addr);
        let nzm = if addr.is_constant() {
            addr.offset()
        } else {
            u64::MAX
        };
        let id = VarnodeId(self.vns.len() as u32);
        self.vns.push(VarnodeData {
            flags,
            addl: 0,
            merge_group: 0,
            size,
            create_index: self.create_index,
            loc: addr,
            def: NONE,
            high: NONE,
            ty: ty.map_or(NONE, TypeId::raw),
            entry: NONE,
            consumed: u64::MAX,
            nzm,
            readers: IdList::default(),
            cover: None,
        });
        self.vstate.push(VState::default());
        self.create_index += 1;
        Ok(id)
    }

    /// `VarnodeBank::create`: a new free varnode.
    pub(crate) fn bank_create(
        &mut self,
        size: i32,
        addr: Address,
        ty: Option<TypeId>,
    ) -> IrResult<VarnodeId> {
        let vn = self.alloc_varnode(size, addr, ty)?;
        self.bank_insert_plain(vn);
        Ok(vn)
    }

    /// The next `unique` address, advancing the counter by `size`.
    pub(crate) fn take_unique(&mut self, size: i32) -> Address {
        let addr = Address::new(self.unique_space, u64::from(self.uniqid));
        self.uniqid = self.uniqid.wrapping_add(size as u32);
        addr
    }

    /// `VarnodeBank::createUnique`.
    pub(crate) fn bank_create_unique(
        &mut self,
        size: i32,
        ty: Option<TypeId>,
    ) -> IrResult<VarnodeId> {
        let addr = self.take_unique(size);
        self.bank_create(size, addr, ty)
    }

    /// `VarnodeBank::createDef`: a new varnode written by `op` (the op's
    /// output is not set). May return an existing equal varnode (`xref`).
    pub(crate) fn bank_create_def(
        &mut self,
        size: i32,
        addr: Address,
        ty: Option<TypeId>,
        op: OpId,
    ) -> IrResult<VarnodeId> {
        self.opd(op)?;
        if addr.is_constant() {
            return Err(IrError::AssignToConstant {
                vn: VarnodeId(self.vns.len() as u32),
                at: self.shortcut_addr(self.opd(op)?.pc),
            });
        }
        let vn = self.alloc_varnode(size, addr, ty)?;
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.def = op.0;
            d.flags |= vflags::COVERDIRTY | vflags::WRITTEN;
        }
        self.xref(vn)
    }

    /// `VarnodeBank::createDefUnique`.
    pub(crate) fn bank_create_def_unique(
        &mut self,
        size: i32,
        ty: Option<TypeId>,
        op: OpId,
    ) -> IrResult<VarnodeId> {
        self.opd(op)?;
        let addr = self.take_unique(size);
        self.bank_create_def(size, addr, ty, op)
    }

    /// Checks that moving every reader of `old` to `new` (as `replace`
    /// does) cannot fail.
    pub(crate) fn check_replace(&self, old: VarnodeId, new: VarnodeId) -> IrResult<()> {
        let nd = self.vnd(new)?;
        let od = self.vnd(old)?;
        let moving = od
            .readers
            .as_slice(&self.pool)
            .iter()
            .filter(|&&op| self.ops.get(op as usize).is_none_or(|o| o.output != new.0))
            .count();
        if moving == 0 {
            return Ok(());
        }
        let free = nd.flags & (vflags::INPUT | vflags::WRITTEN) == 0;
        if free && nd.flags & vflags::SPACEBASE == 0 && (!nd.readers.is_empty() || moving > 1) {
            return Err(IrError::FreeMultipleDescendants(new));
        }
        Ok(())
    }

    /// `VarnodeBank::xref`: inserts `vn` into loc order; if an equal
    /// varnode is already there, every reader of `vn` moves to it, `vn` is
    /// deleted (its create index stays consumed) and the existing one is
    /// returned.
    pub(crate) fn xref(&mut self, vn: VarnodeId) -> IrResult<VarnodeId> {
        if let Some(other) = self.bank_twin(vn) {
            self.check_replace(vn, other)?;
            self.replace(vn, other)?;
            if let Some(s) = self.vstate.get_mut(vn.index()) {
                s.destroyed = true;
            }
            let pool = &mut self.pool;
            if let Some(d) = self.vns.get_mut(vn.index()) {
                d.readers.clear(pool);
                d.def = NONE;
                d.cover = None;
            }
            return Ok(other);
        }
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.flags |= vflags::INSERT;
        }
        self.bank_insert_plain(vn);
        Ok(vn)
    }

    /// `VarnodeBank::replace`: every reader of `old` (except an op whose
    /// output is `new`) reads `new` instead, in reader order.
    pub(crate) fn replace(&mut self, old: VarnodeId, new: VarnodeId) -> IrResult<()> {
        self.check_replace(old, new)?;
        let mut idx = 0;
        while let Some(op_raw) = self.vnd(old)?.readers.get(&self.pool, idx) {
            let op = OpId(op_raw);
            if self.opd_any(op)?.output == new.0 {
                idx += 1;
                continue;
            }
            let slot = self
                .opd_any(op)?
                .inputs
                .position(&self.pool, old.0)
                .ok_or(IrError::NotADescendant { vn: old, op })?;
            let pool = &mut self.pool;
            if let Some(d) = self.vns.get_mut(old.index()) {
                d.readers.remove(pool, idx);
            }
            if let Some(o) = self.ops.get_mut(op.index()) {
                o.inputs.set(pool, slot, NONE);
            }
            self.add_descend(new, op)?;
            let pool = &mut self.pool;
            if let Some(o) = self.ops.get_mut(op.index()) {
                o.inputs.set(pool, slot, new.0);
            }
        }
        self.vnd_mut(old)?.flags |= vflags::COVERDIRTY;
        self.vnd_mut(new)?.flags |= vflags::COVERDIRTY;
        Ok(())
    }

    /// `Varnode::addDescend`.
    pub(crate) fn add_descend(&mut self, vn: VarnodeId, op: OpId) -> IrResult<()> {
        let d = self.vnd(vn)?;
        let free = d.flags & (vflags::INPUT | vflags::WRITTEN) == 0;
        if free && d.flags & vflags::SPACEBASE == 0 && !d.readers.is_empty() {
            return Err(IrError::FreeMultipleDescendants(vn));
        }
        let pool = &mut self.pool;
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.readers.push(pool, op.0);
            d.flags |= vflags::COVERDIRTY;
        }
        Ok(())
    }

    /// `Varnode::eraseDescend`: removes the first occurrence of `op`.
    pub(crate) fn erase_descend(&mut self, vn: VarnodeId, op: OpId) -> IrResult<()> {
        let pos = self
            .vnd(vn)?
            .readers
            .position(&self.pool, op.0)
            .ok_or(IrError::NotADescendant { vn, op })?;
        let pool = &mut self.pool;
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.readers.remove(pool, pos);
            d.flags |= vflags::COVERDIRTY;
        }
        Ok(())
    }

    /// `VarnodeBank::setInput`.
    pub(crate) fn bank_set_input(&mut self, vn: VarnodeId) -> IrResult<VarnodeId> {
        let d = self.vnd(vn)?;
        if d.flags & (vflags::INPUT | vflags::WRITTEN) != 0 {
            return Err(IrError::InputNotFree(vn));
        }
        if d.flags & vflags::CONSTANT != 0 {
            return Err(IrError::InputConstant(vn));
        }
        self.check_merge(vn, vflags::INPUT, None)?;
        self.bank_remove(vn);
        self.vnd_mut(vn)?.flags |= vflags::INPUT | vflags::COVERDIRTY;
        self.xref(vn)
    }

    /// Before a free varnode becomes `class_flag` (input or written by
    /// `def`), checks that the `xref` merge it may cause cannot fail.
    fn check_merge(&self, vn: VarnodeId, class_flag: u32, def: Option<OpId>) -> IrResult<()> {
        let Some(mut k) = self.key_parts(vn) else {
            return Ok(());
        };
        k.flags = (k.flags & !(vflags::INPUT | vflags::WRITTEN)) | class_flag;
        if let Some(op) = def {
            let o = self.opd_any(op)?;
            k.seq = (o.pc, o.time);
        }
        if let Some(&other) = self.loc.get(&k.loc())
            && other != vn
        {
            self.check_replace(vn, other)?;
        }
        Ok(())
    }

    /// `VarnodeBank::setDef`.
    pub(crate) fn bank_set_def(&mut self, vn: VarnodeId, op: OpId) -> IrResult<VarnodeId> {
        let pc = self.opd(op)?.pc;
        let d = self.vnd(vn)?;
        if d.flags & (vflags::INPUT | vflags::WRITTEN) != 0 {
            return Err(IrError::DefineNotFree {
                vn,
                at: self.shortcut_addr(pc),
            });
        }
        if d.flags & vflags::CONSTANT != 0 {
            return Err(IrError::AssignToConstant {
                vn,
                at: self.shortcut_addr(pc),
            });
        }
        self.check_merge(vn, vflags::WRITTEN, Some(op))?;
        self.bank_remove(vn);
        let d = self.vnd_mut(vn)?;
        d.def = op.0;
        d.flags |= vflags::COVERDIRTY | vflags::WRITTEN;
        self.xref(vn)
    }

    /// `VarnodeBank::makeFree`.
    pub(crate) fn bank_make_free(&mut self, vn: VarnodeId) -> IrResult<()> {
        self.vnd(vn)?;
        self.bank_remove(vn);
        let d = self.vnd_mut(vn)?;
        d.def = NONE;
        d.flags |= vflags::COVERDIRTY;
        d.flags &= !(vflags::WRITTEN | vflags::INSERT | vflags::INPUT | vflags::INDIRECT_CREATION);
        self.bank_insert_plain(vn);
        Ok(())
    }

    /// `VarnodeBank::destroy`.
    pub(crate) fn bank_destroy(&mut self, vn: VarnodeId) -> IrResult<()> {
        let d = self.vnd(vn)?;
        if d.def != NONE || !d.readers.is_empty() {
            return Err(IrError::IntegratedVarnode(vn));
        }
        self.bank_remove(vn);
        if let Some(s) = self.vstate.get_mut(vn.index()) {
            s.destroyed = true;
        }
        if let Some(d) = self.vns.get_mut(vn.index()) {
            d.cover = None;
        }
        Ok(())
    }
}
