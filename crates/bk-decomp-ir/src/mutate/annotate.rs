//! Annotations: the flag setters Ghidra exposes on `Varnode` and `PcodeOp`
//! (and the `setFlags`/`setFlag` its `Funcdata` uses as a friend), types,
//! consumed and non-zero masks, high variables, symbol entries, covers.
//! None of these changes structure: the bits that place a varnode or op in
//! the banks and lists (`input`, `written`, `insert`, `constant`,
//! `annotation`; `dead`) are refused.

use bk_decomp_types::TypeId;

use crate::cover::Cover;
use crate::error::{IrError, IrResult};
use crate::flags::{oflags, vaddl, vflags};
use crate::ids::{EntryRef, HighId, NONE, OpId, VarnodeId};
use crate::ssa::Ssa;

/// Varnode flag bits only the bank may change.
pub const STRUCTURAL_VFLAGS: u32 =
    vflags::INPUT | vflags::WRITTEN | vflags::INSERT | vflags::CONSTANT | vflags::ANNOTATION;

macro_rules! vn_setters {
    ($( $(#[$m:meta])* $set:ident / $clear:ident => $bits:expr ;)*) => {
        impl Ssa {
            $(
                $(#[$m])*
                pub fn $set(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vnd_mut(vn)?.flags |= $bits;
                    Ok(())
                }
                #[doc = concat!("The clearing counterpart of [`Ssa::", stringify!($set), "`].")]
                pub fn $clear(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vnd_mut(vn)?.flags &= !$bits;
                    Ok(())
                }
            )*
        }
    };
}

/// Setters that go through `Varnode::setFlags`/`clearFlags` and so report
/// to the high variable (`crate::high`).
macro_rules! vn_reported_setters {
    ($( $(#[$m:meta])* $set:ident / $clear:ident => $bits:expr ;)*) => {
        impl Ssa {
            $(
                $(#[$m])*
                pub fn $set(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vn_set_flags(vn, $bits)
                }
                #[doc = concat!("The clearing counterpart of [`Ssa::", stringify!($set), "`].")]
                pub fn $clear(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vn_clear_flags(vn, $bits)
                }
            )*
        }
    };
}

macro_rules! vn_addl_setters {
    ($( $(#[$m:meta])* $set:ident / $clear:ident => $bits:expr ;)*) => {
        impl Ssa {
            $(
                $(#[$m])*
                pub fn $set(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vnd_mut(vn)?.addl |= $bits;
                    Ok(())
                }
                #[doc = concat!("The clearing counterpart of [`Ssa::", stringify!($set), "`].")]
                pub fn $clear(&mut self, vn: VarnodeId) -> IrResult<()> {
                    self.vnd_mut(vn)?.addl &= !$bits;
                    Ok(())
                }
            )*
        }
    };
}

// Ghidra writes these bits directly (varnode.hh:305–308, 315–316,
// 328–331): no report to the high.
vn_setters! {
    /// `setMark`.
    set_mark / clear_mark => vflags::MARK;
    /// `setDirectWrite`.
    set_direct_write / clear_direct_write => vflags::DIRECTWRITE;
    /// `setReturnAddress`.
    set_return_address / clear_return_address => vflags::RETURN_ADDRESS;
    /// `setAutoLiveHold`.
    set_auto_live_hold / clear_auto_live_hold => vflags::AUTOLIVE_HOLD;
    /// `setProtoPartial`.
    set_proto_partial / clear_proto_partial => vflags::PROTO_PARTIAL;
}

// Through `setFlags`/`clearFlags` (varnode.hh:168, 309–314, 322–325):
// `FlagsDirty` for the high.
vn_reported_setters! {
    /// `setAddrForce`.
    set_addr_force / clear_addr_force => vflags::ADDRFORCE;
    /// `setImplied`.
    set_implied / clear_implied => vflags::IMPLIED;
    /// `setExplicit`.
    set_explicit / clear_explicit => vflags::EXPLICIT;
    /// `setPrecisLo`.
    set_precis_lo / clear_precis_lo => vflags::PRECISLO;
    /// `setPrecisHi`.
    set_precis_hi / clear_precis_hi => vflags::PRECISHI;
    /// `setUnaffected` (Ghidra has no clear; the clear reports as
    /// `clearFlags` would).
    set_unaffected / clear_unaffected => vflags::UNAFFECTED;
}

vn_addl_setters! {
    /// `setActiveHeritage`.
    set_active_heritage / clear_active_heritage => vaddl::ACTIVEHERITAGE;
    /// `setPtrFlow`.
    set_ptr_flow / clear_ptr_flow => vaddl::PTRFLOW;
    /// `setSpacebasePlaceholder`.
    set_spacebase_placeholder / clear_spacebase_placeholder => vaddl::SPACEBASE_PLACEHOLDER;
    /// `setWriteMask`.
    set_write_mask / clear_write_mask => vaddl::WRITEMASK;
    /// `setStopUpPropagation`.
    set_stop_up_propagation / clear_stop_up_propagation => vaddl::STOP_UPPROPAGATION;
    /// `setConsumeList`.
    set_consume_list / clear_consume_list => vaddl::LISCONSUME;
    /// `setConsumeVacuous`.
    set_consume_vacuous / clear_consume_vacuous => vaddl::VACCONSUME;
    /// `setUnsignedPrint` (Ghidra has no clear).
    set_unsigned_print / clear_unsigned_print => vaddl::UNSIGNEDPRINT;
    /// `setLongPrint` (Ghidra has no clear).
    set_long_print / clear_long_print => vaddl::LONGPRINT;
    /// `setImpliedField` (Ghidra has no clear).
    set_implied_field / clear_implied_field => vaddl::HAS_IMPLIED_FIELD;
    /// `setStackStore` (Ghidra has no clear).
    set_stack_store / clear_stack_store => vaddl::STACK_STORE;
    /// `setLockedInput` (Ghidra has no clear).
    set_locked_input / clear_locked_input => vaddl::LOCKED_INPUT;
}

impl Ssa {
    /// `Varnode::setFlags` as `Funcdata` uses it; structural bits are
    /// refused.
    pub fn varnode_set_flags(&mut self, vn: VarnodeId, bits: u32) -> IrResult<()> {
        if bits & STRUCTURAL_VFLAGS != 0 {
            return Err(IrError::StructuralFlags {
                method: "setFlags",
                vn,
                bits: bits & STRUCTURAL_VFLAGS,
            });
        }
        self.vn_set_flags(vn, bits)
    }

    /// `Varnode::clearFlags`; structural bits are refused.
    pub fn varnode_clear_flags(&mut self, vn: VarnodeId, bits: u32) -> IrResult<()> {
        if bits & STRUCTURAL_VFLAGS != 0 {
            return Err(IrError::StructuralFlags {
                method: "clearFlags",
                vn,
                bits: bits & STRUCTURAL_VFLAGS,
            });
        }
        self.vn_clear_flags(vn, bits)
    }

    /// `setSymbolCheck`.
    pub fn set_symbol_check(&mut self, vn: VarnodeId, val: u16) -> IrResult<()> {
        let d = self.vnd_mut(vn)?;
        d.addl = (d.addl & !vaddl::SYMCHECK_COMPLETE) | (val & vaddl::SYMCHECK_COMPLETE);
        Ok(())
    }

    /// `updateType(ct)`: sets the type unless it is locked; whether it
    /// changed (`TypeDirty` for the high when it did).
    pub fn update_type(&mut self, vn: VarnodeId, ty: TypeId) -> IrResult<bool> {
        let d = self.vnd_mut(vn)?;
        if d.ty == ty.raw() || d.flags & vflags::TYPELOCK != 0 {
            return Ok(false);
        }
        d.ty = ty.raw();
        self.type_dirty(vn);
        Ok(true)
    }

    /// `updateType(ct, lock, override)`; `lock` must already be false for a
    /// type of metatype `TYPE_UNKNOWN` (the caller has the factory).
    pub fn update_type_locked(
        &mut self,
        vn: VarnodeId,
        ty: TypeId,
        lock: bool,
        over: bool,
    ) -> IrResult<bool> {
        let d = self.vnd_mut(vn)?;
        let locked = d.flags & vflags::TYPELOCK != 0;
        if locked && !over {
            return Ok(false);
        }
        if d.ty == ty.raw() && locked == lock {
            return Ok(false);
        }
        d.flags &= !vflags::TYPELOCK;
        if lock {
            d.flags |= vflags::TYPELOCK;
        }
        d.ty = ty.raw();
        self.type_dirty(vn);
        Ok(true)
    }

    /// `setConsume`.
    pub fn set_consume(&mut self, vn: VarnodeId, mask: u64) -> IrResult<()> {
        self.vnd_mut(vn)?.consumed = mask;
        Ok(())
    }

    /// Sets `nzm` (Ghidra's `calcNZMask` writes it as a friend).
    pub fn set_nzm(&mut self, vn: VarnodeId, mask: u64) -> IrResult<()> {
        self.vnd_mut(vn)?.nzm = mask;
        Ok(())
    }

    /// `setHigh(tv, mg)`.
    pub fn set_high(&mut self, vn: VarnodeId, high: Option<HighId>, group: i16) -> IrResult<()> {
        let d = self.vnd_mut(vn)?;
        d.high = high.map_or(NONE, HighId::get);
        d.merge_group = group;
        Ok(())
    }

    /// Sets the merge group alone.
    pub fn set_merge_group(&mut self, vn: VarnodeId, group: i16) -> IrResult<()> {
        self.vnd_mut(vn)?.merge_group = group;
        Ok(())
    }

    /// Sets or clears the symbol entry reference (`mapentry`) without
    /// touching flags. `Varnode::setSymbolEntry` is
    /// [`Ssa::varnode_set_flags`] with `mapped` (and `namelock` for a
    /// name-locked symbol), then this with `Some`, which reports
    /// `SetSymbol` to the high (varnode.cc:461–471); `None` has no Ghidra
    /// setter and reports nothing.
    pub fn set_symbol_entry(&mut self, vn: VarnodeId, entry: Option<EntryRef>) -> IrResult<()> {
        self.vnd(vn)?;
        let idx = entry.map_or(NONE, |e| self.intern_entry(e));
        self.vnd_mut(vn)?.entry = idx;
        if entry.is_some() {
            self.high_set_symbol(vn);
        }
        Ok(())
    }

    /// `copySymbol`: type, entry and the type/name locks of `from`.
    pub fn copy_symbol(&mut self, vn: VarnodeId, from: VarnodeId) -> IrResult<()> {
        let f = self.vnd(from)?;
        let (ty, entry, locks) = (
            f.ty,
            f.entry,
            f.flags & (vflags::TYPELOCK | vflags::NAMELOCK),
        );
        let d = self.vnd_mut(vn)?;
        d.ty = ty;
        d.entry = entry;
        d.flags = (d.flags & !(vflags::TYPELOCK | vflags::NAMELOCK)) | locks;
        self.type_dirty(vn);
        if entry != NONE {
            self.high_set_symbol(vn);
        }
        Ok(())
    }

    /// `calcCover`: gives a varnode that has a cover an (empty, dirty) cover
    /// object.
    pub fn calc_cover(&mut self, vn: VarnodeId) -> IrResult<()> {
        if self.has_cover(vn) {
            self.vnd_mut(vn)?.cover = Some(Box::default());
            self.vn_set_flags(vn, vflags::COVERDIRTY)?;
        }
        Ok(())
    }

    /// `clearCover`.
    pub fn clear_cover(&mut self, vn: VarnodeId) -> IrResult<()> {
        self.vnd_mut(vn)?.cover = None;
        Ok(())
    }

    /// `updateCover` then `getCover`: rebuilds a dirty cover object and
    /// returns it (`None` without a cover object).
    pub fn varnode_cover(&mut self, vn: VarnodeId) -> IrResult<Option<&Cover>> {
        let d = self.vnd(vn)?;
        if d.flags & vflags::COVERDIRTY != 0 {
            if self.has_cover(vn) && d.cover.is_some() {
                let mut c = Cover::default();
                self.cover_rebuild(&mut c, vn);
                self.vnd_mut(vn)?.cover = Some(Box::new(c));
            }
            self.vn_clear_flags(vn, vflags::COVERDIRTY)?;
        }
        Ok(self.vnd(vn)?.cover.as_deref())
    }

    /// `PcodeOp::setFlag` as `Funcdata` uses it; `dead` is refused.
    pub fn op_set_flags(&mut self, op: OpId, bits: u32) -> IrResult<()> {
        if bits & oflags::DEAD != 0 {
            return Err(IrError::WrongOp {
                method: "setFlag",
                op,
                what: "changed through markAlive/markDead only (dead bit)",
            });
        }
        self.opd_mut(op)?.flags |= bits;
        Ok(())
    }

    /// `PcodeOp::clearFlag`; `dead` is refused.
    pub fn op_clear_flags(&mut self, op: OpId, bits: u32) -> IrResult<()> {
        if bits & oflags::DEAD != 0 {
            return Err(IrError::WrongOp {
                method: "clearFlag",
                op,
                what: "changed through markAlive/markDead only (dead bit)",
            });
        }
        self.opd_mut(op)?.flags &= !bits;
        Ok(())
    }

    /// `PcodeOp::flipFlag`; `dead` is refused.
    pub fn op_flip_flags(&mut self, op: OpId, bits: u32) -> IrResult<()> {
        if bits & oflags::DEAD != 0 {
            return Err(IrError::WrongOp {
                method: "flipFlag",
                op,
                what: "changed through markAlive/markDead only (dead bit)",
            });
        }
        self.opd_mut(op)?.flags ^= bits;
        Ok(())
    }

    /// `setAdditionalFlag`.
    pub fn op_set_addl(&mut self, op: OpId, bits: u32) -> IrResult<()> {
        self.opd_mut(op)?.addl |= bits;
        Ok(())
    }

    /// `clearAdditionalFlag`.
    pub fn op_clear_addl(&mut self, op: OpId, bits: u32) -> IrResult<()> {
        self.opd_mut(op)?.addl &= !bits;
        Ok(())
    }
}
