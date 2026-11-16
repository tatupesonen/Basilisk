//! Queries of varnodes (Ghidra `Varnode`'s public getters and storage
//! queries, varnode.hh:183–353, varnode.cc).

mod shadow;

use bk_core::Address;
use bk_decomp_types::TypeId;

use crate::data::VarnodeData;
use crate::flags::{vaddl, vflags};
use crate::ids::{CallSpecId, EntryRef, HighId, NONE, OpId, VarnodeId};
use crate::ssa::{SpecialSpace, Ssa};

/// What a varnode's offset denotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffsetKind {
    /// An ordinary offset (or constant value).
    Plain(u64),
    /// An `iop` varnode: the op it names.
    Op(OpId),
    /// An `fspec` varnode: the call spec it names.
    Call(CallSpecId),
    /// A `LOAD`/`STORE` space constant: the space index.
    Space(u32),
}

macro_rules! flag_getters {
    ($( $(#[$m:meta])* $name:ident => $test:expr ;)*) => {
        impl Ssa {
            $(
                $(#[$m])*
                pub fn $name(&self, vn: VarnodeId) -> bool {
                    self.vns.get(vn.index()).is_some_and(|d| {
                        let f: fn(&VarnodeData) -> bool = $test;
                        f(d)
                    })
                }
            )*
        }
    };
}

const fn has(d: &VarnodeData, bits: u32) -> bool {
    d.flags & bits != 0
}

const fn has_addl(d: &VarnodeData, bits: u16) -> bool {
    d.addl & bits != 0
}

flag_getters! {
    /// `isAnnotation`.
    is_annotation => |d| has(d, vflags::ANNOTATION);
    /// `isImplied`.
    is_implied => |d| has(d, vflags::IMPLIED);
    /// `isExplicit`.
    is_explicit => |d| has(d, vflags::EXPLICIT);
    /// `isConstant`.
    is_constant => |d| has(d, vflags::CONSTANT);
    /// `isFree`: neither input nor written.
    is_free => |d| !has(d, vflags::INPUT | vflags::WRITTEN);
    /// `isInput`.
    is_input => |d| has(d, vflags::INPUT);
    /// `isIllegalInput`: input but not direct-write.
    is_illegal_input => |d| d.flags & (vflags::INPUT | vflags::DIRECTWRITE) == vflags::INPUT;
    /// `isIndirectOnly`.
    is_indirect_only => |d| has(d, vflags::INDIRECTONLY);
    /// `isExternalRef`.
    is_external_ref => |d| has(d, vflags::EXTERNREF);
    /// `hasActionProperty`: read-only or volatile.
    has_action_property => |d| has(d, vflags::READONLY | vflags::VOLATILE);
    /// `isReadOnly`.
    is_read_only => |d| has(d, vflags::READONLY);
    /// `isVolatile`.
    is_volatile => |d| has(d, vflags::VOLATILE);
    /// `isPersist`.
    is_persist => |d| has(d, vflags::PERSIST);
    /// `isDirectWrite`.
    is_direct_write => |d| has(d, vflags::DIRECTWRITE);
    /// `isAddrTied`: `addrtied` and `insert`.
    is_addr_tied => |d| d.flags & (vflags::ADDRTIED | vflags::INSERT) == (vflags::ADDRTIED | vflags::INSERT);
    /// `isAddrForce`.
    is_addr_force => |d| has(d, vflags::ADDRFORCE);
    /// `isAutoLive`: address-forced or held.
    is_auto_live => |d| has(d, vflags::ADDRFORCE | vflags::AUTOLIVE_HOLD);
    /// `isAutoLiveHold`.
    is_auto_live_hold => |d| has(d, vflags::AUTOLIVE_HOLD);
    /// `isMapped`.
    is_mapped => |d| has(d, vflags::MAPPED);
    /// `isUnaffected`.
    is_unaffected => |d| has(d, vflags::UNAFFECTED);
    /// `isSpacebase`.
    is_spacebase => |d| has(d, vflags::SPACEBASE);
    /// `isReturnAddress`.
    is_return_address => |d| has(d, vflags::RETURN_ADDRESS);
    /// `isProtoPartial`.
    is_proto_partial => |d| has(d, vflags::PROTO_PARTIAL);
    /// `isPtrFlow`.
    is_ptr_flow => |d| has_addl(d, vaddl::PTRFLOW);
    /// `isSpacebasePlaceholder`.
    is_spacebase_placeholder => |d| has_addl(d, vaddl::SPACEBASE_PLACEHOLDER);
    /// `hasNoLocalAlias`.
    has_no_local_alias => |d| has(d, vflags::NOLOCALALIAS);
    /// `isMark`.
    is_mark => |d| has(d, vflags::MARK);
    /// `isActiveHeritage`.
    is_active_heritage => |d| has_addl(d, vaddl::ACTIVEHERITAGE);
    /// `isStackStore`.
    is_stack_store => |d| has_addl(d, vaddl::STACK_STORE);
    /// `isLockedInput`.
    is_locked_input => |d| has_addl(d, vaddl::LOCKED_INPUT);
    /// `stopsUpPropagation`.
    stops_up_propagation => |d| has_addl(d, vaddl::STOP_UPPROPAGATION);
    /// `hasImpliedField`.
    has_implied_field => |d| has_addl(d, vaddl::HAS_IMPLIED_FIELD);
    /// `isIndirectZero`: `indirect_creation` and `constant`.
    is_indirect_zero => |d| d.flags & (vflags::INDIRECT_CREATION | vflags::CONSTANT) == (vflags::INDIRECT_CREATION | vflags::CONSTANT);
    /// `isExtraOut`: `indirect_creation` without `addrtied`.
    is_extra_out => |d| d.flags & (vflags::INDIRECT_CREATION | vflags::ADDRTIED) == vflags::INDIRECT_CREATION;
    /// `isPrecisLo`.
    is_precis_lo => |d| has(d, vflags::PRECISLO);
    /// `isPrecisHi`.
    is_precis_hi => |d| has(d, vflags::PRECISHI);
    /// `isIncidentalCopy`.
    is_incidental_copy => |d| has(d, vflags::INCIDENTAL_COPY);
    /// `isWriteMask`.
    is_write_mask => |d| has_addl(d, vaddl::WRITEMASK);
    /// `isUnsignedPrint`.
    is_unsigned_print => |d| has_addl(d, vaddl::UNSIGNEDPRINT);
    /// `isLongPrint`.
    is_long_print => |d| has_addl(d, vaddl::LONGPRINT);
    /// `isWritten`.
    is_written => |d| has(d, vflags::WRITTEN);
    /// `hasCover`: `insert` without `constant` or `annotation`.
    has_cover => |d| d.flags & (vflags::CONSTANT | vflags::ANNOTATION | vflags::INSERT) == vflags::INSERT;
    /// `isHeritageKnown`: `insert`, `constant` or `annotation`.
    is_heritage_known => |d| has(d, vflags::INSERT | vflags::CONSTANT | vflags::ANNOTATION);
    /// `isTypeLock`.
    is_type_lock => |d| has(d, vflags::TYPELOCK);
    /// `isNameLock`.
    is_name_lock => |d| has(d, vflags::NAMELOCK);
    /// `isConsumeList`.
    is_consume_list => |d| has_addl(d, vaddl::LISCONSUME);
    /// `isConsumeVacuous`.
    is_consume_vacuous => |d| has_addl(d, vaddl::VACCONSUME);
}

impl Ssa {
    /// Whether `vn` is a live varnode of this function.
    pub fn varnode_exists(&self, vn: VarnodeId) -> bool {
        self.vnd(vn).is_ok()
    }

    /// `getFlags`.
    pub fn varnode_flags(&self, vn: VarnodeId) -> u32 {
        self.vns.get(vn.index()).map_or(0, |d| d.flags)
    }

    /// `addlflags`.
    pub fn varnode_addl(&self, vn: VarnodeId) -> u16 {
        self.vns.get(vn.index()).map_or(0, |d| d.addl)
    }

    /// `getSize`.
    pub fn varnode_size(&self, vn: VarnodeId) -> i32 {
        self.vns.get(vn.index()).map_or(0, |d| d.size)
    }

    /// `getAddr`, as stored (pointer-valued offsets are ids; see
    /// [`Ssa::varnode_offset_kind`]).
    pub fn varnode_addr(&self, vn: VarnodeId) -> Address {
        self.vns.get(vn.index()).map_or(Address::INVALID, |d| d.loc)
    }

    /// `getOffset`.
    pub fn varnode_offset(&self, vn: VarnodeId) -> u64 {
        self.varnode_addr(vn).offset()
    }

    /// What the offset denotes.
    pub fn varnode_offset_kind(&self, vn: VarnodeId) -> OffsetKind {
        let Some(d) = self.vns.get(vn.index()) else {
            return OffsetKind::Plain(0);
        };
        let off = d.loc.offset();
        if self.vstate(vn).space_const {
            OffsetKind::Space(off as u32)
        } else if self.is_space(d.loc, SpecialSpace::Iop) {
            OffsetKind::Op(OpId(off as u32))
        } else if self.is_space(d.loc, SpecialSpace::Fspec) {
            OffsetKind::Call(CallSpecId(off as u32))
        } else {
            OffsetKind::Plain(off)
        }
    }

    /// `getCreateIndex`.
    pub fn varnode_create_index(&self, vn: VarnodeId) -> u32 {
        self.vns.get(vn.index()).map_or(0, |d| d.create_index)
    }

    /// `getMergeGroup`.
    pub fn varnode_merge_group(&self, vn: VarnodeId) -> i16 {
        self.vns.get(vn.index()).map_or(0, |d| d.merge_group)
    }

    /// `getDef`.
    pub fn varnode_def(&self, vn: VarnodeId) -> Option<OpId> {
        self.vns.get(vn.index()).and_then(VarnodeData::def)
    }

    /// The high variable (`high`; `getHigh` throws where this is `None`).
    pub fn varnode_high(&self, vn: VarnodeId) -> Option<HighId> {
        self.vns
            .get(vn.index())
            .and_then(|d| HighId::from_packed(d.high))
    }

    /// `getSymbolEntry`.
    pub fn varnode_entry(&self, vn: VarnodeId) -> Option<EntryRef> {
        self.vns.get(vn.index()).and_then(|d| self.entry_of(d))
    }

    /// `getType`.
    pub fn varnode_type(&self, vn: VarnodeId) -> Option<TypeId> {
        self.vns
            .get(vn.index())
            .and_then(|d| (d.ty != NONE).then(|| TypeId::from_raw(d.ty)))
    }

    /// `getConsume`.
    pub fn varnode_consume(&self, vn: VarnodeId) -> u64 {
        self.vns.get(vn.index()).map_or(0, |d| d.consumed)
    }

    /// `getNZMask`.
    pub fn varnode_nzm(&self, vn: VarnodeId) -> u64 {
        self.vns.get(vn.index()).map_or(0, |d| d.nzm)
    }

    /// The readers in `descend` order.
    pub fn readers(&self, vn: VarnodeId) -> Vec<OpId> {
        self.vns.get(vn.index()).map_or_else(Vec::new, |d| {
            d.readers
                .as_slice(&self.pool)
                .iter()
                .map(|&r| OpId(r))
                .collect()
        })
    }

    /// The number of readers.
    pub fn reader_count(&self, vn: VarnodeId) -> usize {
        self.vns.get(vn.index()).map_or(0, |d| d.readers.len())
    }

    /// `hasNoDescend`.
    pub fn has_no_descend(&self, vn: VarnodeId) -> bool {
        self.reader_count(vn) == 0
    }

    /// `loneDescend`: the only reader, if there is exactly one.
    pub fn lone_descend(&self, vn: VarnodeId) -> Option<OpId> {
        let d = self.vns.get(vn.index())?;
        (d.readers.len() == 1)
            .then(|| d.readers.get(&self.pool, 0).map(OpId))
            .flatten()
    }

    /// `constantMatch`.
    pub fn constant_match(&self, vn: VarnodeId, val: u64) -> bool {
        self.is_constant(vn) && self.varnode_offset(vn) == val
    }

    /// `getSymbolCheck`.
    pub fn symbol_check(&self, vn: VarnodeId) -> u16 {
        self.varnode_addl(vn) & vaddl::SYMCHECK_COMPLETE
    }

    /// `getUsePoint`: the defining op's address, else the address before
    /// the function's entry (`fd.getAddress() + -1`, passed in).
    pub fn use_point(&self, vn: VarnodeId, before_entry: Address) -> Address {
        self.varnode_def(vn)
            .and_then(|op| self.ops.get(op.index()))
            .map_or(before_entry, |o| o.pc)
    }

    fn is_big_endian(&self, addr: Address) -> bool {
        addr.is_big_endian(&self.spaces)
    }

    /// `intersects(Varnode)`.
    pub fn intersects(&self, a: VarnodeId, b: VarnodeId) -> bool {
        match (self.vns.get(a.index()), self.vns.get(b.index())) {
            (Some(da), Some(db)) => Self::intersects_range(da, db.loc, db.size),
            _ => false,
        }
    }

    pub(crate) fn intersects_range(d: &VarnodeData, addr: Address, size: i32) -> bool {
        if d.loc.space() != addr.space() || d.loc.is_constant() {
            return false;
        }
        let a = d.loc.offset();
        let b = addr.offset();
        if b < a {
            return a < b.wrapping_add(size as u64);
        }
        b < a.wrapping_add(d.size as u64)
    }

    /// `intersects(Address, size)`.
    pub fn intersects_addr(&self, vn: VarnodeId, addr: Address, size: i32) -> bool {
        self.vns
            .get(vn.index())
            .is_some_and(|d| Self::intersects_range(d, addr, size))
    }

    /// `contains`: -1 if `op` starts before `this`, 0 if contained, 1 if
    /// only its start is contained, 2 if it starts after, 3 if the spaces
    /// are not comparable.
    pub fn contains(&self, this: VarnodeId, op: VarnodeId) -> i32 {
        let (Some(t), Some(o)) = (self.vns.get(this.index()), self.vns.get(op.index())) else {
            return 3;
        };
        if t.loc.space() != o.loc.space() || t.loc.is_constant() {
            return 3;
        }
        let a = t.loc.offset();
        let b = o.loc.offset();
        if b < a {
            return -1;
        }
        if b >= a.wrapping_add(t.size as u64) {
            return 2;
        }
        if b.wrapping_add(o.size as u64) > a.wrapping_add(t.size as u64) {
            return 1;
        }
        0
    }

    /// `characterizeOverlap`: 0 no overlap, 1 partial, 2 identical.
    pub fn characterize_overlap(&self, a: VarnodeId, b: VarnodeId) -> i32 {
        let (Some(x), Some(y)) = (self.vns.get(a.index()), self.vns.get(b.index())) else {
            return 0;
        };
        if x.loc.space() != y.loc.space() {
            return 0;
        }
        let (xo, yo) = (x.loc.offset(), y.loc.offset());
        if xo == yo {
            return if x.size == y.size { 2 } else { 1 };
        }
        if xo < yo {
            let right = xo.wrapping_add((x.size as u64).wrapping_sub(1));
            i32::from(right >= yo)
        } else {
            let right = yo.wrapping_add((y.size as u64).wrapping_sub(1));
            i32::from(right >= xo)
        }
    }

    fn overlap_with(&self, d: &VarnodeData, addr: Address, size: i32, join: bool) -> i32 {
        let size_u = size as u32;
        let lookup = |skip: i32| {
            if join {
                d.loc.overlap_join(&self.spaces, skip, addr, size_u)
            } else {
                d.loc.overlap(&self.spaces, skip, addr, size_u)
            }
        };
        if !self.is_big_endian(d.loc) {
            return lookup(0).map_or(-1, |v| v as i32);
        }
        match lookup(d.size - 1) {
            Some(over) => size - 1 - over as i32,
            None => -1,
        }
    }

    /// `overlap(Varnode)`: where the least significant byte of `this` falls
    /// in `op`, or -1.
    pub fn overlap(&self, this: VarnodeId, op: VarnodeId) -> i32 {
        match (self.vns.get(this.index()), self.vns.get(op.index())) {
            (Some(t), Some(o)) => self.overlap_with(t, o.loc, o.size, false),
            _ => -1,
        }
    }

    /// `overlapJoin`.
    pub fn overlap_join(&self, this: VarnodeId, op: VarnodeId) -> i32 {
        match (self.vns.get(this.index()), self.vns.get(op.index())) {
            (Some(t), Some(o)) => self.overlap_with(t, o.loc, o.size, true),
            _ => -1,
        }
    }

    /// `overlap(Address, size)`.
    pub fn overlap_addr(&self, this: VarnodeId, addr: Address, size: i32) -> i32 {
        self.vns
            .get(this.index())
            .map_or(-1, |t| self.overlap_with(t, addr, size, false))
    }

    /// `termOrder`: constants last; otherwise by address, looking through
    /// a multiplication by a constant.
    pub fn term_order(&self, a: VarnodeId, b: VarnodeId) -> i32 {
        if self.is_constant(a) {
            return i32::from(!self.is_constant(b));
        }
        if self.is_constant(b) {
            return -1;
        }
        let through = |v: VarnodeId| {
            if let Some(op) = self.varnode_def(v)
                && self.op_opcode(op) == Some(bk_pcode::OpCode::IntMult)
                && self.op_input(op, 1).is_some_and(|c| self.is_constant(c))
                && let Some(i) = self.op_input(op, 0)
            {
                return i;
            }
            v
        };
        let (x, y) = (self.varnode_addr(through(a)), self.varnode_addr(through(b)));
        match x.cmp(&y) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        }
    }

    /// `isConstantExtended`: the 128-bit value of a constant, or of a
    /// `ZEXT`, `SEXT` or `PIECE` of constants (outputs of at most 16 bytes).
    pub fn constant_extended(&self, vn: VarnodeId) -> Option<[u64; 2]> {
        if self.is_constant(vn) {
            return Some([self.varnode_offset(vn), 0]);
        }
        let size = self.varnode_size(vn);
        if !self.is_written(vn) || size <= 8 || size > 16 {
            return None;
        }
        let def = self.varnode_def(vn)?;
        let in0 = self.op_input(def, 0)?;
        match self.op_opcode(def)? {
            bk_pcode::OpCode::IntZExt if self.is_constant(in0) => {
                Some([self.varnode_offset(in0), 0])
            }
            bk_pcode::OpCode::IntSExt if self.is_constant(in0) => {
                let mut v = self.varnode_offset(in0);
                let in_size = self.varnode_size(in0);
                if in_size < 8 {
                    v = bk_pcode::mask::sign_extend(v, in_size.max(0) as u32, size as u32);
                }
                let hi = if v >> 63 != 0 { u64::MAX } else { 0 };
                Some([v, hi])
            }
            bk_pcode::OpCode::Piece => {
                let lo = self.op_input(def, 1)?;
                if !self.is_constant(lo) || !self.is_constant(in0) {
                    return None;
                }
                let mut v0 = self.varnode_offset(lo);
                let mut v1 = self.varnode_offset(in0);
                let lsize = self.varnode_size(lo);
                if lsize == 8 {
                    return Some([v0, v1]);
                }
                let shift = 8 * lsize.max(0) as u32;
                v0 |= v1.checked_shl(shift).unwrap_or(0);
                v1 = v1.checked_shr(8 * (8 - lsize).max(0) as u32).unwrap_or(0);
                Some([v0, v1])
            }
            _ => None,
        }
    }
}
