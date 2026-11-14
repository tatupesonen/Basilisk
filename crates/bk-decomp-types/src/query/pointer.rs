//! Pointer arithmetic over types (Ghidra `TypePointer::downChain`,
//! `TypePointerRel::downChain`, `isPtrsubMatching`, `isOffsetValid`,
//! `TypePointerRel::evaluateThruParent`, `getPtrToFromParent`).

use bk_core::bits::{calc_mask, sign_extend_bit};

use crate::entry::TypeKind;
use crate::error::Result;
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// The result of [`TypeFactory::down_chain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownChain {
    /// The pointer to the component, if there is one.
    pub pointer: Option<TypeId>,
    /// The remaining offset into the component.
    pub offset: i64,
    /// The pointer to the container passed through, if any.
    pub parent: Option<TypeId>,
    /// The offset into that container.
    pub parent_offset: i64,
}

impl TypeFactory {
    /// Ghidra `downChain`: adds `off` to pointer `ptr` and goes down one
    /// level to the component there.
    pub fn down_chain(
        &mut self,
        ptr: TypeId,
        off: i64,
        allow_array_wrap: bool,
    ) -> Result<DownChain> {
        let mut res = DownChain {
            pointer: None,
            offset: off,
            parent: None,
            parent_offset: 0,
        };
        let e = self.entry_checked(ptr)?.clone();
        match &e.kind {
            TypeKind::PointerRel {
                ptr: p,
                parent,
                offset,
                ..
            } => {
                let target = self.entry(p.ptrto);
                if off >= 0
                    && off < i64::from(target.size)
                    && matches!(target.metatype, Metatype::Struct | Metatype::Array)
                {
                    return self.down_chain_plain(ptr, res, allow_array_wrap);
                }
                let rel = (off.wrapping_add(i64::from(*offset)) as u64
                    & calc_mask(e.size.max(0) as u32)) as i64;
                if rel < 0 || rel >= i64::from(self.entry(*parent).size) {
                    return Ok(res);
                }
                let orig = self.pointer(e.size, *parent, p.wordsize)?;
                res.offset = rel;
                if rel == 0 && *offset != 0 {
                    res.pointer = Some(orig);
                    return Ok(res);
                }
                self.down_chain_plain(orig, res, allow_array_wrap)
            }
            TypeKind::Pointer(_) => self.down_chain_plain(ptr, res, allow_array_wrap),
            _ => Ok(res),
        }
    }

    fn down_chain_plain(
        &mut self,
        ptr: TypeId,
        mut res: DownChain,
        wrap: bool,
    ) -> Result<DownChain> {
        let e = self.entry(ptr);
        let Some(p) = e.pointer().copied() else {
            return Ok(res);
        };
        let size = e.size;
        let target = self.entry(p.ptrto);
        let ptrto_size = i64::from(target.align_size);
        if res.offset < 0 || res.offset >= ptrto_size {
            if ptrto_size != 0 && !target.is_variable_length() {
                if !wrap {
                    return Ok(res);
                }
                let bit = (size.saturating_mul(8) - 1).clamp(0, 63) as u32;
                let mut sign_off = sign_extend_bit(res.offset, bit) % ptrto_size;
                if sign_off < 0 {
                    sign_off += ptrto_size;
                }
                res.offset = sign_off;
                if res.offset == 0 {
                    res.pointer = Some(ptr);
                    return Ok(res);
                }
            }
        }
        if target.is_enum() {
            let byte = self.base(1, Metatype::Uint)?;
            res.offset = 0;
            res.pointer = Some(self.pointer(size, byte, p.wordsize)?);
            return Ok(res);
        }
        let is_array = target.metatype == Metatype::Array;
        if is_array || target.metatype == Metatype::Struct {
            res.parent = Some(ptr);
            res.parent_offset = res.offset;
        }
        let (sub, newoff) = self.sub_type(p.ptrto, res.offset);
        res.offset = newoff;
        let Some(pt) = sub else { return Ok(res) };
        res.pointer = Some(if is_array {
            self.pointer(size, pt, p.wordsize)?
        } else {
            self.pointer_strip_array(size, pt, p.wordsize)?
        });
        Ok(res)
    }

    /// Ghidra `isPtrsubMatching`.
    pub fn is_ptrsub_matching(&self, id: TypeId, off: i64, extra: i64, multiplier: i64) -> bool {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Pointer(p) => {
                let ws = i64::from(p.wordsize);
                self.is_offset_valid(
                    p.ptrto,
                    off.wrapping_mul(ws),
                    extra.wrapping_mul(ws),
                    multiplier.wrapping_mul(ws),
                )
            }
            TypeKind::PointerRel {
                ptr,
                parent,
                offset,
                stripped,
            } => {
                let ws = i64::from(ptr.wordsize);
                if stripped.is_some() {
                    return self.is_offset_valid(
                        ptr.ptrto,
                        off.wrapping_mul(ws),
                        extra.wrapping_mul(ws),
                        multiplier.wrapping_mul(ws),
                    );
                }
                let i_off = (off.wrapping_mul(ws) as i32)
                    .wrapping_add(*offset)
                    .wrapping_add(extra.wrapping_mul(ws) as i32);
                i_off >= 0 && i_off <= self.entry(*parent).size
            }
            _ => false,
        }
    }

    /// Ghidra `isOffsetValid`.
    pub fn is_offset_valid(&self, id: TypeId, off: i64, extra: i64, multiplier: i64) -> bool {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Array { .. } => off == 0 && multiplier < i64::from(e.align_size),
            TypeKind::Struct { .. } => {
                if multiplier >= i64::from(e.align_size) {
                    return false;
                }
                let (sub, newoff) = self.sub_type(id, off);
                match sub {
                    Some(sub) => {
                        if newoff != 0 {
                            return false;
                        }
                        if (extra < 0 || extra >= i64::from(self.entry(sub).size))
                            && !self.test_for_array_slack(sub, extra)
                        {
                            return false;
                        }
                        true
                    }
                    None => {
                        let extra = extra + newoff;
                        !((extra < 0 || extra >= i64::from(e.size)) && e.size != 0)
                    }
                }
            }
            TypeKind::Code(_) => extra >= 0,
            _ => false,
        }
    }

    /// Ghidra `TypePointerRel::evaluateThruParent`.
    pub fn evaluate_thru_parent(&self, id: TypeId, addr_off: u64) -> bool {
        let e = self.entry(id);
        let TypeKind::PointerRel {
            ptr,
            parent,
            offset,
            ..
        } = &e.kind
        else {
            return false;
        };
        let mut byte_off = addr_off.wrapping_mul(u64::from(ptr.wordsize));
        let target = self.entry(ptr.ptrto);
        if target.metatype == Metatype::Struct && byte_off < target.size.max(0) as u64 {
            return false;
        }
        byte_off = byte_off.wrapping_add(*offset as i64 as u64) & calc_mask(e.size.max(0) as u32);
        byte_off < self.entry(*parent).size.max(0) as u64
    }

    /// Ghidra `TypePointerRel::getPtrToFromParent`: the largest component
    /// starting exactly at `off` in `base`, else `xunknown1`.
    pub fn ptr_to_from_parent(&mut self, base: TypeId, off: i32) -> Result<TypeId> {
        if off > 0 {
            let (mut cur, mut cur_off) = (Some(base), i64::from(off));
            for _ in 0..=crate::MAX_DEPTH {
                let Some(t) = cur else { break };
                let (sub, newoff) = self.sub_type(t, cur_off);
                cur = sub;
                cur_off = newoff;
                if cur_off == 0 || cur.is_none() {
                    break;
                }
            }
            if let (Some(t), 0) = (cur, cur_off) {
                return Ok(t);
            }
            if let Some(t) = cur {
                return Ok(t);
            }
        }
        self.base(1, Metatype::Unknown)
    }
}
