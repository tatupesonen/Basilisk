//! Pointers and arrays (Ghidra `getTypePointer` and its variants,
//! `getTypePointerRel`, `getTypePointerWithSpace`, `resizePointer`,
//! `getTypeArray`, `TypePointer::calcSubmeta`, `calcTruncate`,
//! `recalcPointerSubmeta`, `TypePointerRel::markEphemeral`).

use bk_marshal::SpaceId;

use crate::entry::{PointerData, TypeEntry, TypeFlags, TypeKind, hash_name};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};

impl TypeFactory {
    /// Ghidra `TypePointer::calcSubmeta`: the sub-metatype and flags a
    /// pointer to `ptrto` gets.
    pub(crate) fn calc_pointer_submeta(&self, e: &mut TypeEntry, ptrto: TypeId) {
        let target = self.entry(ptrto);
        match target.metatype {
            Metatype::Struct => {
                e.submeta = if target.needs_resolution() {
                    SubMetatype::Ptr
                } else {
                    SubMetatype::PtrStruct
                };
            }
            Metatype::Union => e.submeta = SubMetatype::PtrStruct,
            Metatype::Array => e.flags |= TypeFlags::POINTER_TO_ARRAY,
            _ => {}
        }
        if target.needs_resolution() && target.metatype != Metatype::Ptr {
            e.flags |= TypeFlags::NEEDS_RESOLUTION;
        }
    }

    /// The candidate for `TypePointer(size, ptrto, wordsize)`.
    pub(crate) fn pointer_entry(
        &self,
        size: i32,
        ptrto: TypeId,
        wordsize: u32,
    ) -> Result<TypeEntry> {
        if size < 0 {
            return Err(TypeError::new("Bad data-type size"));
        }
        let mut e = TypeEntry::new(
            size,
            -1,
            Metatype::Ptr,
            TypeKind::Pointer(PointerData {
                ptrto,
                space: None,
                truncate: None,
                wordsize,
            }),
        );
        e.flags = self.entry(ptrto).inherit_for_pointer();
        self.calc_pointer_submeta(&mut e, ptrto);
        Ok(e)
    }

    fn strip(&self, id: TypeId) -> TypeId {
        let e = self.entry(id);
        if e.has_stripped() {
            e.stripped().unwrap_or(id)
        } else {
            id
        }
    }

    /// Ghidra `getTypePointer(s, pt, ws)`.
    pub fn pointer(&mut self, size: i32, ptrto: TypeId, wordsize: u32) -> Result<TypeId> {
        self.entry_checked(ptrto)?;
        let pt = self.strip(ptrto);
        let cand = self.pointer_entry(size, pt, wordsize)?;
        let res = self.find_add(cand)?;
        self.calc_truncate(res)?;
        Ok(res)
    }

    /// Ghidra `getTypePointerStripArray`: a pointer to an array becomes a
    /// pointer to its element.
    pub fn pointer_strip_array(
        &mut self,
        size: i32,
        ptrto: TypeId,
        wordsize: u32,
    ) -> Result<TypeId> {
        self.entry_checked(ptrto)?;
        let mut pt = self.strip(ptrto);
        if let TypeKind::Array { element, .. } = self.entry(pt).kind {
            if self.entry(pt).metatype == Metatype::Array {
                pt = element;
            }
        }
        let cand = self.pointer_entry(size, pt, wordsize)?;
        let res = self.find_add(cand)?;
        self.calc_truncate(res)?;
        Ok(res)
    }

    /// Ghidra `getTypePointer(s, pt, ws, n)`: a named pointer.
    pub fn pointer_named(
        &mut self,
        size: i32,
        ptrto: TypeId,
        wordsize: u32,
        name: &str,
    ) -> Result<TypeId> {
        self.entry_checked(ptrto)?;
        let pt = self.strip(ptrto);
        let mut cand = self.pointer_entry(size, pt, wordsize)?;
        cand.set_name(name, hash_name(name));
        let res = self.find_add(cand)?;
        self.calc_truncate(res)?;
        Ok(res)
    }

    /// Ghidra `getTypePointerWithSpace`: a named pointer into a given space.
    pub fn pointer_with_space(
        &mut self,
        ptrto: TypeId,
        space: SpaceId,
        name: &str,
    ) -> Result<TypeId> {
        self.entry_checked(ptrto)?;
        let info = self
            .env
            .space(space)
            .ok_or_else(|| TypeError::new(format!("Unknown address space {}", space.index())))?;
        let (size, ws) = (info.addr_size, info.word_size);
        let mut cand = self.pointer_entry(size, ptrto, ws)?;
        if let TypeKind::Pointer(p) = &mut cand.kind {
            p.space = Some(space);
        }
        cand.set_name(name, hash_name(name));
        let res = self.find_add(cand)?;
        self.calc_truncate(res)?;
        Ok(res)
    }

    /// Ghidra `resizePointer`: the same pointer with another size.
    pub fn resize_pointer(&mut self, ptr: TypeId, new_size: i32) -> Result<TypeId> {
        let p = *self
            .entry_checked(ptr)?
            .pointer()
            .ok_or_else(|| TypeError::new("Not a pointer"))?;
        let pt = self.strip(p.ptrto);
        let cand = self.pointer_entry(new_size, pt, p.wordsize)?;
        self.find_add(cand)
    }

    /// Ghidra `TypePointer::calcTruncate`: a pointer of the alternate size
    /// gets a truncated form.
    pub(crate) fn calc_truncate(&mut self, id: TypeId) -> Result<()> {
        let e = self.entry(id);
        let Some(p) = e.pointer() else { return Ok(()) };
        if p.truncate.is_some() || e.size != self.org.size_of_alt_pointer {
            return Ok(());
        }
        let short = self.resize_pointer(id, self.org.size_of_pointer)?;
        let big = self.env.data_space.big_endian;
        self.modify(id, |e| {
            if let TypeKind::Pointer(p) | TypeKind::PointerRel { ptr: p, .. } = &mut e.kind {
                p.truncate = Some(short);
            }
            if big {
                e.flags |= TypeFlags::TRUNCATE_BIGENDIAN;
            }
        })
    }

    /// Ghidra `recalcPointerSubmeta`: pointers to `base` still carrying
    /// sub-metatype `sub` get the one a pointer to `base` now gets.
    pub(crate) fn recalc_pointer_submeta(&mut self, base: TypeId, sub: SubMetatype) -> Result<()> {
        let mut probe = self.pointer_entry(1, base, 0)?;
        self.calc_pointer_submeta(&mut probe, base);
        let current = probe.submeta;
        if current == sub {
            return Ok(());
        }
        for ptr in self.pointers_to(base) {
            let e = self.entry(ptr);
            if matches!(e.kind, TypeKind::Pointer(_)) && e.submeta == sub {
                self.modify(ptr, |e| e.submeta = current)?;
            }
        }
        Ok(())
    }

    /// The candidate for an ephemeral or named relative pointer.
    fn pointer_rel_entry(
        &self,
        size: i32,
        ptrto: TypeId,
        wordsize: u32,
        parent: TypeId,
        offset: i32,
    ) -> Result<TypeEntry> {
        let base = self.pointer_entry(size, ptrto, wordsize)?;
        let TypeKind::Pointer(ptr) = base.kind else {
            return Err(TypeError::new("Bad pointer"));
        };
        let mut e = base;
        e.kind = TypeKind::PointerRel {
            ptr,
            parent,
            offset,
            stripped: None,
        };
        e.flags |= TypeFlags::IS_PTRREL;
        e.submeta = SubMetatype::PtrRel;
        Ok(e)
    }

    /// Ghidra `getTypePointerRel(parentPtr, ptrTo, off)`: an unnamed,
    /// ephemeral relative pointer.
    pub fn pointer_rel(
        &mut self,
        parent_ptr: TypeId,
        ptrto: TypeId,
        offset: i32,
    ) -> Result<TypeId> {
        self.entry_checked(ptrto)?;
        let pe = self.entry_checked(parent_ptr)?;
        let p = *pe
            .pointer()
            .ok_or_else(|| TypeError::new("Not a pointer"))?;
        let size = pe.size;
        let mut cand = self.pointer_rel_entry(size, ptrto, p.wordsize, p.ptrto, offset)?;
        // markEphemeral
        let stripped = self.pointer(size, ptrto, p.wordsize)?;
        if let TypeKind::PointerRel { stripped: s, .. } = &mut cand.kind {
            *s = Some(stripped);
        }
        cand.flags |= TypeFlags::HAS_STRIPPED;
        if self.entry(ptrto).metatype == Metatype::Unknown {
            cand.submeta = SubMetatype::PtrRelUnk;
        }
        self.find_add(cand)
    }

    /// Ghidra `getTypePointerRel(sz, parent, ptrTo, ws, off, nm)`: a named,
    /// formal relative pointer.
    pub fn pointer_rel_named(
        &mut self,
        size: i32,
        parent: TypeId,
        ptrto: TypeId,
        wordsize: u32,
        offset: i32,
        name: &str,
    ) -> Result<TypeId> {
        self.entry_checked(parent)?;
        self.entry_checked(ptrto)?;
        let mut cand = self.pointer_rel_entry(size, ptrto, wordsize, parent, offset)?;
        cand.set_name(name, hash_name(name));
        self.find_add(cand)
    }

    /// The candidate for `TypeArray(n, element)`.
    pub(crate) fn array_entry(&self, count: i32, element: TypeId) -> Result<TypeEntry> {
        let el = self.entry(element);
        let size = count
            .checked_mul(el.align_size)
            .filter(|&s| s >= 0)
            .ok_or_else(|| TypeError::new("Bad data-type size"))?;
        let mut e = TypeEntry::new(
            size,
            el.alignment,
            Metatype::Array,
            TypeKind::Array { element, count },
        );
        if count == 1 {
            e.flags |= TypeFlags::NEEDS_RESOLUTION;
        }
        Ok(e)
    }

    /// Ghidra `getTypeArray`.
    pub fn array(&mut self, count: i32, element: TypeId) -> Result<TypeId> {
        self.entry_checked(element)?;
        let el = self.strip(element);
        let cand = self.array_entry(count, el)?;
        self.find_add(cand)
    }
}
