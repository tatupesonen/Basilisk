//! Questions about a type's components that need no IR: Ghidra's
//! `getSubType`, `getHoleSize`, `nearestArrayedComponent*`,
//! `findSmallestContainer`, `isPrimitiveWhole`, `testForArraySlack`,
//! `numDepend`/`getDepend`, `getPtrInto`, `printRaw`.

mod fields;
mod pointer;

pub use fields::BitFieldTriple;

use crate::entry::{TypeEntry, TypeKind};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// Response to a sub-component query (Ghidra `Datatype::Nearest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Nearest {
    /// Distance in bytes from the query point to the component.
    pub distance: i64,
    /// Offset from the query point to the component's start.
    pub offset: i64,
    /// Element size of the component.
    pub el_size: i32,
}

impl TypeFactory {
    /// Ghidra `getSubType`: the component at `off` and the offset into it;
    /// `None` (with `off` unchanged) when there is none.
    pub fn sub_type(&self, id: TypeId, off: i64) -> (Option<TypeId>, i64) {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Pointer(p) | TypeKind::PointerRel { ptr: p, .. } => {
                if let Some(t) = p.truncate {
                    let tsize = i64::from(self.entry(t).size);
                    let min = if e.flags.contains(crate::TypeFlags::TRUNCATE_BIGENDIAN) {
                        i64::from(e.size) - tsize
                    } else {
                        0
                    };
                    if off >= min && off < min + tsize {
                        return (Some(t), off - min);
                    }
                }
                (None, off)
            }
            TypeKind::Array { element, .. } => {
                let el = i64::from(self.entry(*element).align_size);
                if off >= i64::from(e.size) || el == 0 {
                    return (None, off);
                }
                (Some(*element), off % el)
            }
            TypeKind::Struct { fields, .. } => match self.field_iter(fields, off) {
                Some(f) => (Some(f.ty), off - i64::from(f.offset)),
                None => (None, off),
            },
            TypeKind::PartialStruct {
                container, offset, ..
            } => {
                let size_left = i64::from(e.size) - off;
                let mut off = off + i64::from(*offset);
                let mut ct = *container;
                let mut guard = 0;
                loop {
                    let (sub, newoff) = self.sub_type(ct, off);
                    let Some(sub) = sub else {
                        return (None, newoff);
                    };
                    ct = sub;
                    off = newoff;
                    guard += 1;
                    if i64::from(self.entry(ct).size) - off <= size_left || guard > crate::MAX_DEPTH
                    {
                        return (Some(ct), off);
                    }
                }
            }
            TypeKind::Code(Some(_)) => match self.cache.table.get(1).and_then(|r| r[1]) {
                Some(code) => (Some(code), 0),
                None => (None, off),
            },
            _ => (None, off),
        }
    }

    /// Ghidra `getHoleSize`: bytes of padding at `off`, or 0.
    pub fn hole_size(&self, id: TypeId, off: i32) -> i32 {
        self.hole_size_depth(id, off, 0)
    }

    fn hole_size_depth(&self, id: TypeId, off: i32, depth: usize) -> i32 {
        if depth > crate::MAX_DEPTH {
            return 0;
        }
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Array { element, .. } => {
                let el = self.entry(*element).align_size;
                if el == 0 {
                    return 0;
                }
                self.hole_size_depth(*element, off % el, depth + 1)
            }
            TypeKind::Struct { fields, .. } => {
                let i = Self::lower_bound_field(fields, i64::from(off));
                if let Some(f) = i.and_then(|i| fields.get(i)) {
                    let new_off = off.saturating_sub(f.offset);
                    if new_off < self.entry(f.ty).size {
                        return self.hole_size_depth(f.ty, new_off, depth + 1);
                    }
                }
                let next = i.map_or(0, |i| i + 1);
                match fields.get(next) {
                    Some(f) => f.offset - off,
                    None => e.size - off,
                }
            }
            TypeKind::PartialStruct {
                container, offset, ..
            } => {
                let size_left = e.size - off;
                let res = self.hole_size_depth(*container, off.saturating_add(*offset), depth + 1);
                res.min(size_left)
            }
            _ => 0,
        }
    }

    /// Ghidra `nearestArrayedComponentForward`.
    pub fn nearest_forward(&self, id: TypeId, off: i64) -> Option<Nearest> {
        self.nearest_dir(id, off, true, 0)
    }

    /// Ghidra `nearestArrayedComponentBackward`.
    pub fn nearest_backward(&self, id: TypeId, off: i64) -> Option<Nearest> {
        self.nearest_dir(id, off, false, 0)
    }

    fn nearest_dir(&self, id: TypeId, off: i64, forward: bool, depth: usize) -> Option<Nearest> {
        if depth > crate::MAX_DEPTH {
            return None;
        }
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Array { element, .. } => {
                let el_size = self.entry(*element).align_size;
                if forward {
                    if off > 0 {
                        return None;
                    }
                    Some(Nearest {
                        offset: off,
                        el_size,
                        distance: -off,
                    })
                } else {
                    if off < 0 {
                        return None;
                    }
                    let size = i64::from(e.size);
                    let distance = if off < size { 0 } else { off - size };
                    Some(Nearest {
                        offset: off,
                        el_size,
                        distance,
                    })
                }
            }
            TypeKind::Struct { fields, .. } => {
                if forward {
                    let (mut i, mut remain) = match Self::lower_bound_field(fields, off) {
                        None => (0, 0),
                        Some(i) => (i, off - fields.get(i).map_or(0, |f| i64::from(f.offset))),
                    };
                    while let Some(f) = fields.get(i) {
                        let diff = i64::from(f.offset) - off;
                        if let Some(mut res) = self.nearest_dir(f.ty, remain, true, depth + 1) {
                            res.distance += diff + remain;
                            res.offset = -diff;
                            return Some(res);
                        }
                        i += 1;
                        remain = 0;
                    }
                    None
                } else {
                    let first = Self::lower_bound_field(fields, off)?;
                    let mut i = first;
                    loop {
                        let f = fields.get(i)?;
                        let diff = off - i64::from(f.offset);
                        let remain = if i == first {
                            diff
                        } else {
                            i64::from(self.entry(f.ty).size)
                        };
                        if let Some(mut res) = self.nearest_dir(f.ty, remain, false, depth + 1) {
                            res.distance += diff - remain;
                            res.offset = diff;
                            return Some(res);
                        }
                        i = i.checked_sub(1)?;
                    }
                }
            }
            TypeKind::Union { fields } => fields
                .iter()
                .find_map(|f| self.nearest_dir(f.ty, off, forward, depth + 1)),
            _ => None,
        }
    }

    /// Ghidra `nearestArrayedComponent`: the offset of the best arrayed
    /// component near `off`, preferring element size `hint`.
    pub fn nearest_arrayed_component(&self, id: TypeId, off: i64, hint: u32) -> Option<i64> {
        let before = self.nearest_backward(id, off);
        let after = self.nearest_forward(id, off);
        let (before, after) = match (before, after) {
            (None, None) => return None,
            (None, Some(a)) => return Some(a.offset),
            (Some(b), None) => return Some(b.offset),
            (Some(b), Some(a)) => (b, a),
        };
        if hint != 1 && before.el_size != after.el_size {
            if i64::from(before.el_size) == i64::from(hint) {
                return Some(before.offset);
            }
            if i64::from(after.el_size) == i64::from(hint) {
                return Some(after.offset);
            }
        }
        let (sub, newoff) = self.sub_type(id, off);
        if sub.is_some() && (newoff == before.offset || newoff == after.offset) {
            return Some(newoff);
        }
        Some(if after.distance <= before.distance {
            after.offset
        } else {
            before.offset
        })
    }

    /// Ghidra `testForArraySlack`.
    pub fn test_for_array_slack(&self, id: TypeId, off: i64) -> bool {
        if self.entry(id).metatype == Metatype::Array {
            return true;
        }
        if off < 0 {
            self.nearest_forward(id, off).is_some()
        } else {
            self.nearest_backward(id, off).is_some()
        }
    }

    /// Ghidra `findSmallestContainer`: the smallest component holding
    /// `off..off+sz`, and the offset into it.
    pub fn find_smallest_container(&self, id: TypeId, off: i64, sz: i64) -> (TypeId, i64) {
        let (mut res, mut res_off) = (id, off);
        let (mut next, mut cur_off) = (id, off);
        for _ in 0..=crate::MAX_DEPTH {
            let (sub, newoff) = self.sub_type(next, cur_off);
            cur_off = newoff;
            let Some(sub) = sub else { break };
            next = sub;
            if cur_off + sz > i64::from(self.entry(sub).size) {
                break;
            }
            res = sub;
            res_off = cur_off;
        }
        (res, res_off)
    }

    /// Ghidra `numDepend`.
    pub fn num_depend(&self, id: TypeId) -> usize {
        match &self.entry(id).kind {
            TypeKind::PartialUnion { container, .. } => self.entry(*container).num_depend_local(),
            _ => self.entry(id).num_depend_local(),
        }
    }

    /// Ghidra `getDepend`.
    pub fn depend(&self, id: TypeId, index: usize) -> Option<TypeId> {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Pointer(p) | TypeKind::PointerRel { ptr: p, .. } => Some(p.ptrto),
            TypeKind::Array { element, .. } => Some(*element),
            TypeKind::Struct { fields, .. } | TypeKind::Union { fields } => {
                fields.get(index).map(|f| f.ty)
            }
            TypeKind::PartialUnion {
                container,
                stripped,
                ..
            } => {
                let res = self.depend(*container, index)?;
                Some(if self.entry(res).size == e.size {
                    res
                } else {
                    *stripped
                })
            }
            _ => None,
        }
    }

    /// Ghidra `isPrimitiveWhole`.
    pub fn is_primitive_whole(&self, id: TypeId) -> bool {
        let mut cur = id;
        for _ in 0..=crate::MAX_DEPTH {
            let e = self.entry(cur);
            if !e.is_piece_structured() {
                return true;
            }
            if !matches!(e.metatype, Metatype::Array | Metatype::Struct)
                || self.num_depend(cur) == 0
            {
                return false;
            }
            let Some(comp) = self.depend(cur, 0) else {
                return false;
            };
            if self.entry(comp).size != e.size {
                return false;
            }
            cur = comp;
        }
        false
    }

    /// Ghidra `getPtrInto`: the type a pointer points into, and the offset.
    pub fn ptr_into(&self, id: TypeId) -> Option<(TypeId, i32)> {
        match &self.entry(id).kind {
            TypeKind::Pointer(p) => Some((p.ptrto, 0)),
            TypeKind::PointerRel {
                ptr,
                parent,
                offset,
                ..
            } => {
                let meta = self.entry(ptr.ptrto).metatype;
                if matches!(meta, Metatype::Struct | Metatype::Union) {
                    Some((ptr.ptrto, 0))
                } else {
                    Some((*parent, *offset))
                }
            }
            _ => None,
        }
    }

    /// Ghidra `TypePartialStruct::getComponentForPtr`.
    pub fn component_for_ptr(&self, id: TypeId) -> Option<TypeId> {
        let TypeKind::PartialStruct {
            container,
            offset,
            stripped,
        } = self.entry(id).kind
        else {
            return None;
        };
        if let TypeKind::Array { element, .. } = self.entry(container).kind {
            let el = self.entry(element);
            if el.metatype != Metatype::Unknown && el.align_size != 0 && offset % el.align_size == 0
            {
                return Some(element);
            }
        }
        Some(stripped)
    }

    /// Ghidra `printRaw`: a debugging description of a type.
    pub fn print_raw(&self, id: TypeId) -> String {
        self.print_raw_entry(self.entry(id))
    }

    pub(crate) fn print_raw_entry(&self, e: &TypeEntry) -> String {
        let mut s = String::new();
        self.print_raw_into(&mut s, e, 0);
        s
    }

    fn print_raw_into(&self, s: &mut String, e: &TypeEntry, depth: usize) {
        use std::fmt::Write as _;
        if depth > crate::MAX_DEPTH {
            s.push_str("...");
            return;
        }
        match &e.kind {
            TypeKind::Pointer(p) => {
                self.print_raw_into(s, self.entry(p.ptrto), depth + 1);
                s.push_str(" *");
                if let Some(space) = p.space {
                    let name = self.env.space(space).map_or("?", |i| i.name.as_str());
                    let _ = write!(s, "({name})");
                }
            }
            TypeKind::PointerRel {
                ptr,
                parent,
                offset,
                ..
            } => {
                self.print_raw_into(s, self.entry(ptr.ptrto), depth + 1);
                let _ = write!(s, " *+{offset}[");
                self.print_raw_into(s, self.entry(*parent), depth + 1);
                s.push(']');
            }
            TypeKind::Array { element, count } => {
                self.print_raw_into(s, self.entry(*element), depth + 1);
                let _ = write!(s, " [{count}]");
            }
            TypeKind::PartialEnum {
                parent: c, offset, ..
            }
            | TypeKind::PartialStruct {
                container: c,
                offset,
                ..
            }
            | TypeKind::PartialUnion {
                container: c,
                offset,
                ..
            } => {
                self.print_raw_into(s, self.entry(*c), depth + 1);
                let _ = write!(s, "[off={offset},sz={}]", e.size);
            }
            TypeKind::Code(_) => {
                s.push_str(if e.name.is_empty() {
                    "funcptr"
                } else {
                    &e.name
                });
                s.push_str("()");
            }
            _ => {
                if e.name.is_empty() {
                    let _ = write!(s, "unkbyte{}", e.size);
                } else {
                    s.push_str(&e.name);
                }
            }
        }
    }
}
