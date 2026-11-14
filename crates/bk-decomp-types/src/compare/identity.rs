//! The identity order (Ghidra `compareDependency` of every class, and
//! `DatatypeCompare`), and a hash consistent with it.
//!
//! Where Ghidra compares component *pointers* ("Compare absolute pointers")
//! this compares component [`TypeId`]s, which follow creation order instead
//! of heap addresses (spec 4.3). Where Ghidra would cast a type to the wrong
//! class (two kinds sharing a sub-metatype, which Ghidra never creates in
//! practice but which hostile XML can), the kinds' families are compared.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use rustc_hash::FxHasher;

use crate::entry::{CodeSignature, TypeEntry, TypeKind};

/// Turns an [`Ordering`] into Ghidra's -1/0/1.
pub(crate) const fn sign(ord: Ordering) -> i32 {
    match ord {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Ghidra's `(a < b) ? -1 : 1` for values known to differ, 0 when equal.
pub(crate) fn cmp3<T: Ord>(a: &T, b: &T) -> i32 {
    sign(a.cmp(b))
}

/// Larger size first: Ghidra's `op.size - size`, as a sign.
pub(crate) fn size_order(a: i32, b: i32) -> i32 {
    sign(b.cmp(&a)) // b > a gives positive: a comes later
}

/// The comparison families: kinds whose `compareDependency` reads the same
/// data.
pub(crate) const fn family(kind: &TypeKind) -> u8 {
    match kind {
        TypeKind::Base | TypeKind::Char | TypeKind::Unicode | TypeKind::Void => 0,
        TypeKind::Enum(_) => 1,
        TypeKind::Pointer(_) => 2,
        TypeKind::PointerRel { .. } => 3,
        TypeKind::Array { .. } => 4,
        TypeKind::PartialEnum { .. } => 5,
        TypeKind::Struct { .. } => 6,
        TypeKind::Union { .. } => 7,
        TypeKind::PartialStruct { .. } => 8,
        TypeKind::PartialUnion { .. } => 9,
        TypeKind::Code(_) => 10,
        TypeKind::Spacebase { .. } => 11,
    }
}

/// Ghidra `TypeCode::compareBasic`: -1/1 on a surface difference, 0 when
/// equal with nothing more to compare, 2 to continue with the parameters.
pub(crate) fn compare_basic(a: Option<&CodeSignature>, b: Option<&CodeSignature>) -> i32 {
    let (a, b) = match (a, b) {
        (None, None) => return 0,
        (None, Some(_)) => return 1,
        (Some(_), None) => return -1,
        (Some(a), Some(b)) => (a, b),
    };
    match (&a.model, &b.model) {
        (None, Some(_)) => return 1,
        (Some(_), None) => return -1,
        (Some(m1), Some(m2)) if m1 != m2 => return cmp3(m1, m2),
        _ => {}
    }
    let (n1, n2) = (a.params.len(), b.params.len());
    if n1 != n2 {
        return if n2 < n1 { -1 } else { 1 };
    }
    if a.flags != b.flags {
        return cmp3(&a.flags, &b.flags);
    }
    2
}

/// Field-count difference as Ghidra computes it: `other.len() - self.len()`
/// as a sign (more fields first).
fn count_order(a: usize, b: usize) -> i32 {
    sign(b.cmp(&a))
}

/// Ghidra `compareDependency`: negative when `a` sorts first.
#[expect(
    clippy::many_single_char_names,
    reason = "the two types and their parts, side by side"
)]
pub fn compare_dependency(a: &TypeEntry, b: &TypeEntry) -> i32 {
    if a.submeta != b.submeta {
        return cmp3(&a.submeta, &b.submeta);
    }
    let (fa, fb) = (family(&a.kind), family(&b.kind));
    if fa != fb {
        return cmp3(&fa, &fb);
    }
    match (&a.kind, &b.kind) {
        (TypeKind::Pointer(p), TypeKind::Pointer(q)) => {
            if p.ptrto != q.ptrto {
                return cmp3(&p.ptrto, &q.ptrto);
            }
            if p.wordsize != q.wordsize {
                return cmp3(&p.wordsize, &q.wordsize);
            }
            if p.space != q.space {
                return match (p.space, q.space) {
                    (None, _) => 1,
                    (_, None) => -1,
                    (Some(s), Some(t)) => cmp3(&s.index(), &t.index()),
                };
            }
            size_order(a.size, b.size)
        }
        (
            TypeKind::PointerRel {
                ptr: p,
                parent: pp,
                offset: po,
                ..
            },
            TypeKind::PointerRel {
                ptr: q,
                parent: qp,
                offset: qo,
                ..
            },
        ) => {
            if p.ptrto != q.ptrto {
                return cmp3(&p.ptrto, &q.ptrto);
            }
            if po != qo {
                return cmp3(po, qo);
            }
            if pp != qp {
                return cmp3(pp, qp);
            }
            if p.wordsize != q.wordsize {
                return cmp3(&p.wordsize, &q.wordsize);
            }
            size_order(a.size, b.size)
        }
        (TypeKind::Array { element: e1, .. }, TypeKind::Array { element: e2, .. }) => {
            if e1 != e2 {
                return cmp3(e1, e2);
            }
            size_order(a.size, b.size)
        }
        (
            TypeKind::PartialEnum {
                parent: c1,
                offset: o1,
                ..
            },
            TypeKind::PartialEnum {
                parent: c2,
                offset: o2,
                ..
            },
        )
        | (
            TypeKind::PartialStruct {
                container: c1,
                offset: o1,
                ..
            },
            TypeKind::PartialStruct {
                container: c2,
                offset: o2,
                ..
            },
        )
        | (
            TypeKind::PartialUnion {
                container: c1,
                offset: o1,
                ..
            },
            TypeKind::PartialUnion {
                container: c2,
                offset: o2,
                ..
            },
        ) => {
            if c1 != c2 {
                return cmp3(c1, c2);
            }
            if o1 != o2 {
                return cmp3(o1, o2);
            }
            size_order(a.size, b.size)
        }
        _ => {
            let res = size_order(a.size, b.size);
            if res != 0 {
                return res;
            }
            compare_dependency_rest(a, b)
        }
    }
}

/// The part of `compareDependency` after the common size test, for the
/// kinds that start with `Datatype::compareDependency`.
fn compare_dependency_rest(a: &TypeEntry, b: &TypeEntry) -> i32 {
    match (&a.kind, &b.kind) {
        (TypeKind::Enum(e1), TypeKind::Enum(e2)) => {
            if e1.values.len() != e2.values.len() {
                return cmp3(&e1.values.len(), &e2.values.len());
            }
            for ((v1, n1), (v2, n2)) in e1.values.iter().zip(&e2.values) {
                if v1 != v2 {
                    return cmp3(v1, v2);
                }
                if n1 != n2 {
                    return cmp3(n1, n2);
                }
            }
            0
        }
        (
            TypeKind::Struct {
                fields: f1,
                bitfields: b1,
            },
            TypeKind::Struct {
                fields: f2,
                bitfields: b2,
            },
        ) => {
            if f1.len() != f2.len() {
                return count_order(f1.len(), f2.len());
            }
            for (x, y) in f1.iter().zip(f2) {
                if x.offset != y.offset {
                    return cmp3(&x.offset, &y.offset);
                }
                if x.name != y.name {
                    return cmp3(&x.name, &y.name);
                }
                if x.ty != y.ty {
                    return cmp3(&x.ty, &y.ty);
                }
            }
            if b1.len() != b2.len() {
                return count_order(b1.len(), b2.len());
            }
            for (x, y) in b1.iter().zip(b2) {
                let res = sign(x.bits.compare(&y.bits));
                if res != 0 {
                    return res;
                }
                if x.name != y.name {
                    return cmp3(&x.name, &y.name);
                }
                if x.ty != y.ty {
                    return cmp3(&x.ty, &y.ty);
                }
            }
            0
        }
        (TypeKind::Union { fields: f1 }, TypeKind::Union { fields: f2 }) => {
            if f1.len() != f2.len() {
                return count_order(f1.len(), f2.len());
            }
            for (x, y) in f1.iter().zip(f2) {
                if x.name != y.name {
                    return cmp3(&x.name, &y.name);
                }
                if x.ty != y.ty {
                    return cmp3(&x.ty, &y.ty);
                }
            }
            0
        }
        (TypeKind::Code(s1), TypeKind::Code(s2)) => {
            let res = compare_basic(s1.as_deref(), s2.as_deref());
            if res != 2 {
                return res;
            }
            let (Some(s1), Some(s2)) = (s1.as_deref(), s2.as_deref()) else {
                return 0;
            };
            for ((p1, _), (p2, _)) in s1.params.iter().zip(&s2.params) {
                if p1 != p2 {
                    return cmp3(p1, p2);
                }
            }
            match (s1.output, s2.output) {
                (None, None) => 0,
                (None, Some(_)) => 1,
                (Some(_), None) => -1,
                (Some(o1), Some(o2)) => cmp3(&o1, &o2),
            }
        }
        (
            TypeKind::Spacebase {
                space: s1,
                scope: c1,
            },
            TypeKind::Spacebase {
                space: s2,
                scope: c2,
            },
        ) => {
            if s1 != s2 {
                return cmp3(&s1.index(), &s2.index());
            }
            cmp3(c1, c2)
        }
        _ => 0,
    }
}

/// Ghidra `DatatypeCompare`: `compareDependency`, then the 64-bit id.
pub fn compare_identity(a: &TypeEntry, b: &TypeEntry) -> Ordering {
    match compare_dependency(a, b) {
        0 => a.id.cmp(&b.id),
        r if r < 0 => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// A hash of exactly what [`compare_identity`] compares, so that entries
/// equal under it hash alike.
pub(crate) fn identity_hash(e: &TypeEntry) -> u64 {
    let mut h = FxHasher::default();
    (e.submeta as u8).hash(&mut h);
    family(&e.kind).hash(&mut h);
    e.size.hash(&mut h);
    e.id.hash(&mut h);
    match &e.kind {
        TypeKind::Pointer(p) => {
            (p.ptrto, p.wordsize, p.space).hash(&mut h);
        }
        TypeKind::PointerRel {
            ptr,
            parent,
            offset,
            ..
        } => {
            (ptr.ptrto, ptr.wordsize, parent, offset).hash(&mut h);
        }
        TypeKind::Array { element, .. } => element.hash(&mut h),
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
        } => (c, offset).hash(&mut h),
        TypeKind::Enum(values) => values.values.hash(&mut h),
        TypeKind::Struct { fields, bitfields } => {
            for f in fields {
                (f.offset, &f.name, f.ty).hash(&mut h);
            }
            for b in bitfields {
                let r = &b.bits;
                (
                    r.byte_offset,
                    r.byte_size,
                    r.least_sig_bit,
                    r.num_bits,
                    &b.name,
                    b.ty,
                )
                    .hash(&mut h);
            }
        }
        TypeKind::Union { fields } => {
            for f in fields {
                (&f.name, f.ty).hash(&mut h);
            }
        }
        TypeKind::Code(sig) => {
            if let Some(sig) = sig {
                (&sig.model, sig.flags, sig.output).hash(&mut h);
                for (p, _) in &sig.params {
                    p.hash(&mut h);
                }
            }
        }
        TypeKind::Spacebase { space, scope } => (space, scope).hash(&mut h),
        TypeKind::Base | TypeKind::Char | TypeKind::Unicode | TypeKind::Void => {}
    }
    h.finish()
}
