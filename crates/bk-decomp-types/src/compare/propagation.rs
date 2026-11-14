//! The propagation order (Ghidra `compare` of every class, `typeOrder`,
//! `typeOrderFormal`, `TypeField::compare`, `TypeBitField::compare`).

use std::cmp::Ordering;

use crate::compare::identity::{cmp3, compare_basic, compare_dependency, family, sign, size_order};
use crate::entry::TypeKind;
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// The deepest `level` honoured; Ghidra always passes 10. Clamping keeps
/// the recursion bounded for any caller (ADR-009).
pub const MAX_LEVEL: i32 = 64;

impl TypeFactory {
    /// Ghidra `compare(op, level)` as a sign: negative when `a` is the more
    /// specific, preferred type.
    pub fn compare_raw(&self, a: TypeId, b: TypeId, level: i32) -> i32 {
        self.cmp_level(a, b, level.min(MAX_LEVEL))
    }

    /// Ghidra `compare(op, level)`: [`Ordering::Less`] when `a` is preferred.
    pub fn compare(&self, a: TypeId, b: TypeId, level: i32) -> Ordering {
        self.compare_raw(a, b, level).cmp(&0)
    }

    /// Ghidra `compareDependency` of two types.
    pub fn compare_dependency(&self, a: TypeId, b: TypeId) -> i32 {
        compare_dependency(self.entry(a), self.entry(b))
    }

    /// Ghidra `typeOrder`: `compare(b, 10)`, equal for the same type.
    pub fn type_order(&self, a: TypeId, b: TypeId) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        self.compare(a, b, 10)
    }

    /// Ghidra `typeOrderFormal`: partial unions last, `bool` after
    /// integers, otherwise `compare(b, 10)`.
    pub fn type_order_formal(&self, a: TypeId, b: TypeId) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        let (ma, mb) = (self.entry(a).metatype, self.entry(b).metatype);
        if ma == Metatype::PartialUnion {
            return Ordering::Greater;
        }
        if mb == Metatype::PartialUnion {
            return Ordering::Less;
        }
        if ma == Metatype::Bool {
            return Ordering::Greater;
        }
        if mb == Metatype::Bool {
            return Ordering::Less;
        }
        self.compare(a, b, 10)
    }

    fn base_compare(&self, a: TypeId, b: TypeId) -> i32 {
        let (x, y) = (self.entry(a), self.entry(b));
        if x.submeta != y.submeta {
            return cmp3(&x.submeta, &y.submeta);
        }
        size_order(x.size, y.size)
    }

    /// Ghidra's `id` tie-break when the recursion depth is used up.
    fn id_order(&self, a: TypeId, b: TypeId) -> i32 {
        cmp3(&self.entry(a).id, &self.entry(b).id)
    }

    fn cmp_level(&self, a: TypeId, b: TypeId, level: i32) -> i32 {
        let (x, y) = (self.entry(a), self.entry(b));
        // Enumerations and spacebases compare as in `compareDependency`.
        if matches!(x.kind, TypeKind::Enum(_) | TypeKind::Spacebase { .. }) {
            return compare_dependency(x, y);
        }
        let res = self.base_compare(a, b);
        if res != 0 {
            return res;
        }
        let (fx, fy) = (family(&x.kind), family(&y.kind));
        if fx != fy {
            // Ghidra would cast to the wrong class; order by family instead.
            if fx == 0 || fy == 0 {
                return 0;
            }
            return cmp3(&fx, &fy);
        }
        match (&x.kind, &y.kind) {
            (TypeKind::Pointer(p), TypeKind::Pointer(q)) => {
                self.pointer_tail(a, b, p.ptrto, q.ptrto, level, p, q)
            }
            (
                TypeKind::PointerRel {
                    ptr: p,
                    stripped: s1,
                    ..
                },
                TypeKind::PointerRel {
                    ptr: q,
                    stripped: s2,
                    ..
                },
            ) => {
                let res = self.pointer_tail(a, b, p.ptrto, q.ptrto, level, p, q);
                if res != 0 {
                    return res;
                }
                match (s1, s2) {
                    (None, Some(_)) => -1,
                    (Some(_), None) => 1,
                    _ => 0,
                }
            }
            (TypeKind::Array { element: e1, .. }, TypeKind::Array { element: e2, .. }) => {
                if level - 1 < 0 {
                    return self.id_order(a, b);
                }
                self.cmp_level(*e1, *e2, level - 1)
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
                if o1 != o2 {
                    return cmp3(o1, o2);
                }
                if level - 1 < 0 {
                    return self.id_order(a, b);
                }
                self.cmp_level(*c1, *c2, level - 1)
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
                    return sign(f2.len().cmp(&f1.len()));
                }
                for (u, v) in f1.iter().zip(f2) {
                    if u.offset != v.offset {
                        return cmp3(&u.offset, &v.offset);
                    }
                    if u.name != v.name {
                        return cmp3(&u.name, &v.name);
                    }
                    let (m1, m2) = (self.entry(u.ty).metatype, self.entry(v.ty).metatype);
                    if m1 != m2 {
                        return cmp3(&m1, &m2);
                    }
                }
                if b1.len() != b2.len() {
                    return sign(b2.len().cmp(&b1.len()));
                }
                for (u, v) in b1.iter().zip(b2) {
                    let r = sign(u.bits.compare(&v.bits));
                    if r != 0 {
                        return r;
                    }
                    if u.name != v.name {
                        return cmp3(&u.name, &v.name);
                    }
                    let (m1, m2) = (self.entry(u.ty).metatype, self.entry(v.ty).metatype);
                    if m1 != m2 {
                        return cmp3(&m1, &m2);
                    }
                }
                if level - 1 < 0 {
                    return self.id_order(a, b);
                }
                let pairs = f1.iter().map(|f| f.ty).zip(f2.iter().map(|f| f.ty));
                let bit_pairs = b1.iter().map(|f| f.ty).zip(b2.iter().map(|f| f.ty));
                for (t1, t2) in pairs.chain(bit_pairs) {
                    if t1 != t2 {
                        let c = self.cmp_level(t1, t2, level - 1);
                        if c != 0 {
                            return c;
                        }
                    }
                }
                0
            }
            (TypeKind::Union { fields: f1 }, TypeKind::Union { fields: f2 }) => {
                if f1.len() != f2.len() {
                    return sign(f2.len().cmp(&f1.len()));
                }
                for (u, v) in f1.iter().zip(f2) {
                    if u.name != v.name {
                        return cmp3(&u.name, &v.name);
                    }
                    let (m1, m2) = (self.entry(u.ty).metatype, self.entry(v.ty).metatype);
                    if m1 != m2 {
                        return cmp3(&m1, &m2);
                    }
                }
                if level - 1 < 0 {
                    return self.id_order(a, b);
                }
                for (u, v) in f1.iter().zip(f2) {
                    if u.ty != v.ty {
                        let c = self.cmp_level(u.ty, v.ty, level - 1);
                        if c != 0 {
                            return c;
                        }
                    }
                }
                0
            }
            (TypeKind::Code(s1), TypeKind::Code(s2)) => {
                let res = compare_basic(s1.as_deref(), s2.as_deref());
                if res != 2 {
                    return res;
                }
                if level - 1 < 0 {
                    return self.id_order(a, b);
                }
                let (Some(s1), Some(s2)) = (s1.as_deref(), s2.as_deref()) else {
                    return 0;
                };
                for ((p1, _), (p2, _)) in s1.params.iter().zip(&s2.params) {
                    let c = self.cmp_level(*p1, *p2, level - 1);
                    if c != 0 {
                        return c;
                    }
                }
                match (s1.output, s2.output) {
                    (None, None) => 0,
                    (None, Some(_)) => 1,
                    (Some(_), None) => -1,
                    (Some(o1), Some(o2)) => self.cmp_level(o1, o2, level - 1),
                }
            }
            _ => 0,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the two pointers' parts, as Ghidra's TypePointer::compare reads them"
    )]
    fn pointer_tail(
        &self,
        a: TypeId,
        b: TypeId,
        pa: TypeId,
        pb: TypeId,
        level: i32,
        p: &crate::entry::PointerData,
        q: &crate::entry::PointerData,
    ) -> i32 {
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
        if level - 1 < 0 {
            return self.id_order(a, b);
        }
        self.cmp_level(pa, pb, level - 1)
    }
}
