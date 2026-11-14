//! Flattening a data type into its primitive members (Ghidra
//! `PrimitiveExtractor`).

use crate::types::{Metatype, ParamTypes, TypeHandle};

/// Deepest nesting followed; Ghidra recurses without a limit (ADR-009).
const MAX_DEPTH: u32 = 64;

/// A primitive member and its offset within the containing type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Primitive {
    /// The primitive type.
    pub ty: TypeHandle,
    /// Its offset in bytes.
    pub offset: i32,
}

/// The primitives of a type and what was seen while collecting them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrimitiveExtractor {
    primitives: Vec<Primitive>,
    unknown_element: bool,
    unaligned: bool,
    extra_space: bool,
    invalid: bool,
    union_invalid: bool,
    array_primitive: bool,
}

impl PrimitiveExtractor {
    /// Extracts at most `max` primitives of `ty` starting at `offset`.
    /// `union_illegal` makes any union invalid; `array_primitive` keeps
    /// nested arrays whole (Ghidra's constructor).
    pub fn new(
        types: &dyn ParamTypes,
        ty: TypeHandle,
        flags: (bool, bool),
        offset: i32,
        max: usize,
    ) -> Self {
        let (union_illegal, array_primitive) = flags;
        let mut res = Self {
            union_invalid: union_illegal,
            array_primitive,
            ..Self::default()
        };
        if !res.extract(types, ty, max, offset, 0) {
            res.invalid = true;
        }
        res
    }

    /// Number of primitives.
    pub fn len(&self) -> usize {
        self.primitives.len()
    }
    /// Whether no primitive was extracted.
    pub fn is_empty(&self) -> bool {
        self.primitives.is_empty()
    }
    /// The `i`-th primitive.
    pub fn get(&self, i: usize) -> Option<Primitive> {
        self.primitives.get(i).copied()
    }
    /// All primitives in offset order.
    pub fn primitives(&self) -> &[Primitive] {
        &self.primitives
    }
    /// Whether extraction succeeded (Ghidra `isValid`).
    pub const fn is_valid(&self) -> bool {
        !self.invalid
    }
    /// Whether an unknown primitive was seen (Ghidra `containsUnknown`).
    pub const fn contains_unknown(&self) -> bool {
        self.unknown_element
    }
    /// Whether every primitive is aligned (Ghidra `isAligned`).
    pub const fn is_aligned(&self) -> bool {
        !self.unaligned
    }
    /// Whether there is space that is not padding (Ghidra
    /// `containsHoles`).
    pub const fn contains_holes(&self) -> bool {
        self.extra_space
    }

    fn push(&mut self, ty: TypeHandle, offset: i32, max: usize) -> bool {
        if self.primitives.len() >= max {
            return false;
        }
        self.primitives.push(Primitive { ty, offset });
        true
    }

    fn extract(
        &mut self,
        types: &dyn ParamTypes,
        ty: TypeHandle,
        max: usize,
        mut offset: i32,
        depth: u32,
    ) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        match types.metatype(ty) {
            Metatype::Unknown => {
                self.unknown_element = true;
                self.push(ty, offset, max)
            }
            Metatype::Int
            | Metatype::Uint
            | Metatype::Bool
            | Metatype::Code
            | Metatype::Float
            | Metatype::Ptr
            | Metatype::PtrRel => self.push(ty, offset, max),
            Metatype::Array => {
                if self.array_primitive && depth != 0 {
                    return self.push(ty, offset, max);
                }
                let Some((base, count)) = types.array_element(ty) else {
                    return false;
                };
                let step = types.align_size(base);
                for _ in 0..count.max(0) {
                    if !self.extract(types, base, max, offset, depth + 1) {
                        return false;
                    }
                    offset = offset.wrapping_add(step);
                }
                true
            }
            Metatype::Union => self.handle_union(types, ty, max, offset, depth),
            Metatype::Struct => self.handle_struct(types, ty, max, offset, depth),
            _ => false,
        }
    }

    fn handle_struct(
        &mut self,
        types: &dyn ParamTypes,
        ty: TypeHandle,
        max: usize,
        offset: i32,
        depth: u32,
    ) -> bool {
        let mut expected = offset;
        for i in 0..types.field_count(ty) {
            let Some(field) = types.field(ty, i) else {
                return false;
            };
            let cur = field.offset.wrapping_add(offset);
            let align = types.alignment(field.ty).max(1);
            if cur.wrapping_rem(align) != 0 {
                self.unaligned = true;
            }
            let rem = expected.wrapping_rem(align);
            if rem != 0 {
                expected = expected.wrapping_add(align - rem);
            }
            if expected != cur {
                self.extra_space = true;
            }
            if !self.extract(types, field.ty, max, cur, depth + 1) {
                return false;
            }
            expected = cur.wrapping_add(types.align_size(field.ty));
        }
        true
    }

    /// Adds the common refinement of the union's fields (Ghidra
    /// `handleUnion`).
    fn handle_union(
        &mut self,
        types: &dyn ParamTypes,
        ty: TypeHandle,
        max: usize,
        offset: i32,
        depth: u32,
    ) -> bool {
        if self.union_invalid {
            return false;
        }
        let num = types.field_count(ty);
        let Some(first) = types.field(ty, 0) else {
            return false;
        };
        if num == 0 {
            return false;
        }
        let sub = |field: crate::types::TypeField| {
            let mut e = Self {
                array_primitive: self.array_primitive,
                ..Self::default()
            };
            if !e.extract(
                types,
                field.ty,
                max,
                offset.wrapping_add(field.offset),
                depth + 1,
            ) {
                e.invalid = true;
            }
            e
        };
        let mut common = sub(first);
        if common.invalid {
            return false;
        }
        for i in 1..num {
            let Some(field) = types.field(ty, i) else {
                return false;
            };
            let next = sub(field);
            if next.invalid {
                return false;
            }
            match common_refinement(types, &common.primitives, &next.primitives) {
                Some(refined) => common.primitives = refined,
                None => return false,
            }
        }
        if self.primitives.len() + common.primitives.len() > max {
            return false;
        }
        self.primitives.extend_from_slice(&common.primitives);
        true
    }
}

/// Checks that `big` properly overlaps `small[point..]`, adding to `res`
/// the overlapped primitives when `big` is floating point and `big` itself
/// otherwise; the index after the overlap (Ghidra `checkOverlap`).
fn check_overlap(
    types: &dyn ParamTypes,
    res: &mut Vec<Primitive>,
    small: &[Primitive],
    mut point: usize,
    big: Primitive,
) -> Option<usize> {
    let end = big.offset.wrapping_add(types.align_size(big.ty));
    let use_small = types.metatype(big.ty) == Metatype::Float;
    while let Some(s) = small.get(point) {
        if s.offset >= end {
            break;
        }
        if s.offset.wrapping_add(types.align_size(s.ty)) > end {
            return None;
        }
        if use_small {
            res.push(*s);
        }
        point += 1;
    }
    if !use_small {
        res.push(big);
    }
    Some(point)
}

/// The common refinement of two primitive lists, or `None` on a partial
/// overlap (Ghidra `commonRefinement`).
fn common_refinement(
    types: &dyn ParamTypes,
    first: &[Primitive],
    second: &[Primitive],
) -> Option<Vec<Primitive>> {
    let (mut i, mut j) = (0, 0);
    let mut common = Vec::new();
    while let (Some(&a), Some(&b)) = (first.get(i), second.get(j)) {
        if a.offset < b.offset && a.offset.wrapping_add(types.align_size(a.ty)) <= b.offset {
            common.push(a);
            i += 1;
            continue;
        }
        if b.offset < a.offset && b.offset.wrapping_add(types.align_size(b.ty)) <= a.offset {
            common.push(b);
            j += 1;
            continue;
        }
        if types.align_size(a.ty) >= types.align_size(b.ty) {
            j = check_overlap(types, &mut common, second, j, a)?;
            i += 1;
        } else {
            i = check_overlap(types, &mut common, first, i, b)?;
            j += 1;
        }
    }
    common.extend_from_slice(first.get(i..).unwrap_or(&[]));
    common.extend_from_slice(second.get(j..).unwrap_or(&[]));
    Some(common)
}
