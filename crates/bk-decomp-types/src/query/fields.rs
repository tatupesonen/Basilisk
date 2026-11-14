//! Structure fields and bitfields (Ghidra `TypeStruct::getFieldIter`,
//! `getLowerBoundField`, `findTruncation`, `collectBitFields`,
//! `hasBitFieldsInRange`, `findMatchingBitField`, `BitFieldTriple`).

use bk_core::{BitOverlap, BitRange};

use crate::entry::{BitField, Field, TypeKind};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// A bitfield with its immediate container and that container's offset in
/// the root structure (Ghidra `BitFieldTriple`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitFieldTriple {
    /// The structure holding the bitfield.
    pub container: TypeId,
    /// The bitfield.
    pub bitfield: BitField,
    /// Byte offset of the container in the root structure.
    pub offset: i32,
}

impl BitFieldTriple {
    /// Ghidra `BitFieldTriple::compare`: least significant first.
    pub fn less(a: &Self, b: &Self) -> bool {
        let big = a.bitfield.bits.is_big_endian;
        let o1 = a.offset.saturating_add(a.bitfield.bits.byte_offset);
        let o2 = b.offset.saturating_add(b.bitfield.bits.byte_offset);
        if o1 != o2 {
            return if big { o1 > o2 } else { o1 < o2 };
        }
        a.bitfield.bits.least_sig_bit < b.bitfield.bits.least_sig_bit
    }
}

impl TypeFactory {
    /// Ghidra `getFieldIter`: the field containing `off`.
    pub(crate) fn field_iter<'f>(&self, fields: &'f [Field], off: i64) -> Option<&'f Field> {
        let (mut lo, mut hi) = (0i64, fields.len() as i64 - 1);
        while lo <= hi {
            let mid = i64::midpoint(lo, hi);
            let f = fields.get(mid as usize)?;
            if i64::from(f.offset) > off {
                hi = mid - 1;
            } else {
                if i64::from(f.offset) + i64::from(self.entry(f.ty).size) > off {
                    return Some(f);
                }
                lo = mid + 1;
            }
        }
        None
    }

    /// Ghidra `getLowerBoundField`: the last field starting at or before
    /// `off`.
    pub(crate) fn lower_bound_field(fields: &[Field], off: i64) -> Option<usize> {
        if fields.is_empty() {
            return None;
        }
        let (mut lo, mut hi) = (0usize, fields.len() - 1);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if fields.get(mid).is_some_and(|f| i64::from(f.offset) > off) {
                hi = mid - 1;
            } else {
                lo = mid;
            }
        }
        fields
            .get(lo)
            .filter(|f| i64::from(f.offset) <= off)
            .map(|_| lo)
    }

    /// The pure part of Ghidra `TypeStruct::findTruncation`: the field of a
    /// structure containing `off..off+sz`, and the offset into it. For a
    /// union the field depends on the op and is resolved with the IR.
    pub fn struct_truncation(&self, id: TypeId, off: i64, sz: i32) -> Option<(usize, i64)> {
        let TypeKind::Struct { fields, .. } = &self.entry(id).kind else {
            return None;
        };
        let f = self.field_iter(fields, off)?;
        let index = fields.iter().position(|x| std::ptr::eq(x, f))?;
        let noff = off - i64::from(f.offset);
        if noff + i64::from(sz) > i64::from(self.entry(f.ty).size) {
            return None;
        }
        Some((index, noff))
    }

    /// The field of a union at an index (Ghidra `TypeUnion::getField`).
    pub fn union_field(&self, id: TypeId, index: usize) -> Option<&Field> {
        match &self.entry(id).kind {
            TypeKind::Union { fields } => fields.get(index),
            _ => None,
        }
    }

    /// Ghidra `findMatchingBitField`: the bitfield with exactly this range.
    pub fn find_matching_bitfield(&self, id: TypeId, range: &BitRange) -> Option<&BitField> {
        let bits = self.entry(id).bitfields();
        let (mut lo, mut hi) = (0i64, bits.len() as i64 - 1);
        while lo <= hi {
            let mid = i64::midpoint(lo, hi);
            let b = bits.get(mid as usize)?;
            match range.overlap_test(&b.bits) {
                BitOverlap::Equal => return Some(b),
                BitOverlap::Before => hi = mid - 1,
                BitOverlap::After => lo = mid + 1,
                _ => break,
            }
        }
        None
    }

    /// Ghidra `collectBitFields`: bitfields overlapping
    /// `offset..offset+sz`, nested structures included (not in order).
    pub fn collect_bitfields(
        &self,
        id: TypeId,
        base_offset: i32,
        offset: i32,
        sz: i32,
    ) -> Vec<BitFieldTriple> {
        let mut out = Vec::new();
        self.collect_into(id, base_offset, offset, sz, &mut out, 0);
        out
    }

    fn collect_into(
        &self,
        id: TypeId,
        base: i32,
        offset: i32,
        sz: i32,
        out: &mut Vec<BitFieldTriple>,
        depth: usize,
    ) {
        if depth > crate::MAX_DEPTH {
            return;
        }
        let e = self.entry(id);
        let TypeKind::Struct { fields, bitfields } = &e.kind else {
            return;
        };
        for b in bitfields_overlapping(bitfields, offset, sz) {
            out.push(BitFieldTriple {
                container: id,
                bitfield: b.clone(),
                offset: base,
            });
        }
        for f in fields_from(self, fields, offset) {
            if f.offset >= offset.saturating_add(sz) {
                break;
            }
            let ft = self.entry(f.ty);
            if ft.metatype != Metatype::Struct || !ft.has_bitfields() {
                continue;
            }
            self.collect_into(
                f.ty,
                base.saturating_add(f.offset),
                offset - f.offset,
                sz,
                out,
                depth + 1,
            );
        }
    }

    /// Ghidra `hasBitFieldsInRange`.
    pub fn has_bitfields_in_range(&self, id: TypeId, offset: i32, sz: i32) -> bool {
        !self.collect_bitfields(id, 0, offset, sz).is_empty()
    }
}

/// The bitfields from the first whose byte container ends after `offset`,
/// that overlap the byte range.
fn bitfields_overlapping(bits: &[BitField], offset: i32, sz: i32) -> Vec<&BitField> {
    let start =
        bits.partition_point(|b| offset >= b.bits.byte_offset.saturating_add(b.bits.byte_size));
    let mut out = Vec::new();
    let Some(first) = bits.get(start) else {
        return out;
    };
    let range = BitRange::bytes(offset, sz, first.bits.is_big_endian);
    for b in bits.iter().skip(start) {
        match b.bits.overlap_test(&range) {
            BitOverlap::After => break,
            BitOverlap::Before => {}
            _ => out.push(b),
        }
    }
    out
}

/// Fields from the first whose end lies after `offset`.
fn fields_from<'f>(f: &TypeFactory, fields: &'f [Field], offset: i32) -> &'f [Field] {
    let start = fields.partition_point(|x| {
        i64::from(offset) >= i64::from(x.offset) + i64::from(f.entry(x.ty).size)
    });
    fields.get(start..).unwrap_or_default()
}
