//! Structures and unions (Ghidra `getTypeStruct`, `getTypeUnion`,
//! `setFields`, `assignRawFields`, `TypeStruct::assignFieldOffsets`,
//! `assignContiguousBitfields`, `TypeUnion::assignFieldOffsets`).

use crate::entry::{BitField, Field, TypeEntry, TypeFlags, TypeKind, calc_align_size, hash_name};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};

/// The layout computed for a structure or union.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Total size.
    pub size: i32,
    /// Alignment.
    pub align: i32,
    /// Flags to set on the type.
    pub flags: TypeFlags,
}

impl TypeFactory {
    /// Ghidra `getTypeStruct`: an incomplete structure stub.
    pub fn structure_stub(&mut self, name: &str) -> Result<TypeId> {
        let mut tmp = TypeEntry::new(
            0,
            -1,
            Metatype::Struct,
            TypeKind::Struct {
                fields: Vec::new(),
                bitfields: Vec::new(),
            },
        );
        tmp.flags |= TypeFlags::TYPE_INCOMPLETE;
        tmp.set_name(name, hash_name(name));
        self.find_add(tmp)
    }

    /// Ghidra `getTypeUnion`: an incomplete union stub.
    pub fn union_stub(&mut self, name: &str) -> Result<TypeId> {
        let mut tmp = TypeEntry::new(
            0,
            -1,
            Metatype::Union,
            TypeKind::Union { fields: Vec::new() },
        );
        tmp.flags |= TypeFlags::TYPE_INCOMPLETE | TypeFlags::NEEDS_RESOLUTION;
        tmp.set_name(name, hash_name(name));
        self.find_add(tmp)
    }

    /// Ghidra `TypeFactory::setFields` for a structure: completes a stub.
    pub fn set_struct_fields(
        &mut self,
        id: TypeId,
        fields: Vec<Field>,
        bitfields: Vec<BitField>,
        layout: Layout,
    ) -> Result<()> {
        let e = self.entry_checked(id)?;
        if !e.is_incomplete() || !matches!(e.kind, TypeKind::Struct { .. }) {
            return Err(TypeError::new(
                "Can only set fields on an incomplete structure",
            ));
        }
        let single_fills = match fields.as_slice() {
            [only] => self.entry(only.ty).size == layout.size,
            _ => false,
        };
        self.modify(id, |e| {
            e.kind = TypeKind::Struct { fields, bitfields };
            e.size = layout.size;
            e.alignment = layout.align;
            if single_fills {
                e.flags |= TypeFlags::NEEDS_RESOLUTION;
            }
            e.align_size = calc_align_size(e.size, e.alignment);
            e.flags.remove(TypeFlags::TYPE_INCOMPLETE);
            e.flags |= layout.flags
                & (TypeFlags::OPAQUE_STRING
                    | TypeFlags::VARIABLE_LENGTH
                    | TypeFlags::TYPE_INCOMPLETE
                    | TypeFlags::HAS_BITFIELDS);
        })?;
        self.recalc_pointer_submeta(id, SubMetatype::Ptr)?;
        self.recalc_pointer_submeta(id, SubMetatype::PtrStruct)
    }

    /// Ghidra `TypeFactory::setFields` for a union: completes a stub.
    pub fn set_union_fields(
        &mut self,
        id: TypeId,
        fields: Vec<Field>,
        layout: Layout,
    ) -> Result<()> {
        let e = self.entry_checked(id)?;
        if !e.is_incomplete() || !matches!(e.kind, TypeKind::Union { .. }) {
            return Err(TypeError::new("Can only set fields on an incomplete union"));
        }
        self.modify(id, |e| {
            e.kind = TypeKind::Union { fields };
            e.size = layout.size;
            e.alignment = layout.align;
            e.align_size = calc_align_size(e.size, e.alignment);
            e.flags.remove(TypeFlags::TYPE_INCOMPLETE);
            e.flags |= layout.flags & (TypeFlags::VARIABLE_LENGTH | TypeFlags::TYPE_INCOMPLETE);
        })
    }

    /// Ghidra `assignRawFields` for a structure: lays out fields and
    /// bitfields that have no offsets yet, then completes the stub.
    pub fn assign_raw_struct_fields(
        &mut self,
        id: TypeId,
        mut fields: Vec<Field>,
        mut bitfields: Vec<BitField>,
    ) -> Result<()> {
        let name = self.entry_checked(id)?.name.to_string();
        let layout = self.assign_struct_offsets(&mut fields, &mut bitfields, &name)?;
        self.set_struct_fields(id, fields, bitfields, layout)
    }

    /// Ghidra `assignRawFields` for a union.
    pub fn assign_raw_union_fields(&mut self, id: TypeId, mut fields: Vec<Field>) -> Result<()> {
        let name = self.entry_checked(id)?.name.to_string();
        let layout = self.assign_union_offsets(&mut fields, &name)?;
        self.set_union_fields(id, fields, layout)
    }

    /// Ghidra `TypeStruct::assignFieldOffsets`.
    pub fn assign_struct_offsets(
        &self,
        list: &mut [Field],
        bitlist: &mut [BitField],
        name: &str,
    ) -> Result<Layout> {
        let mut cur_bit = 0usize;
        let mut next_bit_pos = bitlist.first().map_or(-1, |b| b.ident);
        let mut offset: i32 = 0;
        let mut align = 1;
        let mut flags = TypeFlags::empty();
        for pos in 0..list.len() {
            if pos as i64 == i64::from(next_bit_pos) {
                assign_contiguous_bitfields(self, bitlist, &mut cur_bit, &mut offset, &mut align);
                next_bit_pos = bitlist.get(cur_bit).map_or(next_bit_pos, |b| b.ident);
            }
            let Some(field) = list.get_mut(pos) else {
                break;
            };
            let ft = self.entry(field.ty);
            if ft.metatype == Metatype::Void {
                return Err(TypeError::new(format!(
                    "Illegal field void in structure: {name}"
                )));
            }
            if field.offset != -1 {
                continue;
            }
            let cursize = ft.align_size;
            let mut a = ft.alignment;
            if a > align {
                align = a;
            }
            a -= 1;
            if a > 0 && (offset & a) != 0 {
                offset = (offset - (offset & a)).saturating_add(a + 1);
            }
            field.offset = offset;
            field.ident = offset;
            offset = offset
                .checked_add(cursize)
                .ok_or_else(|| TypeError::new(format!("Structure too large: {name}")))?;
            if ft.has_bitfields() {
                flags |= TypeFlags::HAS_BITFIELDS;
            }
        }
        if list.len() as i64 == i64::from(next_bit_pos) {
            assign_contiguous_bitfields(self, bitlist, &mut cur_bit, &mut offset, &mut align);
        }
        if !bitlist.is_empty() && cur_bit != bitlist.len() {
            return Err(TypeError::new(format!(
                "Malformed bitfield description in structure: {name}"
            )));
        }
        if !bitlist.is_empty() {
            flags |= TypeFlags::HAS_BITFIELDS;
        }
        Ok(Layout {
            size: calc_align_size(offset, align),
            align,
            flags,
        })
    }

    /// Ghidra `TypeUnion::assignFieldOffsets`.
    pub fn assign_union_offsets(&self, list: &mut [Field], name: &str) -> Result<Layout> {
        let (mut size, mut align) = (0, 1);
        for field in list.iter_mut() {
            let ct = self.entry(field.ty);
            if ct.metatype == Metatype::Void {
                return Err(TypeError::new(format!(
                    "Bad field data-type for union: {name}"
                )));
            }
            if field.name.is_empty() {
                return Err(TypeError::new(format!("Bad field name for union: {name}")));
            }
            field.offset = 0;
            size = size.max(ct.size);
            align = align.max(ct.alignment);
        }
        Ok(Layout {
            size,
            align,
            flags: TypeFlags::empty(),
        })
    }
}

/// Ghidra `assignContiguousBitfields`: places the run of bitfields sharing
/// the `ident` at `pos`.
fn assign_contiguous_bitfields(
    f: &TypeFactory,
    bitlist: &mut [BitField],
    pos: &mut usize,
    offset: &mut i32,
    new_align: &mut i32,
) {
    let start = *pos;
    let Some(first) = bitlist.get(start) else {
        return;
    };
    let group = first.ident;
    let mut total: i32 = 0;
    while let Some(b) = bitlist.get(*pos) {
        if b.ident != group {
            break;
        }
        total = total.saturating_add(b.bits.num_bits);
        *pos += 1;
    }
    let mut align = f.entry(first.ty).alignment;
    let big = first.bits.is_big_endian;
    if align > *new_align {
        *new_align = align;
    }
    align -= 1;
    if align > 0 && (*offset & align) != 0 {
        *offset = (*offset - (*offset & align)).saturating_add(align + 1);
    }
    let total_bytes = total.saturating_add(7) / 8;
    let mut lsb = 0;
    for i in start..*pos {
        if let Some(b) = bitlist.get_mut(i) {
            b.bits.byte_offset = *offset;
            b.bits.byte_size = total_bytes;
            b.bits.least_sig_bit = lsb;
            lsb = lsb.saturating_add(b.bits.num_bits);
            b.ident = i as i32;
        }
    }
    *offset = offset.saturating_add(total_bytes);
    if big && *pos - start > 1 {
        if let Some(run) = bitlist.get_mut(start..*pos) {
            run.reverse();
        }
    }
}
