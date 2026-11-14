//! Decoding structures and unions (Ghidra `decodeStruct`, `decodeUnion`,
//! `TypeStruct::decodeFields`, `decodeField`, `decodeBitField`,
//! `TypeUnion::decodeFields`, the `TypeField` and `TypeBitField` decoding
//! constructors).

use bk_core::BitRange;
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE};

use crate::entry::{BitField, Field, TypeEntry, TypeFlags, TypeKind, calc_align_size};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::composite::Layout;
use crate::ids::TypeId;
use crate::meta::Metatype;
use crate::xml::decode::decode_basic;
use crate::xml::ids::{ATTRIB_FIRST, ELEM_BITFIELD, ELEM_FIELD};

/// Accumulated state while decoding structure fields (Ghidra `FieldAccum`).
struct FieldAccum {
    last_off: i32,
    calc_size: i32,
    calc_align: i32,
    warning: String,
    has_bitfields: bool,
}

impl TypeFactory {
    /// Ghidra `decodeStruct`.
    pub(super) fn decode_struct(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        forcecore: bool,
    ) -> Result<TypeId> {
        let mut ts = TypeEntry::new(
            0,
            -1,
            Metatype::Struct,
            TypeKind::Struct {
                fields: Vec::new(),
                bitfields: Vec::new(),
            },
        );
        ts.flags |= TypeFlags::TYPE_INCOMPLETE;
        decode_basic(&mut ts, dec)?;
        if forcecore {
            ts.flags |= TypeFlags::CORETYPE;
        }
        let ct = match self.find_by_id_local(&ts.name, ts.id) {
            None => self.find_add(ts.clone())?,
            Some(ct) if self.entry(ct).metatype != Metatype::Struct => {
                return Err(TypeError::new(format!(
                    "Trying to redefine type: {}",
                    ts.name
                )));
            }
            Some(ct) => ct,
        };
        let warning = self.decode_struct_fields(&mut ts, dec)?;
        if self.entry(ct).is_incomplete() {
            let layout = Layout {
                size: ts.size,
                align: ts.alignment,
                flags: ts.flags,
            };
            let TypeKind::Struct { fields, bitfields } = ts.kind else {
                return Err(TypeError::new("Bad structure"));
            };
            self.set_struct_fields(ct, fields, bitfields, layout)?;
        } else if crate::compare::identity::compare_dependency(self.entry(ct), &ts) != 0 {
            return Err(TypeError::new(format!(
                "Redefinition of structure: {}",
                ts.name
            )));
        }
        if !warning.is_empty() {
            self.insert_warning(ct, warning)?;
        }
        self.resolve_incomplete_typedefs()?;
        Ok(ct)
    }

    /// Ghidra `TypeStruct::decodeFields`.
    fn decode_struct_fields(
        &mut self,
        ts: &mut TypeEntry,
        dec: &mut dyn Decoder<'_>,
    ) -> Result<String> {
        let mut acc = FieldAccum {
            last_off: -1,
            calc_size: 0,
            calc_align: 1,
            warning: String::new(),
            has_bitfields: false,
        };
        let mut fields: Vec<Field> = Vec::new();
        let mut bits: Vec<BitField> = Vec::new();
        while let Some(el) = dec.peek_element() {
            if el == ELEM_FIELD {
                self.decode_field(ts, dec, &mut acc, &mut fields)?;
            } else if el == ELEM_BITFIELD {
                self.decode_bitfield(ts, dec, &mut acc, &mut fields, &mut bits)?;
            } else {
                return Err(TypeError::new("Expecting <field> or <bitfield>"));
            }
        }
        if ts.size == 0 {
            ts.flags |= TypeFlags::TYPE_INCOMPLETE;
        }
        if !fields.is_empty() || !bits.is_empty() {
            ts.flags.remove(TypeFlags::TYPE_INCOMPLETE);
        }
        if !bits.is_empty() || acc.has_bitfields {
            ts.flags |= TypeFlags::HAS_BITFIELDS;
        }
        if let [only] = fields.as_slice()
            && self.entry(only.ty).size == ts.size
        {
            ts.flags |= TypeFlags::NEEDS_RESOLUTION;
        }
        if ts.alignment < 1 {
            ts.alignment = acc.calc_align;
        }
        ts.align_size = calc_align_size(ts.size, ts.alignment);
        ts.kind = TypeKind::Struct {
            fields,
            bitfields: bits,
        };
        Ok(acc.warning)
    }

    /// Ghidra's `TypeField(decoder, typegrp)` constructor.
    fn read_field(&mut self, dec: &mut dyn Decoder<'_>) -> Result<Field> {
        let elem = dec.open_element_expecting(ELEM_FIELD)?;
        let (mut ident, mut offset, mut name) = (-1i64, -1i64, String::new());
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_NAME {
                dec.read_string()?.clone_into(&mut name);
            } else if attr == ATTRIB_OFFSET {
                offset = dec.read_signed()?;
            } else if attr == ATTRIB_ID {
                ident = dec.read_signed()?;
            }
        }
        let ty = self.decode_type(dec)?;
        if name.is_empty() {
            return Err(TypeError::new(
                "name attribute must not be empty in <field> tag",
            ));
        }
        if !(0..=i64::from(i32::MAX)).contains(&offset) {
            return Err(TypeError::new("offset attribute invalid for <field> tag"));
        }
        if ident < 0 {
            ident = offset;
        }
        dec.close_element(elem)?;
        Ok(Field {
            ident: ident as i32,
            offset: offset as i32,
            name: name.into(),
            ty,
        })
    }

    fn decode_field(
        &mut self,
        ts: &TypeEntry,
        dec: &mut dyn Decoder<'_>,
        acc: &mut FieldAccum,
        fields: &mut Vec<Field>,
    ) -> Result<()> {
        let f = self.read_field(dec)?;
        let ft = self.entry(f.ty);
        if ft.metatype == Metatype::Void {
            return Err(TypeError::new(format!(
                "Bad field data-type for structure: {}",
                ts.name
            )));
        }
        if f.offset < acc.last_off {
            return Err(TypeError::new("Fields are out of order"));
        }
        if f.offset < acc.calc_size {
            acc.warning = if acc.warning.is_empty() {
                format!(
                    "Struct \"{}\": ignoring overlapping field \"{}\"",
                    ts.name, f.name
                )
            } else {
                format!(
                    "Struct \"{}\": ignoring multiple overlapping fields",
                    ts.name
                )
            };
            return Ok(());
        }
        let (fsize, falign, fbits) = (ft.size, ft.alignment, ft.has_bitfields());
        acc.last_off = f.offset;
        acc.calc_size = f.offset.saturating_add(fsize);
        if acc.calc_size > ts.size {
            return Err(TypeError::new(format!(
                "Field {} does not fit in structure {}",
                f.name, ts.name
            )));
        }
        if fbits {
            acc.has_bitfields = true;
        }
        acc.calc_align = acc.calc_align.max(falign);
        fields.push(f);
        Ok(())
    }

    fn decode_bitfield(
        &mut self,
        ts: &TypeEntry,
        dec: &mut dyn Decoder<'_>,
        acc: &mut FieldAccum,
        fields: &mut Vec<Field>,
        bits: &mut Vec<BitField>,
    ) -> Result<()> {
        let elem = dec.open_element_expecting(ELEM_BITFIELD)?;
        let mut ident: i64 = -1;
        let mut name = String::new();
        let (mut byte_offset, mut num_bits, mut lsb) = (-1i64, -1i64, -1i64);
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_NAME {
                dec.read_string()?.clone_into(&mut name);
            } else if attr == ATTRIB_ID {
                ident = dec.read_signed()?;
            } else if attr == ATTRIB_OFFSET {
                byte_offset = dec.read_signed()?;
            } else if attr == ATTRIB_SIZE {
                num_bits = dec.read_signed()?;
            } else if attr == ATTRIB_FIRST {
                lsb = dec.read_signed()?;
            }
        }
        let ty = self.decode_type(dec)?;
        if name.is_empty() {
            return Err(TypeError::new(
                "<bitfield> name attribute must not be empty",
            ));
        }
        if ident < 0 {
            return Err(TypeError::new("<bitfield> id attribute must not be empty"));
        }
        let limit = i64::from(i32::MAX / 2);
        if !(0..limit).contains(&byte_offset)
            || !(0..limit).contains(&lsb)
            || !(0..limit).contains(&num_bits)
        {
            return Err(TypeError::new(
                "<bitfield> missing offset/size/first attributes",
            ));
        }
        dec.close_element(elem)?;
        let big = self.env.data_space.big_endian;
        let (bo, nb, lb) = (byte_offset as i32, num_bits as i32, lsb as i32);
        let mut bf = BitField {
            name: name.into(),
            ty,
            bits: BitRange::new(bo, (lb + nb + 7) / 8, lb, nb, big),
            ident: ident as i32,
        };
        let meta = self.entry(ty).metatype;
        if !matches!(
            meta,
            Metatype::Int
                | Metatype::Uint
                | Metatype::Bool
                | Metatype::EnumInt
                | Metatype::EnumUint
        ) {
            return Err(TypeError::new(format!(
                "Non integer data-type for bitfield \"{}\" in structure: {}",
                bf.name, ts.name
            )));
        }
        if bf.bits.byte_offset < acc.last_off {
            return Err(TypeError::new(format!(
                "Bitfields are out of order in structure: {}",
                ts.name
            )));
        }
        if bf.bits.byte_offset < acc.calc_size {
            let prev_before = bits
                .last()
                .is_some_and(|p| p.bits.overlap_test(&bf.bits) == bk_core::BitOverlap::Before);
            if !prev_before {
                acc.warning = if acc.warning.is_empty() {
                    format!(
                        "Struct \"{}\": ignoring overlapping bit field \"{}\"",
                        ts.name, bf.name
                    )
                } else {
                    format!(
                        "Struct \"{}\": ignoring multiple overlapping fields",
                        ts.name
                    )
                };
                return Ok(());
            }
        }
        acc.last_off = bf.bits.byte_offset;
        acc.calc_size = bf.bits.byte_offset.saturating_add(bf.bits.byte_size);
        if acc.calc_size > ts.size {
            return Err(TypeError::new(format!(
                "Bitfield {} does not fit in structure {}",
                bf.name, ts.name
            )));
        }
        if bf.bits.is_byte_range() {
            bf.bits.minimize_container();
            let mut dt = ty;
            if self.entry(dt).size != bf.bits.byte_size {
                let m = match meta {
                    Metatype::Int | Metatype::Uint => meta,
                    _ => Metatype::Unknown,
                };
                dt = self.base(bf.bits.byte_size, m)?;
            }
            fields.push(Field {
                ident: bf.bits.byte_offset,
                offset: bf.bits.byte_offset,
                name: bf.name,
                ty: dt,
            });
            return Ok(());
        }
        bits.push(bf);
        Ok(())
    }

    /// Ghidra `decodeUnion` with `TypeUnion::decodeFields`.
    pub(super) fn decode_union(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        forcecore: bool,
    ) -> Result<TypeId> {
        let mut tu = TypeEntry::new(
            0,
            -1,
            Metatype::Union,
            TypeKind::Union { fields: Vec::new() },
        );
        tu.flags |= TypeFlags::TYPE_INCOMPLETE | TypeFlags::NEEDS_RESOLUTION;
        decode_basic(&mut tu, dec)?;
        if forcecore {
            tu.flags |= TypeFlags::CORETYPE;
        }
        let ct = match self.find_by_id_local(&tu.name, tu.id) {
            None => self.find_add(tu.clone())?,
            Some(ct) if self.entry(ct).metatype != Metatype::Union => {
                return Err(TypeError::new(format!(
                    "Trying to redefine type: {}",
                    tu.name
                )));
            }
            Some(ct) => ct,
        };
        let mut calc_align = 1;
        let mut fields = Vec::new();
        while dec.peek_element().is_some() {
            let f = self.read_field(dec)?;
            let ft = self.entry(f.ty);
            if i64::from(f.offset) + i64::from(ft.size) > i64::from(tu.size) {
                return Err(TypeError::new(format!(
                    "Field {} does not fit in union {}",
                    f.name, tu.name
                )));
            }
            calc_align = calc_align.max(ft.alignment);
            fields.push(f);
        }
        if tu.size == 0 {
            tu.flags |= TypeFlags::TYPE_INCOMPLETE;
        }
        if !fields.is_empty() {
            tu.flags.remove(TypeFlags::TYPE_INCOMPLETE);
        }
        if tu.alignment < 1 {
            tu.alignment = calc_align;
        }
        tu.align_size = calc_align_size(tu.size, tu.alignment);
        tu.kind = TypeKind::Union { fields };
        if self.entry(ct).is_incomplete() {
            let layout = Layout {
                size: tu.size,
                align: tu.alignment,
                flags: tu.flags,
            };
            let TypeKind::Union { fields } = tu.kind else {
                return Err(TypeError::new("Bad union"));
            };
            self.set_union_fields(ct, fields, layout)?;
        } else if crate::compare::identity::compare_dependency(self.entry(ct), &tu) != 0 {
            return Err(TypeError::new(format!(
                "Redefinition of union: {}",
                tu.name
            )));
        }
        self.resolve_incomplete_typedefs()?;
        Ok(ct)
    }
}
