//! Encoding types and the factory (Ghidra `Datatype::encode` and the
//! subclasses', `encodeBasic`, `encodeRef`, `encodeTypedef`,
//! `TypeField::encode`, `TypeBitField::encode`, `TypeFactory::encode`,
//! `encodeCoreTypes`).

use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_FORMAT, ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_NAME, ATTRIB_OFFSET,
    ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_VALUE, ATTRIB_WORDSIZE, ELEM_OFF, ELEM_VAL, ELEM_VOID,
};
use bk_marshal::{Encoder, PackedSpace, SpaceRef};

use crate::entry::{TypeEntry, TypeKind, decode_integer_format, hash_size};
use crate::error::Result;
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;
use crate::xml::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_ARRAYSIZE, ATTRIB_CHAR, ATTRIB_CORE, ATTRIB_FIRST,
    ATTRIB_OPAQUESTRING, ATTRIB_UTF, ATTRIB_VARLENGTH, ELEM_ADDR, ELEM_BITFIELD, ELEM_CORETYPES,
    ELEM_DEF, ELEM_FIELD, ELEM_TYPE, ELEM_TYPEGRP, ELEM_TYPEREF,
};

fn write_meta(enc: &mut dyn Encoder, meta: Metatype) {
    enc.write_enum(ATTRIB_METATYPE, meta as u64, meta.name());
}

impl TypeFactory {
    fn space_ref(&self, space: bk_marshal::SpaceId) -> (String, PackedSpace) {
        let name = self
            .env
            .space(space)
            .map_or_else(|| format!("space{}", space.index()), |s| s.name.clone());
        (name, PackedSpace::Index(space.index()))
    }

    /// Ghidra `encodeBasic`.
    fn encode_basic(
        &self,
        enc: &mut dyn Encoder,
        e: &TypeEntry,
        meta: Metatype,
        align: i32,
    ) -> Result<()> {
        enc.write_string(ATTRIB_NAME, &e.name)?;
        let id = e.unsized_id();
        if id != 0 {
            enc.write_unsigned(ATTRIB_ID, id);
        }
        enc.write_signed(ATTRIB_SIZE, i64::from(e.size));
        write_meta(enc, meta);
        if align > 0 {
            enc.write_signed(ATTRIB_ALIGNMENT, i64::from(align));
        }
        if e.is_core() {
            enc.write_bool(ATTRIB_CORE, true);
        }
        if e.is_variable_length() {
            enc.write_bool(ATTRIB_VARLENGTH, true);
        }
        if e.is_opaque_string() {
            enc.write_bool(ATTRIB_OPAQUESTRING, true);
        }
        let format = e.display_format();
        if format != 0 {
            enc.write_string(ATTRIB_FORMAT, decode_integer_format(format)?)?;
        }
        Ok(())
    }

    /// Ghidra `encodeTypedef`.
    fn encode_typedef(
        &self,
        enc: &mut dyn Encoder,
        e: &TypeEntry,
        of: TypeId,
        depth: usize,
    ) -> Result<()> {
        enc.open_element(ELEM_DEF);
        enc.write_string(ATTRIB_NAME, &e.name)?;
        enc.write_unsigned(ATTRIB_ID, e.id);
        let format = e.display_format();
        if format != 0 {
            enc.write_string(ATTRIB_FORMAT, decode_integer_format(format)?)?;
        }
        self.encode_ref_depth(enc, of, depth + 1)?;
        enc.close_element(ELEM_DEF);
        Ok(())
    }

    /// Ghidra `encode`: a full description of a type, its components by
    /// reference.
    pub fn encode_type(&self, enc: &mut dyn Encoder, id: TypeId) -> Result<()> {
        self.encode_depth(enc, id, 0)
    }

    fn encode_depth(&self, enc: &mut dyn Encoder, id: TypeId, depth: usize) -> Result<()> {
        if depth > crate::MAX_DEPTH {
            return Err(crate::TypeError::TooDeep(crate::MAX_DEPTH));
        }
        let e = self.entry(id);
        // Every class but TypeBase, the partial types and TypePointerRel
        // writes a typedef as <def>.
        let typedef_kind = !matches!(
            e.kind,
            TypeKind::Base
                | TypeKind::PartialEnum { .. }
                | TypeKind::PartialStruct { .. }
                | TypeKind::PartialUnion { .. }
                | TypeKind::PointerRel { .. }
        );
        if typedef_kind {
            if let Some(of) = e.typedef_imm {
                return self.encode_typedef(enc, e, of, depth);
            }
        }
        match &e.kind {
            TypeKind::Void => {
                enc.open_element(ELEM_VOID);
                enc.close_element(ELEM_VOID);
                return Ok(());
            }
            TypeKind::PointerRel {
                ptr,
                parent,
                offset,
                ..
            } => {
                enc.open_element(ELEM_TYPE);
                self.encode_basic(enc, e, Metatype::PtrRel, -1)?;
                if ptr.wordsize != 1 {
                    enc.write_unsigned(ATTRIB_WORDSIZE, u64::from(ptr.wordsize));
                }
                self.encode_depth(enc, ptr.ptrto, depth + 1)?;
                self.encode_ref_depth(enc, *parent, depth + 1)?;
                enc.open_element(ELEM_OFF);
                enc.write_signed(ATTRIB_CONTENT, i64::from(*offset));
                enc.close_element(ELEM_OFF);
                enc.close_element(ELEM_TYPE);
                return Ok(());
            }
            _ => {}
        }
        enc.open_element(ELEM_TYPE);
        match &e.kind {
            TypeKind::Base | TypeKind::PartialStruct { .. } => {
                self.encode_basic(enc, e, e.metatype, -1)?
            }
            TypeKind::Char => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                enc.write_bool(ATTRIB_CHAR, true);
            }
            TypeKind::Unicode => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                enc.write_bool(ATTRIB_UTF, true);
            }
            TypeKind::Pointer(p) => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                if p.wordsize != 1 {
                    enc.write_unsigned(ATTRIB_WORDSIZE, u64::from(p.wordsize));
                }
                if let Some(space) = p.space {
                    let (name, packed) = self.space_ref(space);
                    enc.write_space(
                        ATTRIB_SPACE,
                        &SpaceRef {
                            name: &name,
                            packed,
                        },
                    );
                }
                self.encode_ref_depth(enc, p.ptrto, depth + 1)?;
            }
            TypeKind::Array { element, count } => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                enc.write_signed(ATTRIB_ARRAYSIZE, i64::from(*count));
                self.encode_ref_depth(enc, *element, depth + 1)?;
            }
            TypeKind::Enum(values) => {
                let meta = if e.metatype == Metatype::Int {
                    Metatype::EnumInt
                } else {
                    Metatype::EnumUint
                };
                self.encode_basic(enc, e, meta, -1)?;
                for (v, n) in &values.values {
                    enc.open_element(ELEM_VAL);
                    enc.write_string(ATTRIB_NAME, n)?;
                    enc.write_unsigned(ATTRIB_VALUE, *v);
                    enc.close_element(ELEM_VAL);
                }
            }
            TypeKind::PartialEnum { parent, offset, .. } => {
                self.encode_basic(enc, e, Metatype::PartialEnum, -1)?;
                enc.write_signed(ATTRIB_OFFSET, i64::from(*offset));
                self.encode_ref_depth(enc, *parent, depth + 1)?;
            }
            TypeKind::PartialUnion {
                container, offset, ..
            } => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                enc.write_signed(ATTRIB_OFFSET, i64::from(*offset));
                self.encode_ref_depth(enc, *container, depth + 1)?;
            }
            TypeKind::Struct { fields, bitfields } => {
                self.encode_basic(enc, e, e.metatype, e.alignment)?;
                let (mut fi, mut bi) = (fields.iter().peekable(), bitfields.iter().peekable());
                loop {
                    let take_field = match (fi.peek(), bi.peek()) {
                        (Some(f), Some(b)) => f.offset < b.bits.byte_offset,
                        (Some(_), None) => true,
                        (None, Some(_)) => false,
                        (None, None) => break,
                    };
                    if take_field {
                        if let Some(f) = fi.next() {
                            self.encode_field(enc, f, depth)?;
                        }
                    } else if let Some(b) = bi.next() {
                        enc.open_element(ELEM_BITFIELD);
                        enc.write_string(ATTRIB_NAME, &b.name)?;
                        enc.write_signed(ATTRIB_OFFSET, i64::from(b.bits.byte_offset));
                        enc.write_signed(ATTRIB_SIZE, i64::from(b.bits.num_bits));
                        enc.write_signed(ATTRIB_FIRST, i64::from(b.bits.least_sig_bit));
                        self.encode_ref_depth(enc, b.ty, depth + 1)?;
                        enc.close_element(ELEM_BITFIELD);
                    }
                }
            }
            TypeKind::Union { fields } => {
                self.encode_basic(enc, e, e.metatype, e.alignment)?;
                for f in fields {
                    self.encode_field(enc, f, depth)?;
                }
            }
            TypeKind::Code(sig) => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                if let Some(sig) = sig {
                    self.encode_signature(enc, sig, depth)?;
                }
            }
            TypeKind::Spacebase { space, scope } => {
                self.encode_basic(enc, e, e.metatype, -1)?;
                let (name, packed) = self.space_ref(*space);
                enc.write_space(
                    ATTRIB_SPACE,
                    &SpaceRef {
                        name: &name,
                        packed,
                    },
                );
                let frame = self
                    .hooks
                    .scopes
                    .as_ref()
                    .and_then(|s| s.frame_of_scope(*scope));
                self.encode_address(enc, frame)?;
            }
            TypeKind::Void | TypeKind::PointerRel { .. } => {}
        }
        enc.close_element(ELEM_TYPE);
        Ok(())
    }

    /// Ghidra `Address::encode` for an optional address.
    pub(crate) fn encode_address(
        &self,
        enc: &mut dyn Encoder,
        addr: Option<(bk_marshal::SpaceId, u64)>,
    ) -> Result<()> {
        enc.open_element(ELEM_ADDR);
        if let Some((space, offset)) = addr {
            let (name, packed) = self.space_ref(space);
            enc.write_space(
                ATTRIB_SPACE,
                &SpaceRef {
                    name: &name,
                    packed,
                },
            );
            enc.write_unsigned(ATTRIB_OFFSET, offset);
        }
        enc.close_element(ELEM_ADDR);
        Ok(())
    }

    fn encode_field(
        &self,
        enc: &mut dyn Encoder,
        f: &crate::entry::Field,
        depth: usize,
    ) -> Result<()> {
        enc.open_element(ELEM_FIELD);
        enc.write_string(ATTRIB_NAME, &f.name)?;
        enc.write_signed(ATTRIB_OFFSET, i64::from(f.offset));
        if f.ident != f.offset {
            enc.write_signed(ATTRIB_ID, i64::from(f.ident));
        }
        self.encode_ref_depth(enc, f.ty, depth + 1)?;
        enc.close_element(ELEM_FIELD);
        Ok(())
    }

    /// Ghidra `encodeRef`: a `<typeref>` for a named type, else the full
    /// description.
    pub fn encode_ref(&self, enc: &mut dyn Encoder, id: TypeId) -> Result<()> {
        self.encode_ref_depth(enc, id, 0)
    }

    fn encode_ref_depth(&self, enc: &mut dyn Encoder, id: TypeId, depth: usize) -> Result<()> {
        let e = self.entry(id);
        if e.id != 0 && e.metatype != Metatype::Void {
            enc.open_element(ELEM_TYPEREF);
            enc.write_string(ATTRIB_NAME, &e.name)?;
            if e.is_variable_length() {
                enc.write_unsigned(ATTRIB_ID, hash_size(e.id, e.size));
                enc.write_signed(ATTRIB_SIZE, i64::from(e.size));
            } else {
                enc.write_unsigned(ATTRIB_ID, e.id);
            }
            enc.close_element(ELEM_TYPEREF);
            Ok(())
        } else {
            self.encode_depth(enc, id, depth)
        }
    }

    /// Ghidra `TypeFactory::encode`: `<typegrp>` with every named type in
    /// dependency order (core types only if pointer, array, structure or
    /// union).
    pub fn encode(&self, enc: &mut dyn Encoder) -> Result<()> {
        enc.open_element(ELEM_TYPEGRP);
        for id in self.dependent_order() {
            let e = self.entry(id);
            if e.name.is_empty() {
                continue;
            }
            if e.is_core()
                && !matches!(
                    e.metatype,
                    Metatype::Ptr | Metatype::Array | Metatype::Struct | Metatype::Union
                )
            {
                continue;
            }
            self.encode_type(enc, id)?;
        }
        enc.close_element(ELEM_TYPEGRP);
        Ok(())
    }

    /// Ghidra `encodeCoreTypes`: `<coretypes>` with the core types.
    pub fn encode_core_types(&self, enc: &mut dyn Encoder) -> Result<()> {
        enc.open_element(ELEM_CORETYPES);
        for id in self.sorted_ids() {
            let e = self.entry(id);
            if !e.is_core()
                || matches!(
                    e.metatype,
                    Metatype::Ptr | Metatype::Array | Metatype::Struct | Metatype::Union
                )
            {
                continue;
            }
            self.encode_type(enc, id)?;
        }
        enc.close_element(ELEM_CORETYPES);
        Ok(())
    }

    /// Encodes a type to XML text (no formatting), for tests and tables.
    pub fn encode_type_text(&self, id: TypeId) -> Result<String> {
        let mut enc = bk_marshal::XmlEncoder::new(false);
        self.encode_type(&mut enc, id)?;
        Ok(enc.into_string())
    }
}
