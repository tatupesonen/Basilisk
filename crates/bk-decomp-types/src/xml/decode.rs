//! Decoding types and the factory (Ghidra `decodeType`, `decodeTypeNoRef`,
//! `decodeTypedef`, `decodeEnum`, `decodeStruct`, `decodeUnion`,
//! `decodeCode`, `decodeTypeWithCodeFlags`, `decode`, `decodeCoreTypes`, and
//! the classes' `decode`/`decodeBasic`/`decodeFields`).

use bk_core::BitRange;
use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_FORMAT, ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_NAME, ATTRIB_OFFSET,
    ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_VALUE, ATTRIB_WORDSIZE, ELEM_OFF, ELEM_VOID,
};
use bk_marshal::{Decoder, Document, XmlDecoder};

use crate::entry::{
    BitField, EnumValues, Field, PointerData, TypeEntry, TypeFlags, TypeKind, calc_align_size,
    encode_integer_format, hash_name, hash_size,
};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::composite::Layout;
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};
use crate::xml::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_ARRAYSIZE, ATTRIB_CHAR, ATTRIB_CORE, ATTRIB_FIRST, ATTRIB_INCOMPLETE,
    ATTRIB_LABEL, ATTRIB_OPAQUESTRING, ATTRIB_UTF, ATTRIB_VARLENGTH, ELEM_ADDR, ELEM_BITFIELD,
    ELEM_CORETYPES, ELEM_DEF, ELEM_FIELD, ELEM_TYPEGRP, ELEM_TYPEREF, id_table,
};

/// The deepest nesting of type definitions decoded.
pub const MAX_DECODE_DEPTH: usize = 200;

fn metatype_by_name(name: &str) -> Option<i64> {
    Metatype::from_name(name).ok().map(|m| m as i64)
}

fn read_meta<'a>(dec: &mut dyn Decoder<'a>) -> Result<Metatype> {
    let v = dec.read_enum(&metatype_by_name)?;
    u8::try_from(v)
        .ok()
        .and_then(Metatype::from_u8)
        .ok_or_else(|| TypeError::new("Unknown metatype"))
}

/// Ghidra `Datatype::decodeBasic`: reads name, size, metatype, id and
/// properties into `e`.
fn decode_basic<'a>(e: &mut TypeEntry, dec: &mut dyn Decoder<'a>) -> Result<()> {
    let mut size: i64 = -1;
    e.metatype = Metatype::Void;
    e.id = 0;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_NAME {
            e.name = dec.read_string()?.into();
        } else if attr == ATTRIB_SIZE {
            size = dec.read_signed()?;
        } else if attr == ATTRIB_METATYPE {
            e.metatype = read_meta(dec)?;
        } else if attr == ATTRIB_CORE {
            if dec.read_bool()? {
                e.flags |= TypeFlags::CORETYPE;
            }
        } else if attr == ATTRIB_ID {
            e.id = dec.read_unsigned()?;
        } else if attr == ATTRIB_VARLENGTH {
            if dec.read_bool()? {
                e.flags |= TypeFlags::VARIABLE_LENGTH;
            }
        } else if attr == ATTRIB_ALIGNMENT {
            e.alignment = dec.read_signed()? as i32;
        } else if attr == ATTRIB_OPAQUESTRING {
            if dec.read_bool()? {
                e.flags |= TypeFlags::OPAQUE_STRING;
            }
        } else if attr == ATTRIB_FORMAT {
            let v = encode_integer_format(dec.read_string()?)?;
            e.set_display_format(v);
        } else if attr == ATTRIB_LABEL {
            e.display_name = dec.read_string()?.into();
        } else if attr == ATTRIB_INCOMPLETE && dec.read_bool()? {
            e.flags |= TypeFlags::TYPE_INCOMPLETE;
        }
    }
    if !(0..=i64::from(i32::MAX)).contains(&size) {
        return Err(TypeError::new(format!("Bad size for type {}", e.name)));
    }
    e.size = size as i32;
    e.align_size = e.size;
    e.submeta = e.metatype.base_sub();
    if e.id == 0 && !e.name.is_empty() {
        e.id = hash_name(&e.name);
    }
    if e.is_variable_length() {
        e.id = hash_size(e.id, e.size);
    }
    if e.display_name.is_empty() {
        e.display_name.clone_from(&e.name);
    }
    Ok(())
}

/// Accumulated state while decoding structure fields (Ghidra `FieldAccum`).
struct FieldAccum {
    last_off: i32,
    calc_size: i32,
    calc_align: i32,
    warning: String,
    has_bitfields: bool,
}

impl TypeFactory {
    /// Ghidra `decodeType`: a `<typeref>`, or a definition.
    pub fn decode_type<'a>(&mut self, dec: &mut dyn Decoder<'a>) -> Result<TypeId> {
        if dec.peek_element() == Some(ELEM_TYPEREF.code()) {
            let elem = dec
                .open_element()?
                .ok_or_else(|| TypeError::new("Missing <typeref>"))?;
            let mut newid = 0;
            let mut size: i64 = -1;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_ID {
                    newid = dec.read_unsigned()?;
                } else if attr == ATTRIB_SIZE {
                    size = dec.read_signed()?;
                }
            }
            let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
            if newid == 0 {
                newid = hash_name(&name);
            }
            let size = i32::try_from(size).unwrap_or(-1);
            let ct = self
                .find_by_id_hooked(&name, newid, size)?
                .ok_or_else(|| TypeError::new(format!("Unable to resolve type: {name}")))?;
            dec.close_element(elem)?;
            return Ok(ct);
        }
        self.decode_type_no_ref(dec, false)
    }

    /// Ghidra's virtual `findById`: the factory, then the [`TypeSource`](crate::xml::TypeSource).
    fn find_by_id_hooked(&mut self, name: &str, id: u64, size: i32) -> Result<Option<TypeId>> {
        if let Some(t) = self.find_by_id(name, id, size) {
            return Ok(Some(t));
        }
        let Some(source) = self.hooks.source.clone() else {
            return Ok(None);
        };
        let Some((text, provenance)) = source.definition(name, id, size) else {
            return Ok(None);
        };
        let saved = self.provenance();
        self.set_provenance(provenance);
        let res = self.decode_type_text(&text);
        self.set_provenance(saved);
        res.map(Some)
    }

    /// Decodes one type definition from XML text.
    pub fn decode_type_text(&mut self, text: &str) -> Result<TypeId> {
        let doc = Document::parse(text).map_err(bk_marshal::DecodeError::from)?;
        let ids = id_table();
        let env = self.env.clone();
        let mut dec = XmlDecoder::new(&doc, &ids, &env);
        self.decode_type(&mut dec)
    }

    /// Ghidra `decodeTypeNoRef`: a `<type>`, `<def>` or `<void>` element.
    pub fn decode_type_no_ref<'a>(
        &mut self,
        dec: &mut dyn Decoder<'a>,
        forcecore: bool,
    ) -> Result<TypeId> {
        if self.decode_depth >= MAX_DECODE_DEPTH {
            return Err(TypeError::TooDeep(MAX_DECODE_DEPTH));
        }
        self.decode_depth += 1;
        let res = self.decode_no_ref_inner(dec, forcecore);
        self.decode_depth -= 1;
        res
    }

    fn decode_no_ref_inner<'a>(
        &mut self,
        dec: &mut dyn Decoder<'a>,
        forcecore: bool,
    ) -> Result<TypeId> {
        let elem = dec
            .open_element()?
            .ok_or_else(|| TypeError::new("Expecting a type element"))?;
        if elem == ELEM_VOID {
            let ct = self.type_void()?;
            dec.close_element(elem)?;
            return Ok(ct);
        }
        if elem == ELEM_DEF {
            let ct = self.decode_typedef(dec)?;
            dec.close_element(elem)?;
            return Ok(ct);
        }
        let v = dec.read_enum_attr(ATTRIB_METATYPE, &metatype_by_name)?;
        let meta = u8::try_from(v)
            .ok()
            .and_then(Metatype::from_u8)
            .ok_or_else(|| TypeError::new("Unknown metatype"))?;
        let core = if forcecore {
            TypeFlags::CORETYPE
        } else {
            TypeFlags::empty()
        };
        let ct = match meta {
            Metatype::Ptr => {
                let mut tp = TypeEntry::new(0, -1, Metatype::Ptr, TypeKind::Base);
                decode_basic(&mut tp, dec)?;
                let (wordsize, space) = self.pointer_attrs(dec)?;
                let ptrto = self.decode_type(dec)?;
                tp.kind = TypeKind::Pointer(PointerData {
                    ptrto,
                    space,
                    truncate: None,
                    wordsize,
                });
                self.calc_pointer_submeta(&mut tp, ptrto);
                if tp.name.is_empty() {
                    tp.flags |= self.entry(ptrto).inherit_for_pointer();
                }
                self.truncate_candidate(&mut tp)?;
                tp.flags |= core;
                self.find_add(tp)?
            }
            Metatype::PtrRel => {
                let mut tp = TypeEntry::new(0, -1, Metatype::Ptr, TypeKind::Base);
                tp.flags |= TypeFlags::IS_PTRREL;
                decode_basic(&mut tp, dec)?;
                tp.metatype = Metatype::Ptr;
                let (wordsize, space) = self.pointer_attrs(dec)?;
                let ptrto = self.decode_type(dec)?;
                let parent = self.decode_type(dec)?;
                let sub = dec.open_element_expecting(ELEM_OFF)?;
                let offset = dec.read_signed_attr(ATTRIB_CONTENT)? as i32;
                dec.close_element(sub)?;
                if offset == 0 {
                    return Err(TypeError::new(
                        "For metatype=\"ptrstruct\", <off> tag must not be zero",
                    ));
                }
                tp.submeta = SubMetatype::PtrRel;
                let ptr = PointerData {
                    ptrto,
                    space,
                    truncate: None,
                    wordsize,
                };
                let mut stripped = None;
                if tp.name.is_empty() {
                    stripped = Some(self.pointer(tp.size, ptrto, wordsize)?);
                    tp.flags |= TypeFlags::HAS_STRIPPED;
                    if self.entry(ptrto).metatype == Metatype::Unknown {
                        tp.submeta = SubMetatype::PtrRelUnk;
                    }
                }
                tp.kind = TypeKind::PointerRel {
                    ptr,
                    parent,
                    offset,
                    stripped,
                };
                tp.flags |= core;
                self.find_add(tp)?
            }
            Metatype::Array => {
                let mut ta = TypeEntry::new(0, -1, Metatype::Array, TypeKind::Base);
                decode_basic(&mut ta, dec)?;
                dec.rewind_attributes();
                let mut count: i64 = -1;
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_ARRAYSIZE {
                        count = dec.read_signed()?;
                    }
                }
                let element = self.decode_type(dec)?;
                let el = self.entry(element);
                if count <= 0
                    || count.checked_mul(i64::from(el.align_size)) != Some(i64::from(ta.size))
                {
                    return Err(TypeError::new(format!(
                        "Bad size for array of type {}",
                        el.name
                    )));
                }
                ta.alignment = el.alignment;
                if count == 1 {
                    ta.flags |= TypeFlags::NEEDS_RESOLUTION;
                }
                ta.kind = TypeKind::Array {
                    element,
                    count: count as i32,
                };
                ta.flags |= core;
                self.find_add(ta)?
            }
            Metatype::EnumInt | Metatype::EnumUint => self.decode_enum(dec, forcecore)?,
            Metatype::Struct => self.decode_struct(dec, forcecore)?,
            Metatype::Union => self.decode_union(dec, forcecore)?,
            Metatype::Spacebase => {
                let mut tsb = TypeEntry::new(0, 1, Metatype::Spacebase, TypeKind::Base);
                decode_basic(&mut tsb, dec)?;
                let space = dec.read_space_attr(ATTRIB_SPACE)?;
                let frame = self.decode_address(dec)?;
                let scope = self
                    .hooks
                    .scopes
                    .as_ref()
                    .map_or(0, |s| s.scope_of_frame(frame));
                tsb.kind = TypeKind::Spacebase { space, scope };
                tsb.flags |= core;
                self.find_add(tsb)?
            }
            Metatype::Code => self.decode_code(dec, false, false, forcecore)?,
            Metatype::Void => {
                let mut tv = TypeEntry::new(0, 1, Metatype::Void, TypeKind::Void);
                tv.name = "void".into();
                tv.display_name = "void".into();
                tv.flags |= TypeFlags::CORETYPE;
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_ID {
                        tv.id = dec.read_unsigned()?;
                    }
                }
                self.find_add(tv)?
            }
            _ => self.decode_atomic(dec, core)?,
        };
        dec.close_element(elem)?;
        Ok(ct)
    }

    /// The default case of `decodeTypeNoRef`: a character, wide character
    /// or plain base type.
    fn decode_atomic<'a>(&mut self, dec: &mut dyn Decoder<'a>, core: TypeFlags) -> Result<TypeId> {
        let mut kind = TypeKind::Base;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_CHAR && dec.read_bool()? {
                kind = TypeKind::Char;
                break;
            }
            if attr == ATTRIB_UTF && dec.read_bool()? {
                kind = TypeKind::Unicode;
                break;
            }
        }
        dec.rewind_attributes();
        let mut e = TypeEntry::new(0, -1, Metatype::Unknown, kind);
        match e.kind {
            TypeKind::Char => {
                e.flags |= TypeFlags::CHARTYPE;
                decode_basic(&mut e, dec)?;
                e.submeta = if e.metatype == Metatype::Int {
                    SubMetatype::IntChar
                } else {
                    SubMetatype::UintChar
                };
            }
            TypeKind::Unicode => {
                decode_basic(&mut e, dec)?;
                crate::factory::base::unicode_flags(&mut e);
                e.submeta = if e.metatype == Metatype::Int {
                    SubMetatype::IntUnicode
                } else {
                    SubMetatype::UintUnicode
                };
            }
            _ => decode_basic(&mut e, dec)?,
        }
        e.flags |= core;
        self.find_add(e)
    }

    fn pointer_attrs<'a>(
        &self,
        dec: &mut dyn Decoder<'a>,
    ) -> Result<(u32, Option<bk_marshal::SpaceId>)> {
        dec.rewind_attributes();
        let (mut wordsize, mut space) = (1u32, None);
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_WORDSIZE {
                wordsize = dec.read_unsigned()? as u32;
            } else if attr == ATTRIB_SPACE {
                space = Some(dec.read_space()?);
            }
        }
        Ok((wordsize, space))
    }

    /// `calcTruncate` on a pointer that is not yet in the factory.
    fn truncate_candidate(&mut self, tp: &mut TypeEntry) -> Result<()> {
        let Some(p) = tp.pointer().copied() else {
            return Ok(());
        };
        if p.truncate.is_some() || tp.size != self.org.size_of_alt_pointer {
            return Ok(());
        }
        let cand = self.pointer_entry(self.org.size_of_pointer, p.ptrto, p.wordsize)?;
        let short = self.find_add(cand)?;
        if let TypeKind::Pointer(q) = &mut tp.kind {
            q.truncate = Some(short);
        }
        if self.env.data_space.big_endian {
            tp.flags |= TypeFlags::TRUNCATE_BIGENDIAN;
        }
        Ok(())
    }

    /// Ghidra `Address::decode`: an `<addr>` element; `None` when invalid.
    pub(crate) fn decode_address<'a>(
        &self,
        dec: &mut dyn Decoder<'a>,
    ) -> Result<Option<(bk_marshal::SpaceId, u64)>> {
        let elem = dec.open_element_expecting(ELEM_ADDR)?;
        let (mut space, mut offset) = (None, 0);
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_SPACE {
                space = Some(dec.read_space()?);
            } else if attr == ATTRIB_OFFSET {
                offset = dec.read_unsigned()?;
            }
        }
        dec.close_element(elem)?;
        Ok(space.map(|s| (s, offset)))
    }

    /// Ghidra `decodeTypedef`.
    fn decode_typedef<'a>(&mut self, dec: &mut dyn Decoder<'a>) -> Result<TypeId> {
        let (mut id, mut name, mut format) = (0u64, String::new(), 0u32);
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_ID {
                id = dec.read_unsigned()?;
            } else if attr == ATTRIB_NAME {
                name = dec.read_string()?.to_owned();
            } else if attr == ATTRIB_FORMAT {
                format = encode_integer_format(dec.read_string()?)?;
            }
        }
        if id == 0 {
            id = hash_name(&name);
        }
        let defed = self.decode_type(dec)?;
        let d = self.entry(defed).clone();
        if d.is_variable_length() {
            id = hash_size(id, d.size);
        }
        if matches!(d.metatype, Metatype::Struct | Metatype::Union) {
            if let Some(prev) = self.find_by_id_local(&name, id) {
                let p = self.entry(prev);
                if p.typedef_imm != Some(defed) {
                    return Err(TypeError::new(format!(
                        "Trying to create typedef of existing type: {}",
                        p.name
                    )));
                }
                let layout = Layout {
                    size: d.size,
                    align: d.alignment,
                    flags: d.flags,
                };
                if p.fields().len() != d.fields().len() {
                    match d.kind {
                        TypeKind::Struct { fields, bitfields }
                            if p.metatype == Metatype::Struct =>
                        {
                            self.set_struct_fields(prev, fields, bitfields, layout)?;
                        }
                        TypeKind::Union { fields } => {
                            self.set_union_fields(prev, fields, layout)?
                        }
                        _ => {}
                    }
                }
                return Ok(prev);
            }
        }
        self.typedef(defed, &name, id, format)
    }

    /// Ghidra `decodeEnum` with `TypeEnum::decode`.
    fn decode_enum<'a>(&mut self, dec: &mut dyn Decoder<'a>, forcecore: bool) -> Result<TypeId> {
        let mut te = TypeEntry::new(1, -1, Metatype::EnumInt, TypeKind::Enum(Box::default()));
        te.flags |= TypeFlags::ENUMTYPE;
        decode_basic(&mut te, dec)?;
        te.metatype = if te.metatype == Metatype::EnumInt {
            Metatype::Int
        } else {
            Metatype::Uint
        };
        let mask = bk_core::bits::calc_mask(te.size as u32);
        let mut values = EnumValues::default();
        let mut warning = String::new();
        while let Some(child) = dec.open_element()? {
            let (mut val, mut nm) = (0u64, String::new());
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_VALUE {
                    val = (dec.read_signed()? as u64) & mask;
                } else if attr == ATTRIB_NAME {
                    nm = dec.read_string()?.to_owned();
                }
            }
            if nm.is_empty() {
                return Err(TypeError::new(format!(
                    "{}: TypeEnum field missing name attribute",
                    te.name
                )));
            }
            if values.values.contains_key(&val) {
                if warning.is_empty() {
                    warning = format!("Enum \"{}\": Some values do not have unique names", te.name);
                }
            } else {
                values.values.insert(val, nm.into());
            }
            dec.close_element(child)?;
        }
        te.kind = TypeKind::Enum(Box::new(values));
        if forcecore {
            te.flags |= TypeFlags::CORETYPE;
        }
        let res = self.find_add(te)?;
        if !warning.is_empty() {
            self.insert_warning(res, warning)?;
        }
        Ok(res)
    }

    /// Ghidra `decodeStruct`.
    fn decode_struct<'a>(&mut self, dec: &mut dyn Decoder<'a>, forcecore: bool) -> Result<TypeId> {
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
    fn decode_struct_fields<'a>(
        &mut self,
        ts: &mut TypeEntry,
        dec: &mut dyn Decoder<'a>,
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
        if let [only] = fields.as_slice() {
            if self.entry(only.ty).size == ts.size {
                ts.flags |= TypeFlags::NEEDS_RESOLUTION;
            }
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
    fn read_field<'a>(&mut self, dec: &mut dyn Decoder<'a>) -> Result<Field> {
        let elem = dec.open_element_expecting(ELEM_FIELD)?;
        let (mut ident, mut offset, mut name) = (-1i64, -1i64, String::new());
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_NAME {
                name = dec.read_string()?.to_owned();
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

    fn decode_field<'a>(
        &mut self,
        ts: &TypeEntry,
        dec: &mut dyn Decoder<'a>,
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

    fn decode_bitfield<'a>(
        &mut self,
        ts: &TypeEntry,
        dec: &mut dyn Decoder<'a>,
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
                name = dec.read_string()?.to_owned();
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
    fn decode_union<'a>(&mut self, dec: &mut dyn Decoder<'a>, forcecore: bool) -> Result<TypeId> {
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

    /// Ghidra `decodeCode`.
    fn decode_code<'a>(
        &mut self,
        dec: &mut dyn Decoder<'a>,
        ctor: bool,
        dtor: bool,
        forcecore: bool,
    ) -> Result<TypeId> {
        let mut tc = TypeEntry::new(1, 1, Metatype::Code, TypeKind::Code(None));
        tc.flags |= TypeFlags::TYPE_INCOMPLETE;
        if dec.peek_element().is_some() {
            tc.flags |= TypeFlags::VARIABLE_LENGTH;
        }
        decode_basic(&mut tc, dec)?;
        if tc.metatype != Metatype::Code {
            return Err(TypeError::new("Expecting metatype=\"code\""));
        }
        if forcecore {
            tc.flags |= TypeFlags::CORETYPE;
        }
        let ct = match self.find_by_id_local(&tc.name, tc.id) {
            None => self.find_add(tc.clone())?,
            Some(ct) if self.entry(ct).metatype != Metatype::Code => {
                return Err(TypeError::new(format!(
                    "Trying to redefine type: {}",
                    tc.name
                )));
            }
            Some(ct) => ct,
        };
        if dec.peek_element().is_some() {
            let mut sig = self.decode_signature(dec)?;
            if ctor {
                sig.flags |= crate::entry::sigflags::IS_CONSTRUCTOR;
            } else {
                sig.flags &= !crate::entry::sigflags::IS_CONSTRUCTOR;
            }
            if dtor {
                sig.flags |= crate::entry::sigflags::IS_DESTRUCTOR;
            } else {
                sig.flags &= !crate::entry::sigflags::IS_DESTRUCTOR;
            }
            tc.kind = TypeKind::Code(Some(Box::new(sig)));
        }
        tc.flags.remove(TypeFlags::TYPE_INCOMPLETE);
        if self.entry(ct).is_incomplete() {
            let sig = match tc.kind {
                TypeKind::Code(s) => s.map(|b| *b),
                _ => None,
            };
            self.set_prototype(ct, sig, tc.flags)?;
        } else if crate::compare::identity::compare_dependency(self.entry(ct), &tc) != 0 {
            return Err(TypeError::new(format!(
                "Redefinition of code data-type: {}",
                tc.name
            )));
        }
        self.resolve_incomplete_typedefs()?;
        Ok(ct)
    }

    /// Ghidra `decodeTypeWithCodeFlags`: a pointer to a function type with
    /// constructor/destructor flags.
    pub fn decode_type_with_code_flags<'a>(
        &mut self,
        dec: &mut dyn Decoder<'a>,
        ctor: bool,
        dtor: bool,
    ) -> Result<TypeId> {
        let elem = dec
            .open_element()?
            .ok_or_else(|| TypeError::new("Expecting a type element"))?;
        let mut tp = TypeEntry::new(0, -1, Metatype::Ptr, TypeKind::Base);
        decode_basic(&mut tp, dec)?;
        if tp.metatype != Metatype::Ptr {
            return Err(TypeError::new("Special type decode does not see pointer"));
        }
        // As in Ghidra, the attribute loop after decodeBasic finds nothing
        // left to read, so the word size stays 1.
        let inner = dec
            .open_element()?
            .ok_or_else(|| TypeError::new("Expecting a type element"))?;
        let ptrto = self.decode_code(dec, ctor, dtor, false)?;
        dec.close_element(inner)?;
        dec.close_element(elem)?;
        tp.kind = TypeKind::Pointer(PointerData {
            ptrto,
            space: None,
            truncate: None,
            wordsize: 1,
        });
        self.truncate_candidate(&mut tp)?;
        self.find_add(tp)
    }

    /// Ghidra `TypeFactory::decode`: every definition in a `<typegrp>`.
    pub fn decode<'a>(&mut self, dec: &mut dyn Decoder<'a>) -> Result<()> {
        let elem = dec.open_element_expecting(ELEM_TYPEGRP)?;
        while dec.peek_element().is_some() {
            self.decode_type_no_ref(dec, false)?;
        }
        dec.close_element(elem)?;
        Ok(())
    }

    /// Ghidra `decodeCoreTypes`: clears the factory, reads `<coretypes>`
    /// and caches them.
    pub fn decode_core_types<'a>(&mut self, dec: &mut dyn Decoder<'a>) -> Result<()> {
        self.clear();
        let elem = dec.open_element_expecting(ELEM_CORETYPES)?;
        while dec.peek_element().is_some() {
            self.decode_type_no_ref(dec, true)?;
        }
        dec.close_element(elem)?;
        self.cache_core_types();
        Ok(())
    }

    /// Decodes a `<typegrp>` from XML text.
    pub fn decode_text(&mut self, text: &str) -> Result<()> {
        let doc = Document::parse(text).map_err(bk_marshal::DecodeError::from)?;
        let ids = id_table();
        let env = self.env.clone();
        let mut dec = XmlDecoder::new(&doc, &ids, &env);
        self.decode(&mut dec)
    }
}
