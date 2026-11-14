//! Decoding types and the factory (Ghidra `decodeType`, `decodeTypeNoRef`,
//! `decodeTypedef`, `decodeEnum`, `decodeStruct`, `decodeUnion`,
//! `decodeCode`, `decodeTypeWithCodeFlags`, `decode`, `decodeCoreTypes`, and
//! the classes' `decode`/`decodeBasic`/`decodeFields`).

use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_FORMAT, ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_NAME, ATTRIB_OFFSET,
    ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_VALUE, ATTRIB_WORDSIZE, ELEM_OFF, ELEM_VOID,
};
use bk_marshal::{Decoder, Document, XmlDecoder};

use crate::entry::{
    EnumValues, PointerData, TypeEntry, TypeFlags, TypeKind, encode_integer_format, hash_name,
    hash_size,
};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::composite::Layout;
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};
use crate::xml::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_ARRAYSIZE, ATTRIB_CHAR, ATTRIB_CORE, ATTRIB_INCOMPLETE, ATTRIB_LABEL,
    ATTRIB_OPAQUESTRING, ATTRIB_UTF, ATTRIB_VARLENGTH, ELEM_ADDR, ELEM_CORETYPES, ELEM_DEF,
    ELEM_TYPEGRP, ELEM_TYPEREF, id_table,
};

/// The deepest nesting of type definitions decoded.
pub const MAX_DECODE_DEPTH: usize = 200;

fn metatype_by_name(name: &str) -> Option<i64> {
    Metatype::from_name(name).ok().map(|m| m as i64)
}

fn read_meta(dec: &mut dyn Decoder<'_>) -> Result<Metatype> {
    let v = dec.read_enum(&metatype_by_name)?;
    u8::try_from(v)
        .ok()
        .and_then(Metatype::from_u8)
        .ok_or_else(|| TypeError::new("Unknown metatype"))
}

/// Ghidra `Datatype::decodeBasic`: reads name, size, metatype, id and
/// properties into `e`.
pub(super) fn decode_basic(e: &mut TypeEntry, dec: &mut dyn Decoder<'_>) -> Result<()> {
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

impl TypeFactory {
    /// Ghidra `decodeType`: a `<typeref>`, or a definition.
    pub fn decode_type(&mut self, dec: &mut dyn Decoder<'_>) -> Result<TypeId> {
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
    pub fn decode_type_no_ref(
        &mut self,
        dec: &mut dyn Decoder<'_>,
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

    fn decode_no_ref_inner(
        &mut self,
        dec: &mut dyn Decoder<'_>,
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
                let (wordsize, space) = Self::pointer_attrs(dec)?;
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
                let (wordsize, space) = Self::pointer_attrs(dec)?;
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
                let frame = Self::decode_address(dec)?;
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
    fn decode_atomic(&mut self, dec: &mut dyn Decoder<'_>, core: TypeFlags) -> Result<TypeId> {
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

    fn pointer_attrs(dec: &mut dyn Decoder<'_>) -> Result<(u32, Option<bk_marshal::SpaceId>)> {
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
    pub(crate) fn decode_address(
        dec: &mut dyn Decoder<'_>,
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
    fn decode_typedef(&mut self, dec: &mut dyn Decoder<'_>) -> Result<TypeId> {
        let (mut id, mut name, mut format) = (0u64, String::new(), 0u32);
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_ID {
                id = dec.read_unsigned()?;
            } else if attr == ATTRIB_NAME {
                dec.read_string()?.clone_into(&mut name);
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
        if matches!(d.metatype, Metatype::Struct | Metatype::Union)
            && let Some(prev) = self.find_by_id_local(&name, id)
        {
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
                    TypeKind::Struct { fields, bitfields } if p.metatype == Metatype::Struct => {
                        self.set_struct_fields(prev, fields, bitfields, layout)?;
                    }
                    TypeKind::Union { fields } => {
                        self.set_union_fields(prev, fields, layout)?;
                    }
                    _ => {}
                }
            }
            return Ok(prev);
        }
        self.typedef(defed, &name, id, format)
    }

    /// Ghidra `decodeEnum` with `TypeEnum::decode`.
    fn decode_enum(&mut self, dec: &mut dyn Decoder<'_>, forcecore: bool) -> Result<TypeId> {
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
                    dec.read_string()?.clone_into(&mut nm);
                }
            }
            if nm.is_empty() {
                return Err(TypeError::new(format!(
                    "{}: TypeEnum field missing name attribute",
                    te.name
                )));
            }
            if let std::collections::btree_map::Entry::Vacant(e) = values.values.entry(val) {
                e.insert(nm.into());
            } else if warning.is_empty() {
                warning = format!("Enum \"{}\": Some values do not have unique names", te.name);
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

    /// Ghidra `decodeCode`.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "Ghidra's decodeCode(decoder, isConstructor, isDestructor, forcecore)"
    )]
    fn decode_code(
        &mut self,
        dec: &mut dyn Decoder<'_>,
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
    pub fn decode_type_with_code_flags(
        &mut self,
        dec: &mut dyn Decoder<'_>,
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
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        let elem = dec.open_element_expecting(ELEM_TYPEGRP)?;
        while dec.peek_element().is_some() {
            self.decode_type_no_ref(dec, false)?;
        }
        dec.close_element(elem)?;
        Ok(())
    }

    /// Ghidra `decodeCoreTypes`: clears the factory, reads `<coretypes>`
    /// and caches them.
    pub fn decode_core_types(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
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
