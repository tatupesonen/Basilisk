//! Symbols and entries in XML or packed form (database.cc 158–300,
//! 449–912, 1680–1730; spec 4.11).

use bk_core::{Address, RangeList};
use bk_decomp_types::entry::{decode_integer_format, encode_integer_format};
use bk_decomp_types::{Metatype, TypeFactory};
use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_FORMAT, ATTRIB_HIDDENRETPARM, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_INDIRECTSTORAGE, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_THISPTR,
    ATTRIB_TYPELOCK, ATTRIB_VAL, ELEM_SYMBOL, ELEM_VALUE,
};
use bk_marshal::{Decoder, Encoder};

use super::FunctionCodec;
use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::{VarnodeFlags, category, disp, entry_props};
use crate::ids::{
    ATTRIB_ADDRTIED, ATTRIB_CAT, ATTRIB_FIELD, ATTRIB_LABEL, ATTRIB_MERGE, ATTRIB_VOLATILE,
    ELEM_EQUATESYMBOL, ELEM_EXTERNREFSYMBOL, ELEM_FACETSYMBOL, ELEM_FUNCTION, ELEM_FUNCTIONSHELL,
    ELEM_HASH, ELEM_LABELSYM, ELEM_MAPSYM, EntryId, ScopeId, SymbolId,
};
use crate::model::{EntryData, EntryKind, Handle, SymbolData, SymbolKind};
use crate::scope::add::ID_BASE;

impl Database {
    /// Ghidra `Symbol::encodeHeader`.
    fn encode_header(&self, sym: &SymbolData, enc: &mut dyn Encoder) -> Result<()> {
        enc.write_string(ATTRIB_NAME, &sym.name)?;
        enc.write_unsigned(ATTRIB_ID, sym.ghidra_id);
        let f = sym.flags;
        let pairs = [
            (VarnodeFlags::NAMELOCK, ATTRIB_NAMELOCK),
            (VarnodeFlags::TYPELOCK, ATTRIB_TYPELOCK),
            (VarnodeFlags::READONLY, ATTRIB_READONLY),
            (VarnodeFlags::VOLATILE, ATTRIB_VOLATILE),
            (VarnodeFlags::INDIRECTSTORAGE, ATTRIB_INDIRECTSTORAGE),
            (VarnodeFlags::HIDDENRETPARM, ATTRIB_HIDDENRETPARM),
        ];
        for (flag, attr) in pairs {
            if f.contains(flag) {
                enc.write_bool(attr, true);
            }
        }
        if sym.disp & disp::ISOLATE != 0 {
            enc.write_bool(ATTRIB_MERGE, false);
        }
        if sym.disp & disp::IS_THIS_PTR != 0 {
            enc.write_bool(ATTRIB_THISPTR, true);
        }
        let format = sym.display_format();
        if format != 0 {
            enc.write_string(ATTRIB_FORMAT, decode_integer_format(format)?)?;
        }
        enc.write_signed(ATTRIB_CAT, i64::from(sym.category));
        if sym.category >= 0 {
            enc.write_unsigned(ATTRIB_INDEX, u64::from(sym.catindex));
        }
        Ok(())
    }

    /// Ghidra `Symbol::encode` and its overrides.
    pub fn encode_symbol(
        &self,
        id: SymbolId,
        enc: &mut dyn Encoder,
        types: &TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<()> {
        let sym = self.symbol(id)?;
        match &sym.kind {
            SymbolKind::Plain => {
                enc.open_element(ELEM_SYMBOL);
                self.encode_header(sym, enc)?;
                types.encode_ref(enc, sym.ty)?;
                enc.close_element(ELEM_SYMBOL);
            }
            SymbolKind::Equate { value } => {
                enc.open_element(ELEM_EQUATESYMBOL);
                self.encode_header(sym, enc)?;
                enc.open_element(ELEM_VALUE);
                enc.write_unsigned(ATTRIB_CONTENT, *value);
                enc.close_element(ELEM_VALUE);
                enc.close_element(ELEM_EQUATESYMBOL);
            }
            SymbolKind::UnionFacet { field, .. } => {
                enc.open_element(ELEM_FACETSYMBOL);
                self.encode_header(sym, enc)?;
                enc.write_signed(ATTRIB_FIELD, i64::from(*field));
                enc.write_bool(ATTRIB_ADDRTIED, true);
                types.encode_ref(enc, sym.ty)?;
                enc.close_element(ELEM_FACETSYMBOL);
            }
            SymbolKind::Label => {
                enc.open_element(ELEM_LABELSYM);
                self.encode_header(sym, enc)?;
                enc.close_element(ELEM_LABELSYM);
            }
            SymbolKind::ExternRef { ref_addr } => {
                enc.open_element(ELEM_EXTERNREFSYMBOL);
                enc.write_string(ATTRIB_NAME, &sym.name)?;
                ref_addr.encode(enc, &self.env.spaces)?;
                enc.close_element(ELEM_EXTERNREFSYMBOL);
            }
            SymbolKind::Function { .. } => {
                let written = match codec {
                    Some(c) => c.encode(self, id, enc)?,
                    None => false,
                };
                if !written {
                    enc.open_element(ELEM_FUNCTIONSHELL);
                    enc.write_string(ATTRIB_NAME, &sym.name)?;
                    if sym.ghidra_id != 0 {
                        enc.write_unsigned(ATTRIB_ID, sym.ghidra_id);
                    }
                    enc.close_element(ELEM_FUNCTIONSHELL);
                }
            }
        }
        Ok(())
    }

    /// Ghidra `SymbolEntry::encode` (each kind's form; pieces write
    /// nothing).
    pub fn encode_entry(&self, id: EntryId, enc: &mut dyn Encoder) -> Result<()> {
        let e = self.entry(id)?;
        let spaces = &self.env.spaces;
        match e.kind {
            EntryKind::Map { .. } | EntryKind::Dynamic { .. } if e.is_piece() => return Ok(()),
            EntryKind::Map {
                addr,
                conflict: None,
            } => addr.encode(enc, spaces)?,
            EntryKind::Map {
                conflict: Some(_), ..
            } => {
                enc.open_element(ELEM_HASH);
                enc.write_unsigned(ATTRIB_VAL, 0);
                enc.close_element(ELEM_HASH);
            }
            EntryKind::Dynamic { hash } => {
                enc.open_element(ELEM_HASH);
                enc.write_unsigned(ATTRIB_VAL, hash);
                enc.close_element(ELEM_HASH);
            }
            EntryKind::Unassigned => {
                enc.open_element(bk_core::ids::ELEM_ADDR);
                enc.close_element(bk_core::ids::ELEM_ADDR);
            }
        }
        e.use_limit.encode(enc, spaces)?;
        Ok(())
    }

    /// One `<mapsym>`: the symbol and its entries.
    pub fn encode_mapsym(
        &self,
        id: SymbolId,
        enc: &mut dyn Encoder,
        types: &TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<()> {
        enc.open_element(ELEM_MAPSYM);
        self.encode_symbol(id, enc, types, codec)?;
        for &entry in &self.symbol(id)?.entries {
            self.encode_entry(entry, enc)?;
        }
        enc.close_element(ELEM_MAPSYM);
        Ok(())
    }

    /// Ghidra `Symbol::decodeHeader`: the attributes of a symbol element.
    fn decode_header(&self, sym: &mut SymbolData, dec: &mut dyn Decoder<'_>) -> Result<()> {
        sym.name = "".into();
        sym.display_name = "".into();
        sym.category = category::NONE;
        sym.ghidra_id = 0;
        let mut display = String::new();
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_CAT {
                sym.category = dec.read_signed()? as i16;
            } else if attr == ATTRIB_FORMAT {
                sym.disp |= encode_integer_format(dec.read_string()?)?;
            } else if attr == ATTRIB_HIDDENRETPARM {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::HIDDENRETPARM;
                }
            } else if attr == ATTRIB_ID {
                let id = dec.read_unsigned()?;
                sym.ghidra_id = if id >> 56 == ID_BASE >> 56 { 0 } else { id };
            } else if attr == ATTRIB_INDIRECTSTORAGE {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::INDIRECTSTORAGE;
                }
            } else if attr == ATTRIB_MERGE {
                if !dec.read_bool()? {
                    sym.disp |= disp::ISOLATE;
                    sym.flags |= VarnodeFlags::TYPELOCK;
                }
            } else if attr == ATTRIB_NAME {
                sym.name = check_name(dec.read_string()?)?.into();
            } else if attr == ATTRIB_NAMELOCK {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::NAMELOCK;
                }
            } else if attr == ATTRIB_READONLY {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::READONLY;
                }
            } else if attr == ATTRIB_TYPELOCK {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::TYPELOCK;
                }
            } else if attr == ATTRIB_THISPTR {
                if dec.read_bool()? {
                    sym.disp |= disp::IS_THIS_PTR;
                }
            } else if attr == ATTRIB_VOLATILE {
                if dec.read_bool()? {
                    sym.flags |= VarnodeFlags::VOLATILE;
                }
            } else if attr == ATTRIB_LABEL {
                display = check_name(dec.read_string()?)?.to_owned();
            }
        }
        sym.catindex = if sym.category == category::FUNCTION_PARAMETER {
            u32::try_from(dec.read_unsigned_attr(ATTRIB_INDEX)?)
                .map_err(|_| SymbolError::Limit("category index"))?
        } else {
            0
        };
        sym.display_name = if display.is_empty() {
            sym.name.clone()
        } else {
            display.into()
        };
        Ok(())
    }

    fn set_decoded_type(
        &self,
        sym: &mut SymbolData,
        ty: bk_decomp_types::TypeId,
        types: &TypeFactory,
    ) -> Result<()> {
        let facts = crate::scope::add::type_facts(types, ty)?;
        sym.ty = ty;
        sym.type_size = facts.size;
        sym.type_unknown = facts.unknown;
        sym.primitive_whole = facts.primitive_whole;
        Ok(())
    }

    /// Decodes the symbol element inside a `<mapsym>` (Ghidra `addMapSym`'s
    /// choice of kind and `Symbol::decode` of each kind), without adding it.
    fn decode_symbol(
        &mut self,
        scope: ScopeId,
        dec: &mut dyn Decoder<'_>,
        types: &mut TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<SymbolData> {
        let kind = dec.peek_element();
        let unknown = types.base(1, Metatype::Unknown)?;
        let mut sym = self.new_symbol(scope, SymbolKind::Plain, "", unknown, types)?;
        sym.name_provenance = bk_core::Provenance::Analysis;
        if kind == Some(ELEM_SYMBOL.code()) {
            let el = dec.open_element_expecting(ELEM_SYMBOL)?;
            self.decode_header(&mut sym, dec)?;
            let ty = types.decode_type(dec)?;
            self.set_decoded_type(&mut sym, ty, types)?;
            sym.check_size_type_lock();
            dec.close_element(el)?;
        } else if kind == Some(ELEM_EQUATESYMBOL.code()) {
            let el = dec.open_element_expecting(ELEM_EQUATESYMBOL)?;
            self.decode_header(&mut sym, dec)?;
            let sub = dec.open_element_expecting(ELEM_VALUE)?;
            let value = dec.read_unsigned_attr(ATTRIB_CONTENT)?;
            dec.close_element(sub)?;
            sym.kind = SymbolKind::Equate { value };
            dec.close_element(el)?;
        } else if kind == Some(ELEM_FUNCTION.code()) {
            let codec = codec.ok_or(SymbolError::NoFunctionCodec)?;
            let decoded = codec.decode(self, scope, dec)?;
            let code = types.type_code()?;
            self.set_decoded_type(&mut sym, code, types)?;
            let mut consume = self.env.min_funcsymbol_size;
            if consume < decoded.size && decoded.size > 1 && decoded.size <= 8 {
                consume = decoded.size;
            }
            sym.kind = SymbolKind::Function {
                consume_size: consume,
            };
            sym.flags |= VarnodeFlags::NAMELOCK | VarnodeFlags::TYPELOCK;
            sym.name = decoded.name.into();
            sym.display_name = decoded.display_name.into();
            sym.ghidra_id = decoded.ghidra_id;
        } else if kind == Some(ELEM_FUNCTIONSHELL.code()) {
            let el = dec.open_element_expecting(ELEM_FUNCTIONSHELL)?;
            let code = types.type_code()?;
            self.set_decoded_type(&mut sym, code, types)?;
            sym.kind = SymbolKind::Function {
                consume_size: self.env.min_funcsymbol_size,
            };
            sym.flags |= VarnodeFlags::NAMELOCK | VarnodeFlags::TYPELOCK;
            sym.ghidra_id = 0;
            let mut display = String::new();
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_NAME {
                    sym.name = check_name(dec.read_string()?)?.into();
                } else if attr == ATTRIB_ID {
                    sym.ghidra_id = dec.read_unsigned()?;
                } else if attr == ATTRIB_LABEL {
                    display = check_name(dec.read_string()?)?.to_owned();
                }
            }
            sym.display_name = if display.is_empty() {
                sym.name.clone()
            } else {
                display.into()
            };
            dec.close_element(el)?;
        } else if kind == Some(ELEM_LABELSYM.code()) {
            let el = dec.open_element_expecting(ELEM_LABELSYM)?;
            self.decode_header(&mut sym, dec)?;
            sym.kind = SymbolKind::Label;
            dec.close_element(el)?;
        } else if kind == Some(ELEM_EXTERNREFSYMBOL.code()) {
            let el = dec.open_element_expecting(ELEM_EXTERNREFSYMBOL)?;
            let mut name = String::new();
            let mut display = String::new();
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_NAME {
                    name = check_name(dec.read_string()?)?.to_owned();
                } else if attr == ATTRIB_LABEL {
                    display = check_name(dec.read_string()?)?.to_owned();
                }
            }
            let ref_addr = Address::decode(dec, &self.env.spaces)?;
            dec.close_element(el)?;
            sym = self.new_extern_ref(scope, ref_addr, &name, &display, types)?;
        } else if kind == Some(ELEM_FACETSYMBOL.code()) {
            let el = dec.open_element_expecting(ELEM_FACETSYMBOL)?;
            self.decode_header(&mut sym, dec)?;
            let field = dec.read_signed_attr(ATTRIB_FIELD)?;
            let addr_based = dec.read_bool_attr(ATTRIB_ADDRTIED)?;
            let ty = types.decode_type(dec)?;
            self.set_decoded_type(&mut sym, ty, types)?;
            sym.check_size_type_lock();
            dec.close_element(el)?;
            let mut test = ty;
            if let Some(p) = types.get(ty).and_then(|e| e.pointer()) {
                test = p.ptrto;
            }
            let entry = types.entry_checked(test)?;
            if entry.metatype() != Metatype::Union {
                return Err(SymbolError::FacetNotUnion);
            }
            let depend = types.num_depend(test) as i64;
            if field < -1 || field >= depend {
                return Err(SymbolError::FacetField);
            }
            sym.kind = SymbolKind::UnionFacet {
                field: field as i32,
                addr_based,
            };
        } else {
            return Err(SymbolError::UnknownSymbolType);
        }
        Ok(sym)
    }

    /// Ghidra `Scope::addMapSym`: decodes a `<mapsym>` into the scope. A
    /// failure while adding its entries prints `Throwing out symbol with
    /// invalid mapping: <name>`, removes the symbol and yields `None`.
    pub fn add_map_sym(
        &mut self,
        scope: ScopeId,
        dec: &mut dyn Decoder<'_>,
        types: &mut TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<Option<SymbolId>> {
        let el = dec.open_element_expecting(ELEM_MAPSYM)?;
        let sym = self.decode_symbol(scope, dec, types, codec)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        let entries = self.decode_entries(scope, sym, dec);
        let result = match entries {
            Ok(()) => Some(sym),
            Err(_) => {
                let name = self.symbol(sym)?.name.to_string();
                self.warn(format!("Throwing out symbol with invalid mapping: {name}"));
                self.remove_symbol(sym)?;
                None
            }
        };
        dec.close_element(el)?;
        Ok(result)
    }

    fn decode_entries(
        &mut self,
        scope: ScopeId,
        sym: SymbolId,
        dec: &mut dyn Decoder<'_>,
    ) -> Result<()> {
        while let Some(child) = dec.peek_element() {
            if child == ELEM_HASH.code() {
                let el = dec.open_element_expecting(ELEM_HASH)?;
                let hash = dec.read_unsigned_attr(ATTRIB_VAL)?;
                dec.close_element(el)?;
                let mut use_limit = RangeList::default();
                use_limit.decode(dec, &self.env.spaces)?;
                let entry = EntryData {
                    symbol: sym,
                    kind: EntryKind::Dynamic { hash },
                    use_limit,
                    properties: entry_props::DYNAMIC_ENTRY,
                    extra_flags: VarnodeFlags::empty(),
                    offset: 0,
                    size: -1,
                    handle: Handle::None,
                    live: true,
                };
                self.add_dynamic(scope, entry)?;
            } else {
                let addr = Address::decode(dec, &self.env.spaces)?;
                let mut use_limit = RangeList::default();
                use_limit.decode(dec, &self.env.spaces)?;
                let mut entry = Self::map_entry(sym, addr, Address::INVALID);
                entry.use_limit = use_limit;
                self.add_map(scope, entry)?;
            }
        }
        Ok(())
    }
}

/// Names longer than the limit are refused (ADR-009).
fn check_name(name: &str) -> Result<&str> {
    if name.len() > crate::error::limits::MAX_NAME {
        return Err(SymbolError::Limit("name length"));
    }
    Ok(name)
}
