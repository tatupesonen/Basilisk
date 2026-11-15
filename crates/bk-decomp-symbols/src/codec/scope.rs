//! Scopes and the whole database in XML or packed form (database.cc
//! 2801–2974, 3458–3617; spec 4.11).

use bk_core::{Range, RangeList, VarnodeData};
use bk_decomp_types::{Metatype, TypeFactory};
use bk_marshal::ids::{ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_READONLY, ATTRIB_VAL, ELEM_VAL};
use bk_marshal::{Decoder, Encoder};

use super::FunctionCodec;
use crate::database::Database;
use crate::error::{Result, SymbolError, limits};
use crate::flags::{VarnodeFlags, category};
use crate::ids::{
    ATTRIB_LABEL, ATTRIB_SCOPEIDBYNAME, ATTRIB_VOLATILE, ELEM_COLLISION, ELEM_DB, ELEM_HOLE,
    ELEM_MAPSYM, ELEM_PARENT, ELEM_PROPERTY_CHANGEPOINT, ELEM_RANGEEQUALSSYMBOLS, ELEM_SCOPE,
    ELEM_SYMBOLLIST, ScopeId,
};
use crate::model::ScopeKind;

impl Database {
    /// Ghidra `ScopeInternal::encode`: `<scope name id>`, `<parent>`, the
    /// owned ranges and the symbols in name order (union facets skipped).
    /// It can be called inside a wrapper element the caller opened.
    pub fn encode_scope(
        &self,
        scope: ScopeId,
        enc: &mut dyn Encoder,
        types: &TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<()> {
        let data = self.scope(scope)?;
        enc.open_element(ELEM_SCOPE);
        enc.write_string(ATTRIB_NAME, &data.name)?;
        enc.write_unsigned(ATTRIB_ID, data.ghidra_id);
        if let Some(parent) = data.parent {
            enc.open_element(ELEM_PARENT);
            enc.write_unsigned(ATTRIB_ID, self.scope(parent)?.ghidra_id);
            enc.close_element(ELEM_PARENT);
        }
        data.ranges.encode(enc, &self.env.spaces)?;
        if !data.names.is_empty() {
            enc.open_element(ELEM_SYMBOLLIST);
            for &sym in data.names.values() {
                if self.symbol(sym)?.category == category::UNION_FACET {
                    continue;
                }
                self.encode_mapsym(sym, enc, types, codec)?;
            }
            enc.close_element(ELEM_SYMBOLLIST);
        }
        enc.close_element(ELEM_SCOPE);
        Ok(())
    }

    /// Ghidra `encodeRecursive(…, true)`: the scope and every non-function
    /// descendant, pre-order with children in id order.
    pub fn encode_recursive(
        &self,
        root: ScopeId,
        enc: &mut dyn Encoder,
        types: &TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<()> {
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            let data = self.scope(id)?;
            if !data.is_global() {
                continue;
            }
            self.encode_scope(id, enc, types, codec)?;
            for child in data.children.values().rev() {
                stack.push(*child);
            }
        }
        Ok(())
    }

    /// Ghidra `Database::encode`: `<db>`, the property change points, then
    /// the global scopes.
    pub fn encode(&self, enc: &mut dyn Encoder, types: &TypeFactory, codec: Option<&dyn FunctionCodec>) -> Result<()> {
        enc.open_element(ELEM_DB);
        if self.id_by_name_hash {
            enc.write_bool(ATTRIB_SCOPEIDBYNAME, true);
        }
        for (addr, value) in self.property_points() {
            // A split point past the last space (Ghidra's maximal address,
            // which it would dereference) has no space to write.
            let Some(space) = addr.space() else { continue };
            enc.open_element(ELEM_PROPERTY_CHANGEPOINT);
            self.env.spaces.encode_attributes(enc, space, addr.offset())?;
            enc.write_unsigned(ATTRIB_VAL, u64::from(value));
            enc.close_element(ELEM_PROPERTY_CHANGEPOINT);
        }
        if let Some(global) = self.global {
            self.encode_recursive(global, enc, types, codec)?;
        }
        enc.close_element(ELEM_DB);
        Ok(())
    }

    /// Ghidra `ScopeInternal::decode`: the body of a `<scope>` after its
    /// attributes (`<parent>` skipped, ranges, symbols, holes, collisions).
    pub fn decode_scope_body(
        &mut self,
        scope: ScopeId,
        dec: &mut dyn Decoder<'_>,
        types: &mut TypeFactory,
        codec: Option<&dyn FunctionCodec>,
    ) -> Result<()> {
        let mut range_equals_symbols = false;
        let mut sub = dec.peek_element();
        if sub == Some(ELEM_PARENT.code()) {
            dec.skip_element()?;
            sub = dec.peek_element();
        }
        if sub == Some(bk_core::ids::ELEM_RANGELIST.code()) {
            let mut ranges = RangeList::default();
            ranges.decode(dec, &self.env.spaces)?;
            self.set_range(scope, ranges)?;
        } else if sub == Some(ELEM_RANGEEQUALSSYMBOLS.code()) {
            let el = dec.open_element_expecting(ELEM_RANGEEQUALSSYMBOLS)?;
            dec.close_element(el)?;
            range_equals_symbols = true;
        }
        if dec.peek_element().is_some() {
            let list = dec.open_element_expecting(ELEM_SYMBOLLIST)?;
            while let Some(child) = dec.peek_element() {
                if child == ELEM_MAPSYM.code() {
                    let Some(sym) = self.add_map_sym(scope, dec, types, codec)? else {
                        // Ghidra dereferences the thrown-out symbol here.
                        continue;
                    };
                    let first = self.symbol(sym)?.entries.first().copied();
                    let map_range = first
                        .and_then(|e| self.entry(e).ok())
                        .filter(|e| e.is_map_entry())
                        .and_then(|e| Some(Range::new(e.addr()?.space()?, e.addr()?.offset(), e.last_offset()?)));
                    if range_equals_symbols && let Some(r) = map_range {
                        self.add_range(scope, r.space(), r.first(), r.last())?;
                    }
                    let props = self.symbol(sym)?.flags & (VarnodeFlags::READONLY | VarnodeFlags::VOLATILE);
                    if !props.is_empty() && let Some(r) = map_range {
                        self.set_property_range(props, &r);
                    }
                } else if child == ELEM_HOLE.code() {
                    self.decode_hole(dec)?;
                } else if child == ELEM_COLLISION.code() {
                    self.decode_collision(scope, dec, types)?;
                } else {
                    return Err(SymbolError::UnknownSymbollistTag);
                }
            }
            dec.close_element(list)?;
        }
        self.category_sanity(scope)
    }

    /// Ghidra `decodeHole`: a range with `readonly`/`volatile` properties.
    fn decode_hole(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_HOLE)?;
        let range = Range::decode_from_attributes(dec, &self.env.spaces)?;
        dec.rewind_attributes();
        let mut flags = VarnodeFlags::empty();
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_READONLY && dec.read_bool()? {
                flags |= VarnodeFlags::READONLY;
            } else if attr == ATTRIB_VOLATILE && dec.read_bool()? {
                flags |= VarnodeFlags::VOLATILE;
            }
        }
        if !flags.is_empty() {
            self.set_property_range(flags, &range);
        }
        dec.close_element(el)?;
        Ok(())
    }

    /// Ghidra `decodeCollision`: an unmapped one-byte `int` of that name,
    /// unless one exists.
    fn decode_collision(&mut self, scope: ScopeId, dec: &mut dyn Decoder<'_>, types: &mut TypeFactory) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_COLLISION)?;
        let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
        dec.close_element(el)?;
        if !self.name_exists(scope, &name) {
            let ty = types.base(1, Metatype::Int)?;
            self.add_symbol(scope, &name, ty, types)?;
        }
        Ok(())
    }

    fn parse_parent_tag(&self, dec: &mut dyn Decoder<'_>) -> Result<ScopeId> {
        let el = dec.open_element_expecting(ELEM_PARENT)?;
        let id = dec.read_unsigned_attr(ATTRIB_ID)?;
        let scope = self.resolve_scope_id(id).ok_or(SymbolError::NoScopeMatchingId)?;
        dec.close_element(el)?;
        Ok(scope)
    }

    /// Ghidra `Database::decode`: a `<db>` element.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, types: &mut TypeFactory, codec: Option<&dyn FunctionCodec>) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_DB)?;
        self.id_by_name_hash = false;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_SCOPEIDBYNAME {
                self.id_by_name_hash = dec.read_bool()?;
            }
        }
        while dec.peek_element() == Some(ELEM_PROPERTY_CHANGEPOINT.code()) {
            let sub = dec.open_element_expecting(ELEM_PROPERTY_CHANGEPOINT)?;
            let value = dec.read_unsigned_attr(ATTRIB_VAL)? as u32;
            let vdata = VarnodeData::decode_from_attributes(dec, &self.env.spaces)?;
            dec.close_element(sub)?;
            self.set_property_point(vdata.addr(), value);
        }
        while dec.peek_element() == Some(ELEM_SCOPE.code()) {
            let sub = dec.open_element_expecting(ELEM_SCOPE)?;
            let mut name = String::new();
            let mut display = String::new();
            let mut id = 0u64;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_NAME {
                    name = dec.read_string()?.to_owned();
                } else if attr == ATTRIB_ID {
                    id = dec.read_unsigned()?;
                } else if attr == ATTRIB_LABEL {
                    display = dec.read_string()?.to_owned();
                }
            }
            let parent = if dec.peek_element() == Some(ELEM_PARENT.code()) {
                Some(self.parse_parent_tag(dec)?)
            } else {
                None
            };
            let scope = self.find_create_scope(id, &name, parent)?;
            if !display.is_empty() {
                self.scope_mut(scope)?.display_name = display.into();
            }
            self.decode_scope_body(scope, dec, types, codec)?;
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(())
    }

    /// Ghidra `Database::decodeScope`: a `<scope>`, or a wrapper element
    /// whose attributes go to `wrapping` around one, attached as a new scope
    /// of the given name, id and kind under its `<parent>`.
    pub fn decode_scope(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        name: &str,
        ghidra_id: u64,
        kind: ScopeKind,
        types: &mut TypeFactory,
        codec: Option<&dyn FunctionCodec>,
        wrapping: &mut dyn FnMut(&mut dyn Decoder<'_>) -> Result<()>,
    ) -> Result<ScopeId> {
        let el = dec.open_element()?.ok_or(SymbolError::Decode(bk_marshal::DecodeError::NoElement {
            expected: "scope",
        }))?;
        let scope;
        if el == ELEM_SCOPE.code() {
            let parent = self.parse_parent_tag(dec)?;
            scope = self.attach_scope(name, ghidra_id, Some(parent), kind)?;
            self.decode_scope_body(scope, dec, types, codec)?;
        } else {
            wrapping(dec)?;
            let sub = dec.open_element_expecting(ELEM_SCOPE)?;
            let parent = self.parse_parent_tag(dec)?;
            scope = self.attach_scope(name, ghidra_id, Some(parent), kind)?;
            self.decode_scope_body(scope, dec, types, codec)?;
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(scope)
    }

    /// Ghidra `decodeScopePath`: a `<parent>` of `<val id label>name</val>`
    /// after a skipped root element; each namespace found or created.
    pub fn decode_scope_path(&mut self, dec: &mut dyn Decoder<'_>) -> Result<ScopeId> {
        let mut cur = self.global_scope()?;
        let el = dec.open_element_expecting(ELEM_PARENT)?;
        if let Some(root) = dec.open_element()? {
            dec.close_element_skipping(root)?;
        }
        let mut depth = 0;
        while dec.peek_element() == Some(ELEM_VAL.code()) {
            depth += 1;
            if depth > limits::MAX_PATH {
                return Err(SymbolError::Limit("namespace path length"));
            }
            let sub = dec.open_element_expecting(ELEM_VAL)?;
            let mut display = String::new();
            let mut id = 0u64;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_ID {
                    id = dec.read_unsigned()?;
                } else if attr == ATTRIB_LABEL {
                    display = dec.read_string()?.to_owned();
                }
            }
            let name = dec.read_string_attr(ATTRIB_CONTENT)?.to_owned();
            if id == 0 {
                return Err(SymbolError::MissingScopeId);
            }
            cur = self.find_create_scope(id, &name, Some(cur))?;
            if !display.is_empty() {
                self.scope_mut(cur)?.display_name = display.into();
            }
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(cur)
    }
}
