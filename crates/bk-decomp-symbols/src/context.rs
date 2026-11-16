//! Named context variables, tracked-register look-ups and the
//! `<context_points>` / `<context_data>` XML over the context store
//! (`bk_context::ContextDb`; Ghidra `ContextDatabase` and `ContextInternal`
//! in globalcontext.cc; spec 4.16, ADR-043).

use std::collections::BTreeMap;

use bk_context::{ContextDb, ContextVar, OffsetRange, TrackedValue};
use bk_core::{Address, Range, SpaceManager, VarnodeData};
use bk_marshal::ids::{ATTRIB_NAME, ATTRIB_VAL};
use bk_marshal::{Decoder, Encoder};

use crate::error::{Result, SymbolError, limits};
use crate::ids::{
    ELEM_CONTEXT_DATA, ELEM_CONTEXT_POINTS, ELEM_CONTEXT_POINTSET, ELEM_CONTEXT_SET, ELEM_SET,
    ELEM_TRACKED_POINTSET, ELEM_TRACKED_SET,
};

/// The context database with Ghidra's variable names (Ghidra
/// `ContextInternal` seen through `ContextDatabase`).
#[derive(Clone, Debug)]
pub struct ContextNames {
    vars: BTreeMap<String, ContextVar>,
    db: ContextDb,
}

impl Default for ContextNames {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextNames {
    /// An empty database of no words.
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
            db: ContextDb::new(0),
        }
    }

    /// Sets the highest offset of each space (for the bounds of
    /// [`context`](Self::context)).
    pub fn set_space_limits(&mut self, spaces: &SpaceManager) {
        self.db
            .set_space_limits(spaces.spaces().map(bk_core::Space::highest).collect());
    }

    /// The store.
    pub fn db(&self) -> &ContextDb {
        &self.db
    }

    /// The store, to change it (the decoder's `globalset` writes go here).
    pub fn db_mut(&mut self) -> &mut ContextDb {
        &mut self.db
    }

    /// The number of context words (Ghidra `getContextSize`).
    pub fn size(&self) -> usize {
        self.db.size()
    }

    /// The variables in name order.
    pub fn variables(&self) -> impl Iterator<Item = (&str, &ContextVar)> {
        self.vars.iter().map(|(n, v)| (n.as_str(), v))
    }

    /// Ghidra `registerVariable`: bits `sbit..=ebit`, most significant
    /// first.
    pub fn register_variable(&mut self, name: &str, sbit: u32, ebit: u32) -> Result<()> {
        if self.db.has_split_points() {
            return Err(SymbolError::ContextInitialized);
        }
        let var = ContextVar::new(name, sbit, ebit).ok_or(SymbolError::ContextWord)?;
        let size = (sbit / 32) as usize + 1;
        if size > limits::MAX_CONTEXT_WORDS {
            return Err(SymbolError::Limit("context words"));
        }
        if size > self.db.size() {
            self.db.grow(size);
        }
        self.vars.insert(name.to_owned(), var);
        Ok(())
    }

    /// A variable by name (Ghidra `getVariable`).
    pub fn variable(&self, name: &str) -> Result<&ContextVar> {
        self.vars
            .get(name)
            .ok_or_else(|| SymbolError::UnknownContextVariable {
                name: name.to_owned(),
            })
    }

    /// Ghidra `setVariableDefault`.
    pub fn set_variable_default(&mut self, name: &str, value: u32) -> Result<()> {
        let var = self.variable(name)?.clone();
        self.db.set_variable_default(&var, value);
        Ok(())
    }

    /// Ghidra `getDefaultValue(name)`.
    pub fn default_value(&self, name: &str) -> Result<u32> {
        Ok(self.variable(name)?.get(self.db.default_words()))
    }

    /// Ghidra `setVariable` (the flowing set).
    pub fn set_variable(&mut self, name: &str, addr: Address, value: u32) -> Result<()> {
        let var = self.variable(name)?.clone();
        self.db.set_variable(&var, addr, value);
        Ok(())
    }

    /// Ghidra `getVariable(name, addr)`.
    pub fn variable_at(&self, name: &str, addr: Address) -> Result<u32> {
        Ok(self.db.variable(self.variable(name)?, addr))
    }

    /// Ghidra `setVariableRegion` (to the end when `end` is `None`).
    pub fn set_variable_region(
        &mut self,
        name: &str,
        first: Address,
        end: Option<Address>,
        value: u32,
    ) -> Result<()> {
        let var = self.variable(name)?.clone();
        self.db.set_variable_region(&var, first, end, value);
        Ok(())
    }

    /// Ghidra `setContextChangePoint` (value `ORed` in unmasked).
    pub fn set_context_change_point(&mut self, addr: Address, word: usize, mask: u32, value: u32) {
        self.db.change_point(addr, word, mask, value);
    }

    /// Ghidra `getContext(addr, first, last)`.
    pub fn context(&self, addr: Address) -> (&[u32], OffsetRange) {
        self.db.get_with_range(addr)
    }

    /// Ghidra `createSet(a1, a2)` filled with `values`.
    pub fn create_set(&mut self, first: Address, end: Address, values: Vec<TrackedValue>) {
        self.db.set_tracked(first, end, values);
    }

    /// Ghidra `getTrackedValue(mem, point)`.
    pub fn tracked_value(&self, mem: VarnodeData, point: Address) -> u64 {
        match mem.space() {
            Some(space) => self.db.tracked_value(space, mem.offset, mem.size, point),
            None => 0,
        }
    }

    /// Ghidra `ContextInternal::encode`: nothing when there are no split
    /// points at all (returns `false`), else `<context_points>`.
    pub fn encode(&self, enc: &mut dyn Encoder, spaces: &SpaceManager) -> Result<bool> {
        let tracked: Vec<_> = self.db.tracked_points().collect();
        if !self.db.has_split_points() && tracked.is_empty() {
            return Ok(false);
        }
        enc.open_element(ELEM_CONTEXT_POINTS);
        for (addr, values, _) in self.db.split_points() {
            enc.open_element(ELEM_CONTEXT_POINTSET);
            if let Some(space) = addr.space() {
                spaces.encode_attributes(enc, space, addr.offset())?;
            }
            for (name, var) in &self.vars {
                enc.open_element(ELEM_SET);
                enc.write_string(ATTRIB_NAME, name)?;
                enc.write_unsigned(ATTRIB_VAL, u64::from(var.get(values)));
                enc.close_element(ELEM_SET);
            }
            enc.close_element(ELEM_CONTEXT_POINTSET);
        }
        for (addr, set) in tracked {
            if set.is_empty() {
                continue;
            }
            enc.open_element(ELEM_TRACKED_POINTSET);
            if let Some(space) = addr.space() {
                spaces.encode_attributes(enc, space, addr.offset())?;
            }
            for t in set {
                enc.open_element(ELEM_SET);
                spaces.encode_attributes_sized(enc, t.space, t.offset, t.size)?;
                enc.write_unsigned(ATTRIB_VAL, t.value);
                enc.close_element(ELEM_SET);
            }
            enc.close_element(ELEM_TRACKED_POINTSET);
        }
        enc.close_element(ELEM_CONTEXT_POINTS);
        Ok(true)
    }

    /// Ghidra `decodeContext`: `<set name val>` children from `first` to
    /// `end`, or into the default when `first` is `None`. Basilisk zeroes
    /// the default once per element (Ghidra zeroes it before every `<set>`,
    /// so only the last variable survived; ADR-045).
    fn decode_sets(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        first: Option<Address>,
        end: Option<Address>,
    ) -> Result<()> {
        if first.is_none() {
            for word in 0..self.db.size() {
                self.db.set_default(word, u32::MAX, 0);
            }
        }
        while dec.peek_element() == Some(ELEM_SET.code()) {
            let el = dec.open_element_expecting(ELEM_SET)?;
            let value = dec.read_unsigned_attr(ATTRIB_VAL)? as u32;
            let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
            let var = self.variable(&name)?.clone();
            match first {
                None => self.db.set_variable_default(&var, value),
                Some(addr) => self.db.set_variable_region(&var, addr, end, value),
            }
            dec.close_element(el)?;
        }
        Ok(())
    }

    /// Ghidra `decodeTracked`: `<set space offset size val>` children.
    fn decode_tracked(
        dec: &mut dyn Decoder<'_>,
        spaces: &SpaceManager,
    ) -> Result<Vec<TrackedValue>> {
        let mut out = Vec::new();
        while dec.peek_element().is_some() {
            let el = dec.open_element_expecting(ELEM_SET)?;
            let loc = VarnodeData::decode_from_attributes(dec, spaces)?;
            let value = dec.read_unsigned_attr(ATTRIB_VAL)?;
            dec.close_element(el)?;
            let Some(space) = loc.space() else { continue };
            let big_endian = spaces
                .space(space)
                .is_some_and(bk_core::Space::is_big_endian);
            out.push(TrackedValue {
                space,
                offset: loc.offset,
                size: loc.size,
                big_endian,
                value,
            });
        }
        Ok(out)
    }

    /// Ghidra `ContextInternal::decode`: a `<context_points>` element.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, spaces: &SpaceManager) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_CONTEXT_POINTS)?;
        while let Some(sub) = dec.open_element()? {
            if sub == ELEM_CONTEXT_POINTSET.code() {
                let has_attr = dec.next_attribute()?.is_some();
                dec.rewind_attributes();
                if has_attr {
                    let v = VarnodeData::decode_from_attributes(dec, spaces)?;
                    self.decode_sets(dec, Some(v.addr()), None)?;
                } else {
                    self.decode_sets(dec, None, None)?;
                }
            } else if sub == ELEM_TRACKED_POINTSET.code() {
                let v = VarnodeData::decode_from_attributes(dec, spaces)?;
                let set = Self::decode_tracked(dec, spaces)?;
                self.db.set_tracked_at(v.addr(), set);
            } else {
                return Err(SymbolError::ContextPointsTag);
            }
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(())
    }

    /// Ghidra `ContextInternal::decodeFromSpec`: a `<context_data>` element
    /// of a `.pspec` or `.cspec`.
    pub fn decode_from_spec(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        spaces: &SpaceManager,
    ) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_CONTEXT_DATA)?;
        while let Some(sub) = dec.open_element()? {
            let range = Range::decode_from_attributes(dec, spaces)?;
            let first = range.first_addr();
            let end = range.last_addr_open(spaces);
            if sub == ELEM_CONTEXT_SET.code() {
                self.decode_sets(dec, Some(first), Some(end))?;
            } else if sub == ELEM_TRACKED_SET.code() {
                let set = Self::decode_tracked(dec, spaces)?;
                self.db.set_tracked(first, end, set);
            } else {
                return Err(SymbolError::ContextDataTag);
            }
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(())
    }
}
