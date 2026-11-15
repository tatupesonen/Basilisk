//! What the architecture puts into the symbol table and property map, as
//! functions over a [`Database`] named after Ghidra's (architecture.cc
//! 335–357, 436–447, 813–925, 1160–1415; sleigh_arch.cc 265–300; spec
//! 4.18). D07 calls them in Ghidra's order:
//!
//! 1. while reading the `.pspec`: [`decode_volatile`],
//!    [`decode_incidental_copy`], [`decode_register_data`] (and the context
//!    store reads `<context_data>`);
//! 2. while reading the `.cspec`: [`decode_readonly`], [`decode_global`]
//!    (collected), then [`add_to_global_scope`] for each and
//!    [`add_other_space`];
//! 3. [`Database::adjust_caches`];
//! 4. [`build_default_symbols`] (the `.pspec`'s `<default_symbols>`);
//! 5. [`fill_readonly_from_image`]; for data tests [`read_loader_symbols`];
//!    for the console's `global spaces` [`globalify`].

use bk_core::{Address, Range, RangeProperties, SpaceType, VarnodeData};
use bk_decomp_types::{Metatype, TypeFactory};
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_NAME, ATTRIB_SIZE};

use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::VarnodeFlags;
use crate::ids::{
    ATTRIB_ADDRESS, ATTRIB_VECTOR_LANE_SIZES, ATTRIB_VOLATILE, ELEM_DEFAULT_SYMBOLS, ELEM_GLOBAL,
    ELEM_INCIDENTALCOPY, ELEM_READONLY, ELEM_REGISTER_DATA, ELEM_VOLATILE,
};
use crate::image::LoadImage;

/// Ghidra `decodeVolatile`: each range of a `<volatile>` element becomes
/// `volatil` (the user-op names are the user-op table's).
pub fn decode_volatile(db: &mut Database, dec: &mut dyn Decoder<'_>) -> Result<()> {
    let el = dec.open_element_expecting(ELEM_VOLATILE)?;
    while dec.peek_element().is_some() {
        let range = Range::decode(dec, &db.env.spaces)?;
        db.set_property_range(VarnodeFlags::VOLATILE, &range);
    }
    dec.close_element(el)?;
    Ok(())
}

/// Ghidra `decodeIncidentalCopy`: each location becomes `incidental_copy`.
pub fn decode_incidental_copy(db: &mut Database, dec: &mut dyn Decoder<'_>) -> Result<()> {
    let el = dec.open_element_expecting(ELEM_INCIDENTALCOPY)?;
    while dec.peek_element().is_some() {
        let v = VarnodeData::decode(dec, &db.env.spaces)?;
        if let Some(space) = v.space() {
            let last = v.offset.wrapping_add(u64::from(v.size)).wrapping_sub(1);
            db.set_property_range(
                VarnodeFlags::INCIDENTAL_COPY,
                &Range::new(space, v.offset, last),
            );
        }
    }
    dec.close_element(el)?;
    Ok(())
}

/// Ghidra `decodeRegisterData`, the part for this crate: registers marked
/// `volatile` become `volatil` (laned registers are the function state's).
pub fn decode_register_data(db: &mut Database, dec: &mut dyn Decoder<'_>) -> Result<()> {
    let el = dec.open_element_expecting(ELEM_REGISTER_DATA)?;
    while dec.peek_element().is_some() {
        let sub = dec.open_element_expecting(bk_core::ids::ELEM_REGISTER)?;
        let mut is_volatile = false;
        let mut lanes = false;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_VECTOR_LANE_SIZES {
                lanes = !dec.read_string()?.is_empty();
            } else if attr == ATTRIB_VOLATILE {
                is_volatile = dec.read_bool()?;
            }
        }
        if lanes || is_volatile {
            dec.rewind_attributes();
            let v = VarnodeData::decode_from_attributes(dec, &db.env.spaces)?;
            if is_volatile && let Some(space) = v.space() {
                let last = v.offset.wrapping_add(u64::from(v.size)).wrapping_sub(1);
                db.set_property_range(VarnodeFlags::VOLATILE, &Range::new(space, v.offset, last));
            }
        }
        dec.close_element(sub)?;
    }
    dec.close_element(el)?;
    Ok(())
}

/// Ghidra `decodeReadOnly`: each range of a `<readonly>` element becomes
/// `readonly`.
pub fn decode_readonly(db: &mut Database, dec: &mut dyn Decoder<'_>) -> Result<()> {
    let el = dec.open_element_expecting(ELEM_READONLY)?;
    while dec.peek_element().is_some() {
        let range = Range::decode(dec, &db.env.spaces)?;
        db.set_property_range(VarnodeFlags::READONLY, &range);
    }
    dec.close_element(el)?;
    Ok(())
}

/// Ghidra `decodeGlobal`: the ranges of a `<global>` element, kept as
/// properties until the whole `.cspec` is read.
pub fn decode_global(dec: &mut dyn Decoder<'_>) -> Result<Vec<RangeProperties>> {
    let el = dec.open_element_expecting(ELEM_GLOBAL)?;
    let mut out = Vec::new();
    while dec.peek_element().is_some() {
        out.push(RangeProperties::decode(dec)?);
    }
    dec.close_element(el)?;
    Ok(out)
}

/// Ghidra `addToGlobalScope`: the range into the global scope, and into
/// every overlay of its space.
pub fn add_to_global_scope(db: &mut Database, props: &RangeProperties) -> Result<()> {
    let range = Range::from_properties(props, &db.env.spaces)?;
    add_range_with_overlays(db, range)
}

/// [`add_to_global_scope`] for a range already resolved.
pub fn add_range_with_overlays(db: &mut Database, range: Range) -> Result<()> {
    let global = db.global_scope()?;
    db.add_range(global, range.space(), range.first(), range.last())?;
    let spaces = std::sync::Arc::clone(&db.env.spaces);
    if spaces
        .space(range.space())
        .is_some_and(bk_core::Space::is_overlay_base)
    {
        for s in spaces.spaces() {
            if s.is_overlay() && s.contain() == Some(range.space()) {
                db.add_range(global, s.id(), range.first(), range.last())?;
            }
        }
    }
    Ok(())
}

/// Ghidra `addOtherSpace`: the whole OTHER space, and its overlays, into
/// the global scope.
pub fn add_other_space(db: &mut Database) -> Result<()> {
    let spaces = std::sync::Arc::clone(&db.env.spaces);
    let Some(other) = spaces.spaces().find(|s| s.is_other_space()) else {
        return Ok(());
    };
    let global = db.global_scope()?;
    db.add_range(global, other.id(), 0, other.highest())?;
    if other.is_overlay_base() {
        for s in spaces.spaces() {
            if s.is_overlay() && s.contain() == Some(other.id()) {
                db.add_range(global, s.id(), 0, other.highest())?;
            }
        }
    }
    Ok(())
}

/// Ghidra `SleighArchitecture::buildSymbols`: each `<symbol name address
/// [size] [volatile]>` of `<default_symbols>` (`address="next"`: the
/// previous symbol's address plus its size; size 0: the space's word size)
/// sets or clears `volatil` over it and goes into the global scope as an
/// undefined type of its size, with no use limit.
pub fn build_default_symbols(
    db: &mut Database,
    dec: &mut dyn Decoder<'_>,
    types: &mut TypeFactory,
) -> Result<()> {
    let el = dec.open_element_expecting(ELEM_DEFAULT_SYMBOLS)?;
    let mut last: Option<(Address, i64)> = None;
    while dec.peek_element().is_some() {
        let sub = dec.open_element_expecting(bk_marshal::ids::ELEM_SYMBOL)?;
        let mut addr = Address::INVALID;
        let mut name = String::new();
        let mut size: i64 = 0;
        let mut volatile: Option<bool> = None;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_NAME {
                name = dec.read_string()?.to_owned();
            } else if attr == ATTRIB_ADDRESS {
                let text = dec.read_string()?;
                addr = match (text, last) {
                    ("next", Some((a, s))) => a.add(&db.env.spaces, s),
                    _ => db.env.spaces.parse_address_simple(text)?,
                };
            } else if attr == ATTRIB_VOLATILE {
                volatile = Some(dec.read_bool()?);
            } else if attr == ATTRIB_SIZE {
                size = dec.read_signed()?;
            }
        }
        dec.close_element(sub)?;
        if name.is_empty() {
            return Err(SymbolError::DefaultSymbolName);
        }
        if addr.is_invalid() {
            return Err(SymbolError::DefaultSymbolAddress);
        }
        if size == 0 {
            size = i64::from(
                db.env
                    .spaces
                    .space_of(addr)
                    .map_or(1, bk_core::Space::word_size),
            );
        }
        if let (Some(v), Some(space)) = (volatile, addr.space()) {
            let range = Range::new(
                space,
                addr.offset(),
                addr.offset().wrapping_add((size - 1) as u64),
            );
            if v {
                db.set_property_range(VarnodeFlags::VOLATILE, &range);
            } else {
                db.clear_property_range(VarnodeFlags::VOLATILE, &range);
            }
        }
        let size32 = i32::try_from(size).map_err(|_| SymbolError::Limit("default symbol size"))?;
        let ty = types.base(size32, Metatype::Unknown)?;
        let global = db.global_scope()?;
        let entry = db.add_symbol_at(global, &name, ty, addr, Address::INVALID, types)?;
        let sym = db.entry(entry)?.symbol;
        let data = db.symbol_mut(sym)?;
        data.name_provenance = bk_core::Provenance::Imported;
        last = Some((addr, size));
    }
    dec.close_element(el)?;
    Ok(())
}

/// Ghidra `fillinReadOnlyFromLoader`: the image's read-only ranges become
/// `readonly`.
pub fn fill_readonly_from_image(db: &mut Database, image: &dyn LoadImage) {
    for range in image.readonly().iter() {
        db.set_property_range(VarnodeFlags::READONLY, &range);
    }
}

/// Ghidra `readLoaderSymbols`: each image symbol creates its namespace path
/// and a function there.
pub fn read_loader_symbols(
    db: &mut Database,
    image: &dyn LoadImage,
    types: &mut TypeFactory,
) -> Result<()> {
    for record in image.symbols() {
        let (scope, base) = db.find_create_scope_from_symbol_name(&record.name, None)?;
        let base = base.to_owned();
        let sym = db.add_function(scope, record.address, &base, types)?;
        db.symbol_mut(sym)?.name_provenance = bk_core::Provenance::Imported;
    }
    Ok(())
}

/// Ghidra `globalify`: every processor and register-relative space wholly
/// into the global scope.
pub fn globalify(db: &mut Database) -> Result<()> {
    let global = db.global_scope()?;
    let spaces = std::sync::Arc::clone(&db.env.spaces);
    for s in spaces.spaces() {
        if matches!(s.space_type(), SpaceType::Processor | SpaceType::Spacebase) {
            db.add_range(global, s.id(), 0, s.highest())?;
        }
    }
    Ok(())
}
