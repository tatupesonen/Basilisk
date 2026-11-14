//! Reading a `<pentry>` (Ghidra `ParamEntry::decode`, `resolveFirst`,
//! `resolveJoin`, `resolveOverlap`, `orderWithinGroup`).

use bk_core::{SpaceManager, SpaceType, VarnodeData};
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_ALIGN, ATTRIB_METATYPE, ATTRIB_SIZE, ATTRIB_STORAGE};

use super::{EntryFlags, ParamEntry};
use crate::error::{CspecError, Result};
use crate::ids::{ATTRIB_EXTENSION, ATTRIB_MAXSIZE, ATTRIB_MINSIZE, ELEM_PENTRY};
use crate::types::TypeClass;

/// How an entry is being read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntryContext {
    /// Group number given to the entry before overlaps are resolved.
    pub(crate) group: i32,
    /// Parameters are allocated from the front of the range.
    pub(crate) normal_stack: bool,
    /// The entry is inside a `<group>`.
    pub(crate) grouped: bool,
}

/// The storage class named by an attribute value (Ghidra
/// `string2typeclass`, with its message).
pub(crate) fn type_class(name: &str) -> Result<TypeClass> {
    TypeClass::from_name(name)
        .ok_or_else(|| CspecError::new(format!("Unknown data-type class: {name}")))
}

fn read_i32(dec: &mut dyn Decoder<'_>) -> Result<i32> {
    let v = dec.read_signed()?;
    i32::try_from(v).map_err(|e| CspecError::new(format!("Value out of range: {v} ({e})")))
}

/// Reads one `<pentry>`; `previous` holds the entries read before it in the
/// same list.
pub(crate) fn decode_entry(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    ctx: EntryContext,
    previous: &[ParamEntry],
) -> Result<ParamEntry> {
    let mut flags = EntryFlags::empty();
    let mut class = TypeClass::General;
    let mut size: i32 = -1;
    let mut minsize: i32 = -1;
    let mut alignment: i32 = 0;
    let elem = dec.open_element_expecting(ELEM_PENTRY)?;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_MINSIZE {
            minsize = read_i32(dec)?;
        } else if attr == ATTRIB_SIZE || attr == ATTRIB_ALIGN {
            alignment = read_i32(dec)?;
        } else if attr == ATTRIB_MAXSIZE {
            size = read_i32(dec)?;
        } else if attr == ATTRIB_STORAGE || attr == ATTRIB_METATYPE {
            class = type_class(dec.read_string()?)?;
        } else if attr == ATTRIB_EXTENSION {
            flags.remove(
                EntryFlags::SMALLSIZE_ZEXT
                    | EntryFlags::SMALLSIZE_SEXT
                    | EntryFlags::SMALLSIZE_INTTYPE,
            );
            match dec.read_string()? {
                "sign" => flags |= EntryFlags::SMALLSIZE_SEXT,
                "zero" => flags |= EntryFlags::SMALLSIZE_ZEXT,
                "inttype" => flags |= EntryFlags::SMALLSIZE_INTTYPE,
                "float" => flags |= EntryFlags::SMALLSIZE_FLOATEXT,
                "none" => {}
                ext => return Err(CspecError::new(format!("Bad extension attribute: {ext}"))),
            }
        } else {
            return Err(CspecError::new("Unknown <pentry> attribute"));
        }
    }
    if size == -1 || minsize == -1 {
        return Err(CspecError::new("ParamEntry not fully specified"));
    }
    // Ghidra accepts any value here and then divides by it or uses it as a
    // count; basilisk refuses what cannot be a size (ADR-009).
    if size <= 0 || minsize < 0 || alignment < 0 {
        return Err(CspecError::new("ParamEntry sizes must not be negative"));
    }
    if alignment == size {
        alignment = 0;
    }
    let vn = VarnodeData::decode(dec, manager)?;
    dec.close_element(elem)?;
    let space_id = vn
        .space()
        .ok_or_else(|| CspecError::new("ParamEntry not fully specified"))?;
    let space = manager.require(space_id)?;
    let mut numslots = 1;
    if alignment != 0 {
        numslots = size / alignment;
        if space.space_type() == SpaceType::Spacebase {
            flags |= EntryFlags::IS_STACKSPILL;
        }
    }
    if space.is_reverse_justified() {
        if space.is_big_endian() {
            flags |= EntryFlags::FORCE_LEFT_JUSTIFY;
        } else {
            return Err(CspecError::new(
                "No support for right justification in little endian encoding",
            ));
        }
    }
    if !ctx.normal_stack {
        flags |= EntryFlags::REVERSE_STACK;
        if alignment != 0 && size % alignment != 0 {
            return Err(CspecError::new(
                "For positive stack growth, <pentry> size must match alignment",
            ));
        }
    }
    if ctx.grouped {
        flags |= EntryFlags::IS_GROUPED;
    }
    let mut entry = ParamEntry {
        flags,
        class,
        groups: vec![ctx.group],
        space: space_id,
        space_type: space.space_type(),
        big_endian: space.is_big_endian(),
        base: vn.offset,
        size,
        minsize,
        alignment,
        numslots,
        join: None,
    };
    resolve_first(&mut entry, previous);
    resolve_join(&mut entry, manager, previous)?;
    resolve_overlap(&mut entry, previous)?;
    Ok(entry)
}

/// Marks the entry as first in its storage class when the previous entry
/// has another class (Ghidra `resolveFirst`).
fn resolve_first(entry: &mut ParamEntry, previous: &[ParamEntry]) {
    match previous.last() {
        None => entry.flags |= EntryFlags::FIRST_STORAGE,
        Some(prev) if prev.class != entry.class => entry.flags |= EntryFlags::FIRST_STORAGE,
        Some(_) => {}
    }
}

/// Caches the pieces of a join entry and takes the groups of the earlier
/// entries it overlaps (Ghidra `resolveJoin`).
fn resolve_join(
    entry: &mut ParamEntry,
    manager: &SpaceManager,
    previous: &[ParamEntry],
) -> Result<()> {
    if entry.space_type != SpaceType::Join {
        return Ok(());
    }
    let record = manager.find_join(entry.base)?;
    let pieces: Box<[VarnodeData]> = record.pieces().into();
    entry.groups.clear();
    for (i, piece) in pieces.iter().enumerate() {
        if piece.space() == Some(bk_core::space::CONSTANT_SPACE) {
            continue;
        }
        // Ghidra searches the whole list backwards, this entry included; a
        // join entry never matches a register piece.
        let found = previous.iter().rev().find(|e| {
            Some(e.space) == piece.space() && e.base == piece.offset && e.size == piece.size as i32
        });
        if let Some(found) = found {
            entry.groups.extend_from_slice(&found.groups);
            entry.flags |= if i == 0 {
                EntryFlags::EXTRACHECK_LOW
            } else {
                EntryFlags::EXTRACHECK_HIGH
            };
        }
    }
    if entry.groups.is_empty() {
        return Err(CspecError::new(
            "<pentry> join must overlap at least one previous entry",
        ));
    }
    entry.groups.sort_unstable();
    entry.flags |= EntryFlags::OVERLAPPING;
    entry.join = Some(pieces);
    Ok(())
}

/// Takes the groups of earlier entries this one contains (Ghidra
/// `resolveOverlap`).
fn resolve_overlap(entry: &mut ParamEntry, previous: &[ParamEntry]) -> Result<()> {
    if entry.join.is_some() {
        return Ok(());
    }
    let mut overlap = Vec::new();
    let addr = entry.address();
    for other in previous {
        if !other.intersects(addr, entry.size) {
            continue;
        }
        if !entry.contains(other) {
            return Err(CspecError::new(
                "Illegal overlap of <pentry> in compiler spec",
            ));
        }
        if other.is_overlap() {
            continue;
        }
        overlap.extend_from_slice(&other.groups);
        let same_start = entry.base == other.base;
        entry.flags |= if same_start == entry.big_endian {
            EntryFlags::EXTRACHECK_LOW
        } else {
            EntryFlags::EXTRACHECK_HIGH
        };
    }
    if overlap.is_empty() {
        return Ok(());
    }
    overlap.sort_unstable();
    entry.groups = overlap;
    entry.flags |= EntryFlags::OVERLAPPING;
    Ok(())
}

/// Entries of one group must be told apart by size or class (Ghidra
/// `orderWithinGroup`).
pub(crate) fn order_within_group(first: &ParamEntry, second: &ParamEntry) -> Result<()> {
    if second.minsize > first.size || first.minsize > second.size {
        return Ok(());
    }
    if first.class != second.class {
        if first.class == TypeClass::General {
            return Err(CspecError::new(
                "<pentry> tags with a specific type must come before the general type",
            ));
        }
        return Ok(());
    }
    Err(CspecError::new(
        "<pentry> tags within a group must be distinguished by size or type",
    ))
}
