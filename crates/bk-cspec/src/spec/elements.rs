//! The simple elements of `<compiler_spec>` (Ghidra `decodeStackPointer`,
//! `decodeSpacebase`, `decodeReturnAddress`, `decodeGlobal`,
//! `decodeReadOnly`, `decodeNoHighPtr`, `decodePreferSplit`,
//! `decodeAggressiveTrim`, `decodeFuncPtrAlign`, `decodeDeadcodeDelay`,
//! `decodeInferPtrBounds`, `addSpacebase`).

use bk_core::{Range, RangeProperties, Space, SpaceId, SpaceManager, VarnodeData};
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_ALIGN, ATTRIB_NAME, ATTRIB_SPACE};

use super::{PreferSplit, SpacebaseDef, StackPointerDef};
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_DELAY, ATTRIB_GROWTH, ATTRIB_REGISTER, ATTRIB_REVERSEJUSTIFY, ATTRIB_SIGNEXT,
    ATTRIB_STYLE, ELEM_STACKPOINTER,
};

/// Reads a list of `<range>`/`<register>` children.
pub(super) fn decode_range_list(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
) -> Result<Vec<Range>> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let mut out = Vec::new();
    while dec.peek_element().is_some() {
        out.push(Range::decode(dec, manager)?);
    }
    dec.close_element(elem)?;
    Ok(out)
}

/// Reads `<global>` children as unresolved properties (Ghidra
/// `decodeGlobal`).
pub(super) fn decode_global(
    dec: &mut dyn Decoder<'_>,
    out: &mut Vec<RangeProperties>,
) -> Result<()> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    while dec.peek_element().is_some() {
        out.push(RangeProperties::decode(dec)?);
    }
    dec.close_element(elem)?;
    Ok(())
}

/// Creates a register-relative space (Ghidra `addSpacebase`).
fn add_spacebase(
    manager: &mut SpaceManager,
    (base, name): (SpaceId, &str),
    ptr: VarnodeData,
    trunc_size: u32,
    (reverse, grows_negative, formal): (bool, bool, bool),
) -> Result<SpaceId> {
    let base_space = manager.require(base)?.clone();
    let delay = ptr
        .space()
        .and_then(|s| manager.space(s))
        .map_or(0, Space::delay)
        .wrapping_add(1);
    let big_endian = manager
        .default_code_space()
        .map_or_else(|| base_space.is_big_endian(), Space::is_big_endian);
    let index = manager.num_spaces();
    let space = Space::spacebase(
        name,
        index,
        trunc_size,
        &base_space,
        delay,
        formal,
        big_endian,
    )?;
    let id = manager.insert_space(space)?;
    if reverse {
        manager.set_reverse_justified(id)?;
    }
    manager.add_spacebase_pointer(id, ptr, trunc_size, grows_negative)?;
    Ok(id)
}

/// Ghidra `decodeStackPointer`.
pub(super) fn decode_stack_pointer(
    dec: &mut dyn Decoder<'_>,
    manager: &mut SpaceManager,
) -> Result<StackPointerDef> {
    let elem = dec.open_element_expecting(ELEM_STACKPOINTER)?;
    let mut register = String::new();
    let mut grows_negative = true;
    let mut reverse = false;
    let mut base = None;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_REVERSEJUSTIFY {
            reverse = dec.read_bool()?;
        } else if attr == ATTRIB_GROWTH {
            grows_negative = dec.read_string()? == "negative";
        } else if attr == ATTRIB_SPACE {
            base = Some(dec.read_space()?);
        } else if attr == ATTRIB_REGISTER {
            dec.read_string()?.clone_into(&mut register);
        }
    }
    let base =
        base.ok_or_else(|| CspecError::new("stackpointer element missing \"space\" attribute"))?;
    let point = manager.register(&register)?;
    dec.close_element(elem)?;
    let base_space = manager.require(base)?;
    let mut trunc = point.size;
    if base_space.is_truncated() && point.size > base_space.addr_size() {
        trunc = base_space.addr_size();
    }
    let space = add_spacebase(
        manager,
        (base, "stack"),
        point,
        trunc,
        (reverse, grows_negative, true),
    )?;
    Ok(StackPointerDef {
        base,
        register: point,
        truncated_size: trunc,
        reverse_justify: reverse,
        grows_negative,
        space,
    })
}

/// Ghidra `decodeSpacebase`.
pub(super) fn decode_spacebase(
    dec: &mut dyn Decoder<'_>,
    manager: &mut SpaceManager,
) -> Result<SpacebaseDef> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
    let register = dec.read_string_attr(ATTRIB_REGISTER)?.to_owned();
    let base = dec.read_space_attr(ATTRIB_SPACE)?;
    dec.close_element(elem)?;
    let point = manager.register(&register)?;
    let space = add_spacebase(
        manager,
        (base, &name),
        point,
        point.size,
        (false, false, false),
    )?;
    Ok(SpacebaseDef {
        name,
        register: point,
        base,
        space,
    })
}

/// Ghidra `decodePreferSplit`.
pub(super) fn decode_prefer_split(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
) -> Result<Vec<PreferSplit>> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let style = dec.read_string_attr(ATTRIB_STYLE)?;
    if style != "inhalf" {
        return Err(CspecError::new(format!(
            "Unknown prefersplit style: {style}"
        )));
    }
    let mut out = Vec::new();
    while dec.peek_element().is_some() {
        let storage = VarnodeData::decode(dec, manager)?;
        out.push(PreferSplit {
            storage,
            split_offset: storage.size / 2,
        });
    }
    dec.close_element(elem)?;
    Ok(out)
}

/// Ghidra `decodeAggressiveTrim`.
pub(super) fn decode_aggressive_trim(dec: &mut dyn Decoder<'_>, current: bool) -> Result<bool> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let mut res = current;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_SIGNEXT {
            res = dec.read_bool()?;
        }
    }
    dec.close_element(elem)?;
    Ok(res)
}

/// Ghidra `decodeFuncPtrAlign`: the number of low zero bits of `align`.
pub(super) fn decode_funcptr_align(dec: &mut dyn Decoder<'_>) -> Result<u32> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let align = dec.read_signed_attr(ATTRIB_ALIGN)? as i32;
    dec.close_element(elem)?;
    if align == 0 {
        return Ok(0);
    }
    Ok(align.trailing_zeros())
}

/// Ghidra `decodeDeadcodeDelay`.
pub(super) fn decode_deadcode_delay(dec: &mut dyn Decoder<'_>) -> Result<(SpaceId, i32)> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let space = dec.read_space_attr(ATTRIB_SPACE)?;
    let delay = dec.read_signed_attr(ATTRIB_DELAY)? as i32;
    if delay < 0 {
        return Err(CspecError::new("Bad <deadcodedelay> tag"));
    }
    dec.close_element(elem)?;
    Ok((space, delay))
}

/// Ghidra `decodeReturnAddress`: the storage, if the element has a child.
pub(super) fn decode_return_address(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    current: Option<VarnodeData>,
) -> Result<Option<VarnodeData>> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing element"))?;
    let mut res = current;
    if dec.peek_element().is_some() {
        if current.is_some() {
            return Err(CspecError::new("Multiple <returnaddress> tags in .cspec"));
        }
        res = Some(VarnodeData::decode(dec, manager)?);
    }
    dec.close_element(elem)?;
    Ok(res)
}
