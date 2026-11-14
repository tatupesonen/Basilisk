//! Reading a `<prototype>` (Ghidra `ProtoModel::decode`,
//! `buildParamList`, `defaultLocalRange`, `defaultParamRange`).

use bk_core::{Range, RangeList, SpaceId, SpaceManager, VarnodeData};
use bk_marshal::Decoder;
use bk_marshal::ids::{
    ATTRIB_CONSTRUCTOR, ATTRIB_EXTRAPOP, ATTRIB_NAME, ELEM_INPUT, ELEM_OUTPUT, ELEM_RETURNADDRESS,
};

use super::{EXTRAPOP_UNKNOWN, ProtoModel, SharedAction};
use crate::effect::{EffectKind, EffectRecord, sort_effects};
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_HASTHIS, ATTRIB_STACKSHIFT, ATTRIB_STRATEGY, ELEM_INTERNAL_STORAGE, ELEM_KILLEDBYCALL,
    ELEM_LIKELYTRASH, ELEM_LOCALRANGE, ELEM_PARAMRANGE, ELEM_PCODE, ELEM_PROTOTYPE,
    ELEM_SHARESTACK, ELEM_UNAFFECTED,
};
use crate::inject::InjectLibrary;
use crate::list::{ListKind, ParamList, decode_list};

/// What decoding a model needs from the architecture as it stands.
pub(crate) struct DecodeContext<'a> {
    pub(crate) manager: &'a SpaceManager,
    /// The formal stack space, if `<stackpointer>` has been read.
    pub(crate) stack: Option<SpaceId>,
    /// The default return address storage, if any.
    pub(crate) default_return: Option<VarnodeData>,
    pub(crate) injects: &'a mut InjectLibrary,
}

/// The default range of local variables (Ghidra `defaultLocalRange`).
pub(crate) fn default_local_range(
    manager: &SpaceManager,
    stack: SpaceId,
    negative: bool,
    res: &mut RangeList,
) {
    let Some(spc) = manager.space(stack) else {
        return;
    };
    let highest = spc.highest();
    if negative {
        let size = (highest >> 1).min(0x7fff_ffff);
        res.insert_range(stack, highest - size, highest);
    } else {
        res.insert_range(stack, 0, (highest >> 1).min(0x7fff_ffff));
    }
}

/// The default range of stack parameters (Ghidra `defaultParamRange`).
pub(crate) fn default_param_range(
    manager: &SpaceManager,
    stack: SpaceId,
    negative: bool,
    res: &mut RangeList,
) {
    let Some(spc) = manager.space(stack) else {
        return;
    };
    let highest = spc.highest();
    if negative {
        res.insert_range(stack, 0, (highest >> 2).min(0x7fff_ffff));
    } else {
        let size = (highest >> 2).min(0x7fff_ffff);
        res.insert_range(stack, highest - size, highest);
    }
}

fn decode_varnode_list(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    out: &mut Vec<VarnodeData>,
) -> Result<()> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing list"))?;
    while dec.peek_element().is_some() {
        out.push(VarnodeData::decode(dec, manager)?);
    }
    dec.close_element(elem)?;
    Ok(())
}

fn decode_effects(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    kind: EffectKind,
    out: &mut Vec<EffectRecord>,
) -> Result<()> {
    let mut list = Vec::new();
    decode_varnode_list(dec, manager, &mut list)?;
    out.extend(list.into_iter().map(|v| EffectRecord::new(v, kind)));
    Ok(())
}

fn decode_ranges(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    out: &mut RangeList,
) -> Result<()> {
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing list"))?;
    while dec.peek_element().is_some() {
        out.insert(Range::decode(dec, manager)?);
    }
    dec.close_element(elem)?;
    Ok(())
}

/// Reads the `<prototype>` that is next (Ghidra `ProtoModel::decode`).
pub(crate) fn decode_model(
    dec: &mut dyn Decoder<'_>,
    ctx: &mut DecodeContext<'_>,
) -> Result<ProtoModel> {
    let manager = ctx.manager;
    let stack_grows_negative = ctx
        .stack
        .and_then(|s| manager.space(s))
        .is_none_or(bk_core::Space::stack_grows_negative);
    let mut name = String::new();
    let mut extrapop: i64 = -300;
    let mut strategy = String::new();
    let mut has_this = false;
    let mut is_construct = false;
    let elem = dec.open_element_expecting(ELEM_PROTOTYPE)?;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_NAME {
            dec.read_string()?.clone_into(&mut name);
        } else if attr == ATTRIB_EXTRAPOP {
            extrapop = dec.read_signed_or_string("unknown", i64::from(EXTRAPOP_UNKNOWN))?;
        } else if attr == ATTRIB_STACKSHIFT {
            // Accepted for backward compatibility and ignored.
        } else if attr == ATTRIB_STRATEGY {
            dec.read_string()?.clone_into(&mut strategy);
        } else if attr == ATTRIB_HASTHIS {
            has_this = dec.read_bool()?;
        } else if attr == ATTRIB_CONSTRUCTOR {
            is_construct = dec.read_bool()?;
        } else {
            return Err(CspecError::new("Unknown prototype attribute"));
        }
    }
    let path = format!("prototype[{name}]");
    if name == "__thiscall" {
        has_this = true;
    }
    if extrapop == -300 {
        return Err(CspecError::new("Missing prototype attributes").at(&path));
    }
    let (in_kind, out_kind) = match strategy.as_str() {
        "" | "standard" => (ListKind::Standard, ListKind::StandardOut),
        "register" => (ListKind::Register, ListKind::RegisterOut),
        s => return Err(CspecError::new(format!("Unknown strategy type: {s}")).at(&path)),
    };
    let mut m = ProtoModel {
        name,
        extrapop: extrapop as i32,
        input: ParamList::empty(in_kind),
        output: ParamList::empty(out_kind),
        shared: vec![SharedAction::HiddenReturn],
        alias_of: None,
        effects: Vec::new(),
        likelytrash: Vec::new(),
        internalstorage: Vec::new(),
        inject_upon_entry: None,
        inject_upon_return: None,
        localrange: RangeList::new(),
        paramrange: RangeList::new(),
        stack_grows_negative,
        has_this,
        is_construct,
        is_printed: true,
        merged: None,
    };
    decode_body(dec, ctx, &mut m).map_err(|e| e.at(&path))?;
    dec.close_element(elem)?;
    Ok(m)
}

fn decode_body(
    dec: &mut dyn Decoder<'_>,
    ctx: &mut DecodeContext<'_>,
    m: &mut ProtoModel,
) -> Result<()> {
    let manager = ctx.manager;
    let mut saw_local = false;
    let mut saw_param = false;
    let mut saw_retaddr = false;
    while let Some(sub) = dec.peek_element() {
        if sub == ELEM_INPUT {
            m.input = decode_list(
                dec,
                manager,
                m.input.kind,
                &mut m.effects,
                m.stack_grows_negative,
            )
            .map_err(|e| e.at("input"))?;
            if let Some(stack) = ctx.stack {
                m.input.range_list(stack, &mut m.paramrange);
                if !m.paramrange.is_empty() {
                    saw_param = true;
                }
            }
        } else if sub == ELEM_OUTPUT {
            m.output = decode_list(
                dec,
                manager,
                m.output.kind,
                &mut m.effects,
                m.stack_grows_negative,
            )
            .map_err(|e| e.at("output"))?;
        } else if sub == ELEM_UNAFFECTED {
            decode_effects(dec, manager, EffectKind::Unaffected, &mut m.effects)?;
        } else if sub == ELEM_KILLEDBYCALL {
            decode_effects(dec, manager, EffectKind::KilledByCall, &mut m.effects)?;
        } else if sub == ELEM_RETURNADDRESS {
            decode_effects(dec, manager, EffectKind::ReturnAddress, &mut m.effects)?;
            saw_retaddr = true;
        } else if sub == ELEM_LOCALRANGE {
            saw_local = true;
            decode_ranges(dec, manager, &mut m.localrange)?;
        } else if sub == ELEM_PARAMRANGE {
            saw_param = true;
            decode_ranges(dec, manager, &mut m.paramrange)?;
        } else if sub == ELEM_SHARESTACK {
            let a = SharedAction::decode_share_stack(dec, &m.input, &m.output)?;
            m.shared.push(a);
        } else if sub == ELEM_LIKELYTRASH {
            decode_varnode_list(dec, manager, &mut m.likelytrash)?;
        } else if sub == ELEM_INTERNAL_STORAGE {
            decode_varnode_list(dec, manager, &mut m.internalstorage)?;
        } else if sub == ELEM_PCODE {
            let id = ctx.injects.decode_mechanism(dec, &m.name)?;
            let entry = ctx
                .injects
                .payload(id)
                .is_some_and(|p| p.name.contains("uponentry"));
            if entry {
                m.inject_upon_entry = Some(id);
            } else {
                m.inject_upon_return = Some(id);
            }
        } else {
            return Err(CspecError::new("Unknown element in prototype"));
        }
    }
    if !saw_retaddr && let Some(ret) = ctx.default_return {
        m.effects
            .push(EffectRecord::new(ret, EffectKind::ReturnAddress));
    }
    sort_effects(&mut m.effects);
    m.likelytrash.sort();
    m.internalstorage.sort();
    if let Some(stack) = ctx.stack {
        if !saw_local {
            default_local_range(manager, stack, m.stack_grows_negative, &mut m.localrange);
        }
        if !saw_param {
            default_param_range(manager, stack, m.stack_grows_negative, &mut m.paramrange);
        }
    }
    Ok(())
}
