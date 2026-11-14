//! Joining several registers for one parameter (Ghidra `MultiSlotAssign`,
//! `MultiMemberAssign`, `AssignAction::justifyPieces`).

use bk_core::VarnodeData;
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_ALIGN, ATTRIB_STACKSPILL, ATTRIB_STORAGE};

use super::extractor::PrimitiveExtractor;
use crate::entry::type_class;
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_BACKFILL, ATTRIB_REVERSEJUSTIFY, ATTRIB_REVERSESIGNIF, ELEM_JOIN,
    ELEM_JOIN_PER_PRIMITIVE,
};
use crate::list::{AssignResult, Env, ParamList};
use crate::proto::{ParameterPieces, PieceFlags};
use crate::status::Status;
use crate::trial::ParamActive;
use crate::types::{TypeClass, TypeHandle};

/// Consume registers until the type is covered (Ghidra `MultiSlotAssign`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiSlotAssign {
    /// Class of the registers consumed.
    pub resource: TypeClass,
    /// Big-endian resources.
    pub big_endian: bool,
    /// Spill to the stack when registers run out.
    pub consume_from_stack: bool,
    /// Consume most significant bytes first.
    pub consume_most_sig: bool,
    /// Skip registers to align the value.
    pub enforce_alignment: bool,
    /// Padding goes first for odd sizes.
    pub justify_right: bool,
    /// Skipped registers stay free for later parameters.
    pub allow_backfill: bool,
    /// The registers that can be joined, in order.
    pub tiles: Vec<usize>,
    /// The stack entry, if any.
    pub stack: Option<usize>,
}

/// Removes `offset` bytes of padding from one end of a tiling (Ghidra
/// `justifyPieces`).
pub(crate) fn justify_pieces(
    pieces: &mut [VarnodeData],
    offset: i32,
    big_endian: bool,
    (consume_most_sig, justify_right): (bool, bool),
) {
    let add = big_endian ^ consume_most_sig ^ justify_right;
    let pos = if justify_right {
        0
    } else {
        pieces.len().saturating_sub(1)
    };
    if let Some(p) = pieces.get_mut(pos) {
        if add {
            p.offset = p.offset.wrapping_add(offset as u64);
        }
        p.size = p.size.wrapping_sub(offset as u32);
    }
}

/// The partial-trial checks shared by the join actions' `fillinOutputMap`.
pub(crate) fn fillin_tiles(
    list: &ParamList,
    active: &mut ParamActive,
    class: Option<(TypeClass, TypeClass)>,
    (justify_right, consume_most_sig): (bool, bool),
) -> bool {
    let mut count = 0usize;
    let mut cur_group = -1;
    let mut partial: Option<usize> = None;
    let mut resource = class.map(|c| c.0);
    for (i, t) in active.trials().iter().enumerate() {
        let Some(e) = t.entry.and_then(|e| list.entry(e)) else {
            break;
        };
        match (count, class, resource) {
            (0, Some((base, alt)), _) if base != alt => {
                if e.type_class() != base && e.type_class() != alt {
                    return false;
                }
                resource = Some(e.type_class());
            }
            (_, _, Some(r)) if e.type_class() != r => return false,
            _ => {}
        }
        if count == 0 {
            if !e.is_first_in_class() {
                return false;
            }
        } else if e.group() != cur_group + 1 {
            return false;
        }
        cur_group = e.group();
        if t.size != e.size() {
            if partial.is_some() {
                return false;
            }
            partial = Some(i);
        }
        count += 1;
    }
    if let Some(p) = partial {
        if justify_right {
            if p != 0 {
                return false;
            }
        } else if p + 1 != count {
            return false;
        }
        let Some(t) = active.trial(p) else {
            return false;
        };
        if justify_right == consume_most_sig {
            if t.offset != 0 {
                return false;
            }
        } else {
            let esize = t
                .entry
                .and_then(|e| list.entry(e))
                .map_or(0, super::super::entry::ParamEntry::size);
            if t.offset.wrapping_add(t.size) != esize {
                return false;
            }
        }
    }
    if count == 0 {
        return false;
    }
    if consume_most_sig {
        active.set_join_most_sig_first();
    }
    true
}

impl MultiSlotAssign {
    /// Reads a `<join>` (Ghidra `MultiSlotAssign::decode` with the
    /// defaults of its decoding constructor).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let big_endian = list.is_big_endian();
        let mut a = Self {
            resource: TypeClass::General,
            big_endian,
            consume_from_stack: !list.kind().is_output(),
            consume_most_sig: big_endian,
            enforce_alignment: false,
            justify_right: big_endian,
            allow_backfill: false,
            tiles: Vec::new(),
            stack: None,
        };
        let elem = dec.open_element_expecting(ELEM_JOIN)?;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_REVERSEJUSTIFY {
                if dec.read_bool()? {
                    a.justify_right = !a.justify_right;
                }
            } else if attr == ATTRIB_REVERSESIGNIF {
                if dec.read_bool()? {
                    a.consume_most_sig = !a.consume_most_sig;
                }
            } else if attr == ATTRIB_STORAGE {
                a.resource = type_class(dec.read_string()?)?;
            } else if attr == ATTRIB_ALIGN {
                a.enforce_alignment = dec.read_bool()?;
            } else if attr == ATTRIB_STACKSPILL {
                a.consume_from_stack = dec.read_bool()?;
            } else if attr == ATTRIB_BACKFILL {
                a.allow_backfill = dec.read_bool()?;
            }
        }
        dec.close_element(elem)?;
        a.tiles = list.extract_tiles(a.resource);
        a.stack = list.stack_entry();
        if a.tiles.is_empty() {
            return Err(CspecError::new(
                "Could not find matching resources for action: join",
            ));
        }
        if a.consume_from_stack && a.stack.is_none() {
            return Err(CspecError::new(
                "Cannot find matching <pentry> for action: join",
            ));
        }
        Ok(a)
    }

    /// Ghidra `checkFit`. Its adjacency loop never advances, so only the
    /// register at `iter` is tested; reproduced as such.
    fn check_fit(
        &self,
        list: &ParamList,
        iter: usize,
        align: i32,
        consumed: i32,
        tmp: &Status,
    ) -> bool {
        let Some(entry) = self.tiles.get(iter).and_then(|&t| list.entry(t)) else {
            return false;
        };
        if tmp.get(entry.group()) != 0 {
            return false;
        }
        if self.enforce_alignment && align > entry.size() && consumed.wrapping_rem(align) != 0 {
            return false;
        }
        true
    }

    /// Ghidra `MultiSlotAssign::assignAddress`.
    pub(crate) fn assign(
        &self,
        list: &ParamList,
        env: &mut Env<'_>,
        dt: TypeHandle,
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        let mut tmp = status.clone();
        let mut pieces: Vec<VarnodeData> = Vec::new();
        let size = env.types.size(dt);
        let mut left = size;
        let mut align = env.types.alignment(dt);
        let mut iter = 0;
        let mut consumed = 0i32;
        while iter < self.tiles.len() {
            if self.check_fit(list, iter, align, consumed, &tmp) {
                break;
            }
            if let Some(entry) = self.tiles.get(iter).and_then(|&t| list.entry(t)) {
                if !self.allow_backfill {
                    tmp.set(entry.group(), -1);
                }
                consumed = consumed.wrapping_add(entry.size());
            }
            iter += 1;
        }
        while left > 0 && iter < self.tiles.len() {
            let Some(entry) = self.tiles.get(iter).and_then(|&t| list.entry(t)) else {
                break;
            };
            iter += 1;
            let g = entry.group();
            if tmp.get(g) != 0 {
                continue;
            }
            let trial = entry.size();
            let mut slot = tmp.get(g);
            let addr = entry.addr_by_slot(env.manager, &mut slot, trial, align)?;
            tmp.set(g, -1);
            pieces.push(VarnodeData::from_address(addr, trial as u32));
            left -= trial;
            align = 1;
        }
        if left > 0 {
            if !self.consume_from_stack {
                return Ok(AssignResult::Fail);
            }
            let Some(stack) = self.stack.and_then(|s| list.entry(s)) else {
                return Ok(AssignResult::Fail);
            };
            let g = stack.group();
            let mut slot = tmp.get(g);
            let addr = stack.addr_by_slot_justified(
                env.manager,
                &mut slot,
                (left, align),
                self.justify_right,
            )?;
            tmp.set(g, slot);
            if addr.is_invalid() {
                return Ok(AssignResult::Fail);
            }
            pieces.push(VarnodeData::from_address(addr, left as u32));
        } else if left < 0 {
            if self.resource == TypeClass::Float && pieces.len() == 1 {
                if let Some(p) = pieces.first_mut() {
                    let addr = env.manager.construct_float_extension_address(
                        p.addr(),
                        p.size,
                        size as u32,
                    )?;
                    *p = VarnodeData::from_address(addr, size as u32);
                }
            } else {
                justify_pieces(
                    &mut pieces,
                    -left,
                    self.big_endian,
                    (self.consume_most_sig, self.justify_right),
                );
            }
        }
        *status = tmp;
        res.flags = PieceFlags::empty();
        res.ty = dt;
        res.assign_from_pieces(env.manager, pieces, self.consume_most_sig)?;
        Ok(AssignResult::Success)
    }

    /// Ghidra `MultiSlotAssign::fillinOutputMap`.
    pub(crate) fn fillin_output_map(&self, list: &ParamList, active: &mut ParamActive) -> bool {
        fillin_tiles(
            list,
            active,
            Some((self.resource, self.resource)),
            (self.justify_right, self.consume_most_sig),
        )
    }
}

/// A register per primitive member (Ghidra `MultiMemberAssign`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiMemberAssign {
    /// Class consumed from when not recursive.
    pub resource: TypeClass,
    /// Assign each primitive as a parameter of its own.
    pub recursive: bool,
    /// May consume the stack.
    pub consume_from_stack: bool,
    /// Most significant first.
    pub consume_most_sig: bool,
    /// The stack entry, if any.
    pub stack: Option<usize>,
}

impl MultiMemberAssign {
    /// Reads a `<join_per_primitive>` (Ghidra's decoding constructor and
    /// `decode`).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let mut a = Self {
            resource: TypeClass::General,
            recursive: true,
            consume_from_stack: false,
            consume_most_sig: list.is_big_endian(),
            stack: list.stack_entry(),
        };
        let elem = dec.open_element_expecting(ELEM_JOIN_PER_PRIMITIVE)?;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_STORAGE {
                a.resource = type_class(dec.read_string()?)?;
                a.recursive = false;
            }
        }
        dec.close_element(elem)?;
        Ok(a)
    }

    /// Ghidra `MultiMemberAssign::assignAddress`.
    pub(crate) fn assign(
        &self,
        list: &ParamList,
        env: &mut Env<'_>,
        (dt, pos): (TypeHandle, i32),
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        let mut tmp = status.clone();
        let prims = PrimitiveExtractor::new(&*env.types, dt, (false, self.recursive), 0, 16);
        if !prims.is_valid()
            || prims.is_empty()
            || prims.contains_unknown()
            || !prims.is_aligned()
            || prims.contains_holes()
        {
            return Ok(AssignResult::Fail);
        }
        let mut pieces = Vec::with_capacity(prims.len() * 2);
        let mut param = ParameterPieces::new(dt);
        let mut size = 0i32;
        if self.recursive && prims.len() == 1 && prims.get(0).is_some_and(|p| p.ty == dt) {
            return Ok(AssignResult::Fail);
        }
        let stack_group = self
            .stack
            .and_then(|s| list.entry(s))
            .map(super::super::entry::ParamEntry::group);
        let before = stack_group.map_or(-1, |g| tmp.get(g));
        for prim in prims.primitives() {
            let code = if self.recursive {
                env.depth += 1;
                let c = list.assign_address(env, prim.ty, pos, &mut tmp, &mut param);
                env.depth -= 1;
                c?
            } else {
                list.assign_fallback(
                    env,
                    self.resource,
                    (prim.ty, !self.consume_from_stack),
                    &mut tmp,
                    &mut param,
                )?
            };
            if code == AssignResult::Fail {
                return Ok(AssignResult::Fail);
            }
            if self.recursive
                && !self.consume_from_stack
                && let Some(g) = stack_group
                && before != tmp.get(g)
            {
                return Ok(AssignResult::Fail);
            }
            if !add_padding(&mut pieces, prim.offset.wrapping_sub(size)) {
                return Ok(AssignResult::Fail);
            }
            let psize = env.types.size(prim.ty);
            size = prim.offset.wrapping_add(psize);
            pieces.push(VarnodeData::from_address(param.addr, psize as u32));
        }
        if !add_padding(&mut pieces, env.types.size(dt).wrapping_sub(size)) {
            return Ok(AssignResult::Fail);
        }
        *status = tmp;
        res.flags = PieceFlags::empty();
        res.ty = dt;
        res.assign_from_pieces(env.manager, pieces, self.consume_most_sig)?;
        Ok(AssignResult::Success)
    }

    /// Ghidra `MultiMemberAssign::fillinOutputMap`.
    pub(crate) fn fillin_output_map(&self, list: &ParamList, active: &mut ParamActive) -> bool {
        if self.recursive {
            return false;
        }
        let mut count = 0;
        let mut cur_group = -1;
        for t in active.trials() {
            let Some(e) = t.entry.and_then(|e| list.entry(e)) else {
                break;
            };
            if e.type_class() != self.resource {
                return false;
            }
            if count == 0 {
                if !e.is_first_in_class() {
                    return false;
                }
            } else if e.group() != cur_group + 1 {
                return false;
            }
            cur_group = e.group();
            if t.offset != 0 {
                return false;
            }
            count += 1;
        }
        if count == 0 {
            return false;
        }
        if self.consume_most_sig {
            active.set_join_most_sig_first();
        }
        true
    }
}

/// Adds a padding piece in the constant space (Ghidra `addPadding`).
fn add_padding(pieces: &mut Vec<VarnodeData>, pad: i32) -> bool {
    if pad == 0 {
        return true;
    }
    if pad < 0 {
        return false;
    }
    pieces.push(VarnodeData::new(
        bk_core::space::CONSTANT_SPACE,
        0,
        pad as u32,
    ));
    true
}
