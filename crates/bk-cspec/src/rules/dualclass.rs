//! Registers of two classes for one composite value, by tile, the way the
//! System V x86-64 ABI does (Ghidra `MultiSlotDualAssign`).

use bk_core::VarnodeData;
use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_STACKSPILL, ATTRIB_STORAGE};

use super::extractor::PrimitiveExtractor;
use super::multislot::{fillin_tiles, justify_pieces};
use crate::entry::type_class;
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_A, ATTRIB_B, ATTRIB_FILL_ALTERNATE, ATTRIB_REVERSEJUSTIFY, ATTRIB_REVERSESIGNIF,
    ELEM_JOIN_DUAL_CLASS,
};
use crate::list::{AssignResult, Env, ParamList};
use crate::proto::{ParameterPieces, PieceFlags};
use crate::status::Status;
use crate::trial::ParamActive;
use crate::types::{ParamTypes, TypeClass, TypeHandle};

/// Ghidra `MultiSlotDualAssign`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualClassAssign {
    /// Class of the general tiles.
    pub base: TypeClass,
    /// Class of the alternate tiles.
    pub alt: TypeClass,
    /// Big-endian resources.
    pub big_endian: bool,
    /// Spill to the stack.
    pub consume_from_stack: bool,
    /// Most significant first.
    pub consume_most_sig: bool,
    /// Padding first for odd sizes.
    pub justify_right: bool,
    /// An alternate tile needs one primitive of exactly the tile size.
    pub fill_alternate: bool,
    /// Bytes in a tile.
    pub tile_size: i32,
    /// General registers.
    pub base_tiles: Vec<usize>,
    /// Alternate registers.
    pub alt_tiles: Vec<usize>,
    /// The stack entry, if any.
    pub stack: Option<usize>,
}

impl DualClassAssign {
    /// Reads a `<join_dual_class>` (Ghidra's decoding constructor and
    /// `decode`, then `initializeEntries`).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let big_endian = list.is_big_endian();
        let mut a = Self {
            base: TypeClass::General,
            alt: TypeClass::Float,
            big_endian,
            consume_from_stack: false,
            consume_most_sig: big_endian,
            justify_right: big_endian,
            fill_alternate: false,
            tile_size: 0,
            base_tiles: Vec::new(),
            alt_tiles: Vec::new(),
            stack: None,
        };
        let elem = dec.open_element_expecting(ELEM_JOIN_DUAL_CLASS)?;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_REVERSEJUSTIFY {
                if dec.read_bool()? {
                    a.justify_right = !a.justify_right;
                }
            } else if attr == ATTRIB_REVERSESIGNIF {
                if dec.read_bool()? {
                    a.consume_most_sig = !a.consume_most_sig;
                }
            } else if attr == ATTRIB_STORAGE || attr == ATTRIB_A {
                a.base = type_class(dec.read_string()?)?;
            } else if attr == ATTRIB_B {
                a.alt = type_class(dec.read_string()?)?;
            } else if attr == ATTRIB_STACKSPILL {
                a.consume_from_stack = dec.read_bool()?;
            } else if attr == ATTRIB_FILL_ALTERNATE {
                a.fill_alternate = dec.read_bool()?;
            }
        }
        dec.close_element(elem)?;
        a.base_tiles = list.extract_tiles(a.base);
        a.alt_tiles = list.extract_tiles(a.alt);
        a.stack = list.stack_entry();
        let size_of = |tiles: &[usize]| {
            tiles
                .first()
                .and_then(|&t| list.entry(t))
                .map(super::super::entry::ParamEntry::size)
        };
        let (Some(bs), Some(as_)) = (size_of(&a.base_tiles), size_of(&a.alt_tiles)) else {
            return Err(CspecError::new(
                "Could not find matching resources for action: join_dual_class",
            ));
        };
        a.tile_size = bs;
        if bs != as_ {
            return Err(CspecError::new(
                "Storage class register sizes do not match for action: join_dual_class",
            ));
        }
        if a.consume_from_stack && a.stack.is_none() {
            return Err(CspecError::new(
                "Cannot find matching stack resource for action: join_dual_class",
            ));
        }
        Ok(a)
    }

    /// The first unconsumed tile at or after `iter` (Ghidra
    /// `getFirstUnused`).
    fn first_unused(list: &ParamList, mut iter: usize, tiles: &[usize], status: &Status) -> usize {
        while let Some(&t) = tiles.get(iter) {
            if list.entry(t).is_some_and(|e| status.get(e.group()) == 0) {
                return iter;
            }
            iter += 1;
        }
        tiles.len()
    }

    /// 0 for a general tile, 1 for an alternate one, -1 when a primitive
    /// crosses the tile boundary (Ghidra `getTileClass`).
    fn tile_class(
        &self,
        types: &dyn ParamTypes,
        prims: &PrimitiveExtractor,
        off: i32,
        index: &mut usize,
    ) -> i32 {
        let mut res = 1;
        let mut count = 0;
        let end = off.wrapping_add(self.tile_size);
        let Some(first) = prims.get(*index) else {
            return -1;
        };
        while let Some(el) = prims.get(*index) {
            if el.offset < off {
                return -1;
            }
            if el.offset >= end {
                break;
            }
            if el.offset.wrapping_add(types.size(el.ty)) > end {
                return -1;
            }
            count += 1;
            *index += 1;
            if types.metatype(el.ty).type_class() != self.alt {
                res = 0;
            }
        }
        if count == 0 {
            return -1;
        }
        if self.fill_alternate && (count > 1 || types.size(first.ty) != self.tile_size) {
            res = 0;
        }
        res
    }

    /// Ghidra `MultiSlotDualAssign::assignAddress`.
    pub(crate) fn assign(
        &self,
        list: &ParamList,
        env: &mut Env<'_>,
        dt: TypeHandle,
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        let prims = PrimitiveExtractor::new(&*env.types, dt, (false, false), 0, 1024);
        if !prims.is_valid() || prims.is_empty() || prims.contains_holes() {
            return Ok(AssignResult::Fail);
        }
        let mut index = 0usize;
        let mut tmp = status.clone();
        let mut pieces = Vec::new();
        let type_size = env.types.size(dt);
        let align = env.types.alignment(dt);
        let mut left = type_size;
        let (mut iter_base, mut iter_alt) = (0usize, 0usize);
        while left > 0 {
            let class = self.tile_class(&*env.types, &prims, type_size - left, &mut index);
            if class < 0 {
                return Ok(AssignResult::Fail);
            }
            let tile = if class == 0 {
                iter_base = Self::first_unused(list, iter_base, &self.base_tiles, &tmp);
                self.base_tiles.get(iter_base)
            } else {
                iter_alt = Self::first_unused(list, iter_alt, &self.alt_tiles, &tmp);
                self.alt_tiles.get(iter_alt)
            };
            let Some(entry) = tile.and_then(|&t| list.entry(t)) else {
                if !self.consume_from_stack {
                    return Ok(AssignResult::Fail);
                }
                break;
            };
            let trial = entry.size();
            let g = entry.group();
            let mut slot = tmp.get(g);
            let addr = entry.addr_by_slot(env.manager, &mut slot, trial, 1)?;
            tmp.set(g, -1);
            pieces.push(VarnodeData::from_address(addr, trial as u32));
            left -= trial;
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
        }
        if left < 0 {
            justify_pieces(
                &mut pieces,
                -left,
                self.big_endian,
                (self.consume_most_sig, self.justify_right),
            );
        }
        *status = tmp;
        res.flags = PieceFlags::empty();
        res.ty = dt;
        res.assign_from_pieces(env.manager, pieces, self.consume_most_sig)?;
        Ok(AssignResult::Success)
    }

    /// Ghidra `MultiSlotDualAssign::fillinOutputMap`.
    pub(crate) fn fillin_output_map(&self, list: &ParamList, active: &mut ParamActive) -> bool {
        fillin_tiles(
            list,
            active,
            Some((self.base, self.alt)),
            (self.justify_right, self.consume_most_sig),
        )
    }
}
