//! Resolving template constants and varnode templates to concrete varnodes
//! (Ghidra `ConstTpl::fix`, `fixSpace`, `SleighBuilder::generateLocation`,
//! `generatePointer`).

use bk_core::{Address, SpaceId, VarnodeData};
use bk_sla::{ConstTpl, HandleSelect, VarnodeTpl};

use super::buffer::calc_mask;
use crate::decode::{FixedHandle, Parse};
use crate::error::DecodeError;
use crate::language::Language;

/// The constant space's index.
pub(crate) const CONST: u32 = 0;

/// Where a template being built takes its operand handles from.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Handles<'p> {
    /// A node of a parse: operand `i` is the node's child `i`.
    Node {
        /// The parse.
        parse: &'p Parse,
        /// The node whose constructor's template is being built.
        node: u32,
    },
    /// Parameters of a free-standing template, by operand index.
    Params(&'p [(u32, VarnodeData)]),
}

/// The state a template is built in (Ghidra's `ParserWalker` with its
/// cross context): handles, the addresses constants refer to and the
/// unique-space bits. It is a value: a nested build makes a new one and an
/// early return cannot leave a stale one behind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Walk<'p> {
    pub(crate) handles: Handles<'p>,
    /// `inst_start`.
    pub(crate) start: Address,
    /// `inst_next`.
    pub(crate) next: Address,
    /// `inst_next2`, when available.
    pub(crate) next2: Option<Address>,
    /// Why `inst_next2` is not available, when the next instruction does
    /// not decode.
    pub(crate) next2_error: Option<&'p DecodeError>,
    /// `inst_ref`/`inst_dest` (free-standing templates only).
    pub(crate) flow: Option<Address>,
    /// The space of the instruction stream.
    pub(crate) cur_space: u32,
    /// The bits `OR`ed into unique-space offsets.
    pub(crate) unique: u64,
}

impl<'p> Walk<'p> {
    /// The walk of `node` of `parse`, with constants from `parse` itself.
    pub(crate) fn of(parse: &'p Parse, node: u32, unique: u64) -> Self {
        Self {
            handles: Handles::Node { parse, node },
            start: parse.addr,
            next: parse.naddr,
            next2: parse.next2,
            next2_error: parse.next2_error.as_ref(),
            flow: None,
            cur_space: parse.addr.space().map_or(CONST, SpaceId::index),
            unique,
        }
    }

    /// The same walk moved to another node of the same parse.
    pub(crate) fn at(self, node: u32) -> Self {
        match self.handles {
            Handles::Node { parse, .. } => Self {
                handles: Handles::Node { parse, node },
                ..self
            },
            Handles::Params(_) => self,
        }
    }

    /// The handle of operand `index`.
    pub(crate) fn handle(&self, index: u32) -> FixedHandle {
        match self.handles {
            Handles::Node { parse, node } => parse
                .nodes
                .get(node as usize)
                .and_then(|n| n.child(index))
                .and_then(|c| parse.nodes.get(c as usize))
                .map_or(FixedHandle::UNSET, |n| n.handle),
            Handles::Params(params) => {
                params
                    .iter()
                    .find(|(i, _)| *i == index)
                    .map_or(FixedHandle::UNSET, |(_, vn)| {
                        FixedHandle::fixed(
                            vn.space().map_or(CONST, SpaceId::index),
                            vn.offset,
                            vn.size,
                        )
                    })
            }
        }
    }
}

/// The address size of space `space` (0 when there is none).
fn space_size(lang: &Language, space: u32) -> u64 {
    lang.spaces()
        .space_at(space)
        .map_or(0, |s| u64::from(s.addr_size()))
}

/// Ghidra `ConstTpl::fix`.
pub(crate) fn fix(lang: &Language, c: &ConstTpl, w: &Walk<'_>) -> Result<u64, DecodeError> {
    Ok(match *c {
        ConstTpl::Real(value) | ConstTpl::Relative(value) => value,
        ConstTpl::Start => w.start.offset(),
        ConstTpl::Next => w.next.offset(),
        ConstTpl::Next2 => w
            .next2
            .ok_or_else(|| {
                w.next2_error
                    .cloned()
                    .unwrap_or(DecodeError::Next2Unavailable { address: w.start })
            })?
            .offset(),
        ConstTpl::FlowRef | ConstTpl::FlowDest => w.flow.map_or(0, Address::offset),
        ConstTpl::FlowRefSize | ConstTpl::FlowDestSize => w
            .flow
            .and_then(Address::space)
            .map_or(0, |s| space_size(lang, s.index())),
        ConstTpl::CurSpace => u64::from(w.cur_space),
        ConstTpl::CurSpaceSize => space_size(lang, w.cur_space),
        ConstTpl::Space(space) => u64::from(space),
        ConstTpl::Handle {
            index,
            select,
            plus,
        } => {
            let hand = w.handle(index);
            let dynamic = hand.is_dynamic();
            let offset = if dynamic {
                hand.temp_offset
            } else {
                hand.offset_offset
            };
            match select {
                HandleSelect::Space => {
                    u64::from(if dynamic { hand.temp_space } else { hand.space })
                }
                HandleSelect::Offset => offset,
                HandleSelect::Size => u64::from(hand.size),
                HandleSelect::OffsetPlus => {
                    if hand.space == CONST {
                        // ADR-024: shift counts modulo 64.
                        offset.wrapping_shr(8u32.wrapping_mul((plus >> 16) as u32))
                    } else {
                        offset.wrapping_add(plus & 0xffff)
                    }
                }
            }
        }
    })
}

/// Ghidra `ConstTpl::fixSpace`.
pub(crate) fn fix_space(c: &ConstTpl, w: &Walk<'_>) -> Result<u32, DecodeError> {
    match *c {
        ConstTpl::CurSpace => Ok(w.cur_space),
        ConstTpl::Space(space) => Ok(space),
        ConstTpl::Handle {
            index,
            select: HandleSelect::Space,
            ..
        } => {
            let hand = w.handle(index);
            Ok(if hand.is_dynamic() {
                hand.temp_space
            } else {
                hand.space
            })
        }
        _ => Err(DecodeError::NotASpace { address: w.start }),
    }
}

/// The offset of a varnode in `space` after the three space rules: masked
/// to the size in the constant space, `OR`ed with the unique bits in the
/// unique space, wrapped elsewhere.
fn place(lang: &Language, space: u32, offset: u64, size: u32, unique: u64) -> u64 {
    match lang.spaces().space_at(space) {
        Some(s) => match s.kind() {
            bk_core::SpaceKind::Constant => offset & calc_mask(size),
            bk_core::SpaceKind::Unique => offset | unique,
            _ => s.wrap_offset(offset),
        },
        None => offset,
    }
}

/// Ghidra `generateLocation`.
pub(crate) fn location(
    lang: &Language,
    vn: &VarnodeTpl,
    w: &Walk<'_>,
) -> Result<VarnodeData, DecodeError> {
    let space = fix_space(&vn.space, w)?;
    let size = fix(lang, &vn.size, w)? as u32;
    let offset = fix(lang, &vn.offset, w)?;
    Ok(VarnodeData::new(
        SpaceId::new(space),
        place(lang, space, offset, size, w.unique),
        size,
    ))
}

/// Ghidra `generatePointer`: the pointer of a dynamic handle and the space
/// it points into.
pub(crate) fn pointer(lang: &Language, vn: &VarnodeTpl, w: &Walk<'_>) -> (VarnodeData, u32) {
    let index = match vn.offset {
        ConstTpl::Handle { index, .. } => index,
        _ => u32::MAX,
    };
    let hand = w.handle(index);
    let offset = place(
        lang,
        hand.offset_space,
        hand.offset_offset,
        hand.offset_size,
        w.unique,
    );
    (
        VarnodeData::new(SpaceId::new(hand.offset_space), offset, hand.offset_size),
        hand.space,
    )
}

/// Ghidra `VarnodeTpl::isDynamic`.
pub(crate) fn is_dynamic(vn: &VarnodeTpl, w: &Walk<'_>) -> bool {
    match vn.offset {
        ConstTpl::Handle { index, .. } => w.handle(index).is_dynamic(),
        _ => false,
    }
}
