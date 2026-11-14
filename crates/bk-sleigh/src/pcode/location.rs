//! Resolving template constants and varnode templates to concrete varnodes
//! (Ghidra `ConstTpl::fix`, `fixSpace`, `SleighBuilder::generateLocation`,
//! `generatePointer`).

use bk_core::{Address, SpaceId, VarnodeData};
use bk_sla::{ConstTpl, HandleSelect, VarnodeTpl};

use crate::decode::{FixedHandle, Parse};
use crate::error::DecodeError;
use crate::language::Language;

/// The constant space's index.
pub(crate) const CONST: u32 = 0;

/// Where a template being built takes its operand handles from.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Handles<'p> {
    /// A node of a parse: operand `i` is the node's child `i`.
    ///
    /// Only the node's index is kept: a walk is rebuilt for every nested
    /// `BUILD`, and the node's child range stored beside it as two 32-bit
    /// fields was read back as one 64-bit load, which x86-64 cannot forward
    /// from the two stores.
    Node {
        /// The parse.
        parse: &'p Parse,
        /// The node whose constructor's template is being built.
        node: usize,
    },
    /// Parameters of a free-standing template, by operand index.
    Params(&'p [(u32, VarnodeData)]),
}

/// What every template of one build reads besides handles (Ghidra's
/// `ParserWalker` cross context): the addresses constants refer to and the
/// unique-space bits. It is made once per instruction (and per delay-slot
/// or crossbuild target) and walks refer to it, so that a nested `BUILD`
/// copies a handle source, not all of this.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Consts<'p> {
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

impl<'p> Consts<'p> {
    /// The constants of `parse` itself.
    pub(crate) fn of(parse: &'p Parse, unique: u64) -> Self {
        Self {
            start: parse.addr,
            next: parse.naddr,
            next2: parse.next2,
            next2_error: parse.next2_error.as_ref(),
            flow: None,
            cur_space: parse.addr.space().map_or(CONST, SpaceId::index),
            unique,
        }
    }
}

/// The state a template is built in (Ghidra's `ParserWalker`): where its
/// operand handles come from, and the build's constants. It is a value: a
/// nested build makes a new one and an early return cannot leave a stale
/// one behind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Walk<'p> {
    pub(crate) handles: Handles<'p>,
    pub(crate) k: &'p Consts<'p>,
}

impl<'p> Walk<'p> {
    /// The walk of `node` of `parse` with the constants `k`.
    pub(crate) fn of(parse: &'p Parse, node: u32, k: &'p Consts<'p>) -> Self {
        Self {
            handles: Handles::Node {
                parse,
                node: node as usize,
            },
            k,
        }
    }

    /// The same walk moved to another node of the same parse.
    pub(crate) fn at(self, node: u32) -> Self {
        match self.handles {
            Handles::Node { parse, .. } => Self {
                handles: Handles::Node {
                    parse,
                    node: node as usize,
                },
                ..self
            },
            Handles::Params(_) => self,
        }
    }

    /// The handle of operand `index`.
    #[inline]
    pub(crate) fn handle(&self, index: u32) -> FixedHandle {
        match self.handles {
            Handles::Node { parse, node } => parse
                .nodes
                .get(node)
                .and_then(|n| n.child(index))
                .map_or(FixedHandle::UNSET, |child| parse.handle(child)),
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
#[inline]
fn space_size(lang: &Language, space: u32) -> u64 {
    lang.spaces()
        .space_at(space)
        .map_or(0, |s| u64::from(s.addr_size()))
}

/// Ghidra `ConstTpl::fix`.
#[inline]
pub(crate) fn fix(lang: &Language, c: &ConstTpl, w: &Walk<'_>) -> Result<u64, DecodeError> {
    Ok(match *c {
        ConstTpl::Real(value) | ConstTpl::Relative(value) => value,
        ConstTpl::Start => w.k.start.offset(),
        ConstTpl::Next => w.k.next.offset(),
        ConstTpl::Next2 => {
            w.k.next2
                .ok_or_else(|| {
                    w.k.next2_error
                        .cloned()
                        .unwrap_or(DecodeError::Next2Unavailable { address: w.k.start })
                })?
                .offset()
        }
        ConstTpl::FlowRef | ConstTpl::FlowDest => w.k.flow.map_or(0, Address::offset),
        ConstTpl::FlowRefSize | ConstTpl::FlowDestSize => {
            w.k.flow
                .and_then(Address::space)
                .map_or(0, |s| space_size(lang, s.index()))
        }
        ConstTpl::CurSpace => u64::from(w.k.cur_space),
        ConstTpl::CurSpaceSize => space_size(lang, w.k.cur_space),
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
#[inline]
pub(crate) fn fix_space(c: &ConstTpl, w: &Walk<'_>) -> Result<u32, DecodeError> {
    match *c {
        ConstTpl::CurSpace => Ok(w.k.cur_space),
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
        _ => Err(DecodeError::NotASpace { address: w.k.start }),
    }
}

/// The offset of a varnode in `space` after the three space rules: masked
/// to the size in the constant space, `OR`ed with the unique bits in the
/// unique space, wrapped elsewhere.
#[inline]
fn place(lang: &Language, space: u32, offset: u64, size: u32, unique: u64) -> u64 {
    lang.place_offset(space, offset, size, unique)
}

/// Ghidra `generateLocation`, with [`is_dynamic`]'s answer.
#[expect(
    clippy::inline_always,
    reason = "returned through memory, the varnode is written field by field and copied with 16-byte loads that x86-64 cannot forward from those stores; inlined it stays in registers (measured, docs/agents/sleigh-perf-linux.md)"
)]
#[inline(always)]
pub(crate) fn locate(
    lang: &Language,
    vn: &VarnodeTpl,
    w: &Walk<'_>,
) -> Result<(VarnodeData, bool), DecodeError> {
    // The common case: an operand used whole (space, offset and size of
    // one handle), resolved with one handle lookup.
    if let (
        ConstTpl::Handle {
            index,
            select: HandleSelect::Space,
            ..
        },
        ConstTpl::Handle {
            index: i2,
            select: HandleSelect::Offset,
            ..
        },
        ConstTpl::Handle {
            index: i3,
            select: HandleSelect::Size,
            ..
        },
    ) = (vn.space, vn.offset, vn.size)
        && index == i2
        && index == i3
    {
        let hand = w.handle(index);
        let dynamic = hand.is_dynamic();
        let (space, offset) = if dynamic {
            (hand.temp_space, hand.temp_offset)
        } else {
            (hand.space, hand.offset_offset)
        };
        return Ok((
            VarnodeData::new(
                SpaceId::new(space),
                place(lang, space, offset, hand.size, w.k.unique),
                hand.size,
            ),
            dynamic,
        ));
    }
    // The next most common: a fixed varnode (a register, a unique
    // temporary, a constant, a label), nothing to look up.
    if let (
        ConstTpl::Space(space),
        ConstTpl::Real(offset) | ConstTpl::Relative(offset),
        ConstTpl::Real(size),
    ) = (vn.space, vn.offset, vn.size)
    {
        let size = size as u32;
        return Ok((
            VarnodeData::new(
                SpaceId::new(space),
                place(lang, space, offset, size, w.k.unique),
                size,
            ),
            false,
        ));
    }
    let space = fix_space(&vn.space, w)?;
    let size = fix(lang, &vn.size, w)? as u32;
    let offset = fix(lang, &vn.offset, w)?;
    Ok((
        VarnodeData::new(
            SpaceId::new(space),
            place(lang, space, offset, size, w.k.unique),
            size,
        ),
        is_dynamic(vn, w),
    ))
}

/// Ghidra `generatePointer`: the pointer of a dynamic handle and the space
/// it points into.
#[inline]
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
        w.k.unique,
    );
    (
        VarnodeData::new(SpaceId::new(hand.offset_space), offset, hand.offset_size),
        hand.space,
    )
}

/// Ghidra `VarnodeTpl::isDynamic`.
#[inline]
pub(crate) fn is_dynamic(vn: &VarnodeTpl, w: &Walk<'_>) -> bool {
    match vn.offset {
        ConstTpl::Handle { index, .. } => w.handle(index).is_dynamic(),
        _ => false,
    }
}
