//! Resolving handles: the fixed varnode of every non-subtable operand and
//! the export of every constructor (Ghidra `Sleigh::resolveHandles`,
//! `TripleSymbol::getFixedHandle`, `HandleTpl::fix`, `ConstTpl::fix`,
//! `fixSpace`, `fillinSpace`, `fillinOffset`).

use bk_core::Address;
use bk_sla::{ConstTpl, HandleSelect, HandleTpl, SymbolKind};

use super::expr::{Env, Point};
use super::resolve::{MAX_DEPTH, env};
use super::tree::{FixedHandle, NONE, Parse, ParseState};
use crate::error::{DecodeError, Limit, TableKind};
use crate::language::Language;
use crate::language::tables::OpDef;

/// The constant space's index.
const CONST: u32 = 0;

/// Fills in every handle of a resolved parse.
pub(crate) fn resolve_handles(lang: &Language, parse: &mut Parse) -> Result<(), DecodeError> {
    if parse.state < ParseState::Resolved {
        return Err(DecodeError::Model {
            address: parse.addr,
            what: "handles of an unresolved parse",
        });
    }
    let address = parse.addr;
    let model = |what| DecodeError::Model { address, what };
    let naddr = Some(parse.naddr);
    let mut crumbs = [0u32; MAX_DEPTH];
    let mut depth = 0usize;
    let mut cur = 0u32;
    loop {
        let node = *parse.nodes.get(cur as usize).ok_or_else(|| model("node"))?;
        let ctor_id = node.constructor().ok_or_else(|| model("node constructor"))?;
        let info = *lang.tables.ctor(ctor_id).ok_or_else(|| model("constructor"))?;
        let mut oper = crumbs.get(depth).copied().unwrap_or(0);
        let mut descended = false;
        while oper < info.num_ops {
            let op = *lang.tables.op(&info, oper).ok_or_else(|| model("operand"))?;
            if depth > MAX_DEPTH - 2 {
                return Err(DecodeError::Limit {
                    address,
                    limit: Limit::Depth,
                });
            }
            if let Some(crumb) = crumbs.get_mut(depth) {
                *crumb = oper + 1;
            }
            depth += 1;
            if let Some(crumb) = crumbs.get_mut(depth) {
                *crumb = 0;
            }
            let child = node.child(oper).ok_or_else(|| model("operand node"))?;
            if let OpDef::Subtable(_) = op.def {
                cur = child;
                descended = true;
                break;
            }
            let handle = operand_handle(&env(lang, parse, naddr), op.def, child)?;
            if let Some(slot) = parse.nodes.get_mut(child as usize) {
                slot.handle = handle;
            }
            depth -= 1;
            oper += 1;
        }
        if descended {
            continue;
        }
        let sla = lang.sla();
        let export = sla
            .constructor(ctor_id)
            .and_then(|ctor| sla.main_template(ctor))
            .and_then(|template| template.result().copied());
        if let Some(export) = export {
            let handle = fix(&env(lang, parse, naddr), &export, cur)?;
            if let Some(slot) = parse.nodes.get_mut(cur as usize) {
                slot.handle = handle;
            }
        }
        if node.parent == NONE {
            break;
        }
        cur = node.parent;
        depth = depth.saturating_sub(1);
    }
    parse.state = ParseState::Handles;
    Ok(())
}

impl Env<'_> {
    fn cur_space(&self) -> u32 {
        self.addr.space().map_or(CONST, |space| space.index())
    }

    fn space_size(&self, space: u32) -> u32 {
        self.lang
            .spaces()
            .space_at(space)
            .map_or(0, bk_core::Space::addr_size)
    }

    fn address_handle(&self, addr: Option<Address>) -> Result<FixedHandle, DecodeError> {
        let addr = addr.ok_or(DecodeError::Next2Unavailable { address: self.addr })?;
        let space = self.cur_space();
        Ok(FixedHandle::fixed(space, addr.offset(), self.space_size(space)))
    }

    fn handle_of(&self, n: u32) -> FixedHandle {
        self.nodes.get(n as usize).map_or(FixedHandle::UNSET, |node| node.handle)
    }

    fn child_handle(&self, n: u32, index: u32) -> Result<FixedHandle, DecodeError> {
        let node = self.nodes.get(n as usize).ok_or_else(|| self.model("node"))?;
        let child = node.child(index).ok_or_else(|| self.model("const_handle operand"))?;
        Ok(self.handle_of(child))
    }

    /// Ghidra `ConstTpl::fix`: the value of a template constant at node `n`.
    fn fix_const(&self, c: &ConstTpl, n: u32) -> Result<u64, DecodeError> {
        Ok(match *c {
            ConstTpl::Real(value) | ConstTpl::Relative(value) => value,
            ConstTpl::Start => self.addr.offset(),
            ConstTpl::Next => self.naddr.unwrap_or(self.addr).offset(),
            ConstTpl::Next2 => {
                self.next2
                    .ok_or(DecodeError::Next2Unavailable { address: self.addr })?
                    .offset()
            }
            ConstTpl::CurSpace => u64::from(self.cur_space()),
            ConstTpl::CurSpaceSize => u64::from(self.space_size(self.cur_space())),
            ConstTpl::Space(space) => u64::from(space),
            ConstTpl::Handle { index, select, plus } => {
                let hand = self.child_handle(n, index)?;
                let dynamic = hand.is_dynamic();
                match select {
                    HandleSelect::Space => u64::from(if dynamic { hand.temp_space } else { hand.space }),
                    HandleSelect::Offset => {
                        if dynamic {
                            hand.temp_offset
                        } else {
                            hand.offset_offset
                        }
                    }
                    HandleSelect::Size => u64::from(hand.size),
                    HandleSelect::OffsetPlus => {
                        let value = if dynamic {
                            hand.temp_offset
                        } else {
                            hand.offset_offset
                        };
                        if hand.space == CONST {
                            value.wrapping_shr(8u32.wrapping_mul((plus >> 16) as u32))
                        } else {
                            value.wrapping_add(plus & 0xffff)
                        }
                    }
                }
            }
            ConstTpl::FlowRef | ConstTpl::FlowRefSize | ConstTpl::FlowDest | ConstTpl::FlowDestSize => 0,
        })
    }

    /// Ghidra `ConstTpl::fixSpace`.
    fn fix_space(&self, c: &ConstTpl, n: u32) -> Result<u32, DecodeError> {
        match *c {
            ConstTpl::CurSpace => Ok(self.cur_space()),
            ConstTpl::Space(space) => Ok(space),
            ConstTpl::Handle {
                index,
                select: HandleSelect::Space,
                ..
            } => {
                let hand = self.child_handle(n, index)?;
                Ok(if hand.is_dynamic() { hand.temp_space } else { hand.space })
            }
            _ => Err(DecodeError::NotASpace { address: self.addr }),
        }
    }
}

/// Ghidra `HandleTpl::fix` at node `n`.
fn fix(env: &Env<'_>, tpl: &HandleTpl, n: u32) -> Result<FixedHandle, DecodeError> {
    let mut hand = FixedHandle::UNSET;
    if matches!(tpl.ptr_space, ConstTpl::Real(_)) {
        // fillinSpace: the raw space of another handle, not its temporary.
        hand.space = match tpl.space {
            ConstTpl::CurSpace => env.cur_space(),
            ConstTpl::Space(space) => space,
            ConstTpl::Handle {
                index,
                select: HandleSelect::Space,
                ..
            } => env.child_handle(n, index)?.space,
            _ => return Err(DecodeError::NotASpace { address: env.addr }),
        };
        hand.size = env.fix_const(&tpl.size, n)? as u32;
        // fillinOffset.
        if let ConstTpl::Handle { index, .. } = tpl.ptr_offset {
            let other = env.child_handle(n, index)?;
            hand.offset_space = other.offset_space;
            hand.offset_offset = other.offset_offset;
            hand.offset_size = other.offset_size;
            hand.temp_space = other.temp_space;
            hand.temp_offset = other.temp_offset;
        } else {
            hand.offset_space = FixedHandle::NO_SPACE;
            hand.offset_offset = wrap(env, hand.space, env.fix_const(&tpl.ptr_offset, n)?);
        }
    } else {
        hand.space = env.fix_space(&tpl.space, n)?;
        hand.size = env.fix_const(&tpl.size, n)? as u32;
        hand.offset_offset = env.fix_const(&tpl.ptr_offset, n)?;
        hand.offset_space = env.fix_space(&tpl.ptr_space, n)?;
        if hand.offset_space == CONST {
            hand.offset_space = FixedHandle::NO_SPACE;
            let word = env
                .lang
                .spaces()
                .space_at(hand.space)
                .map_or(1, |space| u64::from(space.word_size().max(1)));
            hand.offset_offset = wrap(env, hand.space, hand.offset_offset.wrapping_mul(word));
        } else {
            hand.offset_size = env.fix_const(&tpl.ptr_size, n)? as u32;
            hand.temp_space = env.fix_space(&tpl.temp_space, n)?;
            hand.temp_offset = env.fix_const(&tpl.temp_offset, n)?;
        }
    }
    Ok(hand)
}

fn wrap(env: &Env<'_>, space: u32, offset: u64) -> u64 {
    env.lang
        .spaces()
        .space_at(space)
        .map_or(offset, |s| s.wrap_offset(offset))
}

/// The handle of a non-subtable operand at node `n` (Ghidra
/// `getFixedHandle` of its defining symbol, or the value of its defining
/// expression).
pub(crate) fn operand_handle(env: &Env<'_>, def: OpDef, n: u32) -> Result<FixedHandle, DecodeError> {
    let point = Point::Node(n);
    Ok(match def {
        OpDef::Expr(expr) | OpDef::Value(expr) => FixedHandle::fixed(CONST, env.eval(expr, point, 0)? as u64, 0),
        OpDef::Table {
            symbol, expr, kind, ..
        } => {
            let value = env.eval(expr, point, 0)?;
            let missing = || DecodeError::NoTableEntry {
                address: env.addr,
                at: env.lang.raw_text(env.addr),
                table: kind,
            };
            match (kind, env.sla.symbol(symbol).map(|s| s.kind)) {
                (TableKind::ValueTable, Some(SymbolKind::ValueMap { table, .. })) => {
                    let entry = env
                        .sla
                        .value_table(table)
                        .get(value as u32 as usize)
                        .copied()
                        .ok_or_else(missing)?;
                    FixedHandle::fixed(CONST, entry as u64, 0)
                }
                (TableKind::VarnodeList, Some(SymbolKind::VarnodeList { table, .. })) => {
                    let register = env
                        .sla
                        .varnode_table(table)
                        .get(value as u32 as usize)
                        .copied()
                        .flatten()
                        .ok_or_else(missing)?;
                    match env.sla.symbol(register).map(|s| s.kind) {
                        Some(SymbolKind::Varnode {
                            space,
                            offset,
                            size,
                        }) => FixedHandle::fixed(space, offset, size.max(0) as u32),
                        _ => return Err(missing()),
                    }
                }
                _ => FixedHandle::fixed(CONST, value as u64, 0),
            }
        }
        OpDef::Varnode {
            space,
            offset,
            size,
            ..
        } => FixedHandle::fixed(space, offset, size),
        OpDef::Start => env.address_handle(Some(env.addr))?,
        OpDef::End => env.address_handle(Some(env.naddr.unwrap_or(env.addr)))?,
        OpDef::Next2 => env.address_handle(env.next2)?,
        OpDef::Zero | OpDef::Subtable(_) => FixedHandle::fixed(CONST, 0, 0),
    })
}
