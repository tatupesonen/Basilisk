//! Resolving an instruction: choosing constructors depth-first, placing
//! operands, applying context changes and computing lengths (Ghidra
//! `Sleigh::resolve`; inventory section 5).

use std::cell::Cell;

use bk_core::Address;
use bk_sla::{ConstructorId, ContextChange, SymbolId};

use super::bytes::ByteSource;
use super::expr::{Env, Point};
use super::tree::{Commit, NONE, Node, Parse, ParseState};
use crate::context::ContextSource;
use crate::error::{DecodeError, Limit, TableKind};
use crate::language::Language;
use crate::language::tables::{OpDef, usable_name};

/// Ghidra `ParserContext::MAX_DEPTH`: an operand is allocated only below a
/// node at depth 30 or less.
pub(crate) const MAX_DEPTH: usize = 32;

/// The most nodes one instruction may have (ADR-009).
pub(crate) const MAX_NODES: usize = 4096;

/// Builds an [`Env`] over a parse's fields.
pub(crate) fn env<'a>(
    lang: &'a Language,
    parse: &'a Parse,
    naddr: Option<Address>,
    overhang: &'a Cell<bool>,
) -> Env<'a> {
    Env {
        lang,
        sla: lang.sla(),
        window: &parse.window,
        context: &parse.context,
        nodes: &parse.nodes,
        addr: parse.addr,
        naddr,
        next2: parse.next2,
        overhang,
    }
}

/// Adds `delta` bytes to an address, wrapping in its space (Ghidra
/// `Address::operator+`).
pub(crate) fn add(lang: &Language, addr: Address, delta: u64) -> Address {
    match addr.space().and_then(|space| lang.spaces().space(space)) {
        Some(space) => Address::new(space.id(), space.wrap_offset(addr.offset().wrapping_add(delta))),
        None => addr,
    }
}

/// Decodes the instruction at `addr` into `parse`.
pub(crate) fn resolve<B, C>(
    lang: &Language,
    parse: &mut Parse,
    addr: Address,
    bytes: &B,
    context: &C,
) -> Result<(), DecodeError>
where
    B: ByteSource + ?Sized,
    C: ContextSource + ?Sized,
{
    parse.state = ParseState::Empty;
    parse.addr = addr;
    parse.naddr = addr;
    parse.next2 = None;
    parse.delay_slot = 0;
    parse.commits.clear();
    parse.nodes.clear();
    parse.overhang = false;
    parse.max_operands = 0;
    parse.window.fill(bytes, addr);
    parse.context.clear();
    parse.context.resize(lang.context_words(), 0);
    context.context_at(addr, &mut parse.context);

    let overhang = Cell::new(false);
    let result = walk(lang, parse, &overhang);
    parse.overhang = overhang.get();
    result?;
    parse.naddr = add(lang, addr, u64::from(parse.length()));
    parse.state = ParseState::Resolved;
    Ok(())
}

fn walk(lang: &Language, parse: &mut Parse, overhang: &Cell<bool>) -> Result<(), DecodeError> {
    let address = parse.addr;
    let model = |what| DecodeError::Model { address, what };
    parse.nodes.push(Node::new(NONE));
    let root = env(lang, parse, None, overhang).choose(lang.sla().root(), 0)?;
    set_constructor(lang, parse, 0, root, overhang)?;

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
            let base = if op.base < 0 {
                node.offset
            } else {
                let child = node
                    .child(op.base as u32)
                    .and_then(|c| parse.nodes.get(c as usize))
                    .ok_or_else(|| model("operand base"))?;
                child.offset.wrapping_add(child.length)
            };
            let offset = base.wrapping_add(op.offset as u32);
            // Ghidra `allocateOperand`.
            if depth > MAX_DEPTH - 2 {
                return Err(DecodeError::Limit {
                    address: parse.addr,
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
            {
                let slot = parse.nodes.get_mut(child as usize).ok_or_else(|| model("operand node"))?;
                slot.offset = offset;
                slot.visited = true;
            }
            match op.def {
                OpDef::Subtable(table) => {
                    let ct = env(lang, parse, None, overhang).choose(table, offset)?;
                    set_constructor(lang, parse, child, ct, overhang)?;
                    cur = child;
                    descended = true;
                    break;
                }
                OpDef::Table {
                    symbol,
                    expr,
                    kind,
                    filled: false,
                    ..
                } => check_entry(lang, parse, child, symbol, expr, kind, overhang)?,
                _ => {}
            }
            if let Some(slot) = parse.nodes.get_mut(child as usize) {
                slot.length = op.min_length.max(0) as u32;
            }
            depth -= 1;
            oper += 1;
        }
        if descended {
            continue;
        }
        // Ghidra `calcCurrentLength`.
        let start = i64::from(node.offset);
        let mut end = start + i64::from(info.length);
        for i in 0..info.num_ops {
            if let Some(child) = node.child(i).and_then(|c| parse.nodes.get(c as usize)) {
                end = end.max(i64::from(child.offset) + i64::from(child.length));
            }
        }
        if let Some(slot) = parse.nodes.get_mut(cur as usize) {
            slot.length = (end - start).clamp(0, i64::from(u32::MAX)) as u32;
        }
        if info.delay > 0 {
            parse.delay_slot = info.delay as u32;
        }
        if node.parent == NONE {
            return Ok(());
        }
        cur = node.parent;
        depth = depth.saturating_sub(1);
    }
}

/// Records the constructor chosen at node `n`, applies its context changes
/// (Ghidra `Constructor::applyContext`) and reserves its operand nodes.
fn set_constructor(
    lang: &Language,
    parse: &mut Parse,
    n: u32,
    ct: ConstructorId,
    overhang: &Cell<bool>,
) -> Result<(), DecodeError> {
    let address = parse.addr;
    let model = |what| DecodeError::Model { address, what };
    let info = *lang.tables.ctor(ct).ok_or_else(|| model("constructor"))?;
    let sla = lang.sla();
    let ctor = sla.constructor(ct).ok_or_else(|| model("constructor"))?;
    if let Some(node) = parse.nodes.get_mut(n as usize) {
        node.ctor = ct.index();
    }
    for change in sla.context_changes(ctor) {
        match *change {
            ContextChange::Op {
                word,
                shift,
                mask,
                expr,
            } => {
                let value = env(lang, parse, None, overhang).eval(expr, Point::Node(n), 0)? as u32;
                let value = value.wrapping_shl(shift as u32);
                if let Some(slot) = usize::try_from(word).ok().and_then(|w| parse.context.get_mut(w)) {
                    *slot = (*slot & !mask) | (value & mask);
                }
            }
            ContextChange::Commit {
                symbol,
                word,
                mask,
                flow,
            } => {
                let current = usize::try_from(word)
                    .ok()
                    .and_then(|w| parse.context.get(w))
                    .copied()
                    .unwrap_or(0);
                parse.commits.push(Commit {
                    symbol,
                    node: n,
                    word: word.max(0) as u32,
                    mask,
                    value: current & mask,
                    flow,
                });
            }
        }
    }
    let first = parse.nodes.len();
    if first + info.num_ops as usize > MAX_NODES {
        return Err(DecodeError::Limit {
            address,
            limit: Limit::Nodes,
        });
    }
    parse.max_operands = parse.max_operands.max(info.num_ops);
    parse
        .nodes
        .extend(std::iter::repeat_n(Node::new(n), info.num_ops as usize));
    if let Some(node) = parse.nodes.get_mut(n as usize) {
        node.first_child = first as u32;
        node.num_children = info.num_ops.min(u32::from(u16::MAX)) as u16;
    }
    Ok(())
}

/// Ghidra `ValueMapSymbol::resolve`, `NameSymbol::resolve`,
/// `VarnodeListSymbol::resolve`: the field must select a usable entry.
fn check_entry(
    lang: &Language,
    parse: &Parse,
    n: u32,
    symbol: SymbolId,
    expr: bk_sla::ExprId,
    kind: TableKind,
    overhang: &Cell<bool>,
) -> Result<(), DecodeError> {
    let value = env(lang, parse, None, overhang).eval(expr, Point::Node(n), 0)?;
    if entry_usable(lang, symbol, value) {
        Ok(())
    } else {
        Err(DecodeError::NoTableEntry {
            address: parse.addr,
            at: lang.raw_text(parse.addr),
            table: kind,
        })
    }
}

/// Whether `index` selects a usable entry of a table symbol's table.
pub(crate) fn entry_usable(lang: &Language, symbol: SymbolId, index: i64) -> bool {
    let sla = lang.sla();
    let Ok(index) = usize::try_from(index) else {
        return false;
    };
    match sla.symbol(symbol).map(|s| s.kind) {
        Some(bk_sla::SymbolKind::ValueMap { table, .. }) => sla
            .value_table(table)
            .get(index)
            .is_some_and(|&v| v != 0xBAD_BEEF),
        Some(bk_sla::SymbolKind::Name { table, .. }) => sla
            .name_table(table)
            .get(index)
            .is_some_and(|name| usable_name(sla, *name)),
        Some(bk_sla::SymbolKind::VarnodeList { table, .. }) => sla
            .varnode_table(table)
            .get(index)
            .is_some_and(Option::is_some),
        _ => false,
    }
}
