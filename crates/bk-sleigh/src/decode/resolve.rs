//! Resolving an instruction: choosing constructors depth-first, placing
//! operands, applying context changes and computing lengths (Ghidra
//! `Sleigh::resolve`; inventory section 5).

use bk_core::Address;
use bk_sla::{ConstructorId, ContextChange, SymbolId};

use super::bytes::ByteSource;
use super::expr::{Env, Point};
use super::fault::{Fault, What};
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
pub(crate) fn env<'a>(lang: &'a Language, parse: &'a Parse, naddr: Option<Address>) -> Env<'a> {
    Env {
        lang,
        sla: lang.sla(),
        parse,
        naddr,
    }
}

/// Adds `delta` bytes to an address, wrapping in its space (Ghidra
/// `Address::operator+`).
pub(crate) fn add(lang: &Language, addr: Address, delta: u64) -> Address {
    match addr.space().and_then(|space| lang.spaces().space(space)) {
        Some(space) => Address::new(
            space.id(),
            space.wrap_offset(addr.offset().wrapping_add(delta)),
        ),
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
    operand_limit: u32,
) -> Result<(), DecodeError>
where
    B: ByteSource + ?Sized,
    C: ContextSource + ?Sized,
{
    parse.state = ParseState::Empty;
    parse.addr = addr;
    parse.naddr = addr;
    parse.next2 = None;
    parse.next2_error = None;
    parse.delay_slot = 0;
    parse.commits.clear();
    parse.nodes.clear();
    parse.overhang.set(false);
    parse.max_operands = 0;
    parse.window.fill(bytes, addr);
    parse.context.clear();
    parse.context.resize(lang.context_words(), 0);
    context.context_at(addr, &mut parse.context);

    walk(lang, parse, operand_limit).map_err(|fault| fault.at(lang, addr))?;
    parse.naddr = add(lang, addr, u64::from(parse.length()));
    parse.state = ParseState::Resolved;
    Ok(())
}

fn walk(lang: &Language, parse: &mut Parse, operand_limit: u32) -> Result<(), Fault> {
    parse.nodes.push(Node::new(NONE));
    let root = env(lang, parse, None).choose(lang.sla().root(), 0)?;
    set_constructor(lang, parse, 0, root)?;

    let mut crumbs = [0u32; MAX_DEPTH];
    let mut depth = 0usize;
    let mut cur = 0u32;
    loop {
        let node = *parse
            .nodes
            .get(cur as usize)
            .ok_or(Fault::Model(What::Node))?;
        let ctor_id = node
            .constructor()
            .ok_or(Fault::Model(What::NodeConstructor))?;
        let info = *lang
            .tables
            .ctor(ctor_id)
            .ok_or(Fault::Model(What::Constructor))?;
        let mut oper = crumbs.get(depth).copied().unwrap_or(0);
        let mut descended = false;
        while oper < info.num_ops {
            let op = *lang
                .tables
                .op(&info, oper)
                .ok_or(Fault::Model(What::Operand))?;
            let base = if op.base < 0 {
                node.offset
            } else {
                let child = node
                    .child(op.base as u32)
                    .and_then(|c| parse.nodes.get(c as usize))
                    .ok_or(Fault::Model(What::OperandBase))?;
                child.offset.wrapping_add(child.length)
            };
            let offset = base.wrapping_add(op.offset as u32);
            // Ghidra `allocateOperand`.
            if oper >= operand_limit {
                return Err(Fault::Limit(Limit::Operands));
            }
            if depth > MAX_DEPTH - 2 {
                return Err(Fault::Limit(Limit::Depth));
            }
            if let Some(crumb) = crumbs.get_mut(depth) {
                *crumb = oper + 1;
            }
            depth += 1;
            if let Some(crumb) = crumbs.get_mut(depth) {
                *crumb = 0;
            }
            let child = node.child(oper).ok_or(Fault::Model(What::OperandNode))?;
            {
                let slot = parse
                    .nodes
                    .get_mut(child as usize)
                    .ok_or(Fault::Model(What::OperandNode))?;
                slot.offset = offset;
                slot.visited = true;
            }
            match op.def {
                OpDef::Subtable(table) => {
                    let ct = env(lang, parse, None).choose(table, offset)?;
                    set_constructor(lang, parse, child, ct)?;
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
                } => check_entry(lang, parse, child, symbol, expr, kind)?,
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
        let children = parse
            .nodes
            .get(node.first_child as usize..)
            .unwrap_or_default()
            .iter()
            .take(node.num_children().min(info.num_ops) as usize);
        for child in children {
            end = end.max(i64::from(child.offset) + i64::from(child.length));
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
) -> Result<(), Fault> {
    let info = *lang
        .tables
        .ctor(ct)
        .ok_or(Fault::Model(What::Constructor))?;
    if let Some(node) = parse.nodes.get_mut(n as usize) {
        node.ctor = ct.index();
    }
    for change in lang.tables.changes(&info) {
        match *change {
            ContextChange::Op {
                word,
                shift,
                mask,
                expr,
            } => {
                let value = env(lang, parse, None).value(expr, Point::Node(n))? as u32;
                let value = value.wrapping_shl(shift as u32);
                if let Some(slot) = usize::try_from(word)
                    .ok()
                    .and_then(|w| parse.context.get_mut(w))
                {
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
        return Err(Fault::Limit(Limit::Nodes));
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
) -> Result<(), Fault> {
    let value = env(lang, parse, None).value(expr, Point::Node(n))?;
    if entry_usable(lang, symbol, value) {
        Ok(())
    } else {
        Err(Fault::NoTableEntry(kind))
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
