//! What is written (`SymbolTable::purge`, `renumber`, inventory 9.10):
//! symbols the file does not hold are removed, empty scopes dropped, and
//! scopes and symbols renumbered densely in their old order.

use crate::compiler::{Compiler, ContextChange};
use crate::elaborated::{Constructor, Elaborated, Table};
use crate::ids::{CtorId, ScopeId, SymbolId, TableId};
use crate::symbols::{SymbolData, SymbolKind};

const GONE: u32 = u32::MAX;

/// Which symbols survive the purge.
fn survivors(c: &Compiler<'_>, reachable: &[bool]) -> Vec<bool> {
    let n = c.symbols.len();
    let mut keep = vec![true; n];
    let remove = |id: SymbolId, keep: &mut Vec<bool>| {
        if let Some(k) = keep.get_mut(id.slot()) {
            *k = false;
        }
    };
    for (id, symbol) in c.symbols.iter() {
        if symbol.scope != ScopeId::GLOBAL {
            if !matches!(symbol.kind, SymbolKind::Operand(_)) {
                remove(id, &mut keep);
            }
            continue;
        }
        match &symbol.kind {
            SymbolKind::Space(_)
            | SymbolKind::Token(_)
            | SymbolKind::Epsilon
            | SymbolKind::Section(_)
            | SymbolKind::Bitrange { .. } => {
                remove(id, &mut keep);
            }
            SymbolKind::Macro(m) => {
                remove(id, &mut keep);
                for op in c.macros.get(m.slot()).map_or(&[][..], |d| &d.params[..]) {
                    if let Some(data) = c.operands.get(op.slot()) {
                        remove(data.symbol, &mut keep);
                    }
                }
            }
            SymbolKind::Subtable(t) if !reachable.get(t.slot()).copied().unwrap_or(false) => {
                remove(id, &mut keep);
                for &ctor in c.tables.get(t.slot()).map_or(&[][..], |t| &t.ctors[..]) {
                    for op in c
                        .ctors
                        .get(ctor.slot())
                        .map_or(&[][..], |c| &c.operands[..])
                    {
                        if let Some(data) = c.operands.get(op.slot()) {
                            remove(data.symbol, &mut keep);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    keep
}

/// Builds the elaborated specification with the file's ids.
pub(crate) fn finish(c: &Compiler<'_>) -> Elaborated {
    let reachable = c.reachable_tables();
    let keep = survivors(c, &reachable);

    // Scopes: the global scope, and every scope still holding a symbol.
    let mut scope_used = vec![false; c.symbols.num_scopes()];
    if let Some(g) = scope_used.first_mut() {
        *g = true;
    }
    for (id, symbol) in c.symbols.iter() {
        if keep.get(id.slot()).copied().unwrap_or(false)
            && let Some(u) = scope_used.get_mut(symbol.scope.slot())
        {
            *u = true;
        }
    }
    let mut scope_map = vec![GONE; scope_used.len()];
    let mut scopes = Vec::new();
    for (i, used) in scope_used.iter().enumerate() {
        if *used {
            if let Some(m) = scope_map.get_mut(i) {
                *m = scopes.len() as u32;
            }
            scopes.push(i);
        }
    }
    let scopes: Vec<Option<ScopeId>> = scopes
        .iter()
        .map(|&old| {
            c.symbols
                .scope_parent(ScopeId::new(old as u32))
                .and_then(|p| scope_map.get(p.slot()).copied())
                .filter(|&p| p != GONE)
                .map(ScopeId::new)
        })
        .collect();

    let mut symbol_map = vec![GONE; c.symbols.len()];
    let mut next = 0_u32;
    for (i, k) in keep.iter().enumerate() {
        if *k {
            if let Some(m) = symbol_map.get_mut(i) {
                *m = next;
            }
            next += 1;
        }
    }
    let map_symbol =
        |id: SymbolId| SymbolId::new(symbol_map.get(id.slot()).copied().unwrap_or(GONE));

    let back = c.back.as_ref();
    let mut ctor_map = vec![GONE; c.ctors.len()];
    let mut operand_layout = vec![crate::build::OperandLayout::default(); c.operands.len()];
    let mut table_map = vec![GONE; c.tables.len()];
    let mut tables = Vec::new();
    let mut constructors = Vec::new();
    for (i, table) in c.tables.iter().enumerate() {
        if !reachable.get(i).copied().unwrap_or(false) {
            continue;
        }
        if let Some(m) = table_map.get_mut(i) {
            *m = tables.len() as u32;
        }
        let new_table = TableId::new(tables.len() as u32);
        let mut list = Vec::with_capacity(table.ctors.len());
        for &ctor in &table.ctors {
            let Some(data) = c.ctors.get(ctor.slot()) else {
                continue;
            };
            if let Some(m) = ctor_map.get_mut(ctor.slot()) {
                *m = constructors.len() as u32;
            }
            list.push(CtorId::new(constructors.len() as u32));
            let built = back
                .and_then(|b| b.state.ctors.get(ctor.slot()))
                .and_then(Option::as_ref);
            if let Some(built) = built {
                for (op, layout) in data.operands.iter().zip(&built.layout) {
                    if let Some(slot) = operand_layout.get_mut(op.slot()) {
                        *slot = *layout;
                    }
                }
            }
            constructors.push(Constructor {
                length: built.map_or(0, |b| b.min_length),
                handmap: built.map_or_else(
                    || (0..data.operands.len() as u32).collect(),
                    |b| b.handmap.clone(),
                ),
                table: new_table,
                source: data.source,
                line: data.line,
                at: data.at,
                operands: data.operands.clone(),
                print: data.print.clone(),
                first: data.first,
                equation: data.equation,
                context: data
                    .context
                    .iter()
                    .map(|change| match *change {
                        ContextChange::Commit {
                            symbol,
                            word,
                            mask,
                            flow,
                        } => ContextChange::Commit {
                            symbol: map_symbol(symbol),
                            word,
                            mask,
                            flow,
                        },
                        op @ ContextChange::Op { .. } => op,
                    })
                    .collect(),
                main: data.main.clone(),
                sections: data.named.clone(),
            });
        }
        tables.push(Table {
            symbol: map_symbol(table.symbol),
            constructors: list,
            decision: back
                .and_then(|b| b.trees.get(i))
                .and_then(Option::clone)
                .unwrap_or_default(),
        });
    }

    let symbols: Vec<SymbolData> = c
        .symbols
        .iter()
        .filter(|(id, _)| keep.get(id.slot()).copied().unwrap_or(false))
        .map(|(_, s)| {
            let kind = match &s.kind {
                SymbolKind::Context {
                    varnode,
                    low,
                    high,
                    flow,
                    field,
                } => SymbolKind::Context {
                    varnode: map_symbol(*varnode),
                    low: *low,
                    high: *high,
                    flow: *flow,
                    field: *field,
                },
                SymbolKind::VarnodeList(field, list) => SymbolKind::VarnodeList(
                    *field,
                    list.iter().map(|e| e.map(map_symbol)).collect(),
                ),
                SymbolKind::Subtable(t) => SymbolKind::Subtable(TableId::new(
                    table_map.get(t.slot()).copied().unwrap_or(GONE),
                )),
                other => other.clone(),
            };
            SymbolData {
                name: s.name,
                scope: ScopeId::new(scope_map.get(s.scope.slot()).copied().unwrap_or(GONE)),
                kind,
                defined_at: s.defined_at,
            }
        })
        .collect();

    let operands = c
        .operands
        .iter()
        .map(|o| {
            let mut o = o.clone();
            o.symbol = map_symbol(o.symbol);
            o.def_symbol = o.def_symbol.map(map_symbol);
            o.ctor = o
                .ctor
                .and_then(|ct| ctor_map.get(ct.slot()).copied())
                .filter(|&n| n != GONE)
                .map(CtorId::new);
            o
        })
        .collect();

    Elaborated {
        big_endian: c.big_endian,
        align: c.align,
        unique_base: c.unique_base,
        max_delay: c.max_delay,
        unique_mask: if c.crossbuild { 0xff } else { 0 },
        num_sections: c.sections.len() as u32,
        spaces: c.spaces.clone(),
        default_space: c.default_space.unwrap_or(0),
        source_files: c.indexer.iter().map(str::to_owned).collect(),
        scopes,
        symbols,
        names: c.names.clone(),
        operands,
        tables,
        constructors,
        patterns: c.patterns.clone(),
        operand_layout,
    }
}
