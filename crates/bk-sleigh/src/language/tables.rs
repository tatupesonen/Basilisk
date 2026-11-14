//! What the decoder precomputes per constructor and per operand when a
//! language is loaded: operand placement and definitions, whether a table
//! is completely filled (Ghidra `checkTableFill`), the flow-through operand
//! and the delay-slot count.

use bk_sla::{ConstructorId, Expr, ExprId, PrintPiece, Sla, Span, SymbolId, SymbolKind};

use crate::error::TableKind;

/// How an operand is defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpDef {
    /// By an expression.
    Expr(ExprId),
    /// By a subtable: a constructor is chosen for it.
    Subtable(SymbolId),
    /// By a value-map, name or varnode-list symbol.
    Table {
        /// The symbol.
        symbol: SymbolId,
        /// The field selecting the entry.
        expr: ExprId,
        /// Which table.
        kind: TableKind,
        /// The entries.
        table: Span,
        /// Whether every value of the field selects a usable entry.
        filled: bool,
    },
    /// By a value or context symbol: the field's value.
    Value(ExprId),
    /// By a varnode symbol.
    Varnode {
        /// The symbol.
        symbol: SymbolId,
        /// Space index.
        space: u32,
        /// Offset.
        offset: u64,
        /// Size.
        size: u32,
    },
    /// `inst_start`.
    Start,
    /// `inst_next`.
    End,
    /// `inst_next2`.
    Next2,
    /// `epsilon`, or a symbol with nothing to resolve.
    Zero,
}

/// One operand of one constructor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpInfo {
    /// Bytes from the constructor's start (`base < 0`) or from the end of
    /// operand `base`.
    pub(crate) offset: i32,
    /// The operand the offset is relative to, or −1.
    pub(crate) base: i32,
    /// Minimum length of a non-subtable operand.
    pub(crate) min_length: i32,
    /// The definition.
    pub(crate) def: OpDef,
}

/// One constructor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CtorInfo {
    /// First operand in [`Tables::ops`].
    pub(crate) ops: u32,
    /// Number of operands.
    pub(crate) num_ops: u32,
    /// Minimum length of the constructor's own pattern.
    pub(crate) length: i32,
    /// Delay-slot bytes its main template asks for.
    pub(crate) delay: i32,
    /// The operand printed alone, when that is the only print piece and it
    /// is a subtable (Ghidra `flowthruindex` with the subtable test).
    pub(crate) flow_through: Option<u32>,
    /// Whether the constructor has a main template (its body is not
    /// `unimpl`).
    pub(crate) has_main: bool,
    /// The main template's id (meaningful when `has_main`).
    pub(crate) main: bk_sla::TemplateId,
    /// First context change in [`Tables::changes`].
    pub(crate) changes: u32,
    /// Number of context changes.
    pub(crate) num_changes: u32,
}

/// The precomputed tables of a language.
#[derive(Clone, Debug, Default)]
pub(crate) struct Tables {
    pub(crate) ctors: Vec<CtorInfo>,
    pub(crate) ops: Vec<OpInfo>,
    /// Whether some operand prints or resolves through `inst_next2`.
    pub(crate) uses_next2: bool,
    /// Whether anything handle resolution or commits reach uses
    /// `inst_next2` (operands, exports, commit symbols).
    pub(crate) next2_anywhere: bool,
    /// For each symbol, its varnode (space, offset, size) when it is a
    /// varnode symbol: what a varnode-list operand resolves to.
    pub(crate) varnodes: Vec<Option<(u32, u64, u32)>>,
    /// The decision trees.
    pub(crate) trees: super::decide::Trees,
    /// Every constructor's context changes, in order ([`CtorInfo::changes`]).
    pub(crate) changes: Vec<bk_sla::ContextChange>,
}

impl Tables {
    pub(crate) fn build(sla: &Sla) -> Self {
        let mut tables = Self {
            varnodes: sla
                .symbols()
                .iter()
                .map(|symbol| match symbol.kind {
                    SymbolKind::Varnode {
                        space,
                        offset,
                        size,
                    } => Some((space, offset, size.max(0) as u32)),
                    _ => None,
                })
                .collect(),
            trees: super::decide::Trees::build(sla),
            ..Self::default()
        };
        for ctor in sla.constructors() {
            let start = tables.ops.len() as u32;
            for &symbol in sla.operands(ctor) {
                let info = match sla.symbol(symbol).map(|s| s.kind) {
                    Some(SymbolKind::Operand(operand)) => OpInfo {
                        offset: operand.offset,
                        base: operand.base,
                        min_length: operand.min_length,
                        def: definition(sla, operand.defining_symbol, operand.defining_expr),
                    },
                    _ => OpInfo {
                        offset: 0,
                        base: -1,
                        min_length: 0,
                        def: OpDef::Zero,
                    },
                };
                if info.def == OpDef::Next2
                    || matches!(info.def, OpDef::Expr(expr) if mentions_next2(sla, expr))
                {
                    tables.uses_next2 = true;
                }
                tables.ops.push(info);
            }
            let num_ops = tables.ops.len() as u32 - start;
            let flow_through = match sla.print_pieces(ctor) {
                [PrintPiece::Operand(index)] => u32::try_from(*index).ok().filter(|&i| {
                    tables
                        .ops
                        .get((start + i) as usize)
                        .is_some_and(|op| matches!(op.def, OpDef::Subtable(_)))
                }),
                _ => None,
            };
            let main = sla.main_template(ctor);
            let export_next2 = main
                .and_then(|t| t.result().copied())
                .is_some_and(|h| h.parts().contains(&bk_sla::ConstTpl::Next2));
            let commit_next2 = sla.context_changes(ctor).iter().any(|c| {
                matches!(c, bk_sla::ContextChange::Commit { symbol, .. }
                    if matches!(sla.symbol(*symbol).map(|s| s.kind), Some(SymbolKind::Next2)))
            });
            // `inst_next2` in a p-code template: the builder needs it.
            let template_next2 = sla
                .template_ids(ctor)
                .filter_map(|id| sla.template(id))
                .any(|t| {
                    t.ops().iter().any(|op| {
                        t.output(op).into_iter().chain(t.inputs(op)).any(|vn| {
                            [vn.space, vn.offset, vn.size].contains(&bk_sla::ConstTpl::Next2)
                        })
                    })
                });
            tables.next2_anywhere |= export_next2 || commit_next2 || template_next2;
            let changes = tables.changes.len() as u32;
            tables.changes.extend_from_slice(sla.context_changes(ctor));
            tables.ctors.push(CtorInfo {
                changes,
                num_changes: tables.changes.len() as u32 - changes,
                ops: start,
                num_ops,
                length: ctor.length,
                delay: main.map_or(0, |t| t.header().delay),
                flow_through,
                has_main: main.is_some(),
                main: sla
                    .template_ids(ctor)
                    .find(|id| {
                        sla.template(*id)
                            .is_some_and(|t| t.header().section.is_none())
                    })
                    .unwrap_or(bk_sla::TemplateId::new(0)),
            });
        }
        tables.next2_anywhere |= tables.uses_next2;
        tables
    }

    /// The main template of constructor `id` (`None` for `unimpl`).
    pub(crate) fn main_template<'s>(
        &self,
        sla: &'s Sla,
        id: ConstructorId,
    ) -> Option<bk_sla::TemplateRef<'s>> {
        let info = self.ctor(id)?;
        if info.has_main {
            sla.template(info.main)
        } else {
            None
        }
    }

    pub(crate) fn ctor(&self, id: ConstructorId) -> Option<&CtorInfo> {
        self.ctors.get(id.index() as usize)
    }

    /// The context changes of a constructor.
    pub(crate) fn changes(&self, ctor: &CtorInfo) -> &[bk_sla::ContextChange] {
        self.changes
            .get(ctor.changes as usize..ctor.changes.wrapping_add(ctor.num_changes) as usize)
            .unwrap_or_default()
    }

    pub(crate) fn op(&self, ctor: &CtorInfo, index: u32) -> Option<&OpInfo> {
        if index >= ctor.num_ops {
            return None;
        }
        self.ops.get(ctor.ops.wrapping_add(index) as usize)
    }
}

/// How a symbol resolves when it is used directly (a commit's symbol).
pub(crate) fn symbol_def(sla: &Sla, symbol: SymbolId) -> OpDef {
    definition(sla, Some(symbol), None)
}

fn definition(sla: &Sla, symbol: Option<SymbolId>, expr: Option<ExprId>) -> OpDef {
    if let Some(expr) = expr {
        return OpDef::Expr(expr);
    }
    let Some(id) = symbol else {
        return OpDef::Zero;
    };
    let Some(kind) = sla.symbol(id).map(|s| s.kind) else {
        return OpDef::Zero;
    };
    let table = |expr: ExprId, kind: TableKind, table: Span, usable: &dyn Fn(usize) -> bool| {
        let filled = fills(sla, expr, table.len()) && (0..table.len() as usize).all(usable);
        OpDef::Table {
            symbol: id,
            expr,
            kind,
            table,
            filled,
        }
    };
    match kind {
        SymbolKind::Subtable(_) => OpDef::Subtable(id),
        SymbolKind::ValueMap { expr, table: span } => {
            let values = sla.value_table(span);
            table(expr, TableKind::ValueTable, span, &|i| {
                values.get(i).is_some_and(|&v| v != 0xBAD_BEEF)
            })
        }
        SymbolKind::Name { expr, table: span } => {
            let names = sla.name_table(span);
            table(expr, TableKind::NameTable, span, &|i| {
                names.get(i).is_some_and(|name| usable_name(sla, *name))
            })
        }
        SymbolKind::VarnodeList { expr, table: span } => {
            let entries = sla.varnode_table(span);
            table(expr, TableKind::VarnodeList, span, &|i| {
                entries.get(i).is_some_and(Option::is_some)
            })
        }
        SymbolKind::Value { expr } | SymbolKind::Context { expr, .. } => OpDef::Value(expr),
        SymbolKind::Varnode {
            space,
            offset,
            size,
        } => OpDef::Varnode {
            symbol: id,
            space,
            offset,
            size: size.max(0) as u32,
        },
        SymbolKind::Start => OpDef::Start,
        SymbolKind::End => OpDef::End,
        SymbolKind::Next2 => OpDef::Next2,
        _ => OpDef::Zero,
    }
}

/// Whether a name-table entry is usable: present, and not `_` or a tab
/// (Ghidra `NameSymbol::checkTableFill` turns both into the unusable mark).
pub(crate) fn usable_name(sla: &Sla, name: Option<bk_sla::StrId>) -> bool {
    name.is_some_and(|id| !matches!(sla.text(id), "_" | "\t"))
}

/// Ghidra `checkTableFill`'s range test: the field's smallest value is at
/// least 0 and its largest is below the table size.
fn fills(sla: &Sla, expr: ExprId, size: u32) -> bool {
    let (min, max) = match sla.expr(expr) {
        Some(Expr::TokenField(field) | Expr::ContextField(field)) => {
            let Some(field) = sla.field(*field) else {
                return false;
            };
            let bits = field.end_bit.wrapping_sub(field.start_bit);
            (0, zero_extend(-1, bits))
        }
        Some(Expr::Constant(value)) => (*value, *value),
        Some(Expr::Start | Expr::End | Expr::Next2) => (0, 0),
        _ => return false,
    };
    // `max < size` compares a signed value with an unsigned size in C++.
    min >= 0 && (max as u64) < u64::from(size)
}

/// Ghidra `zero_extend(val, bit)`: clears the bits above `bit`; the shift
/// count is taken modulo 64 as on x86-64 (ADR-021).
pub(crate) fn zero_extend(value: i64, bit: i32) -> i64 {
    let shift = (63i32.wrapping_sub(bit)) as u32;
    (value
        .cast_unsigned()
        .wrapping_shl(shift)
        .wrapping_shr(shift))
    .cast_signed()
}

/// Ghidra `sign_extend(val, bit)`: copies bit `bit` into the bits above it.
pub(crate) fn sign_extend(value: i64, bit: i32) -> i64 {
    let shift = (63i32.wrapping_sub(bit)) as u32;
    value.wrapping_shl(shift).wrapping_shr(shift)
}

fn mentions_next2(sla: &Sla, root: ExprId) -> bool {
    let mut stack = vec![root];
    let mut budget = 4096usize;
    while let Some(id) = stack.pop() {
        budget = budget.saturating_sub(1);
        if budget == 0 {
            return false;
        }
        match sla.expr(id) {
            Some(Expr::Next2) => return true,
            Some(Expr::Binary { left, right, .. }) => {
                stack.push(*left);
                stack.push(*right);
            }
            Some(Expr::Unary { operand, .. }) => stack.push(*operand),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_match_ghidra() {
        assert_eq!(zero_extend(-1, 3), 0xf);
        assert_eq!(zero_extend(-1, 63), -1);
        assert_eq!(sign_extend(0x8, 3), -8);
        assert_eq!(sign_extend(0x7, 3), 7);
        assert_eq!(sign_extend(0x80, 7), -128);
        assert_eq!(sign_extend(-1, 63), -1);
    }
}
