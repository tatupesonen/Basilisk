//! Fast structural equality of model values that live in arenas, used
//! before rendering a difference.

use crate::model::Sla;
use crate::model::constructor::{Constructor, ContextChange, DisjointPattern, PrintPiece};
use crate::model::expr::Expr;
use crate::model::handles::{BlockId, ExprId};
use crate::model::symbol::SymbolKind;

pub(super) fn expr_eq(a: &Sla, x: ExprId, b: &Sla, y: ExprId) -> bool {
    let mut work = vec![(x, y)];
    while let Some((x, y)) = work.pop() {
        let (Some(ex), Some(ey)) = (a.expr(x), b.expr(y)) else {
            return false;
        };
        let same = match (*ex, *ey) {
            (Expr::TokenField(fx), Expr::TokenField(fy))
            | (Expr::ContextField(fx), Expr::ContextField(fy)) => a.field(fx) == b.field(fy),
            (Expr::Binary { op, left, right }, Expr::Binary { op: oy, left: ly, right: ry }) => {
                work.push((left, ly));
                work.push((right, ry));
                op == oy
            }
            (Expr::Unary { op, operand }, Expr::Unary { op: oy, operand: py }) => {
                work.push((operand, py));
                op == oy
            }
            (ex, ey) => ex == ey,
        };
        if !same {
            return false;
        }
    }
    true
}

pub(super) fn kind_eq(a: &Sla, x: &SymbolKind, b: &Sla, y: &SymbolKind) -> bool {
    match (*x, *y) {
        (SymbolKind::Value { expr }, SymbolKind::Value { expr: ey }) => expr_eq(a, expr, b, ey),
        (SymbolKind::ValueMap { expr, table }, SymbolKind::ValueMap { expr: ey, table: ty }) => {
            expr_eq(a, expr, b, ey) && a.value_table(table) == b.value_table(ty)
        }
        (SymbolKind::Name { expr, table }, SymbolKind::Name { expr: ey, table: ty }) => {
            let (nx, ny) = (a.name_table(table), b.name_table(ty));
            expr_eq(a, expr, b, ey)
                && nx.len() == ny.len()
                && nx.iter().zip(ny).all(|(p, q)| match (p, q) {
                    (Some(p), Some(q)) => a.text(*p) == b.text(*q),
                    (None, None) => true,
                    _ => false,
                })
        }
        (
            SymbolKind::VarnodeList { expr, table },
            SymbolKind::VarnodeList { expr: ey, table: ty },
        ) => expr_eq(a, expr, b, ey) && a.varnode_table(table) == b.varnode_table(ty),
        (
            SymbolKind::Context { varnode, low, high, flow, expr },
            SymbolKind::Context { varnode: v2, low: l2, high: h2, flow: f2, expr: e2 },
        ) => varnode == v2 && low == l2 && high == h2 && flow == f2 && expr_eq(a, expr, b, e2),
        (SymbolKind::Operand(p), SymbolKind::Operand(q)) => {
            p.index == q.index
                && p.offset == q.offset
                && p.base == q.base
                && p.min_length == q.min_length
                && p.code == q.code
                && p.defining_symbol == q.defining_symbol
                && expr_eq(a, p.local_expr, b, q.local_expr)
                && match (p.defining_expr, q.defining_expr) {
                    (Some(e1), Some(e2)) => expr_eq(a, e1, b, e2),
                    (None, None) => true,
                    _ => false,
                }
        }
        (x, y) => x == y,
    }
}

pub(super) fn print_eq(a: &Sla, x: &Constructor, b: &Sla, y: &Constructor) -> bool {
    let (px, py) = (a.print_pieces(x), b.print_pieces(y));
    px.len() == py.len()
        && px.iter().zip(py).all(|(p, q)| match (p, q) {
            (PrintPiece::Text(p), PrintPiece::Text(q)) => a.text(*p) == b.text(*q),
            (p, q) => p == q,
        })
}

pub(super) fn context_eq(a: &Sla, x: &Constructor, b: &Sla, y: &Constructor) -> bool {
    let (cx, cy) = (a.context_changes(x), b.context_changes(y));
    cx.len() == cy.len()
        && cx.iter().zip(cy).all(|(p, q)| match (*p, *q) {
            (
                ContextChange::Op { word, shift, mask, expr },
                ContextChange::Op { word: w, shift: s, mask: m, expr: e },
            ) => word == w && shift == s && mask == m && expr_eq(a, expr, b, e),
            (p, q) => p == q,
        })
}

fn block_eq(a: &Sla, x: BlockId, b: &Sla, y: BlockId) -> bool {
    match (a.block(x), b.block(y)) {
        (Some(p), Some(q)) => {
            p.offset == q.offset && p.nonzero == q.nonzero && a.block_words(p) == b.block_words(q)
        }
        _ => false,
    }
}

pub(super) fn pattern_eq(a: &Sla, x: &DisjointPattern, b: &Sla, y: &DisjointPattern) -> bool {
    match (*x, *y) {
        (DisjointPattern::Instruction(p), DisjointPattern::Instruction(q))
        | (DisjointPattern::Context(p), DisjointPattern::Context(q)) => block_eq(a, p, b, q),
        (
            DisjointPattern::Combine { context, instruction },
            DisjointPattern::Combine { context: c2, instruction: i2 },
        ) => block_eq(a, context, b, c2) && block_eq(a, instruction, b, i2),
        _ => false,
    }
}
