//! Text forms of model values for differences.

use std::fmt::Write as _;

use crate::model::Sla;
use crate::model::constructor::{ContextChange, DisjointPattern};
use crate::model::expr::{BinaryOp, Expr, UnaryOp};
use crate::model::handles::{BlockId, ExprId};
use crate::model::symbol::SymbolKind;
use crate::model::template::{ConstTpl, VarnodeTpl};

pub(super) fn render_const(sla: &Sla, value: &ConstTpl) -> String {
    match *value {
        ConstTpl::Real(v) => format!("const_real {v:#x}"),
        ConstTpl::Handle {
            index,
            select,
            plus,
        } => {
            format!("const_handle {index} s={} plus={plus:#x}", select.number())
        }
        ConstTpl::Space(index) => format!("const_spaceid {}", sla.space_name(index).unwrap_or("?")),
        ConstTpl::Relative(v) => format!("const_relative {v}"),
        other => other.element_name().to_owned(),
    }
}

pub(super) fn render_varnode(sla: &Sla, v: &VarnodeTpl) -> String {
    format!(
        "({}, {}, {})",
        render_const(sla, &v.space),
        render_const(sla, &v.offset),
        render_const(sla, &v.size)
    )
}

pub(super) fn render_expr(sla: &Sla, id: ExprId) -> String {
    let mut out = String::new();
    write_expr(sla, id, &mut out, 0);
    out
}

fn write_expr(sla: &Sla, id: ExprId, out: &mut String, depth: u32) {
    if depth > 256 {
        out.push_str("...");
        return;
    }
    let Some(expr) = sla.expr(id) else {
        out.push('?');
        return;
    };
    match *expr {
        Expr::TokenField(field) | Expr::ContextField(field) => {
            let f = sla.field(field).copied().unwrap_or_default();
            let kind = if matches!(expr, Expr::TokenField(_)) {
                "token"
            } else {
                "context"
            };
            let _ = write!(
                out,
                "{kind}(be={} sign={} bits {}..{} bytes {}..{} shift {})",
                f.big_endian, f.sign_bit, f.start_bit, f.end_bit, f.start_byte, f.end_byte, f.shift
            );
        }
        Expr::Constant(v) => {
            let _ = write!(out, "{v}");
        }
        Expr::Operand { index, table, ct } => {
            let _ = write!(out, "operand({index} of {table}/{ct})");
        }
        Expr::Start => out.push_str("inst_start"),
        Expr::End => out.push_str("inst_next"),
        Expr::Next2 => out.push_str("inst_next2"),
        Expr::Binary { op, left, right } => {
            out.push('(');
            write_expr(sla, left, out, depth + 1);
            out.push_str(match op {
                BinaryOp::Plus => " + ",
                BinaryOp::Sub => " - ",
                BinaryOp::Mult => " * ",
                BinaryOp::LeftShift => " << ",
                BinaryOp::RightShift => " >> ",
                BinaryOp::And => " & ",
                BinaryOp::Or => " | ",
                BinaryOp::Xor => " ^ ",
                BinaryOp::Div => " / ",
            });
            write_expr(sla, right, out, depth + 1);
            out.push(')');
        }
        Expr::Unary { op, operand } => {
            out.push(if op == UnaryOp::Minus { '-' } else { '~' });
            write_expr(sla, operand, out, depth + 1);
        }
    }
}

pub(super) fn render_kind(sla: &Sla, kind: &SymbolKind) -> String {
    match *kind {
        SymbolKind::UserOp { index } => format!("index {index}"),
        SymbolKind::Value { expr } => render_expr(sla, expr),
        SymbolKind::ValueMap { expr, table } => {
            format!("{} {:?}", render_expr(sla, expr), sla.value_table(table))
        }
        SymbolKind::Name { expr, table } => {
            let names: Vec<_> = sla
                .name_table(table)
                .iter()
                .map(|n| n.map_or("<none>", |n| sla.text(n)))
                .collect();
            format!("{} {names:?}", render_expr(sla, expr))
        }
        SymbolKind::Varnode {
            space,
            offset,
            size,
        } => format!(
            "{}:{offset:#x}:{size}",
            sla.space_name(space).unwrap_or("?")
        ),
        SymbolKind::Context {
            varnode,
            low,
            high,
            flow,
            expr,
        } => format!(
            "varnode {varnode} bits {low}..{high} flow={flow} {}",
            render_expr(sla, expr)
        ),
        SymbolKind::VarnodeList { expr, table } => {
            let vars: Vec<_> = sla
                .varnode_table(table)
                .iter()
                .map(|v| v.map_or_else(|| "null".to_owned(), |v| v.to_string()))
                .collect();
            format!("{} [{}]", render_expr(sla, expr), vars.join(", "))
        }
        SymbolKind::Operand(op) => format!(
            "index={} off={} base={} minlen={} code={} subsym={} local={} def={}",
            op.index,
            op.offset,
            op.base,
            op.min_length,
            op.code,
            op.defining_symbol
                .map_or_else(|| "none".to_owned(), |s| s.to_string()),
            render_expr(sla, op.local_expr),
            op.defining_expr
                .map_or_else(|| "none".to_owned(), |e| render_expr(sla, e)),
        ),
        _ => String::new(),
    }
}

pub(super) fn render_change(sla: &Sla, change: &ContextChange) -> String {
    match *change {
        ContextChange::Op {
            word,
            shift,
            mask,
            expr,
        } => format!(
            "context_op i={word} shift={shift} mask={mask:#x} {}",
            render_expr(sla, expr)
        ),
        ContextChange::Commit {
            symbol,
            word,
            mask,
            flow,
        } => format!("commit {symbol} number={word} mask={mask:#x} flow={flow}"),
    }
}

fn render_block(sla: &Sla, id: BlockId) -> String {
    let Some(block) = sla.block(id) else {
        return "?".to_owned();
    };
    let words: Vec<_> = sla
        .block_words(block)
        .iter()
        .map(|w| format!("{:08x}/{:08x}", w.mask, w.value))
        .collect();
    format!(
        "off={} nonzero={} [{}]",
        block.offset,
        block.nonzero,
        words.join(" ")
    )
}

pub(super) fn render_pattern(sla: &Sla, pattern: &DisjointPattern) -> String {
    match *pattern {
        DisjointPattern::Instruction(b) => format!("instruct {}", render_block(sla, b)),
        DisjointPattern::Context(b) => format!("context {}", render_block(sla, b)),
        DisjointPattern::Combine {
            context,
            instruction,
        } => format!(
            "combine context {} instruct {}",
            render_block(sla, context),
            render_block(sla, instruction)
        ),
    }
}
