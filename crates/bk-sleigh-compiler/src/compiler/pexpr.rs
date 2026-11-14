//! Pattern expressions (`pexpression` of `slghparse.y` 290-308).

use bk_sla::{BinaryOp, UnaryOp};
use bk_sleigh_syntax::ast::{PatBinaryOp, PatExpr, PatExprId, PatUnaryOp};

use super::Compiler;
use crate::ids::PExprId;
use crate::pattern::PExpr;
use crate::symbols::SymbolKind;

/// A pattern expression could not be built (a syntax error was reported).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BadExpr;

impl Compiler<'_> {
    /// Builds a pattern expression. `action` is set inside a context block,
    /// where a family symbol other than a context field is an error
    /// (Ghidra's `actionon`).
    pub(crate) fn pattern_expr(&mut self, id: PatExprId, action: bool) -> Result<PExprId, BadExpr> {
        let nodes = &self.parsed.spec.nodes;
        match &nodes[id] {
            PatExpr::Int(lit) => {
                if let Some(v) = lit.to_u64() {
                    Ok(self.pexpr(PExpr::Constant(v as i64)))
                } else {
                    self.syntax_error(lit.span);
                    Err(BadExpr)
                }
            }
            PatExpr::Ident(ident) => {
                let ident = *ident;
                let Some(sym) = self.lookup(ident.name) else {
                    self.syntax_error(ident.span);
                    return Err(BadExpr);
                };
                let kind = self.kind(sym).cloned();
                match kind {
                    Some(k) if k.is_family() => {
                        if action && !matches!(k, SymbolKind::Context { .. }) {
                            let message = format!(
                                "Global symbol {} is not allowed in action expression",
                                self.text(ident.name)
                            );
                            self.diags.error(Some(ident.span), message);
                        }
                        let value = k.pattern_value().map_or(PExpr::Constant(0), PExpr::Field);
                        Ok(self.pexpr(value))
                    }
                    Some(SymbolKind::Varnode(_) | SymbolKind::Epsilon) => {
                        Ok(self.pexpr(PExpr::Constant(0)))
                    }
                    Some(SymbolKind::Operand(op)) => Ok(self
                        .operands
                        .get(op.slot())
                        .map_or_else(|| self.patterns.expr(PExpr::Operand(op)), |o| o.local_expr)),
                    Some(SymbolKind::Start) => Ok(self.pexpr(PExpr::Start)),
                    Some(SymbolKind::End) => Ok(self.pexpr(PExpr::End)),
                    Some(SymbolKind::Next2) => Ok(self.pexpr(PExpr::Next2)),
                    _ => {
                        self.syntax_error(ident.span);
                        Err(BadExpr)
                    }
                }
            }
            PatExpr::Paren { inner, .. } => self.pattern_expr(*inner, action),
            PatExpr::Apply { span, .. } | PatExpr::Error(span) => {
                let span = *span;
                self.syntax_error(span);
                Err(BadExpr)
            }
            PatExpr::Unary { op, operand, .. } => {
                let op = *op;
                let operand = self.pattern_expr(*operand, action)?;
                let op = match op {
                    PatUnaryOp::Negate => UnaryOp::Minus,
                    PatUnaryOp::Invert => UnaryOp::Not,
                };
                Ok(self.pexpr(PExpr::Unary { op, operand }))
            }
            PatExpr::Binary { op, lhs, rhs, .. } => {
                let (op, lhs, rhs) = (*op, *lhs, *rhs);
                let left = self.pattern_expr(lhs, action)?;
                let right = self.pattern_expr(rhs, action)?;
                let op = match op {
                    PatBinaryOp::Or => BinaryOp::Or,
                    PatBinaryOp::Xor => BinaryOp::Xor,
                    PatBinaryOp::And => BinaryOp::And,
                    PatBinaryOp::Left => BinaryOp::LeftShift,
                    PatBinaryOp::Right => BinaryOp::RightShift,
                    PatBinaryOp::Add => BinaryOp::Plus,
                    PatBinaryOp::Sub => BinaryOp::Sub,
                    PatBinaryOp::Mult => BinaryOp::Mult,
                    PatBinaryOp::Div => BinaryOp::Div,
                };
                Ok(self.pexpr(PExpr::Binary { op, left, right }))
            }
        }
    }
}
