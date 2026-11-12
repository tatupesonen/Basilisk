//! Rendering of pattern equations and pattern expressions.

use std::fmt::Write as _;

use super::{Dumper, constraint_op_str, int, pat_binary_op_str};
use crate::ast::{Equation, EquationId, EquationOp, PatExpr, PatExprId, PatUnaryOp};

impl Dumper<'_> {
    pub(super) fn equation(&self, out: &mut String, id: EquationId) {
        match &self.nodes[id] {
            Equation::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(match op {
                    EquationOp::Or => "|",
                    EquationOp::Seq => ";",
                    EquationOp::And => "&",
                });
                out.push(' ');
                self.equation(out, *lhs);
                out.push(' ');
                self.equation(out, *rhs);
                out.push(')');
            }
            Equation::EllipsisLeft { inner, .. } => {
                out.push_str("(ellipsis-left ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::EllipsisRight { inner, .. } => {
                out.push_str("(ellipsis-right ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::Constraint {
                name, op, value, ..
            } => {
                out.push('(');
                out.push_str(constraint_op_str(*op));
                let _ = write!(out, " {} ", self.name(name.name));
                self.pat_expr(out, *value);
                out.push(')');
            }
            Equation::Symbol(ident) => self.ident(out, *ident),
            Equation::Error(_) => out.push_str("(error)"),
        }
    }

    pub(super) fn pat_expr(&self, out: &mut String, id: PatExprId) {
        match &self.nodes[id] {
            PatExpr::Int(lit) => int(out, lit),
            PatExpr::Ident(ident) => self.ident(out, *ident),
            PatExpr::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.pat_expr(out, *inner);
                out.push(')');
            }
            PatExpr::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.pat_exprs(*args) {
                    out.push(' ');
                    self.pat_expr(out, *arg);
                }
                out.push(')');
            }
            PatExpr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    PatUnaryOp::Negate => "(neg ",
                    PatUnaryOp::Invert => "(inv ",
                });
                self.pat_expr(out, *operand);
                out.push(')');
            }
            PatExpr::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(pat_binary_op_str(*op));
                out.push(' ');
                self.pat_expr(out, *lhs);
                out.push(' ');
                self.pat_expr(out, *rhs);
                out.push(')');
            }
            PatExpr::Error(_) => out.push_str("(error)"),
        }
    }
}
