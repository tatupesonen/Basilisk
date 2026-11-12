//! Rendering of semantic statements and expressions.

use std::fmt::Write as _;

use super::{Dumper, int};
use crate::ast::{
    BinaryOp, ExportValue, Expr, ExprId, JumpDest, LValue, SizedStar, Statement, UnaryOp,
};

impl Dumper<'_> {
    pub(super) fn star(&self, out: &mut String, star: &SizedStar) {
        out.push_str("deref");
        if let Some(space) = star.space {
            let _ = write!(out, "[{}]", self.name(space.name));
        }
        if let Some(size) = &star.size {
            out.push(':');
            int(out, size);
        }
    }

    pub(super) fn expr(&self, out: &mut String, id: ExprId) {
        match &self.nodes[id] {
            Expr::Int(lit) => int(out, lit),
            Expr::Ident(ident) => self.ident(out, *ident),
            Expr::SizedInt { value, size } => {
                int(out, value);
                out.push(':');
                int(out, size);
            }
            Expr::Truncate { name, size } => {
                self.ident(out, *name);
                out.push(':');
                int(out, size);
            }
            Expr::BitRange {
                name, low, width, ..
            } => {
                self.ident(out, *name);
                out.push('[');
                int(out, low);
                out.push(',');
                int(out, width);
                out.push(']');
            }
            Expr::AddressOf { size, operand, .. } => {
                out.push_str("(addr");
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(' ');
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.expr(out, *inner);
                out.push(')');
            }
            Expr::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.exprs(*args) {
                    out.push(' ');
                    self.expr(out, *arg);
                }
                out.push(')');
            }
            Expr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    UnaryOp::Not => "(not ",
                    UnaryOp::Invert => "(inv ",
                    UnaryOp::Negate => "(neg ",
                    UnaryOp::FNegate => "(fneg ",
                });
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Deref { star, operand, .. } => {
                out.push('(');
                self.star(out, star);
                out.push(' ');
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(BinaryOp::as_str(*op));
                out.push(' ');
                self.expr(out, *lhs);
                out.push(' ');
                self.expr(out, *rhs);
                out.push(')');
            }
            Expr::Error(_) => out.push_str("(error)"),
        }
    }

    pub(super) fn jump_dest(&self, out: &mut String, dest: &JumpDest) {
        match dest {
            JumpDest::Symbol(ident) => self.ident(out, *ident),
            JumpDest::Dynamic(target) => {
                out.push_str("(dynamic ");
                self.expr(out, *target);
                out.push(')');
            }
            JumpDest::Absolute(address) => int(out, address),
            JumpDest::Relative { offset, space } => {
                out.push_str("(in-space ");
                int(out, offset);
                let _ = write!(out, " {})", self.name(space.name));
            }
            JumpDest::Label(name) => {
                let _ = write!(out, "<{}>", self.name(name.name));
            }
        }
    }

    pub(super) fn lvalue(&self, out: &mut String, target: &LValue) {
        match target {
            LValue::Ident(ident) => self.ident(out, *ident),
            LValue::Sized { name, size } => {
                self.ident(out, *name);
                out.push(':');
                int(out, size);
            }
            LValue::BitRange { name, low, width } => {
                self.ident(out, *name);
                out.push('[');
                int(out, low);
                out.push(',');
                int(out, width);
                out.push(']');
            }
            LValue::Deref { star, address } => {
                out.push('(');
                self.star(out, star);
                out.push(' ');
                self.expr(out, *address);
                out.push(')');
            }
        }
    }

    pub(super) fn statement(&self, out: &mut String, statement: &Statement) {
        match statement {
            Statement::Assign {
                local,
                target,
                value,
                ..
            } => {
                out.push_str(if *local { "(local= " } else { "(= " });
                self.lvalue(out, target);
                out.push(' ');
                self.expr(out, *value);
                out.push(')');
            }
            Statement::Declare { name, size, .. } => {
                let _ = write!(out, "(local {}", self.name(name.name));
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(')');
            }
            Statement::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.exprs(*args) {
                    out.push(' ');
                    self.expr(out, *arg);
                }
                out.push(')');
            }
            Statement::Build { operand, .. } => {
                let _ = write!(out, "(build {})", self.name(operand.name));
            }
            Statement::CrossBuild {
                address, section, ..
            } => {
                out.push_str("(crossbuild ");
                self.expr(out, *address);
                let _ = write!(out, " {})", self.name(section.name));
            }
            Statement::Goto { dest, .. } => {
                out.push_str("(goto ");
                self.jump_dest(out, dest);
                out.push(')');
            }
            Statement::If {
                condition, dest, ..
            } => {
                out.push_str("(if ");
                self.expr(out, *condition);
                out.push_str(" (goto ");
                self.jump_dest(out, dest);
                out.push_str("))");
            }
            Statement::Call { dest, .. } => {
                out.push_str("(call ");
                self.jump_dest(out, dest);
                out.push(')');
            }
            Statement::Return { target, .. } => {
                out.push_str("(return ");
                self.expr(out, *target);
                out.push(')');
            }
            Statement::Export { value, .. } => {
                out.push_str("(export ");
                match value {
                    ExportValue::Varnode(varnode) => self.expr(out, *varnode),
                    ExportValue::Deref { star, name } => {
                        out.push('(');
                        self.star(out, star);
                        let _ = write!(out, " {})", self.name(name.name));
                    }
                }
                out.push(')');
            }
            Statement::Label { name, .. } => {
                let _ = write!(out, "(label {})", self.name(name.name));
            }
            Statement::Section { name, .. } => {
                let _ = write!(out, "(section {})", self.name(name.name));
            }
            Statement::Error(_) => out.push_str("(error)"),
        }
    }
}
