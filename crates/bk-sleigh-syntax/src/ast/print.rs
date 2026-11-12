//! Printing trees back as SLEIGH source.
//!
//! The printer writes exactly the tokens the tree stands for, separated by
//! single spaces. Parentheses come only from `Paren` nodes, so a tree
//! produced by the parser prints to source that parses to the same tree;
//! that round trip is what the property tests check. (A tree built by hand
//! must contain its own `Paren` nodes where precedence requires them.)

use std::fmt::Write as _;

use super::{
    BinaryOp, ConstraintOp, Equation, EquationId, EquationOp, ExportValue, Expr, ExprId, Ident,
    IntLit, JumpDest, LValue, Nodes, PatBinaryOp, PatExpr, PatExprId, PatUnaryOp, SemanticBody,
    SizedStar, Statement, UnaryOp,
};
use crate::intern::Interner;

/// Prints trees whose nodes live in `nodes` and whose names live in `names`.
#[derive(Clone, Copy, Debug)]
pub struct Printer<'a> {
    nodes: &'a Nodes,
    names: &'a Interner,
}

impl<'a> Printer<'a> {
    /// A printer over the given arenas.
    pub fn new(nodes: &'a Nodes, names: &'a Interner) -> Self {
        Self { nodes, names }
    }

    /// The statements of a body, one per line, without braces.
    pub fn body(&self, body: &SemanticBody) -> String {
        let mut out = String::new();
        for statement in &body.statements {
            self.statement(&mut out, statement);
            out.push('\n');
        }
        out
    }

    /// One semantic expression.
    pub fn expr_string(&self, id: ExprId) -> String {
        let mut out = String::new();
        self.expr(&mut out, id);
        out
    }

    /// One pattern equation.
    pub fn equation_string(&self, id: EquationId) -> String {
        let mut out = String::new();
        self.equation(&mut out, id);
        out
    }

    /// One pattern expression. With `symbols`, the bitwise operators are
    /// written `|`, `^`, `&` (context blocks); without, `$or`, `$xor`,
    /// `$and` (constraints).
    pub fn pat_expr_string(&self, id: PatExprId, symbols: bool) -> String {
        let mut out = String::new();
        self.pat_expr(&mut out, id, symbols);
        out
    }

    fn ident(&self, out: &mut String, ident: Ident) {
        out.push_str(self.names.resolve(ident.name));
    }

    fn star(&self, out: &mut String, star: &SizedStar) {
        out.push('*');
        if let Some(space) = star.space {
            let _ = write!(out, "[{}]", self.names.resolve(space.name));
        }
        if let Some(size) = &star.size {
            out.push(':');
            int(out, size);
        }
    }

    fn expr(&self, out: &mut String, id: ExprId) {
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
                out.push('&');
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(' ');
                self.expr(out, *operand);
            }
            Expr::Paren { inner, .. } => {
                out.push('(');
                self.expr(out, *inner);
                out.push(')');
            }
            Expr::Apply { name, args, .. } => {
                self.ident(out, *name);
                self.args(out, self.nodes.exprs(*args));
            }
            Expr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    UnaryOp::Not => "! ",
                    UnaryOp::Invert => "~ ",
                    UnaryOp::Negate => "- ",
                    UnaryOp::FNegate => "f- ",
                });
                self.expr(out, *operand);
            }
            Expr::Deref { star, operand, .. } => {
                self.star(out, star);
                out.push(' ');
                self.expr(out, *operand);
            }
            Expr::Binary { op, lhs, rhs, .. } => {
                self.expr(out, *lhs);
                let _ = write!(out, " {} ", BinaryOp::as_str(*op));
                self.expr(out, *rhs);
            }
            Expr::Error(_) => out.push_str("?error?"),
        }
    }

    fn args(&self, out: &mut String, args: &[ExprId]) {
        out.push('(');
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            self.expr(out, *arg);
        }
        out.push(')');
    }

    fn jump_dest(&self, out: &mut String, dest: &JumpDest) {
        match dest {
            JumpDest::Symbol(ident) => self.ident(out, *ident),
            JumpDest::Dynamic(target) => {
                out.push('[');
                self.expr(out, *target);
                out.push(']');
            }
            JumpDest::Absolute(address) => int(out, address),
            JumpDest::Relative { offset, space } => {
                int(out, offset);
                let _ = write!(out, "[{}]", self.names.resolve(space.name));
            }
            JumpDest::Label(name) => {
                let _ = write!(out, "<{}>", self.names.resolve(name.name));
            }
        }
    }

    fn statement(&self, out: &mut String, statement: &Statement) {
        match statement {
            Statement::Assign {
                local,
                target,
                value,
                ..
            } => {
                if *local {
                    out.push_str("local ");
                }
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
                        self.star(out, star);
                        out.push(' ');
                        self.expr(out, *address);
                    }
                }
                out.push_str(" = ");
                self.expr(out, *value);
                out.push(';');
            }
            Statement::Declare { name, size, .. } => {
                out.push_str("local ");
                self.ident(out, *name);
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(';');
            }
            Statement::Apply { name, args, .. } => {
                self.ident(out, *name);
                self.args(out, self.nodes.exprs(*args));
                out.push(';');
            }
            Statement::Build { operand, .. } => {
                let _ = write!(out, "build {};", self.names.resolve(operand.name));
            }
            Statement::CrossBuild {
                address, section, ..
            } => {
                out.push_str("crossbuild ");
                self.expr(out, *address);
                let _ = write!(out, ", {};", self.names.resolve(section.name));
            }
            Statement::Goto { dest, .. } => {
                out.push_str("goto ");
                self.jump_dest(out, dest);
                out.push(';');
            }
            Statement::If {
                condition, dest, ..
            } => {
                out.push_str("if ");
                self.expr(out, *condition);
                out.push_str(" goto ");
                self.jump_dest(out, dest);
                out.push(';');
            }
            Statement::Call { dest, .. } => {
                out.push_str("call ");
                self.jump_dest(out, dest);
                out.push(';');
            }
            Statement::Return { target, .. } => {
                out.push_str("return [");
                self.expr(out, *target);
                out.push_str("];");
            }
            Statement::Export { value, .. } => {
                out.push_str("export ");
                match value {
                    ExportValue::Varnode(varnode) => self.expr(out, *varnode),
                    ExportValue::Deref { star, name } => {
                        self.star(out, star);
                        out.push(' ');
                        self.ident(out, *name);
                    }
                }
                out.push(';');
            }
            Statement::Label { name, .. } => {
                let _ = write!(out, "<{}>", self.names.resolve(name.name));
            }
            Statement::Section { name, .. } => {
                let _ = write!(out, "<<{}>>", self.names.resolve(name.name));
            }
            Statement::Error(_) => out.push_str("?error?;"),
        }
    }

    fn equation(&self, out: &mut String, id: EquationId) {
        match &self.nodes[id] {
            Equation::Binary { op, lhs, rhs, .. } => {
                self.equation(out, *lhs);
                out.push_str(match op {
                    EquationOp::Or => " | ",
                    EquationOp::Seq => " ; ",
                    EquationOp::And => " & ",
                });
                self.equation(out, *rhs);
            }
            Equation::EllipsisLeft { inner, .. } => {
                out.push_str("... ");
                self.equation(out, *inner);
            }
            Equation::EllipsisRight { inner, .. } => {
                self.equation(out, *inner);
                out.push_str(" ...");
            }
            Equation::Paren { inner, .. } => {
                out.push('(');
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::Constraint {
                name, op, value, ..
            } => {
                self.ident(out, *name);
                out.push_str(match op {
                    ConstraintOp::Equal => " = ",
                    ConstraintOp::NotEqual => " != ",
                    ConstraintOp::Less => " < ",
                    ConstraintOp::LessEqual => " <= ",
                    ConstraintOp::Great => " > ",
                    ConstraintOp::GreatEqual => " >= ",
                });
                self.pat_expr(out, *value, false);
            }
            Equation::Symbol(ident) => self.ident(out, *ident),
            Equation::Error(_) => out.push_str("?error?"),
        }
    }

    fn pat_expr(&self, out: &mut String, id: PatExprId, symbols: bool) {
        match &self.nodes[id] {
            PatExpr::Int(lit) => int(out, lit),
            PatExpr::Ident(ident) => self.ident(out, *ident),
            PatExpr::Paren { inner, .. } => {
                out.push('(');
                self.pat_expr(out, *inner, symbols);
                out.push(')');
            }
            PatExpr::Apply { name, args, .. } => {
                self.ident(out, *name);
                out.push('(');
                for (i, arg) in self.nodes.pat_exprs(*args).iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    self.pat_expr(out, *arg, symbols);
                }
                out.push(')');
            }
            PatExpr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    PatUnaryOp::Negate => "- ",
                    PatUnaryOp::Invert => "~ ",
                });
                self.pat_expr(out, *operand, symbols);
            }
            PatExpr::Binary { op, lhs, rhs, .. } => {
                self.pat_expr(out, *lhs, symbols);
                out.push(' ');
                out.push_str(match (op, symbols) {
                    (PatBinaryOp::Or, true) => "|",
                    (PatBinaryOp::Or, false) => "$or",
                    (PatBinaryOp::Xor, true) => "^",
                    (PatBinaryOp::Xor, false) => "$xor",
                    (PatBinaryOp::And, true) => "&",
                    (PatBinaryOp::And, false) => "$and",
                    (PatBinaryOp::Left, _) => "<<",
                    (PatBinaryOp::Right, _) => ">>",
                    (PatBinaryOp::Add, _) => "+",
                    (PatBinaryOp::Sub, _) => "-",
                    (PatBinaryOp::Mult, _) => "*",
                    (PatBinaryOp::Div, _) => "/",
                });
                out.push(' ');
                self.pat_expr(out, *rhs, symbols);
            }
            PatExpr::Error(_) => out.push_str("?error?"),
        }
    }
}

/// Writes an integer literal in the radix it was written in.
fn int(out: &mut String, lit: &IntLit) {
    out.push_str(&lit.to_source());
}
