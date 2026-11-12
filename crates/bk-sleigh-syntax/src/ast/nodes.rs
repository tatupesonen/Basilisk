//! Arena storage for the recursive parts of the tree.

use std::ops::Index;

use super::{Equation, Expr, PatExpr};
use crate::span::Span;

/// Id of a semantic [`Expr`] in [`Nodes`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ExprId(u32);

/// Id of a [`PatExpr`] in [`Nodes`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PatExprId(u32);

/// Id of a pattern [`Equation`] in [`Nodes`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EquationId(u32);

/// A list of semantic expressions (call arguments) in [`Nodes`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct ExprList {
    start: u32,
    len: u32,
}

/// A list of pattern expressions (call arguments) in [`Nodes`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct PatExprList {
    start: u32,
    len: u32,
}

impl ExprList {
    /// Number of expressions in the list.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Whether the list is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl PatExprList {
    /// Number of expressions in the list.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Whether the list is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

static MISSING_EXPR: Expr = Expr::Error(Span::new(0, 0));
static MISSING_PAT_EXPR: PatExpr = PatExpr::Error(Span::new(0, 0));
static MISSING_EQUATION: Equation = Equation::Error(Span::new(0, 0));

/// The arenas holding semantic expressions, pattern expressions and pattern
/// equations of one parse.
///
/// Index it with an id (`nodes[id]`) to get the node. An id from another
/// parse yields an `Error` node rather than a panic.
#[derive(Clone, Debug, Default)]
pub struct Nodes {
    exprs: Vec<Expr>,
    expr_lists: Vec<ExprId>,
    pat_exprs: Vec<PatExpr>,
    pat_lists: Vec<PatExprId>,
    equations: Vec<Equation>,
}

fn next_id(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

impl Nodes {
    /// Adds a semantic expression.
    pub fn add_expr(&mut self, expr: Expr) -> ExprId {
        let id = ExprId(next_id(self.exprs.len()));
        self.exprs.push(expr);
        id
    }

    /// Adds a list of semantic expressions.
    pub fn add_expr_list(&mut self, items: &[ExprId]) -> ExprList {
        let start = next_id(self.expr_lists.len());
        self.expr_lists.extend_from_slice(items);
        ExprList {
            start,
            len: next_id(items.len()),
        }
    }

    /// Adds a pattern expression.
    pub fn add_pat_expr(&mut self, expr: PatExpr) -> PatExprId {
        let id = PatExprId(next_id(self.pat_exprs.len()));
        self.pat_exprs.push(expr);
        id
    }

    /// Adds a list of pattern expressions.
    pub fn add_pat_expr_list(&mut self, items: &[PatExprId]) -> PatExprList {
        let start = next_id(self.pat_lists.len());
        self.pat_lists.extend_from_slice(items);
        PatExprList {
            start,
            len: next_id(items.len()),
        }
    }

    /// Adds a pattern equation.
    pub fn add_equation(&mut self, equation: Equation) -> EquationId {
        let id = EquationId(next_id(self.equations.len()));
        self.equations.push(equation);
        id
    }

    /// The expressions of a list.
    pub fn exprs(&self, list: ExprList) -> &[ExprId] {
        let start = list.start as usize;
        self.expr_lists
            .get(start..start + list.len as usize)
            .unwrap_or(&[])
    }

    /// The pattern expressions of a list.
    pub fn pat_exprs(&self, list: PatExprList) -> &[PatExprId] {
        let start = list.start as usize;
        self.pat_lists
            .get(start..start + list.len as usize)
            .unwrap_or(&[])
    }

    /// Number of semantic expression nodes.
    pub fn expr_count(&self) -> usize {
        self.exprs.len()
    }

    /// Number of pattern expression nodes.
    pub fn pat_expr_count(&self) -> usize {
        self.pat_exprs.len()
    }

    /// Number of pattern equation nodes.
    pub fn equation_count(&self) -> usize {
        self.equations.len()
    }
}

impl Index<ExprId> for Nodes {
    type Output = Expr;

    fn index(&self, id: ExprId) -> &Expr {
        self.exprs.get(id.0 as usize).unwrap_or(&MISSING_EXPR)
    }
}

impl Index<PatExprId> for Nodes {
    type Output = PatExpr;

    fn index(&self, id: PatExprId) -> &PatExpr {
        self.pat_exprs
            .get(id.0 as usize)
            .unwrap_or(&MISSING_PAT_EXPR)
    }
}

impl Index<EquationId> for Nodes {
    type Output = Equation;

    fn index(&self, id: EquationId) -> &Equation {
        self.equations
            .get(id.0 as usize)
            .unwrap_or(&MISSING_EQUATION)
    }
}
