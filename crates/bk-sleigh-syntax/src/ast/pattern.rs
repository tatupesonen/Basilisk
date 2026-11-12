//! Bit-pattern equations, pattern expressions and context blocks.

use super::{EquationId, Ident, IntLit, PatExprId, PatExprList};
use crate::span::Span;

/// A binary operator between pattern equations.
///
/// Precedence, loosest first: `|`, `;`, `&` (as in `slghparse.y` and
/// `SleighParser.g`); all are left-associative.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EquationOp {
    /// `|`: either pattern matches.
    Or,
    /// `;`: the patterns match consecutive tokens.
    Seq,
    /// `&`: both patterns match.
    And,
}

/// The comparison of a constraint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConstraintOp {
    /// `=`
    Equal,
    /// `!=`
    NotEqual,
    /// `<`
    Less,
    /// `<=`
    LessEqual,
    /// `>`
    Great,
    /// `>=`
    GreatEqual,
}

/// A bit-pattern equation: what follows `is` in a constructor.
#[derive(Clone, Debug)]
pub enum Equation {
    /// `lhs op rhs`.
    Binary {
        /// The operator.
        op: EquationOp,
        /// Left operand.
        lhs: EquationId,
        /// Right operand.
        rhs: EquationId,
        /// Where the operator is written.
        op_span: Span,
        /// The whole equation.
        span: Span,
    },
    /// `... inner`: `inner` matches the end of the instruction's tokens.
    EllipsisLeft {
        /// The equation after the ellipsis.
        inner: EquationId,
        /// The whole equation.
        span: Span,
    },
    /// `inner ...`: more tokens may follow `inner`.
    EllipsisRight {
        /// The equation before the ellipsis.
        inner: EquationId,
        /// The whole equation.
        span: Span,
    },
    /// `( inner )`.
    Paren {
        /// The parenthesised equation.
        inner: EquationId,
        /// The whole equation, parentheses included.
        span: Span,
    },
    /// `name op value`: a field compared with a pattern expression.
    Constraint {
        /// The field, context variable or operand constrained.
        name: Ident,
        /// The comparison.
        op: ConstraintOp,
        /// Where the comparison operator is written.
        op_span: Span,
        /// The value compared with.
        value: PatExprId,
        /// The whole constraint.
        span: Span,
    },
    /// A bare name: an operand, a sub-table, a field with attached meaning,
    /// or `epsilon`.
    Symbol(Ident),
    /// A placeholder where a syntax error was reported.
    Error(Span),
}

impl Equation {
    /// The extent of the equation.
    pub fn span(&self) -> Span {
        match self {
            Equation::Binary { span, .. }
            | Equation::EllipsisLeft { span, .. }
            | Equation::EllipsisRight { span, .. }
            | Equation::Paren { span, .. }
            | Equation::Constraint { span, .. }
            | Equation::Error(span) => *span,
            Equation::Symbol(ident) => ident.span,
        }
    }
}

/// A binary operator of pattern expressions.
///
/// Precedence, loosest first: or, xor, and, shifts, `+ -`, `* /`; all are
/// left-associative. In a constraint only the spellings `$or`, `$xor` and
/// `$and` are available, because `|` and `&` combine equations there; in a
/// context block `|`, `^` and `&` work too.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PatBinaryOp {
    /// `$or`, or `|` in a context block.
    Or,
    /// `$xor`, or `^` in a context block.
    Xor,
    /// `$and`, or `&` in a context block.
    And,
    /// `<<`
    Left,
    /// `>>`
    Right,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mult,
    /// `/`
    Div,
}

/// A unary operator of pattern expressions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PatUnaryOp {
    /// `-`
    Negate,
    /// `~`
    Invert,
}

/// A pattern expression: the value side of a constraint or of a context
/// assignment.
#[derive(Clone, Debug)]
pub enum PatExpr {
    /// An integer.
    Int(IntLit),
    /// A name.
    Ident(Ident),
    /// `( inner )`.
    Paren {
        /// The parenthesised expression.
        inner: PatExprId,
        /// The whole expression, parentheses included.
        span: Span,
    },
    /// `name(args)`.
    Apply {
        /// The function name.
        name: Ident,
        /// The arguments.
        args: PatExprList,
        /// The whole call.
        span: Span,
    },
    /// `op operand`.
    Unary {
        /// The operator.
        op: PatUnaryOp,
        /// The operand.
        operand: PatExprId,
        /// The whole expression.
        span: Span,
    },
    /// `lhs op rhs`.
    Binary {
        /// The operator.
        op: PatBinaryOp,
        /// Left operand.
        lhs: PatExprId,
        /// Right operand.
        rhs: PatExprId,
        /// Where the operator is written.
        op_span: Span,
        /// The whole expression.
        span: Span,
    },
    /// A placeholder where a syntax error was reported.
    Error(Span),
}

impl PatExpr {
    /// The extent of the expression.
    pub fn span(&self) -> Span {
        match self {
            PatExpr::Int(lit) => lit.span,
            PatExpr::Ident(ident) => ident.span,
            PatExpr::Paren { span, .. }
            | PatExpr::Apply { span, .. }
            | PatExpr::Unary { span, .. }
            | PatExpr::Binary { span, .. }
            | PatExpr::Error(span) => *span,
        }
    }
}

/// The `[ ... ]` block of a constructor or `with` header.
#[derive(Clone, Debug)]
pub struct ContextBlock {
    /// The statements, in order.
    pub stmts: Vec<ContextStmt>,
    /// The whole block, brackets included.
    pub span: Span,
}

/// One statement of a context block.
#[derive(Clone, Debug)]
pub enum ContextStmt {
    /// `name = expression;`: sets a context variable, or defines an operand
    /// computed from other fields.
    Assign {
        /// The context variable or operand.
        target: Ident,
        /// Where the `=` is written.
        op_span: Span,
        /// The value.
        value: PatExprId,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `name(args);`, in practice `globalset(address, variable);`.
    Apply {
        /// The function name.
        name: Ident,
        /// The arguments.
        args: PatExprList,
        /// The whole statement without its `;`.
        span: Span,
    },
}

impl ContextStmt {
    /// The extent of the statement.
    pub fn span(&self) -> Span {
        match self {
            ContextStmt::Assign { span, .. } | ContextStmt::Apply { span, .. } => *span,
        }
    }
}
