//! Pattern expressions and pattern equations as resolved trees
//! (`slghpatexpress.hh`): the values of fields and operands, and the bit
//! patterns of constructors, which the back half turns into patterns; and
//! the bit patterns themselves (`slghpattern.hh`, `TokenPattern`).

mod algebra;
mod block;
mod disjoint;
mod token_pattern;

pub use algebra::Pattern;
pub use block::Block;
pub use disjoint::Disjoint;
pub use token_pattern::{CombineError, Tok, TokenPattern};

use bk_sla::{BinaryOp, Field, UnaryOp};

use crate::ids::{EquationId, OperandId, PExprId};

/// A token or context field (`TokenField`, `ContextField`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PatValue {
    /// Bits of the instruction bytes.
    Token(Field),
    /// Bits of the context words.
    Context(Field),
}

impl PatValue {
    /// The field.
    pub const fn field(&self) -> &Field {
        match self {
            Self::Token(field) | Self::Context(field) => field,
        }
    }

    /// `PatternValue::maxValue`: all ones over the field's width.
    pub fn max_value(&self) -> i64 {
        let field = self.field();
        let bit = i64::from(field.end_bit) - i64::from(field.start_bit);
        // zero_extend(~0, bit): keep bits 0..=bit.
        match bit {
            b if b < 0 => 0,
            b if b >= 63 => -1,
            b => (1_i64 << (b + 1)) - 1,
        }
    }
}

/// A pattern-expression node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PExpr {
    /// A field.
    Field(PatValue),
    /// An integer.
    Constant(i64),
    /// The value of an operand (`OperandValue`).
    Operand(OperandId),
    /// `inst_start`.
    Start,
    /// `inst_next`.
    End,
    /// `inst_next2`.
    Next2,
    /// A binary operator.
    Binary {
        /// The operator.
        op: BinaryOp,
        /// Left operand.
        left: PExprId,
        /// Right operand.
        right: PExprId,
    },
    /// A unary operator.
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: PExprId,
    },
}

/// The comparison of a constraint equation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    Greater,
    /// `>=`
    GreaterEqual,
}

/// A pattern-equation node (`PatternEquation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Equation {
    /// `a & b` (`EquationAnd`).
    And(EquationId, EquationId),
    /// `a | b` (`EquationOr`).
    Or(EquationId, EquationId),
    /// `a ; b` (`EquationCat`).
    Cat(EquationId, EquationId),
    /// `... a` (`EquationLeftEllipsis`).
    LeftEllipsis(EquationId),
    /// `a ...` (`EquationRightEllipsis`).
    RightEllipsis(EquationId),
    /// `field op expression` (`EqualEquation` and its siblings).
    Constraint {
        /// The comparison.
        op: ConstraintOp,
        /// The field constrained (always a [`PExpr::Field`]).
        value: PExprId,
        /// The value compared with.
        expr: PExprId,
    },
    /// An operand's own pattern (`OperandEquation`).
    Operand(OperandId),
    /// An expression that matches anything (`UnconstrainedEquation`).
    Unconstrained(PExprId),
}

/// The arenas of expressions and equations.
#[derive(Clone, Debug, Default)]
pub struct PatternArena {
    pub(crate) exprs: Vec<PExpr>,
    pub(crate) equations: Vec<Equation>,
}

impl PatternArena {
    /// Adds an expression.
    pub(crate) fn expr(&mut self, expr: PExpr) -> PExprId {
        let id = PExprId::next(self.exprs.len());
        self.exprs.push(expr);
        id
    }

    /// Adds an equation.
    pub(crate) fn equation(&mut self, equation: Equation) -> EquationId {
        let id = EquationId::next(self.equations.len());
        self.equations.push(equation);
        id
    }

    /// One expression node.
    pub fn get_expr(&self, id: PExprId) -> Option<&PExpr> {
        self.exprs.get(id.slot())
    }

    /// One equation node.
    pub fn get_equation(&self, id: EquationId) -> Option<&Equation> {
        self.equations.get(id.slot())
    }

    /// Calls `f` on every leaf value of an expression, left to right
    /// (`PatternExpression::listValues`). Iterative, so a deep tree cannot
    /// overflow the stack.
    pub fn for_each_value(&self, root: PExprId, mut f: impl FnMut(&PExpr)) {
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            match self.get_expr(id) {
                Some(PExpr::Binary { left, right, .. }) => {
                    stack.push(*right);
                    stack.push(*left);
                }
                Some(PExpr::Unary { operand, .. }) => stack.push(*operand),
                Some(leaf) => f(leaf),
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_value_is_all_ones_over_the_width() {
        let field = |s, e| {
            PatValue::Token(Field {
                start_bit: s,
                end_bit: e,
                ..Field::default()
            })
        };
        assert_eq!(field(0, 0).max_value(), 1);
        assert_eq!(field(4, 7).max_value(), 15);
        assert_eq!(field(0, 63).max_value(), -1);
    }
}
