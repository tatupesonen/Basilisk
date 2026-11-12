//! Pattern equations, pattern expressions and context blocks.

use super::{PResult, Parser, Reported};
use crate::ast::{
    ConstraintOp, ContextBlock, ContextStmt, Equation, EquationId, EquationOp, PatBinaryOp,
    PatExpr, PatExprId, PatExprList, PatUnaryOp,
};
use crate::lex::TokenKind;

/// Binding strength of an equation operator: `|` < `;` < `&`.
const fn equation_op(kind: TokenKind) -> Option<(EquationOp, u8)> {
    match kind {
        TokenKind::Pipe => Some((EquationOp::Or, 1)),
        TokenKind::Semi => Some((EquationOp::Seq, 2)),
        TokenKind::Ampersand => Some((EquationOp::And, 3)),
        _ => None,
    }
}

/// A binary pattern-expression operator and its binding strength. `|`, `^`
/// and `&` are operators only where `symbols` is set (context blocks).
const fn pat_binary_op(kind: TokenKind, symbols: bool) -> Option<(PatBinaryOp, u8)> {
    match kind {
        TokenKind::SpecOr => Some((PatBinaryOp::Or, 1)),
        TokenKind::Pipe if symbols => Some((PatBinaryOp::Or, 1)),
        TokenKind::SpecXor => Some((PatBinaryOp::Xor, 2)),
        TokenKind::Caret if symbols => Some((PatBinaryOp::Xor, 2)),
        TokenKind::SpecAnd => Some((PatBinaryOp::And, 3)),
        TokenKind::Ampersand if symbols => Some((PatBinaryOp::And, 3)),
        TokenKind::Left => Some((PatBinaryOp::Left, 4)),
        TokenKind::Right => Some((PatBinaryOp::Right, 4)),
        TokenKind::Plus => Some((PatBinaryOp::Add, 5)),
        TokenKind::Minus => Some((PatBinaryOp::Sub, 5)),
        TokenKind::Asterisk => Some((PatBinaryOp::Mult, 6)),
        TokenKind::Slash => Some((PatBinaryOp::Div, 6)),
        _ => None,
    }
}

impl Parser<'_> {
    /// A pattern equation (`pequation`).
    pub(super) fn equation(&mut self) -> PResult<EquationId> {
        self.equation_bp(0)
    }

    fn equation_bp(&mut self, min: u8) -> PResult<EquationId> {
        let mut lhs = self.equation_ellipsis()?;
        while let Some((op, level)) = equation_op(self.tok.kind) {
            if level < min {
                break;
            }
            let op_span = self.bump().span;
            let rhs = self.equation_bp(level + 1)?;
            let span = self.nodes[lhs].span().to(self.nodes[rhs].span());
            lhs = self.nodes.add_equation(Equation::Binary {
                op,
                lhs,
                rhs,
                op_span,
                span,
            });
        }
        Ok(lhs)
    }

    /// `... atomic`, `atomic ...`, `... atomic ...` or `atomic`.
    fn equation_ellipsis(&mut self) -> PResult<EquationId> {
        let left = self.eat(TokenKind::Ellipsis);
        let mut equation = self.equation_atomic()?;
        if let Some(dots) = self.eat(TokenKind::Ellipsis) {
            let span = self.nodes[equation].span().to(dots.span);
            equation = self.nodes.add_equation(Equation::EllipsisRight {
                inner: equation,
                span,
            });
        }
        if let Some(dots) = left {
            let span = dots.span.to(self.nodes[equation].span());
            equation = self.nodes.add_equation(Equation::EllipsisLeft {
                inner: equation,
                span,
            });
        }
        Ok(equation)
    }

    /// A constraint or a parenthesised equation.
    fn equation_atomic(&mut self) -> PResult<EquationId> {
        if let Some(open) = self.eat(TokenKind::LParen) {
            self.enter()?;
            let inner = self.equation();
            self.leave();
            let inner = inner?;
            self.expect(TokenKind::RParen)?;
            let span = self.span_from(open.span);
            return Ok(self.nodes.add_equation(Equation::Paren { inner, span }));
        }
        if !self.at_identifier() {
            let found = self.found();
            return Err(self.error(format!("expected a pattern, found {found}")));
        }
        let name = self.identifier()?;
        let op = match self.tok.kind {
            TokenKind::Assign => ConstraintOp::Equal,
            TokenKind::NotEqual => ConstraintOp::NotEqual,
            TokenKind::Less => ConstraintOp::Less,
            TokenKind::LessEqual => ConstraintOp::LessEqual,
            TokenKind::Great => ConstraintOp::Great,
            TokenKind::GreatEqual => ConstraintOp::GreatEqual,
            _ => return Ok(self.nodes.add_equation(Equation::Symbol(name))),
        };
        let op_span = self.bump().span;
        let value = self.pat_expr(false)?;
        let span = self.span_from(name.span);
        Ok(self.nodes.add_equation(Equation::Constraint {
            name,
            op,
            op_span,
            value,
            span,
        }))
    }

    /// A pattern expression. With `symbols`, `|`, `^` and `&` are operators
    /// (`pexpression`, used in context blocks); without, only `$or`, `$xor`
    /// and `$and` are (`pexpression2`, used in constraints).
    pub(super) fn pat_expr(&mut self, symbols: bool) -> PResult<PatExprId> {
        self.pat_expr_bp(0, symbols)
    }

    fn pat_expr_bp(&mut self, min: u8, symbols: bool) -> PResult<PatExprId> {
        let mut lhs = self.pat_unary(symbols)?;
        while let Some((op, level)) = pat_binary_op(self.tok.kind, symbols) {
            if level < min {
                break;
            }
            let op_span = self.bump().span;
            let rhs = self.pat_expr_bp(level + 1, symbols)?;
            let span = self.nodes[lhs].span().to(self.nodes[rhs].span());
            lhs = self.nodes.add_pat_expr(PatExpr::Binary {
                op,
                lhs,
                rhs,
                op_span,
                span,
            });
        }
        Ok(lhs)
    }

    fn pat_unary(&mut self, symbols: bool) -> PResult<PatExprId> {
        let op = match self.tok.kind {
            TokenKind::Minus => PatUnaryOp::Negate,
            TokenKind::Tilde => PatUnaryOp::Invert,
            _ => return self.pat_primary(symbols),
        };
        let start = self.bump().span;
        self.enter()?;
        let operand = self.pat_unary(symbols);
        self.leave();
        let operand = operand?;
        let span = self.span_from(start);
        Ok(self
            .nodes
            .add_pat_expr(PatExpr::Unary { op, operand, span }))
    }

    fn pat_primary(&mut self, symbols: bool) -> PResult<PatExprId> {
        if let Some(open) = self.eat(TokenKind::LParen) {
            self.enter()?;
            let inner = self.pat_expr(symbols);
            self.leave();
            let inner = inner?;
            self.expect(TokenKind::RParen)?;
            let span = self.span_from(open.span);
            return Ok(self.nodes.add_pat_expr(PatExpr::Paren { inner, span }));
        }
        if self.tok.kind.is_int() {
            let literal = self.integer()?;
            return Ok(self.nodes.add_pat_expr(PatExpr::Int(literal)));
        }
        if self.at_identifier() {
            let name = self.identifier()?;
            if self.at(TokenKind::LParen) {
                let args = self.pat_args(symbols)?;
                let span = self.span_from(name.span);
                return Ok(self.nodes.add_pat_expr(PatExpr::Apply { name, args, span }));
            }
            return Ok(self.nodes.add_pat_expr(PatExpr::Ident(name)));
        }
        let found = self.found();
        Err(self.error(format!("expected a pattern expression, found {found}")))
    }

    /// `( [expr (, expr)*] )`, starting at the `(`.
    fn pat_args(&mut self, symbols: bool) -> PResult<PatExprList> {
        self.expect(TokenKind::LParen)?;
        let base = self.pat_scratch.len();
        let result = self.pat_args_into_scratch(symbols);
        let list = match result {
            Ok(()) => Ok(self
                .nodes
                .add_pat_expr_list(self.pat_scratch.get(base..).unwrap_or(&[]))),
            Err(Reported) => Err(Reported),
        };
        self.pat_scratch.truncate(base);
        list
    }

    fn pat_args_into_scratch(&mut self, symbols: bool) -> PResult<()> {
        if !self.at(TokenKind::RParen) {
            self.enter()?;
            loop {
                if let Ok(arg) = self.pat_expr(symbols) {
                    self.pat_scratch.push(arg);
                } else {
                    self.leave();
                    return Err(Reported);
                }
                if self.eat(TokenKind::Comma).is_none() {
                    break;
                }
            }
            self.leave();
        }
        self.expect(TokenKind::RParen)?;
        Ok(())
    }

    /// `[ statements ]`, starting at the `[`.
    pub(super) fn context_block(&mut self) -> PResult<ContextBlock> {
        let open = self.expect(TokenKind::LBracket)?;
        let mut stmts = Vec::new();
        loop {
            if self.eat(TokenKind::RBracket).is_some() {
                break;
            }
            if self.at_eof() || self.at(TokenKind::LBrace) || self.at(TokenKind::RBrace) {
                return Err(self.error_expected("`]` to close the context block"));
            }
            if let Ok(stmt) = self.context_stmt() {
                stmts.push(stmt);
            } else {
                // Skip to the end of this statement or of the block.
                while !matches!(
                    self.tok.kind,
                    TokenKind::Semi
                        | TokenKind::RBracket
                        | TokenKind::LBrace
                        | TokenKind::RBrace
                        | TokenKind::Eof
                ) {
                    self.bump();
                }
                self.eat(TokenKind::Semi);
            }
        }
        Ok(ContextBlock {
            stmts,
            span: self.span_from(open.span),
        })
    }

    /// `name = expression ;` or `name ( args ) ;`.
    fn context_stmt(&mut self) -> PResult<ContextStmt> {
        let name = self.identifier()?;
        let stmt = if self.at(TokenKind::LParen) {
            let args = self.pat_args(true)?;
            ContextStmt::Apply {
                name,
                args,
                span: self.span_from(name.span),
            }
        } else {
            let op_span = self.expect(TokenKind::Assign)?.span;
            let value = self.pat_expr(true)?;
            ContextStmt::Assign {
                target: name,
                op_span,
                value,
                span: self.span_from(name.span),
            }
        };
        self.expect(TokenKind::Semi)?;
        Ok(stmt)
    }
}
