//! Semantic expressions.

use super::{PResult, Parser, Reported};
use crate::ast::{BinaryOp, Expr, ExprId, ExprList, UnaryOp};
use crate::lex::TokenKind;

/// The binary operator a token stands for in a semantic expression.
const fn binary_op(kind: TokenKind) -> Option<BinaryOp> {
    Some(match kind {
        TokenKind::BoolOr => BinaryOp::BoolOr,
        TokenKind::BoolAnd => BinaryOp::BoolAnd,
        TokenKind::BoolXor => BinaryOp::BoolXor,
        TokenKind::Pipe => BinaryOp::Or,
        TokenKind::Caret => BinaryOp::Xor,
        TokenKind::Ampersand => BinaryOp::And,
        TokenKind::Equal => BinaryOp::Equal,
        TokenKind::NotEqual => BinaryOp::NotEqual,
        TokenKind::FEqual => BinaryOp::FEqual,
        TokenKind::FNotEqual => BinaryOp::FNotEqual,
        TokenKind::Less => BinaryOp::Less,
        TokenKind::GreatEqual => BinaryOp::GreatEqual,
        TokenKind::LessEqual => BinaryOp::LessEqual,
        TokenKind::Great => BinaryOp::Great,
        TokenKind::SLess => BinaryOp::SLess,
        TokenKind::SGreatEqual => BinaryOp::SGreatEqual,
        TokenKind::SLessEqual => BinaryOp::SLessEqual,
        TokenKind::SGreat => BinaryOp::SGreat,
        TokenKind::FLess => BinaryOp::FLess,
        TokenKind::FGreatEqual => BinaryOp::FGreatEqual,
        TokenKind::FLessEqual => BinaryOp::FLessEqual,
        TokenKind::FGreat => BinaryOp::FGreat,
        TokenKind::Left => BinaryOp::Left,
        TokenKind::Right => BinaryOp::Right,
        TokenKind::SRight => BinaryOp::SRight,
        TokenKind::Plus => BinaryOp::Add,
        TokenKind::Minus => BinaryOp::Sub,
        TokenKind::FPlus => BinaryOp::FAdd,
        TokenKind::FMinus => BinaryOp::FSub,
        TokenKind::Asterisk => BinaryOp::Mult,
        TokenKind::Slash => BinaryOp::Div,
        TokenKind::Percent => BinaryOp::Rem,
        TokenKind::SDiv => BinaryOp::SDiv,
        TokenKind::SRem => BinaryOp::SRem,
        TokenKind::FMult => BinaryOp::FMult,
        TokenKind::FDiv => BinaryOp::FDiv,
        _ => return None,
    })
}

impl Parser<'_> {
    /// A semantic expression (`expr`).
    pub(super) fn expr(&mut self) -> PResult<ExprId> {
        self.expr_bp(0)
    }

    /// Precedence climbing: parses operators binding at least as tightly as
    /// `min`; equal precedence associates to the left.
    fn expr_bp(&mut self, min: u8) -> PResult<ExprId> {
        let mut lhs = self.unary()?;
        while let Some(op) = binary_op(self.tok.kind) {
            let level = op.precedence();
            if level < min {
                break;
            }
            let op_span = self.bump().span;
            let rhs = self.expr_bp(level + 1)?;
            let span = self.nodes[lhs].span().to(self.nodes[rhs].span());
            lhs = self.nodes.add_expr(Expr::Binary {
                op,
                lhs,
                rhs,
                op_span,
                span,
            });
        }
        Ok(lhs)
    }

    /// A unary operator or dereference applied to a unary expression, or a
    /// primary expression.
    fn unary(&mut self) -> PResult<ExprId> {
        let start = self.tok.span;
        let op = match self.tok.kind {
            TokenKind::Exclaim => UnaryOp::Not,
            TokenKind::Tilde => UnaryOp::Invert,
            TokenKind::Minus => UnaryOp::Negate,
            TokenKind::FMinus => UnaryOp::FNegate,
            TokenKind::Asterisk => {
                let star = self.sized_star()?;
                let operand = self.nested(Self::unary)?;
                let span = self.span_from(start);
                return Ok(self.nodes.add_expr(Expr::Deref {
                    star,
                    operand,
                    span,
                }));
            }
            _ => return self.primary(),
        };
        self.bump();
        let operand = self.nested(Self::unary)?;
        let span = self.span_from(start);
        Ok(self.nodes.add_expr(Expr::Unary { op, operand, span }))
    }

    /// Runs `parse` one nesting level deeper.
    fn nested<T>(&mut self, parse: impl FnOnce(&mut Self) -> PResult<T>) -> PResult<T> {
        self.enter()?;
        let result = parse(self);
        self.leave();
        result
    }

    /// A parenthesised expression, a call, a bit range or a varnode.
    fn primary(&mut self) -> PResult<ExprId> {
        let start = self.tok.span;
        if self.eat(TokenKind::LParen).is_some() {
            let inner = self.nested(Self::expr)?;
            self.expect(TokenKind::RParen)?;
            let span = self.span_from(start);
            return Ok(self.nodes.add_expr(Expr::Paren { inner, span }));
        }
        if self.at_identifier() {
            match self.peek(1).kind {
                TokenKind::LParen => {
                    let name = self.identifier()?;
                    let args = self.call_args()?;
                    let span = self.span_from(start);
                    return Ok(self.nodes.add_expr(Expr::Apply { name, args, span }));
                }
                TokenKind::LBracket => {
                    let name = self.identifier()?;
                    let (low, width) = self.bit_range_bounds()?;
                    let span = self.span_from(start);
                    return Ok(self.nodes.add_expr(Expr::BitRange {
                        name,
                        low,
                        width,
                        span,
                    }));
                }
                _ => {}
            }
        }
        self.varnode()
    }

    /// `varnode`: an integer, a name, either with `:size`, or `&` applied
    /// to a varnode.
    pub(super) fn varnode(&mut self) -> PResult<ExprId> {
        let start = self.tok.span;
        if self.tok.kind.is_int() {
            let value = self.int_literal();
            if self.eat(TokenKind::Colon).is_some() {
                let size = self.integer()?;
                return Ok(self.nodes.add_expr(Expr::SizedInt { value, size }));
            }
            return Ok(self.nodes.add_expr(Expr::Int(value)));
        }
        if self.eat(TokenKind::Ampersand).is_some() {
            let size = if self.eat(TokenKind::Colon).is_some() {
                Some(self.integer()?)
            } else {
                None
            };
            let operand = self.nested(Self::varnode)?;
            let span = self.span_from(start);
            return Ok(self.nodes.add_expr(Expr::AddressOf {
                size,
                operand,
                span,
            }));
        }
        if self.tok.kind == TokenKind::Ident {
            let name = self.identifier()?;
            if self.eat(TokenKind::Colon).is_some() {
                let size = self.integer()?;
                return Ok(self.nodes.add_expr(Expr::Truncate { name, size }));
            }
            return Ok(self.nodes.add_expr(Expr::Ident(name)));
        }
        let found = self.found();
        Err(self.error(format!("expected an expression, found {found}")))
    }

    /// `( [expr (, expr)*] )`, starting at the `(`.
    pub(super) fn call_args(&mut self) -> PResult<ExprList> {
        self.expect(TokenKind::LParen)?;
        // Arguments collect on a shared scratch stack so that nested calls
        // do not allocate.
        let base = self.expr_scratch.len();
        let result = self.call_args_into_scratch();
        let list = match result {
            Ok(()) => Ok(self
                .nodes
                .add_expr_list(self.expr_scratch.get(base..).unwrap_or(&[]))),
            Err(Reported) => Err(Reported),
        };
        self.expr_scratch.truncate(base);
        list
    }

    fn call_args_into_scratch(&mut self) -> PResult<()> {
        if !self.at(TokenKind::RParen) {
            self.enter()?;
            loop {
                if let Ok(arg) = self.expr() {
                    self.expr_scratch.push(arg);
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
}
