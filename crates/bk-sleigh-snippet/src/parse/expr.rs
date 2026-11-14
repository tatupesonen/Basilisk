//! Expressions (`expr`, `varnode`, `integervarnode`, `specificsymbol`).
//!
//! Binary operators by precedence climbing over the levels of the grammar's
//! `%left`/`%nonassoc` declarations; every prefix operator binds tighter
//! than any binary one. The comparison level is non-associative: a second
//! comparison is a syntax error before the first is reduced.

use bk_sleigh_syntax::ast::{BinaryOp, Expr, ExprId, UnaryOp};

use super::{Fail, PResult, Parser};
use crate::lex::Tok;
use crate::scope::Class;

/// The comparison level (`%nonassoc`).
const COMPARE: u8 = 7;

/// The binary operator a token stands for.
fn binary(tok: Tok) -> Option<BinaryOp> {
    Some(match tok {
        Tok::Op(op) => op,
        Tok::Punct(b'+') => BinaryOp::Add,
        Tok::Punct(b'-') => BinaryOp::Sub,
        Tok::Punct(b'*') => BinaryOp::Mult,
        Tok::Punct(b'/') => BinaryOp::Div,
        Tok::Punct(b'%') => BinaryOp::Rem,
        Tok::Punct(b'&') => BinaryOp::And,
        Tok::Punct(b'|') => BinaryOp::Or,
        Tok::Punct(b'^') => BinaryOp::Xor,
        Tok::Punct(b'<') => BinaryOp::Less,
        Tok::Punct(b'>') => BinaryOp::Great,
        _ => return None,
    })
}

impl Parser<'_> {
    /// An expression; leaves exactly one completed node (its own) on the
    /// pending stack.
    pub(super) fn expr(&mut self) -> PResult<ExprId> {
        self.binary_expr(1)
    }

    fn binary_expr(&mut self, min: u8) -> PResult<ExprId> {
        self.enter()?;
        let result = self.binary_expr_inner(min);
        self.leave();
        result
    }

    fn binary_expr_inner(&mut self, min: u8) -> PResult<ExprId> {
        let mut lhs = self.unary()?;
        loop {
            let t = self.peek();
            let Some(op) = binary(t.tok) else {
                return Ok(lhs);
            };
            let level = op.precedence();
            if level < min {
                return Ok(lhs);
            }
            self.bump();
            let rhs = self.binary_expr(level + 1)?;
            if level == COMPARE
                && binary(self.peek().tok).is_some_and(|next| next.precedence() == COMPARE)
            {
                return Err(Fail::syntax());
            }
            let span = self.nodes[lhs].span().to(self.nodes[rhs].span());
            lhs = self.combine(
                2,
                Expr::Binary {
                    op,
                    lhs,
                    rhs,
                    op_span: t.span,
                    span,
                },
            );
        }
    }

    /// A prefix operator applied to a unary expression, or a primary.
    fn unary(&mut self) -> PResult<ExprId> {
        self.enter()?;
        let result = self.unary_inner();
        self.leave();
        result
    }

    fn unary_inner(&mut self) -> PResult<ExprId> {
        let t = self.peek();
        let op = match t.tok {
            Tok::Punct(b'-') => Some(UnaryOp::Negate),
            Tok::Op(BinaryOp::FSub) => Some(UnaryOp::FNegate),
            Tok::Punct(b'!') => Some(UnaryOp::Not),
            Tok::Punct(b'~') => Some(UnaryOp::Invert),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let operand = self.unary()?;
            let span = t.span.to(self.nodes[operand].span());
            return Ok(self.combine(1, Expr::Unary { op, operand, span }));
        }
        if t.tok == Tok::Punct(b'*') {
            let star = self.sized_star()?;
            let operand = self.unary()?;
            let span = star.span.to(self.nodes[operand].span());
            return Ok(self.combine(
                1,
                Expr::Deref {
                    star,
                    operand,
                    span,
                },
            ));
        }
        self.primary()
    }

    fn primary(&mut self) -> PResult<ExprId> {
        let t = self.peek();
        match t.tok {
            Tok::Int(_) | Tok::BadInt | Tok::Punct(b'&') => self.integer_varnode(),
            Tok::Punct(b'(') => {
                self.bump();
                let inner = self.expr()?;
                let close = self.expect(b')')?;
                Ok(self.combine(
                    1,
                    Expr::Paren {
                        inner,
                        span: t.span.to(close),
                    },
                ))
            }
            Tok::Builtin(builtin) => {
                let Some(arity) = builtin.arity() else {
                    return Err(Fail::syntax());
                };
                self.bump();
                let name = bk_sleigh_syntax::ast::Ident {
                    name: self.names.intern(builtin.name()),
                    span: t.span,
                };
                self.expect(b'(')?;
                let mut args = Vec::with_capacity(arity);
                for i in 0..arity {
                    if i > 0 {
                        self.expect(b',')?;
                    }
                    args.push(self.expr()?);
                }
                let close = self.expect(b')')?;
                let list = self.nodes.add_expr_list(&args);
                Ok(self.combine(
                    arity,
                    Expr::Apply {
                        name,
                        args: list,
                        span: t.span.to(close),
                    },
                ))
            }
            Tok::Name => match self.class(t.span) {
                Class::Unknown => {
                    let text = self.text(t.span).to_owned();
                    self.bump();
                    Err(Fail(format!("Unknown varnode parameter: {text}")))
                }
                Class::UserOp => {
                    let name = self.ident(t.span);
                    self.bump();
                    self.expect(b'(')?;
                    let args = self.param_list()?;
                    let id = self.nodes.add_expr(Expr::Apply {
                        name,
                        args,
                        span: t.span,
                    });
                    Ok(self.complete(id))
                }
                Class::Varnode | Class::Operand | Class::Jump => self.specific(t.span),
                Class::Space | Class::Label => Err(Fail::syntax()),
            },
            _ => Err(Fail::syntax()),
        }
    }

    /// A `specificsymbol` in an expression and its suffix (state 70).
    fn specific(&mut self, at: bk_sleigh_syntax::Span) -> PResult<ExprId> {
        let name = self.ident(at);
        self.bump();
        let next = self.peek().tok;
        let expr = match next {
            Tok::Punct(b':') => {
                self.bump();
                let size = self.integer()?;
                Expr::Truncate { name, size }
            }
            Tok::Punct(b'(') => {
                self.bump();
                let arg = self.integer_varnode()?;
                let close = self.expect(b')')?;
                let args = self.nodes.add_expr_list(&[arg]);
                return Ok(self.combine(
                    1,
                    Expr::Apply {
                        name,
                        args,
                        span: at.to(close),
                    },
                ));
            }
            Tok::Punct(b'[') => {
                self.bump();
                let low = self.integer()?;
                self.expect(b',')?;
                let width = self.integer()?;
                let close = self.expect(b']')?;
                Expr::BitRange {
                    name,
                    low,
                    width,
                    span: at.to(close),
                }
            }
            _ => Expr::Ident(name),
        };
        let id = self.nodes.add_expr(expr);
        Ok(self.complete(id))
    }

    /// `varnode` where only a varnode may stand (after `&`): a specific
    /// symbol without suffix, or an `integervarnode`.
    fn varnode(&mut self) -> PResult<ExprId> {
        let t = self.peek();
        match t.tok {
            Tok::Name => match self.class(t.span) {
                Class::Varnode | Class::Operand | Class::Jump => {
                    let name = self.ident(t.span);
                    self.bump();
                    let id = self.nodes.add_expr(Expr::Ident(name));
                    Ok(self.complete(id))
                }
                Class::Unknown => {
                    let text = self.text(t.span).to_owned();
                    self.bump();
                    Err(Fail(format!("Unknown varnode parameter: {text}")))
                }
                _ => Err(Fail::syntax()),
            },
            _ => self.integer_varnode(),
        }
    }

    /// `integervarnode`: `k`, `k:n`, `&v`, `&:n v`; a `BADINTEGER` reads as
    /// 0 with an error (state 4, 7, 14, 28).
    pub(super) fn integer_varnode(&mut self) -> PResult<ExprId> {
        self.enter()?;
        let result = self.integer_varnode_inner();
        self.leave();
        result
    }

    fn integer_varnode_inner(&mut self) -> PResult<ExprId> {
        let t = self.peek();
        match t.tok {
            Tok::Int(_) => {
                let value = self.integer()?;
                if !self.at_punct(b':') {
                    let id = self.nodes.add_expr(Expr::Int(value));
                    return Ok(self.complete(id));
                }
                self.bump();
                let size = self.integer()?;
                let id = self.nodes.add_expr(Expr::SizedInt { value, size });
                Ok(self.complete(id))
            }
            Tok::BadInt => {
                self.bump();
                let id = self.nodes.add_expr(Expr::Int(Self::bad_integer(t.span)));
                Ok(self.complete(id))
            }
            Tok::Punct(b'&') => {
                self.bump();
                let size = if self.at_punct(b':') {
                    self.bump();
                    Some(self.integer()?)
                } else {
                    None
                };
                let operand = self.varnode()?;
                let span = t.span.to(self.nodes[operand].span());
                Ok(self.combine(
                    1,
                    Expr::AddressOf {
                        size,
                        operand,
                        span,
                    },
                ))
            }
            _ => Err(Fail::syntax()),
        }
    }
}
