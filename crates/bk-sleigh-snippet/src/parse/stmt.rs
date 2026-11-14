//! Statements (`rtlmid`, `statement`, `jumpdest`, `label`, `sizedstar`).

use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{Expr, ExprId, IntLit, JumpDest, LValue, SizedStar, Statement};

use super::{Fail, PResult, Parser};
use crate::lex::{Keyword, Tok};
use crate::scope::Class;

impl Parser<'_> {
    /// One statement, or a `local` declaration (`Ok(Some)`), from the
    /// token after the previous one (parser state 2).
    pub(super) fn statement(&mut self) -> PResult<Option<Statement>> {
        let t = self.peek();
        let start = t.span;
        match t.tok {
            Tok::Name => match self.class(t.span) {
                Class::Unknown => self.unknown_start(start).map(Some),
                Class::UserOp => {
                    let name = self.ident(t.span);
                    self.bump();
                    self.expect(b'(')?;
                    let args = self.param_list()?;
                    let end = self.expect(b';')?;
                    Ok(Some(Statement::Apply {
                        name,
                        args,
                        span: start.to(end),
                    }))
                }
                Class::Varnode | Class::Operand | Class::Jump => {
                    let name = self.ident(t.span);
                    self.bump();
                    if self.at_punct(b'=') {
                        let op_span = self.bump().span;
                        let value = self.expr()?;
                        let end = self.expect(b';')?;
                        Ok(Some(Statement::Assign {
                            local: false,
                            target: LValue::Ident(name),
                            op_span,
                            value,
                            span: start.to(end),
                        }))
                    } else if self.at_punct(b'[') {
                        self.bump();
                        let low = self.integer()?;
                        self.expect(b',')?;
                        let width = self.integer()?;
                        self.expect(b']')?;
                        let op_span = self.expect(b'=')?;
                        let value = self.expr()?;
                        let end = self.expect(b';')?;
                        Ok(Some(Statement::Assign {
                            local: false,
                            target: LValue::BitRange { name, low, width },
                            op_span,
                            value,
                            span: start.to(end),
                        }))
                    } else {
                        // `varnode: specificsymbol`, then state 22.
                        let id = self.nodes.add_expr(Expr::Ident(name));
                        self.complete(id);
                        Err(self.varnode_statement())
                    }
                }
                Class::Space | Class::Label => Err(Fail::syntax()),
            },
            Tok::Int(_) | Tok::BadInt | Tok::Punct(b'&') => {
                self.integer_varnode()?;
                Err(self.varnode_statement())
            }
            Tok::Punct(b'<') => {
                let (name, span) = self.label()?;
                Ok(Some(Statement::Label { name, span }))
            }
            Tok::Punct(b'*') => {
                let star = self.sized_star()?;
                let address = self.expr()?;
                let op_span = self.expect(b'=')?;
                let value = self.expr()?;
                let end = self.expect(b';')?;
                Ok(Some(Statement::Assign {
                    local: false,
                    target: LValue::Deref { star, address },
                    op_span,
                    value,
                    span: start.to(end),
                }))
            }
            Tok::Keyword(Keyword::Goto) => {
                self.bump();
                let dest = self.jump_dest_or_dynamic()?;
                let end = self.expect(b';')?;
                Ok(Some(Statement::Goto {
                    dest,
                    span: start.to(end),
                }))
            }
            Tok::Keyword(Keyword::Call) => {
                self.bump();
                let dest = self.jump_dest_or_dynamic()?;
                let end = self.expect(b';')?;
                Ok(Some(Statement::Call {
                    dest,
                    span: start.to(end),
                }))
            }
            Tok::Keyword(Keyword::Return) => {
                self.bump();
                if self.at_punct(b';') {
                    self.bump();
                    return Err(Fail(
                        "Must specify an indirect parameter for return".to_owned(),
                    ));
                }
                self.expect(b'[')?;
                let target = self.expr()?;
                self.expect(b']')?;
                let end = self.expect(b';')?;
                Ok(Some(Statement::Return {
                    target,
                    span: start.to(end),
                }))
            }
            Tok::Keyword(Keyword::If) => {
                self.bump();
                let condition = self.expr()?;
                if self.peek().tok != Tok::Keyword(Keyword::Goto) {
                    return Err(Fail::syntax());
                }
                self.bump();
                let dest = self.jump_dest()?;
                let end = self.expect(b';')?;
                Ok(Some(Statement::If {
                    condition,
                    dest,
                    span: start.to(end),
                }))
            }
            Tok::Keyword(Keyword::Local) => {
                self.bump();
                self.local(start).map(Some)
            }
            _ => Err(Fail::syntax()),
        }
    }

    /// A statement starting with a name that means nothing (state 15).
    fn unknown_start(&mut self, start: Span) -> PResult<Statement> {
        let name = self.ident(start);
        let text = self.text(start).to_owned();
        self.bump();
        let next = self.peek().tok;
        match next {
            Tok::Punct(b'=') => {
                let op_span = self.bump().span;
                let value = self.expr()?;
                let end = self.expect(b';')?;
                self.define_local(start);
                Ok(Statement::Assign {
                    local: false,
                    target: LValue::Ident(name),
                    op_span,
                    value,
                    span: start.to(end),
                })
            }
            Tok::Punct(b':') => {
                self.bump();
                let size = self.integer()?;
                let op_span = self.expect(b'=')?;
                let value = self.expr()?;
                let end = self.expect(b';')?;
                self.define_local(start);
                Ok(Statement::Assign {
                    local: false,
                    target: LValue::Sized { name, size },
                    op_span,
                    value,
                    span: start.to(end),
                })
            }
            Tok::Punct(b'[') => Err(Fail(format!("Unknown assignment varnode: {text}"))),
            _ => Err(Fail(format!("Unknown varnode parameter: {text}"))),
        }
    }

    /// After `local` (state 13).
    fn local(&mut self, start: Span) -> PResult<Statement> {
        let t = self.peek();
        if t.tok != Tok::Name {
            return Err(Fail::syntax());
        }
        match self.class(t.span) {
            Class::Unknown => {}
            Class::Varnode | Class::Operand | Class::Jump => {
                let text = self.text(t.span).to_owned();
                self.bump();
                self.expect(b'=')?;
                return Err(Fail(format!("Redefinition of symbol: {text}")));
            }
            _ => return Err(Fail::syntax()),
        }
        let name = self.ident(t.span);
        self.bump();
        let mut size: Option<IntLit> = None;
        if self.at_punct(b':') {
            self.bump();
            size = Some(self.integer()?);
        }
        if self.at_punct(b';') {
            let end = self.bump().span;
            self.define_local(t.span);
            return Ok(Statement::Declare {
                name,
                size,
                span: start.to(end),
            });
        }
        let op_span = self.expect(b'=')?;
        let value = self.expr()?;
        let end = self.expect(b';')?;
        self.define_local(t.span);
        let target = match size {
            Some(size) => LValue::Sized { name, size },
            None => LValue::Ident(name),
        };
        Ok(Statement::Assign {
            local: true,
            target,
            op_span,
            value,
            span: start.to(end),
        })
    }

    /// A statement that starts with a `varnode` (state 22): only the two
    /// error rules continue from here. Returns the failure.
    fn varnode_statement(&mut self) -> Fail {
        let result: PResult<()> = (|| {
            if self.at_punct(b':') {
                self.bump();
                self.integer()?;
                self.expect(b'=')?;
                return Err(Fail(
                    "Illegal truncation on left-hand side of assignment".to_owned(),
                ));
            }
            if self.at_punct(b'(') {
                self.bump();
                self.integer()?;
                self.expect(b')')?;
                return Err(Fail(
                    "Illegal subpiece on left-hand side of assignment".to_owned(),
                ));
            }
            Err(Fail::syntax())
        })();
        match result {
            Err(fail) => fail,
            Ok(()) => Fail::syntax(),
        }
    }

    /// `label`: `<name>`; defines the label if it is new (`defineLabel`).
    pub(super) fn label(&mut self) -> PResult<(bk_sleigh_syntax::ast::Ident, Span)> {
        let open = self.expect(b'<')?;
        let t = self.peek();
        if t.tok != Tok::Name {
            return Err(Fail::syntax());
        }
        let class = self.class(t.span);
        if !matches!(class, Class::Unknown | Class::Label) {
            return Err(Fail::syntax());
        }
        let name = self.ident(t.span);
        self.bump();
        let close = self.expect(b'>')?;
        if class == Class::Unknown {
            self.define_label(t.span);
        }
        Ok((name, open.to(close)))
    }

    /// `jumpdest`, or `[ expr ]` after `goto` and `call`.
    fn jump_dest_or_dynamic(&mut self) -> PResult<JumpDest> {
        if self.at_punct(b'[') {
            self.bump();
            let e = self.expr()?;
            self.expect(b']')?;
            return Ok(JumpDest::Dynamic(e));
        }
        self.jump_dest()
    }

    /// `jumpdest` (states 8, 9, 150).
    fn jump_dest(&mut self) -> PResult<JumpDest> {
        let t = self.peek();
        match t.tok {
            Tok::Punct(b'<') => {
                let (name, _) = self.label()?;
                Ok(JumpDest::Label(name))
            }
            Tok::BadInt => {
                self.bump();
                let lit = Self::bad_integer(t.span);
                // Reduced at once, with its error, whatever follows.
                let id = self.nodes.add_expr(Expr::Int(lit.clone()));
                self.complete(id);
                Ok(JumpDest::Absolute(lit))
            }
            Tok::Int(_) => {
                let offset = self.integer()?;
                if !self.at_punct(b'[') {
                    return Ok(JumpDest::Absolute(offset));
                }
                self.bump();
                let s = self.peek();
                if s.tok != Tok::Name || self.class(s.span) != Class::Space {
                    return Err(Fail::syntax());
                }
                let space = self.ident(s.span);
                self.bump();
                self.expect(b']')?;
                Ok(JumpDest::Relative { offset, space })
            }
            Tok::Name => match self.class(t.span) {
                Class::Jump => {
                    let name = self.ident(t.span);
                    self.bump();
                    Ok(JumpDest::Symbol(name))
                }
                Class::Unknown => {
                    let text = self.text(t.span).to_owned();
                    self.bump();
                    Err(Fail(format!("Unknown jump destination: {text}")))
                }
                _ => Err(Fail::syntax()),
            },
            _ => Err(Fail::syntax()),
        }
    }

    /// `sizedstar` (states 6, 33, 34, 170).
    pub(super) fn sized_star(&mut self) -> PResult<SizedStar> {
        let star = self.expect(b'*')?;
        if self.at_punct(b':') {
            self.bump();
            let size = self.integer()?;
            let span = star.to(size.span);
            return Ok(SizedStar {
                space: None,
                size: Some(size),
                span,
            });
        }
        if !self.at_punct(b'[') {
            return Ok(SizedStar {
                space: None,
                size: None,
                span: star,
            });
        }
        self.bump();
        let s = self.peek();
        if s.tok != Tok::Name || self.class(s.span) != Class::Space {
            return Err(Fail::syntax());
        }
        let space = self.ident(s.span);
        self.bump();
        let close = self.expect(b']')?;
        if self.at_punct(b':') {
            self.bump();
            let size = self.integer()?;
            let span = star.to(size.span);
            return Ok(SizedStar {
                space: Some(space),
                size: Some(size),
                span,
            });
        }
        Ok(SizedStar {
            space: Some(space),
            size: None,
            span: star.to(close),
        })
    }

    /// `paramlist ')'` after the `(`: empty, or expressions separated by
    /// commas — and, as Ghidra's grammar allows, a leading comma after an
    /// empty list (`f(, a)` passes `a`).
    pub(super) fn param_list(&mut self) -> PResult<bk_sleigh_syntax::ast::ExprList> {
        let mut args: Vec<ExprId> = Vec::new();
        if !self.at_punct(b')') && !self.at_punct(b',') {
            args.push(self.expr()?);
        }
        while self.at_punct(b',') {
            self.bump();
            args.push(self.expr()?);
        }
        self.expect(b')')?;
        // The arguments are children of the call now.
        let keep = self.pending.len().saturating_sub(args.len());
        self.pending.truncate(keep);
        Ok(self.nodes.add_expr_list(&args))
    }
}
