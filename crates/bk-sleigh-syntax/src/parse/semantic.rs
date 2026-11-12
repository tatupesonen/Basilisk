//! Semantic sections: statements.

use super::{PResult, Parser};
use crate::ast::{
    ExportValue, Ident, IntLit, JumpDest, LValue, SemanticBody, SizedStar, Statement,
};
use crate::intern::kw;
use crate::lex::{Mode, TokenKind};
use crate::span::Span;

impl Parser<'_> {
    /// `{ statements }`, starting at the `{`. Errors inside the body are
    /// reported and skipped statement by statement, so a body always comes
    /// back.
    pub(super) fn semantic_body(&mut self) -> SemanticBody {
        let open = self.tok.span;
        self.set_mode(Mode::Semantic);
        self.bump(); // `{`
        let mut statements = Vec::new();
        loop {
            if self.at(TokenKind::RBrace) {
                self.set_mode(Mode::Base);
                self.bump();
                break;
            }
            if self.at_eof() {
                self.set_mode(Mode::Base);
                self.error_at(open, "this `{` is never closed");
                break;
            }
            self.statement_into(&mut statements);
        }
        SemanticBody {
            statements,
            span: self.span_from(open),
        }
    }

    /// Parses one statement into `statements`; on a syntax error, skips to
    /// the statement's `;` (or stops before a `}`) and records a
    /// placeholder.
    pub(super) fn statement_into(&mut self, statements: &mut Vec<Statement>) {
        let start = self.tok.span;
        if let Ok(statement) = self.statement() {
            statements.push(statement);
        } else {
            while !matches!(
                self.tok.kind,
                TokenKind::Semi | TokenKind::RBrace | TokenKind::Eof
            ) {
                self.bump();
            }
            self.eat(TokenKind::Semi);
            statements.push(Statement::Error(self.span_from(start)));
        }
    }

    fn statement(&mut self) -> PResult<Statement> {
        let start = self.tok.span;
        match self.tok.kind {
            TokenKind::Less => {
                let name = self.label()?;
                return Ok(Statement::Label {
                    name,
                    span: self.span_from(start),
                });
            }
            TokenKind::Left => {
                self.bump();
                let name = self.identifier()?;
                self.expect(TokenKind::Right)?;
                return Ok(Statement::Section {
                    name,
                    span: self.span_from(start),
                });
            }
            TokenKind::Semi => {
                // Ghidra aborts with "Empty statement at <location>".
                let reported = self.error("Empty statement");
                self.bump();
                return Err(reported);
            }
            _ => {}
        }
        let statement = if self.at(TokenKind::Asterisk) {
            self.assignment(false, start)?
        } else if self.tok.kind == TokenKind::Ident {
            self.word_statement(start)?
        } else {
            let found = self.found();
            return Err(self.error(format!("expected a statement, found {found}")));
        };
        if self.eat(TokenKind::Semi).is_none() {
            let found = self.found();
            return Err(self.error(format!("expected `;` after the statement, found {found}")));
        }
        Ok(statement)
    }

    /// Whether the tokens after a `[` that follows the current word are the
    /// start of a bit range (`[ integer ,`).
    fn bit_range_follows(&mut self) -> bool {
        self.peek(2).kind.is_int() && self.peek(3).kind == TokenKind::Comma
    }

    /// A statement that starts with a word. A statement keyword is an
    /// ordinary identifier when what follows can only continue an
    /// assignment or a call (`=`, `(`, `:`, `[`).
    fn word_statement(&mut self, start: Span) -> PResult<Statement> {
        let word = self.tok.symbol;
        if word == kw::IF {
            self.bump();
            let condition = self.expr()?;
            self.expect_word(kw::GOTO)?;
            let dest = self.jump_dest()?;
            return Ok(Statement::If {
                condition,
                dest,
                span: self.span_from(start),
            });
        }
        let next = self.peek(1).kind;
        let bracket_is_range = next == TokenKind::LBracket && self.bit_range_follows();
        let as_name = match next {
            TokenKind::Assign | TokenKind::LParen | TokenKind::Colon => true,
            TokenKind::LBracket => {
                bracket_is_range || !(word == kw::GOTO || word == kw::CALL || word == kw::RETURN)
            }
            _ => false,
        };
        if !as_name {
            if word == kw::LOCAL {
                self.bump();
                return self.local(start);
            }
            if word == kw::BUILD {
                self.bump();
                let operand = self.identifier()?;
                return Ok(Statement::Build {
                    operand,
                    span: self.span_from(start),
                });
            }
            if word == kw::CROSSBUILD {
                self.bump();
                let address = self.varnode()?;
                self.expect(TokenKind::Comma)?;
                let section = self.identifier()?;
                return Ok(Statement::CrossBuild {
                    address,
                    section,
                    span: self.span_from(start),
                });
            }
            if word == kw::GOTO {
                self.bump();
                let dest = self.jump_dest()?;
                return Ok(Statement::Goto {
                    dest,
                    span: self.span_from(start),
                });
            }
            if word == kw::CALL {
                self.bump();
                let dest = self.jump_dest()?;
                return Ok(Statement::Call {
                    dest,
                    span: self.span_from(start),
                });
            }
            if word == kw::RETURN {
                self.bump();
                if !self.at(TokenKind::LBracket) {
                    return Err(self.error_expected("`[` (return takes an indirect target)"));
                }
                self.bump();
                let target = self.expr()?;
                self.expect(TokenKind::RBracket)?;
                return Ok(Statement::Return {
                    target,
                    span: self.span_from(start),
                });
            }
            if word == kw::EXPORT {
                self.bump();
                let value = if self.at(TokenKind::Asterisk) {
                    let star = self.sized_star()?;
                    let name = self.identifier()?;
                    ExportValue::Deref { star, name }
                } else {
                    ExportValue::Varnode(self.varnode()?)
                };
                return Ok(Statement::Export {
                    value,
                    span: self.span_from(start),
                });
            }
        }
        if next == TokenKind::LParen {
            let name = self.identifier()?;
            let args = self.call_args()?;
            return Ok(Statement::Apply {
                name,
                args,
                span: self.span_from(start),
            });
        }
        self.assignment(false, start)
    }

    /// What follows `local`: a declaration or an assignment.
    fn local(&mut self, start: Span) -> PResult<Statement> {
        if self.at(TokenKind::Asterisk) {
            return self.assignment(true, start);
        }
        let name = self.identifier()?;
        let target = match self.tok.kind {
            TokenKind::Colon => {
                self.bump();
                let size = self.integer()?;
                if !self.at(TokenKind::Assign) {
                    let span = self.span_from(start);
                    return Ok(Statement::Declare {
                        name,
                        size: Some(size),
                        span,
                    });
                }
                LValue::Sized { name, size }
            }
            TokenKind::LBracket => self.bit_range_target(name)?,
            TokenKind::Assign => LValue::Ident(name),
            _ => {
                return Ok(Statement::Declare {
                    name,
                    size: None,
                    span: self.span_from(start),
                });
            }
        };
        self.finish_assignment(true, target, start)
    }

    /// `lvalue = expression`.
    fn assignment(&mut self, local: bool, start: Span) -> PResult<Statement> {
        let target = if self.at(TokenKind::Asterisk) {
            let star = self.sized_star()?;
            let address = self.expr()?;
            LValue::Deref { star, address }
        } else {
            let name = self.identifier()?;
            match self.tok.kind {
                TokenKind::Colon => {
                    self.bump();
                    let size = self.integer()?;
                    LValue::Sized { name, size }
                }
                TokenKind::LBracket => self.bit_range_target(name)?,
                _ => LValue::Ident(name),
            }
        };
        self.finish_assignment(local, target, start)
    }

    fn finish_assignment(
        &mut self,
        local: bool,
        target: LValue,
        start: Span,
    ) -> PResult<Statement> {
        if !self.at(TokenKind::Assign) {
            let found = self.found();
            return Err(self.error(format!(
                "expected `=` to complete the assignment, found {found}"
            )));
        }
        let op_span = self.bump().span;
        let value = self.expr()?;
        Ok(Statement::Assign {
            local,
            target,
            op_span,
            value,
            span: self.span_from(start),
        })
    }

    /// `[ low , width ]` after an lvalue's name.
    fn bit_range_target(&mut self, name: Ident) -> PResult<LValue> {
        let (low, width) = self.bit_range_bounds()?;
        Ok(LValue::BitRange { name, low, width })
    }

    /// `[ integer , integer ]`, starting at the `[`.
    pub(super) fn bit_range_bounds(&mut self) -> PResult<(IntLit, IntLit)> {
        self.expect(TokenKind::LBracket)?;
        let low = self.integer()?;
        self.expect(TokenKind::Comma)?;
        let width = self.integer()?;
        self.expect(TokenKind::RBracket)?;
        Ok((low, width))
    }

    /// `*`, `*:size`, `*[space]` or `*[space]:size`, starting at the `*`.
    pub(super) fn sized_star(&mut self) -> PResult<SizedStar> {
        let star = self.expect(TokenKind::Asterisk)?;
        let space = if self.eat(TokenKind::LBracket).is_some() {
            let space = self.identifier()?;
            self.expect(TokenKind::RBracket)?;
            Some(space)
        } else {
            None
        };
        let size = if self.eat(TokenKind::Colon).is_some() {
            Some(self.integer()?)
        } else {
            None
        };
        Ok(SizedStar {
            space,
            size,
            span: self.span_from(star.span),
        })
    }

    /// `< name >`, starting at the `<`.
    fn label(&mut self) -> PResult<Ident> {
        self.expect(TokenKind::Less)?;
        let name = self.identifier()?;
        self.expect(TokenKind::Great)?;
        Ok(name)
    }

    /// The destination of a `goto`, `call` or conditional branch.
    fn jump_dest(&mut self) -> PResult<JumpDest> {
        match self.tok.kind {
            TokenKind::LBracket => {
                self.bump();
                let target = self.expr()?;
                self.expect(TokenKind::RBracket)?;
                Ok(JumpDest::Dynamic(target))
            }
            TokenKind::Less => self.label().map(JumpDest::Label),
            kind if kind.is_int() => {
                let offset = self.integer()?;
                if self.eat(TokenKind::LBracket).is_some() {
                    let space = self.identifier()?;
                    self.expect(TokenKind::RBracket)?;
                    Ok(JumpDest::Relative { offset, space })
                } else {
                    Ok(JumpDest::Absolute(offset))
                }
            }
            TokenKind::Ident => self.identifier().map(JumpDest::Symbol),
            _ => {
                let found = self.found();
                Err(self.error(format!("expected a jump destination, found {found}")))
            }
        }
    }
}
