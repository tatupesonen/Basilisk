//! Constructors, display sections, `with` blocks and macros.

use super::{PResult, Parser};
use crate::ast::{Constructor, ConstructorBody, DisplayPiece, Ident, MacroDef, StrLit, WithBlock};
use crate::intern::kw;
use crate::lex::{Mode, TokenKind, string_content};

impl Parser<'_> {
    /// A constructor, starting at the `:` of its display section; `table`
    /// is the name that preceded it, if any.
    pub(super) fn constructor(&mut self, table: Option<Ident>) -> PResult<Constructor> {
        let colon = self.tok.span;
        let start = table.map_or(colon, |t| t.span);
        let display = self.display()?;
        let pattern = self.equation()?;
        let context = if self.at(TokenKind::LBracket) {
            Some(self.context_block()?)
        } else {
            None
        };
        let body = if let Some(token) = self.eat_word(kw::UNIMPL) {
            ConstructorBody::Unimpl(token.span)
        } else if self.at(TokenKind::LBrace) {
            ConstructorBody::Semantic(self.semantic_body())
        } else {
            let found = self.found();
            return Err(self.error(format!(
                "expected `{{` or `unimpl` after the constructor's pattern, found {found}"
            )));
        };
        Ok(Constructor {
            table,
            colon,
            display,
            pattern,
            context,
            body,
            span: self.span_from(start),
        })
    }

    /// The display section: from the `:` (the current token) through `is`.
    ///
    /// Every token of `DisplayParser.g`'s `printpiece` is a piece; the two
    /// base-lexer tokens that rule leaves out (a lone `_` and `0n` integers)
    /// and the reserved word `with` are errors, reported and skipped.
    fn display(&mut self) -> PResult<Vec<DisplayPiece>> {
        self.set_mode(Mode::Display);
        self.bump(); // `:`
        let mut pieces = Vec::new();
        loop {
            let token = self.tok;
            let piece = match token.kind {
                TokenKind::Eof => {
                    self.set_mode(Mode::Base);
                    return Err(self.error("expected `is` to end the display section"));
                }
                TokenKind::Ident if token.symbol == kw::IS => {
                    self.set_mode(Mode::Base);
                    self.bump();
                    return Ok(pieces);
                }
                TokenKind::Ident if token.symbol == kw::WITH => {
                    self.error("`with` is a reserved word; quote it to print it");
                    None
                }
                TokenKind::Ident => Some(DisplayPiece::Ident(Ident {
                    name: token.symbol,
                    span: token.span,
                })),
                TokenKind::Whitespace => Some(DisplayPiece::Whitespace(token.span)),
                TokenKind::Caret => Some(DisplayPiece::Concat(token.span)),
                TokenKind::QString => {
                    let value = self.names.intern(&string_content(self.text(token.span)));
                    Some(DisplayPiece::Quoted(StrLit {
                        value,
                        span: token.span,
                    }))
                }
                TokenKind::Underscore => {
                    self.error("a lone `_` is not a print piece; quote it to print it");
                    None
                }
                TokenKind::PrefixedDecInt => {
                    self.error("a `0n` integer is not a print piece; quote it to print it");
                    None
                }
                _ => {
                    let text = self.names.intern(self.text(token.span));
                    Some(DisplayPiece::Literal {
                        text,
                        span: token.span,
                    })
                }
            };
            pieces.extend(piece);
            self.bump();
        }
    }

    /// `with [table] : [pattern] [context] { items }`.
    pub(super) fn with_block(&mut self) -> PResult<WithBlock> {
        let start = self.bump().span; // `with`
        let table = if self.at(TokenKind::Colon) {
            None
        } else {
            Some(self.identifier()?)
        };
        self.expect(TokenKind::Colon)?;
        let pattern = if self.at(TokenKind::LBracket) || self.at(TokenKind::LBrace) {
            None
        } else {
            Some(self.equation()?)
        };
        let context = if self.at(TokenKind::LBracket) {
            Some(self.context_block()?)
        } else {
            None
        };
        self.expect(TokenKind::LBrace)?;
        self.enter()?;
        let items = self.items(true);
        self.leave();
        self.expect(TokenKind::RBrace)?;
        Ok(WithBlock {
            table,
            pattern,
            context,
            items,
            span: self.span_from(start),
        })
    }

    /// `macro name ( params ) { body }`.
    pub(super) fn macro_def(&mut self) -> PResult<MacroDef> {
        let start = self.bump().span; // `macro`
        let name = self.identifier()?;
        self.expect(TokenKind::LParen)?;
        let mut params = Vec::new();
        if !self.at(TokenKind::RParen) {
            params.push(self.identifier()?);
            while self.eat(TokenKind::Comma).is_some() {
                params.push(self.identifier()?);
            }
        }
        self.expect(TokenKind::RParen)?;
        if !self.at(TokenKind::LBrace) {
            return Err(self.error_expected("`{`"));
        }
        let body = self.semantic_body();
        Ok(MacroDef {
            name,
            params,
            body,
            span: self.span_from(start),
        })
    }
}
