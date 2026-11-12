//! The parser.
//!
//! A hand-written recursive-descent parser over the modal [`Lexer`], with
//! precedence climbing for the three expression languages. It accepts the
//! language of Ghidra's `SleighParser.g`, `DisplayParser.g` and
//! `SemanticParser.g` and builds the symbol-free tree of [`crate::ast`].
//!
//! The parser drives the lexer's mode: it asks for display-mode tokens
//! between a constructor's `:` and `is`, semantic-mode tokens between `{`
//! and `}`, and base-mode tokens elsewhere. Lookahead never crosses a mode
//! change: switching modes discards any tokens scanned ahead and rescans
//! them in the new mode.
//!
//! Syntax errors are reported as [`Diagnostic`]s and parsing continues: a
//! bad statement is skipped to its `;`, a bad definition or constructor to
//! its `;` or closing `}`. Nesting is bounded ([`MAX_DEPTH`]) and reporting
//! stops after [`MAX_ERRORS`] errors, so no input can exhaust the stack or
//! flood the caller.

mod constructor;
mod definitions;
mod expr;
mod pattern;
mod semantic;

use std::collections::VecDeque;

use crate::ast::{Ident, IntLit, Nodes, SemanticBody, Spec};
use crate::diag::Diagnostic;
use crate::intern::{Interner, Symbol, kw};
use crate::lex::literal::{IntError, IntValue, Radix};
use crate::lex::{Lexer, Mode, Token, TokenKind};
use crate::span::Span;

/// Deepest nesting of parentheses, unary operators and `with` blocks.
pub const MAX_DEPTH: u32 = 128;

/// After this many errors the parser reports one last "too many errors"
/// and stops.
pub const MAX_ERRORS: usize = 500;

/// Marker for "a syntax error was reported; the caller should recover".
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reported;

pub(crate) type PResult<T> = Result<T, Reported>;

/// Everything a parse produces.
#[derive(Debug)]
pub(crate) struct ParseOutput<T> {
    pub(crate) tree: T,
    pub(crate) nodes: Nodes,
    pub(crate) names: Interner,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) tokens: u64,
}

pub(crate) struct Parser<'a> {
    src: &'a str,
    lexer: Lexer<'a>,
    mode: Mode,
    /// The current token: never an error token.
    tok: Token,
    /// Tokens scanned ahead in the current mode (may include error tokens).
    ahead: VecDeque<Token>,
    /// End offset of the most recently consumed token.
    prev_end: u32,
    names: Interner,
    nodes: Nodes,
    diagnostics: Vec<Diagnostic>,
    errors: usize,
    /// Start offset of the token the last syntax error was reported at.
    last_error_at: Option<u32>,
    depth: u32,
    tokens: u64,
    /// The spec's `define endian`, once seen.
    endian: Option<crate::ast::EndianDef>,
    /// Call arguments being collected (a stack shared by nested calls).
    expr_scratch: Vec<crate::ast::ExprId>,
    pat_scratch: Vec<crate::ast::PatExprId>,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(src: &'a str, mode: Mode, names: Interner) -> Self {
        let mut parser = Parser {
            src,
            lexer: Lexer::new(src),
            mode,
            tok: Token {
                kind: TokenKind::Eof,
                span: Span::at(0),
                symbol: kw::WITH,
            },
            ahead: VecDeque::new(),
            prev_end: 0,
            names,
            nodes: Nodes::default(),
            diagnostics: Vec::new(),
            errors: 0,
            last_error_at: None,
            depth: 0,
            tokens: 0,
            endian: None,
            expr_scratch: Vec::new(),
            pat_scratch: Vec::new(),
        };
        parser.tok = parser.next_valid();
        parser
    }

    pub(crate) fn finish<T>(self, tree: T) -> ParseOutput<T> {
        ParseOutput {
            tree,
            nodes: self.nodes,
            names: self.names,
            diagnostics: self.diagnostics,
            tokens: self.tokens,
        }
    }

    // ----- tokens -----

    /// Takes the next non-error token, reporting error tokens on the way.
    fn next_valid(&mut self) -> Token {
        loop {
            let token = match self.ahead.pop_front() {
                Some(token) => token,
                None => self.lexer.next_token(self.mode, &mut self.names),
            };
            if !token.kind.is_error() {
                return token;
            }
            self.lexical_error(token);
        }
    }

    fn lexical_error(&mut self, token: Token) {
        let message = match token.kind {
            TokenKind::CppComment => {
                "`//` comments are not supported; comments start with `#`".to_owned()
            }
            TokenKind::BadString => "invalid escape sequence in string".to_owned(),
            TokenKind::UnterminatedString => "unterminated string".to_owned(),
            _ => {
                let text = self.src.get(token.span.range()).unwrap_or("");
                format!("unexpected character `{}`", text.escape_debug())
            }
        };
        self.push_error(token.span, message);
    }

    /// Consumes the current token and returns it.
    pub(crate) fn bump(&mut self) -> Token {
        let token = self.tok;
        self.prev_end = token.span.end;
        if token.kind != TokenKind::Eof {
            self.tokens += 1;
        }
        self.tok = self.next_valid();
        token
    }

    /// The `n`th token after the current one (1 = the next), skipping error
    /// tokens, without consuming anything.
    pub(crate) fn peek(&mut self, n: usize) -> Token {
        let mut seen = 0;
        let mut index = 0;
        loop {
            let token = if let Some(token) = self.ahead.get(index) {
                *token
            } else {
                let token = self.lexer.next_token(self.mode, &mut self.names);
                self.ahead.push_back(token);
                token
            };
            if token.kind == TokenKind::Eof {
                return token;
            }
            if !token.kind.is_error() {
                seen += 1;
                if seen == n {
                    return token;
                }
            }
            index += 1;
        }
    }

    /// Switches the lexer mode for the tokens after the current one.
    pub(crate) fn set_mode(&mut self, mode: Mode) {
        if mode != self.mode {
            self.mode = mode;
            self.ahead.clear();
            self.lexer.seek(self.tok.span.end);
        }
    }

    pub(crate) fn at(&self, kind: TokenKind) -> bool {
        self.tok.kind == kind
    }

    pub(crate) fn at_word(&self, word: Symbol) -> bool {
        self.tok.is_word(word)
    }

    pub(crate) fn at_eof(&self) -> bool {
        self.tok.kind == TokenKind::Eof
    }

    /// Consumes the current token if it is of `kind`.
    pub(crate) fn eat(&mut self, kind: TokenKind) -> Option<Token> {
        self.at(kind).then(|| self.bump())
    }

    /// Consumes the current token if it is the identifier `word`.
    pub(crate) fn eat_word(&mut self, word: Symbol) -> Option<Token> {
        self.at_word(word).then(|| self.bump())
    }

    pub(crate) fn expect(&mut self, kind: TokenKind) -> PResult<Token> {
        match self.eat(kind) {
            Some(token) => Ok(token),
            None => Err(self.error_expected(kind.describe())),
        }
    }

    pub(crate) fn expect_word(&mut self, word: Symbol) -> PResult<Token> {
        if let Some(token) = self.eat_word(word) {
            Ok(token)
        } else {
            let wanted = format!("`{}`", self.names.resolve(word));
            Err(self.error_expected(&wanted))
        }
    }

    /// The text of a token.
    pub(crate) fn text(&self, span: Span) -> &'a str {
        self.src.get(span.range()).unwrap_or("")
    }

    /// The span from `start` to the end of the last consumed token.
    pub(crate) fn span_from(&self, start: Span) -> Span {
        Span::new(start.start, self.prev_end.max(start.start))
    }

    // ----- diagnostics -----

    fn push_error(&mut self, span: Span, message: String) {
        self.errors += 1;
        if self.errors <= MAX_ERRORS {
            self.diagnostics.push(Diagnostic::error(span, message));
        }
        if self.errors == MAX_ERRORS {
            self.diagnostics
                .push(Diagnostic::error(span, "too many errors; giving up"));
            // Jump to the end of the input so that parsing winds down.
            self.ahead.clear();
            self.lexer.seek(u32::MAX);
            let end = self.lexer.offset();
            self.tok = Token {
                kind: TokenKind::Eof,
                span: Span::at(end),
                symbol: kw::WITH,
            };
        }
    }

    /// Reports a syntax error at the current token (once per token).
    pub(crate) fn error(&mut self, message: impl Into<String>) -> Reported {
        let span = self.tok.span;
        self.error_at(span, message)
    }

    /// Reports a syntax error at `span` (once per position).
    pub(crate) fn error_at(&mut self, span: Span, message: impl Into<String>) -> Reported {
        if self.last_error_at != Some(span.start) {
            self.last_error_at = Some(span.start);
            self.push_error(span, message.into());
        }
        Reported
    }

    /// Describes the current token for an error message.
    pub(crate) fn found(&self) -> String {
        match self.tok.kind {
            TokenKind::Eof => "end of input".to_owned(),
            TokenKind::Whitespace => "whitespace".to_owned(),
            _ => format!("`{}`", self.text(self.tok.span).escape_debug()),
        }
    }

    pub(crate) fn error_expected(&mut self, wanted: &str) -> Reported {
        let found = self.found();
        self.error(format!("expected {wanted}, found {found}"))
    }

    // ----- nesting -----

    /// Enters one level of nesting; fails beyond [`MAX_DEPTH`].
    pub(crate) fn enter(&mut self) -> PResult<()> {
        if self.depth >= MAX_DEPTH {
            return Err(self.error(format!("nesting deeper than {MAX_DEPTH} levels")));
        }
        self.depth += 1;
        Ok(())
    }

    pub(crate) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ----- shared leaves -----

    /// Whether the current token can be an identifier here: any word except
    /// `with` (reserved everywhere) and, in semantic mode, `if`.
    pub(crate) fn at_identifier(&self) -> bool {
        self.is_identifier(self.tok)
    }

    pub(crate) fn is_identifier(&self, token: Token) -> bool {
        match token.ident() {
            Some(name) => !(name.is_reserved() || (self.mode == Mode::Semantic && name == kw::IF)),
            None => false,
        }
    }

    /// `identifier`: a name; keywords are allowed.
    pub(crate) fn identifier(&mut self) -> PResult<Ident> {
        if self.at_identifier() {
            let token = self.bump();
            Ok(Ident {
                name: token.symbol,
                span: token.span,
            })
        } else if self.tok.kind == TokenKind::Ident {
            let found = self.found();
            Err(self.error(format!(
                "{found} is a reserved word and cannot be used as a name"
            )))
        } else {
            Err(self.error_expected("identifier"))
        }
    }

    /// `integer`: decimal, hexadecimal or binary (not the `0n` form).
    pub(crate) fn integer(&mut self) -> PResult<IntLit> {
        match self.tok.kind {
            TokenKind::DecInt | TokenKind::HexInt | TokenKind::BinInt => Ok(self.int_literal()),
            TokenKind::PrefixedDecInt => {
                self.error("`0n` integers are only allowed as operands in a semantic section");
                Ok(self.int_literal())
            }
            _ => Err(self.error_expected("integer")),
        }
    }

    /// Consumes the current integer token (of any of the four kinds).
    pub(crate) fn int_literal(&mut self) -> IntLit {
        let token = self.bump();
        let text = self.text(token.span);
        let (digits, radix) = match token.kind {
            TokenKind::HexInt => (text.get(2..).unwrap_or(""), Radix::Hex),
            TokenKind::BinInt => (text.get(2..).unwrap_or(""), Radix::Binary),
            TokenKind::PrefixedDecInt => (text.get(2..).unwrap_or(""), Radix::Decimal),
            _ => (text, Radix::Decimal),
        };
        let value = match IntValue::parse(digits, radix) {
            Ok(value) => value,
            Err(err) => {
                let message = match err {
                    IntError::TooLong => "integer literal has too many digits",
                    IntError::Empty | IntError::BadDigit => "malformed integer literal",
                };
                self.error_at(token.span, message);
                IntValue::ZERO
            }
        };
        IntLit::new(value, radix, token.span)
    }

    // ----- entry points -----

    /// Parses a whole specification.
    pub(crate) fn spec(mut self) -> ParseOutput<Spec> {
        let items = self.items(false);
        if self.endian.is_none() && self.errors < MAX_ERRORS {
            self.push_error(
                Span::at(0),
                "missing `define endian = big;` or `define endian = little;` \
                 (it must be the first statement)"
                    .to_owned(),
            );
        }
        let endian = self.endian;
        // The caller moves the node arenas into the spec.
        self.finish(Spec {
            endian,
            items,
            nodes: Nodes::default(),
        })
    }

    /// Parses bare semantic statements up to the end of the input.
    pub(crate) fn snippet(mut self) -> ParseOutput<SemanticBody> {
        let start = self.tok.span;
        let mut statements = Vec::new();
        while !self.at_eof() {
            if self.at(TokenKind::RBrace) {
                self.error("unexpected `}`");
                self.bump();
                continue;
            }
            self.statement_into(&mut statements);
        }
        let span = self.span_from(start);
        self.finish(SemanticBody { statements, span })
    }
}
