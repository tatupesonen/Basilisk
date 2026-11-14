//! The snippet grammar (`pcodeparse.y` lines 98–225).
//!
//! A recursive-descent parser that accepts exactly what Ghidra's LALR
//! parser accepts and fails where and how it fails. Names are classified
//! when they are read, from the snippet's tree and the language, as
//! `PcodeSnippet::lex` does, and the tree is updated at the points where
//! Ghidra's grammar actions add symbols (a statement defining a temporary,
//! a label), which Ghidra reaches before it reads the next token.
//!
//! The parser checks the grammar and reports the errors of Ghidra's grammar
//! actions (`yyerror` followed by `YYERROR`); it builds `bk_sleigh_syntax`
//! nodes for what it accepts, and the template builder does the rest.
//! Ghidra keeps the first error only, and the actions it has already run
//! when its parser fails can report errors of their own; so when parsing
//! fails, the parser also returns the expressions of the failing statement
//! that Ghidra had already reduced ([`Parsed::pending`]), for the driver to
//! evaluate before the parse error.

mod expr;
mod stmt;

use bk_sleigh_syntax::ast::{ExprId, Ident, IntLit, Nodes, Statement};
use bk_sleigh_syntax::lex::literal::{IntValue, Radix};
use bk_sleigh_syntax::{Interner, Span};

use crate::lex::{Lexer, Tok, Token};
use crate::scope::{Class, Language, Local, Locals, mangle};

/// What the parser produced.
#[derive(Debug)]
pub(crate) struct Parsed {
    /// The statements that were parsed completely, in order.
    pub(crate) statements: Vec<Statement>,
    /// When parsing failed: the expressions of the failing statement Ghidra
    /// had reduced before the failure, in order.
    pub(crate) pending: Vec<ExprId>,
    /// Why parsing failed (Ghidra's message), if it did.
    pub(crate) failure: Option<String>,
    /// The expression arena.
    pub(crate) nodes: Nodes,
    /// The names.
    pub(crate) names: Interner,
}

/// A parse error with Ghidra's message.
#[derive(Debug)]
pub(crate) struct Fail(pub(crate) String);

impl Fail {
    fn syntax() -> Self {
        Self("syntax error".to_owned())
    }
}

type PResult<T> = Result<T, Fail>;

pub(crate) struct Parser<'a> {
    lexer: Lexer<'a>,
    peeked: Option<Token>,
    language: &'a Language,
    locals: Locals,
    nodes: Nodes,
    names: Interner,
    pending: Vec<ExprId>,
    depth: u32,
    max_depth: u32,
}

/// Parses `text` against `language` with the snippet's initial tree.
pub(crate) fn parse(text: &[u8], language: &Language, locals: Locals, max_depth: u32) -> Parsed {
    let mut parser = Parser {
        lexer: Lexer::new(text),
        peeked: None,
        language,
        locals,
        nodes: Nodes::default(),
        names: Interner::new(),
        pending: Vec::new(),
        depth: 0,
        max_depth,
    };
    let mut statements = Vec::new();
    let failure = loop {
        if parser.peek().tok == Tok::EndOfStream {
            parser.bump();
            // `rtl: rtlmid ENDOFSTREAM`, then the parser wants `$end`.
            if parser.peek().tok == Tok::Eof {
                break None;
            }
            break Some(Fail::syntax());
        }
        let base = parser.pending.len();
        match parser.statement() {
            Ok(Some(statement)) => statements.push(statement),
            Ok(None) => {}
            Err(fail) => break Some(fail),
        }
        parser.pending.truncate(base);
    };
    Parsed {
        statements,
        pending: if failure.is_some() {
            parser.pending
        } else {
            Vec::new()
        },
        failure: failure.map(|f| f.0),
        nodes: parser.nodes,
        names: parser.names,
    }
}

impl Parser<'_> {
    fn peek(&mut self) -> Token {
        if let Some(t) = self.peeked {
            return t;
        }
        let t = self.lexer.next_token();
        self.peeked = Some(t);
        t
    }

    fn bump(&mut self) -> Token {
        let t = self.peek();
        self.peeked = None;
        t
    }

    /// Consumes the one-character token `c` or fails with a syntax error.
    fn expect(&mut self, c: u8) -> PResult<Span> {
        let t = self.peek();
        if t.tok == Tok::Punct(c) {
            self.bump();
            Ok(t.span)
        } else {
            Err(Fail::syntax())
        }
    }

    fn at_punct(&mut self, c: u8) -> bool {
        self.peek().tok == Tok::Punct(c)
    }

    /// Consumes an `INTEGER` (not a `BADINTEGER`) or fails.
    fn integer(&mut self) -> PResult<IntLit> {
        let t = self.peek();
        if let Tok::Int(value) = t.tok {
            self.bump();
            Ok(IntLit::new(IntValue::from_u64(value), Radix::Decimal, t.span))
        } else {
            Err(Fail::syntax())
        }
    }

    /// A literal standing for a `BADINTEGER`: wider than 64 bits, so the
    /// builder reports "Parsed integer is too big (overflow)" and reads it
    /// as 0, as Ghidra's grammar actions do.
    fn bad_integer(span: Span) -> IntLit {
        let value = IntValue::parse("10000000000000000", Radix::Hex).unwrap_or(IntValue::ZERO);
        IntLit::new(value, Radix::Hex, span)
    }

    /// The text of a name token.
    fn text(&self, span: Span) -> &str {
        std::str::from_utf8(self.lexer.slice(span)).unwrap_or("")
    }

    /// The token class of the name at `span`.
    fn class(&self, span: Span) -> Class {
        self.locals.class(self.language, self.text(span))
    }

    /// The identifier for a name token, interned for the builder.
    fn ident(&mut self, span: Span) -> Ident {
        let text = std::str::from_utf8(self.lexer.slice(span)).unwrap_or("");
        let name = self.names.intern(&mangle(text));
        Ident { name, span }
    }

    /// Adds a local temporary's name to the tree (the parser's copy; the
    /// builder defines the real symbol).
    fn define_local(&mut self, span: Span) {
        let text = std::str::from_utf8(self.lexer.slice(span)).unwrap_or("");
        self.locals.insert(
            text,
            Local::Varnode(bk_sleigh_compiler::template::Vn::constant(0, 0)),
        );
    }

    fn define_label(&mut self, span: Span) {
        let text = std::str::from_utf8(self.lexer.slice(span)).unwrap_or("");
        self.locals.insert(
            text,
            Local::Label(bk_sleigh_compiler::pcode::LabelId(u32::MAX)),
        );
    }

    /// Records a completed expression.
    fn complete(&mut self, id: ExprId) -> ExprId {
        self.pending.push(id);
        id
    }

    /// Replaces the last `n` completed expressions (the children of a new
    /// node) by the new node.
    fn combine(&mut self, n: usize, expr: bk_sleigh_syntax::ast::Expr) -> ExprId {
        let keep = self.pending.len().saturating_sub(n);
        self.pending.truncate(keep);
        let id = self.nodes.add_expr(expr);
        self.complete(id)
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(Fail("memory exhausted".to_owned()));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}
