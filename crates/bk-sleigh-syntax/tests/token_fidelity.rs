//! Token fidelity over the corpus: the tree loses and invents no token.
//!
//! For every semantic body (constructors and macros), pattern equation and
//! context block of every shipped specification, the tree is printed back
//! with [`Printer`], the result is lexed, and the token sequence is
//! compared with the tokens of the original source span. Integers compare
//! by value and radix (`0n12` is decimal `12`; `0x0A` is hexadecimal 10),
//! and in context blocks `$or`/`$xor`/`$and` compare equal to `|`/`^`/`&`.
//!
//! Display sections are checked separately: their pieces must tile the
//! text between `:` and `is` exactly, with nothing skipped or overlapping
//! except expansion marks.
//!
//! This shows that the tree holds every token in order. Whether it groups
//! them correctly is what `tests/precedence.rs` and `tests/reference_sla.rs`
//! check. Printer and parser share one author's reading of the grammar, so
//! this is a consistency check, not an independent oracle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use bk_sleigh_syntax::ast::print::Printer;
use bk_sleigh_syntax::ast::{
    ConstructorBody, ContextBlock, ContextStmt, DisplayPiece, Item, SemanticBody,
};
use bk_sleigh_syntax::lex::literal::{IntValue, Radix};
use bk_sleigh_syntax::lex::{Lexer, Mode, TokenKind};
use bk_sleigh_syntax::{FsLoader, Interner, Parsed, Span, parse_file};

/// A token reduced to what must survive a round trip.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Tok {
    Int(Radix, IntValue),
    Other(TokenKind, String),
}

fn tokens(text: &str, mode: Mode, context: bool) -> Vec<Tok> {
    let mut names = Interner::new();
    let mut lexer = Lexer::new(text);
    let mut out = Vec::new();
    loop {
        let token = lexer.next_token(mode, &mut names);
        let raw = text.get(token.span.range()).unwrap();
        let tok = match token.kind {
            TokenKind::Eof => return out,
            TokenKind::DecInt => Tok::Int(
                Radix::Decimal,
                IntValue::parse(raw, Radix::Decimal).unwrap(),
            ),
            TokenKind::PrefixedDecInt => Tok::Int(
                Radix::Decimal,
                IntValue::parse(raw.get(2..).unwrap(), Radix::Decimal).unwrap(),
            ),
            TokenKind::HexInt => Tok::Int(
                Radix::Hex,
                IntValue::parse(raw.get(2..).unwrap(), Radix::Hex).unwrap(),
            ),
            TokenKind::BinInt => Tok::Int(
                Radix::Binary,
                IntValue::parse(raw.get(2..).unwrap(), Radix::Binary).unwrap(),
            ),
            TokenKind::SpecOr if context => Tok::Other(TokenKind::Pipe, "|".to_owned()),
            TokenKind::SpecXor if context => Tok::Other(TokenKind::Caret, "^".to_owned()),
            TokenKind::SpecAnd if context => Tok::Other(TokenKind::Ampersand, "&".to_owned()),
            kind => Tok::Other(kind, raw.to_owned()),
        };
        out.push(tok);
    }
}

#[derive(Default)]
struct Counts {
    bodies: usize,
    equations: usize,
    contexts: usize,
    displays: usize,
    tokens: usize,
}

struct Checker<'a> {
    parsed: &'a Parsed,
    printer: Printer<'a>,
    counts: Counts,
    failures: Vec<String>,
}

impl Checker<'_> {
    fn compare(&mut self, what: &str, span: Span, printed: &str, mode: Mode, context: bool) {
        let original = self.parsed.sources.snippet(span);
        let expected = tokens(original, mode, context);
        let got = tokens(printed, mode, context);
        self.counts.tokens += expected.len();
        if expected != got && self.failures.len() < 20 {
            let loc = self.parsed.sources.locate(span.start).unwrap();
            let file = self.parsed.sources.file(loc.file).unwrap().name();
            let at = expected.iter().zip(&got).position(|(a, b)| a != b);
            self.failures.push(format!(
                "{file}:{}: {what}: first difference at token {at:?}\n  source:  {original}\n  printed: {printed}",
                loc.line
            ));
        }
    }

    fn body(&mut self, body: &SemanticBody) {
        self.counts.bodies += 1;
        let printed = format!("{{ {} }}", self.printer.body(body));
        self.compare("body", body.span, &printed, Mode::Semantic, false);
    }

    fn context(&mut self, block: &ContextBlock) {
        self.counts.contexts += 1;
        let mut printed = String::from("[ ");
        for stmt in &block.stmts {
            match stmt {
                ContextStmt::Assign { target, value, .. } => {
                    printed.push_str(self.parsed.names.resolve(target.name));
                    printed.push_str(" = ");
                    printed.push_str(&self.printer.pat_expr_string(*value, true));
                }
                ContextStmt::Apply { name, args, .. } => {
                    printed.push_str(self.parsed.names.resolve(name.name));
                    printed.push('(');
                    let args: Vec<String> = self
                        .parsed
                        .spec
                        .nodes
                        .pat_exprs(*args)
                        .iter()
                        .map(|a| self.printer.pat_expr_string(*a, true))
                        .collect();
                    printed.push_str(&args.join(", "));
                    printed.push(')');
                }
            }
            printed.push_str("; ");
        }
        printed.push(']');
        self.compare("context block", block.span, &printed, Mode::Base, true);
    }

    fn equation(&mut self, id: bk_sleigh_syntax::ast::EquationId) {
        self.counts.equations += 1;
        let span = self.parsed.spec.nodes[id].span();
        let printed = self.printer.equation_string(id);
        self.compare("pattern", span, &printed, Mode::Base, false);
    }

    /// The display pieces must cover the text from just after `:` to the
    /// `is` exactly (whitespace and `#` are pieces there, so nothing else
    /// can come between).
    fn display(&mut self, colon: Span, pieces: &[DisplayPiece]) {
        self.counts.displays += 1;
        let text = self.parsed.sources.text().as_bytes();
        let mut pos = colon.end;
        for piece in pieces {
            let span = piece.span();
            while pos < span.start && text[pos as usize] == 8 {
                pos += 1;
            }
            if span.start != pos {
                let loc = self.parsed.sources.locate(colon.start).unwrap();
                self.failures.push(format!(
                    "display at line {} has a gap or overlap before {span:?}",
                    loc.line
                ));
                return;
            }
            pos = span.end;
        }
        while text[pos as usize] == 8 {
            pos += 1;
        }
        if !text[pos as usize..].starts_with(b"is") {
            let loc = self.parsed.sources.locate(colon.start).unwrap();
            self.failures
                .push(format!("display at line {} does not reach `is`", loc.line));
        }
    }

    fn items(&mut self, items: &[Item]) {
        for item in items {
            match item {
                Item::Definition(_) => {}
                Item::Macro(m) => self.body(&m.body),
                Item::With(w) => {
                    if let Some(pattern) = w.pattern {
                        self.equation(pattern);
                    }
                    if let Some(block) = &w.context {
                        self.context(block);
                    }
                    self.items(&w.items);
                }
                Item::Constructor(c) => {
                    self.display(c.colon, &c.display);
                    self.equation(c.pattern);
                    if let Some(block) = &c.context {
                        self.context(block);
                    }
                    if let ConstructorBody::Semantic(body) = &c.body {
                        self.body(body);
                    }
                }
            }
        }
    }
}

#[test]
fn printed_trees_lex_to_the_source_tokens() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let defines = common::build_defines();
    let mut totals = Counts::default();
    let mut failures = Vec::new();
    for path in common::slaspec_files(&ghidra) {
        let parsed = parse_file(&path, &defines, &mut FsLoader);
        assert!(parsed.diagnostics.is_empty(), "{}", path.display());
        let mut checker = Checker {
            parsed: &parsed,
            printer: Printer::new(&parsed.spec.nodes, &parsed.names),
            counts: Counts::default(),
            failures: Vec::new(),
        };
        checker.items(&parsed.spec.items);
        totals.bodies += checker.counts.bodies;
        totals.equations += checker.counts.equations;
        totals.contexts += checker.counts.contexts;
        totals.displays += checker.counts.displays;
        totals.tokens += checker.counts.tokens;
        for f in checker.failures {
            failures.push(format!("{}: {f}", path.display()));
        }
    }
    eprintln!(
        "fidelity: {} bodies, {} pattern equations, {} context blocks ({} tokens) round-trip; \
         {} display sections tile their source",
        totals.bodies, totals.equations, totals.contexts, totals.tokens, totals.displays
    );
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.into_iter().take(30).collect::<Vec<_>>().join("\n")
    );
}
