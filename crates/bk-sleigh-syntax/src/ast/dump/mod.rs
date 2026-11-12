//! A readable, stable text rendering of the syntax tree.
//!
//! Used for golden snapshots and in tests that check tree structure. The
//! format is S-expressions: every operator application is parenthesised, so
//! precedence and associativity are visible. `(paren x)` marks parentheses
//! that were written in the source.
//!
//! | Source | Rendering |
//! |---|---|
//! | `a + b * 2` | `(+ a (* b 2))` |
//! | `-x`, `~x`, `!x`, `f- x` | `(neg x)`, `(inv x)`, `(not x)`, `(fneg x)` |
//! | `*[ram]:4 p`, `&:4 r` | `(deref[ram]:4 p)`, `(addr:4 r)` |
//! | `zext(x)`, `r:2`, `1:4`, `r[0,8]` | `(apply zext x)`, `r:2`, `1:4`, `r[0,8]` |
//! | `a=1 & b; c ...` | `(; (& (= a 1) b) (ellipsis-right c))` |

mod items;
mod pattern;
mod semantic;

use std::fmt::Write as _;

use super::{
    ConstraintOp, ContextBlock, DisplayPiece, Endian, EquationId, ExprId, Ident, IntLit, Item,
    Nodes, PatBinaryOp, PatExprId, SemanticBody, Spec, Statement,
};
use crate::intern::{Interner, Symbol};
use crate::source::SourceMap;
use crate::span::Span;

/// Renders trees as text. Create one per parse and call the `*_string`
/// methods, or use the free functions for one-off renderings.
#[derive(Clone, Copy, Debug)]
pub struct Dumper<'a> {
    nodes: &'a Nodes,
    names: &'a Interner,
    sources: Option<&'a SourceMap>,
}

/// Renders a whole specification. With `sources`, each item is annotated
/// with the file, line and column it starts at (`@file:line:column`).
pub fn spec(spec: &Spec, names: &Interner, sources: Option<&SourceMap>) -> String {
    Dumper {
        nodes: &spec.nodes,
        names,
        sources,
    }
    .spec_string(spec)
}

/// Renders the statements of a semantic body, one per line.
pub fn body(body: &SemanticBody, nodes: &Nodes, names: &Interner) -> String {
    let dumper = Dumper::new(nodes, names);
    let mut out = String::new();
    for statement in &body.statements {
        dumper.statement(&mut out, statement);
        out.push('\n');
    }
    out
}

impl<'a> Dumper<'a> {
    /// A dumper for trees whose nodes live in `nodes` and whose names live
    /// in `names`.
    pub fn new(nodes: &'a Nodes, names: &'a Interner) -> Self {
        Self {
            nodes,
            names,
            sources: None,
        }
    }

    /// Annotates items with their source location.
    #[must_use]
    pub fn with_sources(mut self, sources: &'a SourceMap) -> Self {
        self.sources = Some(sources);
        self
    }

    /// Renders a semantic expression.
    pub fn expr_string(&self, id: ExprId) -> String {
        let mut out = String::new();
        self.expr(&mut out, id);
        out
    }

    /// Renders a pattern equation.
    pub fn equation_string(&self, id: EquationId) -> String {
        let mut out = String::new();
        self.equation(&mut out, id);
        out
    }

    /// Renders a pattern expression.
    pub fn pat_expr_string(&self, id: PatExprId) -> String {
        let mut out = String::new();
        self.pat_expr(&mut out, id);
        out
    }

    /// Renders one statement.
    pub fn statement_string(&self, statement: &Statement) -> String {
        let mut out = String::new();
        self.statement(&mut out, statement);
        out
    }

    /// Renders a display section on one line.
    pub fn display_string(&self, pieces: &[DisplayPiece]) -> String {
        let mut out = String::new();
        self.display(&mut out, pieces);
        out
    }

    /// Renders a context block on one line.
    pub fn context_string(&self, block: &ContextBlock) -> String {
        let mut out = String::new();
        self.context(&mut out, block);
        out
    }

    /// Renders a whole specification.
    pub fn spec_string(&self, spec: &Spec) -> String {
        let mut out = String::from("(spec\n");
        match &spec.endian {
            Some(def) => {
                let _ = write!(out, "  (endian {})", endian_name(def.endian));
                self.location(&mut out, def.span);
                out.push('\n');
            }
            None => out.push_str("  (endian missing)\n"),
        }
        self.items(&mut out, &spec.items, 1);
        out.push_str(")\n");
        out
    }

    fn name(&self, symbol: Symbol) -> &'a str {
        self.names.resolve(symbol)
    }

    fn ident(&self, out: &mut String, ident: Ident) {
        out.push_str(self.name(ident.name));
    }

    fn location(&self, out: &mut String, span: Span) {
        let Some(sources) = self.sources else { return };
        if let Some(loc) = sources.locate(span.start) {
            let file = sources.file(loc.file).map_or("?", |f| f.name());
            let _ = write!(out, " @{file}:{}:{}", loc.line, loc.column);
        }
    }

    fn items(&self, out: &mut String, items: &[Item], level: usize) {
        for item in items {
            indent(out, level);
            match item {
                Item::Definition(def) => self.definition(out, def, level),
                Item::Macro(def) => self.macro_def(out, def, level),
                Item::With(block) => self.with_block(out, block, level),
                Item::Constructor(ctor) => self.constructor(out, ctor, level),
            }
            out.push('\n');
        }
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn endian_name(endian: Endian) -> &'static str {
    match endian {
        Endian::Big => "big",
        Endian::Little => "little",
    }
}

/// Writes an integer literal in the radix it was written in.
fn int(out: &mut String, lit: &IntLit) {
    out.push_str(&lit.to_source());
}

const fn constraint_op_str(op: ConstraintOp) -> &'static str {
    match op {
        ConstraintOp::Equal => "=",
        ConstraintOp::NotEqual => "!=",
        ConstraintOp::Less => "<",
        ConstraintOp::LessEqual => "<=",
        ConstraintOp::Great => ">",
        ConstraintOp::GreatEqual => ">=",
    }
}

const fn pat_binary_op_str(op: PatBinaryOp) -> &'static str {
    match op {
        PatBinaryOp::Or => "$or",
        PatBinaryOp::Xor => "$xor",
        PatBinaryOp::And => "$and",
        PatBinaryOp::Left => "<<",
        PatBinaryOp::Right => ">>",
        PatBinaryOp::Add => "+",
        PatBinaryOp::Sub => "-",
        PatBinaryOp::Mult => "*",
        PatBinaryOp::Div => "/",
    }
}
