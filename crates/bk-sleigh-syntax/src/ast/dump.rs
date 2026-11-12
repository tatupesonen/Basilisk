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

use std::fmt::Write as _;

use super::{
    BinaryOp, ConstraintOp, Constructor, ConstructorBody, ContextBlock, ContextStmt, Definition,
    DisplayPiece, Endian, Equation, EquationId, EquationOp, ExportValue, Expr, ExprId, FieldDef,
    FieldDisplay, Ident, IdentOrWild, IntLit, IntOrWild, Item, JumpDest, LValue, MacroDef,
    NameOrWild, Nodes, PatBinaryOp, PatExpr, PatExprId, PatUnaryOp, SemanticBody, SizedStar,
    SpaceMod, Spec, Statement, UnaryOp, WithBlock,
};
use crate::intern::{Interner, Symbol};
use crate::lex::literal::Radix;
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

    fn definition(&self, out: &mut String, def: &Definition, level: usize) {
        match def {
            Definition::Alignment(d) => {
                out.push_str("(alignment ");
                int(out, &d.value);
            }
            Definition::Token(d) => {
                let _ = write!(out, "(token {} ", self.name(d.name.name));
                int(out, &d.size);
                if let Some(endian) = d.endian {
                    let _ = write!(out, " (endian {})", endian_name(endian));
                }
                self.location(out, d.span);
                self.fields(out, &d.fields, level + 1);
            }
            Definition::Context(d) => {
                let _ = write!(out, "(context {}", self.name(d.varnode.name));
                self.location(out, d.span);
                self.fields(out, &d.fields, level + 1);
            }
            Definition::Space(d) => {
                let _ = write!(out, "(space {}", self.name(d.name.name));
                for m in &d.mods {
                    match m {
                        SpaceMod::Type(kind) => {
                            let _ = write!(out, " (type {})", self.name(kind.name));
                        }
                        SpaceMod::Size(size) => {
                            out.push_str(" (size ");
                            int(out, size);
                            out.push(')');
                        }
                        SpaceMod::WordSize(size) => {
                            out.push_str(" (wordsize ");
                            int(out, size);
                            out.push(')');
                        }
                        SpaceMod::Default(_) => out.push_str(" default"),
                    }
                }
            }
            Definition::Varnode(d) => {
                let _ = write!(out, "(varnode {} (offset ", self.name(d.space.name));
                int(out, &d.offset);
                out.push_str(") (size ");
                int(out, &d.size);
                out.push_str(") ");
                self.ident_list(out, &d.names);
            }
            Definition::Bitrange(d) => {
                out.push_str("(bitrange");
                for entry in &d.entries {
                    let _ = write!(
                        out,
                        " ({} {}[",
                        self.name(entry.name.name),
                        self.name(entry.varnode.name)
                    );
                    int(out, &entry.low);
                    out.push(',');
                    int(out, &entry.width);
                    out.push_str("])");
                }
            }
            Definition::PcodeOp(d) => {
                out.push_str("(pcodeop ");
                self.ident_list(out, &d.names);
            }
            Definition::AttachValues(d) => {
                out.push_str("(attach-values ");
                self.ident_list(out, &d.fields);
                out.push_str(" [");
                for (i, value) in d.values.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    match value {
                        IntOrWild::Int { negative, value } => {
                            if *negative {
                                out.push('-');
                            }
                            int(out, value);
                        }
                        IntOrWild::Wildcard(_) => out.push('_'),
                    }
                }
                out.push(']');
            }
            Definition::AttachNames(d) => {
                out.push_str("(attach-names ");
                self.ident_list(out, &d.fields);
                out.push_str(" [");
                for (i, name) in d.names.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    match name {
                        NameOrWild::Ident(ident) => self.ident(out, *ident),
                        NameOrWild::Str(s) => {
                            let _ = write!(out, "{:?}", self.name(s.value));
                        }
                        NameOrWild::Wildcard(_) => out.push('_'),
                    }
                }
                out.push(']');
            }
            Definition::AttachVariables(d) => {
                out.push_str("(attach-variables ");
                self.ident_list(out, &d.fields);
                out.push(' ');
                self.ident_list(out, &d.varnodes);
            }
        }
        if !matches!(def, Definition::Token(_) | Definition::Context(_)) {
            self.location(out, def.span());
        }
        out.push(')');
    }

    fn fields(&self, out: &mut String, fields: &[FieldDef], level: usize) {
        for field in fields {
            out.push('\n');
            indent(out, level);
            let _ = write!(out, "(field {} (", self.name(field.name.name));
            int(out, &field.low);
            out.push(' ');
            int(out, &field.high);
            out.push(')');
            if field.signed {
                out.push_str(" signed");
            }
            if field.noflow {
                out.push_str(" noflow");
            }
            match field.display {
                Some(FieldDisplay::Hex) => out.push_str(" hex"),
                Some(FieldDisplay::Dec) => out.push_str(" dec"),
                None => {}
            }
            out.push(')');
        }
    }

    fn ident_list(&self, out: &mut String, list: &[IdentOrWild]) {
        out.push('[');
        for (i, entry) in list.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            match entry {
                IdentOrWild::Ident(ident) => self.ident(out, *ident),
                IdentOrWild::Wildcard(_) => out.push('_'),
            }
        }
        out.push(']');
    }

    fn macro_def(&self, out: &mut String, def: &MacroDef, level: usize) {
        let _ = write!(out, "(macro {} [", self.name(def.name.name));
        for (i, param) in def.params.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            self.ident(out, *param);
        }
        out.push(']');
        self.location(out, def.span);
        self.statements(out, &def.body, level + 1);
        out.push(')');
    }

    fn with_block(&self, out: &mut String, block: &WithBlock, level: usize) {
        out.push_str("(with");
        if let Some(table) = block.table {
            let _ = write!(out, " {}", self.name(table.name));
        }
        self.location(out, block.span);
        if let Some(pattern) = block.pattern {
            out.push('\n');
            indent(out, level + 1);
            out.push_str("(pattern ");
            self.equation(out, pattern);
            out.push(')');
        }
        if let Some(context) = &block.context {
            out.push('\n');
            indent(out, level + 1);
            self.context(out, context);
        }
        out.push('\n');
        self.items(out, &block.items, level + 1);
        indent(out, level);
        out.push(')');
    }

    fn constructor(&self, out: &mut String, ctor: &Constructor, level: usize) {
        out.push_str("(constructor");
        if let Some(table) = ctor.table {
            let _ = write!(out, " {}", self.name(table.name));
        }
        self.location(out, ctor.span);
        out.push('\n');
        indent(out, level + 1);
        self.display(out, &ctor.display);
        out.push('\n');
        indent(out, level + 1);
        out.push_str("(pattern ");
        self.equation(out, ctor.pattern);
        out.push(')');
        if let Some(context) = &ctor.context {
            out.push('\n');
            indent(out, level + 1);
            self.context(out, context);
        }
        out.push('\n');
        indent(out, level + 1);
        match &ctor.body {
            ConstructorBody::Unimpl(_) => out.push_str("unimpl"),
            ConstructorBody::Semantic(body) => {
                out.push_str("(body");
                self.statements(out, body, level + 2);
                out.push(')');
            }
        }
        out.push(')');
    }

    fn display(&self, out: &mut String, pieces: &[DisplayPiece]) {
        out.push_str("(display");
        for piece in pieces {
            out.push(' ');
            match piece {
                DisplayPiece::Ident(ident) => self.ident(out, *ident),
                DisplayPiece::Whitespace(_) => out.push_str("ws"),
                DisplayPiece::Concat(_) => out.push('^'),
                DisplayPiece::Literal { text, .. } => {
                    let _ = write!(out, "{:?}", self.name(*text));
                }
                DisplayPiece::Quoted(s) => {
                    let _ = write!(out, "q{:?}", self.name(s.value));
                }
            }
        }
        out.push(')');
    }

    fn context(&self, out: &mut String, block: &ContextBlock) {
        out.push_str("(context");
        for stmt in &block.stmts {
            out.push(' ');
            match stmt {
                ContextStmt::Assign { target, value, .. } => {
                    let _ = write!(out, "(= {} ", self.name(target.name));
                    self.pat_expr(out, *value);
                    out.push(')');
                }
                ContextStmt::Apply { name, args, .. } => {
                    let _ = write!(out, "(apply {}", self.name(name.name));
                    for arg in self.nodes.pat_exprs(*args) {
                        out.push(' ');
                        self.pat_expr(out, *arg);
                    }
                    out.push(')');
                }
            }
        }
        out.push(')');
    }

    fn statements(&self, out: &mut String, body: &SemanticBody, level: usize) {
        for statement in &body.statements {
            out.push('\n');
            indent(out, level);
            self.statement(out, statement);
        }
    }

    fn equation(&self, out: &mut String, id: EquationId) {
        match &self.nodes[id] {
            Equation::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(match op {
                    EquationOp::Or => "|",
                    EquationOp::Seq => ";",
                    EquationOp::And => "&",
                });
                out.push(' ');
                self.equation(out, *lhs);
                out.push(' ');
                self.equation(out, *rhs);
                out.push(')');
            }
            Equation::EllipsisLeft { inner, .. } => {
                out.push_str("(ellipsis-left ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::EllipsisRight { inner, .. } => {
                out.push_str("(ellipsis-right ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.equation(out, *inner);
                out.push(')');
            }
            Equation::Constraint {
                name, op, value, ..
            } => {
                out.push('(');
                out.push_str(constraint_op_str(*op));
                let _ = write!(out, " {} ", self.name(name.name));
                self.pat_expr(out, *value);
                out.push(')');
            }
            Equation::Symbol(ident) => self.ident(out, *ident),
            Equation::Error(_) => out.push_str("(error)"),
        }
    }

    fn pat_expr(&self, out: &mut String, id: PatExprId) {
        match &self.nodes[id] {
            PatExpr::Int(lit) => int(out, lit),
            PatExpr::Ident(ident) => self.ident(out, *ident),
            PatExpr::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.pat_expr(out, *inner);
                out.push(')');
            }
            PatExpr::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.pat_exprs(*args) {
                    out.push(' ');
                    self.pat_expr(out, *arg);
                }
                out.push(')');
            }
            PatExpr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    PatUnaryOp::Negate => "(neg ",
                    PatUnaryOp::Invert => "(inv ",
                });
                self.pat_expr(out, *operand);
                out.push(')');
            }
            PatExpr::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(pat_binary_op_str(*op));
                out.push(' ');
                self.pat_expr(out, *lhs);
                out.push(' ');
                self.pat_expr(out, *rhs);
                out.push(')');
            }
            PatExpr::Error(_) => out.push_str("(error)"),
        }
    }

    fn star(&self, out: &mut String, star: &SizedStar) {
        out.push_str("deref");
        if let Some(space) = star.space {
            let _ = write!(out, "[{}]", self.name(space.name));
        }
        if let Some(size) = &star.size {
            out.push(':');
            int(out, size);
        }
    }

    fn expr(&self, out: &mut String, id: ExprId) {
        match &self.nodes[id] {
            Expr::Int(lit) => int(out, lit),
            Expr::Ident(ident) => self.ident(out, *ident),
            Expr::SizedInt { value, size } => {
                int(out, value);
                out.push(':');
                int(out, size);
            }
            Expr::Truncate { name, size } => {
                self.ident(out, *name);
                out.push(':');
                int(out, size);
            }
            Expr::BitRange {
                name, low, width, ..
            } => {
                self.ident(out, *name);
                out.push('[');
                int(out, low);
                out.push(',');
                int(out, width);
                out.push(']');
            }
            Expr::AddressOf { size, operand, .. } => {
                out.push_str("(addr");
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(' ');
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Paren { inner, .. } => {
                out.push_str("(paren ");
                self.expr(out, *inner);
                out.push(')');
            }
            Expr::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.exprs(*args) {
                    out.push(' ');
                    self.expr(out, *arg);
                }
                out.push(')');
            }
            Expr::Unary { op, operand, .. } => {
                out.push_str(match op {
                    UnaryOp::Not => "(not ",
                    UnaryOp::Invert => "(inv ",
                    UnaryOp::Negate => "(neg ",
                    UnaryOp::FNegate => "(fneg ",
                });
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Deref { star, operand, .. } => {
                out.push('(');
                self.star(out, star);
                out.push(' ');
                self.expr(out, *operand);
                out.push(')');
            }
            Expr::Binary { op, lhs, rhs, .. } => {
                out.push('(');
                out.push_str(BinaryOp::as_str(*op));
                out.push(' ');
                self.expr(out, *lhs);
                out.push(' ');
                self.expr(out, *rhs);
                out.push(')');
            }
            Expr::Error(_) => out.push_str("(error)"),
        }
    }

    fn jump_dest(&self, out: &mut String, dest: &JumpDest) {
        match dest {
            JumpDest::Symbol(ident) => self.ident(out, *ident),
            JumpDest::Dynamic(target) => {
                out.push_str("(dynamic ");
                self.expr(out, *target);
                out.push(')');
            }
            JumpDest::Absolute(address) => int(out, address),
            JumpDest::Relative { offset, space } => {
                out.push_str("(in-space ");
                int(out, offset);
                let _ = write!(out, " {})", self.name(space.name));
            }
            JumpDest::Label(name) => {
                let _ = write!(out, "<{}>", self.name(name.name));
            }
        }
    }

    fn lvalue(&self, out: &mut String, target: &LValue) {
        match target {
            LValue::Ident(ident) => self.ident(out, *ident),
            LValue::Sized { name, size } => {
                self.ident(out, *name);
                out.push(':');
                int(out, size);
            }
            LValue::BitRange { name, low, width } => {
                self.ident(out, *name);
                out.push('[');
                int(out, low);
                out.push(',');
                int(out, width);
                out.push(']');
            }
            LValue::Deref { star, address } => {
                out.push('(');
                self.star(out, star);
                out.push(' ');
                self.expr(out, *address);
                out.push(')');
            }
        }
    }

    fn statement(&self, out: &mut String, statement: &Statement) {
        match statement {
            Statement::Assign {
                local,
                target,
                value,
                ..
            } => {
                out.push_str(if *local { "(local= " } else { "(= " });
                self.lvalue(out, target);
                out.push(' ');
                self.expr(out, *value);
                out.push(')');
            }
            Statement::Declare { name, size, .. } => {
                let _ = write!(out, "(local {}", self.name(name.name));
                if let Some(size) = size {
                    out.push(':');
                    int(out, size);
                }
                out.push(')');
            }
            Statement::Apply { name, args, .. } => {
                let _ = write!(out, "(apply {}", self.name(name.name));
                for arg in self.nodes.exprs(*args) {
                    out.push(' ');
                    self.expr(out, *arg);
                }
                out.push(')');
            }
            Statement::Build { operand, .. } => {
                let _ = write!(out, "(build {})", self.name(operand.name));
            }
            Statement::CrossBuild {
                address, section, ..
            } => {
                out.push_str("(crossbuild ");
                self.expr(out, *address);
                let _ = write!(out, " {})", self.name(section.name));
            }
            Statement::Goto { dest, .. } => {
                out.push_str("(goto ");
                self.jump_dest(out, dest);
                out.push(')');
            }
            Statement::If {
                condition, dest, ..
            } => {
                out.push_str("(if ");
                self.expr(out, *condition);
                out.push_str(" (goto ");
                self.jump_dest(out, dest);
                out.push_str("))");
            }
            Statement::Call { dest, .. } => {
                out.push_str("(call ");
                self.jump_dest(out, dest);
                out.push(')');
            }
            Statement::Return { target, .. } => {
                out.push_str("(return ");
                self.expr(out, *target);
                out.push(')');
            }
            Statement::Export { value, .. } => {
                out.push_str("(export ");
                match value {
                    ExportValue::Varnode(varnode) => self.expr(out, *varnode),
                    ExportValue::Deref { star, name } => {
                        out.push('(');
                        self.star(out, star);
                        let _ = write!(out, " {})", self.name(name.name));
                    }
                }
                out.push(')');
            }
            Statement::Label { name, .. } => {
                let _ = write!(out, "(label {})", self.name(name.name));
            }
            Statement::Section { name, .. } => {
                let _ = write!(out, "(section {})", self.name(name.name));
            }
            Statement::Error(_) => out.push_str("(error)"),
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
    out.push_str(match lit.radix {
        Radix::Hex => "0x",
        Radix::Binary => "0b",
        Radix::Decimal => "",
    });
    out.push_str(&lit.value.to_string_radix(lit.radix));
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
