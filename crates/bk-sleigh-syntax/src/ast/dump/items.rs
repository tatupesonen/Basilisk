//! Rendering of definitions, macros, `with` blocks and constructors.

use std::fmt::Write as _;

use super::{Dumper, endian_name, indent, int};
use crate::ast::{
    Constructor, ConstructorBody, ContextBlock, ContextStmt, Definition, DisplayPiece, FieldDef,
    FieldDisplay, IdentOrWild, IntOrWild, MacroDef, NameOrWild, SemanticBody, SpaceMod, WithBlock,
};

impl Dumper<'_> {
    pub(super) fn definition(&self, out: &mut String, def: &Definition, level: usize) {
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

    pub(super) fn fields(&self, out: &mut String, fields: &[FieldDef], level: usize) {
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

    pub(super) fn ident_list(&self, out: &mut String, list: &[IdentOrWild]) {
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

    pub(super) fn macro_def(&self, out: &mut String, def: &MacroDef, level: usize) {
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

    pub(super) fn with_block(&self, out: &mut String, block: &WithBlock, level: usize) {
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

    pub(super) fn constructor(&self, out: &mut String, ctor: &Constructor, level: usize) {
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

    pub(super) fn display(&self, out: &mut String, pieces: &[DisplayPiece]) {
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

    pub(super) fn context(&self, out: &mut String, block: &ContextBlock) {
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

    pub(super) fn statements(&self, out: &mut String, body: &SemanticBody, level: usize) {
        for statement in &body.statements {
            out.push('\n');
            indent(out, level);
            self.statement(out, statement);
        }
    }
}
