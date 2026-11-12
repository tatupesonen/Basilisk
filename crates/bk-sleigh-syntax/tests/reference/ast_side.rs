//! The model, built from this crate's syntax tree with the rules Ghidra's
//! compiler applies to it (`slgh_compile.cc`, `slghsymbol.cc`): print
//! pieces through `Constructor::addSyntax`, varnode offsets through
//! `defineVarnodes` and `defineBitrange`, `with` prefixes through
//! `WithBlock`.

use std::collections::{BTreeMap, BTreeSet};

use bk_sleigh_syntax::Parsed;
use bk_sleigh_syntax::ast::{
    ConstructorBody, ContextBlock, ContextStmt, Definition, DisplayPiece, Endian, Equation,
    EquationId, IdentOrWild, IntOrWild, Item, NameOrWild, PatBinaryOp, PatExpr, PatExprId,
    PatUnaryOp, SpaceMod, Statement, WithBlock,
};

use super::{Attached, Ctor, Model, Piece, binary_shape};

/// The shape of a pattern expression, in the vocabulary of `super`.
fn shape(parsed: &Parsed, id: PatExprId) -> String {
    let nodes = &parsed.spec.nodes;
    match &nodes[id] {
        PatExpr::Int(lit) => (lit.to_u64().unwrap() as i64).to_string(),
        PatExpr::Ident(_) => "leaf".to_owned(),
        PatExpr::Paren { inner, .. } => shape(parsed, *inner),
        PatExpr::Apply { .. } => "apply".to_owned(),
        PatExpr::Unary { op, operand, .. } => {
            let name = match op {
                PatUnaryOp::Negate => "neg",
                PatUnaryOp::Invert => "inv",
            };
            format!("({name} {})", shape(parsed, *operand))
        }
        PatExpr::Binary { op, lhs, rhs, .. } => {
            let op = match op {
                PatBinaryOp::Or => "$or",
                PatBinaryOp::Xor => "$xor",
                PatBinaryOp::And => "$and",
                PatBinaryOp::Left => "<<",
                PatBinaryOp::Right => ">>",
                PatBinaryOp::Add => "+",
                PatBinaryOp::Sub => "-",
                PatBinaryOp::Mult => "*",
                PatBinaryOp::Div => "/",
            };
            binary_shape(op, &shape(parsed, *lhs), &shape(parsed, *rhs))
        }
        PatExpr::Error(_) => "error".to_owned(),
    }
}

/// Collects `name = expression` constraints of an equation.
fn constraints(parsed: &Parsed, id: EquationId, out: &mut BTreeMap<String, Vec<String>>) {
    match &parsed.spec.nodes[id] {
        Equation::Binary { lhs, rhs, .. } => {
            constraints(parsed, *lhs, out);
            constraints(parsed, *rhs, out);
        }
        Equation::EllipsisLeft { inner, .. }
        | Equation::EllipsisRight { inner, .. }
        | Equation::Paren { inner, .. } => constraints(parsed, *inner, out),
        Equation::Constraint {
            name,
            op: bk_sleigh_syntax::ast::ConstraintOp::Equal,
            value,
            ..
        } => out
            .entry(parsed.names.resolve(name.name).to_owned())
            .or_default()
            .push(shape(parsed, *value)),
        Equation::Constraint { .. } | Equation::Symbol(_) | Equation::Error(_) => {}
    }
}

/// Collects every name an equation mentions.
fn equation_names(parsed: &Parsed, id: EquationId, out: &mut BTreeSet<String>) {
    match &parsed.spec.nodes[id] {
        Equation::Binary { lhs, rhs, .. } => {
            equation_names(parsed, *lhs, out);
            equation_names(parsed, *rhs, out);
        }
        Equation::EllipsisLeft { inner, .. }
        | Equation::EllipsisRight { inner, .. }
        | Equation::Paren { inner, .. } => equation_names(parsed, *inner, out),
        Equation::Constraint { name, .. } | Equation::Symbol(name) => {
            out.insert(parsed.names.resolve(name.name).to_owned());
        }
        Equation::Error(_) => {}
    }
}

/// Ghidra's `Constructor::addSyntax`: adjacent text joins, runs of
/// whitespace become one `" "`, and an all-space string counts as one.
fn add_syntax(pieces: &mut Vec<Piece>, text: &str) {
    if text.is_empty() {
        return;
    }
    let text = if text.chars().all(|c| c == ' ') {
        " "
    } else {
        text
    };
    match pieces.last_mut() {
        Some(Piece::Text(last)) if last == " " && text == " " => {}
        Some(Piece::Text(last)) if last != " " && text != " " => last.push_str(text),
        _ => pieces.push(Piece::Text(text.to_owned())),
    }
}

struct Walker<'a> {
    parsed: &'a Parsed,
    model: Model,
    context_fields: BTreeSet<String>,
    macros: BTreeSet<String>,
    /// Enclosing `with` blocks, outermost first.
    with_stack: Vec<&'a WithBlock>,
    /// The names each table's patterns and displays mention.
    mentions: BTreeMap<String, BTreeSet<String>>,
}

impl<'a> Walker<'a> {
    fn name(&self, ident: bk_sleigh_syntax::ast::Ident) -> String {
        self.parsed.names.resolve(ident.name).to_owned()
    }

    fn context(&self, block: &ContextBlock, ctor: &mut Ctor) {
        for stmt in &block.stmts {
            match stmt {
                ContextStmt::Assign { target, value, .. } => {
                    let target = self.name(*target);
                    let shape = shape(self.parsed, *value);
                    if self.context_fields.contains(&target) {
                        ctor.context_ops.push(shape);
                    } else {
                        ctor.operand_defs.entry(target).or_default().push(shape);
                    }
                }
                ContextStmt::Apply { name, .. } => {
                    if self.parsed.names.resolve(name.name) == "globalset" {
                        ctor.commits += 1;
                    }
                }
            }
        }
    }

    fn constructor(&mut self, c: &bk_sleigh_syntax::ast::Constructor) {
        let table = c
            .table
            .or_else(|| self.with_stack.iter().rev().find_map(|w| w.table))
            .map_or_else(|| "instruction".to_owned(), |t| self.name(t));
        let loc = self.parsed.sources.locate(c.colon.start).unwrap();
        let mut ctor = Ctor {
            file: self
                .parsed
                .sources
                .file(loc.file)
                .unwrap()
                .name()
                .to_owned(),
            line: loc.line,
            ..Ctor::default()
        };

        let mentions = self.mentions.entry(table.clone()).or_default();
        equation_names(self.parsed, c.pattern, mentions);
        for with in &self.with_stack {
            if let Some(pattern) = with.pattern {
                equation_names(self.parsed, pattern, mentions);
            }
        }
        for piece in &c.display {
            if let DisplayPiece::Ident(ident) = piece {
                mentions.insert(self.parsed.names.resolve(ident.name).to_owned());
            }
        }

        let in_root = table == "instruction";
        let mut first = true;
        for piece in &c.display {
            if first && matches!(piece, DisplayPiece::Whitespace(_)) {
                continue;
            }
            match piece {
                DisplayPiece::Ident(ident) if first && in_root => {
                    add_syntax(&mut ctor.display, &self.name(*ident));
                }
                DisplayPiece::Ident(ident) => ctor.display.push(Piece::Operand(self.name(*ident))),
                DisplayPiece::Whitespace(_) => add_syntax(&mut ctor.display, " "),
                DisplayPiece::Concat(_) => {}
                DisplayPiece::Literal { text, .. } => {
                    add_syntax(&mut ctor.display, self.parsed.names.resolve(*text));
                }
                DisplayPiece::Quoted(s) => {
                    add_syntax(&mut ctor.display, self.parsed.names.resolve(s.value));
                }
            }
            first = false;
        }
        if ctor.display.last() == Some(&Piece::Text(" ".to_owned())) {
            ctor.display.pop();
        }

        for with in self.with_stack.clone() {
            if let Some(block) = &with.context {
                self.context(block, &mut ctor);
            }
            if let Some(pattern) = with.pattern {
                constraints(self.parsed, pattern, &mut ctor.operand_defs);
            }
        }
        if let Some(block) = &c.context {
            self.context(block, &mut ctor);
        }
        constraints(self.parsed, c.pattern, &mut ctor.operand_defs);

        match &c.body {
            ConstructorBody::Unimpl(_) => ctor.unimpl = true,
            ConstructorBody::Semantic(body) => {
                for (section, statements) in body.sections() {
                    if section.is_some() {
                        ctor.named_sections += 1;
                        continue;
                    }
                    for statement in statements {
                        match statement {
                            Statement::Export { .. } => ctor.export = true,
                            Statement::Label { .. } => ctor.labels += 1,
                            Statement::Apply { name, .. }
                                if self.macros.contains(self.parsed.names.resolve(name.name)) =>
                            {
                                ctor.calls_macro = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        self.model.tables.entry(table).or_default().push(ctor);
    }

    fn items(&mut self, items: &'a [Item]) {
        for item in items {
            match item {
                Item::Constructor(c) => self.constructor(c),
                Item::With(w) => {
                    self.with_stack.push(w);
                    self.items(&w.items);
                    self.with_stack.pop();
                }
                Item::Definition(_) | Item::Macro(_) => {}
            }
        }
    }
}

/// Every item of the tree, `with` blocks flattened.
fn all_items<'a>(items: &'a [Item], out: &mut Vec<&'a Item>) {
    for item in items {
        out.push(item);
        if let Item::With(w) = item {
            all_items(&w.items, out);
        }
    }
}

fn int(lit: &bk_sleigh_syntax::ast::IntLit) -> u64 {
    lit.to_u64().unwrap()
}

/// Builds the model from a parse.
pub(crate) fn model(parsed: &Parsed) -> Model {
    let mut items = Vec::new();
    all_items(&parsed.spec.items, &mut items);
    let name = |i: bk_sleigh_syntax::ast::Ident| parsed.names.resolve(i.name).to_owned();
    let names = |list: &[IdentOrWild]| -> Vec<Option<String>> {
        list.iter()
            .map(|e| match e {
                IdentOrWild::Ident(i) => Some(name(*i)),
                IdentOrWild::Wildcard(_) => None,
            })
            .collect()
    };
    let big_endian = parsed.spec.endian.is_some_and(|e| e.endian == Endian::Big);

    let mut model = Model::default();
    let mut context_fields = BTreeSet::new();
    let mut macros = BTreeSet::new();
    let mut bitranges = Vec::new();
    for item in &items {
        match item {
            Item::Macro(m) => {
                macros.insert(name(m.name));
            }
            Item::Definition(def) => match def {
                Definition::Space(d) => {
                    let mut size = 0;
                    let mut wordsize = 1;
                    for m in &d.mods {
                        match m {
                            SpaceMod::Size(s) => size = int(s),
                            SpaceMod::WordSize(s) => wordsize = int(s),
                            SpaceMod::Default(_) => model.default_space = Some(name(d.name)),
                            SpaceMod::Type(_) => {}
                        }
                    }
                    model.spaces.insert(name(d.name), (size, wordsize));
                }
                Definition::Varnode(d) => {
                    let size = int(&d.size);
                    for (i, entry) in d.names.iter().enumerate() {
                        if let IdentOrWild::Ident(n) = entry {
                            model.varnodes.insert(
                                name(*n),
                                (name(d.space), int(&d.offset) + i as u64 * size, size),
                            );
                        }
                    }
                }
                Definition::Bitrange(d) => bitranges.extend(d.entries.iter()),
                Definition::Token(d) => {
                    for f in &d.fields {
                        model
                            .token_fields
                            .insert(name(f.name), (int(&f.low), int(&f.high), f.signed));
                    }
                }
                Definition::Context(d) => {
                    for f in &d.fields {
                        context_fields.insert(name(f.name));
                        model
                            .context_fields
                            .insert(name(f.name), (int(&f.low), int(&f.high), !f.noflow));
                    }
                }
                Definition::PcodeOp(d) => {
                    model.userops.extend(names(&d.names).into_iter().flatten());
                }
                Definition::AttachVariables(d) => {
                    for field in names(&d.fields).into_iter().flatten() {
                        model
                            .attached
                            .insert(field, Attached::Variables(names(&d.varnodes)));
                    }
                }
                Definition::AttachNames(d) => {
                    let list: Vec<Option<String>> = d
                        .names
                        .iter()
                        .map(|n| match n {
                            NameOrWild::Ident(i) => Some(name(*i)),
                            NameOrWild::Str(s) => Some(parsed.names.resolve(s.value).to_owned()),
                            NameOrWild::Wildcard(_) => None,
                        })
                        .collect();
                    for field in names(&d.fields).into_iter().flatten() {
                        model.attached.insert(field, Attached::Names(list.clone()));
                    }
                }
                Definition::AttachValues(d) => {
                    let list: Vec<Option<i64>> = d
                        .values
                        .iter()
                        .map(|v| match v {
                            IntOrWild::Int { negative, value } => {
                                let v = int(value) as i64;
                                Some(if *negative { v.wrapping_neg() } else { v })
                            }
                            IntOrWild::Wildcard(_) => None,
                        })
                        .collect();
                    for field in names(&d.fields).into_iter().flatten() {
                        model.attached.insert(field, Attached::Values(list.clone()));
                    }
                }
                Definition::Alignment(_) => {}
            },
            Item::With(_) | Item::Constructor(_) => {}
        }
    }
    // Byte-aligned bit ranges are plain varnodes (`defineBitrange`).
    for entry in bitranges {
        let (low, width) = (int(&entry.low), int(&entry.width));
        if low % 8 != 0 || width % 8 != 0 {
            continue;
        }
        let Some((space, offset, size)) = model.varnodes.get(&name(entry.varnode)).cloned() else {
            continue;
        };
        let delta = if big_endian {
            (size * 8 - low - width) / 8
        } else {
            low / 8
        };
        model
            .varnodes
            .insert(name(entry.name), (space, offset + delta, width / 8));
    }
    // A context field with attached meaning is stored as that, not as a
    // plain context symbol.
    for field in model.attached.keys() {
        model.context_fields.remove(field);
    }

    let mut walker = Walker {
        parsed,
        model,
        context_fields,
        macros,
        with_stack: Vec::new(),
        mentions: BTreeMap::new(),
    };
    walker.items(&parsed.spec.items);

    // Ghidra builds patterns, and writes tables, only for the tables the
    // root table reaches (`SleighCompile::buildPatterns`; the others draw
    // an "Unreferenced table" warning and are left out of the `.sla`).
    let mut reached = BTreeSet::from(["instruction".to_owned()]);
    let mut work = vec!["instruction".to_owned()];
    while let Some(table) = work.pop() {
        for name in walker.mentions.get(&table).into_iter().flatten() {
            if walker.model.tables.contains_key(name) && reached.insert(name.clone()) {
                work.push(name.clone());
            }
        }
    }
    walker
        .model
        .tables
        .retain(|table, _| reached.contains(table));
    walker.model
}
