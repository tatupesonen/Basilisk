//! The canonical form of a compiled `.sla` file read through `bk_sla`.

use std::fmt::Write as _;

use bk_sla::{Constructor, ContextChange, Expr, PrintPiece, Sla, SpaceKind, SymbolId, SymbolKind};

use super::{Canonical, binary_name, field_text, handle_text, op_text, quote, unary_name};

struct Writer<'s> {
    sla: &'s Sla,
}

impl Writer<'_> {
    fn space_name(&self, index: u32) -> String {
        self.sla
            .space_name(index)
            .map_or_else(|| format!("#{index}"), str::to_owned)
    }

    fn operand_symbol(&self, ctor: &Constructor, index: u32) -> String {
        self.sla
            .operands(ctor)
            .get(index as usize)
            .map_or_else(|| format!("?{index}"), |s| s.index().to_string())
    }

    fn expr(&self, id: bk_sla::ExprId, out: &mut String) {
        match self.sla.expr(id) {
            Some(Expr::TokenField(f)) => match self.sla.field(*f) {
                Some(f) => field_text(false, f, out),
                None => out.push('?'),
            },
            Some(Expr::ContextField(f)) => match self.sla.field(*f) {
                Some(f) => field_text(true, f, out),
                None => out.push('?'),
            },
            Some(Expr::Constant(v)) => {
                let _ = write!(out, "#{v}");
            }
            Some(Expr::Operand { index, table, ct }) => {
                let symbol = self
                    .sla
                    .subtable(*table)
                    .and_then(|t| t.constructor(*ct))
                    .and_then(|c| self.sla.constructor(c))
                    .and_then(|c| self.sla.operands(c).get(*index as usize).copied());
                match symbol {
                    Some(s) => {
                        let _ = write!(out, "op{}", s.index());
                    }
                    None => out.push_str("op?"),
                }
            }
            Some(Expr::Start) => out.push_str("start"),
            Some(Expr::End) => out.push_str("end"),
            Some(Expr::Next2) => out.push_str("next2"),
            Some(Expr::Binary { op, left, right }) => {
                let _ = write!(out, "({} ", binary_name(*op));
                self.expr(*left, out);
                out.push(' ');
                self.expr(*right, out);
                out.push(')');
            }
            Some(Expr::Unary { op, operand }) => {
                let _ = write!(out, "({} ", unary_name(*op));
                self.expr(*operand, out);
                out.push(')');
            }
            None => out.push('?'),
        }
    }

    fn symbol(&self, c: &mut Canonical, id: usize) {
        let Some(s) = self.sla.symbols().get(id) else { return };
        let name = self.sla.text(s.name);
        c.put(format!("symbol.{id:07}.id"), format!("{name} scope={} {}", s.scope.index(), s.kind.element_name()));
        let mut body = String::new();
        match &s.kind {
            SymbolKind::UserOp { index } => {
                let _ = write!(body, "index={index}");
            }
            SymbolKind::Varnode { space, offset, size } => {
                let _ = write!(body, "space={} off={offset:#x} size={size}", self.space_name(*space));
            }
            SymbolKind::Value { expr } => self.expr(*expr, &mut body),
            SymbolKind::ValueMap { expr, table } => {
                self.expr(*expr, &mut body);
                let _ = write!(body, " {:?}", self.sla.value_table(*table));
            }
            SymbolKind::Name { expr, table } => {
                self.expr(*expr, &mut body);
                let names: Vec<&str> = self
                    .sla
                    .name_table(*table)
                    .iter()
                    .map(|n| n.map_or("<none>", |n| self.sla.text(n)))
                    .collect();
                let _ = write!(body, " {names:?}");
            }
            SymbolKind::VarnodeList { expr, table } => {
                self.expr(*expr, &mut body);
                let list: Vec<String> = self
                    .sla
                    .varnode_table(*table)
                    .iter()
                    .map(|e| e.map_or_else(|| "<none>".to_owned(), |s| s.index().to_string()))
                    .collect();
                let _ = write!(body, " {list:?}");
            }
            SymbolKind::Context { varnode, low, high, flow, expr } => {
                let _ = write!(body, "varnode={} low={low} high={high} flow={} ", varnode.index(), u8::from(*flow));
                self.expr(*expr, &mut body);
            }
            SymbolKind::Operand(o) => {
                if let Some(def) = o.defining_symbol {
                    let _ = write!(body, "def={}", def.index());
                } else if let Some(e) = o.defining_expr {
                    body.push_str("expr=");
                    self.expr(e, &mut body);
                } else {
                    body.push_str("undefined");
                }
                let _ = write!(body, " code={}", u8::from(o.code));
            }
            SymbolKind::Subtable(t) => {
                let _ = write!(body, "numct={}", t.num_constructors());
            }
            _ => {}
        }
        c.put(format!("symbol.{id:07}.body"), body);
    }

    fn constructor(&self, c: &mut Canonical, table: &str, index: usize, ctor: &Constructor) {
        let prefix = format!("ctor.{table}.{index:05}");
        let file = self.sla.source_file(ctor.source).unwrap_or("");
        c.put(format!("{prefix}.loc"), format!("{file}:{} source={}", ctor.line, ctor.source));
        c.put(format!("{prefix}.first"), ctor.first.to_string());
        let mut ids: Vec<u32> = self.sla.operands(ctor).iter().map(|s| s.index()).collect();
        ids.sort_unstable();
        c.put(format!("{prefix}.operands"), format!("{ids:?}"));
        let print: Vec<String> = self
            .sla
            .print_pieces(ctor)
            .iter()
            .map(|p| match p {
                PrintPiece::Text(t) => quote(self.sla.text(*t)),
                PrintPiece::Operand(i) => format!("op{}", self.operand_symbol(ctor, *i as u32)),
            })
            .collect();
        c.put(format!("{prefix}.print"), print.join(" "));
        for (j, change) in self.sla.context_changes(ctor).iter().enumerate() {
            let mut text = String::new();
            match change {
                ContextChange::Op { word, shift, mask, expr } => {
                    let _ = write!(text, "op word={word} shift={shift} mask={mask:#x} ");
                    self.expr(*expr, &mut text);
                }
                ContextChange::Commit { symbol, word, mask, flow } => {
                    let _ = write!(text, "commit sym={} word={word} mask={mask:#x} flow={}", symbol.index(), u8::from(*flow));
                }
            }
            c.put(format!("{prefix}.context.{j:02}"), text);
        }
        let operand = |i: u32| self.operand_symbol(ctor, i);
        let space = |i: u32| self.space_name(i);
        for id in self.sla.template_ids(ctor) {
            let Some(tpl) = self.sla.template(id) else { continue };
            let header = tpl.header();
            let sec = header.section.map_or_else(|| "main".to_owned(), |n| format!("s{n}"));
            let tprefix = format!("{prefix}.tpl.{sec}");
            c.put(format!("{tprefix}.head"), format!("delay={} labels={}", header.delay, header.labels));
            if let Some(hand) = tpl.result() {
                c.put(format!("{tprefix}.export"), handle_text(hand, &operand, &space));
            }
            c.put(format!("{tprefix}.numops"), tpl.ops().len().to_string());
            for (k, op) in tpl.ops().iter().enumerate() {
                c.put(
                    format!("{tprefix}.op.{k:04}"),
                    op_text(op.opcode, tpl.output(op), tpl.inputs(op), &operand, &space),
                );
            }
        }
    }
}

/// The canonical form of a compiled language.
pub fn canonical(sla: &Sla) -> Canonical {
    let w = Writer { sla };
    let mut c = Canonical::default();
    let h = sla.header();
    c.put("header.bigendian".to_owned(), u8::from(h.big_endian).to_string());
    c.put("header.align".to_owned(), h.align.to_string());
    c.put("header.uniqbase".to_owned(), format!("{:#x}", h.unique_base));
    c.put("header.maxdelay".to_owned(), h.max_delay.to_string());
    c.put("header.uniqmask".to_owned(), format!("{:#x}", h.unique_mask));
    c.put("header.numsections".to_owned(), h.num_sections.to_string());
    for (i, name) in sla.source_files().enumerate() {
        c.put(format!("sourcefile.{i:03}"), name.to_owned());
    }
    c.put("defaultspace".to_owned(), w.space_name(sla.default_space()));
    for space in sla.space_records() {
        let kind = match space.kind {
            SpaceKind::Processor => "space",
            SpaceKind::Unique => "space_unique",
            SpaceKind::Other => "space_other",
        };
        c.put(
            format!("space.{:02}", space.index),
            format!(
                "{kind} {} be={} delay={} size={} wordsize={} physical={}",
                sla.text(space.name),
                u8::from(space.big_endian),
                space.delay,
                space.size,
                space.word_size.max(1),
                u8::from(space.physical)
            ),
        );
    }
    c.put("scopes".to_owned(), sla.scopes().len().to_string());
    for (i, scope) in sla.scopes().iter().enumerate() {
        c.put(format!("scope.{i:06}"), scope.parent.map_or_else(|| "-".to_owned(), |p| p.index().to_string()));
    }
    c.put("symbols".to_owned(), sla.symbols().len().to_string());
    for id in 0..sla.symbols().len() {
        w.symbol(&mut c, id);
    }
    for (id, symbol) in sla.symbols().iter().enumerate() {
        let SymbolKind::Subtable(table) = &symbol.kind else { continue };
        let name = sla.symbol_name(SymbolId::new(id as u32)).to_owned();
        for i in 0..table.num_constructors() {
            let Some(ctor) = table.constructor(i).and_then(|c| sla.constructor(c)) else { continue };
            w.constructor(&mut c, &name, i as usize, ctor);
        }
    }
    c
}
