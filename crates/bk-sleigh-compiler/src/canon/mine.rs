//! The canonical form of an [`Elaborated`] specification.

use std::fmt::Write as _;

use super::{Canonical, binary_name, field_text, handle_text, op_text, quote, unary_name};
use crate::elaborated::{ContextChange, Elaborated, PrintPiece};
use crate::ids::{CtorId, PExprId, SymbolId};
use crate::pattern::{PExpr, PatValue};
use crate::spaces::SpaceKind;
use crate::symbols::SymbolKind;
use crate::template::Tpl;

struct Writer<'e> {
    spec: &'e Elaborated,
}

impl Writer<'_> {
    fn space_name(&self, index: u32) -> String {
        self.spec
            .spaces
            .iter()
            .find(|s| s.index == index)
            .map_or_else(|| format!("#{index}"), |s| s.name.clone())
    }

    fn operand_symbol(&self, ctor: CtorId, index: u32) -> String {
        self.spec
            .constructors
            .get(ctor.slot())
            .and_then(|c| c.operands.get(index as usize))
            .and_then(|op| self.spec.operands.get(op.slot()))
            .map_or_else(|| format!("?{index}"), |o| o.symbol.index().to_string())
    }

    fn expr(&self, id: PExprId, out: &mut String) {
        match self.spec.patterns.get_expr(id) {
            Some(PExpr::Field(PatValue::Token(f, _))) => field_text(false, f, out),
            Some(PExpr::Field(PatValue::Context(f))) => field_text(true, f, out),
            Some(PExpr::Constant(v)) => {
                let _ = write!(out, "#{v}");
            }
            Some(PExpr::Operand(op)) => {
                let symbol = self
                    .spec
                    .operands
                    .get(op.slot())
                    .map_or(SymbolId::new(u32::MAX), |o| o.symbol);
                let _ = write!(out, "op{}", symbol.index());
            }
            Some(PExpr::Start) => out.push_str("start"),
            Some(PExpr::End) => out.push_str("end"),
            Some(PExpr::Next2) => out.push_str("next2"),
            Some(PExpr::Binary { op, left, right }) => {
                let _ = write!(out, "({} ", binary_name(*op));
                self.expr(*left, out);
                out.push(' ');
                self.expr(*right, out);
                out.push(')');
            }
            Some(PExpr::Unary { op, operand }) => {
                let _ = write!(out, "({} ", unary_name(*op));
                self.expr(*operand, out);
                out.push(')');
            }
            None => out.push('?'),
        }
    }

    fn symbol(&self, c: &mut Canonical, id: usize) {
        let Some(s) = self.spec.symbols.get(id) else {
            return;
        };
        let name = self.spec.names.resolve(s.name);
        let kind = symbol_kind_name(&s.kind);
        c.put(
            format!("symbol.{id:07}.id"),
            format!("{name} scope={} {kind}", s.scope.index()),
        );
        let mut body = String::new();
        match &s.kind {
            SymbolKind::UserOp(index) => {
                let _ = write!(body, "index={index}");
            }
            SymbolKind::Varnode(vn) => {
                let _ = write!(
                    body,
                    "space={} off={:#x} size={}",
                    self.space_name(vn.space),
                    vn.offset,
                    vn.size
                );
            }
            SymbolKind::Value(v) => value_text(v, &mut body),
            SymbolKind::ValueMap(v, values) => {
                value_text(v, &mut body);
                let _ = write!(body, " {values:?}");
            }
            SymbolKind::Name(v, names) => {
                value_text(v, &mut body);
                let names: Vec<&str> = names
                    .iter()
                    .map(|n| n.as_deref().unwrap_or("<none>"))
                    .collect();
                let _ = write!(body, " {names:?}");
            }
            SymbolKind::VarnodeList(v, list) => {
                value_text(v, &mut body);
                let list: Vec<String> = list
                    .iter()
                    .map(|e| e.map_or_else(|| "<none>".to_owned(), |s| s.index().to_string()))
                    .collect();
                let _ = write!(body, " {list:?}");
            }
            SymbolKind::Context {
                varnode,
                low,
                high,
                flow,
                field,
            } => {
                let _ = write!(
                    body,
                    "varnode={} low={low} high={high} flow={} ",
                    varnode.index(),
                    u8::from(*flow)
                );
                value_text(field, &mut body);
            }
            SymbolKind::Operand(op) => {
                if let Some(o) = self.spec.operands.get(op.slot()) {
                    if let Some(def) = o.def_symbol {
                        let _ = write!(body, "def={}", def.index());
                    } else if let Some(e) = o.def_expr {
                        body.push_str("expr=");
                        self.expr(e, &mut body);
                    } else {
                        body.push_str("undefined");
                    }
                    let _ = write!(body, " code={}", u8::from(o.code));
                }
            }
            SymbolKind::Subtable(t) => {
                let n = self
                    .spec
                    .tables
                    .get(t.slot())
                    .map_or(0, |t| t.constructors.len());
                let _ = write!(body, "numct={n}");
            }
            _ => {}
        }
        c.put(format!("symbol.{id:07}.body"), body);
    }

    fn template(&self, c: &mut Canonical, ctor: CtorId, prefix: &str, tpl: &Tpl) {
        let operand = |i: u32| self.operand_symbol(ctor, i);
        let space = |i: u32| self.space_name(i);
        c.put(
            format!("{prefix}.head"),
            format!("delay={} labels={}", tpl.delay, tpl.labels),
        );
        if let Some(hand) = &tpl.result {
            c.put(
                format!("{prefix}.export"),
                handle_text(hand, &operand, &space),
            );
        }
        c.put(format!("{prefix}.numops"), tpl.ops.len().to_string());
        for (k, op) in tpl.ops.iter().enumerate() {
            let inputs: Vec<bk_sla::VarnodeTpl> = op.inputs.iter().map(|v| v.to_sla()).collect();
            let output = op.output.map(crate::template::Vn::to_sla);
            c.put(
                format!("{prefix}.op.{k:04}"),
                op_text(op.opcode, output.as_ref(), &inputs, &operand, &space),
            );
        }
    }

    fn constructor(&self, c: &mut Canonical, table: &str, index: usize, ctor: CtorId) {
        let Some(data) = self.spec.constructors.get(ctor.slot()) else {
            return;
        };
        let prefix = format!("ctor.{table}.{index:05}");
        let file = self
            .spec
            .source_files
            .get(data.source as usize)
            .map_or("", String::as_str);
        c.put(
            format!("{prefix}.loc"),
            format!("{file}:{} source={}", data.line, data.source),
        );
        c.put(format!("{prefix}.first"), data.first.to_string());
        let mut ids: Vec<u32> = data
            .operands
            .iter()
            .filter_map(|op| self.spec.operands.get(op.slot()))
            .map(|o| o.symbol.index())
            .collect();
        ids.sort_unstable();
        c.put(format!("{prefix}.operands"), format!("{ids:?}"));
        let print: Vec<String> = data
            .print
            .iter()
            .map(|p| match p {
                PrintPiece::Text(t) => quote(t),
                PrintPiece::Operand(i) => format!("op{}", self.operand_symbol(ctor, *i)),
            })
            .collect();
        c.put(format!("{prefix}.print"), print.join(" "));
        for (j, change) in data.context.iter().enumerate() {
            let mut text = String::new();
            match change {
                ContextChange::Op {
                    word,
                    shift,
                    mask,
                    expr,
                } => {
                    let _ = write!(text, "op word={word} shift={shift} mask={mask:#x} ");
                    self.expr(*expr, &mut text);
                }
                ContextChange::Commit {
                    symbol,
                    word,
                    mask,
                    flow,
                } => {
                    let _ = write!(
                        text,
                        "commit sym={} word={word} mask={mask:#x} flow={}",
                        symbol.index(),
                        u8::from(*flow)
                    );
                }
            }
            c.put(format!("{prefix}.context.{j:02}"), text);
        }
        if let Some(main) = &data.main {
            self.template(c, ctor, &format!("{prefix}.tpl.main"), main);
        }
        for (n, tpl) in data.sections.iter().enumerate() {
            if let Some(tpl) = tpl {
                self.template(c, ctor, &format!("{prefix}.tpl.s{n}"), tpl);
            }
        }
    }
}

fn value_text(v: &PatValue, out: &mut String) {
    match v {
        PatValue::Token(f, _) => field_text(false, f, out),
        PatValue::Context(f) => field_text(true, f, out),
    }
}

/// The element name of a symbol kind in the file.
fn symbol_kind_name(kind: &SymbolKind) -> &'static str {
    match kind {
        SymbolKind::UserOp(_) => "userop",
        SymbolKind::Value(_) => "value_sym",
        SymbolKind::ValueMap(..) => "valuemap_sym",
        SymbolKind::Name(..) => "name_sym",
        SymbolKind::Varnode(_) => "varnode_sym",
        SymbolKind::Context { .. } => "context_sym",
        SymbolKind::VarnodeList(..) => "varlist_sym",
        SymbolKind::Operand(_) => "operand_sym",
        SymbolKind::Start => "start_sym",
        SymbolKind::End => "end_sym",
        SymbolKind::Next2 => "next2_sym",
        SymbolKind::Epsilon => "epsilon_sym",
        SymbolKind::Subtable(_) => "subtable_sym",
        _ => "compile-only",
    }
}

/// The canonical form of an elaborated specification.
pub fn canonical(spec: &Elaborated) -> Canonical {
    let w = Writer { spec };
    let mut c = Canonical::default();
    c.put(
        "header.bigendian".to_owned(),
        u8::from(spec.big_endian).to_string(),
    );
    c.put("header.align".to_owned(), spec.align.to_string());
    c.put(
        "header.uniqbase".to_owned(),
        format!("{:#x}", spec.unique_base),
    );
    c.put("header.maxdelay".to_owned(), spec.max_delay.to_string());
    c.put(
        "header.uniqmask".to_owned(),
        format!("{:#x}", spec.unique_mask),
    );
    c.put(
        "header.numsections".to_owned(),
        spec.num_sections.to_string(),
    );
    for (i, name) in spec.source_files.iter().enumerate() {
        c.put(format!("sourcefile.{i:03}"), name.clone());
    }
    c.put("defaultspace".to_owned(), w.space_name(spec.default_space));
    for space in spec.spaces.iter().filter(|s| s.kind != SpaceKind::Constant) {
        let kind = if space.is_other {
            "space_other"
        } else if space.kind == SpaceKind::Unique {
            "space_unique"
        } else {
            "space"
        };
        c.put(
            format!("space.{:02}", space.index),
            format!(
                "{kind} {} be={} delay={} size={} wordsize={} physical={}",
                space.name,
                u8::from(spec.big_endian),
                space.delay,
                space.addr_size,
                space.word_size,
                u8::from(space.physical)
            ),
        );
    }
    c.put("scopes".to_owned(), spec.scopes.len().to_string());
    for (i, parent) in spec.scopes.iter().enumerate() {
        c.put(
            format!("scope.{i:06}"),
            parent.map_or_else(|| "-".to_owned(), |p| p.index().to_string()),
        );
    }
    c.put("symbols".to_owned(), spec.symbols.len().to_string());
    for id in 0..spec.symbols.len() {
        w.symbol(&mut c, id);
    }
    for table in &spec.tables {
        let name = spec.symbol_name(table.symbol).to_owned();
        for (i, &ctor) in table.constructors.iter().enumerate() {
            w.constructor(&mut c, &name, i, ctor);
        }
    }
    c
}
