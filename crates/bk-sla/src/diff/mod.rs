//! Structural comparison of two models (`features/sla.md` 5.2).
//!
//! The comparison walks both models in file order and reports each value
//! that differs with a path such as
//! `table "instruction" constructor 12 (ia.sinc:155) main op 3 input 1 offset`,
//! the left value and the right value. Arena layout does not matter: two
//! models that encode to the same document compare equal. The number of
//! differences reported is capped.

mod equal;
mod render;

use std::fmt::Display;

use crate::model::Sla;
use crate::model::constructor::{DecisionNode, DisjointPattern, PrintPiece};
use crate::model::handles::{DecisionId, ExprId, SymbolId};
use crate::model::symbol::SymbolKind;
use crate::model::template::TemplateRef;
use render::{render_const, render_expr, render_kind, render_pattern};

/// One difference between two models.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// Where: the table, constructor, template, op and field concerned.
    pub path: String,
    /// The value in the left model.
    pub left: String,
    /// The value in the right model.
    pub right: String,
}

impl Display for Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} \u{2260} {}", self.path, self.left, self.right)
    }
}

/// Compares two models; returns at most `cap` differences, in file order.
pub fn diff(left: &Sla, right: &Sla, cap: usize) -> Vec<Difference> {
    let mut differ = Differ {
        a: left,
        b: right,
        cap,
        out: Vec::new(),
    };
    if cap > 0 {
        differ.run();
    }
    differ.out
}

struct Differ<'s> {
    a: &'s Sla,
    b: &'s Sla,
    cap: usize,
    out: Vec<Difference>,
}

impl Differ<'_> {
    fn full(&self) -> bool {
        self.out.len() >= self.cap
    }

    /// Records a difference when the values differ; returns whether the
    /// walk should go on.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers pass values built for the comparison"
    )]
    fn check<T: PartialEq + Display>(&mut self, path: impl FnOnce() -> String, x: T, y: T) -> bool {
        if x != y && !self.full() {
            self.out.push(Difference {
                path: path(),
                left: x.to_string(),
                right: y.to_string(),
            });
        }
        !self.full()
    }

    /// Like `check`, for values that are compared first and rendered only
    /// when they differ.
    fn check_lazy(
        &mut self,
        path: impl FnOnce() -> String,
        equal: bool,
        render: impl FnOnce() -> (String, String),
    ) -> bool {
        if !equal && !self.full() {
            let (left, right) = render();
            self.out.push(Difference {
                path: path(),
                left,
                right,
            });
        }
        !self.full()
    }

    fn run(&mut self) {
        let (a, b) = (self.a, self.b);
        let (ha, hb) = (a.header(), b.header());
        let fields: [(&str, String, String); 6] = [
            (
                "bigendian",
                ha.big_endian.to_string(),
                hb.big_endian.to_string(),
            ),
            ("align", ha.align.to_string(), hb.align.to_string()),
            (
                "uniqbase",
                ha.unique_base.to_string(),
                hb.unique_base.to_string(),
            ),
            (
                "maxdelay",
                ha.max_delay.to_string(),
                hb.max_delay.to_string(),
            ),
            (
                "uniqmask",
                ha.unique_mask.to_string(),
                hb.unique_mask.to_string(),
            ),
            (
                "numsections",
                ha.num_sections.to_string(),
                hb.num_sections.to_string(),
            ),
        ];
        for (name, x, y) in fields {
            if !self.check(|| format!("sleigh {name}"), x, y) {
                return;
            }
        }
        let files_a: Vec<&str> = a.source_files().collect();
        let files_b: Vec<&str> = b.source_files().collect();
        if !self.check(
            || "sourcefiles".to_owned(),
            files_a.join(", "),
            files_b.join(", "),
        ) {
            return;
        }
        if !self.spaces() || !self.scopes() {
            return;
        }
        if !self.check(
            || "symbol_table symbolsize".to_owned(),
            a.symbols().len(),
            b.symbols().len(),
        ) {
            return;
        }
        for index in 0..a.symbols().len().min(b.symbols().len()) {
            if !self.symbol(SymbolId::new(index as u32)) {
                return;
            }
        }
    }

    fn spaces(&mut self) -> bool {
        let (a, b) = (self.a, self.b);
        let render = |sla: &Sla| {
            let mut spaces: Vec<_> = sla.space_records().iter().collect();
            spaces.sort_by_key(|space| space.index);
            let list: Vec<String> = spaces
                .iter()
                .map(|s| {
                    format!(
                        "{} {} index={} bigendian={} delay={} size={} wordsize={} physical={}",
                        s.kind.element_name(),
                        sla.text(s.name),
                        s.index,
                        s.big_endian,
                        s.delay,
                        s.size,
                        s.word_size,
                        s.physical
                    )
                })
                .collect();
            format!(
                "default {}; {}",
                sla.space_name(sla.default_space()).unwrap_or("?"),
                list.join("; ")
            )
        };
        self.check(|| "spaces".to_owned(), render(a), render(b))
    }

    fn scopes(&mut self) -> bool {
        let (a, b) = (self.a, self.b);
        if !self.check(
            || "symbol_table scopesize".to_owned(),
            a.scopes().len(),
            b.scopes().len(),
        ) {
            return false;
        }
        for (index, (x, y)) in a.scopes().iter().zip(b.scopes()).enumerate() {
            let parent =
                |p: Option<crate::ScopeId>| p.map_or_else(|| "none".to_owned(), |p| p.to_string());
            if !self.check(
                || format!("scope {index} parent"),
                parent(x.parent),
                parent(y.parent),
            ) {
                return false;
            }
        }
        true
    }

    fn symbol(&mut self, id: SymbolId) -> bool {
        let (a, b) = (self.a, self.b);
        let (Some(x), Some(y)) = (a.symbol(id), b.symbol(id)) else {
            return true;
        };
        let path = || format!("symbol {id} \"{}\"", a.symbol_name(id));
        if !self.check(
            || format!("{} name", path()),
            a.text(x.name),
            b.text(y.name),
        ) || !self.check(|| format!("{} scope", path()), x.scope, y.scope)
            || !self.check(
                || format!("{} kind", path()),
                x.kind.element_name(),
                y.kind.element_name(),
            )
        {
            return false;
        }
        match (x.kind, y.kind) {
            (SymbolKind::Subtable(ta), SymbolKind::Subtable(tb)) => self.subtable(id, &ta, &tb),
            (kx, ky) => {
                let equal = equal::kind_eq(a, &kx, b, &ky);
                self.check_lazy(
                    || format!("{} content", path()),
                    equal,
                    || (render_kind(a, &kx), render_kind(b, &ky)),
                )
            }
        }
    }

    fn subtable(&mut self, id: SymbolId, ta: &crate::Subtable, tb: &crate::Subtable) -> bool {
        let (a, b) = (self.a, self.b);
        let name = a.symbol_name(id).to_owned();
        if !self.check(
            || format!("table \"{name}\" numct"),
            ta.num_constructors(),
            tb.num_constructors(),
        ) {
            return false;
        }
        for ct in 0..ta.num_constructors().min(tb.num_constructors()) {
            let (Some(ca), Some(cb)) = (
                ta.constructor(ct).and_then(|c| a.constructor(c)),
                tb.constructor(ct).and_then(|c| b.constructor(c)),
            ) else {
                continue;
            };
            let file = a.source_file(ca.source).unwrap_or("?");
            let prefix = format!("table \"{name}\" constructor {ct} ({file}:{})", ca.line);
            let scalars = [
                (
                    "parent",
                    ca.parent.index().to_string(),
                    cb.parent.index().to_string(),
                ),
                ("first", ca.first.to_string(), cb.first.to_string()),
                ("length", ca.length.to_string(), cb.length.to_string()),
                ("source", ca.source.to_string(), cb.source.to_string()),
                ("line", ca.line.to_string(), cb.line.to_string()),
            ];
            for (field, x, y) in scalars {
                if !self.check(|| format!("{prefix} {field}"), x, y) {
                    return false;
                }
            }
            let ops = |sla: &Sla, c| {
                sla.operands(c)
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let print = |sla: &Sla, c| {
                sla.print_pieces(c)
                    .iter()
                    .map(|piece| match *piece {
                        PrintPiece::Text(text) => format!("{:?}", sla.text(text)),
                        PrintPiece::Operand(index) => format!("op{index}"),
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let context = |sla: &Sla, c| {
                sla.context_changes(c)
                    .iter()
                    .map(|change| render::render_change(sla, change))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let same_ops = a.operands(ca) == b.operands(cb);
            let same_print = equal::print_eq(a, ca, b, cb);
            let same_context = equal::context_eq(a, ca, b, cb);
            if !self.check_lazy(
                || format!("{prefix} operands"),
                same_ops,
                || (ops(a, ca), ops(b, cb)),
            ) || !self.check_lazy(
                || format!("{prefix} print"),
                same_print,
                || (print(a, ca), print(b, cb)),
            ) || !self.check_lazy(
                || format!("{prefix} context"),
                same_context,
                || (context(a, ca), context(b, cb)),
            ) {
                return false;
            }
            let ta_ids: Vec<_> = a.template_ids(ca).filter_map(|t| a.template(t)).collect();
            let tb_ids: Vec<_> = b.template_ids(cb).filter_map(|t| b.template(t)).collect();
            if !self.check(|| format!("{prefix} templates"), ta_ids.len(), tb_ids.len()) {
                return false;
            }
            for (x, y) in ta_ids.iter().zip(&tb_ids) {
                let section = x
                    .header()
                    .section
                    .map_or_else(|| "main".to_owned(), |s| format!("section {s}"));
                if !self.template(&format!("{prefix} {section}"), x, y) {
                    return false;
                }
            }
        }
        match (a.decision(ta.decision), b.decision(tb.decision)) {
            (Some(x), Some(y)) => self.decision(&format!("table \"{name}\" decision"), x, y),
            _ => true,
        }
    }

    fn template(&mut self, prefix: &str, x: &TemplateRef<'_>, y: &TemplateRef<'_>) -> bool {
        let (a, b) = (self.a, self.b);
        let (hx, hy) = (x.header(), y.header());
        let section = |s: Option<u32>| s.map_or_else(|| "main".to_owned(), |s| s.to_string());
        let result = |sla: &Sla, t: &TemplateRef<'_>| {
            t.result().map_or_else(
                || "null".to_owned(),
                |h| {
                    h.parts()
                        .iter()
                        .map(|c| render_const(sla, c))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            )
        };
        if !self.check(
            || format!("{prefix} section"),
            section(hx.section),
            section(hy.section),
        ) || !self.check(|| format!("{prefix} delay"), hx.delay, hy.delay)
            || !self.check(|| format!("{prefix} labels"), hx.labels, hy.labels)
            || !self.check_lazy(
                || format!("{prefix} export"),
                x.result() == y.result(),
                || (result(a, x), result(b, y)),
            )
            || !self.check(|| format!("{prefix} ops"), x.ops().len(), y.ops().len())
        {
            return false;
        }
        for (number, (ox, oy)) in x.ops().iter().zip(y.ops()).enumerate() {
            let at = format!("{prefix} op {number}");
            if !self.check(
                || format!("{at} opcode"),
                ox.opcode.name(),
                oy.opcode.name(),
            ) {
                return false;
            }
            let output = |sla: &Sla, t: &TemplateRef<'_>, op| {
                t.output(op)
                    .map_or_else(|| "null".to_owned(), |v| render::render_varnode(sla, v))
            };
            if !self.check_lazy(
                || format!("{at} output"),
                x.output(ox) == y.output(oy),
                || (output(a, x, ox), output(b, y, oy)),
            ) || !self.check(
                || format!("{at} inputs"),
                x.inputs(ox).len(),
                y.inputs(oy).len(),
            ) {
                return false;
            }
            for (slot, (vx, vy)) in x.inputs(ox).iter().zip(y.inputs(oy)).enumerate() {
                let parts = [
                    ("space", vx.space, vy.space),
                    ("offset", vx.offset, vy.offset),
                    ("size", vx.size, vy.size),
                ];
                for (part, cx, cy) in parts {
                    if !self.check_lazy(
                        || format!("{at} input {slot} {part}"),
                        cx == cy,
                        || (render_const(a, &cx), render_const(b, &cy)),
                    ) {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn decision(&mut self, prefix: &str, x: &DecisionNode, y: &DecisionNode) -> bool {
        let (a, b) = (self.a, self.b);
        let head = |n: &DecisionNode| {
            format!(
                "number={} context={} startbit={} size={}",
                n.number, n.context, n.start_bit, n.size
            )
        };
        if !self.check(|| prefix.to_owned(), head(x), head(y))
            || !self.check(
                || format!("{prefix} pairs"),
                a.pairs(x).len(),
                b.pairs(y).len(),
            )
        {
            return false;
        }
        for (index, (px, py)) in a.pairs(x).iter().zip(b.pairs(y)).enumerate() {
            let render = |sla: &Sla, constructor: u32, pattern: &DisjointPattern| {
                format!("ct {constructor} {}", render_pattern(sla, pattern))
            };
            let same = px.constructor == py.constructor
                && equal::pattern_eq(a, &px.pattern, b, &py.pattern);
            if !self.check_lazy(
                || format!("{prefix} pair {index}"),
                same,
                || {
                    (
                        render(a, px.constructor, &px.pattern),
                        render(b, py.constructor, &py.pattern),
                    )
                },
            ) {
                return false;
            }
        }
        let children: Vec<(DecisionId, DecisionId)> = a.children(x).zip(b.children(y)).collect();
        for (value, (cx, cy)) in children.into_iter().enumerate() {
            if let (Some(nx), Some(ny)) = (a.decision(cx), b.decision(cy))
                && !self.decision(&format!("{prefix}/{value}"), nx, ny)
            {
                return false;
            }
        }
        true
    }
}

/// Renders an expression of `sla` as text (for messages and tests).
pub fn expr_text(sla: &Sla, expr: ExprId) -> String {
    render_expr(sla, expr)
}
