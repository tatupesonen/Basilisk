//! A neutral model of what a specification's syntax tree determines and
//! Ghidra's compiled `.sla` also records, so the two can be compared.
//!
//! `xml_side` builds it from the XML form of `.sla` that Ghidra's C++ `sleigh`
//! compiler writes with `-y`; `ast_side` builds it from this crate's tree.
//! Everything here is what the *syntax* fixes: constructor boundaries and
//! tables, source lines, display pieces, the shape of pattern expressions,
//! context changes, section structure and the values in definitions.

pub(crate) mod ast_side;
pub(crate) mod xml_side;

use std::collections::{BTreeMap, BTreeSet};

/// One print piece of a constructor, after Ghidra's whitespace rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Piece {
    /// Literal text.
    Text(String),
    /// An operand, by name.
    Operand(String),
}

/// What is compared per constructor.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct Ctor {
    /// Source file name and line Ghidra records for the constructor.
    pub file: String,
    pub line: u32,
    /// Print pieces in order.
    pub display: Vec<Piece>,
    /// Shapes of the values assigned to context variables, in order (the
    /// enclosing `with` blocks' first).
    pub context_ops: Vec<String>,
    /// Number of `globalset` commits.
    pub commits: usize,
    /// The body is `unimpl`.
    pub unimpl: bool,
    /// The main section exports a value.
    pub export: bool,
    /// Number of named sections.
    pub named_sections: usize,
    /// Number of labels in the main section.
    pub labels: u32,
    /// The main section calls a macro (labels are then not comparable,
    /// because Ghidra counts the labels of expanded macros too).
    pub calls_macro: bool,
    /// Operand definitions: name to expression shape. On the Ghidra side
    /// only operands with a compound defining expression; on ours every
    /// candidate (context assignments to non-context names, and `name =
    /// expr` constraints).
    pub operand_defs: BTreeMap<String, Vec<String>>,
}

/// A field with attached meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Attached {
    /// `attach variables`: one varnode name per encoding, `None` for `_`.
    Variables(Vec<Option<String>>),
    /// `attach names`: one name per encoding, `None` for `_`.
    Names(Vec<Option<String>>),
    /// `attach values`: one value per encoding, `None` for `_`.
    Values(Vec<Option<i64>>),
}

/// The comparable content of one specification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Model {
    /// Constructors per table, in source order.
    pub tables: BTreeMap<String, Vec<Ctor>>,
    /// Varnodes: name to (space, offset, size).
    pub varnodes: BTreeMap<String, (String, u64, u64)>,
    /// Token fields: name to (first bit, last bit, signed).
    pub token_fields: BTreeMap<String, (u64, u64, bool)>,
    /// Context fields without attached meaning: name to (low, high, flow).
    pub context_fields: BTreeMap<String, (u64, u64, bool)>,
    /// Fields with attached meaning.
    pub attached: BTreeMap<String, Attached>,
    /// User-defined p-code operations.
    pub userops: BTreeSet<String>,
    /// Address spaces: name to (size, word size).
    pub spaces: BTreeMap<String, (u64, u64)>,
    /// The default space.
    pub default_space: Option<String>,
}

/// The pattern-expression shape vocabulary shared by both sides: binary
/// operators by their SLEIGH spelling, `neg`/`inv` for unary ones, decimal
/// integers (as Ghidra's signed 64-bit `intb`), and `leaf` for any symbol.
pub(crate) fn binary_shape(op: &str, lhs: &str, rhs: &str) -> String {
    format!("({op} {lhs} {rhs})")
}

/// Whether our shape matches Ghidra's. A symbol (`leaf`) on our side also
/// matches an integer on Ghidra's: a symbol without a pattern value, such as
/// a register, is the constant 0 in a pattern expression
/// (`PatternlessSymbol::getPatternExpression`), which is the compiler's
/// doing, not the parser's.
pub(crate) fn shapes_match(ours: &str, ghidra: &str) -> bool {
    let tokens = |s: &str| -> Vec<String> {
        s.replace('(', " ( ")
            .replace(')', " ) ")
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    };
    let (a, b) = (tokens(ours), tokens(ghidra));
    a.len() == b.len()
        && a.iter()
            .zip(&b)
            .all(|(x, y)| x == y || (x == "leaf" && y.parse::<i64>().is_ok()))
}

fn shape_lists_match(ours: &[String], ghidra: &[String]) -> bool {
    ours.len() == ghidra.len() && ours.iter().zip(ghidra).all(|(a, b)| shapes_match(a, b))
}

/// Compares two models and returns a description of each difference.
pub(crate) fn differences(ours: &Model, ghidra: &Model) -> Vec<String> {
    let mut out = Vec::new();
    compare_maps("varnode", &ours.varnodes, &ghidra.varnodes, &mut out);
    compare_maps(
        "token field",
        &ours.token_fields,
        &ghidra.token_fields,
        &mut out,
    );
    compare_maps(
        "context field",
        &ours.context_fields,
        &ghidra.context_fields,
        &mut out,
    );
    compare_maps("attached field", &ours.attached, &ghidra.attached, &mut out);
    if ours.userops != ghidra.userops {
        out.push(format!(
            "user ops differ: ours {:?}, Ghidra {:?}",
            ours.userops, ghidra.userops
        ));
    }
    compare_maps("space", &ours.spaces, &ghidra.spaces, &mut out);
    if ours.default_space != ghidra.default_space {
        out.push(format!(
            "default space: ours {:?}, Ghidra {:?}",
            ours.default_space, ghidra.default_space
        ));
    }
    let tables: BTreeSet<&String> = ours.tables.keys().chain(ghidra.tables.keys()).collect();
    for table in tables {
        let empty = Vec::new();
        let a = ours.tables.get(table).unwrap_or(&empty);
        let b = ghidra.tables.get(table).unwrap_or(&empty);
        if a.len() != b.len() {
            let at = |c: &Ctor| format!("{}:{}", c.file, c.line);
            let theirs: BTreeSet<String> = b.iter().map(at).collect();
            let mine: BTreeSet<String> = a.iter().map(at).collect();
            let only_here: Vec<&String> = mine.difference(&theirs).take(4).collect();
            let only_there: Vec<&String> = theirs.difference(&mine).take(4).collect();
            out.push(format!(
                "table {table}: {} constructors here, {} in Ghidra; only here {only_here:?}, \
                 only in Ghidra {only_there:?}",
                a.len(),
                b.len()
            ));
            continue;
        }
        for (x, y) in a.iter().zip(b) {
            compare_ctor(table, x, y, &mut out);
        }
    }
    out
}

fn compare_maps<K: Ord + std::fmt::Debug, V: PartialEq + std::fmt::Debug>(
    what: &str,
    ours: &BTreeMap<K, V>,
    ghidra: &BTreeMap<K, V>,
    out: &mut Vec<String>,
) {
    for (key, value) in ours {
        match ghidra.get(key) {
            None => out.push(format!("{what} {key:?} only here")),
            Some(other) if other != value => {
                out.push(format!("{what} {key:?}: ours {value:?}, Ghidra {other:?}"));
            }
            Some(_) => {}
        }
    }
    for key in ghidra.keys() {
        if !ours.contains_key(key) {
            out.push(format!("{what} {key:?} only in Ghidra"));
        }
    }
}

fn compare_ctor(table: &str, ours: &Ctor, ghidra: &Ctor, out: &mut Vec<String>) {
    let at = format!("{table} constructor at {}:{}", ghidra.file, ghidra.line);
    if (ours.file.as_str(), ours.line) != (ghidra.file.as_str(), ghidra.line) {
        out.push(format!("{at}: ours is at {}:{}", ours.file, ours.line));
        return;
    }
    let mut check = |what: &str, same: bool, a: &dyn std::fmt::Debug, b: &dyn std::fmt::Debug| {
        if !same {
            out.push(format!("{at}: {what}: ours {a:?}, Ghidra {b:?}"));
        }
    };
    check(
        "display",
        ours.display == ghidra.display,
        &ours.display,
        &ghidra.display,
    );
    check(
        "context changes",
        shape_lists_match(&ours.context_ops, &ghidra.context_ops),
        &ours.context_ops,
        &ghidra.context_ops,
    );
    check(
        "globalset commits",
        ours.commits == ghidra.commits,
        &ours.commits,
        &ghidra.commits,
    );
    check(
        "unimpl",
        ours.unimpl == ghidra.unimpl,
        &ours.unimpl,
        &ghidra.unimpl,
    );
    check(
        "export",
        ours.export == ghidra.export,
        &ours.export,
        &ghidra.export,
    );
    check(
        "named sections",
        ours.named_sections == ghidra.named_sections,
        &ours.named_sections,
        &ghidra.named_sections,
    );
    if !ours.calls_macro {
        check(
            "labels",
            ours.labels == ghidra.labels,
            &ours.labels,
            &ghidra.labels,
        );
    }
    for (name, shapes) in &ghidra.operand_defs {
        let Some(shape) = shapes.first() else {
            continue;
        };
        let candidates = ours.operand_defs.get(name);
        if !candidates.is_some_and(|c| c.iter().any(|ours| shapes_match(ours, shape))) {
            out.push(format!(
                "{at}: operand {name} defined as {shape}; our candidates {candidates:?}"
            ));
        }
    }
}
