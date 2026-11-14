//! Structure dumps (format `bkstruct 1`, `docs/features/decomp-oracle.md`
//! 4.7): what `bk structure` and `bk dump structure` write — Ghidra's
//! structured hierarchy with every node's kind, flags and edges, and for
//! `bk structure` the goto marks, condition flips, change count and rule trace.
//!
//! (`→` stands for one tab.)
//!
//! ```text
//! H → bkstruct → 1 → ok|error → <message or ->
//! G → <source> → <out-slot> → <target> → <cause>        (bk structure only)
//! F → <leaf>                                         (bk structure only)
//! C → <dataflow change count>                        (bk structure only)
//! S → <node> → <kind> → <index> → <flags> → <depth> → <leaf count> → <parent> → <components> → <kind data> → <in-edges> → <out-edges>
//! P → <top-level nodes in list order>
//! R → <seq> → <rule> → <node>                           (with trace)
//! T
//! ```

use std::fmt;
use std::fmt::Write as _;

use super::text::{
    Lines, ParseError, ParseErrorKind, Record, Status, list_items, parse_hex_u64, parse_i32,
    parse_u32, push_display, read_status_header, write_list, write_status_header,
};

/// A whole structure dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructureDump {
    /// Ghidra raised an error with this message (`Could not finish
    /// collapsing block structure`, …), or the trace replica disagreed with
    /// Ghidra's own collapse (`trace replica differs`).
    Error(String),
    /// The hierarchy and what happened while building it.
    Ok(Structured),
}

/// A structured hierarchy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Structured {
    /// Goto marks in the order they were made.
    pub gotos: Vec<GotoMark>,
    /// Condition flips, in call order: the leaf whose `negateCondition` ran.
    pub flips: Vec<NodeName>,
    /// The structurer's data-flow change count (absent in `bk dump structure`).
    pub change_count: Option<u32>,
    /// Every node in pre-order (top-level list order, components in order).
    pub nodes: Vec<StructNode>,
    /// The top-level nodes in list order.
    pub top: Vec<NodeName>,
    /// Rule applications, when traced.
    pub trace: Vec<RuleApplication>,
}

/// A node's name: `L<input id>` for a leaf (a `BlockCopy`), `S<n>` for a
/// structured node, numbered in pre-order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeName {
    /// A leaf: the graph-file id (or basic block position) it copies.
    Leaf(u32),
    /// A structured node.
    Structured(u32),
}

impl NodeName {
    /// Parse `L<n>` or `S<n>`.
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(n) = text.strip_prefix('L') {
            parse_u32(n).map(Self::Leaf)
        } else {
            text.strip_prefix('S')
                .and_then(parse_u32)
                .map(Self::Structured)
        }
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leaf(n) => write!(f, "L{n}"),
            Self::Structured(n) => write!(f, "S{n}"),
        }
    }
}

/// Why an edge was marked as a goto (`G` records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GotoCause {
    /// `selectGoto` chose it.
    Selected,
    /// `selectGoto` found nothing and `clipExtraRoots` marked it.
    Clipped,
    /// `ruleBlockSwitch` matched but marked skips to the exit instead of building.
    SwitchSkip,
    /// `ruleCaseFallthru` marked a fall-through case.
    Fallthru,
}

impl GotoCause {
    const NAMES: [(Self, &'static str); 4] = [
        (Self::Selected, "selected"),
        (Self::Clipped, "clipped"),
        (Self::SwitchSkip, "switchskip"),
        (Self::Fallthru, "fallthru"),
    ];

    /// The cause as written.
    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(c, _)| *c == self)
            .map_or("", |(_, n)| n)
    }

    fn parse(text: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(_, n)| *n == text)
            .map(|(c, _)| *c)
    }
}

/// One goto mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GotoMark {
    /// The node at the current level whose out-edge was marked.
    pub source: NodeName,
    /// The out-slot.
    pub slot: u32,
    /// The edge's target.
    pub target: NodeName,
    /// Why.
    pub cause: GotoCause,
}

/// One rule application of the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleApplication {
    /// The rule (`blockgoto`, `blockcat`, …, `casefallthru`).
    pub rule: String,
    /// The node the rule was applied to.
    pub node: NodeName,
}

/// The kinds of node (Ghidra's `block_type`, `ifnoexit` kept apart from `ifelse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NodeKind {
    /// `BlockCopy`: a leaf.
    Copy,
    /// `BlockGoto`.
    Goto,
    /// `BlockMultiGoto`.
    MultiGoto,
    /// `BlockList`.
    List,
    /// `BlockCondition`.
    Condition,
    /// `BlockIf` (two components).
    If,
    /// `BlockIfElse`.
    IfElse,
    /// `BlockIfNoExit`.
    IfNoExit,
    /// `BlockIfGoto`.
    IfGoto,
    /// `BlockWhileDo`.
    WhileDo,
    /// `BlockDoWhile`.
    DoWhile,
    /// `BlockInfLoop`.
    InfLoop,
    /// `BlockSwitch`.
    Switch,
}

impl NodeKind {
    const NAMES: [(Self, &'static str); 13] = [
        (Self::Copy, "copy"),
        (Self::Goto, "goto"),
        (Self::MultiGoto, "multigoto"),
        (Self::List, "list"),
        (Self::Condition, "condition"),
        (Self::If, "if"),
        (Self::IfElse, "ifelse"),
        (Self::IfNoExit, "ifnoexit"),
        (Self::IfGoto, "ifgoto"),
        (Self::WhileDo, "whiledo"),
        (Self::DoWhile, "dowhile"),
        (Self::InfLoop, "infloop"),
        (Self::Switch, "switch"),
    ];

    /// The kind as written.
    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("", |(_, n)| n)
    }

    /// Parse a kind name.
    pub fn parse(text: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(_, n)| *n == text)
            .map(|(k, _)| *k)
    }
}

/// The kind-specific field of an `S` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KindData {
    /// `-`.
    None,
    /// `goto` and `ifgoto`: target (absent for an `ifgoto` without one) and goto type.
    Goto {
        /// The goto's target.
        target: Option<NodeName>,
        /// `f_goto_goto`, `f_break_goto`, `f_continue_goto`.
        goto_type: u32,
    },
    /// `multigoto`: the targets and whether one is the switch default.
    MultiGoto {
        /// Targets in order.
        targets: Vec<NodeName>,
        /// Whether a goto edge is the formal default.
        default: bool,
    },
    /// `condition`: the stored opcode name (`INT_OR`, `BOOL_AND`, `BOOL_OR`).
    Condition(String),
    /// `whiledo`: whether the overflow syntax is needed.
    WhileDo {
        /// `f_whiledo_overflow`.
        overflow: bool,
    },
    /// `switch`: the cases in `caseblocks` order.
    Switch(Vec<SwitchCase>),
}

/// One case of a switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwitchCase {
    /// The case's node.
    pub node: NodeName,
    /// The switch's out-edge to it.
    pub out_index: i32,
    /// The case it falls through to (index into the cases), or -1.
    pub chain: i32,
    /// Goto type when the case is unstructured, else 0.
    pub goto_type: u32,
    /// Whether the case flows to the switch's exit.
    pub is_exit: bool,
    /// Whether it is the default case.
    pub is_default: bool,
}

/// An edge of a node: the node at the other end, the reverse index, the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StructEdge {
    /// The other end.
    pub node: NodeName,
    /// Its position in the other end's edge list.
    pub rev: i32,
    /// The label.
    pub label: u32,
}

/// One node (`S` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructNode {
    /// Its name.
    pub name: NodeName,
    /// Its kind.
    pub kind: NodeKind,
    /// `FlowBlock::index`.
    pub index: i32,
    /// `FlowBlock::flags`.
    pub flags: u32,
    /// `getStructureDepth()`.
    pub depth: i32,
    /// `getBasicCount()`.
    pub leaf_count: i32,
    /// The enclosing node, `None` at the top level.
    pub parent: Option<NodeName>,
    /// Components in order.
    pub components: Vec<NodeName>,
    /// Kind-specific data.
    pub data: KindData,
    /// In-edges in order.
    pub in_edges: Vec<StructEdge>,
    /// Out-edges in order.
    pub out_edges: Vec<StructEdge>,
}

fn name_at(record: &Record<'_>, i: usize, what: &'static str) -> Result<NodeName, ParseError> {
    NodeName::parse(record.field(i)).ok_or_else(|| record.bad(what, record.field(i)))
}

fn names(
    record: &Record<'_>,
    field: &str,
    what: &'static str,
) -> Result<Vec<NodeName>, ParseError> {
    list_items(field)
        .and_then(|items| items.into_iter().map(NodeName::parse).collect())
        .ok_or_else(|| record.bad(what, field))
}

fn parse_struct_edge(item: &str) -> Option<StructEdge> {
    let mut parts = item.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(node), Some(rev), Some(label), None) => Some(StructEdge {
            node: NodeName::parse(node)?,
            rev: parse_i32(rev)?,
            label: u32::try_from(parse_hex_u64(label)?).ok()?,
        }),
        _ => None,
    }
}

fn struct_edges(record: &Record<'_>, field: &str) -> Result<Vec<StructEdge>, ParseError> {
    let items = list_items(field).ok_or_else(|| record.bad("edges", field))?;
    items
        .into_iter()
        .map(|item| parse_struct_edge(item).ok_or_else(|| record.bad("edge", item)))
        .collect()
}

fn write_edges(out: &mut String, edges: &[StructEdge]) {
    let items: Vec<String> = edges
        .iter()
        .map(|e| format!("{}:{}:{:#x}", e.node, e.rev, e.label))
        .collect();
    write_list(out, &items);
}

/// Read an `S` record.
pub(crate) fn parse_node(s: &Record<'_>) -> Result<StructNode, ParseError> {
    s.expect("S", 12, "an S record")?;
    let kind = NodeKind::parse(s.field(2)).ok_or_else(|| s.bad("node kind", s.field(2)))?;
    let name = name_at(s, 1, "node name")?;
    if matches!(name, NodeName::Leaf(_)) != (kind == NodeKind::Copy) {
        return Err(s.bad(
            "node name (leaves, and only leaves, are copies)",
            s.field(1),
        ));
    }
    let parent = match s.field(7) {
        "-" => None,
        _ => Some(name_at(s, 7, "parent")?),
    };
    Ok(StructNode {
        name,
        kind,
        index: s.i32_at(3, "index")?,
        flags: s.hex32_at(4, "flags")?,
        depth: s.i32_at(5, "structure depth")?,
        leaf_count: s.i32_at(6, "leaf count")?,
        parent,
        components: names(s, s.field(8), "components")?,
        data: kind_data(kind, s.field(9)).ok_or_else(|| s.bad("kind data", s.field(9)))?,
        in_edges: struct_edges(s, s.field(10))?,
        out_edges: struct_edges(s, s.field(11))?,
    })
}

/// Read the `P` record.
pub(crate) fn parse_top(p: &Record<'_>) -> Result<Vec<NodeName>, ParseError> {
    p.expect("P", 2, "the P record")?;
    names(p, p.field(1), "top-level nodes")
}

/// Append an `S` record.
pub(crate) fn write_node(s: &mut String, n: &StructNode) {
    let _ = write!(
        s,
        "S\t{}\t{}\t{}\t{:#x}\t{}\t{}\t",
        n.name,
        n.kind.name(),
        n.index,
        n.flags,
        n.depth,
        n.leaf_count
    );
    match n.parent {
        Some(p) => push_display(s, &p),
        None => s.push('-'),
    }
    s.push('\t');
    write_list(s, &n.components);
    s.push('\t');
    write_kind_data(s, &n.data);
    s.push('\t');
    write_edges(s, &n.in_edges);
    s.push('\t');
    write_edges(s, &n.out_edges);
    s.push('\n');
}

/// Append the `P` record.
pub(crate) fn write_top(s: &mut String, top: &[NodeName]) {
    s.push_str("P\t");
    write_list(s, top);
    s.push('\n');
}

impl StructureDump {
    /// Read a structure dump.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("bkstruct", text)?;
        if let Status::Error(message) = read_status_header(&mut lines, "bkstruct")? {
            lines.finish()?;
            return Ok(Self::Error(message));
        }
        let mut result = Structured::default();
        while lines.peek_tag() == Some("G") {
            let g = lines.next_line("a G record")?;
            g.expect("G", 5, "a G record")?;
            result.gotos.push(GotoMark {
                source: name_at(&g, 1, "goto source")?,
                slot: g.u32_at(2, "out-slot")?,
                target: name_at(&g, 3, "goto target")?,
                cause: GotoCause::parse(g.field(4))
                    .ok_or_else(|| g.bad("goto cause", g.field(4)))?,
            });
        }
        while lines.peek_tag() == Some("F") {
            let f = lines.next_line("an F record")?;
            f.expect("F", 2, "an F record")?;
            result.flips.push(name_at(&f, 1, "flipped leaf")?);
        }
        if lines.peek_tag() == Some("C") {
            let c = lines.next_line("the C record")?;
            c.expect("C", 2, "the C record")?;
            result.change_count = Some(c.u32_at(1, "change count")?);
        }
        while lines.peek_tag() == Some("S") {
            let s = lines.next_line("an S record")?;
            result.nodes.push(parse_node(&s)?);
        }
        let p = lines.next_line("the P record")?;
        result.top = parse_top(&p)?;
        let mut seq = 0_u32;
        while lines.peek_tag() == Some("R") {
            let r = lines.next_line("an R record")?;
            r.expect("R", 4, "an R record")?;
            if r.u32_at(1, "trace sequence number")? != seq {
                return Err(r.bad("trace sequence number (0, 1, 2, … in order)", r.field(1)));
            }
            seq = seq.saturating_add(1);
            let rule = r.field(2);
            if rule.is_empty() || !rule.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(r.bad("rule name", rule));
            }
            result.trace.push(RuleApplication {
                rule: rule.to_owned(),
                node: name_at(&r, 3, "rule node")?,
            });
        }
        let end = lines.next_line("the final T record")?;
        end.expect("T", 1, "the final T record")?;
        if lines.peek_tag().is_some() {
            return Err(lines.error_at(end.number + 1, ParseErrorKind::TrailingText));
        }
        Ok(Self::Ok(result))
    }

    /// The dump's text; `write(parse(text)) == text` for any parsed text.
    pub fn write(&self) -> String {
        let mut s = String::new();
        let result = match self {
            Self::Error(message) => {
                write_status_header(&mut s, "bkstruct", &Status::Error(message.clone()));
                s.push_str("T\n");
                return s;
            }
            Self::Ok(result) => result,
        };
        write_status_header(&mut s, "bkstruct", &Status::Ok);
        for g in &result.gotos {
            let _ = writeln!(
                s,
                "G\t{}\t{}\t{}\t{}",
                g.source,
                g.slot,
                g.target,
                g.cause.name()
            );
        }
        for f in &result.flips {
            let _ = writeln!(s, "F\t{f}");
        }
        if let Some(c) = result.change_count {
            let _ = writeln!(s, "C\t{c}");
        }
        for n in &result.nodes {
            write_node(&mut s, n);
        }
        write_top(&mut s, &result.top);

        for (i, r) in result.trace.iter().enumerate() {
            let _ = writeln!(s, "R\t{i}\t{}\t{}", r.rule, r.node);
        }
        s.push_str("T\n");
        s
    }
}

impl Structured {
    /// The node named `name`.
    pub fn node(&self, name: NodeName) -> Option<&StructNode> {
        self.nodes.iter().find(|n| n.name == name)
    }
}

mod kind;

use kind::{kind_data, write_kind_data};

#[cfg(test)]
mod tests;
