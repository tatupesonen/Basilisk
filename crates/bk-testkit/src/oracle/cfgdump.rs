//! Analysis dumps (format `bkcfg 1`, `docs/features/decomp-oracle.md` 4.6):
//! what `bk cfg analyze` writes — Ghidra's `structureLoops`,
//! `calcForwardDominator` and `orderLoopBodies` on a graph file.
//!
//! (`→` stands for one tab.)
//!
//! ```text
//! H → bkcfg → 1 → ok|error → <message or ->
//! O → <ids in list order after the analysis>
//! N → <id> → <index> → <idom or -> → <numdesc> → <dom depth>      (list order)
//! I → <id> → <src>:<slot>:<label hex>,…                        (list order)
//! R → <root ids, rootlist order>
//! L → <head> → <depth> → <exit or -> → <uniquecount> → <tails> → <exit edges top>bottom> → <container head or ->
//! T
//! ```

use super::graph::GraphEdge;
use super::text::{
    Lines, ParseError, ParseErrorKind, Record, Status, list_items, parse_hex_u64, parse_u32,
    push_display, read_status_header, write_list, write_status_header,
};

/// A whole analysis dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgDump {
    /// Ghidra raised an error (`LowlevelError`) with this message.
    Error(String),
    /// The analysis.
    Ok(CfgAnalysis),
}

/// Ghidra's analysis of a graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfgAnalysis {
    /// Input ids in the list order the analysis left (reverse post-order).
    pub order: Vec<u32>,
    /// Per node, in that order.
    pub nodes: Vec<CfgNode>,
    /// The entry points `structureLoops` found.
    pub roots: Vec<u32>,
    /// The loop bodies of `orderLoopBodies`, in Ghidra's list order (deepest first).
    pub loops: Vec<LoopRecord>,
}

/// One node after the analysis (`N` and `I` records).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfgNode {
    /// The input id.
    pub id: u32,
    /// The index `structureLoops` assigned.
    pub index: u32,
    /// The immediate dominator's input id.
    pub idom: Option<u32>,
    /// Descendants in the spanning tree (+1).
    pub numdesc: u32,
    /// Depth in the dominator tree (`buildDomDepth`).
    pub dom_depth: u32,
    /// In-edges with their labels after the analysis; `src` is an input id.
    pub in_edges: Vec<GraphEdge>,
}

/// One `LoopBody`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoopRecord {
    /// The loop head's input id.
    pub head: u32,
    /// Nesting depth.
    pub depth: u32,
    /// The chosen exit block.
    pub exit: Option<u32>,
    /// `uniquecount`.
    pub unique_count: u32,
    /// Tails in order.
    pub tails: Vec<u32>,
    /// Exit edges in order, `(top, bottom)`.
    pub exit_edges: Vec<(u32, u32)>,
    /// The head of the immediately containing loop.
    pub container: Option<u32>,
}

fn id_or_dash(
    record: &Record<'_>,
    i: usize,
    name: &'static str,
) -> Result<Option<u32>, ParseError> {
    match record.field(i) {
        "-" => Ok(None),
        _ => record.u32_at(i, name).map(Some),
    }
}

fn ids(record: &Record<'_>, i: usize, name: &'static str) -> Result<Vec<u32>, ParseError> {
    let field = record.field(i);
    list_items(field)
        .and_then(|items| items.into_iter().map(parse_u32).collect::<Option<Vec<_>>>())
        .ok_or_else(|| record.bad(name, field))
}

fn parse_edge(item: &str) -> Option<GraphEdge> {
    let mut parts = item.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(src), Some(slot), Some(label), None) => Some(GraphEdge {
            src: parse_u32(src)?,
            slot: parse_u32(slot)?,
            label: u32::try_from(parse_hex_u64(label)?).ok()?,
        }),
        _ => None,
    }
}

fn edges(record: &Record<'_>, i: usize) -> Result<Vec<GraphEdge>, ParseError> {
    let field = record.field(i);
    let items = list_items(field).ok_or_else(|| record.bad("in-edges", field))?;
    items
        .into_iter()
        .map(|item| parse_edge(item).ok_or_else(|| record.bad("edge", item)))
        .collect()
}

fn write_edges(out: &mut String, edges: &[GraphEdge]) {
    let items: Vec<String> = edges
        .iter()
        .map(|e| format!("{}:{}:{:#x}", e.src, e.slot, e.label))
        .collect();
    write_list(out, &items);
}

fn write_opt(out: &mut String, value: Option<u32>) {
    match value {
        Some(v) => push_display(out, &v),
        None => out.push('-'),
    }
}

impl CfgDump {
    /// Read an analysis dump.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("bkcfg", text)?;
        if let Status::Error(message) = read_status_header(&mut lines, "bkcfg")? {
            lines.finish()?;
            return Ok(Self::Error(message));
        }
        let o = lines.next_line("the O record")?;
        o.expect("O", 2, "the O record")?;
        let order = ids(&o, 1, "list order")?;
        let mut analysis = CfgAnalysis {
            order,
            ..CfgAnalysis::default()
        };
        for &id in &analysis.order {
            let n = lines.next_line("an N record")?;
            n.expect("N", 6, "an N record")?;
            if n.u32_at(1, "node id")? != id {
                return Err(n.bad("node id (N records follow the O order)", n.field(1)));
            }
            analysis.nodes.push(CfgNode {
                id,
                index: n.u32_at(2, "index")?,
                idom: id_or_dash(&n, 3, "dominator")?,
                numdesc: n.u32_at(4, "descendant count")?,
                dom_depth: n.u32_at(5, "dominator depth")?,
                in_edges: Vec::new(),
            });
        }
        for node in &mut analysis.nodes {
            let i = lines.next_line("an I record")?;
            i.expect("I", 3, "an I record")?;
            if i.u32_at(1, "node id")? != node.id {
                return Err(i.bad("node id (I records follow the O order)", i.field(1)));
            }
            node.in_edges = edges(&i, 2)?;
        }
        let r = lines.next_line("the R record")?;
        r.expect("R", 2, "the R record")?;
        analysis.roots = ids(&r, 1, "roots")?;
        while lines.peek_tag() == Some("L") {
            let l = lines.next_line("an L record")?;
            l.expect("L", 8, "an L record")?;
            let exit_field = l.field(6);
            let exit_edges = list_items(exit_field)
                .and_then(|items| {
                    items
                        .into_iter()
                        .map(|item| {
                            let (top, bottom) = item.split_once('>')?;
                            Some((parse_u32(top)?, parse_u32(bottom)?))
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| l.bad("exit edges", exit_field))?;
            analysis.loops.push(LoopRecord {
                head: l.u32_at(1, "loop head")?,
                depth: l.u32_at(2, "loop depth")?,
                exit: id_or_dash(&l, 3, "loop exit")?,
                unique_count: l.u32_at(4, "unique count")?,
                tails: ids(&l, 5, "loop tails")?,
                exit_edges,
                container: id_or_dash(&l, 7, "containing loop")?,
            });
        }
        lines.finish()?;
        let mut sorted = analysis.order.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(ParseError {
                format: "bkcfg",
                line: 2,
                kind: ParseErrorKind::Inconsistent {
                    reason: "a node appears twice in the list order".into(),
                },
            });
        }
        Ok(Self::Ok(analysis))
    }

    /// The dump's text; `write(parse(text)) == text` for any parsed text.
    pub fn write(&self) -> String {
        let mut s = String::new();
        let analysis = match self {
            Self::Error(message) => {
                write_status_header(&mut s, "bkcfg", &Status::Error(message.clone()));
                s.push_str("T\n");
                return s;
            }
            Self::Ok(analysis) => analysis,
        };
        write_status_header(&mut s, "bkcfg", &Status::Ok);
        s.push_str("O\t");
        write_list(&mut s, &analysis.order);
        s.push('\n');
        for node in &analysis.nodes {
            s.push_str("N\t");
            push_display(&mut s, &node.id);
            s.push('\t');
            push_display(&mut s, &node.index);
            s.push('\t');
            write_opt(&mut s, node.idom);
            s.push('\t');
            push_display(&mut s, &node.numdesc);
            s.push('\t');
            push_display(&mut s, &node.dom_depth);
            s.push('\n');
        }
        for node in &analysis.nodes {
            s.push_str("I\t");
            push_display(&mut s, &node.id);
            s.push('\t');
            write_edges(&mut s, &node.in_edges);
            s.push('\n');
        }
        s.push_str("R\t");
        write_list(&mut s, &analysis.roots);
        s.push('\n');
        for l in &analysis.loops {
            s.push_str("L\t");
            push_display(&mut s, &l.head);
            s.push('\t');
            push_display(&mut s, &l.depth);
            s.push('\t');
            write_opt(&mut s, l.exit);
            s.push('\t');
            push_display(&mut s, &l.unique_count);
            s.push('\t');
            write_list(&mut s, &l.tails);
            s.push('\t');
            let edges: Vec<String> = l
                .exit_edges
                .iter()
                .map(|(t, b)| format!("{t}>{b}"))
                .collect();
            write_list(&mut s, &edges);
            s.push('\t');
            write_opt(&mut s, l.container);
            s.push('\n');
        }
        s.push_str("T\n");
        s
    }
}

#[cfg(test)]
mod tests;
