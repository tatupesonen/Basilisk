//! Graph files (format `bkgraph 1`, `docs/features/decomp-oracle.md` 4.6):
//! the input of `bk cfg analyze` and `bk structure`, the output of `bk dump
//! blocks`. A control-flow graph with Ghidra's edge labels and the four
//! per-block facts of `docs/features/decomp-cfg.md` 4.1.
//!
//! (`→` stands for one tab.)
//!
//! ```text
//! H → bkgraph → 1 → <node count>
//! N → <id> → <index> → <flags hex> → <facts> → <idom id or -> → <numdesc>
//! I → <id> → <src>:<src out-slot>:<label hex>,…   (- if none)
//! A → <id> → <start address> → <stop address>      (optional)
//! T
//! ```

use super::text::{
    Lines, ParseError, ParseErrorKind, hex, list_items, parse_hex_u64, parse_u32, push_display,
    shown,
};

/// The largest graph a graph file may describe (the extension's limit too).
pub const MAX_GRAPH_NODES: usize = 100_000;

/// A whole graph file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphFile {
    /// The nodes in Ghidra's list order; a node's id is its position.
    pub nodes: Vec<GraphNode>,
}

/// One node (`N`, `I` and optional `A` records).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphNode {
    /// `FlowBlock::index`; used by `asgiven` mode only.
    pub index: u32,
    /// `FlowBlock::flags` (`block_flags`).
    pub flags: u32,
    /// The per-block facts.
    pub facts: Facts,
    /// The immediate dominator's id; used by `asgiven` mode only.
    pub idom: Option<u32>,
    /// `FlowBlock::numdesc`; used by `asgiven` mode only.
    pub numdesc: u32,
    /// In-edges in order.
    pub in_edges: Vec<GraphEdge>,
    /// The instruction range of a basic block (`A` record), as written.
    pub range: Option<AddressRange>,
}

/// The per-block facts of `decomp-cfg.md` 4.1 (letters `c`, `s`, `r`, `n`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Facts {
    /// `c`: too complex to be a condition (`isComplex`).
    pub complex: bool,
    /// `s`: the block's outputs are decided by a switch (`f_switch_out`).
    pub switch_out: bool,
    /// `r`: the block ends in `RETURN`.
    pub ends_in_return: bool,
    /// `n`: negating the block's condition changes data-flow.
    pub negation_changes_dataflow: bool,
}

impl Facts {
    /// The facts Ghidra's plain blocks have (`structure blocks`): complex only.
    pub const NEUTRAL: Self = Self {
        complex: true,
        switch_out: false,
        ends_in_return: false,
        negation_changes_dataflow: false,
    };

    /// The facts field: the letters in the order `csrn`, or `-`.
    pub fn letters(self) -> String {
        let mut s = String::new();
        for (on, letter) in [
            (self.complex, 'c'),
            (self.switch_out, 's'),
            (self.ends_in_return, 'r'),
            (self.negation_changes_dataflow, 'n'),
        ] {
            if on {
                s.push(letter);
            }
        }
        if s.is_empty() {
            s.push('-');
        }
        s
    }

    /// Parse a facts field in its one spelling.
    pub fn from_letters(text: &str) -> Option<Self> {
        if text == "-" {
            return Some(Self::default());
        }
        let mut facts = Self::default();
        let mut rest = text;
        for (letter, slot) in [
            ('c', &mut facts.complex),
            ('s', &mut facts.switch_out),
            ('r', &mut facts.ends_in_return),
            ('n', &mut facts.negation_changes_dataflow),
        ] {
            if let Some(after) = rest.strip_prefix(letter) {
                *slot = true;
                rest = after;
            }
        }
        (rest.is_empty() && !text.is_empty()).then_some(facts)
    }
}

/// One edge as an in-edge list names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GraphEdge {
    /// The source node's id.
    pub src: u32,
    /// The edge's position in the source's out-edges.
    pub slot: u32,
    /// Ghidra's edge label (`FlowBlock::edge_flags`).
    pub label: u32,
}

/// An address as the oracle formats write it: `<space>:0x<offset>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OracleAddress {
    /// The address space's name.
    pub space: String,
    /// The offset in it.
    pub offset: u64,
}

impl OracleAddress {
    /// Parse `<space>:0x<offset>`.
    pub fn parse(text: &str) -> Option<Self> {
        let (space, offset) = text.rsplit_once(':')?;
        if space.is_empty() || space.contains(['\t', ',', ' ']) {
            return None;
        }
        Some(Self {
            space: space.to_owned(),
            offset: parse_hex_u64(offset)?,
        })
    }
}

impl std::fmt::Display for OracleAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.offset)
    }
}

/// The first and last address of a basic block's original instructions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressRange {
    /// `getStart()`.
    pub start: OracleAddress,
    /// `getStop()`.
    pub stop: OracleAddress,
}

impl GraphFile {
    /// Read a graph file, checking it as the extension does: ids in order,
    /// edges naming existing nodes, every out-slot of every node named by
    /// exactly one in-edge, no node both switching and ending in `RETURN`.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("bkgraph", text)?;
        let header = lines.next_line("the header")?;
        if header.tag() != "H" || header.field(1) != "bkgraph" {
            return Err(header.error(ParseErrorKind::UnexpectedRecord {
                expected: "the bkgraph header",
                found: shown(header.text),
            }));
        }
        header.expect("H", 4, "the header")?;
        if header.field(2) != "1" {
            return Err(header.error(ParseErrorKind::UnsupportedVersion {
                version: shown(header.field(2)),
            }));
        }
        let count = header.u32_at(3, "node count")? as usize;
        if count > MAX_GRAPH_NODES {
            return Err(header.error(ParseErrorKind::TooMany {
                what: "nodes",
                limit: MAX_GRAPH_NODES,
            }));
        }
        let count32 = u32::try_from(count).unwrap_or(u32::MAX);
        let node_ref = |record: &super::text::Record<'_>, text: &str, what: &'static str| {
            parse_u32(text)
                .filter(|&v| v < count32)
                .ok_or_else(|| record.bad(what, text))
        };
        let mut nodes = Vec::with_capacity(count.min(4096));
        for id in 0..count32 {
            let n = lines.next_line("an N record")?;
            n.expect("N", 7, "an N record")?;
            if n.u32_at(1, "node id")? != id {
                return Err(n.bad("node id (ids are 0..n-1 in order)", n.field(1)));
            }
            let facts =
                Facts::from_letters(n.field(4)).ok_or_else(|| n.bad("facts", n.field(4)))?;
            if facts.switch_out && facts.ends_in_return {
                return Err(n.error(ParseErrorKind::Inconsistent {
                    reason: format!("node {id} both switches and ends in RETURN"),
                }));
            }
            let idom = match n.field(5) {
                "-" => None,
                text => Some(node_ref(&n, text, "dominator")?),
            };
            let mut node = GraphNode {
                index: n.u32_at(2, "index")?,
                flags: n.hex32_at(3, "flags")?,
                facts,
                idom,
                numdesc: n.u32_at(6, "descendant count")?,
                in_edges: Vec::new(),
                range: None,
            };
            let i = lines.next_line("an I record")?;
            i.expect("I", 3, "an I record")?;
            if i.u32_at(1, "node id")? != id {
                return Err(i.bad("node id of the I record", i.field(1)));
            }
            let items = list_items(i.field(2)).ok_or_else(|| i.bad("in-edges", i.field(2)))?;
            for item in items {
                let mut parts = item.split(':');
                let (Some(src), Some(slot), Some(label), None) =
                    (parts.next(), parts.next(), parts.next(), parts.next())
                else {
                    return Err(i.bad("edge", item));
                };
                node.in_edges.push(GraphEdge {
                    src: node_ref(&i, src, "edge source")?,
                    slot: parse_u32(slot).ok_or_else(|| i.bad("out-slot", slot))?,
                    label: parse_hex_u64(label)
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or_else(|| i.bad("edge label", label))?,
                });
            }
            if lines.peek_tag() == Some("A") {
                let a = lines.next_line("an A record")?;
                a.expect("A", 4, "an A record")?;
                if a.u32_at(1, "node id")? != id {
                    return Err(a.bad("node id of the A record", a.field(1)));
                }
                node.range = Some(AddressRange {
                    start: OracleAddress::parse(a.field(2))
                        .ok_or_else(|| a.bad("start address", a.field(2)))?,
                    stop: OracleAddress::parse(a.field(3))
                        .ok_or_else(|| a.bad("stop address", a.field(3)))?,
                });
            }
            nodes.push(node);
        }
        lines.finish()?;
        let graph = Self { nodes };
        graph.check_slots().map_err(|reason| ParseError {
            format: "bkgraph",
            line: 0,
            kind: ParseErrorKind::Inconsistent { reason },
        })?;
        Ok(graph)
    }

    /// Every out-slot of every node must be named by exactly one in-edge.
    fn check_slots(&self) -> Result<(), String> {
        let mut out_degree = vec![0_usize; self.nodes.len()];
        for edge in self.nodes.iter().flat_map(|n| &n.in_edges) {
            if let Some(d) = out_degree.get_mut(edge.src as usize) {
                *d += 1;
            }
        }
        let mut seen: Vec<Vec<bool>> = out_degree.iter().map(|&d| vec![false; d]).collect();
        for edge in self.nodes.iter().flat_map(|n| &n.in_edges) {
            let slots = seen
                .get_mut(edge.src as usize)
                .ok_or_else(|| format!("edge source {} is not a node", edge.src))?;
            let degree = slots.len();
            let slot = slots.get_mut(edge.slot as usize).ok_or_else(|| {
                format!(
                    "out-slot {} of node {} is beyond its {degree} out-edges",
                    edge.slot, edge.src
                )
            })?;
            if *slot {
                return Err(format!(
                    "out-slot {} of node {} is named twice",
                    edge.slot, edge.src
                ));
            }
            *slot = true;
        }
        Ok(())
    }

    /// The out-edges of every node, in slot order: `(target id, label)`.
    pub fn out_edges(&self) -> Vec<Vec<(u32, u32)>> {
        let mut outs: Vec<Vec<(u32, u32, u32)>> = vec![Vec::new(); self.nodes.len()];
        for (target, node) in self.nodes.iter().enumerate() {
            for edge in &node.in_edges {
                if let Some(list) = outs.get_mut(edge.src as usize) {
                    list.push((
                        edge.slot,
                        u32::try_from(target).unwrap_or(u32::MAX),
                        edge.label,
                    ));
                }
            }
        }
        outs.into_iter()
            .map(|mut list| {
                list.sort_unstable();
                list.into_iter().map(|(_, t, l)| (t, l)).collect()
            })
            .collect()
    }

    /// Build a graph from out-edge lists (`outs[i]` = targets of node `i` in
    /// slot order), with the given facts, all labels, flags, indices and
    /// descendant counts zero but `index = id`, and no dominators. This is
    /// how generated graphs are written for `bare` mode. Returns `None` when
    /// a target is not a node.
    pub fn from_out_edges(outs: &[Vec<u32>], facts: &[Facts]) -> Option<Self> {
        let n = outs.len();
        let mut nodes: Vec<GraphNode> = (0..n)
            .map(|i| GraphNode {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                facts: facts.get(i).copied().unwrap_or(Facts::NEUTRAL),
                ..GraphNode::default()
            })
            .collect();
        for (src, targets) in outs.iter().enumerate() {
            for (slot, &target) in targets.iter().enumerate() {
                nodes.get_mut(target as usize)?.in_edges.push(GraphEdge {
                    src: u32::try_from(src).ok()?,
                    slot: u32::try_from(slot).ok()?,
                    label: 0,
                });
            }
        }
        Some(Self { nodes })
    }

    /// Ghidra's XML form of the same graph, as `structure blocks` reads it
    /// (`BlockGraph::decode`): plain blocks, in-edges with `end` and `rev`.
    /// Labels, facts, indices other than the id and dominators are not
    /// representable there.
    pub fn to_ghidra_xml(&self) -> String {
        let mut s = String::from("<block index=\"0\">\n");
        for i in 0..self.nodes.len() {
            s.push_str("<bhead index=\"");
            push_display(&mut s, &i);
            s.push_str("\" type=\"plain\"/>\n");
        }
        for (i, node) in self.nodes.iter().enumerate() {
            s.push_str("<block index=\"");
            push_display(&mut s, &i);
            s.push_str("\">");
            for edge in &node.in_edges {
                s.push_str("<edge end=\"");
                push_display(&mut s, &edge.src);
                s.push_str("\" rev=\"");
                push_display(&mut s, &edge.slot);
                s.push_str("\"/>");
            }
            s.push_str("</block>\n");
        }
        s.push_str("</block>\n");
        s
    }

    /// The file's text; `parse(write(g)) == g` and, for any parsed text,
    /// `write(parse(text)) == text`.
    pub fn write(&self) -> String {
        let mut s = String::new();
        s.push_str("H\tbkgraph\t1\t");
        push_display(&mut s, &self.nodes.len());
        s.push('\n');
        for (id, node) in self.nodes.iter().enumerate() {
            s.push_str("N\t");
            push_display(&mut s, &id);
            s.push('\t');
            push_display(&mut s, &node.index);
            s.push('\t');
            s.push_str(&hex(u64::from(node.flags)));
            s.push('\t');
            s.push_str(&node.facts.letters());
            s.push('\t');
            match node.idom {
                Some(d) => push_display(&mut s, &d),
                None => s.push('-'),
            }
            s.push('\t');
            push_display(&mut s, &node.numdesc);
            s.push_str("\nI\t");
            push_display(&mut s, &id);
            s.push('\t');
            if node.in_edges.is_empty() {
                s.push('-');
            }
            for (k, edge) in node.in_edges.iter().enumerate() {
                if k != 0 {
                    s.push(',');
                }
                push_display(&mut s, &edge.src);
                s.push(':');
                push_display(&mut s, &edge.slot);
                s.push(':');
                s.push_str(&hex(u64::from(edge.label)));
            }
            s.push('\n');
            if let Some(range) = &node.range {
                s.push_str("A\t");
                push_display(&mut s, &id);
                s.push('\t');
                push_display(&mut s, &range.start);
                s.push('\t');
                push_display(&mut s, &range.stop);
                s.push('\n');
            }
        }
        s.push_str("T\n");
        s
    }
}

#[cfg(test)]
mod tests;
