//! Decision-tree analysis: for each subtable whose tree differs between two
//! models, says whether the trees have the same shape (same node heads,
//! recursively), and at the leaves whether the pair lists are equal, equal
//! up to order, or different as multisets.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bk_sla::{DecisionNode, DecisionPair, DisjointPattern, Sla, SymbolKind};

/// A pair rendered as text (constructor index and pattern words), so pairs
/// of two models can be compared.
pub fn pair_text(sla: &Sla, pair: &DecisionPair) -> String {
    format!("ct{} {}", pair.constructor, pattern_text(sla, &pair.pattern))
}

fn block_text(sla: &Sla, id: bk_sla::BlockId) -> String {
    let Some(block) = sla.block(id) else {
        return "?".to_owned();
    };
    let words: Vec<_> = sla
        .block_words(block)
        .iter()
        .map(|w| format!("{:08x}/{:08x}", w.mask, w.value))
        .collect();
    format!("off={} nz={} [{}]", block.offset, block.nonzero, words.join(" "))
}

pub fn pattern_text(sla: &Sla, p: &DisjointPattern) -> String {
    match *p {
        DisjointPattern::Instruction(b) => format!("I {}", block_text(sla, b)),
        DisjointPattern::Context(b) => format!("C {}", block_text(sla, b)),
        DisjointPattern::Combine {
            context,
            instruction,
        } => format!("C {} I {}", block_text(sla, context), block_text(sla, instruction)),
    }
}

fn head(n: &DecisionNode) -> String {
    format!(
        "{}[{}..+{}]",
        if n.context { "ctx" } else { "ins" },
        n.start_bit,
        n.size
    )
}

/// Counters for one table.
#[derive(Default)]
struct TableStats {
    nodes_a: usize,
    nodes_b: usize,
    leaves_a: usize,
    leaves_b: usize,
    shape_differs: Vec<String>,
    leaves_equal: usize,
    leaves_reordered: usize,
    leaves_different: usize,
    reorder_examples: Vec<String>,
    diff_examples: Vec<String>,
}

fn count(sla: &Sla, n: &DecisionNode, nodes: &mut usize, leaves: &mut usize) {
    *nodes += 1;
    if n.is_leaf() {
        *leaves += 1;
    }
    for c in sla.children(n) {
        if let Some(child) = sla.decision(c) {
            count(sla, child, nodes, leaves);
        }
    }
}

fn walk(a: &Sla, x: &DecisionNode, b: &Sla, y: &DecisionNode, path: &str, st: &mut TableStats) {
    if head(x) != head(y) {
        st.shape_differs
            .push(format!("{path}: {} vs {}", head(x), head(y)));
        return;
    }
    if x.is_leaf() {
        let pa: Vec<String> = a.pairs(x).iter().map(|p| pair_text(a, p)).collect();
        let pb: Vec<String> = b.pairs(y).iter().map(|p| pair_text(b, p)).collect();
        if pa == pb {
            st.leaves_equal += 1;
        } else {
            let (mut sa, mut sb) = (pa.clone(), pb.clone());
            sa.sort();
            sb.sort();
            if sa == sb {
                st.leaves_reordered += 1;
                if st.reorder_examples.len() < 3 {
                    st.reorder_examples.push(format!(
                        "{path}:\n        L: {}\n        R: {}",
                        pa.join("\n           "),
                        pb.join("\n           ")
                    ));
                }
            } else {
                st.leaves_different += 1;
                if st.diff_examples.len() < 3 {
                    st.diff_examples.push(format!(
                        "{path}:\n        L: {}\n        R: {}",
                        pa.join("\n           "),
                        pb.join("\n           ")
                    ));
                }
            }
        }
    }
    let ca: Vec<_> = a.children(x).collect();
    let cb: Vec<_> = b.children(y).collect();
    for (v, (cx, cy)) in ca.iter().zip(&cb).enumerate() {
        if let (Some(nx), Some(ny)) = (a.decision(*cx), b.decision(*cy)) {
            walk(a, nx, b, ny, &format!("{path}/{v}"), st);
        }
    }
}

/// Compares the decision trees of every subtable present in both models
/// (paired by symbol name).
pub fn compare(a: &Sla, b: &Sla, verbose: bool) -> String {
    let mut out = String::new();
    let tables = |sla: &Sla| -> BTreeMap<String, bk_sla::Subtable> {
        sla.symbols()
            .iter()
            .filter_map(|s| match s.kind {
                SymbolKind::Subtable(t) => Some((sla.text(s.name).to_owned(), t)),
                _ => None,
            })
            .collect()
    };
    let (ta, tb) = (tables(a), tables(b));
    let mut total = TableStats::default();
    let mut differing_tables = 0;
    for (name, x) in &ta {
        let Some(y) = tb.get(name) else {
            let _ = writeln!(out, "  table {name}: only left");
            continue;
        };
        let (Some(rx), Some(ry)) = (a.decision(x.decision), b.decision(y.decision)) else {
            continue;
        };
        let mut st = TableStats::default();
        count(a, rx, &mut st.nodes_a, &mut st.leaves_a);
        count(b, ry, &mut st.nodes_b, &mut st.leaves_b);
        walk(a, rx, b, ry, "root", &mut st);
        if st.shape_differs.is_empty() && st.leaves_reordered == 0 && st.leaves_different == 0 {
            continue;
        }
        differing_tables += 1;
        let _ = writeln!(
            out,
            "  table {name}: nodes {}/{} leaves {}/{}; shape differences {}; leaves equal {}, reordered {}, different {}",
            st.nodes_a,
            st.nodes_b,
            st.leaves_a,
            st.leaves_b,
            st.shape_differs.len(),
            st.leaves_equal,
            st.leaves_reordered,
            st.leaves_different
        );
        let limit = if verbose { usize::MAX } else { 2 };
        for s in st.shape_differs.iter().take(limit) {
            let _ = writeln!(out, "      shape {s}");
        }
        for s in st.reorder_examples.iter().take(limit) {
            let _ = writeln!(out, "      reorder {s}");
        }
        for s in st.diff_examples.iter().take(limit) {
            let _ = writeln!(out, "      differ {s}");
        }
        total.shape_differs.extend(st.shape_differs);
        total.leaves_reordered += st.leaves_reordered;
        total.leaves_different += st.leaves_different;
    }
    let _ = writeln!(
        out,
        "  trees: {differing_tables} tables differ; {} shape differences, {} reordered leaves, {} leaves with different pairs",
        total.shape_differs.len(),
        total.leaves_reordered,
        total.leaves_different
    );
    out
}

/// For each subtable, the number of distinct (constructor, pattern) pairs
/// over all leaves of its decision tree.
pub fn distinct_pairs(sla: &Sla) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for s in sla.symbols() {
        let SymbolKind::Subtable(t) = s.kind else { continue };
        let mut set = std::collections::BTreeSet::new();
        let mut stack: Vec<bk_sla::DecisionId> = vec![t.decision];
        while let Some(id) = stack.pop() {
            let Some(n) = sla.decision(id) else { continue };
            for p in sla.pairs(n) {
                set.insert(pair_text(sla, p));
            }
            stack.extend(sla.children(n));
        }
        out.push((sla.text(s.name).to_owned(), set.len()));
    }
    out
}
