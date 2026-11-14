//! Between `bk-decomp-cfg` and the oracle's formats (`bk_testkit::oracle`,
//! `tools/reference/README.md`): graph files in and out, and Basilisk's
//! results written as `bkcfg` and `bkstruct` dumps with `bk-testkit`'s own
//! writers, so that they compare byte for byte with `decomp_bk`'s.

#![allow(dead_code, reason = "each test binary uses a part")]

use std::collections::HashMap;

use bk_decomp_cfg::{
    BlockFacts, Cfg, CfgError, EdgeView, Fact, Hierarchy, Kind, Limits, NodeId, Structured,
};
use bk_testkit::oracle::{
    CfgAnalysis, CfgDump, CfgNode, Facts, GotoCause, GotoMark, GraphEdge, GraphFile, GraphNode,
    KindData, LoopRecord, NodeKind, NodeName, RuleApplication, StructEdge, StructNode,
    StructureDump, SwitchCase,
};

use super::graphgen::GenGraph;

fn to_facts(f: Fact) -> Facts {
    Facts {
        complex: f.complex,
        switch_out: f.switch_out,
        ends_in_return: f.ends_in_return,
        negation_changes_dataflow: f.negation_changes_dataflow,
    }
}

fn from_facts(f: Facts) -> Fact {
    Fact {
        complex: f.complex,
        switch_out: f.switch_out,
        ends_in_return: f.ends_in_return,
        negation_changes_dataflow: f.negation_changes_dataflow,
    }
}

/// A generated graph as a bare graph file (indices are ids; labels and
/// facts as generated; the switch flag accompanies an `s` fact).
pub(crate) fn graph_of(g: &GenGraph) -> GraphFile {
    let nodes = (0..g.outs.len())
        .map(|i| GraphNode {
            index: i as u32,
            flags: if g.facts[i].switch_out { 0x10 } else { 0 },
            facts: to_facts(g.facts[i]),
            idom: None,
            numdesc: 0,
            in_edges: g.ins[i]
                .iter()
                .map(|&(src, slot)| GraphEdge {
                    src: src as u32,
                    slot: slot as u32,
                    label: g.labels[src][slot],
                })
                .collect(),
            range: None,
        })
        .collect();
    GraphFile { nodes }
}

/// A graph file as a [`Cfg`] (ids = positions) with its facts, its
/// indices, dominators, descendant counts, flags and labels.
pub(crate) fn cfg_of(file: &GraphFile) -> (Cfg, BlockFacts) {
    let mut cfg = Cfg::new();
    let ids: Vec<NodeId> = file
        .nodes
        .iter()
        .map(|n| cfg.add_node(n.flags).unwrap())
        .collect();
    let mut facts = BlockFacts::neutral(ids.len());
    for (i, node) in file.nodes.iter().enumerate() {
        facts.set(i, from_facts(node.facts));
        cfg.set_index(ids[i], node.index as i32).unwrap();
        cfg.set_numdesc(ids[i], node.numdesc as i32).unwrap();
        for e in &node.in_edges {
            cfg.add_edge_at(ids[e.src as usize], e.slot as usize, ids[i], e.label)
                .unwrap();
        }
    }
    for (i, node) in file.nodes.iter().enumerate() {
        cfg.set_idom(ids[i], node.idom.map(|d| ids[d as usize]))
            .unwrap();
    }
    cfg.check_slots().unwrap();
    (cfg, facts)
}

/// An analysed graph renumbered by list position: the `asgiven` input.
pub(crate) fn asgiven_of(cfg: &Cfg, facts: &BlockFacts) -> GraphFile {
    let order = cfg.nodes().to_vec();
    let pos: HashMap<NodeId, u32> = order
        .iter()
        .enumerate()
        .map(|(i, &n)| (n, i as u32))
        .collect();
    let nodes = order
        .iter()
        .map(|&n| GraphNode {
            index: cfg.index(n).unwrap() as u32,
            flags: cfg.flags(n).unwrap(),
            facts: to_facts(facts.get(n.index())),
            idom: cfg.idom(n).map(|d| pos[&d]),
            numdesc: cfg.numdesc(n).unwrap() as u32,
            in_edges: cfg
                .in_edges(n)
                .iter()
                .map(|e| GraphEdge {
                    src: pos[&e.node],
                    slot: e.rev,
                    label: e.label,
                })
                .collect(),
            range: None,
        })
        .collect();
    GraphFile { nodes }
}

fn graph_edges(c: &Cfg, n: NodeId) -> Vec<GraphEdge> {
    c.in_edges(n)
        .iter()
        .map(|e| GraphEdge {
            src: e.node.get(),
            slot: e.rev,
            label: e.label,
        })
        .collect()
}

/// `bk cfg analyze` in Basilisk: the analyses and loop bodies of a bare
/// graph file, as a `bkcfg` dump.
pub(crate) fn cfg_dump(file: &GraphFile) -> CfgDump {
    let (cfg, facts) = cfg_of(file);
    let mut c = cfg;
    let res = (|| -> Result<_, CfgError> {
        let roots = c.structure_loops()?;
        c.forward_dominators(&roots)?;
        let loops = bk_decomp_cfg::loop_bodies(&c, &facts, &Limits::default())?;
        Ok((roots, loops))
    })();
    let (roots, loops) = match res {
        Ok(x) => x,
        Err(e) => return CfgDump::Error(e.to_string()),
    };
    let (depth, _) = c.dom_depth().unwrap_or_default();
    let nodes = c
        .nodes()
        .iter()
        .enumerate()
        .map(|(i, &n)| CfgNode {
            id: n.get(),
            index: c.index(n).unwrap() as u32,
            idom: c.idom(n).map(NodeId::get),
            numdesc: c.numdesc(n).unwrap() as u32,
            dom_depth: depth.get(i).copied().unwrap_or(0) as u32,
            in_edges: graph_edges(&c, n),
        })
        .collect();
    CfgDump::Ok(CfgAnalysis {
        order: c.nodes().iter().map(|n| n.get()).collect(),
        nodes,
        roots: roots.iter().map(|n| n.get()).collect(),
        loops: loops
            .iter()
            .map(|l| LoopRecord {
                head: l.head.get(),
                depth: l.depth as u32,
                exit: l.exit.map(NodeId::get),
                unique_count: l.uniquecount as u32,
                tails: l.tails.iter().map(|t| t.get()).collect(),
                exit_edges: l
                    .exit_edges
                    .iter()
                    .map(|(a, b)| (a.get(), b.get()))
                    .collect(),
                container: l.immed_container.map(NodeId::get),
            })
            .collect(),
    })
}

/// The oracle's names of a hierarchy's nodes: `L<id>` for leaves, `S<n>`
/// for structured nodes in pre-order; and that pre-order.
pub(crate) fn names(h: &Hierarchy) -> (Vec<NodeId>, HashMap<NodeId, NodeName>) {
    let mut order = Vec::new();
    let mut map = HashMap::new();
    let mut next = 0;
    let mut stack: Vec<NodeId> = h.top_level().iter().rev().copied().collect();
    while let Some(n) = stack.pop() {
        order.push(n);
        let name = if h.kind(n) == Some(Kind::Copy) {
            NodeName::Leaf(n.get())
        } else {
            next += 1;
            NodeName::Structured(next - 1)
        };
        map.insert(n, name);
        stack.extend(h.components(n).iter().rev().copied());
    }
    (order, map)
}

fn node_kind(k: Kind) -> NodeKind {
    match k {
        Kind::Goto => NodeKind::Goto,
        Kind::MultiGoto => NodeKind::MultiGoto,
        Kind::List => NodeKind::List,
        Kind::Condition => NodeKind::Condition,
        Kind::If => NodeKind::If,
        Kind::IfElse => NodeKind::IfElse,
        Kind::IfNoExit => NodeKind::IfNoExit,
        Kind::IfGoto => NodeKind::IfGoto,
        Kind::WhileDo => NodeKind::WhileDo,
        Kind::DoWhile => NodeKind::DoWhile,
        Kind::InfLoop => NodeKind::InfLoop,
        Kind::Switch => NodeKind::Switch,
        _ => NodeKind::Copy,
    }
}

fn cause(c: bk_decomp_cfg::GotoCause) -> GotoCause {
    match c {
        bk_decomp_cfg::GotoCause::Selected => GotoCause::Selected,
        bk_decomp_cfg::GotoCause::ClippedRoot => GotoCause::Clipped,
        bk_decomp_cfg::GotoCause::SwitchSkip => GotoCause::SwitchSkip,
        bk_decomp_cfg::GotoCause::CaseFallthru => GotoCause::Fallthru,
    }
}

/// The `S` and `P` records of a hierarchy (what `bk dump structure` has).
pub(crate) fn struct_nodes(h: &Hierarchy) -> (Vec<StructNode>, Vec<NodeName>) {
    let (order, names) = names(h);
    let name = |n: &NodeId| names[n];
    let edges = |v: Vec<EdgeView>| {
        v.into_iter()
            .map(|e| StructEdge {
                node: name(&e.node),
                rev: e.rev as i32,
                label: e.label,
            })
            .collect()
    };
    let nodes = order
        .iter()
        .map(|n| {
            let kind = h.kind(*n).unwrap();
            let data = match kind {
                Kind::Goto | Kind::IfGoto => {
                    let (t, ty) = h.goto_target(*n).unwrap();
                    KindData::Goto {
                        target: Some(name(&t)),
                        goto_type: ty,
                    }
                }
                Kind::MultiGoto => {
                    let (ts, d) = h.multi_goto(*n).unwrap();
                    KindData::MultiGoto {
                        targets: ts.iter().map(name).collect(),
                        default: d,
                    }
                }
                Kind::Condition => {
                    KindData::Condition(h.condition_op(*n).unwrap().name().to_owned())
                }
                Kind::WhileDo => KindData::WhileDo {
                    overflow: h.has_overflow_syntax(*n),
                },
                Kind::Switch => KindData::Switch(
                    h.cases(*n)
                        .iter()
                        .map(|c| SwitchCase {
                            node: name(&c.block),
                            out_index: c.outindex,
                            chain: c.chain,
                            goto_type: c.gototype,
                            is_exit: c.isexit,
                            is_default: c.isdefault,
                        })
                        .collect(),
                ),
                _ => KindData::None,
            };
            StructNode {
                name: name(n),
                kind: node_kind(kind),
                index: h.index(*n),
                flags: h.flags(*n),
                depth: h.structure_depth(*n),
                leaf_count: h.leaf_count(*n),
                parent: h.parent(*n).map(|p| name(&p)),
                components: h.components(*n).iter().map(name).collect(),
                data,
                in_edges: edges(h.in_edges(*n)),
                out_edges: edges(h.out_edges(*n)),
            }
        })
        .collect();
    (nodes, h.top_level().iter().map(name).collect())
}

/// A structuring result as a `bkstruct` dump.
pub(crate) fn struct_dump(res: &Result<Structured, CfgError>) -> StructureDump {
    let s = match res {
        Ok(s) => s,
        Err(e) => return StructureDump::Error(e.to_string()),
    };
    let h = &s.hierarchy;
    let (_, names) = names(h);
    let name = |n: &NodeId| names[n];
    let (nodes, top) = struct_nodes(h);
    StructureDump::Ok(bk_testkit::oracle::Structured {
        gotos: s
            .goto_edges
            .iter()
            .map(|g| GotoMark {
                source: name(&g.source),
                slot: g.slot,
                target: name(&g.target),
                cause: cause(g.cause),
            })
            .collect(),
        flips: s.flips.iter().map(name).collect(),
        change_count: Some(s.dataflow_changes),
        nodes,
        top,
        trace: s
            .trace
            .iter()
            .flatten()
            .map(|r| RuleApplication {
                rule: r.rule.to_owned(),
                node: name(&r.node),
            })
            .collect(),
    })
}

/// What `bk dump structure` writes of a hierarchy: `S` and `P` only.
pub(crate) fn dump_structure(h: &Hierarchy) -> StructureDump {
    let (nodes, top) = struct_nodes(h);
    StructureDump::Ok(bk_testkit::oracle::Structured {
        gotos: Vec::new(),
        flips: Vec::new(),
        change_count: None,
        nodes,
        top,
        trace: Vec::new(),
    })
}
