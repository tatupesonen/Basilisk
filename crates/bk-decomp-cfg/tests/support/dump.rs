//! The oracle's formats (`docs/features/decomp-oracle.md` 4.6, 4.7), written
//! from Basilisk's side: graph files (the input of `bk cfg analyze` and
//! `bk structure`), the `bkcfg` analysis dump and the `bkstruct` structure
//! dump. Local helpers until D00's `bk-testkit` readers and writers land.

#![allow(dead_code, reason = "each test binary uses a part")]

use std::fmt::Write as _;

use bk_decomp_cfg::{
    BlockFacts, Cfg, CfgError, Fact, Hierarchy, Kind, LoopInfo, NodeId, Structured,
};

use super::graphgen::GenGraph;

fn facts_letters(f: Fact) -> String {
    let mut s = String::new();
    if f.complex {
        s.push('c');
    }
    if f.switch_out {
        s.push('s');
    }
    if f.ends_in_return {
        s.push('r');
    }
    if f.negation_changes_dataflow {
        s.push('n');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

fn list<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    let v: Vec<String> = items.into_iter().map(|x| x.to_string()).collect();
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.join(",")
    }
}

/// A bare graph file: ids and indices are node numbers, no dominators.
pub(crate) fn graph_file(g: &GenGraph) -> String {
    let n = g.outs.len();
    let mut s = format!("H\tbkgraph\t1\t{n}\n");
    for i in 0..n {
        let _ = writeln!(s, "N\t{i}\t{i}\t0x0\t{}\t-\t0", facts_letters(g.facts[i]));
        let ins = g.ins[i]
            .iter()
            .map(|&(src, slot)| format!("{src}:{slot}:0x{:x}", g.labels[src][slot]));
        let _ = writeln!(s, "I\t{i}\t{}", list(ins));
    }
    s.push_str("T\n");
    s
}

/// An analysed graph renumbered by list position: the `asgiven` input,
/// with its facts.
pub(crate) fn asgiven(cfg: &Cfg, facts: &BlockFacts) -> (Cfg, BlockFacts, String) {
    let order = cfg.nodes().to_vec();
    let pos = |n: NodeId| order.iter().position(|&m| m == n).unwrap();
    let mut out = Cfg::new();
    let ids: Vec<NodeId> = order.iter().map(|_| out.add_node(0).unwrap()).collect();
    let mut new_facts = BlockFacts::neutral(order.len());
    let mut text = format!("H\tbkgraph\t1\t{}\n", order.len());
    for (i, &n) in order.iter().enumerate() {
        let f = facts.get(n.index());
        new_facts.set(i, f);
        let idom = cfg.idom(n).map(pos);
        out.set_index(ids[i], cfg.index(n).unwrap()).unwrap();
        out.set_numdesc(ids[i], cfg.numdesc(n).unwrap()).unwrap();
        out.set_flags(ids[i], cfg.flags(n).unwrap()).unwrap();
        let ins = cfg.in_edges(n);
        for e in &ins {
            out.add_edge_at(ids[pos(e.node)], e.rev as usize, ids[i], e.label)
                .unwrap();
        }
        let _ = writeln!(
            text,
            "N\t{i}\t{}\t0x{:x}\t{}\t{}\t{}",
            cfg.index(n).unwrap(),
            cfg.flags(n).unwrap(),
            facts_letters(f),
            idom.map_or_else(|| "-".to_owned(), |d| d.to_string()),
            cfg.numdesc(n).unwrap()
        );
        let ins = ins
            .iter()
            .map(|e| format!("{}:{}:0x{:x}", pos(e.node), e.rev, e.label));
        let _ = writeln!(text, "I\t{i}\t{}", list(ins));
    }
    for (i, &n) in order.iter().enumerate() {
        out.set_idom(ids[i], cfg.idom(n).map(|d| ids[pos(d)]))
            .unwrap();
    }
    out.check_slots().unwrap();
    text.push_str("T\n");
    (out, new_facts, text)
}

/// The `bkcfg` dump of `bk cfg analyze` for `cfg` (bare, unanalysed).
pub(crate) fn cfg_dump(cfg: &Cfg, facts: &BlockFacts) -> String {
    let mut c = cfg.clone();
    let res = (|| -> Result<(Vec<NodeId>, Vec<LoopInfo>), CfgError> {
        let roots = c.structure_loops()?;
        c.forward_dominators(&roots)?;
        let loops = bk_decomp_cfg::loop_bodies(&c, facts, &bk_decomp_cfg::Limits::default())?;
        Ok((roots, loops))
    })();
    let (roots, loops) = match res {
        Ok(x) => x,
        Err(e) => return format!("H\tbkcfg\t1\terror\t{e}\nT\n"),
    };
    let (depth, _) = c.dom_depth().unwrap_or_default();
    let mut s = String::from("H\tbkcfg\t1\tok\t-\n");
    let _ = writeln!(s, "O\t{}", list(c.nodes().iter().map(|n| n.get())));
    for (i, &n) in c.nodes().iter().enumerate() {
        let _ = writeln!(
            s,
            "N\t{}\t{}\t{}\t{}\t{}",
            n.get(),
            c.index(n).unwrap(),
            c.idom(n)
                .map_or_else(|| "-".to_owned(), |d| d.get().to_string()),
            c.numdesc(n).unwrap(),
            depth.get(i).copied().unwrap_or(0)
        );
        let ins = c
            .in_edges(n)
            .into_iter()
            .map(|e| format!("{}:{}:0x{:x}", e.node.get(), e.rev, e.label));
        let _ = writeln!(s, "I\t{}\t{}", n.get(), list(ins));
    }
    let _ = writeln!(s, "R\t{}", list(roots.iter().map(|n| n.get())));
    for l in &loops {
        let _ = writeln!(
            s,
            "L\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            l.head.get(),
            l.depth,
            l.exit
                .map_or_else(|| "-".to_owned(), |e| e.get().to_string()),
            l.uniquecount,
            list(l.tails.iter().map(|t| t.get())),
            list(
                l.exit_edges
                    .iter()
                    .map(|(a, b)| format!("{}>{}", a.get(), b.get()))
            ),
            l.immed_container
                .map_or_else(|| "-".to_owned(), |h| h.get().to_string())
        );
    }
    s.push_str("T\n");
    s
}

/// Names of the hierarchy's nodes: `L<id>` for leaves, `S<n>` for structured
/// nodes in pre-order of the final hierarchy.
fn names(h: &Hierarchy) -> (Vec<NodeId>, std::collections::HashMap<NodeId, String>) {
    let mut order = Vec::new();
    let mut map = std::collections::HashMap::new();
    let mut next = 0;
    let mut stack: Vec<NodeId> = h.top_level().iter().rev().copied().collect();
    while let Some(n) = stack.pop() {
        order.push(n);
        let name = if h.kind(n) == Some(Kind::Copy) {
            format!("L{}", n.get())
        } else {
            next += 1;
            format!("S{}", next - 1)
        };
        map.insert(n, name);
        stack.extend(h.components(n).iter().rev().copied());
    }
    (order, map)
}

/// The `bkstruct` dump of `bk structure` for a structuring result.
pub(crate) fn struct_dump(res: &Result<Structured, CfgError>) -> String {
    let s = match res {
        Ok(s) => s,
        Err(e) => return format!("H\tbkstruct\t1\terror\t{e}\nT\n"),
    };
    let h = &s.hierarchy;
    let (order, names) = names(h);
    let name = |n: &NodeId| {
        names
            .get(n)
            .cloned()
            .unwrap_or_else(|| format!("?{}", n.get()))
    };
    let mut out = String::from("H\tbkstruct\t1\tok\t-\n");
    for g in &s.goto_edges {
        let _ = writeln!(
            out,
            "G\t{}\t{}\t{}\t{}",
            name(&g.source),
            g.slot,
            name(&g.target),
            g.cause.name()
        );
    }
    for f in &s.flips {
        let _ = writeln!(out, "F\t{}", name(f));
    }
    let _ = writeln!(out, "C\t{}", s.dataflow_changes);
    for n in &order {
        let kind = h.kind(*n).unwrap();
        let data = match kind {
            Kind::Goto | Kind::IfGoto => {
                let (t, ty) = h.goto_target(*n).unwrap();
                format!("{}:0x{ty:x}", name(&t))
            }
            Kind::MultiGoto => {
                let (ts, d) = h.multi_goto(*n).unwrap();
                format!(
                    "{}:{}",
                    list(ts.iter().map(name)),
                    if d { "default" } else { "-" }
                )
            }
            Kind::Condition => h.condition_op(*n).unwrap().name().to_owned(),
            Kind::WhileDo => if h.has_overflow_syntax(*n) {
                "overflow"
            } else {
                "-"
            }
            .to_owned(),
            Kind::Switch => list(h.cases(*n).iter().map(|c| {
                format!(
                    "{}:{}:{}:0x{:x}:{}:{}",
                    name(&c.block),
                    c.outindex,
                    c.chain,
                    c.gototype,
                    u8::from(c.isexit),
                    u8::from(c.isdefault)
                )
            })),
            _ => "-".to_owned(),
        };
        let edges = |v: Vec<bk_decomp_cfg::EdgeView>| {
            list(
                v.into_iter()
                    .map(|e| format!("{}:{}:0x{:x}", name(&e.node), e.rev, e.label)),
            )
        };
        let _ = writeln!(
            out,
            "S\t{}\t{}\t{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            name(n),
            kind.dump_name(),
            h.index(*n),
            h.flags(*n),
            h.structure_depth(*n),
            h.leaf_count(*n),
            h.parent(*n).map_or_else(|| "-".to_owned(), |p| name(&p)),
            list(h.components(*n).iter().map(name)),
            data,
            edges(h.in_edges(*n)),
            edges(h.out_edges(*n)),
        );
    }
    let _ = writeln!(out, "P\t{}", list(h.top_level().iter().map(name)));
    if let Some(trace) = &s.trace {
        for (i, r) in trace.iter().enumerate() {
            let _ = writeln!(out, "R\t{i}\t{}\t{}", r.rule, name(&r.node));
        }
    }
    out.push_str("T\n");
    out
}
