//! Seeded random control-flow graphs (`docs/features/decomp-cfg.md` 6.2,
//! 6.3.1), from a `rand_chacha` stream so that a graph is named by its class
//! and seed alone. Only `u32` ranges and `f64` draws are used, which `rand`
//! produces identically on every platform.
//!
//! Classes: `func` (function-like: every node reachable from node 0, node 0
//! without in-edges, no two out-edges of one node to one target), `arb`
//! (anything: multi-edges, self-loops, unreachable parts, in-edges to node
//! 0), `red` (built from nested structured statements, gotos included),
//! `irr` (a structured graph plus cross edges into loop bodies).

#![allow(dead_code, reason = "each test binary uses a part")]

use bk_decomp_cfg::{BlockFacts, Cfg, Fact, NodeId, edge_labels};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// A generator class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Class {
    Func,
    Arb,
    Red,
    Irr,
}

impl Class {
    pub(crate) const ALL: [Self; 4] = [Self::Func, Self::Arb, Self::Red, Self::Irr];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Func => "func",
            Self::Arb => "arb",
            Self::Red => "red",
            Self::Irr => "irr",
        }
    }

    pub(crate) fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// A generated graph: out-lists, in-edge order, labels and facts.
#[derive(Clone, Debug, Default)]
pub(crate) struct GenGraph {
    /// `outs[n]` = targets of `n` in out-slot order.
    pub(crate) outs: Vec<Vec<usize>>,
    /// `ins[n]` = (source, out-slot) in in-edge order.
    pub(crate) ins: Vec<Vec<(usize, usize)>>,
    /// Input labels of out-edges, parallel to `outs`.
    pub(crate) labels: Vec<Vec<u32>>,
    pub(crate) facts: Vec<Fact>,
}

fn below(rng: &mut ChaCha8Rng, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    rng.gen_range(0..n as u32) as usize
}

fn chance(rng: &mut ChaCha8Rng, p: f64) -> bool {
    rng.r#gen::<f64>() < p
}

impl GenGraph {
    fn with_nodes(n: usize) -> Self {
        Self {
            outs: vec![Vec::new(); n],
            ins: Vec::new(),
            labels: Vec::new(),
            facts: vec![Fact::NEUTRAL; n],
        }
    }

    fn add_node(&mut self) -> usize {
        self.outs.push(Vec::new());
        self.facts.push(Fact::NEUTRAL);
        self.outs.len() - 1
    }

    /// Derives `ins` in source-major order (as `gen_graphs.py` does), then
    /// optionally shuffles each in-list; labels default to 0.
    fn finish(&mut self, rng: Option<&mut ChaCha8Rng>) {
        let n = self.outs.len();
        self.ins = vec![Vec::new(); n];
        for (s, list) in self.outs.iter().enumerate() {
            for (slot, &t) in list.iter().enumerate() {
                self.ins[t].push((s, slot));
            }
        }
        if let Some(rng) = rng {
            for list in &mut self.ins {
                for i in (1..list.len()).rev() {
                    let j = below(rng, i + 1);
                    list.swap(i, j);
                }
            }
        }
        self.labels.resize(n, Vec::new());
        for (l, o) in self.labels.iter_mut().zip(&self.outs) {
            l.resize(o.len(), 0);
        }
    }

    /// The graph as a [`Cfg`], indices `0..n` in node order.
    pub(crate) fn to_cfg(&self) -> Cfg {
        let mut cfg = Cfg::new();
        let ids: Vec<NodeId> = (0..self.outs.len())
            .map(|_| cfg.add_node(0).unwrap())
            .collect();
        for (t, list) in self.ins.iter().enumerate() {
            for &(s, slot) in list {
                let label = self
                    .labels
                    .get(s)
                    .and_then(|l| l.get(slot))
                    .copied()
                    .unwrap_or(0);
                cfg.add_edge_at(ids[s], slot, ids[t], label).unwrap();
            }
        }
        cfg.check_slots().unwrap();
        cfg.number_in_list_order().unwrap();
        cfg
    }

    /// The facts table.
    pub(crate) fn block_facts(&self) -> BlockFacts {
        BlockFacts::from_vec(self.facts.clone())
    }

    /// The graph in the XML `structure blocks` reads (labels and facts are
    /// not representable there).
    pub(crate) fn to_xml(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::from("<block index=\"0\">\n");
        for i in 0..self.outs.len() {
            let _ = writeln!(s, "<bhead index=\"{i}\" type=\"plain\"/>");
        }
        for (i, list) in self.ins.iter().enumerate() {
            let _ = write!(s, "<block index=\"{i}\">");
            for &(src, slot) in list {
                let _ = write!(s, "<edge end=\"{src}\" rev=\"{slot}\"/>");
            }
            s.push_str("</block>\n");
        }
        s.push_str("</block>\n");
        s
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.outs.iter().map(Vec::len).sum()
    }
}

fn degree(rng: &mut ChaCha8Rng) -> usize {
    let r = rng.r#gen::<f64>();
    if r < 0.1 {
        0
    } else if r < 0.55 {
        1
    } else if r < 0.9 {
        2
    } else {
        3 + below(rng, 4)
    }
}

fn gen_arb(rng: &mut ChaCha8Rng, n: usize) -> GenGraph {
    let mut g = GenGraph::with_nodes(n);
    for out in &mut g.outs {
        let k = degree(rng);
        *out = (0..k).map(|_| below(rng, n)).collect();
    }
    g.finish(Some(rng));
    g
}

fn gen_func(rng: &mut ChaCha8Rng, n: usize) -> GenGraph {
    let mut g = GenGraph::with_nodes(n);
    // A random order of the nodes 1..n so ids do not follow the tree.
    let mut order: Vec<usize> = (1..n).collect();
    for i in (1..order.len()).rev() {
        let j = below(rng, i + 1);
        order.swap(i, j);
    }
    let mut placed = vec![0usize];
    for &v in &order {
        let p = placed[below(rng, placed.len())];
        g.outs[p].push(v);
        placed.push(v);
    }
    for out in &mut g.outs {
        let want = degree(rng);
        let mut tries = 0;
        while out.len() < want && tries < 4 * n + 8 {
            tries += 1;
            let t = below(rng, n);
            if t == 0 || out.contains(&t) {
                continue;
            }
            out.push(t);
        }
        for a in (1..out.len()).rev() {
            let b = below(rng, a + 1);
            out.swap(a, b);
        }
    }
    g.finish(Some(rng));
    g
}

/// A statement of the structured generator.
enum Stmt {
    Basic,
    Seq(Vec<Self>),
    If(Box<Self>),
    IfElse(Box<Self>, Box<Self>),
    While(Box<Self>),
    DoWhile(Box<Self>),
    Switch(Vec<(Self, bool)>),
    Break,
    Continue,
    Return,
    Goto,
}

fn gen_stmt(rng: &mut ChaCha8Rng, depth: u32, budget: &mut i32, in_loop: bool) -> Stmt {
    gen_stmt_with(rng, depth, budget, in_loop, false)
}

/// `clean`: no `break`, `continue`, `return` or goto, so that every node is
/// reachable and the graph structures without gotos.
fn gen_stmt_with(
    rng: &mut ChaCha8Rng,
    depth: u32,
    budget: &mut i32,
    in_loop: bool,
    clean: bool,
) -> Stmt {
    *budget -= 1;
    if *budget <= 0 || depth > 5 {
        return Stmt::Basic;
    }
    let r = below(rng, 100);
    match r {
        0..=24 => {
            let k = 2 + below(rng, 3);
            Stmt::Seq(
                (0..k)
                    .map(|_| gen_stmt_with(rng, depth + 1, budget, in_loop, clean))
                    .collect(),
            )
        }
        25..=37 => Stmt::If(Box::new(gen_stmt_with(
            rng,
            depth + 1,
            budget,
            in_loop,
            clean,
        ))),
        38..=49 => Stmt::IfElse(
            Box::new(gen_stmt_with(rng, depth + 1, budget, in_loop, clean)),
            Box::new(gen_stmt_with(rng, depth + 1, budget, in_loop, clean)),
        ),
        50..=57 => Stmt::While(Box::new(gen_stmt_with(rng, depth + 1, budget, true, clean))),
        58..=64 => Stmt::DoWhile(Box::new(gen_stmt_with(rng, depth + 1, budget, true, clean))),
        65..=70 => {
            let k = 3 + below(rng, 4);
            Stmt::Switch(
                (0..k)
                    .map(|_| {
                        (
                            gen_stmt_with(rng, depth + 1, budget, in_loop, clean),
                            chance(rng, 0.25),
                        )
                    })
                    .collect(),
            )
        }
        71..=74 if in_loop && !clean => Stmt::Break,
        75..=77 if in_loop && !clean => Stmt::Continue,
        78..=80 if !clean => Stmt::Return,
        81..=82 if !clean => Stmt::Goto,
        _ => Stmt::Basic,
    }
}

struct Lower<'r> {
    g: GenGraph,
    rng: &'r mut ChaCha8Rng,
    exit: usize,
    /// Pending gotos: sources that need a target once all nodes exist.
    gotos: Vec<usize>,
}

impl Lower<'_> {
    fn edge(&mut self, from: usize, to: usize) {
        self.g.outs[from].push(to);
    }

    /// Lowers `s` so that it continues at `next`; returns its entry.
    fn lower(&mut self, s: &Stmt, next: usize, brk: Option<usize>, cont: Option<usize>) -> usize {
        match s {
            Stmt::Basic => {
                let b = self.g.add_node();
                self.edge(b, next);
                b
            }
            Stmt::Seq(list) => {
                let mut entry = next;
                for st in list.iter().rev() {
                    entry = self.lower(st, entry, brk, cont);
                }
                entry
            }
            Stmt::If(t) => {
                let c = self.g.add_node();
                let te = self.lower(t, next, brk, cont);
                self.edge(c, next);
                self.edge(c, te);
                c
            }
            Stmt::IfElse(t, e) => {
                let c = self.g.add_node();
                let te = self.lower(t, next, brk, cont);
                let ee = self.lower(e, next, brk, cont);
                self.edge(c, ee);
                self.edge(c, te);
                c
            }
            Stmt::While(body) => {
                let head = self.g.add_node();
                let be = self.lower(body, head, Some(next), Some(head));
                self.edge(head, next);
                self.edge(head, be);
                head
            }
            Stmt::DoWhile(body) => {
                let test = self.g.add_node();
                let be = self.lower(body, test, Some(next), Some(test));
                self.edge(test, next);
                self.edge(test, be);
                be
            }
            Stmt::Switch(cases) => {
                let sw = self.g.add_node();
                let mut follow = next;
                let mut entries = Vec::new();
                for (st, fallthrough) in cases.iter().rev() {
                    let target = if *fallthrough { follow } else { next };
                    let e = self.lower(st, target, Some(next), cont);
                    entries.push(e);
                    follow = e;
                }
                entries.reverse();
                for e in entries {
                    self.edge(sw, e);
                }
                if chance(self.rng, 0.5) {
                    self.edge(sw, next);
                }
                sw
            }
            Stmt::Break => brk.unwrap_or(next),
            Stmt::Continue => cont.unwrap_or(next),
            Stmt::Return => {
                let b = self.g.add_node();
                self.edge(b, self.exit);
                b
            }
            Stmt::Goto => {
                let b = self.g.add_node();
                self.gotos.push(b);
                b
            }
        }
    }
}

/// A structured graph of at most about `size` nodes; returns the graph and
/// the loop bodies' node ranges (for the `irr` class).
fn gen_red_raw(rng: &mut ChaCha8Rng, size: usize) -> GenGraph {
    let mut budget = (size as i32 / 2).max(1);
    let body = gen_stmt(rng, 0, &mut budget, false);
    let mut g = GenGraph::default();
    let entry_stub = g.add_node();
    let exit = g.add_node();
    let mut low = Lower {
        g,
        rng,
        exit,
        gotos: Vec::new(),
    };
    let first = low.lower(&body, exit, None, None);
    low.edge(entry_stub, first);
    let n = low.g.outs.len();
    for b in std::mem::take(&mut low.gotos) {
        let t = 1 + below(low.rng, n - 1);
        low.edge(b, t);
    }
    let mut g = low.g;
    // Two out-edges of one node to one target appear when a branch body
    // is empty (a break or continue); they are kept: Ghidra's basic-block
    // graphs have them too after edits.
    g.finish(None);
    g
}

fn gen_irr(rng: &mut ChaCha8Rng, size: usize) -> GenGraph {
    let mut g = gen_red_raw(rng, size);
    let n = g.outs.len();
    let extra = 1 + below(rng, 3);
    for _ in 0..extra {
        let s = below(rng, n);
        let t = 1 + below(rng, n - 1);
        g.outs[s].push(t);
    }
    g.finish(None);
    g
}

/// Random facts and input labels on about 10 % of graphs
/// (`docs/features/decomp-cfg.md` 6.3.1).
fn add_facts(rng: &mut ChaCha8Rng, g: &mut GenGraph) {
    for i in 0..g.outs.len() {
        g.facts[i].complex = chance(rng, 0.5);
        if g.outs[i].is_empty() {
            g.facts[i].ends_in_return = chance(rng, 0.7);
        }
        g.facts[i].negation_changes_dataflow = true;
    }
    for i in 0..g.outs.len() {
        for slot in 0..g.outs[i].len() {
            if chance(rng, 0.05) {
                g.labels[i][slot] |= edge_labels::GOTO;
            }
        }
        if g.outs[i].len() > 2 && chance(rng, 0.5) {
            let slot = below(rng, g.outs[i].len());
            g.labels[i][slot] |= edge_labels::DEFAULT_SWITCH;
        }
    }
}

/// The graph of `class` and `seed`, of 1 to `max_nodes` nodes (roughly, for
/// the structured classes). With `facts`, about 10 % of graphs get random
/// facts and labels.
pub(crate) fn generate(class: Class, seed: u64, max_nodes: usize, facts: bool) -> GenGraph {
    let mut rng =
        ChaCha8Rng::seed_from_u64(seed ^ (class as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let n = 1 + below(&mut rng, max_nodes);
    let mut g = match class {
        Class::Func => gen_func(&mut rng, n),
        Class::Arb => gen_arb(&mut rng, n),
        Class::Red => gen_red_raw(&mut rng, n),
        Class::Irr => gen_irr(&mut rng, n),
    };
    if facts && chance(&mut rng, 0.1) {
        add_facts(&mut rng, &mut g);
    }
    g
}

/// A function-like graph of exactly `n` nodes (benchmarks).
pub(crate) fn generate_func_sized(seed: u64, n: usize) -> GenGraph {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    gen_func(&mut rng, n)
}

/// A large structured graph of about `nodes` nodes (benchmarks).
pub(crate) fn generate_large_reducible(seed: u64, nodes: usize) -> GenGraph {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let parts: Vec<Stmt> = (0..(nodes / 40).max(1))
        .map(|_| {
            let mut budget = 80;
            gen_stmt_with(&mut rng, 0, &mut budget, false, true)
        })
        .collect();
    let mut big = GenGraph::default();
    let e = big.add_node();
    let exit = big.add_node();
    let mut low = Lower {
        g: big,
        rng: &mut rng,
        exit,
        gotos: Vec::new(),
    };
    let mut next = exit;
    for p in parts.iter().rev() {
        next = low.lower(p, next, None, None);
    }
    low.edge(e, next);
    let n = low.g.outs.len();
    for b in std::mem::take(&mut low.gotos) {
        let t = 1 + below(low.rng, n - 1);
        low.edge(b, t);
    }
    let mut g = low.g;
    g.finish(None);
    g
}
