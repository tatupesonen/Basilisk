#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]
//! Properties of the analyses and the structurer on generated graphs of all
//! four classes (`docs/features/decomp-cfg.md` 6.5). The case count follows
//! `PROPTEST_CASES`.

mod support {
    pub(crate) mod graphgen;
}

use bk_decomp_cfg::{
    Analyse, BlockFacts, Cfg, CfgError, GhidraGotoSelector, Hierarchy, Kind, LimitKind, NodeId,
    Record, StructureOptions, Structured, edge_labels, finish, structure,
};
use proptest::prelude::*;
use support::graphgen::{Class, generate};

fn bare(c: &Cfg, facts: &BlockFacts, record: Record) -> Result<Structured, CfgError> {
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        record,
        ..StructureOptions::default()
    };
    structure(c, facts, &options, &mut GhidraGotoSelector::new())
}

fn class_of(i: u8) -> Class {
    Class::ALL[usize::from(i) % 4]
}

/// Ghidra's own errors that generated graphs reach, and Basilisk's error
/// for Ghidra's endless trace. Anything else is a bug. (`CaseDetached`
/// needs input default-switch labels: a multigoto can collect a goto to
/// itself through the self-edge `forceOutputNum` adds, and `addCase` finds
/// no edge from the switch block to its own original.)
fn expected_error(e: &CfgError) -> bool {
    matches!(
        e,
        CfgError::CouldNotFinish | CfgError::TraceCycle | CfgError::CaseDetached
    )
}

fn check_hierarchy(h: &Hierarchy, inputs: &[NodeId]) {
    assert!(h.edges_consistent());
    let mut seen = vec![0u32; h.node_count()];
    let mut stack: Vec<NodeId> = h.top_level().to_vec();
    for &t in h.top_level() {
        assert!(h.parent(t).is_none());
        assert!(
            h.in_edges(t).is_empty() && h.out_edges(t).is_empty(),
            "top-level node {t} not isolated"
        );
    }
    while let Some(x) = stack.pop() {
        seen[x.index()] += 1;
        for &c in h.components(x) {
            assert_eq!(h.parent(c), Some(x));
            stack.push(c);
        }
    }
    for &i in inputs {
        assert_eq!(h.kind(i), Some(Kind::Copy));
        assert_eq!(
            seen[i.index()],
            1,
            "leaf {i} appears {} times",
            seen[i.index()]
        );
    }
}

/// Whether the graph without loop-labelled edges is acyclic (Kahn).
fn loop_edges_cut_cycles(c: &Cfg) -> bool {
    let nodes = c.nodes();
    let mut indeg = vec![0usize; c.id_bound()];
    for &x in nodes {
        for e in c.out_edges(x) {
            if e.label & edge_labels::LOOP == 0 {
                indeg[e.node.index()] += 1;
            }
        }
    }
    let mut queue: Vec<NodeId> = nodes
        .iter()
        .copied()
        .filter(|x| indeg[x.index()] == 0)
        .collect();
    let mut done = 0;
    while let Some(x) = queue.pop() {
        done += 1;
        for e in c.out_edges(x) {
            if e.label & edge_labels::LOOP == 0 {
                indeg[e.node.index()] -= 1;
                if indeg[e.node.index()] == 0 {
                    queue.push(e.node);
                }
            }
        }
    }
    done == nodes.len()
}

/// Naive dominator sets from `root` by iteration; the immediate dominator of
/// each reachable node.
fn naive_idoms(c: &Cfg, root: NodeId) -> Vec<Option<NodeId>> {
    let n = c.id_bound();
    let all: Vec<bool> = vec![true; n];
    let mut dom: Vec<Vec<bool>> = vec![all; n];
    let mut reach = vec![false; n];
    let mut stack = vec![root];
    reach[root.index()] = true;
    while let Some(x) = stack.pop() {
        for e in c.out_edges(x) {
            if !reach[e.node.index()] {
                reach[e.node.index()] = true;
                stack.push(e.node);
            }
        }
    }
    dom[root.index()] = (0..n).map(|i| i == root.index()).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for &x in c.nodes() {
            if x == root || !reach[x.index()] {
                continue;
            }
            let mut d: Vec<bool> = vec![true; n];
            for e in c.in_edges(x) {
                if reach[e.node.index()] {
                    for i in 0..n {
                        d[i] &= dom[e.node.index()][i];
                    }
                }
            }
            d[x.index()] = true;
            if d != dom[x.index()] {
                dom[x.index()] = d;
                changed = true;
            }
        }
    }
    (0..n)
        .map(|x| {
            if x == root.index() || !reach[x] {
                return None;
            }
            // The strict dominator with the most dominators of its own.
            (0..n)
                .filter(|&d| d != x && dom[x][d])
                .max_by_key(|&d| dom[d].iter().filter(|&&b| b).count())
                .map(|d| NodeId::new(d as u32))
        })
        .collect()
}

proptest! {
    #[test]
    fn structuring(class in 0u8..4, seed in any::<u64>(), max in 1usize..=64, facts in any::<bool>()) {
        let g = generate(class_of(class), seed, max, facts);
        let c = g.to_cfg();
        let f = g.block_facts();
        let before = format!("{c:?}");
        let a = bare(&c, &f, Record::Trace);
        let b = bare(&c.clone(), &f, Record::Trace);
        prop_assert_eq!(format!("{c:?}"), before, "input changed");
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"), "not repeatable");
        match a {
            Ok(mut s) => {
                check_hierarchy(&s.hierarchy, c.nodes());
                prop_assert_eq!(s.measure.goto_marks.total() as usize, s.goto_edges.len());
                finish(&mut s.hierarchy, &f, None);
                check_hierarchy(&s.hierarchy, c.nodes());
            }
            Err(e) => prop_assert!(expected_error(&e), "unexpected error {e:?}"),
        }
        // As given after the same analysis: the same result.
        let mut analysed = c.clone();
        let roots = analysed.structure_loops();
        prop_assert!(!matches!(roots, Err(CfgError::SpanningTreeRebuild)));
        if let Ok(roots) = roots {
            prop_assert!(loop_edges_cut_cycles(&analysed), "loop edges leave a cycle");
            analysed.forward_dominators(&roots).unwrap();
            let given = structure(&analysed, &f, &StructureOptions { record: Record::Trace, ..StructureOptions::default() }, &mut GhidraGotoSelector::new());
            let rec = bare(&c, &f, Record::Trace);
            prop_assert_eq!(
                given.as_ref().map(|s| (&s.trace, &s.flips, &s.goto_edges)).map_err(Clone::clone),
                rec.as_ref().map(|s| (&s.trace, &s.flips, &s.goto_edges)).map_err(Clone::clone)
            );
        }
    }

    #[test]
    fn dominators_of_function_like_graphs(seed in any::<u64>(), max in 1usize..=64) {
        let g = generate(Class::Func, seed, max, false);
        let mut c = g.to_cfg();
        let roots = c.structure_loops().unwrap();
        c.forward_dominators(&roots).unwrap();
        let naive = naive_idoms(&c, NodeId::new(0));
        for &x in c.nodes() {
            prop_assert_eq!(c.idom(x), naive[x.index()], "idom of {}", x);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn large_graphs_finish_within_limits(class in 0u8..4, seed in any::<u64>()) {
        let g = generate(class_of(class), seed, 1000, true);
        let c = g.to_cfg();
        match bare(&c, &g.block_facts(), Record::None) {
            Ok(s) => check_hierarchy(&s.hierarchy, c.nodes()),
            Err(CfgError::LimitExceeded { what, .. }) => prop_assert!(what != LimitKind::Steps, "step limit on {} nodes", c.len()),
            Err(e) => prop_assert!(expected_error(&e), "unexpected error {e:?}"),
        }
    }
}
