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
//! Unit tests of the structuring rules on hand-built graphs
//! (`docs/features/decomp-cfg.md` 6.1, 4.4–4.8). Graphs are written as
//! out-lists, `"1,2|3|3|"` meaning 0→1, 0→2, 1→3, 2→3 (out-slot order);
//! in-edges are in source order, as `structure blocks` documents give them.

mod support {
    pub(crate) mod graphgen;
}

use bk_decomp_cfg::{
    Analyse, BlockFacts, Cfg, CfgError, CondOp, Fact, GhidraGotoSelector, GotoCause, Kind, NodeId,
    Record, StructureOptions, Structured, edge_labels, node_flags, structure,
};
use rstest::rstest;

fn cfg(spec: &str) -> Cfg {
    let outs: Vec<Vec<usize>> = spec
        .split('|')
        .map(|p| {
            p.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().unwrap())
                .collect()
        })
        .collect();
    let mut c = Cfg::new();
    let ids: Vec<NodeId> = outs.iter().map(|_| c.add_node(0).unwrap()).collect();
    for (s, list) in outs.iter().enumerate() {
        for &t in list {
            c.add_edge(ids[s], ids[t]).unwrap();
        }
    }
    c.number_in_list_order().unwrap();
    c
}

fn run_with(c: &Cfg, facts: &BlockFacts) -> Result<Structured, CfgError> {
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        record: Record::Trace,
        ..StructureOptions::default()
    };
    structure(c, facts, &options, &mut GhidraGotoSelector::new())
}

fn run(spec: &str) -> Result<Structured, CfgError> {
    let c = cfg(spec);
    run_with(&c, &BlockFacts::neutral(c.id_bound()))
}

fn rules(s: &Structured) -> Vec<&'static str> {
    s.trace.as_ref().unwrap().iter().map(|r| r.rule).collect()
}

fn n(i: u32) -> NodeId {
    NodeId::new(i)
}

/// The kind of the single top-level node.
fn top_kind(s: &Structured) -> Kind {
    let top = s.hierarchy.top_level();
    assert_eq!(top.len(), 1, "one top-level node");
    s.hierarchy.kind(top[0]).unwrap()
}

#[rstest]
#[case::cat("1|2|3|", "blockcat")]
#[case::proper_if("1,2|2|", "blockproperif")]
#[case::if_else("1,2|3|3|", "blockifelse")]
#[case::while_do("1|2,3|1|", "blockwhiledo")]
#[case::do_while("1|1,2|", "blockdowhile")]
#[case::inf_loop("1|1", "blockinfloop")]
#[case::switch("1,2,3|4|4|4|", "blockswitch")]
#[case::if_no_exit("1,2||", "blockifnoexit")]
#[case::or("1,2|3,2|4|4|", "blockor")]
fn first_rule(#[case] spec: &str, #[case] rule: &str) {
    let c = cfg(spec);
    let mut facts = BlockFacts::neutral(c.id_bound());
    if rule == "blockor" {
        facts.set(
            1,
            Fact {
                complex: false,
                ..Fact::NEUTRAL
            },
        );
    }
    let s = run_with(&c, &facts).unwrap();
    let r = rules(&s);
    assert!(r.contains(&rule), "{rule} not in {r:?}");
}

#[test]
fn cat_takes_the_whole_chain() {
    let s = run("1|2|3|").unwrap();
    assert_eq!(rules(&s), ["blockcat"]);
    let top = s.hierarchy.top_level()[0];
    assert_eq!(s.hierarchy.kind(top), Some(Kind::List));
    assert_eq!(s.hierarchy.components(top), [n(0), n(1), n(2), n(3)]);
}

#[test]
fn cat_needs_single_entry_successor() {
    // 2 has two in-edges: the chain stops before it.
    let s = run("1,2|2|3|").unwrap();
    assert!(!rules(&s).starts_with(&["blockcat"]));
}

#[test]
fn or_needs_a_simple_second_block() {
    // Complex second block (the neutral fact): no condition is formed.
    let s = run("1,2|3,2|4|4|").unwrap();
    assert!(!rules(&s).contains(&"blockor"));
}

#[test]
fn or_creates_int_or() {
    let c = cfg("1,2|3,2|4|4|");
    let mut facts = BlockFacts::neutral(c.id_bound());
    facts.set(
        1,
        Fact {
            complex: false,
            ..Fact::NEUTRAL
        },
    );
    let s = run_with(&c, &facts).unwrap();
    let h = &s.hierarchy;
    let cond = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::Condition))
        .unwrap();
    // Created as INT_OR; negated afterwards when the if rule flips it.
    let op = h.condition_op(cond).unwrap();
    assert!(
        matches!(op, CondOp::IntOr | CondOp::BoolAnd | CondOp::BoolOr),
        "{op:?}"
    );
}

#[test]
fn proper_if_with_false_clause_negates() {
    // Clause on out-edge 0 (false): the condition is negated first.
    let c = cfg("1,2|2|");
    let mut facts = BlockFacts::neutral(c.id_bound());
    facts.set(
        0,
        Fact {
            negation_changes_dataflow: true,
            ..Fact::NEUTRAL
        },
    );
    let s = run_with(&c, &facts).unwrap();
    assert_eq!(s.flips, [n(0)]);
    assert_eq!(s.dataflow_changes, 1);
    assert_eq!(top_kind(&s), Kind::List);
}

#[test]
fn proper_if_with_true_clause_does_not_negate() {
    let s = run("2,1|2|").unwrap();
    assert!(s.flips.is_empty());
    assert_eq!(s.dataflow_changes, 0);
}

#[test]
fn neutral_negation_changes_no_dataflow() {
    let s = run("1,2|2|").unwrap();
    assert_eq!(s.flips, [n(0)]);
    assert_eq!(s.dataflow_changes, 0);
}

#[rstest]
#[case::complex_head(true)]
#[case::simple_head(false)]
fn while_do_overflow_follows_complexity(#[case] complex: bool) {
    let c = cfg("1|2,3|1|");
    let mut facts = BlockFacts::neutral(c.id_bound());
    facts.set(
        1,
        Fact {
            complex,
            ..Fact::NEUTRAL
        },
    );
    let s = run_with(&c, &facts).unwrap();
    let h = &s.hierarchy;
    let w = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::WhileDo))
        .unwrap();
    assert_eq!(h.has_overflow_syntax(w), complex);
}

#[test]
fn input_goto_label_makes_a_goto_node() {
    let mut c = cfg("1|2|");
    c.set_out_edge_label(n(0), 0, edge_labels::GOTO).unwrap();
    let s = run_with(&c, &BlockFacts::neutral(3)).unwrap();
    assert_eq!(rules(&s)[0], "blockgoto");
    let h = &s.hierarchy;
    let gotos: Vec<_> = (0..h.node_count() as u32)
        .map(n)
        .filter(|&x| h.kind(x) == Some(Kind::Goto))
        .collect();
    assert_eq!(gotos.len(), 1);
    assert_eq!(h.goto_target(gotos[0]).unwrap().1, node_flags::GOTO_GOTO);
    assert_eq!(s.measure.input_gotos, 1);
}

#[test]
fn goto_on_false_branch_negates_and_makes_if_goto() {
    let mut c = cfg("1,2|3|3|");
    c.set_out_edge_label(n(0), 0, edge_labels::GOTO).unwrap();
    let s = run_with(&c, &BlockFacts::neutral(4)).unwrap();
    assert_eq!(rules(&s)[0], "blockgoto");
    assert_eq!(s.flips, [n(0)]);
    let h = &s.hierarchy;
    assert!(
        (0..h.node_count() as u32)
            .map(n)
            .any(|x| h.kind(x) == Some(Kind::IfGoto))
    );
}

#[test]
fn goto_on_switch_makes_multigoto() {
    let mut c = cfg("1,2,3|4|4|4|");
    c.set_out_edge_label(n(0), 1, edge_labels::GOTO).unwrap();
    let s = run_with(&c, &BlockFacts::neutral(5)).unwrap();
    assert_eq!(rules(&s)[0], "blockgoto");
    let h = &s.hierarchy;
    let m = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::MultiGoto))
        .unwrap();
    assert_eq!(h.multi_goto(m).unwrap().0.len(), 1);
}

#[test]
fn switch_skip_marks_gotos_without_building() {
    // Default edge (slot 0) to a case, a non-default edge straight to the
    // exit 4: the skip edge becomes a goto and the rule reports applied.
    let mut c = cfg("1,2,3,4|4|4|4|");
    c.set_default_switch(n(0), 0).unwrap();
    let s = run_with(&c, &BlockFacts::neutral(5)).unwrap();
    let r = rules(&s);
    assert_eq!(r[0], "blockswitch");
    assert_eq!(r[1], "blockgoto", "the marked edge is consumed next: {r:?}");
    assert_eq!(s.goto_edges.len(), 1);
    assert_eq!(s.goto_edges[0].cause, GotoCause::SwitchSkip);
    assert_eq!(s.goto_edges[0].source, n(0));
    assert_eq!(s.goto_edges[0].slot, 3);
    assert_eq!(s.measure.goto_marks.switch_skip, 1);
}

#[test]
fn case_fallthru_marks_gotos() {
    // Case 1 falls through to case 2.
    let s = run("1,2,3|2|4|4|").unwrap();
    let r = rules(&s);
    assert!(r.contains(&"casefallthru"), "{r:?}");
    assert!(
        s.goto_edges
            .iter()
            .any(|g| g.cause == GotoCause::CaseFallthru && g.source == n(1))
    );
    let h = &s.hierarchy;
    let sw = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::Switch))
        .unwrap();
    let chained: Vec<i32> = h.cases(sw).iter().map(|c| c.chain).collect();
    assert!(chained.contains(&1), "case 0 chains to case 1: {chained:?}");
}

#[test]
fn selected_goto_cuts_an_unreachable_loop() {
    // The cycle 1 <-> 2 is unreachable from 0: its loop body's likely gotos
    // are traced, and the back edge 2 -> 1 is chosen.
    let s = run("|2|1").unwrap();
    assert_eq!(s.goto_edges.len(), 1);
    assert_eq!(s.goto_edges[0].cause, GotoCause::Selected);
    assert_eq!(
        (s.goto_edges[0].source, s.goto_edges[0].target),
        (n(2), n(1))
    );
    assert_eq!(rules(&s), ["blockgoto", "blockcat"]);
    assert_eq!(s.measure.goto_marks.total() as usize, s.goto_edges.len());
}

/// The five reachable graphs of `gen_graphs.py 1 3000 40` on which Ghidra
/// ends with "Could not finish collapsing block structure"
/// (`docs/research/decomp-wave1/runs.md` R3): g00199, g01606, g01781,
/// g02290, g02747.
#[rstest]
#[case("1,4|5,5|5,5|2,2|2,3|")]
#[case("2,2,0,1,5,3|3|4,4|3,1,5|5|1")]
#[case("5,4,11,2,14,15|12||4,6|9|10,13|8|15|16,11|6,4|7|16|8|8,8|6,3,2,3,1,17|16|10|6,1")]
#[case("3|3,6|8|7|5|9|0|8,5,4,4,1,2|10||1,3")]
#[case("6,3,6,4,1|5,2|1|4,6,4,4,2|0,4|1|")]
fn reachable_graphs_ghidra_cannot_finish(#[case] spec: &str) {
    assert_eq!(run(spec).unwrap_err(), CfgError::CouldNotFinish);
}

/// A function-like graph on which Ghidra's `TraceDAG::pushBranches` never
/// ends (the reference console was killed after 10 s; Basilisk stops).
#[test]
fn endless_trace_is_an_error() {
    let g = support::graphgen::generate(support::graphgen::Class::Func, 530, 40, false);
    let c = g.to_cfg();
    let r = run_with(&c, &BlockFacts::neutral(c.id_bound()));
    assert_eq!(r.unwrap_err(), CfgError::TraceCycle);
}

#[test]
fn input_is_untouched_and_results_repeat() {
    let c = cfg("1,2|3|3,4|1|");
    let before = format!("{c:?}");
    let a = run_with(&c, &BlockFacts::neutral(5)).unwrap();
    let b = run_with(&c.clone(), &BlockFacts::neutral(5)).unwrap();
    assert_eq!(format!("{c:?}"), before);
    assert_eq!(format!("{:?}", a.hierarchy), format!("{:?}", b.hierarchy));
    assert_eq!(a.flips, b.flips);
    assert_eq!(a.goto_edges, b.goto_edges);
}

#[test]
fn as_given_equals_recompute_after_analysis() {
    let c = cfg("1,2|3|3,4|1|5|");
    let facts = BlockFacts::neutral(6);
    let rec = run_with(&c, &facts).unwrap();
    let mut a = c.clone();
    let roots = a.structure_loops().unwrap();
    a.forward_dominators(&roots).unwrap();
    let options = StructureOptions {
        record: Record::Trace,
        ..StructureOptions::default()
    };
    let given = structure(&a, &facts, &options, &mut GhidraGotoSelector::new()).unwrap();
    assert_eq!(format!("{:?}", rec.trace), format!("{:?}", given.trace));
    assert_eq!(rec.flips, given.flips);
}

#[test]
fn empty_graph_structures_to_nothing() {
    let c = Cfg::new();
    let s = run_with(&c, &BlockFacts::neutral(0)).unwrap();
    assert!(s.hierarchy.top_level().is_empty());
}

#[test]
fn single_node() {
    let s = run("").unwrap();
    assert_eq!(top_kind(&s), Kind::Copy);
    assert_eq!(s.measure.leaves, 1);
}
