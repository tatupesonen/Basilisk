//! Unit tests of edge surgery, identification, the factories' edge order
//! and negation (`docs/features/decomp-cfg.md` 4.4, 4.5, 6.1).

use crate::error::CfgError;
use crate::facts::{BlockFacts, Fact};
use crate::flags::{CondOp, Kind, edge_labels, node_flags};
use crate::graph::{Edge, Graph, KindData, Node, NodeId};

fn n(i: u32) -> NodeId {
    NodeId::new(i)
}

/// A working graph of `k` copies with the given edges, in order.
fn graph(k: u32, edges: &[(u32, u32)]) -> Graph {
    let mut g = Graph::default();
    for i in 0..k {
        let mut node = Node::new(Kind::Copy);
        node.index = i as i32;
        let id = g.push(node).unwrap();
        g.add_block_root(id);
    }
    for &(a, b) in edges {
        g.add_in_edge(n(b), n(a), 0).unwrap();
    }
    g
}

fn outs(g: &Graph, x: u32) -> Vec<u32> {
    g.node(n(x)).outs.iter().map(|e| e.other.get()).collect()
}

fn ins(g: &Graph, x: u32) -> Vec<u32> {
    g.node(n(x)).ins.iter().map(|e| e.other.get()).collect()
}

fn consistent(g: &Graph) -> bool {
    (0..g.nodes.len() as u32).all(|i| g.edges_consistent(n(i)))
}

#[test]
fn sizes() {
    assert_eq!(std::mem::size_of::<Edge>(), 12);
    assert!(std::mem::size_of::<Node>() <= 168, "{}", std::mem::size_of::<Node>());
}

#[test]
fn half_delete_shifts_and_fixes_reverse_indices() {
    let mut g = graph(4, &[(0, 3), (1, 3), (2, 3)]);
    g.remove_in_edge(n(3), 0).unwrap();
    assert_eq!(ins(&g, 3), [1, 2]);
    assert!(consistent(&g));
    assert!(outs(&g, 0).is_empty());
}

#[test]
fn replace_keeps_slot_and_appends_on_new_end() {
    let mut g = graph(4, &[(0, 1), (0, 2)]);
    g.replace_out_edge(n(0), 0, n(3)).unwrap();
    assert_eq!(outs(&g, 0), [3, 2]);
    assert_eq!(ins(&g, 3), [0]);
    assert!(ins(&g, 1).is_empty());
    assert!(consistent(&g));
}

#[test]
fn swap_edges_toggles_flip_path() {
    let mut g = graph(3, &[(0, 1), (0, 2)]);
    g.swap_edges(n(0)).unwrap();
    assert_eq!(outs(&g, 0), [2, 1]);
    assert_ne!(g.node(n(0)).flags & node_flags::FLIP_PATH, 0);
    assert!(consistent(&g));
    assert_eq!(g.swap_edges(n(1)), Err(CfgError::SwapEdges));
}

#[test]
fn dedup_merges_labels_into_one_half_only() {
    // Two edges 0 -> 1; the second labelled back. eliminateInDups ORs the
    // label into the kept in-half only (block.cc:463).
    let mut g = graph(2, &[(0, 1), (0, 1)]);
    g.set_out_edge_flag(n(0), 1, edge_labels::BACK).unwrap();
    let mut scratch = Vec::new();
    g.dedup(n(1), &mut scratch).unwrap();
    assert_eq!(ins(&g, 1), [0]);
    assert_eq!(g.node(n(1)).ins[0].label, edge_labels::BACK);
    assert_eq!(g.node(n(0)).outs[0].label, 0);
    assert!(consistent(&g));
}

#[test]
fn force_output_num_adds_loop_back_self_edges() {
    let mut g = graph(1, &[]);
    g.force_output_num(n(0), 2).unwrap();
    assert_eq!(outs(&g, 0), [0, 0]);
    assert!(g.node(n(0)).outs.iter().all(|e| e.label == edge_labels::LOOP | edge_labels::BACK));
    // More outputs than asked: nothing happens (release behaviour).
    g.force_output_num(n(0), 1).unwrap();
    assert_eq!(outs(&g, 0).len(), 2);
}

#[test]
fn force_false_edge_swaps_or_fails() {
    let mut g = graph(3, &[(0, 1), (0, 2)]);
    g.force_false_edge(n(0), Some(n(2))).unwrap();
    assert_eq!(outs(&g, 0), [2, 1]);
    assert_eq!(g.force_false_edge(n(0), Some(n(0))), Err(CfgError::PreserveCondition));
    let mut g = graph(2, &[(0, 1)]);
    assert_eq!(g.force_false_edge(n(0), Some(n(1))), Err(CfgError::BinaryCondition));
}

#[test]
fn identify_appends_and_redirects_in_order() {
    // 0 -> 1 -> 2 -> 3, 0 -> 3: collapse [1, 2].
    let mut g = graph(4, &[(0, 1), (1, 2), (2, 3), (0, 3)]);
    let mut scratch = Vec::new();
    let s = g.new_block_list(&[n(1), n(2)], &mut scratch).unwrap();
    assert_eq!(g.list, [n(0), n(3), s]);
    assert_eq!(outs(&g, 0), [s.get(), 3], "the slot on the outside node is kept");
    assert_eq!(outs(&g, s.get()), [3]);
    assert_eq!(ins(&g, 3), [s.get(), 0], "the target keeps the slot (replaceInEdge)");
    assert_eq!(g.node(s).index, 1);
    assert_eq!(g.node(s).leaf_count, 2);
    assert_eq!(g.node(s).depth, 1);
    assert_eq!(g.node(n(1)).parent, Some(s));
    assert!(consistent(&g));
}

#[test]
fn identify_rejects_a_nested_node() {
    let mut g = graph(3, &[(0, 1), (1, 2)]);
    let mut scratch = Vec::new();
    g.new_block_list(&[n(0), n(1)], &mut scratch).unwrap();
    assert_eq!(g.new_block_list(&[n(1)], &mut scratch), Err(CfgError::BlockIdentify));
}

#[test]
fn condition_opcode_sequence() {
    // b1's false out is b2: INT_OR; then negation toggles BOOL_AND, BOOL_OR.
    let mut g = graph(4, &[(0, 1), (0, 2), (1, 3), (1, 2)]);
    let mut scratch = Vec::new();
    let c = g.new_block_condition(n(0), n(1), &mut scratch).unwrap();
    let op = |g: &Graph| match g.node(c).data {
        KindData::Condition(op) => op,
        _ => panic!("not a condition"),
    };
    assert_eq!(op(&g), CondOp::IntOr);
    assert_eq!(outs(&g, c.get()), [3, 2], "false edge preserved from b2");
    let facts = BlockFacts::neutral(4);
    let mut flips = Vec::new();
    let mut stack = Vec::new();
    g.negate_condition(c, &facts, &mut flips, &mut stack).unwrap();
    assert_eq!(op(&g), CondOp::BoolAnd);
    assert_eq!(flips, [n(0), n(1)], "component 0 first");
    g.negate_condition(c, &facts, &mut flips, &mut stack).unwrap();
    assert_eq!(op(&g), CondOp::BoolOr);
    assert_eq!(CondOp::BoolOr.symbol(), "||");
    assert_eq!(CondOp::BoolAnd.symbol(), "&&");
}

#[test]
fn negation_result_is_the_or_of_the_leaves() {
    let mut g = graph(4, &[(0, 1), (0, 2), (1, 3), (1, 2)]);
    let mut scratch = Vec::new();
    let c = g.new_block_condition(n(0), n(1), &mut scratch).unwrap();
    let mut facts = BlockFacts::neutral(4);
    facts.set(1, Fact { negation_changes_dataflow: true, ..Fact::NEUTRAL });
    let (mut flips, mut stack) = (Vec::new(), Vec::new());
    assert!(g.negate_condition(c, &facts, &mut flips, &mut stack).unwrap());
}

#[test]
fn list_negates_its_last_component() {
    let mut g = graph(4, &[(0, 1), (1, 2), (1, 3)]);
    let mut scratch = Vec::new();
    let l = g.new_block_list(&[n(0), n(1)], &mut scratch).unwrap();
    let facts = BlockFacts::neutral(4);
    let (mut flips, mut stack) = (Vec::new(), Vec::new());
    let before = outs(&g, l.get());
    g.negate_condition(l, &facts, &mut flips, &mut stack).unwrap();
    assert_eq!(flips, [n(1)]);
    assert_eq!(outs(&g, l.get()), before.into_iter().rev().collect::<Vec<_>>());
}

#[test]
fn goto_factory_removes_the_edge() {
    let mut g = graph(2, &[(0, 1)]);
    let mut scratch = Vec::new();
    let s = g.new_block_goto(n(0), &mut scratch).unwrap();
    assert!(outs(&g, s.get()).is_empty());
    assert!(ins(&g, 1).is_empty());
    assert!(matches!(g.node(s).data, KindData::Goto { target, goto_type: 1 } if target == n(1)));
}

#[test]
fn if_goto_requires_a_goto_true_branch() {
    let mut g = graph(3, &[(0, 1), (0, 2)]);
    let mut scratch = Vec::new();
    assert_eq!(g.new_block_if_goto(n(0), &mut scratch), Err(CfgError::IfGotoTrueBranch));
    g.set_goto_branch(n(0), 1).unwrap();
    let s = g.new_block_if_goto(n(0), &mut scratch).unwrap();
    assert_eq!(outs(&g, s.get()), [1]);
}

#[test]
fn multigoto_keeps_a_collapsed_self_edge() {
    // 0 -> 0 (self), 0 -> 1, 0 -> 2; goto on 0 -> 2.
    let mut g = graph(3, &[(0, 0), (0, 1), (0, 2)]);
    g.node_mut(n(0)).flags |= node_flags::SWITCH_OUT;
    let mut scratch = Vec::new();
    let m = g.new_block_multi_goto(n(0), 2, &mut scratch).unwrap();
    assert_eq!(outs(&g, m.get()), [1, m.get()]);
    let m2 = g.new_block_multi_goto(m, 0, &mut scratch).unwrap();
    assert_eq!(m2, m, "an existing multigoto gains the goto");
    assert!(matches!(&g.node(m).data, KindData::MultiGoto { targets, .. } if targets.len() == 2));
}

#[test]
fn switch_needs_a_copy_leaf() {
    let orig = graph(3, &[(0, 1), (0, 2)]);
    let mut g = graph(3, &[(0, 1), (0, 2)]);
    let mut scratch = Vec::new();
    let w = g.new_block_while_do(n(1), n(2), &mut scratch);
    // A while-do has no exit leaf.
    if let Ok(w) = w {
        assert_eq!(g.new_block_switch(&orig, &[w], false, &mut scratch), Err(CfgError::SwitchLeaf));
    }
}
