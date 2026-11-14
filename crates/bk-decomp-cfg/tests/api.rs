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
//! The public API: graph edits, analyses, the XML codec, errors, limits,
//! finishing and printing (`docs/features/decomp-cfg.md` 4.2, 4.9, 4.10,
//! 5.2, 5.3, 5.5, 6.1).

use bk_decomp_cfg::{
    Analyse, BlockFacts, CaseLabels, Cfg, CfgError, Fact, GhidraGotoSelector, Kind, LimitKind,
    Limits, NodeId, StructureOptions, Structured, edge_labels, finish, node_flags, structure,
};
use bk_marshal::XmlEncoder;
use rstest::rstest;
use std::fmt::Write as _;

fn n(i: u32) -> NodeId {
    NodeId::new(i)
}

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

fn bare(c: &Cfg, facts: &BlockFacts) -> Structured {
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        ..StructureOptions::default()
    };
    structure(c, facts, &options, &mut GhidraGotoSelector::new()).unwrap()
}

#[test]
fn structure_loops_orders_in_reverse_post_order() {
    // 0 -> 2 -> 1: the list becomes [0, 2, 1] with indices 0, 1, 2.
    let mut c = cfg("2||1");
    let roots = c.structure_loops().unwrap();
    assert_eq!(roots, [n(0)]);
    assert_eq!(c.nodes(), [n(0), n(2), n(1)]);
    assert_eq!(c.index(n(2)), Some(1));
    assert_eq!(c.out_edges(n(0))[0].label, edge_labels::TREE);
}

#[test]
fn back_edges_are_loop_edges() {
    let mut c = cfg("1|2|1,3|");
    c.structure_loops().unwrap();
    let e = c.out_edges(n(2));
    assert_eq!(e[0].label, edge_labels::BACK | edge_labels::LOOP);
}

#[test]
fn irreducible_edges_and_calc_loop() {
    // Two entries into the cycle 1 <-> 2.
    let mut c = cfg("1,2|2|1");
    c.structure_loops().unwrap();
    let all: Vec<u32> = c
        .nodes()
        .iter()
        .flat_map(|&x| c.out_edges(x))
        .map(|e| e.label)
        .collect();
    assert!(
        all.iter().any(|l| l & edge_labels::IRREDUCIBLE != 0),
        "{all:x?}"
    );
    assert!(all.iter().any(|l| l & edge_labels::LOOP != 0), "{all:x?}");
}

#[test]
fn extra_roots_for_unreachable_cycles() {
    // 1 <-> 2 has no entry: an extra root, entry 0 still first.
    let mut c = cfg("|2|1");
    let roots = c.structure_loops().unwrap();
    assert_eq!(c.nodes()[0], n(0));
    assert_eq!(roots[0], n(0));
    assert_eq!(roots.len(), 2);
}

#[test]
fn dominators() {
    // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3, 3 -> 4
    let mut c = cfg("1,2|3|3|4|");
    let roots = c.structure_loops().unwrap();
    c.forward_dominators(&roots).unwrap();
    assert_eq!(c.idom(n(0)), None);
    assert_eq!(c.idom(n(3)), Some(n(0)));
    assert_eq!(c.idom(n(4)), Some(n(3)));
    assert!(c.dominates(n(0), n(4)).unwrap());
    assert!(!c.dominates(n(1), n(3)).unwrap());
    let (depth, max) = c.dom_depth().unwrap();
    assert_eq!(max, 3);
    assert_eq!(depth[0], 1);
    assert_eq!(*depth.last().unwrap(), 0);
    let tree = c.dom_tree().unwrap();
    assert_eq!(tree[5], [n(0)], "the entry has no dominator");
    assert_eq!(c.find_common_block(n(1), n(2)).unwrap(), Some(n(0)));
    assert_eq!(c.find_common_block_set(&[n(4), n(1)]).unwrap(), Some(n(0)));
    assert!(c.restricted_by_conditional(n(1), n(0)).unwrap());
    assert!(!c.restricted_by_conditional(n(3), n(0)).unwrap());
    let sub = c.dom_sub_tree(n(3)).unwrap();
    assert_eq!(sub, [n(3), n(4)]);
}

#[test]
fn dominator_root_with_in_edges() {
    // The single root has an in-edge: a virtual root is used and removed.
    let mut c = cfg("1|0");
    let roots = c.structure_loops().unwrap();
    c.forward_dominators(&roots).unwrap();
    assert_eq!(c.idom(n(1)), Some(n(0)));
    assert!(c.edges_consistent());
    assert_eq!(c.in_edges(n(0)).len(), 1);
}

#[test]
fn reachability() {
    let mut c = cfg("1||0,1");
    assert_eq!(c.reachable(n(0)).unwrap(), [n(0), n(1)]);
    assert_eq!(c.unreachable(n(0)).unwrap(), [n(2)]);
}

#[test]
fn find_condition() {
    // 0 -> 1 (false), 0 -> 2 (true), 1 -> 3, 2 -> 3
    let c = cfg("1,2|3|3|");
    let r = c.find_condition(n(3), 0, n(3), 1).unwrap();
    assert_eq!(r, Some((n(0), 0)));
}

#[test]
fn edits() {
    let mut c = cfg("1|2|");
    c.remove_from_flow(n(1)).unwrap();
    assert_eq!(c.out_edges(n(0))[0].node, n(2));
    assert!(c.edges_consistent());
    let mut c = cfg("1|2|");
    c.splice_node(n(0)).unwrap();
    assert_eq!(c.nodes(), [n(0), n(2)]);
    assert_eq!(c.out_edges(n(0))[0].node, n(2));
    let mut c = cfg("2|2|3,4||");
    c.remove_from_flow_split(n(2), false).unwrap();
    assert_eq!(c.out_edges(n(0))[0].node, n(3));
    assert_eq!(c.out_edges(n(1))[0].node, n(4));
    let mut c = cfg("1,2|||");
    c.switch_edge(n(0), n(1), n(3)).unwrap();
    assert_eq!(c.out_edges(n(0))[0].node, n(3));
    c.move_out_edge(n(0), 1, n(1)).unwrap();
    assert_eq!(c.out_edges(n(1))[0].node, n(2));
    c.remove_node(n(3)).unwrap();
    assert_eq!(c.nodes(), [n(0), n(1), n(2)]);
    c.set_start(n(2)).unwrap();
    assert_eq!(c.start().unwrap(), n(2));
    assert_ne!(c.flags(n(2)).unwrap() & node_flags::ENTRY_POINT, 0);
    c.remove_edge(n(1), n(2)).unwrap();
    assert!(c.edges_consistent());
}

#[rstest]
#[case::remove_missing_edge("1|", CfgError::EdgeRemove)]
#[case::illegal_remove_from_flow("1,2||", CfgError::IllegalRemoveFromFlow)]
#[case::splice("1,2||", CfgError::Splice)]
#[case::flow_split("1||", CfgError::IllegalRemoveFromFlowSplit)]
fn edit_errors(#[case] spec: &str, #[case] err: CfgError) {
    let mut c = cfg(spec);
    let r = match err {
        CfgError::EdgeRemove => c.remove_edge(n(1), n(0)),
        CfgError::IllegalRemoveFromFlow => {
            // Two outputs and an input.
            c.add_edge(n(1), n(0)).unwrap();
            c.remove_from_flow(n(0))
        }
        CfgError::Splice => c.splice_node(n(0)),
        CfgError::IllegalRemoveFromFlowSplit => c.remove_from_flow_split(n(0), false),
        _ => unreachable!(),
    };
    assert_eq!(r, Err(err));
}

#[test]
fn foreign_ids_are_rejected() {
    let mut c = cfg("1|");
    assert_eq!(c.add_edge(n(0), n(7)), Err(CfgError::EdgeCreate));
    assert_eq!(c.set_goto_branch(n(0), 3), Err(CfgError::GotoBranch));
    assert_eq!(c.start(), Err(CfgError::NoStart));
    assert_eq!(c.out_edges(n(9)), [] as [bk_decomp_cfg::EdgeView; 0]);
    assert_eq!(c.set_start(n(9)), Err(CfgError::SetStart));
}

#[rstest]
#[case(
    CfgError::CouldNotFinish,
    "Could not finish collapsing block structure"
)]
#[case(CfgError::SpanningTree, "Could not generate spanning tree")]
#[case(CfgError::RootNode, "Problems finding root node of graph")]
#[case(CfgError::OutputForce, "Bad block output force")]
#[case(CfgError::BinaryCondition, "Can only preserve binary condition")]
#[case(CfgError::PreserveCondition, "Unable to preserve condition")]
#[case(CfgError::SwitchLeaf, "Could not get switch leaf")]
#[case(CfgError::CaseDetached, "Case block has become detached from switch")]
#[case(
    CfgError::IfGotoTrueBranch,
    "Building ifgoto where true branch is not the goto"
)]
#[case(
    CfgError::SwapEdges,
    "Swapping edges for block that doesn't have two edges"
)]
#[case(CfgError::GotoBranch, "Could not find block edge to mark unstructured")]
#[case(CfgError::BlockIdentify, "Bad block identify")]
#[case(CfgError::EdgeCreate, "Bad edge create")]
#[case(CfgError::EdgeRemove, "Bad edge remove")]
#[case(CfgError::EdgeMove, "Bad edge move")]
#[case(CfgError::BlockRemove, "Bad block remove")]
#[case(CfgError::RemoveFromFlow, "Bad remove from flow")]
#[case(CfgError::IllegalRemoveFromFlow, "Illegal remove from flow")]
#[case(CfgError::RemoveFromFlowSplit, "Bad remove from flow split")]
#[case(CfgError::IllegalRemoveFromFlowSplit, "Illegal remove from flow split")]
#[case(
    CfgError::Splice,
    "Can only splice a block with 1 output to a block with 1 input"
)]
#[case(CfgError::SetStart, "Bad set start")]
#[case(CfgError::NoStart, "No start block registered")]
#[case(CfgError::SerializedEdge, "Bad serialized edge in block graph")]
fn ghidra_messages(#[case] e: CfgError, #[case] text: &str) {
    assert_eq!(e.to_string(), text);
}

#[test]
fn limits() {
    let c = cfg("1|2|3|");
    let facts = BlockFacts::neutral(4);
    let run = |limits| {
        let options = StructureOptions {
            analyse: Analyse::Recompute,
            limits,
            ..StructureOptions::default()
        };
        structure(&c, &facts, &options, &mut GhidraGotoSelector::new())
    };
    let e = run(Limits {
        max_nodes: 3,
        ..Limits::default()
    })
    .unwrap_err();
    assert_eq!(
        e,
        CfgError::LimitExceeded {
            what: LimitKind::Nodes,
            limit: 3
        }
    );
    let e = run(Limits {
        max_edges: 2,
        ..Limits::default()
    })
    .unwrap_err();
    assert_eq!(
        e,
        CfgError::LimitExceeded {
            what: LimitKind::Edges,
            limit: 2
        }
    );
    let e = run(Limits {
        max_steps: Some(5),
        ..Limits::default()
    })
    .unwrap_err();
    assert_eq!(
        e,
        CfgError::LimitExceeded {
            what: LimitKind::Steps,
            limit: 5
        }
    );
    assert_eq!(Limits::default_steps(10, 20), 2 * 900 + 1_000_000);
    assert!(run(Limits::default()).is_ok());
}

#[test]
fn xml_round_trip_and_errors() {
    let c = cfg("1,2|3|3|");
    let mut enc = XmlEncoder::new(true);
    c.encode(&mut enc).unwrap();
    let back = Cfg::decode_xml(enc.as_str(), &Limits::default()).unwrap();
    assert_eq!(back.len(), 4);
    assert_eq!(
        back.out_edges(n(0))
            .iter()
            .map(|e| e.node)
            .collect::<Vec<_>>(),
        [n(1), n(2)]
    );
    let bad = [
        // out-slot 1 of block 0 never named
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"plain\"/><bhead index=\"1\" type=\"plain\"/><block index=\"0\"/><block index=\"1\"><edge end=\"0\" rev=\"1\"/></block></block>",
            "bad edge slots",
        ),
        // slot named twice
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"plain\"/><bhead index=\"1\" type=\"plain\"/><block index=\"0\"/><block index=\"1\"><edge end=\"0\" rev=\"0\"/><edge end=\"0\" rev=\"0\"/></block></block>",
            "bad edge slots",
        ),
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"plain\"/><block index=\"0\"><edge end=\"5\" rev=\"0\"/></block></block>",
            "Bad serialized edge in block graph",
        ),
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"plain\"/><bhead index=\"0\" type=\"plain\"/><block index=\"0\"/><block index=\"0\"/></block>",
            "two blocks with one index",
        ),
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"graph\"/><block index=\"0\"/></block>",
            "nested block",
        ),
        (
            "<block index=\"0\"><bhead index=\"0\" type=\"plain\"/><block index=\"0\"><edge end=\"0\" rev=\"-1\"/></block></block>",
            "bad edge slots",
        ),
        ("<notablock/>", "block document"),
        ("<block", "block document"),
    ];
    for (xml, msg) in bad {
        let e = Cfg::decode_xml(xml, &Limits::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains(msg), "{xml}: {e}");
    }
}

#[test]
fn encoding_writes_copies_targets_and_conditions() {
    let mut c = cfg("1|2|");
    c.set_out_edge_label(n(0), 0, edge_labels::GOTO).unwrap();
    let s = bare(&c, &BlockFacts::neutral(3));
    let mut enc = XmlEncoder::new(false);
    s.hierarchy.encode(&mut enc).unwrap();
    let xml = enc.into_string();
    assert!(xml.contains("altindex=\"0\""), "{xml}");
    assert!(
        xml.contains("<target index=\"1\" depth=\"0\" type=\"0x1\"/>"),
        "{xml}"
    );
}

#[test]
fn order_by_final_puts_entry_first_and_returns_last() {
    let mut c = cfg("|||");
    let mut facts = BlockFacts::neutral(4);
    facts.set(
        1,
        Fact {
            ends_in_return: true,
            ..Fact::NEUTRAL
        },
    );
    facts.set(
        2,
        Fact {
            ends_in_return: true,
            ..Fact::NEUTRAL
        },
    );
    c.order_by_final(&facts);
    assert_eq!(
        c.nodes(),
        [n(0), n(3), n(1), n(2)],
        "returns last, stable among themselves"
    );
}

struct Labels;
impl CaseLabels for Labels {
    fn first_label(&self, _switch: NodeId, case: NodeId) -> Option<u64> {
        Some(100 - u64::from(case.get()))
    }
}

#[test]
fn finish_orders_cases_marks_breaks_and_labels() {
    // A loop containing a switch whose case leaves the loop: 0 -> 1 (head),
    // 1 -> 2,5 ; 2 switch -> 3,4,6; 3 -> 1; 4 -> 1; 6 -> 5 ; 5 exit.
    let c = cfg("1|2,5|3,4,6|1|1||5");
    let facts = BlockFacts::neutral(7);
    let mut s = bare(&c, &facts);
    let m = finish(&mut s.hierarchy, &facts, Some(&Labels));
    let h = &s.hierarchy;
    assert!(h.edges_consistent());
    let sw = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::Switch));
    if let Some(sw) = sw {
        let labels: Vec<u64> = h.cases(sw).iter().map(|c| c.label).collect();
        let mut sorted = labels.clone();
        sorted.sort_unstable();
        assert_eq!(labels, sorted, "cases sorted by label");
    }
    let _ = m;
    // Some loop component carries the label bump-up.
    assert!(
        (0..h.node_count() as u32)
            .map(n)
            .any(|x| h.is_label_bump_up(x))
    );
}

#[test]
fn print_tree_matches_ghidra_shape() {
    let c = cfg("1,2|3|3|");
    let s = bare(&c, &BlockFacts::neutral(4));
    let mut out = String::new();
    s.hierarchy.print_tree(&mut out, &|o, leaf, level| {
        o.push_str(&"  ".repeat(level));
        let _ = writeln!(o, "Basic Block {}", leaf.get());
    });
    assert_eq!(
        out,
        "List block 0\n  If/else block 0\n    Basic Block 0\n    Basic Block 2\n    Basic Block 1\n  Basic Block 3\n"
    );
}

#[test]
fn plugin_binding_constraints() {
    // Rules 1, 2, 6: owned, no lifetimes, Send + Sync, can go behind an Arc.
    fn send_sync<T: Send + Sync + 'static>() {}
    send_sync::<Structured>();
    send_sync::<bk_decomp_cfg::Hierarchy>();
    send_sync::<Cfg>();
    send_sync::<CfgError>();
    let s = bare(&cfg("1|"), &BlockFacts::neutral(2));
    let shared = std::sync::Arc::new(s);
    let other = std::sync::Arc::clone(&shared);
    assert_eq!(other.hierarchy.top_level(), shared.hierarchy.top_level());
}

#[test]
fn queries() {
    let mut c = cfg("1|2|1,3|");
    c.structure_loops().unwrap();
    assert!(c.has_loop_in(n(1)).unwrap());
    assert!(c.has_loop_out(n(2)).unwrap());
    assert!(!c.has_loop_in(n(3)).unwrap());
    assert!(
        c.is_jump_target(n(1)).unwrap(),
        "1 is entered from 2, index 2"
    );
    assert!(!c.is_jump_target(n(3)).unwrap());
    assert_eq!(c.in_index(n(1), n(2)), Some(1));
    assert_eq!(c.out_index(n(2), n(3)), Some(1));
    let back = c.out_edges(n(2))[0];
    assert!(back.is_back() && back.is_loop() && !back.is_decision() && !back.is_loop_dag());
    assert!(c.out_edges(n(0))[0].is_tree());
    c.clear_edge_labels(edge_labels::BACK | edge_labels::LOOP | edge_labels::TREE);
    assert_eq!(c.out_edges(n(2))[0].label, 0);
}

#[test]
fn hierarchy_negation_and_component_swap() {
    let c = cfg("1,2|3|3|");
    let facts = BlockFacts::neutral(4);
    let mut s = bare(&c, &facts);
    let h = &mut s.hierarchy;
    let ifelse = (0..h.node_count() as u32)
        .map(n)
        .find(|&x| h.kind(x) == Some(Kind::IfElse))
        .unwrap();
    let before = h.components(ifelse).to_vec();
    h.swap_components(ifelse, 1, 2).unwrap();
    assert_eq!(h.components(ifelse), [before[0], before[2], before[1]]);
    assert!(h.is_complex(n(0), &facts));
    let (flips, changed) = h.negate_condition(n(0), &facts).unwrap();
    assert_eq!(flips, [n(0)]);
    assert!(!changed);
}
