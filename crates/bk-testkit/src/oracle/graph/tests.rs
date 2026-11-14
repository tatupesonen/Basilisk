use super::*;
use crate::oracle::strategies::{graph_file, mutated};
use proptest::prelude::*;

const SMALL: &str = "H\tbkgraph\t1\t3\n\
N\t0\t0\t0x200\tcn\t-\t3\n\
I\t0\t-\n\
A\t0\tram:0x1000\tram:0x1004\n\
N\t1\t1\t0x0\t-\t0\t1\n\
I\t1\t0:0:0x10\n\
N\t2\t2\t0x0\tr\t0\t1\n\
I\t2\t0:1:0x10,1:0:0x2\n\
T\n";

#[test]
fn a_small_graph_is_read() {
    let graph = GraphFile::parse(SMALL).unwrap();
    assert_eq!(graph.nodes.len(), 3);
    let n0 = &graph.nodes[0];
    assert_eq!(n0.flags, 0x200);
    assert!(n0.facts.complex && n0.facts.negation_changes_dataflow);
    assert_eq!(n0.idom, None);
    assert_eq!(
        n0.range.as_ref().unwrap().start,
        OracleAddress {
            space: "ram".into(),
            offset: 0x1000
        }
    );
    assert_eq!(graph.nodes[1].idom, Some(0));
    assert!(graph.nodes[2].facts.ends_in_return);
    assert_eq!(
        graph.nodes[2].in_edges,
        [
            GraphEdge {
                src: 0,
                slot: 1,
                label: 0x10
            },
            GraphEdge {
                src: 1,
                slot: 0,
                label: 2
            }
        ]
    );
    assert_eq!(
        graph.out_edges(),
        vec![vec![(1, 0x10), (2, 0x10)], vec![(2, 2)], vec![]]
    );
    assert_eq!(graph.write(), SMALL);
}

#[test]
fn facts_have_one_spelling() {
    assert_eq!(Facts::from_letters("-"), Some(Facts::default()));
    assert_eq!(Facts::from_letters("c"), Some(Facts::NEUTRAL));
    assert_eq!(Facts::from_letters("csrn").unwrap().letters(), "csrn");
    for bad in ["", "nc", "cc", "x", "c-"] {
        assert_eq!(Facts::from_letters(bad), None, "{bad:?}");
    }
}

#[test]
fn inconsistent_graphs_are_rejected() {
    let cases = [
        // slot 1 of node 0 named twice, slot 0 never
        (
            SMALL.replace("I\t1\t0:0:0x10", "I\t1\t0:1:0x10"),
            "named twice",
        ),
        (SMALL.replace("0:1:0x10,1", "0:5:0x10,1"), "beyond"),
        (SMALL.replace("\tr\t", "\tsr\t"), "RETURN"),
        (SMALL.replace("N\t1\t1", "N\t2\t1"), "node id"),
        (SMALL.replace("I\t2\t0:1", "I\t2\t7:1"), "edge source"),
        (SMALL.replace("\t0\t1\nI\t1", "\t9\t1\nI\t1"), "dominator"),
        (SMALL.replace("T\n", ""), "final T"),
        (format!("{SMALL}x\n"), "after"),
        (SMALL.replace("bkgraph\t1", "bkgraph\t2"), "version"),
        (SMALL.replace("0x200", "0x0200"), "flags"),
    ];
    for (text, needle) in cases {
        let error = GraphFile::parse(&text).unwrap_err().to_string();
        assert!(error.contains(needle), "{needle}: {error}");
    }
}

#[test]
fn ghidra_xml_matches_the_research_generator() {
    let graph = GraphFile::from_out_edges(&[vec![1, 2], vec![2], vec![]], &[]).unwrap();
    assert_eq!(
        graph.to_ghidra_xml(),
        "<block index=\"0\">\n<bhead index=\"0\" type=\"plain\"/>\n\
         <bhead index=\"1\" type=\"plain\"/>\n<bhead index=\"2\" type=\"plain\"/>\n\
         <block index=\"0\"></block>\n<block index=\"1\"><edge end=\"0\" rev=\"0\"/></block>\n\
         <block index=\"2\"><edge end=\"0\" rev=\"1\"/><edge end=\"1\" rev=\"0\"/></block>\n\
         </block>\n"
    );
    assert_eq!(GraphFile::from_out_edges(&[vec![3]], &[]), None);
}

#[test]
fn the_extension_sample_round_trips() {
    for name in ["elseif.blocks.bkg", "random.bkg"] {
        let path = crate::workspace_root()
            .join("crates/bk-testkit/tests/data/oracle")
            .join(name);
        let text = std::fs::read_to_string(&path).unwrap();
        let graph = GraphFile::parse(&text).unwrap();
        assert_eq!(graph.write(), text, "{name}");
    }
}

proptest! {
    #[test]
    fn write_then_parse_is_identity(graph in graph_file(12)) {
        let text = graph.write();
        let parsed = GraphFile::parse(&text).unwrap();
        prop_assert_eq!(&parsed, &graph);
        prop_assert_eq!(parsed.write(), text);
    }

    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = GraphFile::parse(&text);
    }

    #[test]
    fn damaged_files_never_panic(text in mutated(graph_file(8).prop_map(|g| g.write()))) {
        if let Ok(graph) = GraphFile::parse(&text) {
            prop_assert_eq!(graph.write(), text);
        }
    }
}
