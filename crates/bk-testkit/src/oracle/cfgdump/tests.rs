use super::*;
use crate::oracle::graph::GraphEdge;
use crate::oracle::sample_dir;
use crate::oracle::strategies::mutated;
use proptest::prelude::*;

fn sample(name: &str) -> String {
    std::fs::read_to_string(sample_dir().join(name)).unwrap()
}

#[test]
fn the_extension_samples_round_trip() {
    for name in ["random.cfg", "elseif.cfg"] {
        let text = sample(name);
        let dump = CfgDump::parse(&text).unwrap();
        assert_eq!(dump.write(), text, "{name}");
    }
}

#[test]
fn the_random_sample_is_read() {
    let CfgDump::Ok(analysis) = CfgDump::parse(&sample("random.cfg")).unwrap() else {
        panic!("expected an analysis");
    };
    assert_eq!(analysis.order.len(), analysis.nodes.len());
    assert_eq!(analysis.nodes[0].idom, None);
    assert!(analysis.nodes[1..].iter().all(|n| n.idom.is_some()));
    assert_eq!(analysis.roots, [analysis.order[0]]);
    assert_eq!(analysis.loops.len(), 3);
}

#[test]
fn an_error_dump_is_read() {
    let text = "H\tbkcfg\t1\terror\tbad\\tthing\nT\n";
    assert_eq!(
        CfgDump::parse(text).unwrap(),
        CfgDump::Error("bad\tthing".into())
    );
    assert_eq!(CfgDump::Error("bad\tthing".into()).write(), text);
    assert!(CfgDump::parse("H\tbkcfg\t1\terror\tx\nO\t-\nT\n").is_err());
}

#[test]
fn malformed_dumps_are_rejected() {
    let good = "H\tbkcfg\t1\tok\t-\nO\t1,0\nN\t1\t0\t-\t2\t1\nN\t0\t1\t1\t1\t2\n\
                I\t1\t-\nI\t0\t1:0:0x10\nR\t1\nL\t1\t0\t-\t1\t0\t0>1\t-\nT\n";
    let CfgDump::Ok(a) = CfgDump::parse(good).unwrap() else {
        panic!()
    };
    assert_eq!(
        a.nodes[1].in_edges,
        [GraphEdge {
            src: 1,
            slot: 0,
            label: 0x10
        }]
    );
    assert_eq!(a.loops[0].exit_edges, [(0, 1)]);
    for (bad, needle) in [
        (good.replace("O\t1,0", "O\t1,1"), "node id"),
        (good.replace("N\t0\t1", "N\t5\t1"), "node id"),
        (good.replace("0>1", "0-1"), "exit edges"),
        (good.replace("R\t1\n", ""), "R record"),
        (good.replace("\tok\t-", "\tok\tx"), "status"),
    ] {
        let e = CfgDump::parse(&bad).unwrap_err().to_string();
        assert!(e.contains(needle), "{needle}: {e}");
    }
}

proptest! {
    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = CfgDump::parse(&text);
    }

    #[test]
    fn damaged_samples_never_panic(text in mutated(Just(sample("random.cfg")))) {
        if let Ok(dump) = CfgDump::parse(&text) {
            prop_assert_eq!(dump.write(), text);
        }
    }
}
