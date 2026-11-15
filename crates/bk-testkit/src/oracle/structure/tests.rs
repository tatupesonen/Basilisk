use super::*;
use crate::oracle::sample_dir;
use crate::oracle::strategies::mutated;
use proptest::prelude::*;

fn sample(name: &str) -> String {
    std::fs::read_to_string(sample_dir().join(name)).unwrap()
}

const SAMPLES: [&str; 6] = [
    "random.trace.bks",
    "clipped.bks",
    "elseif.structure.bks",
    "elseif.finish.trace.bks",
    "error.bks",
    "elseif.asgiven.bks",
];

#[test]
fn the_extension_samples_round_trip() {
    for name in SAMPLES {
        let text = sample(name);
        let dump = StructureDump::parse(&text).unwrap();
        assert_eq!(dump.write(), text, "{name}");
    }
}

#[test]
fn the_random_sample_is_read() {
    let StructureDump::Ok(s) = StructureDump::parse(&sample("random.trace.bks")).unwrap() else {
        panic!("expected a hierarchy");
    };
    assert_eq!(
        s.gotos,
        [GotoMark {
            source: NodeName::Leaf(3),
            slot: 0,
            target: NodeName::Structured(3),
            cause: GotoCause::Fallthru
        }]
    );
    assert_eq!(s.flips, [NodeName::Leaf(2)]);
    assert_eq!(s.change_count, Some(0));
    assert_eq!(s.top, [NodeName::Structured(0)]);
    let switch = s.node(NodeName::Structured(2)).unwrap();
    assert_eq!(switch.kind, NodeKind::Switch);
    let KindData::Switch(cases) = &switch.data else {
        panic!()
    };
    assert_eq!(cases.len(), 3);
    assert_eq!(cases[1].chain, 0);
    assert!(cases[2].is_exit);
    let goto = s.node(NodeName::Structured(5)).unwrap();
    assert_eq!(
        goto.data,
        KindData::Goto {
            target: Some(NodeName::Structured(3)),
            goto_type: 1
        }
    );
    assert_eq!(s.trace.len(), 11);
    assert_eq!(s.trace[6].rule, "casefallthru");
    // Every node but the top is some component of its parent.
    for n in &s.nodes {
        match n.parent {
            Some(p) => assert!(s.node(p).unwrap().components.contains(&n.name)),
            None => assert!(s.top.contains(&n.name)),
        }
    }
}

#[test]
fn the_dump_structure_sample_has_no_run_records() {
    let StructureDump::Ok(s) = StructureDump::parse(&sample("elseif.structure.bks")).unwrap()
    else {
        panic!()
    };
    assert!(s.gotos.is_empty() && s.flips.is_empty() && s.trace.is_empty());
    assert_eq!(s.change_count, None);
    let condition = s
        .nodes
        .iter()
        .find(|n| n.kind == NodeKind::Condition)
        .unwrap();
    assert_eq!(condition.data, KindData::Condition("BOOL_AND".into()));
}

#[test]
fn errors_and_malformed_records() {
    assert_eq!(
        StructureDump::parse(&sample("error.bks")).unwrap(),
        StructureDump::Error("Could not finish collapsing block structure".into())
    );
    let good = "H\tbkstruct\t1\tok\t-\nS\tL0\tcopy\t0\t0x0\t0\t1\t-\t-\t-\t-\t-\nP\tL0\nT\n";
    assert!(StructureDump::parse(good).is_ok());
    for (bad, needle) in [
        (good.replace("L0\tcopy", "S0\tcopy"), "node name"),
        (good.replace("copy", "loop"), "node kind"),
        (
            good.replace("\t-\t-\t-\t-\n", "\t-\tx\t-\t-\n"),
            "kind data",
        ),
        (good.replace("P\tL0\n", ""), "P record"),
        (format!("{good}R\t0\tx\tL0\n"), "after"),
        (good.replace("T\n", "R\t1\tblockcat\tL0\nT\n"), "sequence"),
    ] {
        let e = StructureDump::parse(&bad).unwrap_err().to_string();
        assert!(e.contains(needle), "{needle}: {e}");
    }
}

#[test]
fn names() {
    assert_eq!(NodeName::parse("L12"), Some(NodeName::Leaf(12)));
    assert_eq!(NodeName::parse("S0"), Some(NodeName::Structured(0)));
    for bad in ["", "L", "S01", "X1", "L-1"] {
        assert_eq!(NodeName::parse(bad), None, "{bad:?}");
    }
    assert_eq!(NodeName::Structured(7).to_string(), "S7");
}

proptest! {
    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = StructureDump::parse(&text);
    }

    #[test]
    fn damaged_samples_never_panic(
        text in mutated(prop::sample::select(SAMPLES.to_vec()).prop_map(sample))
    ) {
        if let Ok(dump) = StructureDump::parse(&text) {
            prop_assert_eq!(dump.write(), text);
        }
    }
}
