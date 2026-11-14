use super::*;
use crate::oracle::strategies::mutated;
use crate::oracle::{read_text, sample_dir};
use proptest::prelude::*;

const POINTS: [&str; 5] = ["p1", "p2", "p3", "p4", "end"];

fn sample(point: &str) -> String {
    read_text(&sample_dir().join(format!("switchind.{point}.state.gz"))).unwrap()
}

#[test]
fn the_switchind_dumps_round_trip() {
    for point in POINTS {
        let text = sample(point);
        let dump = StateDump::parse(&text).unwrap_or_else(|e| panic!("{point}: {e}"));
        assert_eq!(dump.write(), text, "{point}");
    }
}

#[test]
fn the_end_dump_is_complete() {
    let dump = StateDump::parse(&sample("end")).unwrap();
    assert_eq!(dump.arch_id, "x86:LE:64:default:gcc");
    assert_eq!(dump.function.function.name, "switchind");
    assert_eq!(dump.actions.len(), 243);
    // Every varnode an op names is in @varnodes; every op a varnode names is in @ops.
    for op in &dump.ops {
        for v in op.output.iter().chain(&op.inputs) {
            assert!(dump.varnode(*v).is_some(), "{v} of {}", op.seq);
        }
    }
    for v in &dump.varnodes {
        for r in v.def.iter().chain(&v.readers) {
            assert!(dump.op(r).is_some(), "{r} of {}", v.id);
        }
        if let Some(t) = v.data_type {
            assert!(dump.data_type(t).is_some());
        }
    }
    // Both orders are permutations of the varnodes.
    for order in [&dump.loc_order, &dump.def_order] {
        let mut ids: Vec<u32> = order.varnodes.iter().map(|v| v.0).collect();
        ids.sort_unstable();
        let all: Vec<u32> = dump.varnodes.iter().map(|v| v.id.0).collect();
        assert_eq!(ids, all);
    }
    assert_eq!(dump.jump_tables.len(), 1);
    assert!(dump.call_specs.len() >= 2);
    assert!(dump.structure.is_some());
    assert!(dump.c.iter().any(|l| l.line.contains("switch")));
    // The start dump has no structure and no C yet.
    let start = StateDump::parse(&sample("p1")).unwrap();
    assert!(start.structure.is_none() && start.c.is_empty());
    assert!(start.varnodes.len() > dump.varnodes.len());
}

#[test]
fn truncation_and_edits_are_caught() {
    let text = sample("p4");
    let cut: String = text.split_inclusive('\n').take(100).collect();
    assert!(StateDump::parse(&cut).is_err());
    let dropped = text.replacen("\nV\t", "\nX\t", 1);
    assert!(StateDump::parse(&dropped).is_err());
    let (body, _) = text.rsplit_once("END\t").unwrap();
    let recount = format!("{body}END\t1\n");
    assert!(
        StateDump::parse(&recount)
            .unwrap_err()
            .to_string()
            .contains("line count")
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = StateDump::parse(&text);
    }

    #[test]
    fn damaged_dumps_never_panic(text in mutated(Just(sample("p4")))) {
        if let Ok(dump) = StateDump::parse(&text) {
            prop_assert_eq!(dump.write(), text);
        }
    }
}
