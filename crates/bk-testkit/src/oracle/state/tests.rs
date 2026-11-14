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

#[test]
fn version_1_dumps_are_still_read() {
    let text = read_text(&sample_dir().join("switchind.end.v1.state.gz")).unwrap();
    let dump = StateDump::parse(&text).unwrap();
    assert_eq!(dump.version, 1);
    assert_eq!(dump.scope.orders, None);
    assert_eq!(dump.write(), text);
    // A version-1 dump cannot carry version-2 records.
    let v2 = sample("end");
    let as_v1 = v2.replacen("BKSTATE\t2\t", "BKSTATE\t1\t", 1);
    assert!(StateDump::parse(&as_v1).is_err());
}

#[test]
fn the_scope_orders_are_consistent() {
    let dump = StateDump::parse(&sample("end")).unwrap();
    assert_eq!(dump.version, 2);
    let orders = dump.scope.orders.as_ref().unwrap();
    // The symbol ids continue from the scope's counter: every id is below it.
    let id_base = 0x4000_0000_0000_0000_u64 + ((orders.identity.ghidra_id & 0xffff) << 40);
    for s in &dump.scope.symbols {
        assert!(
            s.symbol.id.0 >= id_base && s.symbol.id.0 < id_base + orders.identity.next_unique_id
        );
    }
    // Every map record names an entry of a local symbol with that storage;
    // every fragment lies inside its record.
    let entry = |r: &EntryRef| {
        let g = dump
            .scope
            .symbols
            .iter()
            .find(|g| g.symbol.id == r.symbol)
            .unwrap();
        &g.entries[usize::try_from(r.position).unwrap()]
    };
    for r in &orders.records {
        match &entry(&r.entry).storage {
            EntryStorage::Address(a) => {
                assert_eq!((a.space.as_str(), a.offset), (r.space.as_str(), r.first))
            }
            other => panic!("map record for {other:?}"),
        }
    }
    for f in &orders.fragments {
        let rec = orders.records.iter().find(|r| r.entry == f.entry).unwrap();
        assert!(rec.first <= f.first && f.last <= rec.last && f.first <= f.last);
    }
    for q in &orders.dynamic.entries {
        assert!(matches!(entry(q).storage, EntryStorage::Hash(_)));
    }
    // Version 2 needs the I record when there is a local scope.
    let text = sample("end");
    let i_line = text.lines().find(|l| l.starts_with("I\t0x")).unwrap();
    let without = text.replacen(&format!("{i_line}\n"), "", 1);
    assert!(StateDump::parse(&without).is_err());
}
