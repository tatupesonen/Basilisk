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
//! `EntryMap` against a literal transliteration of `rangemap.hh` (spec 6.6):
//! the same fragments in the same multiset order (duplicates included), the
//! same record list, the same answers to every look-up, and the partition
//! invariants, under random inserts and erasures.

mod common;

use bk_decomp_symbols::entrymap::{EntryMap, EntrySubsort, Fragment};
use common::rangemap_model::{MFrag, Model};
use proptest::prelude::*;

type Map = EntryMap<usize, u64, EntrySubsort>;

#[derive(Clone, Debug)]
enum Op {
    Insert(u64, u64, (u32, u64)),
    Erase(usize),
    Probe(u64, u64),
}

/// Offsets near 0, in a small window, and near the top of the domain.
fn point() -> impl Strategy<Value = u64> {
    prop_oneof![
        8 => 0u64..40,
        1 => (0u64..6).prop_map(|d| u64::MAX - d),
    ]
}

fn subsort() -> impl Strategy<Value = (u32, u64)> {
    prop_oneof![
        3 => Just((0u32, 0u64)),
        4 => (1u32..3, 0u64..3),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (point(), 0u64..12, subsort()).prop_map(|(a, len, sub)| {
            let b = a.saturating_add(len);
            Op::Insert(a, b, sub)
        }),
        2 => any::<usize>().prop_map(Op::Erase),
        2 => (point(), 0u64..8).prop_map(|(p, e)| Op::Probe(p, p.saturating_add(e))),
    ]
}

fn sub(s: (u32, u64)) -> EntrySubsort {
    EntrySubsort {
        use_index: s.0,
        use_offset: s.1,
    }
}

fn same(view: &Fragment<usize, u64, EntrySubsort>, model: &MFrag) -> bool {
    view.first == model.first
        && view.last == model.last
        && view.a == model.a
        && view.b == model.b
        && view.subsort == sub(model.sub)
        && view.value == model.rec
}

fn check_structure(map: &Map, model: &Model) {
    let frags: Vec<_> = map.fragments().collect();
    assert_eq!(frags.len(), model.tree.len(), "fragment count");
    for (v, m) in frags.iter().zip(&model.tree) {
        assert!(same(v, m), "fragment {v:?} vs model {m:?}");
    }
    let list: Vec<usize> = map.records().map(|(_, v)| v).collect();
    assert_eq!(list, model.list, "record list");
    let back: Vec<usize> = map.records().rev().map(|(_, v)| v).collect();
    assert_eq!(back, model.list.iter().rev().copied().collect::<Vec<_>>());
    assert_eq!(map.len(), model.list.len());
    assert_eq!(map.fragment_count(), model.tree.len());
    // Partition invariants.
    for f in &frags {
        // Not `f.a <= f.first`: Ghidra's erase can stretch a record over a
        // piece it does not cover (see `erase_can_stretch_a_neighbour`).
        assert!(
            f.first <= f.last && f.last <= f.b,
            "fragment ends inside its record: {f:?}"
        );
        for g in &frags {
            let overlap = f.first <= g.last && g.first <= f.last;
            if overlap {
                assert_eq!((f.first, f.last), (g.first, g.last), "pieces are shared");
            }
        }
    }
}

fn check_probe(map: &Map, model: &Model, p: u64, e: u64) {
    let subs = [(0u32, 0u64), (1, 0), (1, 2), (2, 1), (u32::MAX, u64::MAX)];
    for s1 in [subs[0], subs[2]] {
        for s2 in subs {
            let got: Vec<_> = map.find_sub(p, sub(s1), sub(s2)).collect();
            let want = model.find_sub(p, s1, s2);
            assert_eq!(got.len(), want.len(), "find_sub({p}, {s1:?}, {s2:?})");
            for (g, w) in got.iter().zip(want) {
                assert!(same(g, w));
            }
            assert_eq!(map.find_sub(p, sub(s1), sub(s2)).rev().count(), want.len());
        }
    }
    let at = |pos: Option<_>| pos.and_then(|pos| map.fragment(pos));
    let model_at = |i: Option<usize>| i.map(|i| model.tree[i]);
    let pairs = [
        (
            at(map.find_end(p)),
            model_at(Some(model.find_end(p)).filter(|&i| i < model.tree.len())),
        ),
        (
            at(map.find_first_after(p)),
            model_at(model.find_first_after(p)),
        ),
        (
            at(map.find_last_before(p)),
            model_at(model.find_last_before(p)),
        ),
        (
            at(map.find_overlap(p, e)),
            model_at(model.find_overlap(p, e)),
        ),
    ];
    for (i, (got, want)) in pairs.iter().enumerate() {
        match (got, want) {
            (None, None) => {}
            (Some(g), Some(w)) => assert!(same(g, w), "look-up {i} at {p}: {g:?} vs {w:?}"),
            _ => panic!("look-up {i} at {p}: {got:?} vs {want:?}"),
        }
    }
    // Walks from a position agree with the model's index walk.
    if let (Some(pos), Some(i)) = (map.find_last_before(p), model.find_last_before(p)) {
        let got: Vec<_> = map
            .iter_back_from(pos)
            .map(|f| (f.first, f.value))
            .collect();
        let want: Vec<_> = model.tree[..=i]
            .iter()
            .rev()
            .map(|f| (f.first, f.rec))
            .collect();
        assert_eq!(got, want);
    }
    if let (Some(pos), Some(i)) = (map.find_first_after(p), model.find_first_after(p)) {
        let got: Vec<_> = map.iter_from(pos).map(|f| (f.first, f.value)).collect();
        let want: Vec<_> = model.tree[i..].iter().map(|f| (f.first, f.rec)).collect();
        assert_eq!(got, want);
    }
}

fn run(ops: &[Op]) {
    let mut map = Map::new();
    let mut model = Model::default();
    let mut handles = Vec::new();
    let debug = std::env::var_os("BK_DEBUG").is_some();
    for (step, op) in ops.iter().enumerate() {
        if debug {
            eprintln!("step {step}: {op:?}");
            eprintln!(
                "  before: {:?}",
                map.fragments()
                    .map(|f| (f.first, f.last, f.value))
                    .collect::<Vec<_>>()
            );
        }
        match *op {
            Op::Insert(a, b, s) => {
                let rec = model.insert(a, b, s);
                let id = map.insert(rec, a, b, sub(s));
                assert_eq!(handles.len(), rec);
                handles.push(Some(id));
            }
            Op::Erase(pick) => {
                let live: Vec<usize> = (0..handles.len())
                    .filter(|&i| handles[i].is_some())
                    .collect();
                if live.is_empty() {
                    continue;
                }
                let rec = live[pick % live.len()];
                model.erase(rec);
                map.erase(handles[rec].take().unwrap());
            }
            Op::Probe(p, e) => check_probe(&map, &model, p, e),
        }
        check_structure(&map, &model);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2048)
    ))]

    #[test]
    fn entrymap_matches_the_transliteration(ops in prop::collection::vec(op(), 1..60)) {
        run(&ops);
    }
}

#[test]
fn duplicate_last_fragment_is_reproduced() {
    // A record ending where an existing piece ends gets its last fragment
    // twice (rangemap.hh insert: the final `if (f <= b)` after the break).
    let mut map = Map::new();
    map.insert(0, 0, 9, sub((0, 0)));
    map.insert(1, 5, 9, sub((0, 0)));
    let frags: Vec<_> = map
        .fragments()
        .map(|f| (f.first, f.last, f.value))
        .collect();
    assert_eq!(frags, [(0, 4, 0), (5, 9, 1), (5, 9, 0), (5, 9, 1)]);
    run(&[
        Op::Insert(0, 9, (0, 0)),
        Op::Insert(5, 9, (0, 0)),
        Op::Erase(1),
        Op::Probe(5, 6),
    ]);
}

#[test]
fn record_list_placement_is_not_always_by_end() {
    // Two long records share a piece; a short record inside it goes before
    // the record of the first fragment of that piece (spec 4.2).
    run(&[
        Op::Insert(0, 20, (1, 0)),
        Op::Insert(0, 30, (0, 0)),
        Op::Insert(5, 6, (1, 1)),
        Op::Insert(5, 6, (0, 0)),
        Op::Probe(5, 5),
        Op::Insert(u64::MAX - 3, u64::MAX, (0, 0)),
        Op::Insert(u64::MAX - 1, u64::MAX, (2, 0)),
        Op::Probe(u64::MAX, u64::MAX),
        Op::Erase(0),
        Op::Erase(0),
        Op::Probe(5, 9),
    ]);
}

#[test]
fn erase_can_stretch_a_neighbour() {
    // Ghidra defect (rangemap.hh erase): the right-hand re-sew looks only at
    // the first fragment after the erased record. S = [0,9] sorts before
    // T = [5,9] in the piece [5,9]; erasing R = [0,4] zips the boundary
    // 4|5 although T starts at 5, so T's fragment becomes [0,9].
    let mut map = Map::new();
    map.insert(0, 0, 9, sub((1, 0)));
    map.insert(1, 5, 9, sub((2, 0)));
    let r = map.insert(2, 0, 4, sub((1, 1)));
    map.erase(r);
    let frags: Vec<_> = map
        .fragments()
        .map(|f| (f.first, f.last, f.value))
        .collect();
    assert_eq!(frags, [(0, 9, 0), (0, 9, 1), (0, 9, 1)]);
    assert_eq!(map.find(2).map(|f| f.value).collect::<Vec<_>>(), [0, 1, 1]);
    run(&[
        Op::Insert(0, 9, (1, 0)),
        Op::Insert(5, 9, (2, 0)),
        Op::Insert(0, 4, (1, 1)),
        Op::Erase(2),
        Op::Probe(2, 3),
    ]);
}

#[test]
fn regression_case_2() {
    use Op::{Erase, Insert};
    run(&[
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Erase(0),
        Insert(0, 0, (0, 0)),
        Erase(0),
        Erase(0),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(26, 33, (0, 0)),
        Erase(462_554_449_755_588_757),
        Insert(0, 0, (0, 0)),
        Erase(6_253_580_357_865_957_283),
        Insert(31, 32, (0, 0)),
        Insert(33, 33, (1, 0)),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Erase(12_084_509_669_092_360_880),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Erase(756_378_967_596_917_335),
        Erase(1_442_783_028_104_395_694),
        Insert(0, 0, (0, 0)),
        Insert(0, 0, (0, 0)),
        Insert(22, 26, (0, 0)),
        Erase(7_411_057_458_861_298_732),
        Insert(0, 0, (0, 0)),
    ]);
}
