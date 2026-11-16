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
//! The checked-in sample dumps of `bk-testkit` load and write back.

mod support;

use std::sync::Arc;

use bk_core::NoRegisters;
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_testkit::oracle::{StateDump, read_text, sample_dir};

fn first_diff(a: &str, b: &str) -> Option<(usize, String, String)> {
    for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
        if x != y {
            return Some((i + 1, x.to_owned(), y.to_owned()));
        }
    }
    (a.lines().count() != b.lines().count()).then(|| (0, "length".into(), String::new()))
}

/// Drops the op text field (the last of `O` records in `@ops`).
fn without_texts(text: &str) -> String {
    let mut out = String::new();
    let mut in_ops = false;
    for l in text.lines() {
        if l.starts_with('@') {
            in_ops = l.starts_with("@ops\t");
        }
        if in_ops && l.starts_with("O\t") {
            out.push_str(l.rsplit_once('\t').unwrap().0);
        } else {
            out.push_str(l);
        }
        out.push('\n');
    }
    out
}

#[test]
fn switchind_samples_round_trip_without_registers() {
    for point in ["p1", "p2", "p3", "p4", "end"] {
        let path = sample_dir().join(format!("switchind.{point}.state.gz"));
        let text = read_text(&path).unwrap();
        let dump = StateDump::parse(&text).unwrap();
        let spaces = Arc::new(spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap());
        let ssa = load(&dump, Arc::clone(&spaces)).unwrap();
        let names = DumpNames::from_dump(&dump, &spaces);
        let out = write(&ssa, &dump, &names, &CanonicalCalls::Identity).unwrap();
        if let Some((line, a, b)) = first_diff(&without_texts(&text), &without_texts(&out)) {
            panic!("{point}: line {line}\n dump: {a}\n ours: {b}");
        }
    }
}

#[test]
fn switchind_samples_round_trip_byte_for_byte() {
    let tables = support::lang::LangTables::load("x86:LE:64:default").unwrap();
    for point in ["p1", "p2", "p3", "p4", "end"] {
        let path = sample_dir().join(format!("switchind.{point}.state.gz"));
        let text = read_text(&path).unwrap();
        let dump = StateDump::parse(&text).unwrap();
        let bare = spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap();
        let regs = Arc::new(tables.reg_table(&bare));
        let spaces = Arc::new(spaces_from_dump(&dump, regs).unwrap());
        let ssa = load(&dump, Arc::clone(&spaces)).unwrap();
        let names = DumpNames::from_dump(&dump, &spaces).with_userops(tables.userops.clone());
        let out = write(&ssa, &dump, &names, &CanonicalCalls::Identity).unwrap();
        if let Some((line, a, b)) = first_diff(&text, &out) {
            panic!("{point}: line {line}\n dump: {a}\n ours: {b}");
        }
    }
}

#[test]
fn join_records_replay_at_the_offsets_the_dump_names() {
    use bk_core::VarnodeData;
    use bk_decomp_ir::state::{JoinRecordDump, install_joins};
    let text = read_text(&sample_dir().join("switchind.end.state.gz")).unwrap();
    let dump = StateDump::parse(&text).unwrap();
    let spaces = spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap();
    let reg = spaces.space_by_name("register").unwrap().id();
    let cst = spaces.constant_space().unwrap().id();
    // RDX:RAX (16 bytes, offset 0), then a padded 4-byte piece whose record
    // is 8 bytes long: the second record starts at the next multiple of 16.
    let records = [
        JoinRecordDump {
            offset: 0,
            size: 16,
            pieces: vec![VarnodeData::new(reg, 0x10, 8), VarnodeData::new(reg, 0, 8)],
        },
        JoinRecordDump {
            offset: 0x10,
            size: 8,
            pieces: vec![VarnodeData::new(cst, 0, 4), VarnodeData::new(reg, 0, 4)],
        },
    ];
    install_joins(&spaces, &records).unwrap();
    let second = spaces.find_join(0x10).unwrap();
    assert_eq!(second.pieces(), records[1].pieces.as_slice());
    // A table whose offsets do not follow creation order is refused.
    let fresh = spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap();
    let mut skewed = records[1].clone();
    skewed.offset = 0x20;
    assert!(install_joins(&fresh, &[records[0].clone(), skewed]).is_err());
}
