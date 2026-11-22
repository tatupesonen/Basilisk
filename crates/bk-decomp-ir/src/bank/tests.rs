//! Ranged cursors: insertion and deletion before, at and after the cursor,
//! and the end fixed as the varnode the end iterator named (Ghidra's
//! `vn = *iter++` loops, e.g. `Heritage::processJoins`, heritage.cc:2278–2283).

use crate::VnClass;
use crate::ids::VarnodeId;
use crate::testing::{Fx, fx};

fn walk(
    fix: &mut Fx,
    mut cur: crate::LocCursor,
    mut body: impl FnMut(&mut Fx, VarnodeId),
) -> Vec<u64> {
    let mut seen = Vec::new();
    while let Some(vn) = cur.next(&fix.ssa) {
        seen.push(fix.ssa.varnode_addr(vn).offset());
        body(fix, vn);
    }
    seen
}

#[test]
fn a_space_cursor_sees_inserts_past_its_successor_only() {
    let mut fix = fx(1);
    for off in [0, 8, 16] {
        fix.regvn(off, 4);
    }
    let cur = fix.ssa.loc_cursor_in_space(fix.reg);
    let mut step = 0;
    let seen = walk(&mut fix, cur, |fix, _| {
        step += 1;
        if step == 2 {
            // At 8, the successor 16 is remembered: 2 is behind the
            // cursor, 12 between it and its successor, 24 past it.
            for off in [2, 12, 24] {
                fix.regvn(off, 4);
            }
        }
    });
    assert_eq!(seen, [0, 8, 16, 24]);
    fix.ok();
}

#[test]
fn a_space_cursor_survives_deleting_the_current_and_the_remembered_varnode() {
    let mut fix = fx(1);
    let vns: Vec<_> = [0, 8, 16, 24].map(|o| fix.regvn(o, 4)).into();
    let cur = fix.ssa.loc_cursor_in_space(fix.reg);
    let mut step = 0;
    let seen = walk(&mut fix, cur, |fix, vn| {
        step += 1;
        if step == 1 {
            // The current varnode (0) and its remembered successor (8).
            fix.ssa.destroy_varnode(vn).unwrap();
            fix.ssa.destroy_varnode(vns[1]).unwrap();
        }
    });
    assert_eq!(seen, [0, 16, 24]);
    fix.ok();
}

#[test]
fn the_end_is_the_varnode_the_end_iterator_named() {
    // loc_at(8) ends at the first varnode past address 8, here the one at
    // 16. A varnode inserted at 12 sorts before that end and is visited,
    // as in Ghidra (processJoins re-checks each varnode's space for this);
    // one at 20 is past it.
    let mut fix = fx(1);
    fix.regvn(8, 4);
    fix.regvn(8, 2);
    fix.regvn(16, 4);
    let at = fix.reg(8);
    let cur = fix.ssa.loc_cursor_at(at);
    let mut first = true;
    let seen = walk(&mut fix, cur, |fix, _| {
        if std::mem::take(&mut first) {
            fix.regvn(12, 4);
            fix.regvn(20, 4);
        }
    });
    assert_eq!(seen, [8, 8, 12]);
    // The snapshot query has key bounds: only the two at 8.
    assert_eq!(fix.ssa.loc_at(at).count(), 2);
}

#[test]
fn a_deleted_end_stops_the_walk_at_its_key() {
    let mut fix = fx(1);
    fix.regvn(8, 4);
    let end = fix.regvn(16, 4);
    fix.regvn(20, 4);
    let at = fix.reg(8);
    let cur = fix.ssa.loc_cursor_at(at);
    let seen = walk(&mut fix, cur, |fix, _| {
        if fix.ssa.varnode_exists(end) {
            fix.ssa.destroy_varnode(end).unwrap();
        }
    });
    assert_eq!(seen, [8]);
}

#[test]
fn an_empty_range_stays_empty_and_ranges_compose() {
    let mut fix = fx(1);
    fix.regvn(16, 4);
    let at = fix.reg(8);
    let mut cur = fix.ssa.loc_cursor_at(at);
    fix.regvn(8, 4);
    // begin == end when the cursor was made: nothing is visited.
    assert_eq!(cur.next(&fix.ssa), None);
    // beginLoc(0)..beginLoc(16) (Heritage::collect's form).
    for off in [0, 4, 24] {
        fix.regvn(off, 4);
    }
    let from = fix.ssa.loc_cursor_at(fix.reg(0));
    let to = fix.ssa.loc_cursor_at(fix.reg(16));
    let seen = walk(&mut fix, from.until_start_of(&to), |_, _| {});
    assert_eq!(seen, [0, 4, 8]);
    let seen = walk(&mut fix, from.until_end_of(&to), |_, _| {});
    assert_eq!(seen, [0, 4, 8, 16]);
}

#[test]
fn sized_class_and_def_cursors_follow_the_same_rules() {
    let mut fix = fx(1);
    let a = fix.reg(8);
    fix.regvn(8, 4);
    let mut cur = fix.ssa.loc_cursor_sized(4, a);
    let first = cur.next(&fix.ssa).unwrap();
    // A second free varnode of the same size and address sorts after the
    // first by create index, but the step already moved the iterator to
    // end() (`iter++` with no successor): not visited, as in Ghidra.
    let second = fix.regvn(8, 4);
    assert_eq!(cur.next(&fix.ssa), None);
    let mut cur = fix.ssa.loc_cursor_class(4, a, VnClass::Free);
    assert_eq!(cur.next(&fix.ssa), Some(first));
    assert_eq!(cur.next(&fix.ssa), Some(second));
    assert_eq!(cur.next(&fix.ssa), None);
    let mut cur = fix.ssa.def_cursor_class(VnClass::Free);
    let mut n = 0;
    while let Some(vn) = cur.next(&fix.ssa) {
        n += 1;
        if n == 1 {
            fix.regvn(40, 4);
        }
        assert!(fix.ssa.is_free(vn));
    }
    assert_eq!(n, 3);
    let mut cur = fix.ssa.def_cursor_class_at(VnClass::Free, a).unwrap();
    assert_eq!(cur.next(&fix.ssa), Some(first));
    assert!(fix.ssa.def_cursor_class_at(VnClass::Written, a).is_err());
}
