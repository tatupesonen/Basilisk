//! Spec 6, test 5 (S): the trace recorder on synthetic edits, against
//! `Funcdata::debugModCheck`/`debugModPrint`/`debugCheckRange`
//! (`funcdata.cc:1124`–`1210`) and the record grammar of D00 4.9.

use bk_pcode::OpCode;

use super::{TraceRange, TraceRecorder};
use crate::ids::UnitId;
use crate::print::NoNames;
use crate::testing::fx;

fn output(ssa: &crate::Ssa) -> String {
    ssa.recorder()
        .and_then(|r| r.as_any().downcast_ref::<TraceRecorder>())
        .map(|t| t.output.clone())
        .unwrap()
}

#[test]
fn a_unit_prints_each_touched_op_before_and_after_once() {
    let mut fix = fx(1);
    let k = fix.cst(4, 1);
    let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[k]);
    let mut rec = TraceRecorder::new(Box::new(NoNames));
    rec.add_range(TraceRange {
        addrs: None,
        times: None,
    });
    fix.ssa.set_recorder(Some(Box::new(rec)));
    let c = fix.cst(4, 7);
    fix.ssa.begin_unit(UnitId::new(0), "unit0");
    let a_before = {
        let mut o = crate::RawOut::new();
        fix.ssa.op_debug_text(&mut o, a, &NoNames);
        o.text
    };
    // Two changes to one op: one entry (op->isModified, 1127).
    fix.ssa.op_set_opcode(a, OpCode::IntNegate).unwrap();
    fix.ssa.op_set_input(&mut fix.env, a, c, 0).unwrap();
    fix.ssa.end_unit();
    let after = {
        let mut o = crate::RawOut::new();
        fix.ssa.op_debug_text(&mut o, a, &NoNames);
        o.text
    };
    assert_eq!(
        output(&fix.ssa),
        format!("DEBUG 0: unit0\n{a_before}\n   {after}\n\n")
    );
    // A unit that touches nothing prints nothing and keeps the count
    // (debugModPrint returns on an empty list, 1152).
    fix.ssa.begin_unit(UnitId::new(1), "quiet");
    fix.ssa.end_unit();
    fix.ssa.begin_unit(UnitId::new(2), "unit2");
    fix.ssa.op_uninsert(a).unwrap();
    fix.ssa.end_unit();
    let out = output(&fix.ssa);
    assert!(!out.contains("quiet"));
    assert!(out.contains("DEBUG 1: unit2\n"));
    // A removed op prints as `**` after (printDebug of a dead op).
    assert!(out.ends_with(": **\n\n"), "{out}");
}

#[test]
fn the_range_filter_selects_by_address_and_time() {
    // debugCheckRange (1188–1210): an op is traced when any range contains
    // its address (if given) and its time (if given); with no range,
    // nothing is traced (debugActivate).
    let mut fix = fx(1);
    let a = fix.emit(0, OpCode::Copy, 0x100, None, &[]);
    let b = fix.emit(0, OpCode::Copy, 0x200, None, &[]);
    let (lo, hi) = (fix.ram(0x180), fix.ram(0x280));
    let mut rec = TraceRecorder::new(Box::new(NoNames));
    rec.add_range(TraceRange {
        addrs: Some((lo, hi)),
        times: Some((0, 100)),
    });
    fix.ssa.set_recorder(Some(Box::new(rec)));
    fix.ssa.begin_unit(UnitId::new(0), "r");
    fix.ssa.op_set_opcode(a, OpCode::IntNegate).unwrap();
    fix.ssa.op_set_opcode(b, OpCode::IntNegate).unwrap();
    fix.ssa.end_unit();
    let out = output(&fix.ssa);
    assert!(out.contains("0x00000200:"), "{out}");
    assert!(!out.contains("0x00000100:"), "{out}");

    let mut none = fx(1);
    let a = none.emit(0, OpCode::Copy, 0x100, None, &[]);
    none.ssa
        .set_recorder(Some(Box::new(TraceRecorder::new(Box::new(NoNames)))));
    none.ssa.begin_unit(UnitId::new(0), "x");
    none.ssa.op_set_opcode(a, OpCode::IntNegate).unwrap();
    none.ssa.end_unit();
    assert_eq!(output(&none.ssa), "");
}
