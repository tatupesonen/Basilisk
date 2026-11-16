//! Unit tests of the annotation setters (`varnode.hh`, `varnode.cc`,
//! `op.hh`): they change only the annotation, never structure.

use bk_decomp_types::TypeId;
use bk_pcode::OpCode;

use crate::flags::{oflags, vaddl, vflags};
use crate::ids::{EntryRef, HighId};
use crate::testing::fx;

#[test]
fn update_type_respects_the_lock() {
    // Varnode::updateType(ct) (varnode.cc:488–496) and updateType(ct, lock,
    // override) (506–521; the TYPE_UNKNOWN rule is the caller's).
    let mut fix = fx(1);
    let vn = fix.regvn(0, 4);
    assert!(fix.ssa.update_type(vn, TypeId::from_raw(1)).unwrap());
    assert!(!fix.ssa.update_type(vn, TypeId::from_raw(1)).unwrap());
    assert!(
        fix.ssa
            .update_type_locked(vn, TypeId::from_raw(2), true, false)
            .unwrap()
    );
    assert!(fix.ssa.varnode_flags(vn) & vflags::TYPELOCK != 0);
    assert!(!fix.ssa.update_type(vn, TypeId::from_raw(3)).unwrap());
    assert!(
        !fix.ssa
            .update_type_locked(vn, TypeId::from_raw(3), false, false)
            .unwrap()
    );
    assert!(
        fix.ssa
            .update_type_locked(vn, TypeId::from_raw(3), false, true)
            .unwrap()
    );
    assert_eq!(fix.ssa.varnode_type(vn), Some(TypeId::from_raw(3)));
    assert_eq!(fix.ssa.varnode_flags(vn) & vflags::TYPELOCK, 0);
}

#[test]
fn copy_symbol_takes_type_entry_and_locks() {
    // Varnode::copySymbol (varnode.cc:525–537).
    let mut fix = fx(1);
    let from = fix.regvn(0, 4);
    let to = fix.regvn(8, 4);
    let e = EntryRef {
        symbol: 4,
        position: 1,
    };
    fix.ssa.set_symbol_entry(from, Some(e)).unwrap();
    fix.ssa
        .update_type_locked(from, TypeId::from_raw(9), true, false)
        .unwrap();
    fix.ssa.varnode_set_flags(to, vflags::NAMELOCK).unwrap();
    fix.ssa.copy_symbol(to, from).unwrap();
    assert_eq!(fix.ssa.varnode_entry(to), Some(e));
    assert_eq!(fix.ssa.varnode_type(to), Some(TypeId::from_raw(9)));
    let fl = fix.ssa.varnode_flags(to);
    assert!(fl & vflags::TYPELOCK != 0 && fl & vflags::NAMELOCK == 0);
}

#[test]
fn plain_setters() {
    // setConsume, setHigh(tv, mg), setSymbolCheck (varnode.hh:181, 208,
    // 317), the nzm Funcdata::calcNZMask writes, the addl setters.
    let mut fix = fx(1);
    let vn = fix.regvn(0, 4);
    fix.ssa.set_consume(vn, 0xff).unwrap();
    fix.ssa.set_nzm(vn, 0xf0).unwrap();
    fix.ssa.set_high(vn, Some(HighId::new(5)), 3).unwrap();
    fix.ssa.set_merge_group(vn, 4).unwrap();
    fix.ssa
        .set_symbol_check(vn, vaddl::SYMCHECK_COMPLETE | vaddl::PTRFLOW)
        .unwrap();
    fix.ssa.set_ptr_flow(vn).unwrap();
    assert_eq!(fix.ssa.varnode_consume(vn), 0xff);
    assert_eq!(fix.ssa.varnode_nzm(vn), 0xf0);
    assert_eq!(fix.ssa.varnode_high(vn), Some(HighId::new(5)));
    assert_eq!(fix.ssa.varnode_merge_group(vn), 4);
    let addl = fix.ssa.varnode_addl(vn);
    assert_eq!(addl & vaddl::SYMCHECK_COMPLETE, vaddl::SYMCHECK_COMPLETE);
    assert!(addl & vaddl::PTRFLOW != 0);
    fix.ssa.clear_ptr_flow(vn).unwrap();
    assert_eq!(fix.ssa.varnode_addl(vn) & vaddl::PTRFLOW, 0);
}

#[test]
fn structural_bits_are_refused() {
    // Basilisk: written/input/insert/constant/annotation and an op's dead
    // bit change only through the mutation methods (spec 7.5).
    let mut fix = fx(1);
    let vn = fix.regvn(0, 4);
    assert!(fix.ssa.varnode_set_flags(vn, vflags::WRITTEN).is_err());
    assert!(fix.ssa.varnode_clear_flags(vn, vflags::INPUT).is_err());
    let op = fix.op(OpCode::Copy, 1, 0x100);
    assert!(fix.ssa.op_clear_flags(op, oflags::DEAD).is_err());
    fix.ssa.op_set_flags(op, oflags::MARK).unwrap();
    let before = fix.ssa.op_flags(op);
    fix.ssa
        .op_flip_flags(op, oflags::MARK | oflags::NOCOLLAPSE)
        .unwrap();
    assert_eq!(
        fix.ssa.op_flags(op),
        before ^ (oflags::MARK | oflags::NOCOLLAPSE)
    );
    fix.ok();
}
