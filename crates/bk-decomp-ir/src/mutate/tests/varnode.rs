//! Unit tests of the varnode half of the mutation interface
//! (`funcdata_varnode.cc` unless said otherwise).

use std::sync::{Arc, Mutex};

use bk_core::Address;
use bk_decomp_types::TypeId;
use bk_pcode::OpCode;

use super::Log;
use crate::error::IrError;
use crate::flags::vflags;
use crate::ids::{CallSpecId, EntryRef, OpId};
use crate::mutate::env::{Effect, LockedType, PropertiesAnswer};
use crate::testing::{UNIQ_BASE, fx};

#[test]
fn new_constant_has_the_default_type_and_is_assigned_a_high() {
    // newConstant (68–77): getBase(size, TYPE_UNKNOWN), vbank.create,
    // assignHigh; no symbol query.
    let mut fix = fx(1);
    fix.env.default_types.insert(4, TypeId::from_raw(77));
    let c = fix.cst(4, 0x1234);
    assert!(fix.ssa.is_constant(c));
    assert_eq!(fix.ssa.varnode_type(c), Some(TypeId::from_raw(77)));
    assert_eq!(fix.ssa.varnode_nzm(c), 0x1234);
    assert_eq!(
        fix.env.log,
        vec![format!("assign_high {}", fix.ssa.varnode_create_index(c))]
    );
}

#[test]
fn new_unique_advances_the_unique_counter_and_checks_lanes() {
    // newUnique (85–98) → createUnique (varnode.cc:1300): offsets from
    // uniqbase, advanced by the size; checkForLanedRegister when size >=
    // minLanedSize.
    let mut fix = fx(1);
    fix.env.min_laned_size = 8;
    let a = fix.ssa.new_unique(&mut fix.env, 4, None).unwrap();
    let b = fix.ssa.new_unique(&mut fix.env, 8, None).unwrap();
    assert_eq!(fix.ssa.varnode_offset(a), u64::from(UNIQ_BASE));
    assert_eq!(fix.ssa.varnode_offset(b), u64::from(UNIQ_BASE) + 4);
    assert!(fix.env.log.contains(&"laned 8".to_owned()));
    assert!(!fix.env.log.contains(&"laned 4".to_owned()));
}

#[test]
fn new_varnode_out_defines_and_queries_at_the_op_address() {
    // newVarnodeOut (106–132): createDef, op->setOutput, assignHigh,
    // laned check, queryProperties at the op's address; an entry's flags
    // without typelock.
    let mut fix = fx(1);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    let at = fix.reg(0x10);
    fix.env.properties.insert(
        (at, 4),
        PropertiesAnswer::Flags(vflags::ADDRTIED | vflags::TYPELOCK),
    );
    let vn = fix.ssa.new_varnode_out(&mut fix.env, 4, at, op).unwrap();
    assert_eq!(fix.ssa.op_output(op), Some(vn));
    assert_eq!(fix.ssa.varnode_def(vn), Some(op));
    let fl = fix.ssa.varnode_flags(vn);
    assert!(fl & vflags::ADDRTIED != 0 && fl & vflags::TYPELOCK == 0);
    let fix2 = fix.op(OpCode::Copy, 1, 0x104);
    let uo = fix.ssa.new_unique_out(&mut fix.env, 2, fix2).unwrap();
    assert_eq!(
        fix.ssa.varnode_addr(uo).space(),
        fix.ssa.spaces().unique_space().map(bk_core::Space::id)
    );
    assert_eq!(fix.ssa.varnode_def(uo), Some(fix2));
    fix.ok();
}

#[test]
fn new_varnode_applies_a_symbol_entry() {
    // newVarnode (157–186) with an entry: Varnode::setSymbolProperties
    // (varnode.cc:442–456) — updateType, mapentry when the symbol is
    // type-locked, the entry's flags without typelock.
    let mut fix = fx(1);
    let at = fix.reg(0x30);
    let entry = EntryRef {
        symbol: 9,
        position: 0,
    };
    fix.env.properties.insert(
        (at, 4),
        PropertiesAnswer::Entry {
            entry,
            locked_type: Some(LockedType {
                ty: TypeId::from_raw(55),
                unknown: false,
            }),
            symbol_type_locked: true,
            flags: vflags::NAMELOCK | vflags::TYPELOCK,
        },
    );
    let vn = fix.regvn(0x30, 4);
    assert_eq!(fix.ssa.varnode_entry(vn), Some(entry));
    assert_eq!(fix.ssa.varnode_type(vn), Some(TypeId::from_raw(55)));
    let fl = fix.ssa.varnode_flags(vn);
    assert!(fl & vflags::NAMELOCK != 0);
    assert!(fl & vflags::TYPELOCK != 0, "updateType sets typelock");
}

#[test]
fn new_varnode_wraps_an_invalid_range() {
    // newVarnode (157–186): constructWrappingAddress when !isValidRange.
    let mut fix = fx(1);
    let at = fix.reg(0xffff_fffe);
    fix.ssa.new_varnode(&mut fix.env, 4, at, None).unwrap();
    assert!(fix.env.log.contains(&"wrap 4".to_owned()));
}

#[test]
fn pointer_valued_varnodes() {
    // newVarnodeIop (190–197), newVarnodeSpace (204–212),
    // newVarnodeCallSpecs (219–228): size sizeof(pointer), 8 on every host
    // in Basilisk; newCodeRef (236–246): size 1, the code type, annotation.
    let mut fix = fx(1);
    let op = fix.op(OpCode::Call, 1, 0x100);
    let iop = fix.ssa.new_varnode_iop(&mut fix.env, op).unwrap();
    assert_eq!(fix.ssa.varnode_size(iop), 8);
    assert_eq!(fix.ssa.op_from_iop(iop), Some(op));
    assert!(fix.ssa.varnode_flags(iop) & vflags::ANNOTATION != 0);
    let sp = fix.ssa.new_varnode_space(&mut fix.env, fix.ram).unwrap();
    assert!(fix.ssa.is_constant(sp));
    assert_eq!(fix.ssa.varnode_size(sp), 8);
    let fc = fix
        .ssa
        .new_varnode_callspecs(&mut fix.env, CallSpecId::new(3))
        .unwrap();
    assert_eq!(fix.ssa.varnode_offset(fc), 3);
    fix.env.code = Some(TypeId::from_raw(0xc));
    let at400 = fix.ram(0x400);
    let cr = fix.ssa.new_coderef(&mut fix.env, at400).unwrap();
    assert_eq!(fix.ssa.varnode_size(cr), 1);
    assert_eq!(fix.ssa.varnode_type(cr), Some(TypeId::from_raw(0xc)));
    assert!(fix.ssa.varnode_flags(cr) & vflags::ANNOTATION != 0);
    fix.ok();
}

#[test]
fn clone_varnode_copies_only_the_listed_flags() {
    // cloneVarnode (266–281).
    let mut fix = fx(1);
    let vn = fix.regvn(0, 4);
    fix.ssa
        .varnode_set_flags(vn, vflags::ADDRTIED | vflags::NAMELOCK | vflags::VOLATILE)
        .unwrap();
    let c = fix.ssa.clone_varnode(vn).unwrap();
    assert_eq!(fix.ssa.varnode_addr(c), fix.ssa.varnode_addr(vn));
    let fl = fix.ssa.varnode_flags(c);
    assert!(fl & vflags::ADDRTIED != 0 && fl & vflags::VOLATILE != 0);
    assert_eq!(fl & vflags::NAMELOCK, 0);
    assert_ne!(
        fix.ssa.varnode_create_index(c),
        fix.ssa.varnode_create_index(vn)
    );
}

#[test]
fn destroy_varnode_clears_reader_slots_and_the_def() {
    // destroyVarnode (286–303): each reader's slot cleared (debugModCheck
    // per reader), the def's output cleared, descend emptied, destroy.
    let mut fix = fx(1);
    let log = Arc::new(Mutex::new(Vec::new()));
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let vn = fix.ssa.op_output(def).unwrap();
    let r1 = fix.emit(0, OpCode::IntAdd, 0x104, None, &[vn, vn]);
    fix.ssa.set_recorder(Some(Box::new(Log(Arc::clone(&log)))));
    fix.ssa.destroy_varnode(vn).unwrap();
    assert!(!fix.ssa.varnode_exists(vn));
    assert_eq!(fix.ssa.op_inputs(r1).collect::<Vec<_>>(), vec![None, None]);
    assert_eq!(fix.ssa.op_output(def), None);
    assert_eq!(*log.lock().unwrap(), vec![r1, r1]);
    fix.ok();
}

#[test]
fn set_input_varnode_returns_an_equal_input_and_refuses_overlaps() {
    // setInputVarnode (354–388): an existing input with the same storage
    // is returned; an overlapping one is an error; else setInput,
    // setVarnodeProperties and the effect (unaffected, return address).
    let mut fix = fx(1);
    let at = fix.reg(0x40);
    fix.env.effects.insert((at, 4), Effect::ReturnAddress);
    let a = fix.regvn(0x40, 4);
    let a = fix.ssa.set_input_varnode(&mut fix.env, a).unwrap();
    assert!(fix.ssa.is_input(a));
    let fl = fix.ssa.varnode_flags(a);
    assert!(fl & vflags::UNAFFECTED != 0 && fl & vflags::RETURN_ADDRESS != 0);
    // Already an input: itself.
    assert_eq!(fix.ssa.set_input_varnode(&mut fix.env, a).unwrap(), a);
    let b = fix.regvn(0x40, 4);
    assert_eq!(fix.ssa.set_input_varnode(&mut fix.env, b).unwrap(), a);
    let c = fix.regvn(0x42, 4);
    assert!(matches!(
        fix.ssa.set_input_varnode(&mut fix.env, c),
        Err(IrError::OverlappingInputs(_))
    ));
    let d = fix.regvn(0x44, 4);
    fix.env
        .effects
        .insert((fix.reg(0x44), 4), Effect::Unaffected);
    let d = fix.ssa.set_input_varnode(&mut fix.env, d).unwrap();
    assert!(fix.ssa.varnode_flags(d) & vflags::UNAFFECTED != 0);
    assert_eq!(fix.ssa.varnode_flags(d) & vflags::RETURN_ADDRESS, 0);
    fix.ok();
}

#[test]
fn set_varnode_properties_skips_mapped_and_computes_cover_when_high_is_on() {
    // setVarnodeProperties (25–40).
    let mut fix = fx(1);
    let at = fix.reg(0x50);
    let vn = fix.regvn(0x50, 4);
    fix.ssa.varnode_set_flags(vn, vflags::MAPPED).unwrap();
    fix.env
        .properties
        .insert((at, 4), PropertiesAnswer::Flags(vflags::PERSIST));
    fix.ssa.set_varnode_properties(&mut fix.env, vn).unwrap();
    assert_eq!(fix.ssa.varnode_flags(vn) & vflags::PERSIST, 0);
    fix.ssa.varnode_clear_flags(vn, vflags::MAPPED).unwrap();
    fix.ssa.set_varnode_properties(&mut fix.env, vn).unwrap();
    assert!(fix.ssa.varnode_flags(vn) & vflags::PERSIST != 0);
    // isHighOn: a varnode that can have a cover (an inserted input here,
    // Varnode::calcCover, varnode.cc) gets one.
    fix.env.high_on = true;
    let input = fix.ssa.set_input_varnode(&mut fix.env, vn).unwrap();
    assert!(fix.ssa.has_cover(input));
    assert!(fix.ssa.vns[input.index()].cover.is_some());
}

#[test]
fn total_replace_moves_every_reader() {
    // totalReplace (1544–1557).
    let mut fix = fx(1);
    let x = fix.regvn(0, 4);
    let x = fix.ssa.set_input_varnode(&mut fix.env, x).unwrap();
    let y = fix.regvn(8, 4);
    let y = fix.ssa.set_input_varnode(&mut fix.env, y).unwrap();
    let a = fix.emit(0, OpCode::IntAdd, 0x100, None, &[x, x]);
    let b = fix.emit(0, OpCode::Copy, 0x104, None, &[x]);
    fix.ssa.total_replace(&mut fix.env, x, y).unwrap();
    assert_eq!(fix.ssa.readers(x).collect::<Vec<_>>(), [] as [OpId; 0]);
    assert_eq!(fix.ssa.readers(y).collect::<Vec<_>>(), vec![a, a, b]);
    fix.ok();
}

#[test]
fn total_replace_constant_feeds_markers_through_one_copy() {
    // totalReplaceConstant (1566–1603): ordinary readers get a new
    // constant each; markers share one COPY of the constant, after vn's
    // def (or at the start of block 0 when vn is not written).
    let mut fix = fx(2);
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let vn = fix.ssa.op_output(def).unwrap();
    let m1 = fix.emit(1, OpCode::MultiEqual, 0x200, None, &[vn]);
    let m2 = fix.emit(1, OpCode::MultiEqual, 0x200, None, &[vn]);
    let add = fix.emit(1, OpCode::IntAdd, 0x204, None, &[vn]);
    fix.ssa.total_replace_constant(&mut fix.env, vn, 7).unwrap();
    let ops0 = fix.ssa.block_ops(fix.blocks[0]).collect::<Vec<_>>();
    assert_eq!(ops0.len(), 2);
    let copy = ops0[1];
    assert_eq!(fix.ssa.op_opcode(copy), Some(OpCode::Copy));
    let rep = fix.ssa.op_output(copy).unwrap();
    assert_eq!(fix.ssa.op_input(m1, 0), Some(rep));
    assert_eq!(fix.ssa.op_input(m2, 0), Some(rep));
    let c = fix.ssa.op_input(add, 0).unwrap();
    assert!(fix.ssa.is_constant(c) && fix.ssa.varnode_offset(c) == 7);
    fix.ok();

    // Not written: the COPY goes at the start of block 0.
    let mut fix2 = fx(1);
    let x = fix2.regvn(0, 4);
    let x = fix2.ssa.set_input_varnode(&mut fix2.env, x).unwrap();
    let m = fix2.emit(0, OpCode::MultiEqual, 0x100, None, &[x]);
    let other = fix2.emit(0, OpCode::Copy, 0x104, None, &[]);
    fix2.ssa
        .total_replace_constant(&mut fix2.env, x, 1)
        .unwrap();
    let ops = fix2.ssa.block_ops(fix2.blocks[0]).collect::<Vec<_>>();
    assert_eq!(
        ops[0], m,
        "the COPY goes after the MULTIEQUALs (opInsertBegin)"
    );
    assert_eq!(fix2.ssa.op_opcode(ops[1]), Some(OpCode::Copy));
    assert_eq!(ops[2], other);
    fix2.ok();
}

#[test]
fn clear_dead_varnodes_frees_unread_inputs_and_destroys_unread_free() {
    // clearDeadVarnodes (860–876): an unread input that is not
    // locked_input becomes free (and is then destroyed); an unread free
    // varnode is destroyed; a locked input stays.
    let mut fix = fx(1);
    let a = fix.regvn(0, 4);
    let a = fix.ssa.set_input_varnode(&mut fix.env, a).unwrap();
    let b = fix.regvn(8, 4);
    let b = fix.ssa.set_input_varnode(&mut fix.env, b).unwrap();
    fix.ssa.set_locked_input(b).unwrap();
    let free = fix.regvn(16, 4);
    let used = fix.regvn(24, 4);
    fix.emit(0, OpCode::Copy, 0x100, None, &[used]);
    fix.ssa.clear_dead_varnodes().unwrap();
    assert!(!fix.ssa.varnode_exists(a));
    assert!(fix.ssa.varnode_exists(b) && fix.ssa.is_input(b));
    assert!(!fix.ssa.varnode_exists(free));
    assert!(fix.ssa.varnode_exists(used));
    fix.ok();
}

#[test]
fn errors_change_nothing() {
    // Basilisk: checks first (spec 4.5). A failing call leaves the bank
    // orders and the op unchanged.
    let mut fix = fx(1);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    let before = fix.ssa.loc_order().collect::<Vec<_>>();
    assert!(fix.ssa.op_unset_input(op, 3).is_err());
    assert!(fix.ssa.op_remove_input(op, 1).is_err());
    let stale = crate::ids::VarnodeId::new(999);
    assert!(fix.ssa.op_set_input(&mut fix.env, op, stale, 0).is_err());
    assert_eq!(fix.ssa.loc_order().collect::<Vec<_>>(), before);
    assert_eq!(fix.ssa.op_inputs(op).collect::<Vec<_>>(), vec![None]);
    let _ = Address::constant(0);
    fix.ok();
}

#[test]
fn an_iop_address_must_name_an_op() {
    // Review finding: `new_varnode(8, iop:3)` before op 3 existed sorted
    // under the key MAX, then under op 3's time once it was created; the
    // varnode was then lost to `bank_remove`. Ghidra's offset is always a
    // live `PcodeOp*` (`newVarnodeIop`, `funcdata_varnode.cc:190`).
    let mut fix = fx(1);
    let iop = fix.ssa.spaces().iop_space().unwrap().id();
    assert!(matches!(
        fix.ssa
            .new_varnode(&mut fix.env, 8, Address::new(iop, 3), None),
        Err(IrError::IopNamesNoOp { offset: 3 })
    ));
    for i in 0..4 {
        fix.op(OpCode::Copy, 0, 0x100 + i);
    }
    let vn = fix
        .ssa
        .new_varnode(&mut fix.env, 8, Address::new(iop, 3), None)
        .unwrap();
    fix.ok();
    fix.op(OpCode::Copy, 0, 0x200);
    fix.ssa.destroy_varnode(vn).unwrap();
    assert_eq!(fix.ssa.loc_order().count(), 0);
    fix.ok();
}
