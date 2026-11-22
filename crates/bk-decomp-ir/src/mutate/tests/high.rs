//! High-variable events (`crate::high`): each method's events against the
//! `Varnode` members of varnode.cc it corresponds to, in call order.

use bk_decomp_types::TypeId;
use bk_pcode::OpCode;

use crate::HighEvent::{self, CoverDirty, FlagsDirty, SymbolDirty, TypeDirty};
use crate::flags::vflags;
use crate::ids::{EntryRef, HighId, VarnodeId};
use crate::mutate::env::{Effect, PropertiesAnswer};
use crate::testing::{Fx, fx};

fn h(n: u32) -> HighId {
    HighId::new(n)
}

/// A free register varnode with high `h(n)`; the queue is drained.
fn with_high(fix: &mut Fx, off: u64, n: u32) -> VarnodeId {
    let vn = fix.regvn(off, 4);
    fix.ssa.set_high(vn, Some(h(n)), 0).unwrap();
    let _ = fix.ssa.take_high_events();
    vn
}

fn take(fix: &mut Fx) -> Vec<HighEvent> {
    fix.ssa.take_high_events()
}

const ENTRY: EntryRef = EntryRef {
    symbol: 7,
    position: 0,
};

#[test]
fn flag_setters_report_only_through_set_flags() {
    // setFlags/clearFlags (varnode.cc:371–393): flagsDirty, and coverDirty
    // when the bits include coverdirty; varnode.hh:309–314, 322–325 go
    // through them, 305–308, 315–316, 328–331 write `flags` directly.
    let mut fix = fx(1);
    let vn = with_high(&mut fix, 0, 1);
    fix.ssa.set_implied(vn).unwrap();
    fix.ssa.clear_addr_force(vn).unwrap();
    fix.ssa.set_precis_hi(vn).unwrap();
    assert_eq!(take(&mut fix), [FlagsDirty(h(1)); 3]);
    fix.ssa.set_mark(vn).unwrap();
    fix.ssa.set_direct_write(vn).unwrap();
    fix.ssa.set_return_address(vn).unwrap();
    fix.ssa.set_auto_live_hold(vn).unwrap();
    fix.ssa.set_proto_partial(vn).unwrap();
    fix.ssa.set_ptr_flow(vn).unwrap();
    fix.ssa.set_symbol_check(vn, 1).unwrap();
    fix.ssa.set_consume(vn, 1).unwrap();
    assert_eq!(take(&mut fix), []);
    fix.ssa.varnode_set_flags(vn, vflags::COVERDIRTY).unwrap();
    fix.ssa.varnode_clear_flags(vn, vflags::COVERDIRTY).unwrap();
    // A call that changes no bit still reports (setFlags does not test).
    fix.ssa.varnode_set_flags(vn, 0).unwrap();
    assert_eq!(
        take(&mut fix),
        [
            FlagsDirty(h(1)),
            CoverDirty(h(1)),
            FlagsDirty(h(1)),
            CoverDirty(h(1)),
            FlagsDirty(h(1))
        ]
    );
}

#[test]
fn reads_report_cover_dirty_for_the_read_varnode() {
    // addDescend (varnode.cc:330–340) and eraseDescend (316–326):
    // setFlags(coverdirty).
    let mut fix = fx(1);
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let vn = fix.ssa.op_output(def).unwrap();
    fix.ssa.set_high(vn, Some(h(2)), 0).unwrap();
    let read = fix.op(OpCode::Copy, 1, 0x104);
    let _ = take(&mut fix);
    fix.ssa.op_set_input(&mut fix.env, read, vn, 0).unwrap();
    assert_eq!(take(&mut fix), [FlagsDirty(h(2)), CoverDirty(h(2))]);
    fix.ssa.op_unset_input(read, 0).unwrap();
    assert_eq!(take(&mut fix), [FlagsDirty(h(2)), CoverDirty(h(2))]);
}

#[test]
fn defining_and_freeing_follow_set_def_xref_and_make_free() {
    // opSetOutput: VarnodeBank::setDef → Varnode::setDef(op)
    // (varnode.cc:421–436: setFlags(coverdirty|written)), xref's
    // setFlags(insert) (1307), then setVarnodeProperties
    // (funcdata_varnode.cc:25–41: setFlags(vflags & ~typelock)).
    let mut fix = fx(1);
    let vn = with_high(&mut fix, 0, 3);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    fix.ssa.op_set_output(&mut fix.env, op, vn).unwrap();
    let f = FlagsDirty(h(3));
    let c = CoverDirty(h(3));
    assert_eq!(take(&mut fix), [f, c, f, f]);
    // opUnsetOutput: makeFree (1317–1327): setDef(null) is
    // setFlags(coverdirty) and clearFlags(written); then
    // clearFlags(insert|input|indirect_creation).
    fix.ssa.op_unset_output(op).unwrap();
    assert_eq!(take(&mut fix), [f, c, f, f]);
}

#[test]
fn an_input_merged_into_its_twin_reports_replace_and_removal() {
    // VarnodeBank::setInput (1359–1371): setInput() = setFlags(input |
    // coverdirty); xref finds the twin: replace (1333–1353) moves the
    // reader (addDescend on the twin), then setFlags(coverdirty) on old and
    // new; `delete vn` (642–651) removes it from its high.
    let mut fix = fx(1);
    let a = with_high(&mut fix, 0, 4);
    let a = fix.ssa.set_input_varnode(&mut fix.env, a).unwrap();
    let b = with_high(&mut fix, 0, 5);
    let read = fix.op(OpCode::Copy, 1, 0x100);
    fix.ssa.op_set_input(&mut fix.env, read, b, 0).unwrap();
    let _ = take(&mut fix);
    assert_eq!(fix.ssa.bank_set_input(b).unwrap(), a);
    assert_eq!(
        take(&mut fix),
        [
            FlagsDirty(h(5)),
            CoverDirty(h(5)),
            FlagsDirty(h(4)),
            CoverDirty(h(4)),
            FlagsDirty(h(5)),
            CoverDirty(h(5)),
            FlagsDirty(h(4)),
            CoverDirty(h(4)),
            HighEvent::Removed { high: h(5), vn: b },
        ]
    );
}

#[test]
fn set_input_varnode_reports_set_unaffected_but_not_set_return_address() {
    // Funcdata::setInputVarnode (funcdata_varnode.cc:354–386).
    let mut fix = fx(1);
    let vn = with_high(&mut fix, 0, 6);
    let addr = fix.reg(0);
    fix.env.effects.insert((addr, 4), Effect::ReturnAddress);
    fix.ssa.set_input_varnode(&mut fix.env, vn).unwrap();
    let f = FlagsDirty(h(6));
    // setInput (F, C), xref insert (F), setVarnodeProperties (F),
    // setUnaffected (F).
    assert_eq!(take(&mut fix), [f, CoverDirty(h(6)), f, f, f]);
}

#[test]
fn symbol_properties_report_the_new_entry_then_the_flags() {
    // setSymbolProperties (varnode.cc:441–456): a type-locked symbol's
    // new entry: high->setSymbol, then setFlags.
    let mut fix = fx(1);
    let vn = with_high(&mut fix, 0, 7);
    let addr = fix.reg(0);
    fix.env.properties.insert(
        (addr, 4),
        PropertiesAnswer::Entry {
            entry: ENTRY,
            locked_type: None,
            symbol_type_locked: true,
            flags: vflags::MAPPED,
        },
    );
    fix.ssa.set_varnode_properties(&mut fix.env, vn).unwrap();
    assert_eq!(
        take(&mut fix),
        [HighEvent::SetSymbol { high: h(7), vn }, FlagsDirty(h(7))]
    );
}

#[test]
fn types_and_symbols() {
    // updateType (488–521): typeDirty when changed.
    let mut fix = fx(1);
    let vn = with_high(&mut fix, 0, 8);
    assert!(fix.ssa.update_type(vn, TypeId::from_raw(1)).unwrap());
    assert!(!fix.ssa.update_type(vn, TypeId::from_raw(1)).unwrap());
    assert!(
        fix.ssa
            .update_type_locked(vn, TypeId::from_raw(2), true, false)
            .unwrap()
    );
    assert!(!fix.ssa.update_type(vn, TypeId::from_raw(3)).unwrap());
    assert_eq!(take(&mut fix), [TypeDirty(h(8)); 2]);
    // setSymbolEntry (461–471): the caller's setFlags, then setSymbol.
    fix.ssa.varnode_set_flags(vn, vflags::MAPPED).unwrap();
    fix.ssa.set_symbol_entry(vn, Some(ENTRY)).unwrap();
    assert_eq!(
        take(&mut fix),
        [FlagsDirty(h(8)), HighEvent::SetSymbol { high: h(8), vn }]
    );
    // setSymbolReference (478–484).
    fix.ssa.set_symbol_reference(vn, ENTRY, 4).unwrap();
    assert_eq!(
        take(&mut fix),
        [HighEvent::SetSymbolReference {
            high: h(8),
            vn,
            entry: ENTRY,
            offset: 4
        }]
    );
    // copySymbol (525–537): typeDirty, then setSymbol when the copied
    // entry is set.
    let other = with_high(&mut fix, 8, 9);
    fix.ssa.copy_symbol(other, vn).unwrap();
    assert_eq!(
        take(&mut fix),
        [
            TypeDirty(h(9)),
            HighEvent::SetSymbol {
                high: h(9),
                vn: other
            }
        ]
    );
    let plain = fix.regvn(16, 4);
    fix.ssa.copy_symbol(other, plain).unwrap();
    assert_eq!(take(&mut fix), [TypeDirty(h(9))]);
}

#[test]
fn clear_symbol_links_walks_the_instances() {
    // clearSymbolLinks (397–415): clearFlags per instance, symbolDirty if
    // any had an entry; without a high, only the varnode.
    let mut fix = fx(1);
    let a = with_high(&mut fix, 0, 10);
    let b = with_high(&mut fix, 8, 10);
    fix.ssa.set_symbol_entry(b, Some(ENTRY)).unwrap();
    let _ = take(&mut fix);
    fix.ssa.clear_symbol_links(a).unwrap();
    assert_eq!(
        take(&mut fix),
        [FlagsDirty(h(10)), FlagsDirty(h(10)), SymbolDirty(h(10))]
    );
    assert_eq!(fix.ssa.varnode_entry(b), None);
    fix.ssa.clear_symbol_links(a).unwrap();
    assert_eq!(take(&mut fix), [FlagsDirty(h(10)); 2]);
}

#[test]
fn covers_and_destruction() {
    // calcCover (254–262): setFlags(coverdirty); updateCover (233–242):
    // clearFlags(coverdirty), which reports coverDirty as well.
    let mut fix = fx(1);
    let def = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
    let vn = fix.ssa.op_output(def).unwrap();
    fix.ssa.set_high(vn, Some(h(11)), 0).unwrap();
    let _ = take(&mut fix);
    fix.ssa.calc_cover(vn).unwrap();
    fix.ssa.varnode_cover(vn).unwrap();
    assert_eq!(
        take(&mut fix),
        [FlagsDirty(h(11)), CoverDirty(h(11))].repeat(2)
    );
    // ~Varnode (642–651) through destroyVarnode.
    fix.ssa.op_unset_output(def).unwrap();
    let _ = take(&mut fix);
    fix.ssa.destroy_varnode(vn).unwrap();
    assert_eq!(take(&mut fix), [HighEvent::Removed { high: h(11), vn }]);
}

#[test]
fn varnodes_without_a_high_record_nothing_and_the_queue_does_not_allocate() {
    let mut fix = fx(1);
    let vn = fix.regvn(0, 4);
    let op = fix.op(OpCode::Copy, 1, 0x100);
    fix.ssa.op_set_output(&mut fix.env, op, vn).unwrap();
    fix.ssa.set_implied(vn).unwrap();
    fix.ssa.update_type(vn, TypeId::from_raw(1)).unwrap();
    fix.ssa.set_symbol_reference(vn, ENTRY, 0).unwrap();
    fix.ssa.clear_symbol_links(vn).unwrap();
    fix.ssa.op_unset_output(op).unwrap();
    fix.ssa.destroy_varnode(vn).unwrap();
    assert_eq!(fix.ssa.high_events(), []);
    assert_eq!(fix.ssa.take_high_events().capacity(), 0);
}
