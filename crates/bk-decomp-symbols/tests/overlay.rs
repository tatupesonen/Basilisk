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
//! Overlays and commit (spec 5.7, ADR-044): committing after every
//! function reproduces the sequential database exactly; the frozen part is
//! `Send + Sync`.

mod common;

use std::sync::Arc;

use bk_core::{Address, Provenance, Range};
use bk_decomp_symbols::overlay::Overlay;
use bk_decomp_symbols::{Database, VarnodeFlags};
use bk_decomp_types::{Metatype, TypeFactory};
use bk_marshal::XmlEncoder;
use common::small::{RAM, db};

fn text(db: &Database, types: &TypeFactory) -> String {
    let mut enc = XmlEncoder::new(true);
    db.encode(&mut enc, types, None).unwrap();
    let glob = db.global().unwrap();
    format!(
        "{}{}",
        enc.into_string(),
        db.print_entries(glob, types).unwrap()
    )
}

/// One "function" worth of global additions, through any driver.
fn steps(base_has: usize) -> Vec<(String, u64)> {
    (0..4)
        .map(|i| {
            (
                format!("DAT_{:08x}", 0x1000 + 8 * (i + base_has)),
                0x1000 + 8 * (i + base_has) as u64,
            )
        })
        .collect()
}

#[test]
fn sequential_commits_equal_direct_changes() {
    let (mut direct, mut types) = db();
    let glob = direct.global().unwrap();
    direct.add_range(glob, RAM, 0, u64::MAX).unwrap();
    let mut shared = direct.clone();
    let u4 = types.base(4, Metatype::Unknown).unwrap();
    for f in 0..3 {
        // Direct: Ghidra's single mutable database.
        for (name, at) in steps(f * 4) {
            let e = direct
                .add_symbol_at(
                    glob,
                    &name,
                    u4,
                    Address::new(RAM, at),
                    Address::INVALID,
                    &types,
                )
                .unwrap();
            let s = direct.entry(e).unwrap().symbol();
            direct.set_attribute(s, VarnodeFlags::TYPELOCK).unwrap();
        }
        direct
            .find_create_scope_from_symbol_name("ns::x", None)
            .unwrap();
        direct.set_property_range(VarnodeFlags::READONLY, &Range::new(RAM, 0x2000, 0x20ff));
        // Overlay on the frozen database, committed afterwards.
        let frozen = Arc::new(shared.clone());
        let mut ov = Overlay::new(Arc::clone(&frozen));
        for (name, at) in steps(f * 4) {
            let e = ov
                .add_symbol_at(
                    glob,
                    &name,
                    u4,
                    Address::new(RAM, at),
                    Address::INVALID,
                    &mut types,
                )
                .unwrap();
            let s = ov.db().entry(e).unwrap().symbol();
            ov.set_attribute(s, VarnodeFlags::TYPELOCK, &mut types)
                .unwrap();
            // The overlay sees its own additions; the frozen base does not.
            assert!(
                ov.db()
                    .query_by_addr(glob, Address::new(RAM, at), Address::INVALID)
                    .unwrap()
                    .is_some()
            );
            assert!(
                frozen
                    .query_by_addr(glob, Address::new(RAM, at), Address::INVALID)
                    .unwrap()
                    .is_none()
            );
        }
        ov.find_create_scope_from_symbol_name("ns::x", None, &mut types)
            .unwrap();
        ov.set_property_range(
            VarnodeFlags::READONLY,
            Range::new(RAM, 0x2000, 0x20ff),
            &mut types,
        )
        .unwrap();
        // A change that fails in the overlay fails again on commit.
        let s0 = ov.db().find_by_name(glob, &steps(f * 4)[0].0).unwrap()[0];
        assert!(
            ov.retype_symbol(
                s0,
                types.base(8, Metatype::Unknown).unwrap(),
                Provenance::Analysis,
                &mut types
            )
            .is_ok()
        );
        let e = direct.find_by_name(glob, &steps(f * 4)[0].0).unwrap()[0];
        direct
            .retype_symbol(e, types.base(8, Metatype::Unknown).unwrap(), &types)
            .unwrap();
        ov.commit(&mut shared, &mut types).unwrap();
        assert_eq!(text(&shared, &types), text(&direct, &types));
    }
}

#[test]
fn overlays_from_one_base_commit_in_a_chosen_order() {
    let (mut base, mut types) = db();
    let glob = base.global().unwrap();
    base.add_range(glob, RAM, 0, u64::MAX).unwrap();
    let frozen = Arc::new(base.clone());
    let u4 = types.base(4, Metatype::Unknown).unwrap();
    let mut a = Overlay::new(Arc::clone(&frozen));
    let mut b = Overlay::new(Arc::clone(&frozen));
    let ea = a
        .add_symbol_at(
            glob,
            "x",
            u4,
            Address::new(RAM, 0x10),
            Address::INVALID,
            &mut types,
        )
        .unwrap();
    let sa = a.db().entry(ea).unwrap().symbol();
    a.rename_symbol(sa, "y", Provenance::User, &mut types)
        .unwrap();
    let eb = b
        .add_symbol_at(
            glob,
            "x",
            u4,
            Address::new(RAM, 0x20),
            Address::INVALID,
            &mut types,
        )
        .unwrap();
    let sb = b.db().entry(eb).unwrap().symbol();
    b.rename_symbol(sb, "z", Provenance::User, &mut types)
        .unwrap();
    // Both created "the same" new symbol id; commit translates it.
    assert_eq!(sa, sb);
    a.commit(&mut base, &mut types).unwrap();
    b.commit(&mut base, &mut types).unwrap();
    let names: Vec<String> = base
        .scope(glob)
        .unwrap()
        .symbols_by_name()
        .map(|s| base.symbol(s).unwrap().name().to_owned())
        .collect();
    assert_eq!(names, ["y", "z"]);
    let z = base.find_by_name(glob, "z").unwrap()[0];
    assert_eq!(base.symbol(z).unwrap().name_provenance(), Provenance::User);
}

#[test]
fn frozen_state_is_send_and_sync() {
    fn check<T: Send + Sync + 'static>() {}
    check::<Database>();
    check::<Arc<Database>>();
    check::<Overlay>();
    check::<TypeFactory>();
}
