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
//! `SpacebaseScopes` over the database (spec 5.5).

mod common;

use std::sync::Arc;

use bk_core::Address;
use bk_decomp_symbols::spacebase::DatabaseScopes;
use bk_decomp_types::Metatype;
use bk_decomp_types::xml::SpacebaseScopes;
use common::small::{RAM, db};

#[test]
fn frames_scopes_and_sub_types() {
    let (mut d, mut types) = db();
    let glob = d.global().unwrap();
    d.add_range(glob, RAM, 0, 0xffff).unwrap();
    let f = d
        .add_function(glob, Address::new(RAM, 0x100), "main", &mut types)
        .unwrap();
    let fs = d.create_function_scope(f).unwrap();
    let fid = d.scope(fs).unwrap().ghidra_id();
    let int4 = types.base(4, Metatype::Int).unwrap();
    let byte = types.base(1, Metatype::Unknown).unwrap();
    let arr = types.array(8, int4).unwrap();
    d.add_symbol_at(
        glob,
        "table",
        arr,
        Address::new(RAM, 0x2000),
        Address::INVALID,
        &types,
    )
    .unwrap();
    d.add_symbol_at(
        glob,
        "g",
        int4,
        Address::new(RAM, 0x1000),
        Address::INVALID,
        &types,
    )
    .unwrap();
    let view = DatabaseScopes::new(Arc::new(d), Arc::new(types), byte);
    assert_eq!(view.frame_of_scope(fid), Some((RAM, 0x100)));
    assert_eq!(view.frame_of_scope(0), None);
    assert_eq!(view.scope_of_frame(Some((RAM, 0x100))), fid);
    assert_eq!(view.scope_of_frame(Some((RAM, 0x104))), 0);
    assert_eq!(view.scope_of_frame(None), 0);
    assert_eq!(view.sub_type(RAM, 0, 0x1002), Some((int4, 2)));
    // Inside the scope with no symbol: undefined1; outside it: nothing.
    assert_eq!(view.sub_type(RAM, 0, 0x1800), Some((byte, 0)));
    assert_eq!(view.sub_type(RAM, 0, 0x20000), None);
    // The array: nearest arrayed component forward from just before it.
    let n = view.nearest(RAM, 0, 0x1ffc, true).unwrap();
    assert_eq!((n.offset, n.el_size), (-4, 4));
    // Forward from inside the array: TypeArray answers nothing past its
    // start, and no symbol starts later.
    assert!(view.nearest(RAM, 0, 0x2004, true).is_none());
    let n = view.nearest(RAM, 0, 0x2004, false).unwrap();
    assert_eq!((n.offset, n.el_size, n.distance), (4, 4, 0));
}
