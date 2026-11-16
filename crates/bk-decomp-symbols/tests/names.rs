//! The name rules of spec 4.8, one table each (database.cc:2616–2799):
//! `makeNameUnique`, `buildUndefinedName`, `buildVariableName`.
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

mod common;

use std::sync::Arc;

use bk_core::Address;
use bk_decomp_symbols::{ArchEnv, Database, ScopeId, SymbolError, VarnodeFlags, VarnodeFlags as V};
use bk_decomp_types::{Metatype, TypeFactory};
use common::small::{self, RAM, REG, STACK};

/// The small architecture with its registers, and a global scope holding
/// the given names.
fn scope_with(names: &[&str]) -> (Database, ScopeId, TypeFactory) {
    let m = small::spaces(false);
    let types = small::types(&m);
    let regs = small::Regs(
        ["r0", "r1", "r2", "r3", "sp"]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    (*n).to_owned(),
                    bk_core::VarnodeData::new(REG, 8 * i as u64, 8),
                )
            })
            .collect(),
    );
    let mut env = ArchEnv::new(Arc::new(m));
    env.registers = Some(Arc::new(regs));
    let mut db = Database::new(env, true);
    let global = db.global().unwrap();
    let mut types = types;
    let ty = types.base(4, Metatype::Unknown).unwrap();
    for n in names {
        db.add_symbol(global, n, ty, &types).unwrap();
    }
    (db, global, types)
}

#[test]
fn make_name_unique() {
    // (names in the scope, the name asked for, Ghidra's answer or None for
    // its "Unable to uniquify name" error)
    let cases: &[(&[&str], &str, Option<&str>)] = &[
        (&[], "nm", Some("nm")),
        (&["nm"], "nm", Some("nm_00")),
        (&["nm", "nm_07"], "nm", Some("nm_08")),
        (&["nm", "nm_00", "nm_01"], "nm", Some("nm_02")),
        (&["nm", "nm_99"], "nm", Some("nm_x00100")),
        (&["nm", "nm_x00100"], "nm", Some("nm_x00101")),
        (&["nm", "nm_x99999"], "nm", Some("nm_x100000")),
        // A non-conforming name is skipped, the walk goes on backwards.
        (&["nm", "nm_ab"], "nm", Some("nm_00")),
        (&["nm", "nm_05", "nm_ab"], "nm", Some("nm_06")),
        (&["nm", "nm_05", "nm_123"], "nm", Some("nm_06")),
        (&["nm", "nm_05", "nm_x0012"], "nm", Some("nm_06")),
        (&["nm", "nm_5"], "nm", Some("nm_00")),
        // Names past `nm_x99999` and names not of the form `nm_…` play no part.
        (
            &["nm", "nm_07", "nm_y00", "nmz", "nm0"],
            "nm",
            Some("nm_08"),
        ),
        // The answer is taken: the x form of a small id gives the two-digit
        // form, which sorts before it.
        (&["nm", "nm_06", "nm_x00005"], "nm", None),
        // Duplicated base names count once.
        (&["nm", "nm", "nm_03"], "nm", Some("nm_04")),
    ];
    for (names, nm, want) in cases {
        let (db, scope, _) = scope_with(names);
        let got = db.make_name_unique(scope, nm);
        match want {
            Some(w) => assert_eq!(got.unwrap(), *w, "{names:?} {nm}"),
            None => assert!(
                matches!(got, Err(SymbolError::Uniquify { .. })),
                "{names:?} {nm}: {got:?}"
            ),
        }
    }
}

#[test]
fn build_undefined_name() {
    let cases: &[(&[&str], Option<&str>)] = &[
        (&[], Some("$$undef00000000")),
        (&["a"], Some("$$undef00000000")),
        (&["$$undef00000003"], Some("$$undef00000004")),
        (
            &["$$undef00000003", "$$undef0000000a"],
            Some("$$undef0000000b"),
        ),
        (&["$$undeffffffffe"], Some("$$undefffffffff")),
        // Only the name just before `$$undefz` is looked at.
        (&["$$undef00000003", "$$undefq"], Some("$$undef00000000")),
        (&["$$undef00000003", "$$undef"], Some("$$undef00000004")),
        // Ghidra reads the digits with `istream >> hex`: it stops at the
        // first non-hex character, and a failed read gives 0 (C++11).
        (&["$$undef0000000g"], Some("$$undef00000001")),
        (&["$$undefg0000000"], Some("$$undef00000001")),
        (&["$$undefffffffff"], None),
    ];
    for (names, want) in cases {
        let (db, scope, _) = scope_with(names);
        let got = db.build_undefined_name(scope);
        match want {
            Some(w) => assert_eq!(got.unwrap(), *w, "{names:?}"),
            None => assert!(
                matches!(got, Err(SymbolError::UndefinedName)),
                "{names:?}: {got:?}"
            ),
        }
    }
}

#[test]
fn build_variable_name() {
    let (mut db, scope, mut types) = scope_with(&["iVar5"]);
    let int4 = types.base(4, Metatype::Int).unwrap();
    let int8 = types.base(8, Metatype::Int).unwrap();
    let int4_name = types.get(int4).unwrap().name().to_owned();
    let int8_name = types.get(int8).unwrap().name().to_owned();
    // printNameBase writes the first letter of a named type.
    let i4 = int4_name.get(..1).unwrap();
    let i8 = int8_name.get(..1).unwrap();
    let ram = |o| Address::new(RAM, o);
    let reg = |o| Address::new(REG, o);
    let f = VarnodeFlags::empty;
    // (address, type, index, flags, Ghidra's name, index after)
    let cases: Vec<(Address, Option<_>, i32, VarnodeFlags, String, i32)> = vec![
        (Address::INVALID, None, 0, f(), "unassigned_".into(), 0),
        (
            reg(8),
            Some(int8),
            0,
            V::UNAFFECTED | V::RETURN_ADDRESS,
            "unaff_retaddr".into(),
            0,
        ),
        (reg(8), Some(int8), 0, V::UNAFFECTED, "unaff_r1".into(), 0),
        // The register name needs the type's size.
        (
            reg(8),
            Some(int4),
            0,
            V::UNAFFECTED,
            "unaff_00000008".into(),
            0,
        ),
        (
            ram(0x1000),
            None,
            0,
            V::UNAFFECTED,
            "unaff_00001000".into(),
            0,
        ),
        (reg(0), Some(int8), 0, V::PERSIST, "r0".into(), 0),
        (
            ram(0x1000),
            Some(int4),
            0,
            V::PERSIST,
            format!("{i4}Ram0000000000001000"),
            0,
        ),
        (
            ram(0x1000),
            None,
            0,
            V::PERSIST,
            "Ram0000000000001000".into(),
            0,
        ),
        (reg(16), Some(int8), -1, V::INPUT, "in_r2".into(), -1),
        (
            ram(0x20),
            Some(int4),
            -1,
            V::INPUT,
            "in_ram_00000020".into(),
            -1,
        ),
        (reg(16), Some(int8), 3, V::INPUT, "param_3".into(), 3),
        // The input rules come before addrtied.
        (
            Address::new(STACK, 0x10),
            Some(int4),
            2,
            V::INPUT | V::ADDRTIED,
            "param_2".into(),
            2,
        ),
        (
            Address::new(STACK, 0x10),
            Some(int4),
            0,
            V::ADDRTIED,
            format!("{i4}Stack0000000000000010"),
            0,
        ),
        (
            reg(24),
            Some(int8),
            0,
            V::INDIRECT_CREATION,
            "extraout_r3".into(),
            0,
        ),
        (
            ram(0x40),
            Some(int4),
            0,
            V::INDIRECT_CREATION,
            "extraout_var".into(),
            0,
        ),
        // A local: the index is used and advanced.
        (reg(32), Some(int4), 2, f(), format!("{i4}Var2"), 3),
        (reg(32), Some(int8), 7, f(), format!("{i8}Var7"), 8),
        (reg(32), None, 4, f(), "Var4".into(), 5),
        // "iVar5" is taken: the next free index.
        (reg(32), Some(int4), 5, f(), format!("{i4}Var6"), 7),
    ];
    assert_eq!(i4, "i", "the 4-byte integer is {int4_name}");
    for (addr, ty, index, flags, want, index_after) in cases {
        let mut i = index;
        let got = db
            .build_variable_name(scope, addr, Address::INVALID, ty, &mut i, flags, &types)
            .unwrap();
        assert_eq!(got, want, "{addr:?} {flags:?} {index}");
        assert_eq!(i, index_after, "index after {want}");
    }
    // The unique rule applies to every form: a taken name gets `_00`.
    db.add_symbol(scope, "unaff_r1", int8, &types).unwrap();
    let mut i = 0;
    let got = db
        .build_variable_name(
            scope,
            reg(8),
            Address::INVALID,
            Some(int8),
            &mut i,
            V::UNAFFECTED,
            &types,
        )
        .unwrap();
    assert_eq!(got, "unaff_r1_00");
    // Ten more taken locals: after ten bumps the first name is made unique.
    for k in 6..=15 {
        db.add_symbol(scope, &format!("iVar{k}"), int4, &types)
            .unwrap();
    }
    let mut i = 5;
    let got = db
        .build_variable_name(
            scope,
            reg(32),
            Address::INVALID,
            Some(int4),
            &mut i,
            f(),
            &types,
        )
        .unwrap();
    assert_eq!((got.as_str(), i), ("iVar5_00", 16));
}
