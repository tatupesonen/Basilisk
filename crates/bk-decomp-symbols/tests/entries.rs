//! Entries and symbols (spec 6.1, 4.4–4.5): `Scope::addMap`'s steps
//! (database.cc:1214–1271), category slots (`setCategory`, 3009–3029;
//! `removeSymbol`, 2289–2300), `getMapEntryPosition` (387–399) and
//! `EquateSymbol::isValueClose` (726–743).
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

use bk_core::{Address, Range, SpaceManager, VarnodeData};
use bk_decomp_symbols::flags::entry_props;
use bk_decomp_symbols::{
    ArchEnv, Database, EntryId, EntryKind, ScopeId, SymbolError, SymbolId, VarnodeFlags as V,
};
use bk_decomp_types::{Metatype, TypeFactory};
use common::small::{self, RAM, REG, STACK};

struct Fixture {
    spaces: Arc<SpaceManager>,
    db: Database,
    types: TypeFactory,
    global: ScopeId,
    func: ScopeId,
}

/// The small architecture; the global scope owns `ram:0x1000–0x1fff`,
/// `ram:0x1800–0x18ff` is volatile, and a function at `ram:0x1000` has its
/// local scope.
fn fixture() -> Fixture {
    let m = small::spaces(false);
    let mut types = small::types(&m);
    let spaces = Arc::new(m);
    let mut db = Database::new(ArchEnv::new(Arc::clone(&spaces)), true);
    let global = db.global().unwrap();
    db.add_range(global, RAM, 0x1000, 0x1fff).unwrap();
    db.set_property_range(V::VOLATILE, &Range::new(RAM, 0x1800, 0x18ff));
    let f = db
        .add_function(global, Address::new(RAM, 0x1000), "f", &mut types)
        .unwrap();
    let func = db.create_function_scope(f).unwrap();
    Fixture {
        spaces,
        db,
        types,
        global,
        func,
    }
}

fn symbol_of(db: &Database, e: EntryId) -> SymbolId {
    db.entry(e).unwrap().symbol()
}

#[test]
fn add_map_sets_flags_by_scope_range_and_use_limit() {
    let mut fx = fixture();
    let int4 = fx.types.base(4, Metatype::Int).unwrap();
    let pc = Address::new(RAM, 0x1004);
    let ram = |o| Address::new(RAM, o);
    let stack = |o| Address::new(STACK, o);
    // (scope, address, use point, symbol flags, use limit kept)
    let cases = [
        // A local on the stack, limited to a use point.
        (fx.func, stack(0x10), pc, V::empty(), true),
        // Not limited: address-tied.
        (fx.func, stack(0x20), Address::INVALID, V::ADDRTIED, false),
        // In the global scope's range from a local scope: persistent, and
        // the use limit dropped (Ghidra's "kludge for incorrectly generated
        // XML"), so address-tied with the address's properties.
        (
            fx.func,
            ram(0x1810),
            pc,
            V::PERSIST | V::ADDRTIED | V::VOLATILE,
            false,
        ),
        (fx.func, ram(0x1100), pc, V::PERSIST | V::ADDRTIED, false),
        // Outside the global range, from a local scope: the limit stays.
        (fx.func, ram(0x3000), pc, V::empty(), true),
        // Any global symbol is persistent.
        (
            fx.global,
            ram(0x3000),
            Address::INVALID,
            V::PERSIST | V::ADDRTIED,
            false,
        ),
        (fx.global, ram(0x3100), pc, V::PERSIST, true),
    ];
    for (i, (scope, addr, use_point, flags, limited)) in cases.into_iter().enumerate() {
        let e = fx
            .db
            .add_symbol_at(scope, &format!("s{i}"), int4, addr, use_point, &fx.types)
            .unwrap();
        let entry = fx.db.entry(e).unwrap();
        let sym = fx.db.symbol(entry.symbol()).unwrap();
        let mine = V::PERSIST | V::ADDRTIED | V::VOLATILE;
        assert_eq!(sym.flags() & mine, flags, "case {i}");
        assert_eq!(!entry.use_limit().is_empty(), limited, "case {i}");
        assert_eq!(entry.extra_flags(), V::MAPPED, "case {i}");
        assert_eq!((entry.offset(), entry.size()), (0, 4), "case {i}");
        assert_eq!(entry.properties() & entry_props::PIECE, 0, "case {i}");
    }
}

#[test]
fn an_entry_past_the_end_of_its_space_leaves_the_scope_unchanged() {
    let mut fx = fixture();
    let int8 = fx.types.base(8, Metatype::Int).unwrap();
    let sym = fx.db.add_symbol(fx.func, "late", int8, &fx.types).unwrap();
    let before = fx.db.scope_image(fx.func).unwrap();
    let flags = fx.db.symbol(sym).unwrap().flags();
    let got = fx
        .db
        .add_map_point(sym, Address::new(STACK, u64::MAX - 3), Address::INVALID);
    assert!(
        matches!(got, Err(SymbolError::BeyondSpace { ref name }) if name == "late"),
        "{got:?}"
    );
    assert_eq!(fx.db.scope_image(fx.func).unwrap(), before);
    assert_eq!(fx.db.symbol(sym).unwrap().flags(), flags);
    // The last byte of the space is fine.
    fx.db
        .add_map_point(sym, Address::new(STACK, u64::MAX - 7), Address::INVALID)
        .unwrap();
}

/// A join of two four-byte registers, most significant first, plus a
/// constant-space padding piece in the middle when asked.
fn join_addr(spaces: &SpaceManager, padded: bool) -> Address {
    let mut pieces = vec![VarnodeData::new(REG, 0, 4)];
    if padded {
        pieces.push(VarnodeData::new(bk_core::SpaceId::new(0), 0, 4));
    }
    pieces.push(VarnodeData::new(REG, 8, 4));
    spaces.find_add_join(pieces, 0).unwrap().unified().addr()
}

#[test]
fn a_join_address_adds_one_piece_per_storage_piece() {
    let mut fx = fixture();
    let int8 = fx.types.base(8, Metatype::Int).unwrap();
    let unknown8 = fx.types.base(8, Metatype::Unknown).unwrap();
    let int1 = fx.types.base(1, Metatype::Int).unwrap();
    let int12 = fx.types.array(12, int1).unwrap();
    let plain = join_addr(&fx.spaces, false);
    let padded = join_addr(&fx.spaces, true);
    // (type, join address, pieces as (address, offset, size, flags))
    let lo = Address::new(REG, 8);
    let hi = Address::new(REG, 0);
    let cases = [
        // Little endian: least significant piece first. A primitive whole
        // type marks the pieces precislo / precishi.
        (
            int8,
            plain,
            vec![(lo, 0, 4, V::PRECISLO), (hi, 4, 4, V::PRECISHI)],
        ),
        // `unknown8` is primitive too.
        (
            unknown8,
            plain,
            vec![(lo, 0, 4, V::PRECISLO), (hi, 4, 4, V::PRECISHI)],
        ),
        // An array is not: no flags. The constant piece is skipped but its
        // size still counts towards the offsets.
        (
            int12,
            padded,
            vec![(lo, 0, 4, V::empty()), (hi, 8, 4, V::empty())],
        ),
    ];
    for (k, (ty, addr, want)) in cases.into_iter().enumerate() {
        let e = fx
            .db
            .add_symbol_at(
                fx.func,
                &format!("j{k}"),
                ty,
                addr,
                Address::INVALID,
                &fx.types,
            )
            .unwrap();
        let sym = symbol_of(&fx.db, e);
        let entries = fx.db.symbol(sym).unwrap().entries().to_vec();
        assert_eq!(entries.len(), 1 + want.len(), "case {k}");
        let whole = fx.db.entry(entries[0]).unwrap();
        assert_eq!(whole.extra_flags(), V::MAPPED);
        assert_eq!(whole.properties() & entry_props::PIECE, 0);
        for (e, (addr, offset, size, flags)) in entries[1..].iter().zip(want) {
            let piece = fx.db.entry(*e).unwrap();
            assert_eq!(
                piece.kind(),
                EntryKind::Map {
                    addr,
                    conflict: None
                },
                "case {k}"
            );
            assert_eq!((piece.offset(), piece.size()), (offset, size), "case {k}");
            // Pieces never get `mapped`.
            assert_eq!(piece.extra_flags(), flags, "case {k}");
            assert_ne!(piece.properties() & entry_props::PIECE, 0, "case {k}");
        }
    }
}

#[test]
fn map_entry_position_counts_by_the_asked_entry_size() {
    let mut fx = fixture();
    let int8 = fx.types.base(8, Metatype::Int).unwrap();
    let plain = join_addr(&fx.spaces, false);
    let first = fx
        .db
        .add_symbol_at(fx.func, "m", int8, plain, Address::INVALID, &fx.types)
        .unwrap();
    let sym = symbol_of(&fx.db, first);
    let second = fx
        .db
        .add_map_point(sym, Address::new(STACK, 0x40), Address::INVALID)
        .unwrap();
    let entries = fx.db.symbol(sym).unwrap().entries().to_vec();
    assert_eq!(entries.len(), 4);
    // Ghidra counts every earlier entry when the asked one is whole (pieces
    // included) and none when it is a piece.
    let got: Vec<Option<i32>> = entries
        .iter()
        .map(|e| fx.db.map_entry_position(sym, *e).unwrap())
        .collect();
    assert_eq!(got, [Some(0), Some(0), Some(0), Some(3)]);
    assert_eq!(entries[3], second);
    // An entry of another symbol is not in the list.
    let other = fx
        .db
        .add_symbol_at(
            fx.func,
            "o",
            int8,
            Address::new(STACK, 0x80),
            Address::INVALID,
            &fx.types,
        )
        .unwrap();
    assert_eq!(fx.db.map_entry_position(sym, other).unwrap(), None);
}

#[test]
fn category_slots_keep_holes_and_drop_trailing_ones() {
    let mut fx = fixture();
    let int4 = fx.types.base(4, Metatype::Int).unwrap();
    let mut add = |name: &str| fx.db.add_symbol(fx.func, name, int4, &fx.types).unwrap();
    let (a, b, c, d) = (add("a"), add("b"), add("c"), add("d"));
    let slots = |db: &Database, cat: i16| db.scope(fx.func).unwrap().category(cat).to_vec();
    // Category 0 (parameters) uses the index asked for, filling with holes.
    fx.db.set_category(a, 0, 3).unwrap();
    assert_eq!(slots(&fx.db, 0), [None, None, None, Some(a)]);
    fx.db.set_category(b, 0, 1).unwrap();
    assert_eq!(slots(&fx.db, 0), [None, Some(b), None, Some(a)]);
    // Removing the last member drops the trailing holes; others stay.
    fx.db.remove_symbol(a).unwrap();
    assert_eq!(slots(&fx.db, 0), [None, Some(b)]);
    // Other categories append, whatever index is asked for.
    fx.db.set_category(c, 1, 7).unwrap();
    fx.db.set_category(d, 1, 0).unwrap();
    assert_eq!(slots(&fx.db, 1), [Some(c), Some(d)]);
    assert_eq!(fx.db.symbol(d).unwrap().category_index(), 1);
    // Moving within a category: the old slot empties first.
    fx.db.set_category(c, 1, 0).unwrap();
    assert_eq!(slots(&fx.db, 1), [None, Some(d), Some(c)]);
    assert_eq!(fx.db.symbol(c).unwrap().category_index(), 2);
    // Leaving every category.
    fx.db.set_category(b, -1, 0).unwrap();
    assert_eq!(slots(&fx.db, 0), Vec::<Option<SymbolId>>::new());
    assert_eq!(fx.db.symbol(b).unwrap().category(), -1);
}

#[test]
fn equate_values_that_are_close() {
    let mut fx = fixture();
    let addr = Address::new(RAM, 0x1004);
    // (equate value, operand, size, close)
    let cases: &[(u64, u64, u32, bool)] = &[
        (5, 5, 4, true),
        (5, 4, 4, true),
        (5, 6, 4, true),
        (5, 0xffff_fffb, 4, true),   // -5 at 4 bytes
        (5, 0xffff_fffa, 4, true),   // ~5 at 4 bytes
        (5, 0x1_0000_0005, 4, true), // high bits of the operand ignored
        (5, 7, 4, false),
        (0xffff_ffff_ffff_fffb, 5, 4, true), // a sign-extended value: -5
        (0xffff_ffff_ffff_fffb, 0xffff_fffb, 4, true),
        (0x1_0000_0005, 5, 4, false), // bits above the size: nothing close
        (0x1_0000_0005, 0x1_0000_0005, 4, true), // but equal is equal
        (0x80, 0x80, 1, true),
        (0xffff_ffff_ffff_ff80, 0x7f, 1, true), // -128 at 1 byte, minus one
        (0x8000, 0x7fff, 1, false),
    ];
    for (k, &(value, op2, size, close)) in cases.iter().enumerate() {
        let sym = fx
            .db
            .add_equate_symbol(
                fx.func,
                &format!("e{k}"),
                0,
                value,
                addr,
                k as u64,
                &mut fx.types,
            )
            .unwrap();
        assert_eq!(
            fx.db.symbol(sym).unwrap().is_value_close(op2, size),
            close,
            "{value:#x} {op2:#x} {size}"
        );
    }
    // Not an equate: never close.
    let int4 = fx.types.base(4, Metatype::Int).unwrap();
    let plain = fx.db.add_symbol(fx.func, "p", int4, &fx.types).unwrap();
    assert!(!fx.db.symbol(plain).unwrap().is_value_close(0, 4));
}
