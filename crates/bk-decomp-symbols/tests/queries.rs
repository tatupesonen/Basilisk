//! The queries of spec 4.6, one table row each, on one fixture: the public
//! `query*` / `discoverScope` / `isReadOnly` (database.cc:999–1182 the
//! `stack*` walks, 1318–1547 the queries, 1951 `isReadOnly`, 3373–3400
//! `mapScope`) and `ScopeInternal::find*` (database.cc:2373–2614, with
//! `SymbolEntry::inUse` at 93–99 and `rangemap::find_first_after` /
//! `find_last_before` at rangemap.hh:436–462).
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

use bk_core::{Address, Range};
use bk_decomp_symbols::{Database, EntryId, ScopeId, SymbolId, VarnodeFlags as V};
use bk_decomp_types::{Metatype, TypeFactory};
use common::small::{self, RAM, STACK};

/// The fixture:
///
/// * global scope `G` owns `ram:0x1000–0x1fff`; `ram:0x1800–0x18ff` is
///   volatile and `ram:0x5000–0x50ff` read-only in the property map;
/// * in `G`: function `f` at `0x1000`, `g8` (8 bytes) at `0x1100`, `g2` (2
///   bytes) at `0x1104`, label `lab` at `0x1200`, external reference `ext`
///   at `0x1300` to `f`, external reference `ext2` and then `d8` (8 bytes)
///   at `0x1400`, external reference `ext3` at `0x3040` to `f`, function `h`
///   at `0x3080`, `shadow` at `0x3010`, two symbols named `dup`;
/// * namespace `N` (under `G`) owns `ram:0x3000–0x30ff` and holds `n4` at
///   `0x3010`; function `k` at `0x3020` in `N`, with local scope `K`;
/// * `F`, the local scope of `f`, owns `stack:0x0–0xff` and holds `loc`
///   at `stack:0x10`, valid at `ram:0x1004` only.
struct Fx {
    db: Database,
    g: ScopeId,
    n: ScopeId,
    f: ScopeId,
    k: ScopeId,
    s: std::collections::BTreeMap<&'static str, SymbolId>,
}

fn ram(o: u64) -> Address {
    Address::new(RAM, o)
}

fn stack(o: u64) -> Address {
    Address::new(STACK, o)
}

#[expect(
    clippy::many_single_char_names,
    reason = "the scopes are named by the letters of the fixture description"
)]
fn fixture() -> (Fx, TypeFactory) {
    let (mut db, mut types) = small::db();
    let g = db.global().unwrap();
    let mut s = std::collections::BTreeMap::new();
    db.add_range(g, RAM, 0x1000, 0x1fff).unwrap();
    db.set_property_range(V::VOLATILE, &Range::new(RAM, 0x1800, 0x18ff));
    db.set_property_range(V::READONLY, &Range::new(RAM, 0x5000, 0x50ff));
    let n = db.find_create_scope(0x77, "N", Some(g)).unwrap();
    db.add_range(n, RAM, 0x3000, 0x30ff).unwrap();
    let t2 = types.base(2, Metatype::Int).unwrap();
    let t4 = types.base(4, Metatype::Int).unwrap();
    let t8 = types.base(8, Metatype::Int).unwrap();
    let f_sym = db.add_function(g, ram(0x1000), "f", &mut types).unwrap();
    s.insert("f", f_sym);
    let mut at =
        |db: &mut Database, scope, name: &'static str, ty, addr, usepoint, types: &TypeFactory| {
            let e = db
                .add_symbol_at(scope, name, ty, addr, usepoint, types)
                .unwrap();
            s.insert(name, db.entry(e).unwrap().symbol());
        };
    at(&mut db, g, "g8", t8, ram(0x1100), Address::INVALID, &types);
    at(&mut db, g, "g2", t2, ram(0x1104), Address::INVALID, &types);
    at(
        &mut db,
        g,
        "shadow",
        t4,
        ram(0x3010),
        Address::INVALID,
        &types,
    );
    at(&mut db, n, "n4", t4, ram(0x3010), Address::INVALID, &types);
    let lab = db
        .add_code_label(g, ram(0x1200), "lab", &mut types)
        .unwrap();
    let ext = db
        .add_external_ref(g, ram(0x1300), ram(0x1000), "ext", &mut types)
        .unwrap();
    let ext2 = db
        .add_external_ref(g, ram(0x1400), ram(0x1000), "ext2", &mut types)
        .unwrap();
    // Same size after the reference: rangemap::insert puts the new
    // fragment before the equal one (the hinted insert, rangemap.hh), so
    // `d8` comes first at ram:0x1400.
    at(&mut db, g, "d8", t8, ram(0x1400), Address::INVALID, &types);
    let ext3 = db
        .add_external_ref(g, ram(0x3040), ram(0x1000), "ext3", &mut types)
        .unwrap();
    let h = db.add_function(g, ram(0x3080), "h", &mut types).unwrap();
    let k_sym = db.add_function(n, ram(0x3020), "k", &mut types).unwrap();
    let dup1 = db.add_symbol(g, "dup", t4, &types).unwrap();
    let dup2 = db.add_symbol(g, "dup", t8, &types).unwrap();
    s.extend([
        ("lab", lab),
        ("ext", ext),
        ("ext2", ext2),
        ("ext3", ext3),
        ("h", h),
        ("k", k_sym),
        ("dup1", dup1),
        ("dup2", dup2),
    ]);
    let f = db.create_function_scope(f_sym).unwrap();
    db.add_range(f, STACK, 0, 0xff).unwrap();
    let e = db
        .add_symbol_at(f, "loc", t4, stack(0x10), ram(0x1004), &types)
        .unwrap();
    s.insert("loc", db.entry(e).unwrap().symbol());
    let k = db.create_function_scope(k_sym).unwrap();
    (Fx { db, g, n, f, k, s }, types)
}

impl Fx {
    fn name_of(&self, e: Option<EntryId>) -> Option<String> {
        e.map(|e| {
            let sym = self.db.entry(e).unwrap().symbol();
            self.db.symbol(sym).unwrap().name().to_owned()
        })
    }
    fn sym(&self, name: &str) -> SymbolId {
        self.s[name]
    }
}

#[test]
fn query_by_addr_rows() {
    // queryByAddr (1351) → stackAddr (999) → findAddr (2373): an entry
    // starting exactly at the address and in use there.
    let (fx, _) = fixture();
    let inv = Address::INVALID;
    let cases: &[(ScopeId, Address, Address, Option<&str>)] = &[
        (fx.g, ram(0x1100), inv, Some("g8")),
        (fx.g, ram(0x1104), inv, Some("g2")),
        // Inside g8 but no entry starts there: G discovers, no symbol.
        (fx.g, ram(0x1102), inv, None),
        // From F, walking up to G.
        (fx.f, ram(0x1104), inv, Some("g2")),
        // A use-limited local: only at its use point (inUse, 93–99).
        (fx.f, stack(0x10), ram(0x1004), Some("loc")),
        (fx.f, stack(0x10), inv, None),
        (fx.f, stack(0x10), ram(0x1008), None),
        // mapScope (3373): ram:0x3010 belongs to N, so N answers first
        // even from F, and G's `shadow` there is not reached.
        (fx.f, ram(0x3010), inv, Some("n4")),
        (fx.g, ram(0x3010), inv, Some("n4")),
        // Constants answer nothing (999: addr.isConstant()).
        (fx.g, Address::constant(0x1100), inv, None),
        // Nothing anywhere.
        (fx.g, ram(0x9000), inv, None),
    ];
    for (k, &(scope, addr, use_point, want)) in cases.iter().enumerate() {
        let got = fx.name_of(fx.db.query_by_addr(scope, addr, use_point).unwrap());
        assert_eq!(got.as_deref(), want, "case {k}: {addr:?} at {use_point:?}");
    }
}

#[test]
fn query_container_rows() {
    // queryContainer (1366) → stackContainer (1033) → findContainer
    // (2399): entries covering [addr, addr+size), the first smallest, an
    // exact size stops the walk.
    let (fx, _) = fixture();
    let inv = Address::INVALID;
    let cases: &[(Address, i32, Option<&str>)] = &[
        (ram(0x1104), 2, Some("g2")), // exact size
        (ram(0x1104), 1, Some("g2")), // the smaller container
        (ram(0x1105), 1, Some("g2")),
        (ram(0x1106), 2, Some("g8")), // g2 ends at 0x1105
        (ram(0x1100), 8, Some("g8")),
        (ram(0x1104), 4, Some("g8")), // g2 too short
        (ram(0x1106), 4, None),       // past g8: G discovers, no symbol
    ];
    for (k, &(addr, size, want)) in cases.iter().enumerate() {
        let got = fx.name_of(fx.db.query_container(fx.g, addr, size, inv).unwrap());
        assert_eq!(got.as_deref(), want, "case {k}: {addr:?} size {size}");
    }
}

#[test]
fn query_properties_and_read_only_rows() {
    // queryProperties (1383–1401): an entry gives its extraflags | symbol
    // flags; a discovering scope only gives mapped | addrtied (| persist
    // for a global scope) | the property map; nothing gives the property
    // map alone. isReadOnly (1951) tests readonly in those flags.
    let (fx, _) = fixture();
    let inv = Address::INVALID;
    let (e, flags) = fx.db.query_properties(fx.g, ram(0x1104), 2, inv).unwrap();
    assert_eq!(fx.name_of(e).as_deref(), Some("g2"));
    let sym = fx.db.symbol(fx.sym("g2")).unwrap().flags();
    assert_eq!(flags, V::MAPPED | sym);
    assert!(flags.contains(V::PERSIST | V::ADDRTIED));
    let (e, flags) = fx.db.query_properties(fx.g, ram(0x1810), 4, inv).unwrap();
    assert_eq!(e, None);
    assert_eq!(flags, V::MAPPED | V::ADDRTIED | V::PERSIST | V::VOLATILE);
    // N is a namespace: Ghidra's isGlobal() is "not a function scope", so
    // it gets persist too.
    let (e, flags) = fx.db.query_properties(fx.g, ram(0x3030), 4, inv).unwrap();
    assert_eq!(e, None);
    assert_eq!(flags, V::MAPPED | V::ADDRTIED | V::PERSIST);
    // A function scope discovering a stack location: no persist.
    let (e, flags) = fx.db.query_properties(fx.f, stack(0x40), 4, inv).unwrap();
    assert_eq!(e, None);
    assert_eq!(flags, V::MAPPED | V::ADDRTIED);
    // Nothing: the property map only.
    let (e, flags) = fx.db.query_properties(fx.g, ram(0x5000), 4, inv).unwrap();
    assert_eq!((e, flags), (None, V::READONLY));
    let (_, flags) = fx.db.query_properties(fx.g, ram(0x9000), 4, inv).unwrap();
    assert_eq!(flags, V::empty());
    assert!(fx.db.is_read_only(fx.g, ram(0x5000), 4, inv).unwrap());
    assert!(!fx.db.is_read_only(fx.g, ram(0x1104), 2, inv).unwrap());
    assert!(!fx.db.is_read_only(fx.g, ram(0x9000), 1, inv).unwrap());
}

#[test]
fn function_label_and_external_reference_rows() {
    let (fx, _) = fixture();
    // queryFunction(addr) (1407) → stackFunction (1099), discovery with
    // one byte and an invalid use point; findFunction (2470) walks
    // forwards for a function symbol starting there.
    assert_eq!(
        fx.db.query_function(fx.g, ram(0x1000)).unwrap(),
        Some(fx.sym("f"))
    );
    assert_eq!(
        fx.db.query_function(fx.f, ram(0x1000)).unwrap(),
        Some(fx.sym("f"))
    );
    assert_eq!(fx.db.query_function(fx.g, ram(0x1100)).unwrap(), None);
    // `h` is in G at ram:0x3080, but N owns that address and discovers it
    // first: stackFunction stops there (1120–1121).
    assert_eq!(fx.db.query_function(fx.g, ram(0x3080)).unwrap(), None);
    assert_eq!(
        fx.db.query_function(fx.n, ram(0x3020)).unwrap(),
        Some(fx.sym("k"))
    );
    // queryCodeLabel (1421) → stackCodeLabel (1164) → findCodeLabel
    // (2517): the first entry at the address in use there; its symbol if
    // it is a label, else none.
    assert_eq!(
        fx.db.query_code_label(fx.g, ram(0x1200)).unwrap(),
        Some(fx.sym("lab"))
    );
    assert_eq!(fx.db.query_code_label(fx.g, ram(0x1100)).unwrap(), None);
    assert_eq!(fx.db.query_code_label(fx.g, ram(0x9000)).unwrap(), None);
    // queryExternalRefFunction (1536) → stackExternalRef (1130, no
    // discovery) → findExternalRef (2491), then queryFunction(refaddr)
    // from the scope where it was found.
    assert_eq!(
        fx.db
            .query_external_ref_function(fx.g, ram(0x1300))
            .unwrap(),
        Some(fx.sym("f"))
    );
    assert_eq!(
        fx.db
            .query_external_ref_function(fx.f, ram(0x1300))
            .unwrap(),
        Some(fx.sym("f"))
    );
    // N owns ram:0x3040 but does not stop the walk: `ext3` in G is found.
    assert_eq!(
        fx.db
            .query_external_ref_function(fx.k, ram(0x3040))
            .unwrap(),
        Some(fx.sym("f"))
    );
    // findExternalRef stops at the first entry starting at the address
    // (2505–2507): `d8` comes before `ext2` at ram:0x1400.
    assert_eq!(
        fx.db
            .query_external_ref_function(fx.g, ram(0x1400))
            .unwrap(),
        None
    );
    assert_eq!(fx.db.find_external_ref(fx.g, ram(0x1400)).unwrap(), None);
    assert_eq!(
        fx.db.find_external_ref(fx.g, ram(0x1300)).unwrap(),
        Some(fx.sym("ext"))
    );
}

#[test]
fn discover_scope_rows() {
    // discoverScope (1473): constants none; from mapScope upwards, the
    // first scope owning the range.
    let (fx, _) = fixture();
    let cases: &[(ScopeId, Address, i32, Option<ScopeId>)] = &[
        (fx.f, stack(0x80), 4, Some(fx.f)),
        (fx.f, ram(0x1800), 1, Some(fx.g)),
        (fx.f, ram(0x3020), 4, Some(fx.n)),
        (fx.g, ram(0x3020), 4, Some(fx.n)),
        (fx.k, ram(0x1100), 1, Some(fx.g)),
        (fx.f, ram(0x1ffe), 4, None), // runs past G's range
        (fx.f, ram(0x9000), 1, None),
        (fx.f, Address::constant(0x10), 1, None),
    ];
    for (k, &(scope, addr, size, want)) in cases.iter().enumerate() {
        assert_eq!(
            fx.db.discover_scope(scope, addr, size).unwrap(),
            want,
            "case {k}"
        );
    }
}

#[test]
fn by_name_rows() {
    let (fx, _) = fixture();
    // queryByName (1318): here, else the parent's.
    assert_eq!(fx.db.query_by_name(fx.f, "loc").unwrap(), [fx.sym("loc")]);
    assert_eq!(fx.db.query_by_name(fx.f, "g8").unwrap(), [fx.sym("g8")]);
    assert_eq!(fx.db.query_by_name(fx.k, "n4").unwrap(), [fx.sym("n4")]);
    assert_eq!(
        fx.db.query_by_name(fx.k, "nothing").unwrap(),
        Vec::<SymbolId>::new()
    );
    // findByName (2587): every symbol of the name, in dedup order.
    assert_eq!(
        fx.db.find_by_name(fx.g, "dup").unwrap(),
        [fx.sym("dup1"), fx.sym("dup2")]
    );
    assert_eq!(
        fx.db.find_by_name(fx.f, "g8").unwrap(),
        Vec::<SymbolId>::new()
    );
    // queryFunction(nm) (1332): the first function symbol of queryByName.
    assert_eq!(
        fx.db.query_function_by_name(fx.f, "f").unwrap(),
        Some(fx.sym("f"))
    );
    assert_eq!(fx.db.query_function_by_name(fx.f, "g8").unwrap(), None);
    // isNameUsed (2599): here, else the parent's unless the parent is the
    // stop scope or the global scope.
    assert!(fx.db.is_name_used(fx.k, "n4", None).unwrap());
    assert!(!fx.db.is_name_used(fx.k, "n4", Some(fx.n)).unwrap());
    assert!(!fx.db.is_name_used(fx.k, "g8", None).unwrap()); // never into G
    assert!(!fx.db.is_name_used(fx.f, "g8", None).unwrap());
    assert!(fx.db.is_name_used(fx.g, "g8", None).unwrap());
}

#[test]
fn find_rows() {
    let (fx, _) = fixture();
    let inv = Address::INVALID;
    // findClosestFit (2433): with g2 (diff −2) and g8 (diff +4) covering
    // ram:0x1104 for size 4, a non-negative difference beats a negative
    // one: g8. For size 2, g2 fits exactly.
    let name = |e| fx.name_of(e);
    assert_eq!(
        name(fx.db.find_closest_fit(fx.g, ram(0x1104), 4, inv).unwrap()).as_deref(),
        Some("g8")
    );
    assert_eq!(
        name(fx.db.find_closest_fit(fx.g, ram(0x1104), 2, inv).unwrap()).as_deref(),
        Some("g2")
    );
    // With only a too-small entry, it is still taken.
    assert_eq!(
        name(fx.db.find_closest_fit(fx.g, ram(0x1200), 4, inv).unwrap()).as_deref(),
        Some("lab")
    );
    // findOverlap (2541): any entry overlapping the range.
    assert_eq!(
        name(fx.db.find_overlap(fx.g, ram(0x1106), 4).unwrap()).as_deref(),
        Some("g8")
    );
    assert_eq!(fx.db.find_overlap(fx.g, ram(0x1108), 4).unwrap(), None);
    // findSymbolBefore (2554): the last record ending before the address
    // (find_last_before) that is in use; g8 contains 0x1104, f ends at
    // 0x1000.
    assert_eq!(
        name(fx.db.find_symbol_before(fx.g, ram(0x1104), inv).unwrap()).as_deref(),
        Some("f")
    );
    assert_eq!(
        name(fx.db.find_symbol_before(fx.g, ram(0x1200), inv).unwrap()).as_deref(),
        Some("g8")
    );
    // findSymbolAfter (2572): the first record starting after it.
    assert_eq!(
        name(fx.db.find_symbol_after(fx.g, ram(0x1100), inv).unwrap()).as_deref(),
        Some("g2")
    );
    assert_eq!(
        name(fx.db.find_symbol_after(fx.g, ram(0x1104), inv).unwrap()).as_deref(),
        Some("lab")
    );
    // A use-limited entry is skipped without its use point.
    assert_eq!(fx.db.find_symbol_after(fx.f, stack(0), inv).unwrap(), None);
    assert_eq!(
        name(
            fx.db
                .find_symbol_after(fx.f, stack(0), ram(0x1004))
                .unwrap()
        )
        .as_deref(),
        Some("loc")
    );
    // findAddr / findContainer on one scope, without the walk.
    assert_eq!(fx.db.find_addr(fx.f, ram(0x1104), inv).unwrap(), None);
    assert_eq!(
        name(fx.db.find_container(fx.g, ram(0x1105), 1, inv).unwrap()).as_deref(),
        Some("g2")
    );
    // findFunction / findCodeLabel on one scope.
    assert_eq!(
        fx.db.find_function(fx.g, ram(0x1000)).unwrap(),
        Some(fx.sym("f"))
    );
    assert_eq!(
        fx.db.find_code_label(fx.g, ram(0x1200)).unwrap(),
        Some(fx.sym("lab"))
    );
    assert_eq!(fx.db.find_function(fx.n, ram(0x1000)).unwrap(), None);
}
