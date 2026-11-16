//! Rebuilding a function's scope from a state dump (spec 6.4): every
//! version-2 sample of `bk-testkit` (`bkstate 2`, `@scope`) is turned into a
//! [`ScopeImage`], restored into a fresh scope with
//! [`Database::restore_scope`], read back with [`Database::scope_image`] and
//! written back as `@scope` records, which must equal the dump's (and the
//! whole dump written back must equal the file byte for byte): the
//! symbols and entries (`S`, `M`), the owned ranges (`Z`), the identity
//! (`I`), the category slots (`C`), the multi-entry set (`E`), each space's
//! record list with the subsorts stored at insertion (`R`, read, not
//! recomputed), the fragment multiset (`F`) and the dynamic list (`Q`).
//! Entries are named by their real index in the symbol's list (spec 4.5,
//! amended). A second test restores a scope built through the API, with
//! overlapping records, several use points, a multi-entry symbol, dynamic
//! entries and category slots, and checks that the rebuilt maps answer
//! queries exactly as the originals.
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

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use bk_core::{Address, RangeList, Space, SpaceId, SpaceManager};
use bk_decomp_symbols::entrymap::EntrySubsort;
use bk_decomp_symbols::restore::{
    EntryImage, FragmentImage, RecordImage, ScopeImage, SymbolImage, kind_from_name, kind_name,
};
use bk_decomp_symbols::{ArchEnv, Database, EntryKind, ScopeId, ScopeKind, SymbolId, VarnodeFlags};
use bk_decomp_types::{DataOrganization, Metatype, TypeEnv, TypeFactory, TypeId};
use bk_testkit::oracle::graph::OracleAddress;
use bk_testkit::oracle::state::{
    CategoryRecord, DynamicListRecord, EntryMapRecord, EntryRef, EntryStorage, FragmentRecord,
    MapEntryRecord, MultiEntryRecord, OracleRange, ScopeIdRecord, ScopeOrders, SpaceRecord,
    StateDump, SymbolEntryGroup, SymbolRecord, SymbolRef, TypeRef,
};

/// Ghidra's `AddrSpace` flag `big_endian` (space.hh).
const BIG_ENDIAN: u32 = 0x1;
/// Ghidra's `AddrSpace` flag `hasphysical` (space.hh).
const HAS_PHYSICAL: u32 = 0x200;
/// Ghidra's `AddrSpace` flag `formal_stackspace` (space.hh).
const FORMAL_STACK: u32 = 0x20;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("bk-testkit")
        .join("tests")
        .join("data")
        .join("oracle")
}

fn read_gz(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// The address spaces of a dump (`@spaces`, `P` records; spacetype numbers
/// of Ghidra's `spacetype` enum). A spacebase space is based on `ram`, the
/// only base the samples' architecture has.
fn spaces_from_dump(records: &[SpaceRecord]) -> Arc<SpaceManager> {
    let mut m = SpaceManager::new();
    let mut ram: Option<Space> = None;
    for p in records {
        let index = u32::try_from(p.index).unwrap();
        let big = p.flags & BIG_ENDIAN != 0;
        let space = match p.kind {
            0 => Space::constant(),
            1 if p.name == "OTHER" => Space::other(),
            1 => Space::processor(
                &p.name,
                big,
                p.addr_size,
                p.word_size,
                index,
                p.flags & HAS_PHYSICAL != 0,
                p.delay,
                p.deadcode_delay,
            )
            .unwrap(),
            2 => Space::spacebase(
                &p.name,
                index,
                p.addr_size,
                ram.as_ref().expect("a spacebase space after ram"),
                p.delay,
                p.flags & FORMAL_STACK != 0,
                big,
            )
            .unwrap(),
            3 => Space::unique(index, big).unwrap(),
            4 => Space::fspec(index).unwrap(),
            5 => Space::iop(index).unwrap(),
            6 => Space::join(index, big).unwrap(),
            other => panic!("space type {other}"),
        };
        if p.name == "ram" {
            ram = Some(space.clone());
        }
        let id = m.insert_space(space).unwrap();
        assert_eq!(id.index(), index, "space {}", p.name);
    }
    let ram = m.space_by_name("ram").unwrap().id();
    m.set_default_code_space(ram).unwrap();
    m.set_default_data_space(ram).unwrap();
    Arc::new(m)
}

fn new_types() -> TypeFactory {
    TypeFactory::with_core_types(TypeEnv::simple(8, false), DataOrganization::default()).unwrap()
}

/// A database with a function scope of the given identity under the global
/// scope, ready for [`Database::restore_scope`].
fn function_scope(
    spaces: &Arc<SpaceManager>,
    name: &str,
    ghidra_id: u64,
    types: &mut TypeFactory,
) -> (Database, ScopeId) {
    let mut db = Database::new(ArchEnv::new(Arc::clone(spaces)), true);
    let global = db.global().unwrap();
    let code = types.type_code().unwrap();
    // The function symbol the scope belongs to; only its id is needed.
    let owner: SymbolId = db.add_symbol(global, name, code, types).unwrap();
    let scope = db
        .attach_scope(name, ghidra_id, Some(global), ScopeKind::Function(owner))
        .unwrap();
    (db, scope)
}

/// Everything a dump says about the scope, keyed for comparison.
#[derive(Debug, PartialEq, Eq)]
struct ScopeRecords {
    ranges: Vec<OracleRange>,
    symbols: Vec<SymbolEntryGroup>,
    orders: ScopeOrders,
}

/// Converts between the dump's names and the database's.
struct Names<'a> {
    spaces: &'a SpaceManager,
}

impl Names<'_> {
    fn space(&self, name: &str) -> SpaceId {
        self.spaces
            .space_by_name(name)
            .unwrap_or_else(|| panic!("space {name}"))
            .id()
    }

    fn space_name(&self, id: SpaceId) -> String {
        self.spaces.space(id).unwrap().name().to_owned()
    }

    fn range_list(&self, ranges: &[OracleRange]) -> RangeList {
        let mut list = RangeList::default();
        for r in ranges {
            list.insert_range(self.space(&r.space), r.first, r.last);
        }
        list
    }

    fn ranges(&self, list: &RangeList) -> Vec<OracleRange> {
        list.iter()
            .map(|r| OracleRange {
                space: self.space_name(r.space()),
                first: r.first(),
                last: r.last(),
            })
            .collect()
    }

    fn entry_kind(&self, storage: &EntryStorage) -> EntryKind {
        match storage {
            EntryStorage::Address(a) => EntryKind::Map {
                addr: Address::new(self.space(&a.space), a.offset),
                conflict: None,
            },
            EntryStorage::Hash(hash) => EntryKind::Dynamic { hash: *hash },
            EntryStorage::None => EntryKind::Unassigned,
        }
    }

    fn storage(&self, kind: EntryKind) -> EntryStorage {
        match kind {
            EntryKind::Map { addr, .. } => EntryStorage::Address(OracleAddress {
                space: self.space_name(addr.space().unwrap()),
                offset: addr.offset(),
            }),
            EntryKind::Dynamic { hash } => EntryStorage::Hash(hash),
            EntryKind::Unassigned => EntryStorage::None,
        }
    }
}

/// The dump's `@scope` as a [`ScopeImage`], with the dump's type of each
/// symbol (by symbol id) for writing back.
fn image_from_dump(
    dump: &StateDump,
    names: &Names<'_>,
    types: &mut TypeFactory,
) -> (ScopeImage, BTreeMap<u64, Option<TypeRef>>) {
    let orders = dump.scope.orders.as_ref().unwrap();
    let mut type_ids: BTreeMap<TypeRef, TypeId> = BTreeMap::new();
    let mut dump_types = BTreeMap::new();
    let index_of: BTreeMap<u64, usize> = dump
        .scope
        .symbols
        .iter()
        .enumerate()
        .map(|(i, g)| (g.symbol.id.0, i))
        .collect();
    let entry_ref = |r: &EntryRef| -> (usize, usize) {
        (
            index_of[&r.symbol.0],
            usize::try_from(r.position).expect("an entry the symbol holds"),
        )
    };
    let mut symbols = Vec::new();
    for g in &dump.scope.symbols {
        let s = &g.symbol;
        // The scope needs a type of the right size only; the dump's own type
        // is kept for the comparison.
        let ty = match s.data_type {
            Some(t) => *type_ids.entry(t).or_insert_with(|| {
                let size = dump.types[t.0 as usize].size;
                if size > 0 {
                    types.base(size, Metatype::Unknown).unwrap()
                } else {
                    types.type_void().unwrap()
                }
            }),
            None => types.base(1, Metatype::Unknown).unwrap(),
        };
        dump_types.insert(s.id.0, s.data_type);
        let entries = g
            .entries
            .iter()
            .map(|m| EntryImage {
                kind: names.entry_kind(&m.storage),
                use_limit: names.range_list(&m.use_limit),
                extra_flags: VarnodeFlags::from_bits_retain(m.extra_flags),
                properties: m.properties,
                offset: m.offset,
                size: m.size,
            })
            .collect();
        symbols.push(SymbolImage {
            ghidra_id: s.id.0,
            name: s.name.clone(),
            display_name: s.display_name.clone(),
            ty,
            kind: kind_from_name(&s.kind, 1),
            flags: VarnodeFlags::from_bits_retain(s.flags),
            disp: s.disp_flags,
            category: i16::try_from(s.category).unwrap(),
            catindex: s.cat_index,
            dedup: s.name_dedup,
            whole_count: s.whole_count,
            entries,
        });
    }
    let mut categories: Vec<Vec<Option<usize>>> = Vec::new();
    for c in &orders.categories {
        let at = usize::try_from(c.category).unwrap();
        if categories.len() <= at {
            categories.resize(at + 1, Vec::new());
        }
        categories[at] = c.slots.iter().map(|s| s.map(|s| index_of[&s.0])).collect();
    }
    let image = ScopeImage {
        ghidra_id: orders.identity.ghidra_id,
        next_unique_id: orders.identity.next_unique_id,
        display_name: orders.identity.display_name.clone(),
        symbols,
        categories,
        multi: orders
            .multi_entry
            .symbols
            .iter()
            .map(|s| index_of[&s.0])
            .collect(),
        records: orders
            .records
            .iter()
            .map(|r| RecordImage {
                space: names.space(&r.space),
                entry: entry_ref(&r.entry),
                first: r.first,
                last: r.last,
                subsort: EntrySubsort {
                    use_index: u32::try_from(r.use_index.expect("a stored subsort")).unwrap(),
                    use_offset: r.use_offset.expect("a stored subsort"),
                },
            })
            .collect(),
        fragments: orders
            .fragments
            .iter()
            .map(|f| FragmentImage {
                space: names.space(&f.space),
                first: f.first,
                last: f.last,
                entry: entry_ref(&f.entry),
            })
            .collect(),
        dynamic: orders.dynamic.entries.iter().map(entry_ref).collect(),
    };
    (image, dump_types)
}

/// A restored scope written back as the dump's records.
fn records_from_db(
    db: &Database,
    scope: ScopeId,
    names: &Names<'_>,
    dump_types: &BTreeMap<u64, Option<TypeRef>>,
) -> ScopeRecords {
    let image = db.scope_image(scope).unwrap();
    let data = db.scope(scope).unwrap();
    let sym_ref = |i: usize| SymbolRef(image.symbols[i].ghidra_id);
    let entry_ref = |(i, j): (usize, usize)| EntryRef {
        symbol: sym_ref(i),
        position: i32::try_from(j).unwrap(),
    };
    // The dump lists symbols by id; the image is in name order.
    let mut by_id: Vec<&SymbolImage> = image.symbols.iter().collect();
    by_id.sort_by_key(|s| s.ghidra_id);
    let symbols = by_id
        .iter()
        .map(|s| SymbolEntryGroup {
            symbol: SymbolRecord {
                id: SymbolRef(s.ghidra_id),
                name: s.name.clone(),
                display_name: s.display_name.clone(),
                data_type: dump_types[&s.ghidra_id],
                flags: s.flags.bits(),
                disp_flags: s.disp,
                category: i32::from(s.category),
                cat_index: s.catindex,
                name_dedup: s.dedup,
                kind: kind_name(&s.kind).to_owned(),
                whole_count: s.whole_count,
            },
            entries: s
                .entries
                .iter()
                .map(|e| MapEntryRecord {
                    storage: names.storage(e.kind),
                    size: e.size,
                    offset: e.offset,
                    use_limit: names.ranges(&e.use_limit),
                    extra_flags: e.extra_flags.bits(),
                    properties: e.properties,
                })
                .collect(),
        })
        .collect();
    let parent = data.parent().map(|p| db.scope(p).unwrap().ghidra_id());
    let children = data
        .children()
        .map(|c| db.scope(c).unwrap().ghidra_id())
        .collect();
    let orders = ScopeOrders {
        identity: ScopeIdRecord {
            ghidra_id: data.ghidra_id(),
            next_unique_id: data.next_unique_id(),
            display_name: data.display_name().to_owned(),
            parent,
            children,
        },
        categories: image
            .categories
            .iter()
            .enumerate()
            .map(|(c, slots)| CategoryRecord {
                category: i32::try_from(c).unwrap(),
                slots: slots.iter().map(|s| s.map(sym_ref)).collect(),
            })
            .collect(),
        multi_entry: MultiEntryRecord {
            symbols: image.multi.iter().map(|&i| sym_ref(i)).collect(),
        },
        records: image
            .records
            .iter()
            .map(|r| EntryMapRecord {
                space: names.space_name(r.space),
                entry: entry_ref(r.entry),
                first: r.first,
                last: r.last,
                use_index: Some(i32::try_from(r.subsort.use_index).unwrap()),
                use_offset: Some(r.subsort.use_offset),
            })
            .collect(),
        fragments: image
            .fragments
            .iter()
            .map(|f| FragmentRecord {
                space: names.space_name(f.space),
                first: f.first,
                last: f.last,
                entry: entry_ref(f.entry),
            })
            .collect(),
        dynamic: DynamicListRecord {
            entries: image.dynamic.iter().map(|&r| entry_ref(r)).collect(),
        },
    };
    ScopeRecords {
        ranges: names.ranges(data.ranges()),
        symbols,
        orders,
    }
}

#[test]
fn every_version_2_sample_rebuilds_its_scope_exactly() {
    let dir = samples_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".state.gz"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no samples in {}", dir.display());
    let mut checked = 0;
    for path in &files {
        let text = read_gz(path);
        let dump = StateDump::parse(&text).unwrap();
        let Some(orders) = dump.scope.orders.as_ref() else {
            eprintln!(
                "{}: version {} has no @scope order records; skipped",
                path.display(),
                dump.version
            );
            assert_eq!(dump.version, 1, "{}", path.display());
            continue;
        };
        let local = dump.scope.scope.as_ref().unwrap();
        let spaces = spaces_from_dump(&dump.spaces);
        let names = Names { spaces: &spaces };
        let mut types = new_types();
        let (image, dump_types) = image_from_dump(&dump, &names, &mut types);
        let (mut db, scope) =
            function_scope(&spaces, &local.name, orders.identity.ghidra_id, &mut types);
        for r in &local.ranges {
            db.add_range(scope, names.space(&r.space), r.first, r.last)
                .unwrap();
        }
        db.restore_scope(scope, &image, &types).unwrap();
        let got = records_from_db(&db, scope, &names, &dump_types);
        let want = ScopeRecords {
            ranges: local.ranges.clone(),
            symbols: dump.scope.symbols.clone(),
            orders: orders.clone(),
        };
        assert_eq!(got, want, "{}", path.display());
        // Written back into the dump, the text is byte-equal.
        let mut back = dump.clone();
        let mut local_back = local.clone();
        local_back.ranges = got.ranges;
        back.scope.scope = Some(local_back);
        back.scope.symbols = got.symbols;
        back.scope.orders = Some(got.orders);
        assert!(
            back.write() == text,
            "{}: written back differs",
            path.display()
        );
        // The rebuilt map answers from its records: each record's entry is
        // found at the record's first address.
        for r in &image.records {
            let sym = &image.symbols[r.entry.0];
            let use_point = if sym.flags.contains(VarnodeFlags::ADDRTIED) {
                Address::INVALID
            } else {
                Address::new(SpaceId::new(r.subsort.use_index), r.subsort.use_offset)
            };
            let hit = db
                .query_by_addr(scope, Address::new(r.space, r.first), use_point)
                .unwrap()
                .expect("an entry at the record's start");
            assert_eq!(
                db.symbol(db.entry(hit).unwrap().symbol())
                    .unwrap()
                    .ghidra_id(),
                sym.ghidra_id
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "no version-2 sample");
    eprintln!("{checked} version-2 samples rebuilt");
}

/// The answer of a query as the symbol's id and the entry's index in it.
fn answer(db: &Database, hit: Option<bk_decomp_symbols::EntryId>) -> Option<(u64, usize)> {
    let e = hit?;
    let sym = db.entry(e).unwrap().symbol();
    let data = db.symbol(sym).unwrap();
    let index = data.entries().iter().position(|x| *x == e).unwrap();
    Some((data.ghidra_id(), index))
}

#[test]
fn a_scope_built_through_the_api_restores_to_the_same_image_and_answers() {
    let dump = StateDump::parse(&read_gz(&samples_dir().join("switchind.p2.state.gz"))).unwrap();
    let spaces = spaces_from_dump(&dump.spaces);
    let stack = spaces.space_by_name("stack").unwrap().id();
    let ram = spaces.space_by_name("ram").unwrap().id();
    let mut types = new_types();
    let (mut db, scope) = function_scope(&spaces, "f", 0x4000_0000_0000_0000, &mut types);
    let t4 = types.base(4, Metatype::Unknown).unwrap();
    let t8 = types.base(8, Metatype::Unknown).unwrap();
    let t2 = types.base(2, Metatype::Unknown).unwrap();
    let at = |off: u64| Address::new(stack, off);
    let pc = |off: u64| Address::new(ram, off);
    // Overlapping records, the same start under different use points, a
    // duplicated name, a multi-entry symbol, dynamic entries, categories
    // with a removed member.
    let mut syms = Vec::new();
    for (i, (off, ty, use_at)) in [
        (0x10, t8, None),
        (0x14, t4, None),
        (0x10, t4, Some(0x100)),
        (0x10, t4, Some(0x80)),
        (0x12, t2, Some(0x100)),
        (0x20, t8, None),
        (0x24, t4, Some(0x90)),
    ]
    .into_iter()
    .enumerate()
    {
        let name = if i == 2 || i == 3 {
            "dup".to_owned()
        } else {
            format!("v{i}")
        };
        let usepoint = use_at.map_or(Address::INVALID, pc);
        let e = db
            .add_symbol_at(scope, &name, ty, at(off), usepoint, &types)
            .unwrap();
        syms.push(db.entry(e).unwrap().symbol());
    }
    db.add_map_point(syms[5], at(0x40), pc(0x200)).unwrap();
    db.add_map_point(syms[5], at(0x48), Address::INVALID)
        .unwrap();
    let d0 = db
        .add_dynamic_symbol(scope, "dyn0", t4, pc(0x300), 0xdead_beef, &types)
        .unwrap();
    let d1 = db
        .add_dynamic_symbol(scope, "dyn1", t8, pc(0x310), 0x1234, &types)
        .unwrap();
    db.set_category(syms[0], 0, 0).unwrap();
    db.set_category(syms[1], 0, 1).unwrap();
    db.set_category(syms[6], 0, 2).unwrap();
    db.set_category(d1, 1, 0).unwrap();
    db.remove_symbol(syms[1]).unwrap();
    db.remove_symbol(d0).unwrap();

    let image = db.scope_image(scope).unwrap();
    assert!(image.records.len() >= 8 && image.dynamic.len() == 1 && !image.multi.is_empty());
    let (mut copy, copy_scope) = function_scope(&spaces, "f", 0x4000_0000_0000_0000, &mut types);
    copy.restore_scope(copy_scope, &image, &types).unwrap();
    assert_eq!(copy.scope_image(copy_scope).unwrap(), image);
    let (a, b) = (db.scope(scope).unwrap(), copy.scope(copy_scope).unwrap());
    assert_eq!(a.next_unique_id(), b.next_unique_id());

    let mut hits = 0;
    for off in 0x0c..0x50 {
        for use_at in [None, Some(0x80), Some(0x90), Some(0x100), Some(0x200)] {
            let usepoint = use_at.map_or(Address::INVALID, pc);
            hits += usize::from(
                db.query_by_addr(scope, at(off), usepoint)
                    .unwrap()
                    .is_some(),
            );
            assert_eq!(
                answer(&db, db.query_by_addr(scope, at(off), usepoint).unwrap()),
                answer(
                    &copy,
                    copy.query_by_addr(copy_scope, at(off), usepoint).unwrap()
                ),
                "query_by_addr {off:#x} {use_at:?}"
            );
            for size in [1, 2, 4, 8] {
                assert_eq!(
                    answer(
                        &db,
                        db.query_container(scope, at(off), size, usepoint).unwrap()
                    ),
                    answer(
                        &copy,
                        copy.query_container(copy_scope, at(off), size, usepoint)
                            .unwrap()
                    ),
                    "query_container {off:#x} {size} {use_at:?}"
                );
            }
        }
    }
    assert!(hits > 20, "only {hits} hits");
}
