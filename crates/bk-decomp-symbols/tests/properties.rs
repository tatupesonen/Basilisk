//! Properties of spec 6.6 (the `EntryMap` model property is
//! `entrymap_props.rs`): every codec round-trips on Basilisk's own
//! encodings — the symbol database (`<db>`), comments, strings, the
//! constant pool, overrides — and changing only provenance (ADR-025 3f)
//! never changes a query answer, the printed map or the encoding. The case
//! count is proptest's default unless `PROPTEST_CASES` says otherwise
//! (`scripts/remote.sh long proptest` runs 1,000,000).
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

use bk_core::{Address, Provenance, SpaceManager};
use bk_cspec::FuncProto;
use bk_decomp_symbols::comment::{CommentDb, kind};
use bk_decomp_symbols::cpool::{CPoolRecord, CPoolTag, ConstantPool};
use bk_decomp_symbols::overrides::{Overrides, ProtoCodec};
use bk_decomp_symbols::strings::{StringCache, StringData};
use bk_decomp_symbols::{ArchEnv, Database, SymbolError, SymbolId, VarnodeFlags, ids};
use bk_decomp_types::{Metatype, TypeFactory, TypeId};
use bk_marshal::{Decoder, Document, Encoder, XmlDecoder, XmlEncoder};
use common::small::{self, RAM, STACK};
use proptest::prelude::*;

fn decoded<T>(text: &str, spaces: &SpaceManager, f: impl FnOnce(&mut dyn Decoder<'_>) -> T) -> T {
    let doc = Document::parse(text).unwrap();
    let table = ids::id_table();
    let mut dec = XmlDecoder::new(&doc, &table, spaces);
    f(&mut dec)
}

fn encoded(f: impl FnOnce(&mut XmlEncoder)) -> String {
    let mut enc = XmlEncoder::new(true);
    f(&mut enc);
    enc.into_string()
}

/// Text with XML's special characters, white space and non-ASCII. A run
/// of white space alone between markup or entity references is not kept:
/// Ghidra's XML reader passes it as ignorable white space (xml.y:451–466,
/// `print_content`), and `bk-marshal` does the same, so such text cannot
/// round-trip in Ghidra either. The strategy keeps white space next to
/// ordinary characters only.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z<>&\"'ßé€😀]{0,12}",
        "[a-zé]{1,4}[ \t\na-zé]{0,8}[a-z€]"
    ]
}

// ----- the symbol database -------------------------------------------------

const NAMES: [&str; 7] = ["a", "b", "sym", "sym_00", "Var1", "x", "lab"];
const PREFIXES: [&str; 4] = ["", "ns1::", "ns2::", "ns1::ns3::"];

/// One change to the database: what, which name and namespace, where, which
/// type, which lock bits.
#[derive(Clone, Debug)]
struct Op {
    what: u8,
    name: usize,
    prefix: usize,
    offset: u16,
    ty: usize,
    locks: u8,
    provenance: u8,
}

fn op() -> impl Strategy<Value = Op> {
    (
        0u8..6,
        0..NAMES.len(),
        0..PREFIXES.len(),
        any::<u16>(),
        0usize..4,
        any::<u8>(),
        0u8..7,
    )
        .prop_map(|(what, name, prefix, offset, ty, locks, provenance)| Op {
            what,
            name,
            prefix,
            offset,
            ty,
            locks,
            provenance,
        })
}

fn provenance(n: u8) -> Provenance {
    match n {
        0 => Provenance::Default,
        1 => Provenance::Analysis,
        2 => Provenance::Model,
        3 => Provenance::Imported,
        4 => Provenance::LibrarySignature,
        5 => Provenance::DebugInfo,
        _ => Provenance::User,
    }
}

struct World {
    spaces: Arc<SpaceManager>,
    db: Database,
    types: TypeFactory,
    tys: Vec<TypeId>,
    syms: Vec<SymbolId>,
}

fn world() -> World {
    let m = small::spaces(false);
    let mut types = small::types(&m);
    let spaces = Arc::new(m);
    let db = Database::new(ArchEnv::new(Arc::clone(&spaces)), true);
    let tys = vec![
        types.base(1, Metatype::Unknown).unwrap(),
        types.base(4, Metatype::Int).unwrap(),
        types.base(8, Metatype::Uint).unwrap(),
        types.base(2, Metatype::Unknown).unwrap(),
    ];
    World {
        spaces,
        db,
        types,
        tys,
        syms: Vec::new(),
    }
}

/// Applies the operations; `with_provenance` passes each operation's
/// provenance to renames and retypes, else the default ones are used.
fn apply(w: &mut World, ops: &[Op], with_provenance: bool) {
    let global = w.db.global().unwrap();
    for op in ops {
        let full = format!("{}{}", PREFIXES[op.prefix], NAMES[op.name]);
        let addr = Address::new(RAM, 0x1000 + u64::from(op.offset));
        let ty = w.tys[op.ty];
        let prov = provenance(op.provenance);
        let result: Result<(), SymbolError> = (|| {
            match op.what {
                0 | 1 => {
                    let (scope, base) =
                        w.db.find_create_scope_from_symbol_name(&full, Some(global))?;
                    let base = base.to_owned();
                    let e =
                        w.db.add_symbol_at(scope, &base, ty, addr, Address::INVALID, &w.types)?;
                    let sym = w.db.entry(e)?.symbol();
                    let mut flags = VarnodeFlags::empty();
                    if op.locks & 1 != 0 {
                        flags |= VarnodeFlags::TYPELOCK;
                    }
                    if op.locks & 2 != 0 {
                        flags |= VarnodeFlags::NAMELOCK;
                    }
                    if op.locks & 4 != 0 {
                        flags |= VarnodeFlags::READONLY;
                    }
                    w.db.set_attribute(sym, flags)?;
                    w.syms.push(sym);
                }
                2 => {
                    let (scope, base) =
                        w.db.find_create_scope_from_symbol_name(&full, Some(global))?;
                    let base = base.to_owned();
                    let sym = w.db.add_code_label(scope, addr, &base, &mut w.types)?;
                    w.syms.push(sym);
                }
                3 if !w.syms.is_empty() => {
                    let sym = w.syms[op.offset as usize % w.syms.len()];
                    if with_provenance {
                        w.db.rename_symbol_as(sym, NAMES[op.name], prov)?;
                    } else {
                        w.db.rename_symbol(sym, NAMES[op.name])?;
                    }
                }
                4 if !w.syms.is_empty() => {
                    let sym = w.syms[op.offset as usize % w.syms.len()];
                    if with_provenance {
                        w.db.retype_symbol_as(sym, ty, prov, &w.types)?;
                    } else {
                        w.db.retype_symbol(sym, ty, &w.types)?;
                    }
                }
                5 if !w.syms.is_empty() => {
                    let k = op.offset as usize % w.syms.len();
                    let sym = w.syms.swap_remove(k);
                    w.db.remove_symbol(sym)?;
                }
                _ => {}
            }
            Ok(())
        })();
        // Refused operations (name clashes, overlaps) are part of the input.
        let _ = result;
    }
}

/// `text` with every internal symbol id (`id="0x40…"`) blanked.
fn without_internal_ids(text: &str) -> String {
    text.split("id=\"0x40")
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part.to_owned()
            } else {
                let (_, tail) = part.split_once('"').unwrap();
                format!("id=\"internal\"{tail}")
            }
        })
        .collect()
}

/// Decodes `text` into a fresh database and encodes that.
fn round_trip(w: &mut World, text: &str) -> String {
    let mut back = Database::without_global(ArchEnv::new(Arc::clone(&w.spaces)), true);
    decoded(text, &w.spaces, |d| back.decode(d, &mut w.types, None)).unwrap();
    encoded(|e| back.encode(e, &w.types, None).unwrap())
}

fn encode_db(w: &World) -> String {
    encoded(|e| w.db.encode(e, &w.types, None).unwrap())
}

/// Everything observable about the database: its encoding, the printed
/// map of every scope, and the answers of the address queries.
fn observe(w: &mut World) -> Vec<String> {
    let mut out = vec![encode_db(w)];
    let global = w.db.global().unwrap();
    let mut scopes = vec![global];
    let mut i = 0;
    while let Some(&s) = scopes.get(i) {
        scopes.extend(w.db.scope(s).unwrap().children());
        i += 1;
    }
    for &s in &scopes {
        out.push(w.db.print_entries(s, &w.types).unwrap());
        for off in (0x1000..0x1000 + 0x1_0010u64).step_by(0x777) {
            let a = Address::new(RAM, off);
            let hit = w.db.query_by_addr(s, a, Address::INVALID).unwrap();
            let cont = w.db.query_container(s, a, 4, Address::INVALID).unwrap();
            let names: Vec<String> = [hit, cont]
                .iter()
                .map(|e| {
                    e.map_or_else(String::new, |e| {
                        let sym = w.db.entry(e).unwrap().symbol();
                        w.db.symbol(sym).unwrap().name().to_owned()
                    })
                })
                .collect();
            out.push(format!("{off:x} {names:?} {:?}", w.db.property(a)));
        }
        for name in NAMES {
            out.push(format!("{name} {:?}", w.db.query_by_name(s, name).unwrap()));
        }
    }
    out
}

proptest! {
    #[test]
    fn the_database_round_trips(ops in prop::collection::vec(op(), 0..40)) {
        // Without read-only symbols, decoding gives back what was encoded,
        // except that internal symbol ids (top byte 0x40) are dropped and
        // given anew in decoding order (Symbol::decodeHeader,
        // database.cc:500–503).
        let plain: Vec<Op> = ops.iter().map(|o| Op { locks: o.locks & !4, ..o.clone() }).collect();
        let mut w = world();
        apply(&mut w, &plain, false);
        let text = encode_db(&w);
        let once = round_trip(&mut w, &text);
        prop_assert_eq!(without_internal_ids(&once), without_internal_ids(&text));
        prop_assert_eq!(round_trip(&mut w, &once), once);
        // A read-only symbol makes decoding set the property over it
        // (ScopeInternal::decode, database.cc:2952–2960), which address-tied
        // symbols decoded after it there pick up; the next decoding reads
        // the property change points first, so a symbol decoded earlier
        // picks it up too. Round trips are stable from the second on.
        let mut w = world();
        apply(&mut w, &ops, false);
        let text = encode_db(&w);
        let once = round_trip(&mut w, &text);
        let twice = round_trip(&mut w, &once);
        let thrice = round_trip(&mut w, &twice);
        prop_assert_eq!(thrice, twice);
    }

    #[test]
    fn provenance_never_changes_an_answer(ops in prop::collection::vec(op(), 0..40)) {
        let mut plain = world();
        apply(&mut plain, &ops, false);
        let mut marked = world();
        apply(&mut marked, &ops, true);
        prop_assert_eq!(observe(&mut plain), observe(&mut marked));
    }

    #[test]
    fn comments_round_trip(
        comments in prop::collection::vec((0usize..6, 0u64..4, 0u64..4, text()), 0..20)
    ) {
        let sp = Arc::new(small::spaces(false));
        let kinds = [kind::USER1, kind::USER2, kind::USER3, kind::HEADER, kind::WARNING, kind::WARNINGHEADER];
        let mut db = CommentDb::new();
        for (k, f, a, t) in &comments {
            db.add_comment(kinds[*k], Address::new(RAM, f * 0x100), Address::new(RAM, f * 0x100 + a), t).unwrap();
        }
        let text = encoded(|e| db.encode(e, &sp).unwrap());
        let mut back = CommentDb::new();
        decoded(&text, &sp, |d| back.decode(d, &sp)).unwrap();
        prop_assert_eq!(back.iter().collect::<Vec<_>>(), db.iter().collect::<Vec<_>>());
    }

    #[test]
    fn strings_round_trip(
        entries in prop::collection::btree_map(
            (any::<bool>(), any::<u64>()),
            (any::<bool>(), prop::collection::vec(any::<u8>(), 0..80)),
            0..8,
        )
    ) {
        let sp = Arc::new(small::spaces(false));
        let mut cache = StringCache::default();
        for ((on_stack, off), (truncated, bytes)) in &entries {
            let space = if *on_stack { STACK } else { RAM };
            cache.insert(Address::new(space, *off), StringData { truncated: *truncated, bytes: bytes.clone() });
        }
        let text = encoded(|e| cache.encode(e, &sp).unwrap());
        let mut back = StringCache::default();
        decoded(&text, &sp, |d| back.decode(d, &sp)).unwrap();
        prop_assert_eq!(back.entries().collect::<Vec<_>>(), cache.entries().collect::<Vec<_>>());
    }

    #[test]
    fn the_constant_pool_round_trips(
        records in prop::collection::btree_map(
            (any::<u64>(), any::<u64>()),
            (0u8..8, "[a-zA-Z_<&]{0,8}", any::<u64>(), 0usize..3, prop::option::of(prop::collection::vec(any::<u8>(), 0..40))),
            0..8,
        )
    ) {
        let m = small::spaces(false);
        let mut types = small::types(&m);
        let sp = Arc::new(m);
        let tys = [
            types.base(4, Metatype::Int).unwrap(),
            types.base(1, Metatype::Uint).unwrap(),
            types.base(8, Metatype::Unknown).unwrap(),
        ];
        let tags = [
            CPoolTag::Primitive, CPoolTag::StringLiteral, CPoolTag::ClassReference, CPoolTag::PointerMethod,
            CPoolTag::PointerField, CPoolTag::ArrayLength, CPoolTag::InstanceOf, CPoolTag::CheckCast,
        ];
        let mut pool = ConstantPool::new();
        for ((a, b), (tag, token, value, ty, data)) in &records {
            let tag = tags[*tag as usize];
            // A string literal always carries data; only a primitive keeps
            // its value.
            let data = if tag == CPoolTag::StringLiteral { Some(data.clone().unwrap_or_default()) } else { data.clone() };
            let rec = CPoolRecord {
                tag,
                flags: 0,
                token: if data.is_some() { String::new() } else { token.clone() },
                value: if tag == CPoolTag::Primitive { *value } else { 0 },
                ty: tys[*ty],
                data,
            };
            pool.insert(&[*a, *b], rec).unwrap();
        }
        let text = encoded(|e| pool.encode(e, &types).unwrap());
        let mut back = ConstantPool::new();
        decoded(&text, &sp, |d| back.decode(d, &mut types)).unwrap();
        for (a, b) in records.keys() {
            prop_assert_eq!(back.record(&[*a, *b]).unwrap(), pool.record(&[*a, *b]).unwrap());
        }
        prop_assert_eq!(encoded(|e| back.encode(e, &types).unwrap()), text);
    }

    #[test]
    fn overrides_round_trip(
        gotos in prop::collection::btree_map(any::<u32>(), any::<u32>(), 0..4),
        delays in prop::collection::vec((0usize..9, 0i32..5), 0..4),
        jumps in prop::collection::vec(any::<u32>(), 0..4),
        flows in prop::collection::btree_map(any::<u32>(), (0usize..7, any::<u32>()), 0..6),
    ) {
        let sp = Arc::new(small::spaces(false));
        let a = |o: u32| Address::new(RAM, u64::from(o));
        let mut ov = Overrides::default();
        for (t, d) in &gotos {
            ov.insert_force_goto(a(*t), a(*d));
        }
        for (space, delay) in &delays {
            if let Some(s) = sp.space_at(*space as u32) {
                ov.insert_deadcode_delay(s.id(), *delay);
            }
        }
        for j in &jumps {
            ov.insert_multistage_jump(a(*j));
        }
        let flow_names = ["branch", "call", "callreturn", "return"];
        let dest_names = ["callother_call", "callother_branch", "call_call"];
        for (at, (k, dest)) in &flows {
            if *k < 4 {
                ov.insert_flow_override(a(*at), flow_names[*k]).unwrap();
            } else {
                ov.insert_destination_override(a(*at), a(*dest), dest_names[*k - 4]).unwrap();
            }
        }
        let text = encoded(|e| ov.encode(e, &sp, &NoProtos).unwrap());
        let mut back = Overrides::default();
        if !text.is_empty() {
            decoded(&text, &sp, |d| back.decode(d, &sp, &NoProtos)).unwrap();
        }
        prop_assert_eq!(&back.force_goto, &ov.force_goto);
        prop_assert_eq!(&back.multistage_jump, &ov.multistage_jump);
        prop_assert_eq!(&back.pcode, &ov.pcode);
        prop_assert_eq!(encoded(|e| back.encode(e, &sp, &NoProtos).unwrap()), text);
    }
}

/// Prototype overrides need `bk-cspec`'s codec (D07); none are generated.
struct NoProtos;

impl ProtoCodec for NoProtos {
    fn encode(&self, _: &FuncProto, _: &mut dyn Encoder) -> bk_decomp_symbols::Result<()> {
        Err(SymbolError::Unimplemented("prototype encoding"))
    }
    fn decode(&self, _: &mut dyn Decoder<'_>) -> bk_decomp_symbols::Result<FuncProto> {
        Err(SymbolError::Unimplemented("prototype decoding"))
    }
    fn print_raw(&self, _: &FuncProto) -> String {
        String::new()
    }
}
