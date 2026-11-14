//! Property tests (spec 6.6): interning, the two orderings, dependency
//! order, the forked factory against a flat one, provenance, and that the
//! decoders and the parser never panic.
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

use bk_core::Provenance;
use bk_decomp_types::{Field, Metatype, TypeFactory, TypeId, cdecl};
use common::x86_64_factory;
use proptest::prelude::*;

/// One step of building types; components refer to earlier results by
/// index (modulo the number of results).
#[derive(Clone, Debug)]
enum Op {
    Base(u8, u8),
    Pointer(usize),
    Array(usize, u8),
    Struct(u8, Vec<usize>),
    Union(u8, Vec<usize>),
    Typedef(usize, u8),
    Piece(usize, u8, u8),
    PtrRel(usize, u8),
    Enum(u8, Vec<u8>),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..4, 0u8..6).prop_map(|(s, m)| Op::Base(s, m)),
        any::<usize>().prop_map(Op::Pointer),
        (any::<usize>(), 1u8..5).prop_map(|(k, n)| Op::Array(k, n)),
        (0u8..12, prop::collection::vec(any::<usize>(), 1..4)).prop_map(|(n, f)| Op::Struct(n, f)),
        (0u8..12, prop::collection::vec(any::<usize>(), 1..3)).prop_map(|(n, f)| Op::Union(n, f)),
        (any::<usize>(), 0u8..12).prop_map(|(k, n)| Op::Typedef(k, n)),
        (any::<usize>(), 0u8..16, 1u8..8).prop_map(|(k, o, s)| Op::Piece(k, o, s)),
        (any::<usize>(), 1u8..16).prop_map(|(k, o)| Op::PtrRel(k, o)),
        (0u8..12, prop::collection::vec(0u8..40, 1..5)).prop_map(|(n, v)| Op::Enum(n, v)),
    ]
}

const METAS: [Metatype; 6] = [
    Metatype::Int,
    Metatype::Uint,
    Metatype::Float,
    Metatype::Bool,
    Metatype::Unknown,
    Metatype::Code,
];

/// Applies the ops; returns the results (errors are skipped: names may
/// repeat, which Ghidra refuses as a redefinition).
fn apply(
    f: &mut TypeFactory,
    ops: &[Op],
    seed: &[TypeId],
    prov: &[Provenance],
) -> Vec<Option<TypeId>> {
    let mut res: Vec<TypeId> = seed.to_vec();
    let mut out = Vec::new();
    for (i, o) in ops.iter().enumerate() {
        if let Some(p) = prov.get(i % prov.len().max(1)) {
            f.set_provenance(*p);
        }
        let pick = |k: usize, res: &Vec<TypeId>| res[k % res.len()];
        let r = match o {
            Op::Base(s, m) => f.base(1 << s, METAS[*m as usize]).ok(),
            Op::Pointer(k) => f.pointer(8, pick(*k, &res), 1).ok(),
            Op::Array(k, n) => {
                let el = pick(*k, &res);
                if f.get(el).unwrap().size() == 0 {
                    None
                } else {
                    f.array(i32::from(*n), el).ok()
                }
            }
            Op::Struct(n, fl) => (|| {
                let id = f.structure_stub(&format!("st{n}_{i}")).ok()?;
                let fields: Vec<Field> = fl
                    .iter()
                    .enumerate()
                    .map(|(j, &k)| Field {
                        ident: 0,
                        offset: -1,
                        name: format!("f{j}").into(),
                        ty: pick(k, &res),
                    })
                    .collect();
                f.assign_raw_struct_fields(id, fields, Vec::new()).ok()?;
                Some(id)
            })(),
            Op::Union(n, fl) => (|| {
                let id = f.union_stub(&format!("un{n}_{i}")).ok()?;
                let fields: Vec<Field> = fl
                    .iter()
                    .enumerate()
                    .map(|(j, &k)| Field {
                        ident: j as i32,
                        offset: 0,
                        name: format!("u{j}").into(),
                        ty: pick(k, &res),
                    })
                    .collect();
                f.assign_raw_union_fields(id, fields).ok()?;
                Some(id)
            })(),
            Op::Typedef(k, n) => f.typedef(pick(*k, &res), &format!("td{n}"), 0, 0).ok(),
            Op::Piece(k, o, s) => f
                .exact_piece(pick(*k, &res), i32::from(*o), i32::from(*s))
                .ok()
                .flatten(),
            Op::PtrRel(k, o) => (|| {
                let parent = pick(*k, &res);
                if f.get(parent).unwrap().metatype() != Metatype::Struct {
                    return None;
                }
                let p = f.pointer(8, parent, 1).ok()?;
                let to = f.ptr_to_from_parent(parent, i32::from(*o)).ok()?;
                f.pointer_rel(p, to, i32::from(*o)).ok()
            })(),
            Op::Enum(n, vals) => (|| {
                let id = f.enum_stub(&format!("en{n}_{i}")).ok()?;
                let list: Vec<bk_decomp_types::Enumerator> = vals
                    .iter()
                    .enumerate()
                    .map(|(j, v)| bk_decomp_types::Enumerator {
                        name: format!("E{j}"),
                        value: Some(u64::from(*v)),
                    })
                    .collect();
                let map = bk_decomp_types::assign_values(&list, f.get(id)?.size(), "e").ok()?;
                f.set_enum_values(id, map).ok()?;
                Some(id)
            })(),
        };
        if let Some(t) = r {
            res.push(t);
        }
        out.push(r);
    }
    out
}

fn seed(f: &TypeFactory) -> Vec<TypeId> {
    [
        "int4",
        "uint1",
        "char",
        "float8",
        "xunknown4",
        "void",
        "bool",
    ]
    .iter()
    .map(|n| f.find_by_name(n).unwrap())
    .collect()
}

fn describe(f: &TypeFactory, t: TypeId) -> String {
    let e = f.get(t).unwrap();
    format!(
        "{}|{:x}|{}|{}|{:?}|{:x}",
        f.print_raw(t),
        e.id(),
        e.size(),
        e.alignment(),
        e.submeta(),
        e.flags().bits()
    )
}

fn encode(f: &TypeFactory) -> String {
    let mut enc = bk_marshal::XmlEncoder::new(false);
    f.encode(&mut enc).unwrap();
    enc.into_string()
}

/// At least 1,024 cases; `PROPTEST_CASES` raises it.
fn config() -> ProptestConfig {
    let d = ProptestConfig::default();
    ProptestConfig {
        cases: d.cases.max(1024),
        ..d
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn interning_is_idempotent(ops in prop::collection::vec(op(), 1..12)) {
        let mut f = x86_64_factory();
        let s = seed(&f);
        let first = apply(&mut f, &ops, &s, &[]);
        let len = f.len();
        // Asking again for the same anonymous types finds them.
        for (o, r) in ops.iter().zip(&first) {
            let Some(r) = *r else { continue };
            if let Op::Pointer(_) | Op::Array(..) | Op::Base(..) = o {
                let again = match o {
                    Op::Pointer(_) => f.pointer(8, f.get(r).unwrap().pointer().unwrap().ptrto, 1).unwrap(),
                    Op::Base(sz, m) => f.base(1 << sz, METAS[*m as usize]).unwrap(),
                    Op::Array(..) => {
                        let bk_decomp_types::TypeKind::Array { element, count } = f.get(r).unwrap().kind().clone() else { unreachable!() };
                        f.array(count, element).unwrap()
                    }
                    _ => unreachable!(),
                };
                prop_assert_eq!(again, r);
            }
        }
        prop_assert_eq!(f.len(), len);
    }

    #[test]
    fn orderings_are_consistent(ops in prop::collection::vec(op(), 1..12)) {
        let mut f = x86_64_factory();
        let s = seed(&f);
        apply(&mut f, &ops, &s, &[]);
        let ids = f.ids();
        for &a in &ids {
            for &b in &ids {
                let ab = f.compare_raw(a, b, 10).signum();
                let ba = f.compare_raw(b, a, 10).signum();
                prop_assert_eq!(ab, -ba, "compare {} {}", f.print_raw(a), f.print_raw(b));
                let dab = f.compare_dependency(a, b).signum();
                let dba = f.compare_dependency(b, a).signum();
                prop_assert_eq!(dab, -dba);
            }
        }
        // compareDependency then id is a total order: sorting is stable
        // under re-sorting and adjacent pairs are strictly increasing.
        let sorted = f.sorted_ids();
        for w in sorted.windows(2) {
            let (x, y) = (w[0], w[1]);
            let d = f.compare_dependency(x, y);
            prop_assert!(d < 0 || (d == 0 && f.get(x).unwrap().id() < f.get(y).unwrap().id()));
        }
    }

    #[test]
    fn dependent_order_lists_dependencies_first(ops in prop::collection::vec(op(), 1..12)) {
        let mut f = x86_64_factory();
        let s = seed(&f);
        apply(&mut f, &ops, &s, &[]);
        let order = f.dependent_order();
        let pos: std::collections::HashMap<TypeId, usize> = order.iter().enumerate().map(|(i, t)| (*t, i)).collect();
        prop_assert_eq!(order.len(), f.len());
        for &t in &order {
            let deps = (0..f.num_depend(t)).filter_map(|i| f.depend(t, i)).chain(f.get(t).unwrap().typedef_of());
            for d in deps {
                // A dependency already being visited (a cycle) may follow.
                if d != t && pos[&d] > pos[&t] {
                    let back = (0..f.num_depend(d)).filter_map(|i| f.depend(d, i)).any(|x| x == t);
                    prop_assert!(back || f.get(t).unwrap().is_pointer_rel(), "{} before {}", f.print_raw(t), f.print_raw(d));
                }
            }
        }
    }

    #[test]
    fn fork_answers_as_a_flat_factory(base_ops in prop::collection::vec(op(), 0..6), ops in prop::collection::vec(op(), 1..10)) {
        let mut root = x86_64_factory();
        let s = seed(&root);
        apply(&mut root, &base_ops, &s, &[]);
        let mut flat = root.clone();
        let parent = Arc::new(root);
        let before = encode(&parent);
        let s = seed(&parent);
        let mut child = TypeFactory::fork(&parent).unwrap();
        let rc = apply(&mut child, &ops, &s, &[]);
        let rf = apply(&mut flat, &ops, &s, &[]);
        prop_assert_eq!(rc.len(), rf.len());
        for (c, f) in rc.iter().zip(&rf) {
            match (c, f) {
                (Some(c), Some(f2)) => prop_assert_eq!(describe(&child, *c), describe(&flat, *f2)),
                (None, None) => {}
                _ => prop_assert!(false, "fork and flat disagree on success"),
            }
        }
        let sc: Vec<String> = child.sorted_ids().iter().map(|&t| describe(&child, t)).collect();
        let sf: Vec<String> = flat.sorted_ids().iter().map(|&t| describe(&flat, t)).collect();
        prop_assert_eq!(sc, sf);
        prop_assert_eq!(encode(&child), encode(&flat));
        for id in child.overlay_ids() {
            prop_assert!(id.is_overlay());
            prop_assert_eq!(child.get(id).unwrap().provenance(), Provenance::Analysis);
        }
        drop(child);
        prop_assert_eq!(encode(&parent), before);
    }

    #[test]
    fn provenance_changes_nothing(ops in prop::collection::vec(op(), 1..12), provs in prop::collection::vec(0usize..7, 1..5)) {
        const ALL: [Provenance; 7] = [Provenance::Default, Provenance::Analysis, Provenance::Model, Provenance::Imported, Provenance::LibrarySignature, Provenance::DebugInfo, Provenance::User];
        let provs: Vec<Provenance> = provs.into_iter().map(|i| ALL[i]).collect();
        let mut a = x86_64_factory();
        let mut b = x86_64_factory();
        let s = seed(&a);
        let ra = apply(&mut a, &ops, &s, &[]);
        let rb = apply(&mut b, &ops, &s, &provs);
        prop_assert_eq!(ra, rb);
        prop_assert_eq!(encode(&a), encode(&b));
        prop_assert_eq!(a.sorted_ids(), b.sorted_ids());
    }

    #[test]
    fn decoder_never_panics(text in "\\PC{0,300}") {
        let mut f = x86_64_factory();
        let _ = f.decode_text(&text);
        let wrapped = format!("<typegrp>{text}</typegrp>");
        let _ = f.decode_text(&wrapped);
    }

    #[test]
    fn decoder_never_panics_on_type_like_xml(
        meta in prop::sample::select(vec!["int", "uint", "ptr", "array", "struct", "union", "enum_int", "code", "ptrrel", "partstruct", "spacebase", "void", "bogus"]),
        size in -2i32..40, name in "[a-c]{0,2}", child in 0usize..4, off in -1i32..20,
    ) {
        let mut f = x86_64_factory();
        let inner = ["<typeref name=\"int4\"/>", "<void/>", "<type name=\"\" size=\"4\" metatype=\"int\"/>", ""][child];
        let text = format!("<typegrp><type name=\"{name}\" size=\"{size}\" metatype=\"{meta}\" arraysize=\"2\"><field name=\"x\" offset=\"{off}\">{inner}</field>{inner}<off>{off}</off></type></typegrp>");
        let _ = f.decode_text(&text);
    }

    #[test]
    fn parser_never_panics(text in "\\PC{0,200}") {
        let mut f = x86_64_factory();
        let _ = cdecl::parse_type(&mut f, &text, &cdecl::no_models);
        let _ = cdecl::parse_declaration(&mut f, &text, &cdecl::no_models);
    }

    #[test]
    fn parser_never_panics_on_c_like_text(words in prop::collection::vec(prop::sample::select(vec![
        "int4", "char", "struct", "union", "enum", "typedef", "extern", "const", "*", "(", ")", "[", "]", "{", "}",
        ";", ",", "...", ":", "=", "a", "b", "3", "0x10", "-1", "::", "void", "s", "'x'", "/*", "*/",
    ]), 0..30)) {
        let mut f = x86_64_factory();
        let text = words.join(" ");
        let _ = cdecl::parse_type(&mut f, &text, &cdecl::no_models);
        let _ = cdecl::parse_declaration(&mut f, &text, &cdecl::no_models);
    }
}

#[test]
fn deep_nesting_is_an_error_not_a_crash() {
    let mut f = x86_64_factory();
    let text = format!("int4 {}a{}", "(".repeat(5000), ")".repeat(5000));
    assert!(cdecl::parse_type(&mut f, &text, &cdecl::no_models).is_err());
    let mut xml = String::from("<typegrp>");
    for _ in 0..2000 {
        xml.push_str("<type name=\"\" size=\"8\" metatype=\"ptr\">");
    }
    xml.push_str("<typeref name=\"int4\"/>");
    for _ in 0..2000 {
        xml.push_str("</type>");
    }
    xml.push_str("</typegrp>");
    assert!(f.decode_text(&xml).is_err());
}

#[test]
fn fork_of_fork_is_refused_and_new_types_live_in_the_overlay() {
    let root = x86_64_factory();
    let parent = Arc::new(root);
    let mut child = TypeFactory::fork(&parent).unwrap();
    assert!(TypeFactory::fork(&Arc::new(child.clone())).is_err());
    let int4 = child.find_by_name("int4").unwrap();
    let p = child.pointer(8, int4, 1).unwrap();
    assert!(p.is_overlay());
    assert_eq!(child.overlay_ids(), vec![p]);
    assert_eq!(child.pointer(8, int4, 1).unwrap(), p);
}

/// The case proptest found (`properties.proptest-regressions`): a
/// structure stub left incomplete in the parent (its field list was
/// refused) is completed in a fork. Ghidra's single factory completes the
/// stub in place (`setFields`), keeping its id; the fork must answer the
/// same, so it copies the parent entry under the same id and the parent
/// stays as it was.
#[test]
fn fork_completes_a_parent_stub_under_the_same_id() {
    let mut root = x86_64_factory();
    let void = root.find_by_name("void").unwrap();
    let int4 = root.find_by_name("int4").unwrap();
    let stub = root.structure_stub("st").unwrap();
    let bad = vec![Field {
        ident: 0,
        offset: -1,
        name: "v".into(),
        ty: void,
    }];
    assert_eq!(
        root.assign_raw_struct_fields(stub, bad, Vec::new())
            .unwrap_err()
            .to_string(),
        "Illegal field void in structure: st"
    );
    let ptr = root.pointer(8, stub, 1).unwrap();
    let mut flat = root.clone();
    let parent = Arc::new(root);
    let before = encode(&parent);
    let mut child = TypeFactory::fork(&parent).unwrap();

    let fields = || {
        vec![Field {
            ident: 0,
            offset: -1,
            name: "x".into(),
            ty: int4,
        }]
    };
    for f in [&mut child, &mut flat] {
        let again = f.structure_stub("st").unwrap();
        assert_eq!(again, stub);
        f.assign_raw_struct_fields(again, fields(), Vec::new())
            .unwrap();
    }
    for f in [&child, &flat] {
        let e = f.get(stub).unwrap();
        assert!(!e.is_incomplete());
        assert_eq!(e.size(), 4);
        assert_eq!(f.find_by_name("st"), Some(stub));
        // A single field filling the structure makes it need resolution
        // (Ghidra `setFields`), so recalcPointerSubmeta moves its pointers
        // from SUB_PTR_STRUCT to SUB_PTR.
        assert!(e.needs_resolution());
        assert_eq!(
            f.get(ptr).unwrap().submeta(),
            bk_decomp_types::SubMetatype::Ptr
        );
    }
    assert_eq!(encode(&child), encode(&flat));
    assert_eq!(
        child.shadowed_ids(),
        vec![ptr, stub]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    // The parent is unchanged, and a later stub request in the parent still
    // finds its own incomplete stub.
    assert!(parent.get(stub).unwrap().is_incomplete());
    assert_eq!(encode(&parent), before);
    drop(child);
    assert_eq!(encode(&parent), before);
}

/// The second case proptest found: a fork finding a parent pointer raises
/// its provenance (the fork's `Analysis` over the parent's `Default`),
/// which copies the entry into the fork; the copy must be found again
/// rather than a duplicate made.
#[test]
fn fork_finds_a_parent_type_whose_provenance_it_raised() {
    let mut root = x86_64_factory();
    let uint1 = root.find_by_name("uint1").unwrap();
    let p = root.pointer(8, uint1, 1).unwrap();
    let parent = Arc::new(root);
    let mut child = TypeFactory::fork(&parent).unwrap();
    assert_eq!(child.pointer(8, uint1, 1).unwrap(), p);
    assert_eq!(child.get(p).unwrap().provenance(), Provenance::Analysis);
    assert_eq!(parent.get(p).unwrap().provenance(), Provenance::Default);
    assert_eq!(child.pointer(8, uint1, 1).unwrap(), p);
    assert_eq!(child.len(), parent.len());
    assert!(child.overlay_ids().is_empty());
    assert_eq!(child.shadowed_ids(), vec![p]);
}
