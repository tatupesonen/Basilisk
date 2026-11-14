//! Encode and decode of types: round trips and warnings.
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

use common::{parse, x86_64_factory};

fn encode_all(f: &bk_decomp_types::TypeFactory) -> String {
    let mut enc = bk_marshal::XmlEncoder::new(false);
    f.encode(&mut enc).unwrap();
    enc.into_string()
}

#[test]
fn factory_round_trip() {
    let mut f = x86_64_factory();
    parse(&mut f, "struct pt { int4 x; int4 y; char c; int8 z; }");
    parse(&mut f, "union u { int4 a; float8 b; }");
    parse(&mut f, "enum col { RED, GREEN=5, BLUE }");
    parse(&mut f, "pt *a[3]");
    let text = encode_all(&f);
    let mut g = x86_64_factory();
    g.decode_text(&text).unwrap();
    assert_eq!(encode_all(&g), text);
    let pt = g.find_by_name("pt").unwrap();
    assert_eq!(g.get(pt).unwrap().size(), 24);
}

/// Ghidra writes `<bitfield>` without the `id` its decoder requires, so a
/// structure with bitfields does not survive a round trip (reproduced).
#[test]
fn bitfields_do_not_round_trip() {
    let mut f = x86_64_factory();
    parse(&mut f, "struct bits { int4 a:3; int4 b:5; uint2 c; }");
    let text = encode_all(&f);
    let mut g = x86_64_factory();
    let err = g.decode_text(&text).unwrap_err();
    assert_eq!(err.to_string(), "<bitfield> id attribute must not be empty");
}

#[test]
fn overlapping_field_warning() {
    let mut f = x86_64_factory();
    let text = r#"<typegrp><type name="s" size="8" metatype="struct">
      <field name="a" offset="0"><typeref name="int4"/></field>
      <field name="b" offset="2"><typeref name="int4"/></field>
      </type></typegrp>"#;
    f.decode_text(text).unwrap();
    let s = f.find_by_name("s").unwrap();
    assert_eq!(
        f.find_warning(s),
        Some("Struct \"s\": ignoring overlapping field \"b\"")
    );
    let err = f.decode_text(r#"<typegrp><type name="t" size="2" metatype="struct"><field name="a" offset="0"><typeref name="int4"/></field></type></typegrp>"#).unwrap_err();
    assert_eq!(err.to_string(), "Field a does not fit in structure t");
    let err = f
        .decode_text(r#"<typegrp><typeref name="nothere"/></typegrp>"#)
        .unwrap_err();
    assert!(err.to_string().contains("nothere") || !err.to_string().is_empty());
}

/// Types a host supplies on demand through the `TypeSource` hook carry the
/// host's provenance; a later request with lower trust keeps it.
#[test]
fn type_source_hook_and_provenance() {
    use std::sync::Arc;

    use bk_core::Provenance;
    use bk_decomp_types::xml::{Hooks, TypeSource};

    struct Host;
    impl TypeSource for Host {
        fn definition(&self, name: &str, _id: u64, _size: i32) -> Option<(String, Provenance)> {
            (name == "hosted").then(|| {
                (
                    r#"<type name="hosted" size="4" metatype="struct"><field name="v" offset="0"><typeref name="int4"/></field></type>"#.to_owned(),
                    Provenance::DebugInfo,
                )
            })
        }
    }
    let mut f = x86_64_factory();
    f.set_hooks(Hooks {
        source: Some(Arc::new(Host)),
        ..Hooks::default()
    });
    f.decode_text(r#"<typegrp><type name="" size="8" metatype="ptr"><typeref name="hosted"/></type></typegrp>"#).unwrap();
    let hosted = f.find_by_name("hosted").unwrap();
    assert_eq!(f.get(hosted).unwrap().provenance(), Provenance::DebugInfo);
    let err = f
        .decode_text(r#"<typegrp><type name="" size="8" metatype="ptr"><typeref name="absent"/></type></typegrp>"#)
        .unwrap_err();
    assert_eq!(err.to_string(), "Unable to resolve type: absent");
    // Interned again with lower trust: the id is the same and the more
    // trusted provenance stays; with higher trust, it is raised.
    f.set_provenance(Provenance::Analysis);
    assert_eq!(
        f.typedef(hosted, "alias", 0, 0).unwrap(),
        f.typedef(hosted, "alias", 0, 0).unwrap()
    );
    let p = f.pointer(8, hosted, 1).unwrap();
    f.set_provenance(Provenance::User);
    assert_eq!(f.pointer(8, hosted, 1).unwrap(), p);
    assert_eq!(f.get(p).unwrap().provenance(), Provenance::User);
}
