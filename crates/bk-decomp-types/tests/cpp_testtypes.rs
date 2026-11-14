//! Ghidra's `unittests/testtypes.cc`: the three tests that need no IR
//! (`type_ordering`, `enum_matching`, `enum_matching2`). The other five
//! (`cast_*`) need type operations and belong to the IR tracks.
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

use std::cmp::Ordering;

use bk_decomp_types::Metatype;
use common::{parse, x86_64_factory};

#[test]
fn type_ordering() {
    let mut f = x86_64_factory();
    let lt = |f: &bk_decomp_types::TypeFactory, a, b| f.compare(a, b, 10) == Ordering::Less;

    let (u4, i4) = (parse(&mut f, "uint4"), parse(&mut f, "int4"));
    assert!(lt(&f, u4, i4));
    let int_typedef = f.base_named(4, Metatype::Int, "myint4").unwrap();
    assert_ne!(i4, int_typedef);
    assert_eq!(f.compare_dependency(i4, int_typedef), 0);
    let pairs = [
        ("int1", "char"),
        ("wchar2", "int2"),
        ("wchar4", "int4"),
        ("uint1", "char"),
    ];
    for (a, b) in pairs {
        let (x, y) = (parse(&mut f, a), parse(&mut f, b));
        assert!(lt(&f, x, y), "{a} before {b}");
    }
    let enum1 = parse(&mut f, "enum enum2 { ONE=1, TWO=2 }");
    let i8 = parse(&mut f, "int8");
    assert!(lt(&f, enum1, i8));
    let s1 = parse(&mut f, "struct struct1 { int4 a; int4 b; }");
    let s2 = parse(&mut f, "struct struct2 { int4 a; int4 b; }");
    assert_ne!(s1, s2);
    assert_eq!(f.compare_dependency(s1, s2), 0);
    let pairs = [
        ("uint4", "uint2"),
        ("float8", "float4"),
        ("bool", "uint1"),
        ("uint4 *", "int4 *"),
        ("enum2 *", "int8 *"),
        ("int4 *", "void *"),
        ("int2 *", "xunknown2 *"),
    ];
    for (a, b) in pairs {
        let (x, y) = (parse(&mut f, a), parse(&mut f, b));
        assert!(lt(&f, x, y), "{a} before {b}");
    }
}

#[test]
fn enum_matching() {
    let mut f = x86_64_factory();
    let enum3 = parse(
        &mut f,
        "enum enum3 { ZERO=0, ONE=1, TWO=2, FOUR=4, EIGHT=8 }",
    );
    let rep = f.enum_matches(enum3, 5);
    assert_eq!(rep.names, ["FOUR", "ONE"]);
    assert!(!rep.complement);
    let rep = f.enum_matches(enum3, 0xffff_ffff_ffff_fff7);
    assert_eq!(rep.names, ["EIGHT"]);
    assert!(rep.complement);
    let rep = f.enum_matches(enum3, 0);
    assert_eq!(rep.names, ["ZERO"]);
    assert!(!rep.complement);
    let rep = f.enum_matches(enum3, 0x10);
    assert_eq!(rep.names, Vec::<String>::new());
    assert!(!rep.complement);
}

#[test]
fn enum_matching2() {
    let mut f = x86_64_factory();
    let enum4 = parse(
        &mut f,
        "enum enum4 { ZERO=0, ONE=1, TWO=2, FOUR=4, SIX=6, EIGHT=8, ELEVEN=11 }",
    );
    let rep = f.enum_matches(enum4, 12);
    assert_eq!(rep.names, ["EIGHT", "FOUR"]);
    assert!(!rep.complement);
    let rep = f.enum_matches(enum4, 7);
    assert_eq!(rep.names, ["SIX", "ONE"]);
    assert!(!rep.complement);
    let rep = f.enum_matches(enum4, 11);
    assert_eq!(rep.names, ["ELEVEN"]);
    assert!(!rep.complement);
}
