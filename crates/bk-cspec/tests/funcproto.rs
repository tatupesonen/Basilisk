//! Port of Ghidra's `unittests/testfuncproto.cc` (21 tests), self-contained:
//! the Toy:LE:32 spaces and registers are built in test code
//! (`common::toy_manager`) and the three models of the test are decoded
//! from its `<specextensions>` text.

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

use bk_core::SpaceManager;
use bk_cspec::proto::{ParameterPieces, PieceFlags};
use bk_cspec::types::{Metatype, ParamTypes};
use bk_cspec::{CompilerSpec, ParamActive, ParamTrial};
use common::testtypes::{CSizes, TestTypes};
use common::{at_register, cparse, funcproto_spec, stack_addr};

fn toy_types() -> TestTypes {
    TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 4], CSizes::default())
}

fn assign(model: &str, sig: &str) -> (Vec<ParameterPieces>, TestTypes, SpaceManager) {
    let (spec, m) = funcproto_spec();
    let mut types = toy_types();
    let proto = cparse::proto(&mut types, model, sig);
    let mut res = Vec::new();
    spec.model_by_name(model)
        .unwrap()
        .assign_parameter_storage(&m, &mut types, &proto, &mut res, false)
        .unwrap();
    (res, types, m)
}

fn name(t: &TestTypes, p: &ParameterPieces) -> String {
    t.name(p.ty)
}

#[test]
fn funcproto_register() {
    let (res, _, m) = assign("__model1", "void func(int4 a,int4 b);");
    assert_eq!(res.len(), 3);
    assert!(res[0].addr.is_invalid());
    assert!(at_register(&m, &res[1], "r12"));
    assert!(at_register(&m, &res[2], "r11"));
}

#[test]
fn funcproto_smallregister() {
    let (res, t, m) = assign("__model1", "int4 func(char a,int4 b,int2 c,int4 d);");
    assert_eq!(res.len(), 5);
    let want = [
        ("r12", "int4"),
        ("r12", "char"),
        ("r11", "int4"),
        ("r10", "int2"),
        ("r9", "int4"),
    ];
    for (p, (reg, ty)) in res.iter().zip(want) {
        assert!(at_register(&m, p, reg));
        assert_eq!(name(&t, p), ty);
    }
}

#[test]
fn funcproto_stackalign() {
    let (res, t, m) = assign(
        "__model1",
        "int4 func(int4 a,int4 b,int4 c,int4 d,int4 e,int2 f,int1 *g);",
    );
    assert_eq!(res.len(), 8);
    for (i, reg) in ["r12", "r12", "r11", "r10", "r9", "r8"].iter().enumerate() {
        assert!(at_register(&m, &res[i], reg));
        assert_eq!(res[i].ty, res[0].ty);
    }
    assert_eq!(res[6].addr, stack_addr(&m, 0));
    assert_eq!(name(&t, &res[6]), "int2");
    assert_eq!(res[7].addr, stack_addr(&m, 4));
    assert_eq!(t.metatype(res[7].ty), Metatype::Ptr);
}

#[test]
fn funcproto_pointeroverflow() {
    let (res, t, m) = assign("__model1", "int2 func(int4 a,int8 b,int4 c);");
    assert_eq!(res.len(), 4);
    assert!(at_register(&m, &res[0], "r12"));
    assert_eq!(name(&t, &res[0]), "int2");
    assert!(at_register(&m, &res[1], "r12"));
    assert!(at_register(&m, &res[2], "r11"));
    assert_eq!(t.metatype(res[2].ty), Metatype::Ptr);
    assert_eq!(t.name(t.pointed_to(res[2].ty).unwrap()), "int8");
    assert_eq!(res[2].flags, PieceFlags::INDIRECTSTORAGE);
    assert!(at_register(&m, &res[3], "r10"));
    assert_eq!(name(&t, &res[3]), "int4");
}

#[test]
fn funcproto_stackoverflow() {
    let (res, t, m) = assign("__model2", "char func(int4 a,int8 b,int4 c);");
    assert_eq!(res.len(), 4);
    assert!(at_register(&m, &res[0], "r12"));
    assert_eq!(name(&t, &res[0]), "char");
    assert!(at_register(&m, &res[1], "r10"));
    assert_eq!(res[2].addr, stack_addr(&m, 0));
    assert_eq!(name(&t, &res[2]), "int8");
    assert!(at_register(&m, &res[3], "r9"));
}

#[test]
fn funcproto_floatreg() {
    let (res, t, m) = assign(
        "__model2",
        "void func(int4 a,float4 b,float4 c,int4 d,float4 d);",
    );
    assert_eq!(res.len(), 6);
    assert!(res[0].addr.is_invalid());
    for (i, reg) in [(1, "r10"), (2, "r3"), (3, "r4"), (4, "r9"), (5, "r5")] {
        assert!(at_register(&m, &res[i], reg), "param {i}");
    }
    assert_eq!(name(&t, &res[2]), "float4");
    assert_eq!(name(&t, &res[5]), "float4");
}

#[test]
fn funcproto_floattogeneric() {
    let (res, t, m) = assign(
        "__model2",
        "float4 func(int4 a,float4 b,float4 c,float4 d,float4 e,float4 f);",
    );
    assert_eq!(res.len(), 7);
    for (i, reg) in ["r12", "r10", "r3", "r4", "r5", "r9", "r8"]
        .iter()
        .enumerate()
    {
        assert!(at_register(&m, &res[i], reg), "piece {i}");
    }
    assert_eq!(name(&t, &res[5]), "float4");
}

#[test]
fn funcproto_grouped() {
    let (res, t, m) = assign(
        "__model3",
        "float4 func(int4 a,float4 b,float4 c,int4 d,float4 e);",
    );
    assert_eq!(res.len(), 6);
    for (i, reg) in ["r12", "r10", "r4", "r5"].iter().enumerate() {
        assert!(at_register(&m, &res[i], reg), "piece {i}");
    }
    assert_eq!(res[4].addr, stack_addr(&m, 0));
    assert_eq!(name(&t, &res[4]), "int4");
    assert_eq!(res[5].addr, stack_addr(&m, 4));
    assert_eq!(name(&t, &res[5]), "float4");
}

#[test]
fn funcproto_join() {
    let (res, t, m) = assign("__model2", "int2 func(int8 a,int4 b,int4 c);");
    assert_eq!(res.len(), 4);
    assert!(at_register(&m, &res[0], "r12"));
    assert!(res[1].addr.is_join(&m));
    assert_eq!(name(&t, &res[1]), "int8");
    assert!(at_register(&m, &res[2], "r8"));
    assert_eq!(res[3].addr, stack_addr(&m, 0));
}

#[test]
fn funcproto_nojoin() {
    let (res, t, m) = assign("__model2", "int4 func(int4 a,int8 b,int4 c);");
    assert_eq!(res.len(), 4);
    assert!(at_register(&m, &res[0], "r12"));
    assert!(at_register(&m, &res[1], "r10"));
    assert_eq!(res[2].addr, stack_addr(&m, 0));
    assert_eq!(name(&t, &res[2]), "int8");
    assert!(at_register(&m, &res[3], "r9"));
}

#[test]
fn funcproto_hiddenreturn() {
    let (res, t, m) = assign("__model1", "int8 func(int4 a,int4 b);");
    assert_eq!(res.len(), 4);
    assert!(at_register(&m, &res[0], "r12"));
    assert_eq!(t.metatype(res[0].ty), Metatype::Ptr);
    assert_eq!(t.name(t.pointed_to(res[0].ty).unwrap()), "int8");
    assert!(at_register(&m, &res[1], "r12"));
    assert_eq!(res[1].flags, PieceFlags::HIDDENRETPARM);
    assert_eq!(t.name(t.pointed_to(res[1].ty).unwrap()), "int8");
    assert!(at_register(&m, &res[2], "r11"));
    assert!(at_register(&m, &res[3], "r10"));
}

#[test]
fn funcproto_mixedmeta() {
    let (res, t, m) = assign("__model2", "int4 func(char *a,int4 b,float4 c,int4 *d);");
    assert_eq!(res.len(), 5);
    for (i, reg) in ["r12", "r1", "r10", "r3", "r2"].iter().enumerate() {
        assert!(at_register(&m, &res[i], reg), "piece {i}");
    }
    assert_eq!(t.metatype(res[1].ty), Metatype::Ptr);
    assert_eq!(t.metatype(res[4].ty), Metatype::Ptr);
}

enum Trial<'a> {
    Reg(&'a str, i32),
    Stack(u64, i32),
}

fn derive(model: &str, trials: &[Trial<'_>]) -> (ParamActive, SpaceManager, CompilerSpec) {
    let (spec, m) = funcproto_spec();
    let mut active = ParamActive::new(false);
    for t in trials {
        let (addr, size) = match t {
            Trial::Reg(n, s) => (m.registers().register(n).unwrap().addr(), *s),
            Trial::Stack(off, s) => (stack_addr(&m, *off), *s),
        };
        let i = active.register_trial(&m, addr, size);
        active.trial_mut(i).unwrap().mark_active();
    }
    spec.model_by_name(model)
        .unwrap()
        .derive_input_map(&m, &mut active)
        .unwrap();
    (active, m, spec)
}

fn reg_used(m: &SpaceManager, t: &ParamTrial, name: &str) -> bool {
    let v = m.registers().register(name).unwrap();
    t.is_used() && t.addr == v.addr() && t.size == v.size as i32
}

fn stack_used(m: &SpaceManager, t: &ParamTrial, off: u64, size: i32) -> bool {
    t.is_used() && t.addr == stack_addr(m, off) && t.size == size
}

#[test]
fn funcproto_recoverbasic() {
    let (a, m, _) = derive(
        "__model1",
        &[
            Trial::Reg("r11", 4),
            Trial::Reg("r10", 4),
            Trial::Reg("r12", 4),
        ],
    );
    assert_eq!(a.num_trials(), 3);
    let t = a.trials();
    assert!(reg_used(&m, &t[0], "r12") && reg_used(&m, &t[1], "r11") && reg_used(&m, &t[2], "r10"));
}

#[test]
fn funcproto_recoversmallreg() {
    let (a, m, _) = derive(
        "__model1",
        &[
            Trial::Reg("r11", 4),
            Trial::Reg("r12l", 2),
            Trial::Reg("r10l", 2),
        ],
    );
    assert_eq!(a.num_trials(), 3);
    let t = a.trials();
    assert!(
        reg_used(&m, &t[0], "r12l") && reg_used(&m, &t[1], "r11") && reg_used(&m, &t[2], "r10l")
    );
}

#[test]
fn funcproto_recoverstack() {
    let (a, m, _) = derive(
        "__model2",
        &[
            Trial::Reg("r10", 4),
            Trial::Stack(0, 2),
            Trial::Reg("r8", 4),
            Trial::Stack(4, 4),
            Trial::Reg("r9", 4),
        ],
    );
    assert_eq!(a.num_trials(), 10);
    let t = a.trials();
    for tr in &t[..5] {
        assert!(tr.is_unref() && !tr.is_used());
    }
    assert!(reg_used(&m, &t[5], "r10") && reg_used(&m, &t[6], "r9") && reg_used(&m, &t[7], "r8"));
    assert!(stack_used(&m, &t[8], 0, 2) && stack_used(&m, &t[9], 4, 4));
}

#[test]
fn funcproto_recoverunrefregister() {
    let (a, m, _) = derive("__model1", &[Trial::Reg("r12", 4), Trial::Reg("r10", 4)]);
    assert_eq!(a.num_trials(), 3);
    let t = a.trials();
    assert!(reg_used(&m, &t[0], "r12"));
    assert!(reg_used(&m, &t[1], "r11") && t[1].is_unref());
    assert!(reg_used(&m, &t[2], "r10"));
}

#[test]
fn funcproto_recoverunrefstack() {
    let (a, m, _) = derive(
        "__model2",
        &[
            Trial::Stack(4, 4),
            Trial::Stack(12, 4),
            Trial::Reg("r8", 4),
            Trial::Reg("r9", 4),
            Trial::Reg("r10", 4),
        ],
    );
    assert_eq!(a.num_trials(), 12);
    let t = a.trials();
    for tr in &t[..5] {
        assert!(tr.is_unref() && !tr.is_used());
    }
    assert!(reg_used(&m, &t[5], "r10") && reg_used(&m, &t[6], "r9") && reg_used(&m, &t[7], "r8"));
    assert!(stack_used(&m, &t[8], 0, 4) && t[8].is_unref());
    assert!(stack_used(&m, &t[9], 4, 4));
    assert!(stack_used(&m, &t[10], 8, 4) && t[10].is_unref());
    assert!(stack_used(&m, &t[11], 12, 4));
}

#[test]
fn funcproto_recovergroups() {
    let (a, m, _) = derive(
        "__model3",
        &[
            Trial::Reg("r3", 4),
            Trial::Reg("r5", 4),
            Trial::Reg("r9", 4),
        ],
    );
    assert_eq!(a.num_trials(), 3);
    let t = a.trials();
    assert!(reg_used(&m, &t[0], "r3") && reg_used(&m, &t[1], "r9") && reg_used(&m, &t[2], "r5"));
}

#[test]
fn funcproto_recoverholes() {
    let (a, m, _) = derive(
        "__model1",
        &[
            Trial::Reg("r8", 4),
            Trial::Reg("r12", 4),
            Trial::Stack(0, 4),
        ],
    );
    assert_eq!(a.num_trials(), 6);
    let t = a.trials();
    assert!(reg_used(&m, &t[0], "r12"));
    for tr in &t[1..4] {
        assert!(!tr.is_used() && tr.is_unref());
    }
    assert!(!t[4].is_used() && !t[5].is_used());
}

#[test]
fn funcproto_recoverfloat() {
    let (a, m, _) = derive(
        "__model2",
        &[
            Trial::Reg("r10", 4),
            Trial::Reg("r5", 4),
            Trial::Reg("r3", 4),
        ],
    );
    assert_eq!(a.num_trials(), 6);
    let t = a.trials();
    assert!(t[0].is_unref() && t[1].is_unref() && !t[0].is_used() && !t[1].is_used());
    for (i, r) in [(2, "r3"), (3, "r4"), (4, "r5"), (5, "r10")] {
        assert!(reg_used(&m, &t[i], r), "trial {i}");
    }
}

#[test]
fn funcproto_recovermixedmeta() {
    let (a, m, _) = derive(
        "__model2",
        &[
            Trial::Reg("r10", 4),
            Trial::Reg("r4", 4),
            Trial::Reg("r1", 4),
        ],
    );
    assert_eq!(a.num_trials(), 6);
    let t = a.trials();
    assert!(reg_used(&m, &t[0], "r1"));
    assert!(t[1].is_unref() && !t[1].is_used());
    assert!(reg_used(&m, &t[2], "r3") && reg_used(&m, &t[3], "r4"));
    assert!(t[4].is_unref() && !t[4].is_used());
    assert!(reg_used(&m, &t[5], "r10"));
}
