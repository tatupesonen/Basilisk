//! The second version of the `testfuncproto.cc` port (kind G): the real
//! `toy.cspec` with the test's three models as a `<specextensions>`
//! document, against Toy:LE:32's spaces and registers as Ghidra had them
//! (from the oracle table, until a `.sla`-backed register source exists).
//! Every assignment and recovery case of the self-contained port is run
//! again here and must give the same answers.

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
mod oracle_common;

use bk_core::SpaceManager;
use bk_cspec::types::ParamTypes;
use bk_cspec::{CompilerSpec, ParamActive, ReadOptions};
use common::testtypes::{CSizes, TestTypes};
use common::{FUNCPROTO_MODELS, cparse, funcproto_spec};

fn real() -> Option<(CompilerSpec, SpaceManager)> {
    let ghidra = bk_testkit::require_ghidra()?;
    let table = oracle_common::table();
    let (pairs, _) = oracle_common::pairs(&table);
    let pair = pairs
        .iter()
        .find(|p| p.id == "Toy:LE:32:default:default")
        .unwrap();
    let files = oracle_common::cspec_files(&ghidra.processors_dir());
    let text = std::fs::read_to_string(&files[&pair.cspec]).unwrap();
    let mut m = oracle_common::manager(pair);
    let opts = ReadOptions {
        extensions: Some(FUNCPROTO_MODELS.to_owned()),
        ..ReadOptions::default()
    };
    let spec = CompilerSpec::read(&text, &mut m, opts).unwrap();
    Some((spec, m))
}

/// Storage of a signature as register names or stack offsets.
fn describe(spec: &CompilerSpec, m: &SpaceManager, model: &str, sig: &str) -> Vec<String> {
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 4], CSizes::default());
    let proto = cparse::proto(&mut types, model, sig);
    let mut res = Vec::new();
    spec.model_by_name(model)
        .unwrap()
        .assign_parameter_storage(m, &mut types, &proto, &mut res, false)
        .unwrap();
    res.iter()
        .map(|p| {
            let size = types.size(p.ty);
            let name = p
                .addr
                .space()
                .and_then(|s| m.registers().exact_register_name(s, p.addr.offset(), 4))
                .map(str::to_owned);
            let kind = p
                .addr
                .space()
                .and_then(|s| m.space(s))
                .map_or("none", |s| s.name());
            format!(
                "{}:{}:{size}:{}",
                kind,
                name.unwrap_or_else(|| format!("{:x}", p.addr.offset())),
                p.flags.bits()
            )
        })
        .collect()
}

fn recover(
    spec: &CompilerSpec,
    m: &SpaceManager,
    model: &str,
    regs: &[(&str, i32)],
) -> Vec<String> {
    let mut active = ParamActive::new(false);
    for (r, size) in regs {
        let a = m.registers().register(r).unwrap().addr();
        let i = active.register_trial(m, a, *size);
        active.trial_mut(i).unwrap().mark_active();
    }
    spec.model_by_name(model)
        .unwrap()
        .derive_input_map(m, &mut active)
        .unwrap();
    active
        .trials()
        .iter()
        .map(|t| {
            format!(
                "{:x}:{}:{}:{}",
                t.addr.offset(),
                t.size,
                t.is_used(),
                t.is_unref()
            )
        })
        .collect()
}

#[test]
fn real_toy_cspec_answers_as_the_built_architecture() {
    let Some((spec, m)) = real() else { return };
    let (spec_s, m_s) = funcproto_spec();
    for (model, sig) in [
        ("__model1", "void func(int4 a,int4 b);"),
        ("__model1", "int4 func(char a,int4 b,int2 c,int4 d);"),
        (
            "__model1",
            "int4 func(int4 a,int4 b,int4 c,int4 d,int4 e,int2 f,int1 *g);",
        ),
        ("__model1", "int2 func(int4 a,int8 b,int4 c);"),
        ("__model2", "char func(int4 a,int8 b,int4 c);"),
        (
            "__model2",
            "void func(int4 a,float4 b,float4 c,int4 d,float4 d);",
        ),
        (
            "__model2",
            "float4 func(int4 a,float4 b,float4 c,float4 d,float4 e,float4 f);",
        ),
        (
            "__model3",
            "float4 func(int4 a,float4 b,float4 c,int4 d,float4 e);",
        ),
        ("__model2", "int4 func(int4 a,int8 b,int4 c);"),
        ("__model1", "int8 func(int4 a,int4 b);"),
        ("__model2", "int4 func(char *a,int4 b,float4 c,int4 *d);"),
    ] {
        assert_eq!(
            describe(&spec, &m, model, sig),
            describe(&spec_s, &m_s, model, sig),
            "{model} {sig}"
        );
    }
    for (model, regs) in [
        ("__model1", vec![("r11", 4), ("r10", 4), ("r12", 4)]),
        ("__model1", vec![("r11", 4), ("r12l", 2), ("r10l", 2)]),
        ("__model1", vec![("r12", 4), ("r10", 4)]),
        ("__model3", vec![("r3", 4), ("r5", 4), ("r9", 4)]),
        ("__model2", vec![("r10", 4), ("r5", 4), ("r3", 4)]),
        ("__model2", vec![("r10", 4), ("r4", 4), ("r1", 4)]),
    ] {
        assert_eq!(
            recover(&spec, &m, model, &regs),
            recover(&spec_s, &m_s, model, &regs),
            "{model} {regs:?}"
        );
    }
}
