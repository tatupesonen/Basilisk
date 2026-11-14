//! Property tests (kind S). Case counts follow `PROPTEST_CASES` (default
//! 256); failures are kept in `properties.proptest-regressions`.
//!
//! - Decoding arbitrary or mutated documents never panics.
//! - For generated standard models and signatures, assigned storage never
//!   overlaps, respects slot alignment and size bounds, and classifying the
//!   assigned storage as trials marks exactly those trials used.
//! - Provenance on the pieces changes no assignment.

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

use bk_core::{Provenance, SpaceManager, SpaceType, VarnodeData};
use bk_cspec::proto::{ParameterPieces, PrototypePieces};
use bk_cspec::types::{ParamTypes, TypeHandle};
use bk_cspec::{CompilerSpec, ParamActive, ProtoModel, ReadOptions};
use common::testtypes::{CSizes, TestTypes};
use common::toy_manager;
use proptest::prelude::*;

const TYPES: [&str; 7] = [
    "int1",
    "int2",
    "int4",
    "int8",
    "float4",
    "float8",
    "xunknown4",
];

/// A standard model with `general` 4-byte registers, `floats` float
/// registers after them, and a stack entry with 4-byte slots.
fn model_text(general: usize, floats: usize, stack_align: u32) -> String {
    let mut s = String::from(r#"<prototype name="g" extrapop="0"><input>"#);
    for i in 0..floats {
        s.push_str(&format!(
            r#"<pentry minsize="1" maxsize="4" metatype="float"><register name="r{}"/></pentry>"#,
            i + 1
        ));
    }
    for i in 0..general {
        s.push_str(&format!(
            r#"<pentry minsize="1" maxsize="4"><register name="r{}"/></pentry>"#,
            12 - i
        ));
    }
    s.push_str(&format!(
        r#"<pentry minsize="1" maxsize="500" align="{stack_align}"><addr offset="0" space="stack"/></pentry></input><output><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></output></prototype>"#
    ));
    s
}

fn build(general: usize, floats: usize, stack_align: u32) -> (CompilerSpec, SpaceManager) {
    let mut m = toy_manager();
    let text = format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram"/>{}</compiler_spec>"#,
        model_text(general, floats, stack_align)
    );
    let spec = CompilerSpec::read(&text, &mut m, ReadOptions::default()).unwrap();
    (spec, m)
}

fn assign(
    model: &ProtoModel,
    m: &SpaceManager,
    types: &mut TestTypes,
    proto: &PrototypePieces,
) -> Vec<ParameterPieces> {
    let mut res = Vec::new();
    model
        .assign_parameter_storage(m, types, proto, &mut res, false)
        .unwrap();
    res
}

/// The physical pieces of a piece's storage.
fn locations(m: &SpaceManager, types: &TestTypes, p: &ParameterPieces) -> Vec<VarnodeData> {
    if m.space_of(p.addr)
        .is_some_and(|s| s.space_type() == SpaceType::Join)
    {
        return m.find_join(p.addr.offset()).unwrap().pieces().to_vec();
    }
    vec![VarnodeData::from_address(p.addr, types.size(p.ty) as u32)]
}

fn signature(types: &TestTypes, picks: &[usize]) -> PrototypePieces {
    let void = types.get("void");
    let ins: Vec<TypeHandle> = picks.iter().map(|&i| types.get(TYPES[i])).collect();
    PrototypePieces::new(void).with_inputs(ins)
}

proptest! {
    #[test]
    fn decoding_arbitrary_text_never_panics(text in ".{0,400}") {
        let mut m = toy_manager();
        let _ = CompilerSpec::read(&text, &mut m, ReadOptions::default());
    }

    #[test]
    fn decoding_mutated_models_never_panics(edits in prop::collection::vec((0usize..4000, any::<u8>()), 1..8)) {
        let mut bytes = format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram"/>{}{}</compiler_spec>"#,
            model_text(3, 2, 4),
            common::FUNCPROTO_MODELS.replace("<specextensions>", "").replace("</specextensions>", "").replace("<!--", "<!-- ").lines().skip(1).collect::<String>(),
        )
        .into_bytes();
        for (pos, b) in edits {
            let n = bytes.len();
            bytes[pos % n] = b;
        }
        if let Ok(text) = String::from_utf8(bytes) {
            let mut m = toy_manager();
            if let Ok(spec) = CompilerSpec::read(&text, &mut m, ReadOptions::default()) {
                // Whatever decoded can be used without panicking.
                let mut types = TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 8], CSizes::default());
                let proto = signature(&types, &[2, 3, 4, 5]);
                for model in spec.models() {
                    let mut res = Vec::new();
                    let _ = model.assign_parameter_storage(&m, &mut types, &proto, &mut res, true);
                    let mut active = ParamActive::new(false);
                    for p in res.iter().skip(1).filter(|p| !p.addr.is_invalid()) {
                        let i = active.register_trial(&m, p.addr, types.size(p.ty));
                        active.trial_mut(i).unwrap().mark_active();
                    }
                    let _ = model.derive_input_map(&m, &mut active);
                }
            }
        }
    }

    #[test]
    fn assigned_storage_is_disjoint_aligned_and_recovered(
        general in 0usize..6,
        floats in 0usize..4,
        stack_align in prop::sample::select(vec![4u32, 8]),
        picks in prop::collection::vec(0usize..TYPES.len(), 0..12),
    ) {
        let (spec, m) = build(general, floats, stack_align);
        let model = spec.model_by_name("g").unwrap();
        let mut types = TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 8], CSizes::default());
        let proto = signature(&types, &picks);
        let res = assign(model, &m, &mut types, &proto);
        prop_assert_eq!(res.len(), picks.len() + 1);
        let stack = m.stack_space().unwrap().id();
        let mut seen: Vec<VarnodeData> = Vec::new();
        for p in &res[1..] {
            let size = types.size(p.ty);
            for loc in locations(&m, &types, p) {
                prop_assert!(loc.size > 0 && loc.size as i32 <= size.max(4));
                if loc.space() == Some(stack) {
                    prop_assert_eq!(loc.offset % u64::from(stack_align), 0, "stack slot alignment");
                } else {
                    prop_assert!(loc.size <= 4, "register entries hold at most 4 bytes");
                }
                for s in &seen {
                    let disjoint = s.space() != loc.space()
                        || s.offset + u64::from(s.size) <= loc.offset
                        || loc.offset + u64::from(loc.size) <= s.offset;
                    prop_assert!(disjoint, "{s:?} overlaps {loc:?}");
                }
                seen.push(loc);
            }
        }
        // Classify the assigned storage: every assigned trial is used, and
        // the only other trials used are the unreferenced ones Ghidra
        // creates for holes. Only for signatures of values up to 4 bytes:
        // a larger value skips registers, and Ghidra's recovery ends the
        // parameters after a chain of more than two unused slots
        // (`forceInactiveChain`), by design.
        let small = picks.iter().all(|&i| types.size(types.get(TYPES[i])) <= 4);
        if !small {
            return Ok(());
        }
        let mut active = ParamActive::new(false);
        for p in &res[1..] {
            let i = active.register_trial(&m, p.addr, types.size(p.ty));
            active.trial_mut(i).unwrap().mark_active();
        }
        model.derive_input_map(&m, &mut active).unwrap();
        for p in &res[1..] {
            let size = types.size(p.ty);
            let t = active.trials().iter().find(|t| t.addr == p.addr && t.size == size).unwrap();
            prop_assert!(t.is_used(), "assigned {:?} not used", p.addr);
        }
        for t in active.trials().iter().filter(|t| t.is_used()) {
            let assigned = res[1..].iter().any(|p| p.addr == t.addr && types.size(p.ty) == t.size);
            prop_assert!(assigned || t.is_unref(), "{:?} used but neither assigned nor a hole", t.addr);
        }
    }

    #[test]
    fn provenance_changes_no_assignment(
        picks in prop::collection::vec(0usize..TYPES.len(), 0..10),
        prov in prop::sample::select(vec![Provenance::User, Provenance::DebugInfo, Provenance::Imported, Provenance::Model]),
    ) {
        let (spec, m) = build(4, 2, 4);
        let model = spec.model_by_name("g").unwrap();
        let mut types = TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 8], CSizes::default());
        let plain = signature(&types, &picks);
        let mut marked = plain.clone();
        marked.provenance = prov;
        prop_assert_eq!(assign(model, &m, &mut types, &plain), assign(model, &m, &mut types, &marked));
    }
}
