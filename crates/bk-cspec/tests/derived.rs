//! Tests derived from Ghidra's source (kind S): every decode error path
//! with Ghidra's message, `FuncProto` XML round trips, aliases, merged
//! models and scoring, payload declarations, provenance and summaries.

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

use bk_core::{Provenance, SpaceManager};
use bk_cspec::proto::{EncodeMode, FuncProto, ModelRef, ProtoFlags};
use bk_cspec::summary::{
    AccessKind, CallSite, FunctionSummary, ParamAccesses, PointerAccess, Returns, Sourced, SummaryAddress,
    SummaryStorage, TailCall,
};
use bk_cspec::types::ParamTypes;
use bk_cspec::{CompilerSpec, InjectKind, ParamActive, ReadOptions};
use bk_marshal::{AttributeId, Document, ElementId, IdTable, XmlDecoder, XmlEncoder};
use common::testtypes::{CSizes, TestTypes};
use common::{cparse, funcproto_spec, toy_manager};
use rstest::rstest;

const MODEL: &str = r#"<prototype name="m" extrapop="0" stackshift="4"><input><pentry minsize="1" maxsize="4"><register name="r12"/></pentry><pentry minsize="1" maxsize="500" align="4"><addr offset="0" space="stack"/></pentry></input><output><pentry minsize="1" maxsize="4"><register name="r12"/></pentry></output></prototype>"#;

fn read(body: &str) -> Result<CompilerSpec, String> {
    let mut m = toy_manager();
    let text = format!(r#"<compiler_spec><stackpointer register="sp" space="ram"/>{body}</compiler_spec>"#);
    CompilerSpec::read(&text, &mut m, ReadOptions::default()).map_err(|e| e.message())
}

fn proto(name: &str, input: &str) -> String {
    format!(r#"<prototype name="{name}" extrapop="0"><input>{input}</input><output/></prototype>"#)
}

fn pentry(attrs: &str, reg: &str) -> String {
    format!(r#"<pentry minsize="1" maxsize="4" {attrs}><register name="{reg}"/></pentry>"#)
}

#[rstest]
#[case("<bogus/>", "Unknown element in <compiler_spec>: bogus")]
#[case(&format!("<default_proto>{MODEL}</default_proto><default_proto>{}</default_proto>", MODEL.replace("\"m\"", "\"n\"")), "More than one default prototype model")]
#[case(&format!("{MODEL}{MODEL}"), "Duplicate ProtoModel name: m")]
#[case(r#"<modelalias name="a" parent="zz"/>"#, "Requesting non-existent prototype model: zz")]
#[case(&format!(r#"{MODEL}<modelalias name="a" parent="m"/><modelalias name="b" parent="a"/>"#), "Cannot make alias of an alias: a")]
#[case(&format!(r#"{MODEL}<modelalias name="m" parent="m"/>"#), "Duplicate ProtoModel name: m")]
#[case(&format!(r#"{MODEL}<resolveprototype name="r"><model name="m"/></resolveprototype><modelalias name="a" parent="r"/>"#), "Cannot make alias of merged model: r")]
#[case(r#"<eval_current_prototype name="zz"/>"#, "Unknown prototype model name: zz")]
#[case(&format!(r#"{MODEL}<eval_called_prototype name="m"/><eval_called_prototype name="m"/>"#), "Duplicate <eval_called_prototype> tag")]
#[case(r#"<returnaddress><register name="lr"/></returnaddress><returnaddress><register name="lr"/></returnaddress>"#, "Multiple <returnaddress> tags in .cspec")]
#[case("", "No default prototype specified")]
#[case(r#"<prototype name="p"/>"#, "Missing prototype attributes")]
#[case(r#"<prototype name="p" extrapop="0" bogus="1"/>"#, "Unknown prototype attribute")]
#[case(r#"<prototype name="p" extrapop="0" strategy="odd"/>"#, "Unknown strategy type: odd")]
#[case(r#"<prototype name="p" extrapop="0"><odd/></prototype>"#, "Unknown element in prototype")]
#[case(&proto("p", &pentry("bogus=\"1\"", "r1")), "Unknown <pentry> attribute")]
#[case(&proto("p", r#"<pentry minsize="1"><register name="r1"/></pentry>"#), "ParamEntry not fully specified")]
#[case(&proto("p", &pentry("extension=\"odd\"", "r1")), "Bad extension attribute: odd")]
#[case(&proto("p", &pentry("metatype=\"odd\"", "r1")), "Unknown data-type class: odd")]
#[case(&proto("p", r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r1" piece2="r2"/></pentry>"#), "<pentry> join must overlap at least one previous entry")]
#[case(&proto("p", r#"<pentry minsize="1" maxsize="4"><register name="r1"/></pentry><pentry minsize="1" maxsize="4"><addr space="register" offset="0x1006" size="4"/></pentry>"#), "Illegal overlap of <pentry> in compiler spec")]
#[case(&proto("p", &format!("<group>{}{}</group>", pentry("", "r1"), pentry("", "r2"))), "<pentry> tags within a group must be distinguished by size or type")]
#[case(&proto("p", &format!("<group>{}{}</group>", pentry("", "r1"), pentry("metatype=\"float\"", "r2"))), "<pentry> tags with a specific type must come before the general type")]
#[case(&proto("p", &format!("{}{}", pentry("", "r1"), pentry("metatype=\"float\"", "r2"))), "parameter list entries must be ordered by storage class")]
#[case(&proto("p", &format!(r#"<rule><datatype name="any"/><goto_stack/></rule>{}"#, pentry("", "r1"))), "<pentry> and <group> elements must come before any <modelrule>")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any"/><goto_stack/></rule>"#, pentry("", "r1"))), "Cannot find matching <pentry> for action: goto_stack")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any"/><odd/></rule>"#, pentry("", "r1"))), "Expecting model rule action")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any"/><consume storage="general"/><odd/></rule>"#, pentry("", "r1"))), "Expecting model rule sideeffect")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any" sizes="4,0"/><consume storage="general"/></rule>"#, pentry("", "r1"))), "Bad filter size")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any" sizes="4" minsize="1"/><consume storage="general"/></rule>"#, pentry("", "r1"))), "Mixing \"sizes\" with \"minsize\" and \"maxsize\"")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="odd"/><consume storage="general"/></rule>"#, pentry("", "r1"))), "Unknown metatype: odd")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any"/><join storage="float"/></rule>"#, pentry("", "r1"))), "Could not find matching resources for action: join")]
#[case(&proto("p", &format!(r#"{}<rule><datatype name="any"/><hidden_return strategy="odd"/></rule>"#, pentry("", "r1"))), "Bad <hidden_return> strategy: odd")]
#[case(r#"<prefersplit style="odd"><register name="r1"/></prefersplit>"#, "Unknown prefersplit style: odd")]
#[case(r#"<deadcodedelay space="ram" delay="-1"/>"#, "Bad <deadcodedelay> tag")]
#[case(r#"<resolveprototype name="r"><model name="zz"/></resolveprototype>"#, "Missing prototype model: zz")]
#[case(r#"<callfixup name="f"><target name="g"/></callfixup>"#, "<callfixup> is missing <pcode> subtag: f")]
#[case(r#"<callfixup name="f"><pcode></pcode></callfixup>"#, "Missing <body> subtag in <pcode>:  : compiler spec")]
#[case(r#"<callfixup name="f"><pcode><body>x</body></pcode></callfixup><callfixup name="f"><pcode><body>y</body></pcode></callfixup>"#, "Duplicate <callfixup>: f")]
#[case(&proto("p", &pentry("", "nosuch")), "Unknown register name 'nosuch'")]
fn decode_errors_have_ghidras_messages(#[case] body: &str, #[case] message: &str) {
    let err = read(body).unwrap_err();
    assert_eq!(err, message, "for {body}");
}

#[test]
fn stack_errors() {
    let mut m = toy_manager();
    let err = CompilerSpec::read(r#"<compiler_spec><stackpointer register="sp"/></compiler_spec>"#, &mut m, ReadOptions::default())
        .unwrap_err()
        .message();
    assert_eq!(err, "stackpointer element missing \"space\" attribute");
    let mut m = toy_manager();
    let text = r#"<compiler_spec><stackpointer register="sp" space="ram" reversejustify="true"/><prototype name="p" extrapop="0"><input><pentry minsize="1" maxsize="8" align="4"><addr offset="0" space="stack"/></pentry></input><output/></prototype></compiler_spec>"#;
    let err = CompilerSpec::read(text, &mut m, ReadOptions::default()).unwrap_err().message();
    assert_eq!(err, "No support for right justification in little endian encoding");
    let mut m = toy_manager();
    let text = r#"<compiler_spec><stackpointer register="sp" space="ram" growth="positive"/><prototype name="p" extrapop="0"><input><pentry minsize="1" maxsize="6" align="4"><addr offset="0" space="stack"/></pentry></input><output/></prototype></compiler_spec>"#;
    let err = CompilerSpec::read(text, &mut m, ReadOptions::default()).unwrap_err().message();
    assert_eq!(err, "For positive stack growth, <pentry> size must match alignment");
}

#[test]
fn errors_carry_the_element_path() {
    let mut m = toy_manager();
    let text = format!(r#"<compiler_spec><stackpointer register="sp" space="ram"/>{}</compiler_spec>"#, proto("pp", &pentry("bogus=\"1\"", "r1")));
    let err = CompilerSpec::read(&text, &mut m, ReadOptions::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "compiler_spec/prototype/prototype[pp]/input/pentry[0]: Unknown <pentry> attribute"
    );
}

#[test]
fn defaults_aliases_and_thiscall() {
    let spec = read(&format!("{}{MODEL}", MODEL.replace("\"m\"", "\"zz\""))).unwrap();
    // No <default_proto>: the first model by name, as Ghidra's std::map.
    assert_eq!(spec.default_model_name(), "m");
    let this = spec.model_by_name("__thiscall").unwrap();
    assert!(this.has_this_pointer());
    assert_eq!(this.alias_of(), spec.model_id("m"));
    assert!(this.print_in_decl());
    assert!(!spec.model_by_name("m").unwrap().print_in_decl());
    let (m_id, t_id) = (spec.model_id("m").unwrap(), spec.model_id("__thiscall").unwrap());
    let (m, t) = (spec.model(m_id).unwrap(), spec.model(t_id).unwrap());
    assert!(m.is_compatible(m_id, t, t_id) && t.is_compatible(t_id, m, m_id));
    let z_id = spec.model_id("zz").unwrap();
    assert!(!m.is_compatible(m_id, spec.model(z_id).unwrap(), z_id));
}

#[test]
fn merged_models_score_and_select() {
    let (spec, m) = funcproto_spec();
    let mut text = String::from(r#"<compiler_spec><stackpointer register="sp" space="ram"/></compiler_spec>"#);
    text.clear();
    let _ = text;
    let mut m2 = toy_manager();
    let models = common::FUNCPROTO_MODELS.replace("<specextensions>", "").replace("</specextensions>", "");
    let models = models.lines().filter(|l| !l.starts_with("<!--")).collect::<String>();
    let doc = format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram"/>{models}<resolveprototype name="merged"><model name="__model1"/><model name="__model2"/></resolveprototype></compiler_spec>"#
    );
    let merged_spec = CompilerSpec::read(&doc, &mut m2, ReadOptions::default()).unwrap();
    let merged = merged_spec.model_by_name("merged").unwrap();
    assert!(merged.is_merged());
    assert_eq!(merged.merged_models().unwrap().len(), 2);
    // Inputs are the union: r1 (model2) and r12 (model1) are both possible.
    let r1 = m2.registers().register("r1").unwrap();
    let r12 = m2.registers().register("r12").unwrap();
    assert!(merged.possible_input_param(&m2, r1.addr(), 4));
    assert!(merged.possible_input_param(&m2, r12.addr(), 4));
    // Trials in r10 and r9 fit model2 best; r12 alone fits model1.
    let mut active = ParamActive::new(false);
    for reg in ["r12"] {
        let i = active.register_trial(&m2, m2.registers().register(reg).unwrap().addr(), 4);
        active.trial_mut(i).unwrap().mark_active();
    }
    let ids = merged.merged_models().unwrap();
    let pick = bk_cspec::model::select_model(ids, &|i| merged_spec.model(i), &m2, &active).unwrap();
    assert_eq!(merged_spec.model(pick).unwrap().name(), "__model1");
    let mut active = ParamActive::new(false);
    for reg in ["r10", "r9", "r1"] {
        let i = active.register_trial(&m2, m2.registers().register(reg).unwrap().addr(), 4);
        active.trial_mut(i).unwrap().mark_active();
    }
    let pick = bk_cspec::model::select_model(ids, &|i| merged_spec.model(i), &m2, &active).unwrap();
    assert_eq!(merged_spec.model(pick).unwrap().name(), "__model2");
    // Assignment and recovery need a resolved model.
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4], CSizes::default());
    let p = cparse::proto(&mut types, "merged", "void f(int4 a);");
    let mut res = Vec::new();
    let err = merged.assign_parameter_storage(&m2, &mut types, &p, &mut res, false).unwrap_err();
    assert_eq!(err.message(), "Cannot assign prototype before model has been resolved");
    let err = merged.derive_input_map(&m2, &mut active).unwrap_err();
    assert_eq!(err.message(), "Cannot determine prototype before model has been resolved");
    let _ = (spec, m);
}

fn type_ids() -> IdTable {
    let extra_e = [ElementId::new("type", 60), ElementId::new("typeref", 63)];
    let extra_a: [AttributeId; 0] = [];
    IdTable::new(
        &[bk_marshal::ids::ATTRIBUTES, bk_core::ids::ATTRIBUTES, bk_cspec::ids::ATTRIBUTES, &extra_a],
        &[bk_marshal::ids::ELEMENTS, bk_core::ids::ELEMENTS, bk_cspec::ids::ELEMENTS, &extra_e],
    )
    .unwrap()
}

fn round_trip(spec: &CompilerSpec, m: &SpaceManager, types: &mut TestTypes, fp: &FuncProto, mode: EncodeMode) -> (String, FuncProto) {
    let mut enc = XmlEncoder::new(false);
    fp.encode((spec, m), types, &mut enc, mode).unwrap();
    let text = enc.into_string();
    let doc = Document::parse(&text).unwrap();
    let ids = type_ids();
    let dir = m.directory();
    let mut dec = XmlDecoder::new(&doc, &ids, &*dir);
    let mut back = FuncProto::new();
    let void = types.void();
    back.set_internal(spec, ModelRef::known(spec.default_model()), void);
    back.decode((spec, m), types, &mut dec).unwrap();
    (text, back)
}

#[test]
fn funcproto_xml_round_trips_for_every_signature() {
    let (spec, m) = funcproto_spec();
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4, 4, 4, 4, 4], CSizes::default());
    let sigs = include_str!("oracle/signatures.txt");
    let mut count = 0;
    for model in ["__model1", "__model2", "__model3"] {
        for line in sigs.lines() {
            if line.starts_with('S') {
                cparse::structure(&mut types, &line[2..]);
                continue;
            }
            if !line.starts_with('P') {
                continue;
            }
            let pieces = cparse::proto(&mut types, model, &line[2..]);
            let mut fp = FuncProto::new();
            let void = types.void();
            fp.set_internal(&spec, ModelRef::known(spec.model_id(model).unwrap()), void);
            fp.set_pieces((&spec, &m), &mut types, &pieces).unwrap();
            if fp.flags().contains(ProtoFlags::ERROR_INPUTPARAM) {
                continue;
            }
            let (text, back) = round_trip(&spec, &m, &mut types, &fp, EncodeMode::Ghidra);
            assert!(!text.contains("bk_provenance"), "{text}");
            assert_eq!(back.store(), fp.store(), "{model} {line}\n{text}");
            assert_eq!(back.flags(), fp.flags(), "{model} {line}");
            assert_eq!(back.extrapop(), fp.extrapop());
            count += 1;
        }
    }
    assert!(count > 300, "{count}");
}

#[test]
fn funcproto_xml_has_ghidras_form() {
    let (spec, m) = funcproto_spec();
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4], CSizes::default());
    let pieces = cparse::proto(&mut types, "__model1", "int8 func(int4 a,int4 b);");
    let mut fp = FuncProto::new();
    let void = types.void();
    fp.set_internal(&spec, ModelRef::known(spec.model_id("__model1").unwrap()), void);
    fp.set_pieces((&spec, &m), &mut types, &pieces).unwrap();
    let mut enc = XmlEncoder::new(false);
    fp.encode((&spec, &m), &types, &mut enc, EncodeMode::Ghidra).unwrap();
    let text = enc.into_string();
    assert!(text.starts_with(r#"<prototype model="__model1" extrapop="unknown" modellock="true">"#), "{text}");
    assert!(text.contains(r#"<param name="rethidden" typelock="true" hiddenretparm="true">"#), "{text}");
    assert!(text.contains(r#"<returnsym typelock="true"><addr space="register" offset="0x1030" size="4"/>"#), "{text}");
}

#[test]
fn provenance_survives_basilisk_mode_and_changes_nothing() {
    let (spec, m) = funcproto_spec();
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4], CSizes::default());
    let mut pieces = cparse::proto(&mut types, "__model2", "int4 func(char *a,int4 b,float4 c,int4 *d);");
    let void = types.void();
    let mut plain = FuncProto::new();
    plain.set_internal(&spec, ModelRef::known(spec.default_model()), void);
    plain.set_pieces((&spec, &m), &mut types, &pieces).unwrap();
    pieces.provenance = Provenance::User;
    let mut fp = FuncProto::new();
    fp.set_internal(&spec, ModelRef::known(spec.default_model()), void);
    fp.set_pieces((&spec, &m), &mut types, &pieces).unwrap();
    assert_eq!(fp.provenance, Provenance::User);
    assert_eq!(fp.store(), plain.store());
    let (text, back) = round_trip(&spec, &m, &mut types, &fp, EncodeMode::Basilisk);
    assert!(text.contains(r#"bk_provenance="user""#), "{text}");
    assert_eq!(back.provenance, Provenance::User);
    let (text, back) = round_trip(&spec, &m, &mut types, &fp, EncodeMode::Ghidra);
    assert!(!text.contains("bk_provenance"));
    assert_eq!(back.provenance, Provenance::Default);
}

#[test]
fn locked_prototypes_answer_from_their_parameters() {
    let (spec, m) = funcproto_spec();
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4], CSizes::default());
    let pieces = cparse::proto(&mut types, "__model1", "int4 func(int4 a);");
    let mut fp = FuncProto::new();
    let void = types.void();
    fp.set_internal(&spec, ModelRef::known(spec.model_id("__model1").unwrap()), void);
    let r11 = m.registers().register("r11").unwrap();
    let r12 = m.registers().register("r12").unwrap();
    // Unlocked: the model answers (r11 is a parameter register).
    assert!(fp.possible_input_param((&spec, &m), r11.addr(), 4));
    fp.set_pieces((&spec, &m), &mut types, &pieces).unwrap();
    assert!(fp.is_input_locked() && fp.is_output_locked() && fp.is_model_locked());
    // Locked: only the one parameter, in r12.
    assert!(!fp.possible_input_param((&spec, &m), r11.addr(), 4));
    assert!(fp.possible_input_param((&spec, &m), r12.addr(), 4));
    assert_eq!(fp.print_raw(&spec, &types, "func"), "__model1 int4 func(int4) extrapop=32768");
}

#[test]
fn payload_declarations_keep_their_text() {
    let spec = read(&format!(
        r#"{MODEL}<callfixup name="fix"><target name="___chkstk"/><pcode paramshift="1"><input name="a" size="4"/><output name="o"/><body><![CDATA[ o = a; ]]></body></pcode></callfixup><callotherfixup targetop="op"><pcode incidentalcopy="true"><body>x = 1;</body></pcode></callotherfixup>"#
    ))
    .unwrap();
    let lib = spec.injects();
    let id = lib.payload_id(InjectKind::CallFixup, "fix").unwrap();
    let p = lib.payload(id).unwrap();
    assert_eq!(p.targets, ["___chkstk"]);
    assert_eq!(p.paramshift, 1);
    assert_eq!((p.inputs[0].name.as_str(), p.inputs[0].size, p.outputs[0].index), ("a", 4, 1));
    assert!(p.body.contains("o = a;"));
    assert_eq!(lib.call_fixup_name(id), "fix");
    let other = lib.payload_id(InjectKind::CallOtherFixup, "op").unwrap();
    assert!(lib.payload(other).unwrap().incidental_copy);
    assert_eq!(spec.call_other_fixups(), [other]);
}

#[test]
fn summaries_serialise_and_round_trip() {
    let mut types = TestTypes::new(vec![1, 1, 2, 2, 4], CSizes::default());
    let mut pieces = cparse::proto(&mut types, "__model1", "int4 func(int4 *p);");
    pieces.provenance = Provenance::DebugInfo;
    let at = SummaryAddress { space: 2, offset: 0x1000 };
    let s = FunctionSummary {
        address: at,
        prototype: Sourced::analysis(pieces, 90),
        storage: Sourced::analysis(vec![Some(SummaryStorage { addr: SummaryAddress { space: 3, offset: 0x1030 }, size: 4 }), None], 80),
        returns: Sourced::analysis(Returns::Always, 100),
        tail_call: Sourced::analysis(Some(TailCall { target: None }), 50),
        stack_change: Sourced::analysis(Some(0), 70),
        pointer_accesses: Sourced::analysis(
            vec![ParamAccesses {
                param: 0,
                accesses: vec![PointerAccess { offset: 4, size: 4, stride: 0, kind: AccessKind::Read }],
            }],
            60,
        ),
        callees: Sourced::analysis(vec![SummaryAddress { space: 2, offset: 0x2000 }], 100),
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"debug_info\""), "{json}");
    let back: FunctionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
    let site = CallSite { caller: at, address: SummaryAddress { space: 2, offset: 0x1010 } };
    let back: CallSite = serde_json::from_str(&serde_json::to_string(&site).unwrap()).unwrap();
    assert_eq!(back, site);
    assert_eq!(SummaryAddress::from_address(at.to_address()), Some(at));
}
