//! Tests of p-code generation derived from the source
//! (`features/sleigh-pcode.md` 6.3), on the `bkpc` fixture language and on
//! free-standing templates. The oracle-checked behaviour of the same
//! language is in `pcode_fixture.rs`.
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

mod fixture;

use std::sync::Arc;

use bk_core::{Address, SpaceId, VarnodeData};
use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleSelect, Template, VarnodeTpl};
use bk_sleigh::{
    Decoder, InjectContext, Language, LiftError, PcodeCollector, PcodeCounter, SliceBytes,
};
use rstest::rstest;

fn language() -> Arc<Language> {
    Arc::new(Language::from_sla(Arc::new(fixture::pcode::build_sla())).unwrap())
}

fn bytes(text: &str) -> Vec<u8> {
    let d: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| (c as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

fn ram(lang: &Language, offset: u64) -> Address {
    Address::new(lang.default_space(), offset)
}

/// Lifts the instruction at `at` of `hex` placed at `base`, after lifting
/// every instruction before it (so crossbuild targets were seen): the `P`
/// records, or the error.
fn lift(base: u64, hex: &str, at: u64) -> Result<(u32, String), LiftError> {
    let lang = language();
    let data = bytes(hex);
    let src = SliceBytes::new(base, &data);
    let mut db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let mut out = String::new();
    let mut records = bk_sleigh::PcodeRecords::new(&lang, &mut out);
    let flow = decoder.lift(ram(&lang, at), &src, &mut db, &mut records)?;
    Ok((flow, out))
}

fn ops_of(text: &str) -> Vec<&str> {
    text.lines()
        .map(|l| l.split('\t').nth(1).unwrap())
        .collect()
}

#[test]
fn dynamic_input_and_output() {
    let (_, ld) = lift(0x1000, "0221", 0x1000).unwrap();
    assert_eq!(ops_of(&ld), ["LOAD", "COPY"]);
    assert!(ld.contains("P\tLOAD\t(unique,0x80,4)\t(const,0x3,8,ram)\t(register,0x4,4,r1)"));
    let (_, st) = lift(0x1000, "0321", 0x1000).unwrap();
    assert_eq!(ops_of(&st), ["COPY", "STORE"]);
    let (_, both) = lift(0x1000, "1021", 0x1000).unwrap();
    assert_eq!(ops_of(&both), ["LOAD", "INT_ADD", "STORE"]);
}

#[test]
fn truncated_dynamic_operands_go_through_the_ea_temporary() {
    let (_, ldb) = lift(0x1000, "0421", 0x1000).unwrap();
    assert_eq!(ops_of(&ldb), ["INT_ADD", "LOAD", "INT_ZEXT"]);
    // ea = uniqbase + 0x100, without the uniqmask bits.
    assert!(ldb.contains("P\tINT_ADD\t(unique,0x1100,4)\t(register,0x4,4,r1)\t(const,0x3,4)"));
    assert!(ldb.contains("P\tLOAD\t(unique,0x83,1)\t(const,0x3,8,ram)\t(unique,0x1100,4)"));
    let (_, stb) = lift(0x1000, "0521", 0x1000).unwrap();
    assert_eq!(ops_of(&stb), ["COPY", "INT_ADD", "STORE"]);
}

#[test]
fn constant_pointer_is_static() {
    let (_, text) = lift(0x1000, "1185", 0x1000).unwrap();
    assert_eq!(text, "P\tCOPY\t(register,0x0,4,r0)\t(ram,0xffffff85,4)\n");
}

#[test]
fn constants_masks_and_offset_plus() {
    let (flow, text) = lift(0x2060, "0d12abcd", 0x2060).unwrap();
    assert_eq!(flow, 4);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].ends_with("(const,0x2060,4)"), "{text}");
    assert!(lines[1].ends_with("(const,0x2064,4)"));
    assert!(lines[2].ends_with("(const,0x4,4)"));
    assert!(lines[3].ends_with("(const,0x34,1)"), "masked to size");
    assert!(lines[4].ends_with("(const,0xab,1)"), "constant shifted");
    assert!(
        lines[6].ends_with("(register,0x6,2)"),
        "register offset plus 2"
    );
}

#[test]
fn unique_offsets_carry_the_mask_bits() {
    // uniqmask 6: address 0x1006 contributes (6 & 6) << 8.
    let (_, text) = lift(0x1006, "1410", 0x1006).unwrap();
    assert!(text.contains("(unique,0x660,4)"), "{text}");
    let (_, plain) = lift(0x1000, "1410", 0x1000).unwrap();
    assert!(plain.contains("(unique,0x60,4)"), "{plain}");
}

#[test]
fn labels_forward_and_backward_and_nested() {
    let (_, text) = lift(0x1000, "0612", 0x1000).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // LABEL 1 at op 0, LABEL 0 at op 2.
    assert!(
        lines[0].starts_with("P\tCBRANCH\t-\t(const,0x2,4)"),
        "{text}"
    );
    assert!(
        lines[2].starts_with("P\tCBRANCH\t-\t(const,0xfffe,2)"),
        "{text}"
    );
    assert!(lines[3].starts_with("P\tBRANCH\t-\t(const,0xffffffffffffffff,8)"));
    // nest: label bases per template level.
    let (_, nested) = lift(0x1000, "0f21", 0x1000).unwrap();
    assert_eq!(
        ops_of(&nested),
        ["CBRANCH", "INT_NEGATE", "CBRANCH", "BRANCH"]
    );
    let lines: Vec<&str> = nested.lines().collect();
    assert!(
        lines[0].starts_with("P\tCBRANCH\t-\t(const,0x3,1)"),
        "{nested}"
    );
    assert!(
        lines[2].starts_with("P\tCBRANCH\t-\t(const,0xffff,2)"),
        "{nested}"
    );
    assert!(
        lines[3].starts_with("P\tBRANCH\t-\t(const,0xfd,1)"),
        "{nested}"
    );
}

#[test]
fn delay_slots_of_one_and_two_instructions() {
    let (flow, text) = lift(0x1000, "0802 0112", 0x1000).unwrap();
    assert_eq!(flow, 4);
    assert_eq!(ops_of(&text), ["INT_ADD", "BRANCH"]);
    let (flow, text) = lift(0x1000, "0904 0123 0130", 0x1000).unwrap();
    assert_eq!(flow, 6);
    assert_eq!(ops_of(&text), ["INT_ADD", "INT_ADD", "BRANCH"]);
}

#[test]
fn delay_slot_that_does_not_decode() {
    let err = lift(0x1000, "0802 ff00", 0x1000).unwrap_err();
    assert!(matches!(err, LiftError::DelaySlot { .. }), "{err:?}");
    assert_eq!(
        err.to_string(),
        "r0x00001002: Unable to resolve constructor"
    );
}

#[test]
fn delay_slot_of_a_delay_slot_not_decoded() {
    let err = lift(0x1000, "0802 0802 0100", 0x1000).unwrap_err();
    assert!(matches!(err, LiftError::DelaySlotMissing { .. }), "{err:?}");
}

#[rstest]
#[case::root("0e00", 0x1000, " 0x00001000: halt  ", 2)]
#[case::in_delay_slot("0802 0e00", 0x1000, " 0x00001002: halt  ", 4)]
fn unimplemented_names_the_innermost_instruction(
    #[case] hex: &str,
    #[case] at: u64,
    #[case] text: &str,
    #[case] flow: u32,
) {
    let err = lift(0x1000, hex, at).unwrap_err();
    assert_eq!(err.flow_length(), Some(flow));
    assert_eq!(
        err.to_string(),
        format!("Instruction not implemented in pcode:\n{text}")
    );
}

#[test]
fn crossbuild_present_absent_and_in_section() {
    let lang = language();
    let data = bytes("0112 0a00 0231 0a00 0b00 1300");
    let src = SliceBytes::new(0x2000, &data);
    let mut db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let mut out = String::new();
    for at in [0x2000u64, 0x2002, 0x2004, 0x2006, 0x2008] {
        let mut records = bk_sleigh::PcodeRecords::new(&lang, &mut out);
        decoder
            .lift(ram(&lang, at), &src, &mut db, &mut records)
            .unwrap();
    }
    // The previous add's section 0 with its own unique bits (0x2000 & 6 = 0).
    assert!(
        out.contains("P\tCOPY\t(unique,0x10,4)\t(register,0x4,4,r1)"),
        "{out}"
    );
    // ld has no section 0: implied build into mem's (unique bits of 0x2004).
    assert!(
        out.contains("P\tCOPY\t(unique,0x450,4)\t(const,0x55,4)"),
        "{out}"
    );
    // xs: its own section 0 with inst_next of the current instruction.
    assert!(
        out.contains("P\tCOPY\t(unique,0x40,4)\t(const,0x200a,4)"),
        "{out}"
    );
    let mut counter = PcodeCounter::default();
    let err = decoder
        .lift(ram(&lang, 0x200a), &src, &mut db, &mut counter)
        .unwrap_err();
    assert!(
        matches!(err, LiftError::CrossBuildInSection { .. }),
        "{err:?}"
    );
    // A crossbuild whose target does not decode.
    let err = lift(0x2001, "ff 0a00", 0x2002).unwrap_err();
    assert!(matches!(err, LiftError::CrossBuildTarget { .. }), "{err:?}");
    assert_eq!(
        err.to_string(),
        "Could not obtain cached crossbuild instruction"
    );
    assert_eq!(counter.ops, 0, "nothing is emitted on error");
}

#[test]
fn missing_label_and_alignment() {
    let err = lift(0x1000, "1200", 0x1000).unwrap_err();
    assert_eq!(err.to_string(), "Reference to non-existant sleigh label");
    let err = lift(0x1001, "0112", 0x1001).unwrap_err();
    assert!(matches!(err, LiftError::Unaligned { .. }));
    assert_eq!(err.flow_length(), None);
    assert_eq!(
        err.to_string(),
        "Instruction address not aligned: 0x00001001"
    );
}

#[test]
fn user_op_index_is_a_constant() {
    let (_, text) = lift(0x1000, "0720", 0x1000).unwrap();
    assert_eq!(
        text,
        "P\tCALLOTHER\t(unique,0x14,4)\t(const,0x0,4)\t(register,0x8,4,r2)\n"
    );
}

#[test]
fn every_opcode_reaches_the_emitter_and_no_directive_does() {
    let lang = language();
    let data = bytes("0c12");
    let mut db = lang.initial_context();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let mut ops = PcodeCollector::new();
    decoder
        .lift(ram(&lang, 0), &SliceBytes::new(0, &data), &mut db, &mut ops)
        .unwrap();
    assert_eq!(ops.ops().len(), OpCode::ALL.len() - 4);
    for op in ops.ops() {
        assert!(!matches!(
            op.opcode,
            OpCode::MultiEqual | OpCode::Indirect | OpCode::PtrAdd | OpCode::PtrSub
        ));
    }
    let load = ops.ops().iter().find(|o| o.opcode == OpCode::Load).unwrap();
    let space = ops.inputs(load)[0];
    assert_eq!(space.space_from_const(), Some(SpaceId::new(3)));
    assert_eq!(space.size, 8);
}

// ---------------------------------------------------------------- templates

fn c(v: u64, size: u64) -> VarnodeTpl {
    VarnodeTpl {
        space: ConstTpl::Space(0),
        offset: ConstTpl::Real(v),
        size: ConstTpl::Real(size),
    }
}

fn param(i: u32) -> VarnodeTpl {
    VarnodeTpl {
        space: ConstTpl::Handle {
            index: i,
            select: HandleSelect::Space,
            plus: 0,
        },
        offset: ConstTpl::Handle {
            index: i,
            select: HandleSelect::Offset,
            plus: 0,
        },
        size: ConstTpl::Handle {
            index: i,
            select: HandleSelect::Size,
            plus: 0,
        },
    }
}

fn inject(t: &Template) -> Result<PcodeCollector, LiftError> {
    let lang = language();
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let reg = SpaceId::new(4);
    let ctx = InjectContext {
        inst_start: ram(&lang, 0x4000),
        inst_next: ram(&lang, 0x4004),
        call_addr: Some(ram(&lang, 0x8000)),
        params: vec![
            (0, VarnodeData::new(reg, 4, 4)),
            (1, VarnodeData::new(reg, 8, 4)),
        ],
    };
    let mut out = PcodeCollector::new();
    decoder.build_template(t.as_ref(), &ctx, &mut out)?;
    Ok(out)
}

#[test]
fn free_standing_template_with_parameters_and_flow_constants() {
    let mut t = Template::new();
    t.push_op(OpCode::IntAdd, Some(param(1)), &[param(0), c(1, 4)]);
    t.push_op(
        OpCode::Copy,
        Some(param(0)),
        &[VarnodeTpl {
            space: ConstTpl::Space(0),
            offset: ConstTpl::FlowDest,
            size: ConstTpl::FlowDestSize,
        }],
    );
    let out = inject(&t).unwrap();
    let ops = out.ops();
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].addr.offset(), 0x4000);
    assert_eq!(ops[0].output, Some(VarnodeData::new(SpaceId::new(4), 8, 4)));
    assert_eq!(
        out.inputs(&ops[1])[0],
        VarnodeData::new(SpaceId::new(0), 0x8000, 4)
    );
}

#[rstest]
fn relative_branch_constant_sizes(#[values(1, 2, 3, 4, 5, 6, 7, 8)] size: u64) {
    // LABEL 0; COPY; BRANCH rel(0): displacement -1 masked to the size.
    let mut t = Template::new();
    t.set_header(None, 0, 1);
    t.push_op(OpCode::PtrAdd, None, &[c(0, 4)]);
    t.push_op(OpCode::Copy, Some(param(0)), &[param(1)]);
    t.push_op(
        OpCode::Branch,
        None,
        &[VarnodeTpl {
            space: ConstTpl::Space(0),
            offset: ConstTpl::Relative(0),
            size: ConstTpl::Real(size),
        }],
    );
    let out = inject(&t).unwrap();
    let branch = &out.ops()[1];
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1 << (8 * size)) - 1
    };
    assert_eq!(out.inputs(branch)[0].offset, mask);
}

#[test]
fn directives_that_need_an_instruction_are_errors_in_templates() {
    let mut t = Template::new();
    t.push_op(OpCode::Indirect, None, &[c(2, 4)]);
    assert!(matches!(
        inject(&t),
        Err(LiftError::DirectiveInTemplate {
            directive: "DELAY_SLOT",
            ..
        })
    ));
    let mut t = Template::new();
    t.push_op(OpCode::PtrSub, None, &[c(0x10, 4), c(0, 4)]);
    assert!(matches!(
        inject(&t),
        Err(LiftError::DirectiveInTemplate {
            directive: "CROSSBUILD",
            ..
        })
    ));
    let mut t = Template::new();
    t.set_header(None, 0, 1);
    t.push_op(
        OpCode::Branch,
        None,
        &[VarnodeTpl {
            space: ConstTpl::Space(0),
            offset: ConstTpl::Relative(0),
            size: ConstTpl::Real(4),
        }],
    );
    assert!(matches!(inject(&t), Err(LiftError::MissingLabel { .. })));
}

/// A branch to a label that is never placed, with any label count — as
/// Ghidra's snippet compiler produces for `goto <L>;`, which `bk_sla` now
/// reads — fails where Ghidra's `resolveRelatives` does, with its message,
/// and never allocates per label number or loops.
#[rstest]
fn unplaced_labels_fail_with_ghidras_message(
    #[values(0, 1)] count: i32,
    #[values(0, 1, 7, 1 << 40, u64::MAX)] label: u64,
    #[values(None, Some(3), Some(u64::MAX))] placed: Option<u64>,
) {
    if placed == Some(label) {
        return;
    }
    let mut t = Template::new();
    t.set_header(None, 0, count);
    if let Some(placed) = placed {
        t.push_op(OpCode::PtrAdd, None, &[c(placed, 4)]);
    }
    t.push_op(
        OpCode::Branch,
        None,
        &[VarnodeTpl {
            space: ConstTpl::Space(0),
            offset: ConstTpl::Relative(label),
            size: ConstTpl::Real(4),
        }],
    );
    assert!(t.check_labels().is_err());
    let err = inject(&t).unwrap_err();
    assert!(matches!(err, LiftError::MissingLabel { .. }), "{err:?}");
    assert_eq!(err.to_string(), "Reference to non-existant sleigh label");
}

#[test]
fn one_op_with_too_many_varnodes() {
    let mut t = Template::new();
    let inputs = vec![c(0, 4); 4097];
    t.push_op(OpCode::CallOther, None, &inputs);
    let err = inject(&t).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Maximum parameters exceeded for a single p-code op"
    );
}

/// The reproducers of `docs/research/pcodedump-crashes.md`: an `unimpl`
/// delay slot crashes Ghidra's engine; basilisk returns the error.
#[test]
fn pcodedump_crash_reproducers_lift_without_a_crash() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Pcodedump) else {
        return;
    };
    let mut builder = bk_lang::LanguageRegistry::builder().include_hidden(true);
    let mut dirs: Vec<_> = std::fs::read_dir(reference.root().join("Ghidra").join("Processors"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    dirs.sort();
    for d in dirs {
        builder = builder.module(d);
    }
    let registry = builder.build().unwrap();
    for (id, hex, flow, named) in [
        ("sparc:BE:32:default", "1080000081b80000", 8, "0x00000004"),
        ("MIPS:LE:32:default", "080000106ecac546", 8, "0x00000004"),
    ] {
        let lang =
            Arc::new(Language::load(&registry, &bk_lang::LanguageId::new(id).unwrap()).unwrap());
        let data = bytes(hex);
        let mut db = lang.initial_context();
        let mut decoder = Decoder::new(Arc::clone(&lang));
        let err = decoder
            .lift(
                ram(&lang, 0),
                &SliceBytes::new(0, &data),
                &mut db,
                &mut PcodeCounter::default(),
            )
            .unwrap_err();
        assert_eq!(err.flow_length(), Some(flow), "{id}");
        let text = err.to_string();
        assert!(
            text.starts_with(&format!(
                "Instruction not implemented in pcode:\n {named}: "
            )),
            "{id}: {text}"
        );
    }
}

/// The ARM v8-m instructions that crash `pcodedump` (recorded by the
/// differential harness): their templates read the handle of a subtable
/// operand that exports nothing. basilisk reads the constant 0 and reports
/// it; Ghidra reads an uninitialised `FixedHandle` (a null space in a fresh
/// parse slot, hence the crash; stale data in a reused one).
#[test]
fn arm_v8m_oracle_crashes_read_unset_handles() {
    #[derive(Default)]
    struct Unset(bool);
    impl bk_sleigh::BuildObserver for Unset {
        fn feature(&mut self, f: bk_sleigh::BuildFeature) {
            self.0 |= f == bk_sleigh::BuildFeature::UnsetHandle;
        }
    }
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Pcodedump) else {
        return;
    };
    let registry = bk_lang::LanguageRegistry::builder()
        .include_hidden(true)
        .module(reference.root().join("Ghidra/Processors/ARM"))
        .build()
        .unwrap();
    for (id, hex) in [
        ("ARM:LE:32:v8-m", "79ee01df"),
        ("ARM:LE:32:v8-m", "35fe0c2f"),
        ("ARM:LE:32:v8-m", "71fe4def"),
        ("ARM:LE:32:v8-m", "45fe095f"),
        ("ARM:LE:32:v8-m", "73fe457f"),
        ("ARM:BE:32:v8-m", "fe4baf03"),
    ] {
        let lang =
            Arc::new(Language::load(&registry, &bk_lang::LanguageId::new(id).unwrap()).unwrap());
        let mut db = lang.initial_context();
        assert!(lang.set_context_everywhere(&mut db, "itmode", 1));
        assert!(lang.set_context_everywhere(&mut db, "cond_mask", 8));
        let data = bytes(hex);
        let mut decoder = Decoder::new(Arc::clone(&lang));
        let mut unset = Unset::default();
        decoder
            .lift_observed(
                ram(&lang, 0),
                &SliceBytes::new(0, &data),
                &mut db,
                &mut PcodeCounter::default(),
                &mut unset,
            )
            .unwrap();
        assert!(unset.0, "{id} {hex}");
    }
}

#[test]
fn translator_offers_the_translate_interface() {
    use bk_sleigh::{Translate, Translator, UniqueLayout};
    let lang = language();
    let data = bytes("0112 0720");
    let mut t = Translator::new(Arc::clone(&lang), SliceBytes::new(0, &data));
    let mut ops = PcodeCollector::new();
    assert_eq!(t.one_instruction(ram(&lang, 0), &mut ops).unwrap(), 2);
    assert_eq!(ops.ops()[0].opcode, OpCode::IntAdd);
    assert_eq!(t.instruction_length(ram(&lang, 2)).unwrap(), 2);
    let r1 = t.register("r1").unwrap();
    assert_eq!(r1, VarnodeData::new(SpaceId::new(4), 4, 4));
    assert_eq!(t.register_name(SpaceId::new(4), 5, 1), Some("r1"));
    assert_eq!(t.exact_register_name(SpaceId::new(4), 4, 4), Some("r1"));
    assert_eq!(t.exact_register_name(SpaceId::new(4), 5, 1), None);
    assert_eq!(t.all_registers().len(), 4);
    assert_eq!(t.user_op_names(), [Some("syscall".to_owned())]);
    assert_eq!(t.unique_base(), 0x1000);
    assert_eq!(t.unique_start(UniqueLayout::RuntimeBitrangeEa), 0x1100);
    assert_eq!(t.unique_start(UniqueLayout::Inject), 0x1200);
    assert_eq!(t.unique_start(UniqueLayout::Analysis), 0x1000_0000);
    assert_eq!(t.alignment(), 2);
    assert!(t.is_big_endian());
    assert_eq!(t.float_format(8).map(bk_pcode::FloatFormat::size), Some(8));
    assert!(t.spaces().space_by_name("ram").is_some());
    assert!(!t.set_context_default("nosuch", 1));
}

#[test]
fn translator_can_refuse_context_commits() {
    use bk_sleigh::{Translate, Translator};
    // bkfix: `setmode` (0x60) commits mode = 1 to the next address, where
    // 0x70 then decodes as `m1op` instead of `clrmode`.
    let lang = Arc::new(Language::from_sla(Arc::new(fixture::build())).unwrap());
    let data = bytes("6000 7000");
    for (allow, expected) in [(true, "m1op"), (false, "clrmode")] {
        let mut t = Translator::new(Arc::clone(&lang), SliceBytes::new(0, &data));
        t.allow_context_set(allow);
        t.one_instruction(ram(&lang, 0), &mut PcodeCounter::default())
            .unwrap();
        let (mut m, mut b) = (String::new(), String::new());
        t.print_assembly(ram(&lang, 2), &mut m, &mut b).unwrap();
        assert_eq!(m, expected);
    }
    let mut t = Translator::new(Arc::clone(&lang), SliceBytes::new(0, &data));
    assert!(t.set_context_default("mode", 1));
    let (mut m, mut b) = (String::new(), String::new());
    t.print_assembly(ram(&lang, 2), &mut m, &mut b).unwrap();
    assert_eq!(m, "m1op");
}
