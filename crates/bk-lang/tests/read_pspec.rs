//! The `.pspec` reader on hand-written documents: every element form,
//! what Ghidra rejects, strict errors and lenient fallbacks.

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

use bk_lang::{
    Mode, ParseErrorKind,
    pspec::{
        self, AddressRange, ContextKind, JumpAssistPcode, MemoryBlockKind, MemoryTag, Section,
        SymbolAddress, SymbolType, VarnodeTag, property_keys,
    },
};
use common::documents::PSPEC;
use rstest::rstest;

#[test]
fn pspec_reads_every_element_form() {
    use Section::{
        ContextData, DataSpace, DefaultMemoryBlocks, DefaultSymbols, IncidentalCopy,
        InferPtrBounds, JumpAssist, ProgramCounter, Properties, RegisterData, SegmentOp,
        SegmentedAddress, Volatile,
    };
    let parsed = pspec::parse(PSPEC, Mode::Strict).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.warnings, []);
    let spec = parsed.value;

    // properties: one entry per key, the last value in the first position.
    let keys: Vec<&str> = spec.properties.iter().map(|p| p.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "useNewFunctionStackAnalysis",
            "maximumInstructionLength",
            "custom"
        ]
    );
    assert_eq!(spec.property("custom"), Some("second"));
    assert!(spec.property_as_bool(property_keys::USE_NEW_FUNCTION_STACK_ANALYSIS, false));
    assert!(
        !spec.property_as_bool("custom", true),
        "only \"true\" is true"
    );
    assert!(spec.property_as_bool("absent", true));
    assert_eq!(
        spec.property_as_int(property_keys::MAXIMUM_INSTRUCTION_LENGTH, -1),
        Ok(15)
    );
    assert_eq!(spec.property_as_int("absent", -1), Ok(-1));
    assert!(spec.property_as_int("custom", 0).is_err());
    assert!(spec.has_property("custom") && !spec.has_property("absent"));

    assert_eq!(spec.program_counter.as_deref(), Some("PC"));
    let data_space = spec.data_space.as_ref().unwrap();
    assert_eq!(
        (data_space.space.as_str(), data_space.ptr_wordsize),
        ("data", Some(2))
    );

    let range = |space: &str, first, last| AddressRange {
        space: space.into(),
        first,
        last,
    };
    assert_eq!(
        spec.infer_ptr_bounds,
        [
            range("ram", Some(0x1000), Some(0x1fff)),
            range("rom", None, None),
            range("io", Some(0), Some(8)),
        ],
        "offsets decode 0x as hexadecimal and a leading 0 as octal"
    );

    let segmented = spec.segmented_address.as_ref().unwrap();
    assert_eq!(
        (segmented.space.as_str(), segmented.segment_type.as_deref()),
        ("ram", Some("real"))
    );

    let [far, plain] = spec.segment_ops.as_slice() else {
        panic!("two segmentops")
    };
    assert_eq!(far.space, "ram");
    assert_eq!(far.userop_name(), "segment");
    assert_eq!(far.payload_name(), "segment_pcode");
    assert_eq!(
        far.far_pointer,
        Some(false),
        "present and decoded: Java says no, C++ says yes"
    );
    assert_eq!(far.pcode.param_shift, 1);
    assert!(far.pcode.dynamic && far.pcode.incidental_copy);
    let inputs: Vec<_> = far
        .pcode
        .inputs
        .iter()
        .map(|p| (p.name.as_str(), p.size))
        .collect();
    assert_eq!(inputs, [("base", 2), ("inner", 0)]);
    assert_eq!(far.pcode.outputs[0].name, "res");
    assert_eq!(
        far.pcode.body.as_deref(),
        Some("\n        res = (zext(base) << 4) + zext(inner);\n      ")
    );
    assert_eq!(
        far.const_resolve,
        Some(VarnodeTag::Varnode {
            space: "register".into(),
            offset: 0x10,
            size: 2
        })
    );
    assert_eq!(plain.userop, None);
    assert_eq!(plain.far_pointer, None);
    assert_eq!(plain.pcode.body, None);
    assert_eq!(plain.const_resolve, Some(VarnodeTag::Register("CS".into())));

    // context_data keeps file order across the two kinds.
    let kinds: Vec<ContextKind> = spec.context_data.iter().map(|b| b.kind).collect();
    assert_eq!(kinds, [ContextKind::Tracked, ContextKind::Context]);
    let tracked = spec.tracked_sets().next().unwrap();
    assert_eq!(tracked.range, range("ram", Some(0), Some(0xff)));
    assert_eq!(
        (tracked.values[0].name.as_str(), tracked.values[0].value()),
        ("DF", 0)
    );
    let context = spec.context_sets().next().unwrap();
    assert_eq!(context.range, range("ram", None, None));
    assert_eq!(context.values[0].value(), 1);
    assert_eq!(
        context.values[0].description.as_deref(),
        Some("16-bit mode")
    );
    assert_eq!(context.values[1].val, "junk");
    assert_eq!(
        context.values[1].value(),
        0,
        "Ghidra reads an undecodable value as 0"
    );

    let volatile = spec.volatile.as_ref().unwrap();
    assert_eq!(
        (volatile.inputop.as_str(), volatile.outputop.as_str()),
        ("read_vol", "write_vol")
    );
    assert!(volatile.is_functional());
    assert_eq!(
        volatile.locations,
        [
            MemoryTag::Range(range("io", Some(0), Some(0xff))),
            MemoryTag::Register("STATUS".into())
        ]
    );

    assert_eq!(
        spec.incidental_copy,
        [
            VarnodeTag::Register("r0".into()),
            VarnodeTag::Varnode {
                space: "ram".into(),
                offset: 8,
                size: 4
            }
        ]
    );

    let assist = &spec.jump_assists[0];
    assert_eq!(assist.name, "switchAssist");
    assert_eq!(
        assist.payload_name(JumpAssistPcode::Case),
        "switchAssist_index2case"
    );
    assert_eq!(
        assist.payload_name(JumpAssistPcode::Addr),
        "switchAssist_index2addr"
    );
    assert_eq!(
        assist.payload_name(JumpAssistPcode::Default),
        "switchAssist_defaultaddr"
    );
    assert_eq!(
        assist.payload_name(JumpAssistPcode::Size),
        "switchAssist_calcsize"
    );
    assert_eq!(
        assist.pcode(JumpAssistPcode::Case).unwrap().inputs[0].name,
        "index"
    );
    assert_eq!(
        assist.pcode(JumpAssistPcode::Addr).unwrap().outputs[0].size,
        4
    );
    assert_eq!(
        assist.default_pcode.as_ref().unwrap().body.as_deref(),
        Some("default = 0;")
    );
    assert_eq!(
        assist.size_pcode.as_ref().unwrap().body.as_deref(),
        Some("size = 4;")
    );

    let [r0, r1, v0] = spec.registers.as_slice() else {
        panic!("three registers")
    };
    assert_eq!(
        (r0.group.as_deref(), r0.alias.as_deref()),
        (Some("General"), Some("zero"))
    );
    assert!(!r0.hidden && !r0.volatile && r0.vector_lane_sizes.is_empty());
    assert_eq!(
        (r1.rename.as_deref(), r1.effective_name(), r1.hidden),
        (Some("sp"), "sp", true)
    );
    assert_eq!(v0.vector_lane_sizes, [1, 2, 4]);
    assert!(v0.volatile && v0.is_valid_lane_size(2) && !v0.is_valid_lane_size(3));
    assert_eq!(spec.register("sp").unwrap().name, "r1");
    assert_eq!(spec.register("r1").unwrap().name, "r1");
    assert!(spec.register("nope").is_none());

    let [reset, irq, porta, bare] = spec.default_symbols.as_slice() else {
        panic!("four symbols")
    };
    let SymbolAddress::At(address) = &reset.address else {
        panic!("an address")
    };
    assert_eq!(
        (address.space(), address.offset().unwrap().units),
        (Some("ram"), 0)
    );
    assert!(reset.entry);
    assert_eq!(reset.symbol_type, Some(SymbolType::CodePtr));
    assert_eq!(
        (reset.size, reset.volatile, reset.description.as_deref()),
        (None, None, None)
    );
    assert_eq!(irq.address, SymbolAddress::Next);
    assert_eq!(
        (irq.size, irq.volatile, irq.entry),
        (Some(4), Some(false), false)
    );
    assert_eq!(irq.description.as_deref(), Some("interrupt"));
    assert_eq!(
        (porta.volatile, porta.symbol_type),
        (Some(true), Some(SymbolType::Code))
    );
    assert_eq!(bare.size, None, "a size of 0 means one addressable unit");

    let blocks = &spec.default_memory_blocks;
    assert_eq!(
        blocks[0].kind,
        MemoryBlockKind::Default { initialized: false }
    );
    assert_eq!(
        (blocks[0].length, blocks[0].mode.as_str(), blocks[0].overlay),
        (0x100, "rw", false)
    );
    assert!(blocks[0].is_read() && blocks[0].is_write() && !blocks[0].is_execute());
    assert_eq!(
        blocks[1].kind,
        MemoryBlockKind::Default { initialized: true }
    );
    assert_eq!(
        (blocks[1].length, blocks[1].mode.as_str(), blocks[1].overlay),
        (16, "rx", true)
    );
    assert!(blocks[1].is_execute() && !blocks[1].is_write() && !blocks[1].is_volatile());
    let MemoryBlockKind::BitMapped { address } = &blocks[2].kind else {
        panic!("bit mapped")
    };
    assert_eq!(address.as_str(), "ram:20");
    assert!(blocks[2].is_volatile());
    let MemoryBlockKind::ByteMapped { address, ratio } = &blocks[3].kind else {
        panic!()
    };
    assert_eq!(address.as_str(), "rom:1000");
    assert_eq!(ratio.map(|r| (r.mapped, r.source)), Some((1, 2)));
    let MemoryBlockKind::ByteMapped { address, ratio } = &blocks[4].kind else {
        panic!()
    };
    assert_eq!((address.as_str(), *ratio), ("rom:2000", None));

    assert_eq!(
        spec.sections,
        [
            Properties,
            ProgramCounter,
            DataSpace,
            InferPtrBounds,
            InferPtrBounds,
            SegmentedAddress,
            SegmentOp,
            SegmentOp,
            ContextData,
            Volatile,
            IncidentalCopy,
            JumpAssist,
            RegisterData,
            DefaultSymbols,
            DefaultMemoryBlocks,
        ]
    );
}

#[test]
fn pspec_may_be_empty_and_sections_may_come_in_any_order() {
    let empty = pspec::parse("<processor_spec/>", Mode::Strict)
        .unwrap()
        .value;
    assert_eq!(empty, pspec::ProcessorSpec::default());

    let text = r#"<processor_spec>
        <register_data><register name="pc" rename="PC"/></register_data>
        <programcounter register="PC"/>
        <properties/>
    </processor_spec>"#;
    let spec = pspec::parse(text, Mode::Strict).unwrap().value;
    assert_eq!(
        spec.sections,
        [
            Section::RegisterData,
            Section::ProgramCounter,
            Section::Properties
        ],
        "file order is kept: the rename precedes the use of the new name"
    );
}

fn in_pspec(content: &str) -> String {
    format!("<processor_spec>\n{content}\n</processor_spec>")
}

#[rstest]
#[case::ptr_wordsize_zero(
    r#"<data_space space="ram" ptr_wordsize="0"/>"#,
    "Bad ptr_wordsize attribute"
)]
#[case::ptr_wordsize_32(
    r#"<data_space space="ram" ptr_wordsize="32"/>"#,
    "Bad ptr_wordsize attribute"
)]
#[case::ptr_wordsize_text(
    r#"<data_space space="ram" ptr_wordsize="two"/>"#,
    "expected an integer"
)]
#[case::range_offset(
    r#"<inferptrbounds><range space="ram" first="x" last="1"/></inferptrbounds>"#,
    "expected an offset"
)]
#[case::lane_sizes(
    r#"<register_data><register name="v" vector_lane_sizes="1,two"/></register_data>"#,
    "a comma-separated list of lane sizes"
)]
#[case::length_zero(r#"<default_memory_blocks><memory_block name="m" start_address="0" length="0" initialized="true"/></default_memory_blocks>"#, "a positive length")]
#[case::ratio(r#"<default_memory_blocks><memory_block name="m" start_address="0" length="1" byte_mapped_address="rom:0/2:1"/></default_memory_blocks>"#, "1 <= mapped <= source <= 127")]
#[case::varnode(
    r#"<incidentalcopy><varnode space="ram" offset="zz" size="1"/></incidentalcopy>"#,
    "expected an integer"
)]
#[case::paramshift(
    r#"<segmentop space="ram"><pcode paramshift="x"/></segmentop>"#,
    "expected an integer"
)]
fn pspec_rejects_what_ghidra_rejects_in_both_modes(#[case] content: &str, #[case] message: &str) {
    for mode in [Mode::Strict, Mode::Lenient] {
        let error = pspec::parse(&in_pspec(content), mode)
            .unwrap_err()
            .to_string();
        assert!(error.contains(message), "{mode:?}: {error}");
    }
}

#[rstest]
#[case::no_volatile_range(
    r#"<volatile inputop="a" outputop="b"/>"#,
    "<volatile>: at least one <register> or <range> is required"
)]
#[case::half_range(
    r#"<inferptrbounds><range space="ram" first="0"/></inferptrbounds>"#,
    "<range>: first and last must be given together"
)]
#[case::no_block_kind(r#"<default_memory_blocks><memory_block name="m" start_address="0" length="1"/></default_memory_blocks>"#, "<memory_block>: exactly one of bit_mapped_address, byte_mapped_address and initialized is required")]
#[case::two_resolves(r#"<segmentop space="ram"><pcode/><constresolve><register name="a"/><varnode space="r" offset="0" size="1"/></constresolve></segmentop>"#, "<constresolve>: exactly one <register> or <varnode> is required")]
#[case::empty_copy(
    r"<incidentalcopy/>",
    "<incidentalcopy>: at least one <register> or <varnode> is required"
)]
#[case::boolean(
    r#"<register_data><register name="r" hidden="y"/></register_data>"#,
    "<register> attribute hidden=\"y\": expected one of true, false, yes, no, 1, 0"
)]
#[case::symbol_type(
    r#"<default_symbols><symbol name="s" address="0" type="CODE"/></default_symbols>"#,
    "<symbol> attribute type=\"CODE\": expected code or code_ptr"
)]
#[case::twice(
    r#"<programcounter register="a"/><programcounter register="b"/>"#,
    "<processor_spec> has more than one <programcounter>"
)]
#[case::unknown(
    r"<address_shift_amount/>",
    "element <address_shift_amount> is not allowed in <processor_spec>"
)]
#[case::body_first(
    r#"<segmentop space="ram"><pcode><body>x</body><input name="a"/></pcode></segmentop>"#,
    "<input> is out of order in <pcode>"
)]
#[case::text(r"<properties>words</properties>", "<properties> may not contain text")]
#[case::no_sets(
    r#"<context_data><context_set space="ram"/></context_data>"#,
    "<context_set> is missing required element <set>"
)]
fn pspec_schema_violations_fail_strict_and_warn_lenient(
    #[case] content: &str,
    #[case] message: &str,
) {
    let text = in_pspec(content);
    let strict = pspec::parse(&text, Mode::Strict).unwrap_err();
    assert!(matches!(strict.kind, ParseErrorKind::Schema(_)), "{strict}");
    assert!(strict.to_string().ends_with(message), "{strict}");

    let lenient = pspec::parse(&text, Mode::Lenient).unwrap_or_else(|e| panic!("{e}"));
    let warnings: Vec<String> = lenient
        .warnings
        .iter()
        .map(|w| w.violation.to_string())
        .collect();
    assert_eq!(warnings, [message]);
}

#[test]
fn pspec_lenient_mode_falls_back_as_ghidras_reader_would() {
    let text = in_pspec(
        r#"<programcounter register="a"/><programcounter register="b"/>
           <register_data><register name="r" hidden="y"/><register name="s" hidden="maybe"/></register_data>
           <default_symbols><symbol name="s" address="0" type="CODE"/></default_symbols>
           <default_memory_blocks><memory_block name="m" start_address="0" length="1"/></default_memory_blocks>
           <volatile inputop="a" outputop="b"><range space="x"/></volatile>
           <volatile inputop="c" outputop="d"><range space="y"/></volatile>"#,
    );
    let parsed = pspec::parse(&text, Mode::Lenient).unwrap();
    assert_eq!(parsed.warnings.len(), 6);
    let spec = parsed.value;
    assert_eq!(
        spec.program_counter.as_deref(),
        Some("b"),
        "the later element wins"
    );
    assert!(
        spec.registers[0].hidden,
        "decoded by first letter, as SpecXmlUtils does"
    );
    assert!(!spec.registers[1].hidden);
    assert_eq!(spec.default_symbols[0].symbol_type, Some(SymbolType::Code));
    assert_eq!(
        spec.default_memory_blocks[0].kind,
        MemoryBlockKind::Default { initialized: false }
    );
    let volatile = spec.volatile.unwrap();
    assert_eq!(
        volatile.locations.len(),
        2,
        "a second <volatile> adds its ranges"
    );
    assert_eq!(volatile.inputop, "c");
}

#[test]
fn memory_block_booleans_accept_every_schema_spelling() {
    // Ghidra's schema allows yes/no/1/0 here but its MemoryBlockDefinition
    // then throws on them; Basilisk reads them.
    for (text, expected) in [("yes", true), ("1", true), ("no", false), ("0", false)] {
        let block = format!(
            r#"<default_memory_blocks><memory_block name="m" start_address="0" length="1" initialized="{text}" overlay="{text}"/></default_memory_blocks>"#
        );
        let spec = pspec::parse(&in_pspec(&block), Mode::Strict).unwrap().value;
        assert_eq!(
            spec.default_memory_blocks[0].kind,
            MemoryBlockKind::Default {
                initialized: expected
            }
        );
        assert_eq!(spec.default_memory_blocks[0].overlay, expected);
    }
}
