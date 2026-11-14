//! One fixture per validation rule (`features/sla.md` 4.3) and per limit
//! (4.4): each breaks exactly one rule of an otherwise valid model, and the
//! reader must reject it with the expected message.
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

use bk_sla::{Limits, Operand, Sla, SlaError, SymbolDef, SymbolId};

/// Applies text edits (each `old` must occur exactly once) to the full
/// model's XML and decodes the result.
fn edited(edits: &[(&str, &str)]) -> Result<Sla, SlaError> {
    let mut xml = common::full_model().encode_xml().unwrap();
    for (old, new) in edits {
        assert_eq!(
            xml.matches(old).count(),
            1,
            "edit target must be unique: {old}"
        );
        xml = xml.replacen(old, new, 1);
    }
    Sla::decode_xml(&xml, &Limits::default())
}

fn expect_error(name: &str, result: Result<Sla, SlaError>, needle: &str) {
    match result {
        Ok(_) => panic!("{name}: accepted"),
        Err(error) => {
            let text = error.to_string();
            assert!(
                text.contains(needle),
                "{name}: expected \"{needle}\" in \"{text}\""
            );
        }
    }
}

const SUB_DECISION: &str = "      <decision number=\"1\" context=\"false\" startbit=\"0\" size=\"0\">\n        <pair id=\"0\">\n          <instruct_pat>\n            <pat_block off=\"0\" nonzero=\"0\"/>\n          </instruct_pat>\n        </pair>\n      </decision>\n";
const SUB_HANDLE: &str = "<handle_tpl>\n            <const_handle val=\"0\" s=\"0\"/>\n            <const_handle val=\"0\" s=\"2\"/>\n            <const_real";
const NOT_OPERAND: &str =
    "<not_exp>\n          <operand_exp index=\"0\" table=\"0x0\" ct=\"0x0\"/>";

#[test]
fn the_unedited_fixture_is_valid() {
    assert!(edited(&[]).is_ok());
}

#[test]
fn each_xml_violation_is_rejected() {
    let sub_decision_twice = format!("{SUB_DECISION}{SUB_DECISION}");
    let cases: Vec<(&str, Vec<(&str, &str)>, &str)> = vec![
        // Rule 1: ids refer to existing objects of the right kind.
        (
            "scope parent",
            vec![(
                "<scope id=\"0x1\" parent=\"0x0\"/>",
                "<scope id=\"0x1\" parent=\"0x9\"/>",
            )],
            "exceeds symbol scope table size",
        ),
        (
            "symbol scope",
            vec![("id=\"0x11\" scope=\"0x2\"", "id=\"0x11\" scope=\"0x7\"")],
            "scope id: too large",
        ),
        (
            "subsym kind",
            vec![("subsym=\"0x8\"", "subsym=\"0x4\"")],
            "is not a definable symbol",
        ),
        (
            "context varnode",
            vec![("varnode=\"0x3\"", "varnode=\"0x4\"")],
            "is not a varnode symbol",
        ),
        (
            "varlist entry",
            vec![("<var id=\"0x1\"/>", "<var id=\"0x5\"/>")],
            "is not a varnode symbol",
        ),
        (
            "oper kind",
            vec![("<oper id=\"0x11\"/>", "<oper id=\"0x1\"/>")],
            "is not an operand symbol",
        ),
        (
            "commit symbol",
            vec![("<commit id=\"0x9\"", "<commit id=\"0xe\"")],
            "has no fixed handle",
        ),
        (
            "operand_exp table",
            vec![(
                NOT_OPERAND,
                "<not_exp>\n          <operand_exp index=\"0\" table=\"0x5\" ct=\"0x0\"/>",
            )],
            "is not a subtable",
        ),
        (
            "operand_exp ct",
            vec![(
                NOT_OPERAND,
                "<not_exp>\n          <operand_exp index=\"0\" table=\"0x0\" ct=\"0x5\"/>",
            )],
            "ct 5 is out of range",
        ),
        (
            "operand_exp index",
            vec![(
                NOT_OPERAND,
                "<not_exp>\n          <operand_exp index=\"7\" table=\"0x0\" ct=\"0x0\"/>",
            )],
            "index 7 is out of range",
        ),
        (
            "pair id",
            vec![("<pair id=\"1\">", "<pair id=\"2\">")],
            "pair id 2 is not below numct",
        ),
        (
            "constructor parent",
            vec![("<constructor parent=\"0xe\"", "<constructor parent=\"0x0\"")],
            "not the enclosing subtable",
        ),
        (
            "unknown space name",
            vec![(
                "space=\"register\" off=\"0x0\"",
                "space=\"nowhere\" off=\"0x0\"",
            )],
            "unknown address space nowhere",
        ),
        // Rule 2: shapes.
        ("numct", vec![("numct=\"2\"", "numct=\"3\"")], "numct is 3"),
        (
            "no decision",
            vec![(SUB_DECISION, "")],
            "has no decision tree",
        ),
        (
            "two decisions",
            vec![(SUB_DECISION, sub_decision_twice.as_str())],
            "more than one decision tree",
        ),
        (
            "decision size",
            vec![("startbit=\"0\" size=\"1\"", "startbit=\"0\" size=\"9\"")],
            "not in 0..=8",
        ),
        (
            "decision children",
            vec![("startbit=\"0\" size=\"1\"", "startbit=\"0\" size=\"2\"")],
            "has 2 children, expected 4",
        ),
        (
            "leaf with children",
            vec![("startbit=\"0\" size=\"1\"", "startbit=\"0\" size=\"0\"")],
            "a decision leaf has children",
        ),
        (
            "duplicate section",
            vec![(
                "<construct_tpl section=\"1\">",
                "<construct_tpl section=\"0\">",
            )],
            "Duplicate",
        ),
        (
            "section number",
            vec![(
                "<construct_tpl section=\"1\">",
                "<construct_tpl section=\"2\">",
            )],
            "not below numsections",
        ),
        (
            "first",
            vec![("first=\"1\" length=\"1\"", "first=\"2\" length=\"1\"")],
            "first 2 is out of range",
        ),
        (
            "opprint",
            vec![(
                "<opprint id=\"0\"/>\n        <construct_tpl>",
                "<opprint id=\"1\"/>\n        <construct_tpl>",
            )],
            "opprint 1 is out of range",
        ),
        (
            "const_handle",
            vec![(
                SUB_HANDLE,
                "<handle_tpl>\n            <const_handle val=\"1\" s=\"0\"/>\n            <const_handle val=\"0\" s=\"2\"/>\n            <const_real",
            )],
            "const_handle 1 is out of range",
        ),
        (
            "handle selector",
            vec![(
                SUB_HANDLE,
                "<handle_tpl>\n            <const_handle val=\"0\" s=\"4\"/>\n            <const_handle val=\"0\" s=\"2\"/>\n            <const_real",
            )],
            "Bad handle selector encoding",
        ),
        (
            "directive inputs",
            vec![("code=\"CROSSBUILD\"", "code=\"BUILD\"")],
            "directive BUILD has malformed inputs",
        ),
        (
            "label number",
            vec![(
                "<const_relative val=\"0x0\"/>",
                "<const_relative val=\"0x1\"/>",
            )],
            "label 1 is not below 1",
        ),
        (
            "operand position",
            vec![("minlen=\"0\" index=\"1\"", "minlen=\"0\" index=\"2\"")],
            "has index 2 at position 1",
        ),
        (
            "operand base",
            vec![("off=\"0\" base=\"0\"", "off=\"0\" base=\"1\"")],
            "base 1 is not -1 or below index 1",
        ),
        (
            "both definitions",
            vec![(
                "<operand_sym id=\"0x10\" off",
                "<operand_sym id=\"0x10\" subsym=\"0x8\" off",
            )],
            "exactly one of a defining symbol",
        ),
        (
            "no definition",
            vec![("subsym=\"0xe\" ", "")],
            "exactly one of a defining symbol",
        ),
        (
            "local expression",
            vec![(
                "index=\"0\">\n      <operand_exp index=\"0\" table=\"0xe\"",
                "index=\"0\">\n      <operand_exp index=\"0\" table=\"0x0\"",
            )],
            "does not name it",
        ),
        // Rule 3: value ranges.
        (
            "negative off",
            vec![("subsym=\"0x8\" off=\"1\"", "subsym=\"0x8\" off=\"-1\"")],
            "off -1 is negative",
        ),
        (
            "negative length",
            vec![("first=\"-1\" length=\"1\"", "first=\"-1\" length=\"-5\"")],
            "length -5 is negative",
        ),
        (
            "negative delay",
            vec![("<construct_tpl delay=\"1\"", "<construct_tpl delay=\"-1\"")],
            "delay -1 is negative",
        ),
        (
            "token field shift",
            vec![(
                "<valuemap_sym id=\"0x6\">\n      <tokenfield bigendian=\"true\" signbit=\"false\" startbit=\"0\" endbit=\"7\" startbyte=\"0\" endbyte=\"0\" shift=\"0\"/>",
                "<valuemap_sym id=\"0x6\">\n      <tokenfield bigendian=\"true\" signbit=\"false\" startbit=\"0\" endbit=\"7\" startbyte=\"0\" endbyte=\"0\" shift=\"8\"/>",
            )],
            "malformed field",
        ),
        (
            "token field bits",
            vec![(
                "<value_sym id=\"0x5\">\n      <tokenfield bigendian=\"true\" signbit=\"false\" startbit=\"0\" endbit=\"7\"",
                "<value_sym id=\"0x5\">\n      <tokenfield bigendian=\"true\" signbit=\"false\" startbit=\"8\" endbit=\"7\"",
            )],
            "malformed field",
        ),
        (
            "context field width",
            vec![(
                "startbit=\"0\" endbit=\"3\" startbyte=\"0\" endbyte=\"0\" shift=\"4\"",
                "startbit=\"0\" endbit=\"40\" startbyte=\"0\" endbyte=\"5\" shift=\"4\"",
            )],
            "malformed field",
        ),
        (
            "context_op word",
            vec![("<context_op i=\"0\"", "<context_op i=\"1\"")],
            "context word 1 is outside",
        ),
        (
            "commit word",
            vec![(
                "number=\"0\" mask=\"0xf0000000\"",
                "number=\"1\" mask=\"0xf0000000\"",
            )],
            "context word 1 is outside",
        ),
        (
            "context_op shift",
            vec![("shift=\"28\"", "shift=\"32\"")],
            "shift 32 is out of range",
        ),
        (
            "opcode",
            vec![("code=\"INT_ADD\"", "code=\"NOPE\"")],
            "unknown opcode NOPE",
        ),
        (
            "varnode size",
            vec![("off=\"0x0\" size=\"4\"", "off=\"0x0\" size=\"0\"")],
            "is not positive",
        ),
        (
            "mask too wide",
            vec![(
                "mask=\"0xf0000000\" val=\"0x30000000\"",
                "mask=\"0x1f0000000\" val=\"0x30000000\"",
            )],
            "out of range",
        ),
        // Rule 4: operand-expression cycles.
        (
            "cycle",
            vec![(
                NOT_OPERAND,
                "<not_exp>\n          <operand_exp index=\"1\" table=\"0x0\" ct=\"0x0\"/>",
            )],
            "depends on itself",
        ),
        // Rule 5: spaces.
        (
            "space index",
            vec![("name=\"code\" index=\"5\"", "name=\"code\" index=\"4\"")],
            "two spaces have index 4",
        ),
        (
            "space index 0",
            vec![("name=\"code\" index=\"5\"", "name=\"code\" index=\"0\"")],
            "Expecting index attribute",
        ),
        (
            "default space",
            vec![("defaultspace=\"ram\"", "defaultspace=\"rom\"")],
            "Bad 'defaultspace' attribute: rom",
        ),
        (
            "two unique spaces",
            vec![(
                "<space_other name=\"OTHER\"",
                "<space_unique name=\"OTHER\"",
            )],
            "more than one space_unique",
        ),
        // Rule 6: names.
        (
            "duplicate global",
            vec![("name=\"r1\"", "name=\"r0\"")],
            "share this name",
        ),
        (
            "no root",
            vec![("name=\"instruction\"", "name=\"instr\"")],
            "no global subtable `instruction`",
        ),
        (
            "root kind",
            vec![
                ("name=\"instruction\"", "name=\"instr\""),
                ("name=\"r0\"", "name=\"instruction\""),
            ],
            "is not a subtable",
        ),
        // Grammar and bodies.
        (
            "version",
            vec![("version=\"4\"", "version=\"3\"")],
            "wrong format",
        ),
        (
            "missing body",
            vec![("<userop id=\"0x4\" index=\"0\"/>", "")],
            "has a head and no body",
        ),
        (
            "body kind",
            vec![("<userop id=\"0x4\"", "<userop id=\"0x5\"")],
            "does not match its head",
        ),
        (
            "duplicate body",
            vec![(
                "<start_sym id=\"0xa\"/>",
                "<start_sym id=\"0xa\"/><start_sym id=\"0xa\"/>",
            )],
            "Already decoded symbol",
        ),
        (
            "missing attribute",
            vec![("<userop id=\"0x4\" index=\"0\"/>", "<userop id=\"0x4\"/>")],
            "missing attribute `index`",
        ),
        (
            "unexpected child",
            vec![("<var id=\"0x1\"/>", "<intb val=\"1\"/>")],
            "expected <var> or <null>",
        ),
    ];
    for (name, edits, needle) in cases {
        expect_error(name, edited(&edits), needle);
    }
}

#[test]
fn symbols_without_content_need_no_body() {
    let sla = edited(&[
        ("<epsilon_sym id=\"0xd\"/>", ""),
        ("<next2_sym id=\"0xc\"/>", ""),
    ])
    .unwrap();
    assert_eq!(sla, common::full_model());
}

#[test]
fn builder_violations_are_rejected() {
    // An undeclared space index.
    let (mut b, _) = common::full_builder();
    b.set_symbol(
        SymbolId::new(1),
        SymbolDef::Varnode {
            space: 9,
            offset: 0,
            size: 4,
        },
    );
    expect_error("space index", b.finish(), "unknown space index 9");
    // An operand symbol no constructor owns.
    let (mut b, ids) = common::full_builder();
    let local = b.expr(bk_sla::Expr::Operand {
        index: 0,
        table: ids.instruction,
        ct: 0,
    });
    b.symbol(
        "orphan",
        bk_sla::ScopeId::new(1),
        SymbolDef::Operand(Operand {
            index: 0,
            offset: 0,
            base: -1,
            min_length: 0,
            code: false,
            defining_symbol: Some(SymbolId::new(1)),
            local_expr: local,
            defining_expr: None,
        }),
    );
    expect_error(
        "orphan operand",
        b.finish(),
        "not owned by exactly one constructor",
    );
    // An expression that refers to a later node.
    let (mut b, _) = common::full_builder();
    let later = bk_sla::ExprId::new(1_000);
    b.expr(bk_sla::Expr::Unary {
        op: bk_sla::UnaryOp::Not,
        operand: later,
    });
    expect_error("forward expression", b.finish(), "refers to a later node");
    // A string the packed form cannot hold.
    let (mut b, _) = common::full_builder();
    b.source_file("nul\0.sinc");
    expect_error("nul", b.finish(), "NUL character");
    // A decision node with the wrong number of children.
    let (mut b, ids) = common::full_builder();
    b.set_symbol(ids.dst, SymbolDef::Start);
    expect_error("operand replaced", b.finish(), "is not an operand symbol");
}

fn limited(limits: &Limits) -> Result<Sla, SlaError> {
    let bytes = common::full_model().write().unwrap();
    Sla::read(&bytes, limits)
}

#[test]
fn each_limit_is_enforced() {
    let base = Limits::default();
    let cases: Vec<(Limits, &str)> = vec![
        (
            Limits {
                inflated_size: 100,
                ..base
            },
            "inflated size",
        ),
        (
            Limits { scopes: 2, ..base },
            "scopes exceeds the limit of 2",
        ),
        (
            Limits {
                symbols: 10,
                ..base
            },
            "symbols exceeds the limit of 10",
        ),
        (
            Limits {
                element_depth: 5,
                ..base
            },
            "element nesting exceeds the limit of 5",
        ),
        (
            Limits {
                expr_depth: 3,
                ..base
            },
            "expression nesting exceeds the limit of 3",
        ),
        (
            Limits {
                decision_depth: 1,
                ..base
            },
            "decision-tree depth exceeds the limit of 1",
        ),
        (
            Limits {
                operands: 1,
                ..base
            },
            "operands of one constructor exceeds the limit of 1",
        ),
        (
            Limits {
                op_inputs: 1,
                ..base
            },
            "inputs of one op template exceeds the limit of 1",
        ),
        (
            Limits {
                byte_quantity: 0,
                ..base
            },
            "byte quantity exceeds the limit of 0",
        ),
        (
            Limits {
                context_words: 0,
                ..base
            },
            "context words exceeds the limit of 0",
        ),
    ];
    for (limits, needle) in cases {
        expect_error(needle, limited(&limits), needle);
    }
    // The XML form checks the document size too.
    let xml = common::full_model().encode_xml().unwrap();
    expect_error(
        "xml size",
        Sla::decode_xml(
            &xml,
            &Limits {
                inflated_size: 10,
                ..base
            },
        ),
        "document size",
    );
    // The builder applies the same limits.
    let (b, _) = common::full_builder();
    expect_error(
        "builder",
        b.finish_with(&Limits {
            operands: 1,
            ..base
        }),
        "operands of one constructor",
    );
}

#[test]
fn container_errors() {
    let limits = Limits::default();
    let good = common::full_model().write().unwrap();
    let check = |name: &str, bytes: &[u8], needle: &str| match Sla::read(bytes, &limits) {
        Ok(_) => panic!("{name}: accepted"),
        Err(error) => assert!(error.to_string().contains(needle), "{name}: {error}"),
    };
    check("empty", &[], "not a version 4 .sla file");
    check("short", b"sl", "not a version 4 .sla file");
    check("magic", b"slb\x04xxxx", "not a version 4 .sla file");
    let mut version = good.clone();
    version[3] = 3;
    check("version byte", &version, "not a version 4 .sla file");
    check("truncated", &good[..good.len() - 20], "cannot be inflated");
    check(
        "damaged",
        &[b's', b'l', b'a', 4, 0x78, 0x9c, 0xff, 0xff, 0xff],
        "cannot be inflated",
    );
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    check(
        "trailing bytes",
        &trailing,
        "4 bytes follow the end of the compressed stream",
    );
    // Data after the root element inside the stream.
    let mut stream = common::full_model().encode_packed().unwrap();
    stream.push(0x41);
    let error = Sla::decode_packed(&stream, &limits).unwrap_err();
    assert!(matches!(error, SlaError::TrailingData { .. }), "{error}");
    // A packed stream cut short names an offset.
    let stream = common::full_model().encode_packed().unwrap();
    let error = Sla::decode_packed(&stream[..stream.len() / 2], &limits).unwrap_err();
    assert!(error.to_string().contains("(at byte"), "{error}");
}
