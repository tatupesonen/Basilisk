//! Round trips of the hand-built model that holds every element kind and
//! optional attribute (`features/sla.md` section 6, derived tests).
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

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, Limits, PackedReader, Sla, SpaceTable, Template, VarnodeTpl, ids};

#[test]
fn the_full_model_round_trips_in_both_forms_and_the_container() {
    let sla = common::full_model();
    let limits = Limits::default();
    let packed = sla.encode_packed().unwrap();
    let from_packed = Sla::decode_packed(&packed, &limits).unwrap();
    assert_eq!(
        from_packed,
        sla,
        "{:?}",
        bk_sla::diff(&from_packed, &sla, 5)
    );
    assert_eq!(from_packed.encode_packed().unwrap(), packed);
    let marshal = Sla::decode_packed_using(&packed, &limits, PackedReader::Marshal).unwrap();
    assert_eq!(marshal, sla);
    let xml = sla.encode_xml().unwrap();
    let from_xml = Sla::decode_xml(&xml, &limits).unwrap();
    assert_eq!(from_xml, sla, "{:?}", bk_sla::diff(&from_xml, &sla, 5));
    assert_eq!(from_xml.encode_xml().unwrap(), xml);
    let file = sla.write().unwrap();
    assert_eq!(&file[..4], b"sla\x04");
    assert_eq!(Sla::read(&file, &limits).unwrap(), sla);
}

#[test]
fn the_full_model_contains_every_element_and_optional_attribute() {
    let xml = common::full_model().encode_xml().unwrap();
    for element in ids::ELEMENTS {
        if element.name() == "or_pat" {
            continue; // Never written by Ghidra's encoder inside a .sla.
        }
        assert!(
            xml.contains(&format!("<{} ", element.name()))
                || xml.contains(&format!("<{}>", element.name()))
                || xml.contains(&format!("<{}/>", element.name())),
            "<{}> missing",
            element.name()
        );
    }
    for attribute in [
        "maxdelay=",
        "uniqmask=",
        "numsections=",
        "wordsize=",
        "subsym=",
        "code=\"true\"",
        "plus=",
        "section=",
        "delay=\"1\"",
        "labels=",
    ] {
        assert!(xml.contains(attribute), "{attribute} missing");
    }
    // The unusable name-table entry is written without a name.
    assert!(xml.contains("<nametab/>"));
    assert!(xml.contains("name=\"a&lt;&amp;&gt;\""));
}

#[test]
fn files_write_through_a_temporary_and_read_back() {
    let sla = common::full_model();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.sla");
    sla.write_file(&path).unwrap();
    assert_eq!(Sla::read_file(&path, &Limits::default()).unwrap(), sla);
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "the temporary file was renamed away");
    let error = Sla::read_file(&dir.path().join("absent.sla"), &Limits::default()).unwrap_err();
    assert!(error.to_string().contains("absent.sla"), "{error}");
}

#[test]
fn accessors_reach_every_part() {
    let sla = common::full_model();
    let root = sla.root();
    assert_eq!(sla.symbol_name(root), "instruction");
    assert_eq!(sla.global("sub").map(|id| sla.symbol_name(id)), Some("sub"));
    assert_eq!(sla.source_files().collect::<Vec<_>>(), ["a.sinc", "b.sinc"]);
    let table = sla.subtable(root).unwrap();
    let ctor = sla.constructor(table.constructor(0).unwrap()).unwrap();
    assert_eq!(sla.operands(ctor).len(), 2);
    assert_eq!(sla.print_pieces(ctor).len(), 5);
    assert_eq!(sla.context_changes(ctor).len(), 2);
    let main = sla.main_template(ctor).unwrap();
    assert_eq!(main.ops().len(), 7);
    assert!(main.result().is_some());
    assert_eq!(main.inputs(&main.ops()[5]).len(), 2);
    assert!(main.output(&main.ops()[0]).is_some());
    assert!(sla.section_template(ctor, 0).is_some());
    assert_eq!(sla.section_template(ctor, 1).unwrap().ops(), []);
    assert!(sla.section_template(ctor, 2).is_none());
    // Templates are ordered main first, then by section.
    let sections: Vec<_> = sla
        .template_ids(ctor)
        .map(|id| sla.template(id).unwrap().header().section)
        .collect();
    assert_eq!(sections, [None, Some(0), Some(1)]);
    let node = sla.decision(table.decision).unwrap();
    assert_eq!(node.num_children(), 2);
    let child = sla.decision(sla.decision_child(node, 1).unwrap()).unwrap();
    assert_eq!(sla.pairs(child).len(), 2);
    assert!(sla.decision_child(node, 2).is_none());
    // The instruction block was normalised: the leading zero word and byte
    // moved into the offset.
    let bk_sla::DisjointPattern::Combine { instruction, .. } =
        sla.pairs(sla.decision(sla.decision_child(node, 0).unwrap()).unwrap())[0].pattern
    else {
        panic!("expected a combined pattern");
    };
    let block = sla.block(instruction).unwrap();
    assert_eq!((block.offset, block.nonzero), (5, 1));
    assert_eq!(sla.block_words(block)[0].mask, 0xff00_0000);
    assert_eq!(sla.context_words(), 1);
    assert_eq!(sla.space_name(0), Some("const"));
    assert_eq!(sla.space_name(5), Some("code"));
    assert!(sla.heap_bytes() > 0);
}

#[test]
fn spaces_are_built_as_ghidra_builds_them() {
    let sla = common::full_model();
    let manager = sla.build_spaces().unwrap();
    assert_eq!(manager.default_code_space().unwrap().name(), "ram");
    assert_eq!(manager.space_at(0).unwrap().name(), "const");
    assert_eq!(manager.space_at(1).unwrap().name(), "OTHER");
    assert_eq!(manager.unique_space().unwrap().index(), 2);
    let code = manager.space_by_name("code").unwrap();
    assert_eq!(
        (code.word_size(), code.delay(), code.deadcode_delay()),
        (2, 1, 1)
    );
    assert!(code.is_big_endian());
}

#[test]
fn a_lone_template_round_trips() {
    let template = common::main_template();
    let sla = common::full_model();
    let spaces = sla.space_table();
    let limits = Limits::default();
    let packed = template.encode_packed(&spaces);
    assert_eq!(
        Template::decode_packed(&packed, &spaces, &limits).unwrap(),
        template
    );
    assert_eq!(
        Template::decode_packed_marshal(&packed, &spaces, &limits).unwrap(),
        template
    );
    let xml = template.encode_xml(&spaces);
    assert!(
        xml.starts_with("\n<construct_tpl delay=\"1\" labels=\"1\">"),
        "{xml}"
    );
    assert_eq!(
        Template::decode_xml(&xml, &spaces, &limits).unwrap(),
        template
    );
    // An unknown space name is an error.
    let error = Template::decode_xml(&xml, &SpaceTable::new(), &limits).unwrap_err();
    assert!(
        error.to_string().contains("unknown address space"),
        "{error}"
    );
    template.check_labels().unwrap();
    // A label beyond the count reads, as in Ghidra (`ConstructTpl::decode`
    // does not check it); the separate label check refuses it.
    let bad = xml.replace("labels=\"1\"", "labels=\"0\"");
    let read = Template::decode_xml(&bad, &spaces, &limits).unwrap();
    let error = read.check_labels().unwrap_err();
    assert!(
        error.to_string().contains("label 0 is not below 0"),
        "{error}"
    );
}

/// A branch to a label that is never placed, as Ghidra's snippet compiler
/// produces for `goto <L>;`: reading accepts it in both forms; the label
/// check names the label.
#[test]
fn a_branch_to_an_unplaced_label_reads_and_fails_the_label_check() {
    let sla = common::full_model();
    let spaces = sla.space_table();
    let limits = Limits::default();
    let mut template = Template::new();
    template.set_header(None, 0, 1);
    let target = VarnodeTpl {
        space: ConstTpl::Space(0),
        offset: ConstTpl::Relative(0),
        size: ConstTpl::Real(4),
    };
    template.push_op(OpCode::Branch, None, &[target]);
    let xml = template.encode_xml(&spaces);
    assert_eq!(
        Template::decode_xml(&xml, &spaces, &limits).unwrap(),
        template
    );
    let packed = template.encode_packed(&spaces);
    assert_eq!(
        Template::decode_packed(&packed, &spaces, &limits).unwrap(),
        template
    );
    let error = template.check_labels().unwrap_err();
    assert!(
        error.to_string().contains("label 0 is never placed"),
        "{error}"
    );
}

#[test]
fn diff_reports_paths_and_values() {
    let a = common::full_model();
    let xml = a
        .encode_xml()
        .unwrap()
        .replace("<const_real val=\"0x10\"/>", "<const_real val=\"0x20\"/>");
    let b = Sla::decode_xml(&xml, &Limits::default()).unwrap();
    let differences = bk_sla::diff(&a, &b, 10);
    assert_eq!(differences.len(), 1, "{differences:?}");
    let text = differences[0].to_string();
    assert_eq!(
        text,
        "table \"instruction\" constructor 0 (a.sinc:10) main op 0 output: \
         (const_spaceid ram, const_real 0x10, const_real 0x4) \u{2260} (const_spaceid ram, const_real 0x20, const_real 0x4)"
    );
    assert_eq!(bk_sla::diff(&a, &a, 10), []);
    assert_eq!(bk_sla::diff(&a, &b, 0), []);
}
