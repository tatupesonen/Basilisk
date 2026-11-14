//! The schema tables against Ghidra's RELAX NG schemas.
//!
//! `bk_lang::schema` restates the three `.rxg` grammars as tables, and the
//! strict readers enforce them. These tests check the restatement against
//! Ghidra's own schema files:
//!
//! * every element and attribute name the schemas define is in the
//!   tables, and the reverse (walking the `.rxg` files from `<start>`);
//! * a document built from the tables with every element and attribute
//!   reads in strict mode;
//! * every file Ghidra ships reads in strict mode, including the
//!   `.opinion` files outside `Ghidra/Processors`.
//!
//! The tables were also checked once against a RELAX NG validator on
//! single-step mutations of those documents; the result is recorded in
//! `docs/features/lang.md`, section 9. Skipped without a Ghidra tree.

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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::Path,
};

use bk_lang::{
    Mode, ParseError, ldefs, opinion, pspec,
    schema::{AttrType, Card, ElementDef, LANGUAGE_DEFINITIONS, OPINIONS, PROCESSOR_SPEC},
};

/// One file type: its schema file, its root in the tables, and its strict
/// reader reduced to accept/reject.
struct Kind {
    schema: &'static str,
    extension: &'static str,
    root: &'static ElementDef,
    read: fn(&str) -> Result<(), ParseError>,
}

const KINDS: [Kind; 3] = [
    Kind {
        schema: "language_definitions.rxg",
        extension: ".ldefs",
        root: &LANGUAGE_DEFINITIONS,
        read: |text| ldefs::parse(text, Mode::Strict).map(drop),
    },
    Kind {
        schema: "processor_spec.rxg",
        extension: ".pspec",
        root: &PROCESSOR_SPEC,
        read: |text| pspec::parse(text, Mode::Strict).map(drop),
    },
    Kind {
        schema: "format_opinions.rxg",
        extension: ".opinion",
        root: &OPINIONS,
        read: |text| opinion::parse(text, Mode::Strict).map(drop),
    },
];

// ------------------------------------------------------------ name sets

type Names = BTreeMap<String, BTreeSet<String>>;

/// Element name → attribute names, for everything reachable from `def`.
fn table_names(def: &'static ElementDef, names: &mut Names, seen: &mut Vec<*const ElementDef>) {
    if seen.contains(&std::ptr::from_ref(def)) {
        return;
    }
    seen.push(std::ptr::from_ref(def));
    let attrs = names.entry(def.name.to_owned()).or_default();
    attrs.extend(def.attrs.iter().map(|a| a.name.to_owned()));
    for child in def.children {
        table_names(child.def, names, seen);
    }
}

/// Element name → attribute names, for everything reachable from the
/// `<start>` of a schema file: `<ref>`s are followed into the `<define>`s
/// of the file and of the files it includes.
fn schema_names(dir: &Path, file: &str) -> Names {
    let mut texts = vec![std::fs::read_to_string(dir.join(file)).unwrap()];
    let includes: Vec<String> = roxmltree::Document::parse(&texts[0])
        .unwrap()
        .descendants()
        .filter(|n| n.has_tag_name((RNG, "include")))
        .map(|n| n.attribute("href").unwrap().to_owned())
        .collect();
    for include in includes {
        texts.push(std::fs::read_to_string(dir.join(include)).unwrap());
    }
    let docs: Vec<_> = texts
        .iter()
        .map(|t| roxmltree::Document::parse(t).unwrap())
        .collect();
    let define = |name: &str| {
        docs.iter()
            .flat_map(|d| d.descendants())
            .find(|n| n.has_tag_name((RNG, "define")) && n.attribute("name") == Some(name))
            .unwrap_or_else(|| panic!("no <define name=\"{name}\">"))
    };
    let start = docs[0]
        .descendants()
        .find(|n| n.has_tag_name((RNG, "start")))
        .unwrap();

    let mut names = Names::new();
    let mut followed = BTreeSet::new();
    // (pattern node, enclosing element name)
    let mut pending = vec![(start, None::<String>)];
    while let Some((node, element)) = pending.pop() {
        for child in node.children().filter(roxmltree::Node::is_element) {
            match child.tag_name().name() {
                "element" => {
                    let name = child.attribute("name").unwrap().to_owned();
                    names.entry(name.clone()).or_default();
                    pending.push((child, Some(name)));
                }
                "attribute" => {
                    let owner = element.clone().expect("attribute inside an element");
                    names
                        .entry(owner)
                        .or_default()
                        .insert(child.attribute("name").unwrap().into());
                }
                "ref" => {
                    let target = child.attribute("name").unwrap();
                    // A definition's content belongs to whichever element
                    // refers to it, so follow it once per such element.
                    if followed.insert((target.to_owned(), element.clone())) {
                        pending.push((define(target), element.clone()));
                    }
                }
                _ => pending.push((child, element.clone())),
            }
        }
    }
    names
}

const RNG: &str = "http://relaxng.org/ns/structure/1.0";

#[test]
fn tables_and_schemas_define_the_same_names() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    for kind in &KINDS {
        let mut tables = Names::new();
        table_names(kind.root, &mut tables, &mut Vec::new());
        let schema = schema_names(&common::schema_dir(&ghidra), kind.schema);
        assert_eq!(tables, schema, "{}", kind.schema);
    }
    // The .pspec grammar is the large one: 32 distinct element names.
    let mut pspec_names = Names::new();
    table_names(&PROCESSOR_SPEC, &mut pspec_names, &mut Vec::new());
    assert_eq!(pspec_names.len(), 32);
    assert_eq!(pspec_names.values().map(BTreeSet::len).sum::<usize>(), 70);
}

// ------------------------------------------------- documents from tables

struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Self>,
    text: String,
}

/// A value every reader decodes, so that only the schema decides.
fn sample(element: &str, attr: &str, ty: AttrType) -> &'static str {
    match (ty, element, attr) {
        (AttrType::Boolean, ..) => "true",
        (AttrType::Endian, ..) | (_, "constraint", "endian") => "big",
        (AttrType::SymbolType, ..) => "code",
        _ => "1",
    }
}

/// The fullest valid element for `def`: every attribute, every child once.
/// Where the schema offers a choice the tables cannot express, one branch
/// is taken.
fn full(def: &'static ElementDef, depth: usize) -> Element {
    let attrs = def
        .attrs
        .iter()
        .filter(|a| {
            // <memory_block>: exactly one of three attributes.
            !(def.name == "memory_block"
                && matches!(a.name, "bit_mapped_address" | "byte_mapped_address"))
        })
        .map(|a| (a.name.to_owned(), sample(def.name, a.name, a.ty).to_owned()))
        .collect();
    let children = def
        .children
        .iter()
        // <constresolve>: exactly one of two children.
        .filter(|c| !(def.name == "constresolve" && c.def.name == "varnode"))
        // <constraint> nests without end; three levels show the recursion.
        .filter(|c| !(c.def.name == "constraint" && depth >= 3))
        .map(|c| full(c.def, depth + 1))
        .collect();
    Element {
        name: def.name.to_owned(),
        attrs,
        children,
        text: if def.text {
            "text".to_owned()
        } else {
            String::new()
        },
    }
}

fn write(element: &Element, out: &mut String) {
    write!(out, "<{}", element.name).unwrap();
    for (name, value) in &element.attrs {
        write!(out, " {name}=\"{value}\"").unwrap();
    }
    out.push('>');
    out.push_str(&element.text);
    for child in &element.children {
        write(child, out);
    }
    write!(out, "</{}>", element.name).unwrap();
}

fn render(element: &Element) -> String {
    let mut out = String::new();
    write(element, &mut out);
    out
}

#[test]
fn the_fullest_document_of_each_table_reads() {
    for kind in &KINDS {
        let document = render(&full(kind.root, 0));
        (kind.read)(&document).unwrap_or_else(|e| panic!("{}: {e}\n{document}", kind.schema));
    }
}

#[test]
fn every_shipped_file_reads() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    for kind in &KINDS {
        let files = common::files_with_extension(&ghidra.join("Ghidra"), kind.extension);
        assert_ne!(files, Vec::<std::path::PathBuf>::new());
        for file in files
            .iter()
            .filter(|f| !f.components().any(|c| c.as_os_str() == "test"))
        {
            let text = std::fs::read_to_string(file).unwrap();
            (kind.read)(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

#[test]
fn cardinalities_in_the_tables_are_the_schemas() {
    // Spot checks of what the mutation test proves in bulk, readable as
    // documentation: the tables say how often a child may occur.
    let card = |parent: &'static ElementDef, child: &str| {
        parent.children[parent.child_index(child).unwrap()].card
    };
    assert_eq!(card(&LANGUAGE_DEFINITIONS, "language"), Card::ZeroOrMore);
    let language = LANGUAGE_DEFINITIONS.children[0].def;
    assert_eq!(card(language, "description"), Card::One);
    assert_eq!(card(language, "truncate_space"), Card::Optional);
    assert_eq!(card(language, "compiler"), Card::OneOrMore);
    assert_eq!(card(language, "external_name"), Card::ZeroOrMore);
    assert_eq!(card(&PROCESSOR_SPEC, "segmentop"), Card::ZeroOrMore);
    assert_eq!(card(&PROCESSOR_SPEC, "volatile"), Card::Optional);
    assert!(language.attr("id").unwrap().required);
    assert!(!language.attr("manualindexfile").unwrap().required);
    assert_eq!(language.attr("endian").unwrap().ty, AttrType::Endian);
    assert_eq!(
        language.attr("endian").unwrap().ty.schema_name(),
        Some("endian_type")
    );
}
