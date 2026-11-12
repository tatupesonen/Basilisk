//! The readers' strict mode against Ghidra's RELAX NG schemas.
//!
//! `bk_lang::schema` restates the three `.rxg` grammars as tables. These
//! tests check the restatement with a real RELAX NG validator
//! (`oxixml-relaxng`) loaded with Ghidra's own schema files:
//!
//! * every name the schemas define is in the tables, and the reverse;
//! * a document built from the tables with every element and attribute is
//!   valid, and reads;
//! * for every single-step mutation of that document — an attribute or
//!   child dropped, repeated, misplaced, mistyped or invented — the strict
//!   reader and the validator agree on whether it is acceptable;
//! * every file Ghidra ships validates.
//!
//! Skipped without a Ghidra tree.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::Path,
};

use bk_lang::{
    Mode, ParseError, ParseErrorKind, ldefs, opinion, pspec,
    schema::{AttrType, Card, ElementDef, LANGUAGE_DEFINITIONS, OPINIONS, PROCESSOR_SPEC},
};
use oxixml_relaxng::RelaxNg;

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

fn validator(ghidra: &Path, kind: &Kind) -> RelaxNg {
    RelaxNg::from_file(common::schema_dir(ghidra).join(kind.schema))
        .unwrap_or_else(|e| panic!("{}: {e}", kind.schema))
}

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

#[derive(Clone)]
struct Element {
    def: &'static ElementDef,
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
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
        def,
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

/// Every element of the tree, as the path of child indices leading to it.
fn paths(element: &Element, here: &mut Vec<usize>, all: &mut Vec<Vec<usize>>) {
    all.push(here.clone());
    for (i, child) in element.children.iter().enumerate() {
        here.push(i);
        paths(child, here, all);
        here.pop();
    }
}

fn at<'a>(root: &'a mut Element, path: &[usize]) -> &'a mut Element {
    path.iter()
        .fold(root, |element, i| &mut element.children[*i])
}

/// Every single-step mutation of the element at `path`, described.
fn mutations(root: &Element, path: &[usize]) -> Vec<(String, Element)> {
    let mut out = Vec::new();
    let mut mutate = |what: String, change: &dyn Fn(&mut Element)| {
        let mut copy = root.clone();
        change(at(&mut copy, path));
        out.push((what, copy));
    };
    let mut probe = root.clone();
    let target = at(&mut probe, path).clone();
    let name = &target.name;

    for (i, (attr, _)) in target.attrs.iter().enumerate() {
        mutate(format!("<{name}> without {attr}"), &|e| {
            e.attrs.remove(i);
        });
        mutate(format!("<{name}> with {attr}=\"maybe\""), &|e| {
            e.attrs[i].1 = "maybe".into();
        });
        mutate(format!("<{name}> with {attr}=\"\""), &|e| {
            e.attrs[i].1 = String::new();
        });
    }
    for missing in target
        .def
        .attrs
        .iter()
        .filter(|a| !target.attrs.iter().any(|(n, _)| n == a.name))
    {
        let value = sample(name, missing.name, missing.ty);
        mutate(format!("<{name}> with also {}", missing.name), &|e| {
            e.attrs.push((missing.name.to_owned(), value.to_owned()));
        });
    }
    mutate(format!("<{name}> with an unknown attribute"), &|e| {
        e.attrs.push(("bogus".into(), "1".into()));
    });
    for i in 0..target.children.len() {
        let child = &target.children[i].name;
        mutate(format!("<{name}> without <{child}>"), &|e| {
            e.children.remove(i);
        });
        mutate(format!("<{name}> with <{child}> twice"), &|e| {
            let copy = e.children[i].clone();
            e.children.insert(i, copy);
        });
        mutate(format!("<{name}> with <{child}> moved last"), &|e| {
            let moved = e.children.remove(i);
            e.children.push(moved);
        });
        mutate(format!("<{name}> with <{child}> moved first"), &|e| {
            let moved = e.children.remove(i);
            e.children.insert(0, moved);
        });
    }
    for missing in target
        .def
        .children
        .iter()
        .filter(|c| !target.children.iter().any(|e| e.name == c.def.name))
    {
        mutate(format!("<{name}> with also <{}>", missing.def.name), &|e| {
            e.children.push(full(missing.def, 9));
        });
    }
    mutate(format!("<{name}> with only its last child"), &|e| {
        e.children.drain(..e.children.len().saturating_sub(1));
    });
    mutate(format!("<{name}> with no children"), &|e| {
        e.children.clear();
    });
    mutate(format!("<{name}> with an unknown child"), &|e| {
        let mut bogus = e.clone();
        bogus.name = "bogus".into();
        bogus.attrs.clear();
        bogus.children.clear();
        e.children.push(bogus);
    });
    mutate(format!("<{name}> with text"), &|e| e.text = "stray".into());
    mutate(format!("<{name}> with white space"), &|e| {
        e.text = " \n\t".into();
    });
    mutate(format!("<{name}> renamed"), &|e| e.name = "bogus".into());
    out
}

#[test]
fn strict_reader_and_validator_agree_on_every_mutation() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    for kind in &KINDS {
        let schema = validator(&ghidra, kind);
        let root = full(kind.root, 0);
        let document = render(&root);
        assert!(
            schema.validate(&document).is_ok(),
            "{}: the full document is valid",
            kind.schema
        );
        (kind.read)(&document).unwrap_or_else(|e| panic!("{}: {e}\n{document}", kind.schema));

        let mut all = Vec::new();
        paths(&root, &mut Vec::new(), &mut all);
        let (mut total, mut rejected, mut undecodable) = (0, 0, 0);
        let mut disagreements = Vec::new();
        for path in &all {
            for (what, mutated) in mutations(&root, path) {
                let text = render(&mutated);
                let valid = schema.validate(&text).is_ok();
                let read = (kind.read)(&text);
                total += 1;
                rejected += usize::from(!valid);
                // The reader may also refuse a schema-valid document whose
                // values it cannot decode (size="maybe"); Ghidra's reader
                // throws on those too. Anything else must agree.
                let decode_failure = matches!(
                    &read,
                    Err(e) if matches!(
                        e.kind,
                        ParseErrorKind::InvalidValue { .. } | ParseErrorKind::Rejected { .. }
                    )
                );
                undecodable += usize::from(valid && decode_failure);
                if valid != read.is_ok() && !(valid && decode_failure) {
                    disagreements.push(format!("{what}: schema valid={valid}, reader {read:?}"));
                }
            }
        }
        eprintln!(
            "{}: {} elements, {total} mutations ({rejected} invalid, {undecodable} valid but undecodable)",
            kind.schema,
            all.len()
        );
        assert!(
            disagreements.is_empty(),
            "{}:\n{}",
            kind.schema,
            disagreements.join("\n")
        );
        assert!(
            rejected >= 16 && total > 100,
            "the mutations exercise the schema"
        );
    }
}

#[test]
fn every_shipped_file_validates_and_reads() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    for kind in &KINDS {
        let schema = validator(&ghidra, kind);
        let files = common::files_with_extension(&ghidra.join("Ghidra"), kind.extension);
        assert!(!files.is_empty());
        for file in files
            .iter()
            .filter(|f| !f.components().any(|c| c.as_os_str() == "test"))
        {
            let text = std::fs::read_to_string(file).unwrap();
            if let Err(errors) = schema.validate(&text) {
                panic!("{} violates {}: {}", file.display(), kind.schema, errors[0]);
            }
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
