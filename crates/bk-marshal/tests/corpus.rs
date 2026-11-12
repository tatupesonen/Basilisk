//! Corpus test: every XML-family file of Ghidra's processor specifications
//! and decompiler data tests parses, walks to the end through the XML
//! decoder, and agrees with an independent parser (`roxmltree`) on its
//! element tree, attributes and text.
//!
//! The Ghidra tree is found through `BASILISK_GHIDRA_DIR`, falling back to
//! `../ghidra` beside the workspace; the tests skip with a printed reason when
//! it is absent.

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

use std::path::{Path, PathBuf};

use bk_marshal::ids::ATTRIB_CONTENT;
use bk_marshal::{DecodeError, Decoder, Document, ElementRef, IdTable, NoSpaces, XmlDecoder};

/// File extensions of Ghidra's XML-family files under `Ghidra/Processors`.
const XML_EXTENSIONS: [&str; 11] = [
    "xml",
    "ldefs",
    "pspec",
    "cspec",
    "opinion",
    "trans",
    "lang",
    "dwarf",
    "info",
    "gdis",
    "ldefs_v01",
];

/// The Ghidra source tree, or `None` (with the reason printed) when absent.
/// `bk-testkit` will own this helper; this is the local stand-in for wave 1.
fn ghidra_dir() -> Option<PathBuf> {
    let dir = match std::env::var_os("BASILISK_GHIDRA_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
    };
    if dir.join("Ghidra/Processors").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "skipped: no Ghidra source tree at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, files);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| XML_EXTENSIONS.contains(&e))
        {
            files.push(path);
        }
    }
}

fn corpus(ghidra: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect(&ghidra.join("Ghidra/Processors"), &mut files);
    collect(
        &ghidra.join("Ghidra/Features/Decompiler/src/decompile/datatests"),
        &mut files,
    );
    files.sort();
    // The pinned Ghidra commit has 501 such files; a tree with far fewer is
    // not the tree this test is about.
    assert!(
        files.len() > 400,
        "only {} XML files under {}",
        files.len(),
        ghidra.display()
    );
    files
}

/// Opens every element, reads every attribute and the content, and closes
/// every element with the strict close. Returns (elements, attributes).
fn walk(decoder: &mut XmlDecoder<'_>) -> Result<(usize, usize), DecodeError> {
    let (mut elements, mut attributes) = (0, 0);
    let mut open = Vec::new();
    loop {
        if let Some(code) = decoder.open_element()? {
            elements += 1;
            while decoder.next_attribute()?.is_some() {
                decoder.read_string()?;
                attributes += 1;
            }
            decoder.read_string_attr(ATTRIB_CONTENT)?;
            open.push(code);
        } else if let Some(code) = open.pop() {
            decoder.close_element(code)?;
        } else {
            return Ok((elements, attributes));
        }
    }
}

#[test]
fn every_spec_file_walks_to_the_end() {
    let Some(ghidra) = ghidra_dir() else { return };
    let ids = IdTable::marshal_only();
    let (mut elements, mut attributes) = (0, 0);
    let files = corpus(&ghidra);
    for path in &files {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let document = Document::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut decoder = XmlDecoder::new(&document, &ids, &NoSpaces);
        let (e, a) = walk(&mut decoder).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(e, document.element_count(), "{}", path.display());
        elements += e;
        attributes += a;
    }
    eprintln!(
        "corpus: {} files, {elements} elements, {attributes} attributes",
        files.len()
    );
}

fn is_white_space(text: &str) -> bool {
    text.bytes()
        .all(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
}

fn without_white_space(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, ' ' | '\n' | '\r' | '\t'))
        .collect()
}

/// Compares one element with `roxmltree`'s view of it. Returns whether the
/// content differs in white space (see the test below).
fn compare(path: &Path, ours: ElementRef<'_>, theirs: roxmltree::Node<'_, '_>) -> bool {
    let at = || format!("{} <{}>", path.display(), ours.name());
    assert_eq!(ours.name(), theirs.tag_name().name(), "{}", at());
    let our_attributes: Vec<(&str, &str)> = ours.attributes().collect();
    let their_attributes: Vec<(&str, &str)> =
        theirs.attributes().map(|a| (a.name(), a.value())).collect();
    assert_eq!(our_attributes, their_attributes, "{}", at());
    // roxmltree merges character data, references and CDATA sections into one
    // text node, so Ghidra's rule (drop each piece that is only white space)
    // can only be approximated from it: drop each *node* that is only white
    // space. The two differ exactly where a white-space piece touches a
    // reference or CDATA section.
    let mut their_content = String::new();
    for child in theirs.children().filter(roxmltree::Node::is_text) {
        let text = child.text().unwrap_or_default();
        if !is_white_space(text) {
            their_content.push_str(text);
        }
    }
    assert_eq!(
        without_white_space(ours.content()),
        without_white_space(&their_content),
        "{}",
        at()
    );
    ours.content() != their_content
}

#[test]
fn agrees_with_an_independent_parser() {
    let Some(ghidra) = ghidra_dir() else { return };
    let files = corpus(&ghidra);
    let mut white_space_differences = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        let ours = Document::parse(&text).unwrap();
        let theirs = roxmltree::Document::parse(&text)
            .unwrap_or_else(|e| panic!("{}: roxmltree: {e}", path.display()));
        let mut pairs = vec![(ours.root(), theirs.root_element())];
        while let Some((our_element, their_element)) = pairs.pop() {
            if compare(path, our_element, their_element) {
                white_space_differences.push(format!(
                    "{} <{}>",
                    path.strip_prefix(&ghidra).unwrap().display(),
                    our_element.name()
                ));
            }
            let our_children: Vec<_> = our_element.children().collect();
            let their_children: Vec<_> = their_element
                .children()
                .filter(roxmltree::Node::is_element)
                .collect();
            assert_eq!(
                our_children.len(),
                their_children.len(),
                "{}",
                path.display()
            );
            pairs.extend(our_children.into_iter().zip(their_children));
        }
    }
    // Where Ghidra's piece rule and a standard parser's text nodes part ways.
    // At the pinned commit these are three elements: one `<com>` in a data
    // test and two `<body>` elements of hexagon.cspec, each with white space
    // between a tag and a CDATA section or reference.
    eprintln!(
        "content differs from roxmltree in white space only: {} element(s)",
        white_space_differences.len()
    );
    for place in &white_space_differences {
        eprintln!("  {place}");
    }
    assert!(
        white_space_differences.len() < 20,
        "{white_space_differences:?}"
    );
}
