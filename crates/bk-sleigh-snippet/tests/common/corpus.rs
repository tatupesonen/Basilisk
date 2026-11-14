//! The p-code snippets of the shipped specifications: every `<pcode>` and
//! jump-table `*_pcode` element of a `.pspec` or `.cspec`, in document
//! order, with its parameters numbered as `InjectPayload::orderParameters`
//! does (inputs, then outputs).

use std::path::{Path, PathBuf};

use bk_marshal::{Document, ElementRef};
use bk_sleigh_snippet::Parameter;

/// One snippet element.
#[derive(Clone, Debug)]
pub(crate) struct Snippet {
    /// The file it is in.
    pub(crate) file: PathBuf,
    /// The element's name (`pcode`, `case_pcode`, ...).
    pub(crate) element: String,
    /// Byte offset of the element in the file, to tell elements apart.
    pub(crate) offset: usize,
    /// Its parameters.
    pub(crate) params: Vec<Parameter>,
    /// The `<body>` text, verbatim; `None` for a dynamic payload without
    /// one, which Ghidra never compiles.
    pub(crate) body: Option<String>,
    /// Executable p-code (a segment operator or jump-table helper): Ghidra
    /// compiles it at 0x2000 without touching the library's carried base.
    pub(crate) executable: bool,
    /// `dynamic="true"`: Ghidra does not compile it (the Java side injects
    /// it); compiled here for coverage and counted apart.
    pub(crate) dynamic: bool,
}

impl Snippet {
    /// A label for messages: file name and offset.
    pub(crate) fn label(&self) -> String {
        let name = self
            .file
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        format!("{name}@{}:{}", self.offset, self.element)
    }
}

fn is_snippet(name: &str) -> bool {
    name == "pcode" || name.ends_with("_pcode")
}

fn walk(file: &Path, element: ElementRef<'_>, parent: &str, out: &mut Vec<Snippet>) {
    let name = element.name();
    if is_snippet(name) {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut body: Option<String> = None;
        for child in element.children() {
            match child.name() {
                "input" => inputs.push(child.attribute("name").unwrap_or("").to_owned()),
                "output" => outputs.push(child.attribute("name").unwrap_or("").to_owned()),
                "body" => body = Some(child.content().to_owned()),
                _ => {}
            }
        }
        let params = inputs
            .into_iter()
            .chain(outputs)
            .enumerate()
            .map(|(i, n)| Parameter::new(n, i as u32))
            .collect();
        out.push(Snippet {
            file: file.to_path_buf(),
            element: name.to_owned(),
            offset: element.source_offset(),
            params,
            body: body.filter(|b| !b.is_empty()),
            executable: parent == "segmentop" || name != "pcode",
            dynamic: element.attribute("dynamic") == Some("true"),
        });
        return;
    }
    for child in element.children() {
        walk(file, child, name, out);
    }
}

/// The snippets of one specification file, in document order.
pub(crate) fn snippets_of(file: &Path) -> Vec<Snippet> {
    let text = std::fs::read_to_string(file).expect("spec file reads");
    let document = Document::parse(&text).expect("spec file parses");
    let mut out = Vec::new();
    walk(file, document.root(), "", &mut out);
    out
}
