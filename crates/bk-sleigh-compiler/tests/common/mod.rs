//! Helpers shared by the integration tests.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use std::path::{Path, PathBuf};

use bk_sleigh_compiler::{Options, Outcome, elaborate};
use bk_sleigh_syntax::{Defines, FsLoader, Parsed, parse_file};

/// One shipped specification of the reference build.
#[derive(Clone, Debug)]
pub(crate) struct Spec {
    /// The processor module.
    pub(crate) module: String,
    /// The file stem.
    pub(crate) name: String,
    /// The `.slaspec`.
    pub(crate) slaspec: PathBuf,
    /// The compiled `.sla` beside it.
    pub(crate) sla: PathBuf,
}

/// Every specification in the reference overlay, sorted by module and name.
pub(crate) fn reference_specs(reference: &bk_testkit::ReferenceDir) -> Vec<Spec> {
    let files = bk_testkit::corpus::language_files(&reference.processors_dir(), "slaspec").unwrap();
    files
        .into_iter()
        .map(|f| Spec {
            sla: f.path.with_extension("sla"),
            module: f.module,
            name: f.name,
            slaspec: f.path,
        })
        .collect()
}

/// The options the reference build compiled a module with
/// (`.state/lang/<Module>.opts`).
pub(crate) fn module_options(reference: &bk_testkit::ReferenceDir, module: &str) -> Vec<String> {
    let path = reference
        .root()
        .join(".state")
        .join("lang")
        .join(format!("{module}.opts"));
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Parses a specification from disk with no preprocessor definitions (what
/// Ghidra's build passes).
pub(crate) fn parse(path: &Path) -> Parsed {
    parse_file(path, &Defines::new(), &mut FsLoader)
}

/// Parses and elaborates a specification held in memory.
pub(crate) fn elaborate_text(text: &str, options: Options) -> (Parsed, Outcome) {
    let parsed = bk_sleigh_syntax::parse_str("test.slaspec", text, &Defines::new());
    let outcome = elaborate(&parsed, options);
    (parsed, outcome)
}
