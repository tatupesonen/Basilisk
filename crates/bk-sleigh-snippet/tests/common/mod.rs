//! Shared test support: finding the spec root and the reference build,
//! loading languages, extracting the snippets of the shipped specifications
//! and running the `snippetdump` oracle.

#![allow(dead_code, reason = "each test file uses part of this module")]

pub(crate) mod corpus;
pub(crate) mod oracle;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bk_lang::{LanguageId, LanguageRegistry, RegistryBuilder};
use bk_sla::{Limits, Sla};
use bk_testkit::{GhidraDir, ReferenceDir};

/// The Ghidra tree and the reference build, or `None` after printing why the
/// test is skipped.
pub(crate) fn roots() -> Option<(GhidraDir, ReferenceDir)> {
    let ghidra = bk_testkit::skip::require_ghidra()?;
    let reference = bk_testkit::skip::require_reference()?;
    Some((ghidra, reference))
}

/// The `snippetdump` binary of the reference build, or `None` after printing
/// why the test is skipped.
pub(crate) fn snippetdump(reference: &ReferenceDir) -> Option<PathBuf> {
    let path = reference.root().join("bin").join("snippetdump");
    if path.is_file() {
        Some(path)
    } else {
        let line = format!(
            "SKIPPED: {} not built (run scripts/build-reference.sh)\n",
            path.display()
        );
        let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
        None
    }
}

/// A registry over the Ghidra tree with the reference `.sla` overlay.
pub(crate) fn registry(ghidra: &Path, reference: &Path) -> LanguageRegistry {
    RegistryBuilder::default()
        .ghidra_root(ghidra)
        .sla_overlay(reference)
        .build()
        .expect("language registry")
}

/// The compiled language `id`, from the reference overlay.
pub(crate) fn load_sla(registry: &LanguageRegistry, id: &str) -> Option<Arc<Sla>> {
    let id = LanguageId::new(id).ok()?;
    let path = registry.sla_file(&id).ok()??;
    Some(Arc::new(
        Sla::read_file(&path, &Limits::default()).expect("reference .sla reads"),
    ))
}

/// The `.sla` file of reference language `module`/`name` read directly.
pub(crate) fn reference_sla(reference: &ReferenceDir, module: &str, name: &str) -> Option<Sla> {
    let path = reference.sla_file(module, name);
    if !path.is_file() {
        let line = format!("SKIPPED: {} missing\n", path.display());
        let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
        return None;
    }
    Some(Sla::read_file(&path, &Limits::default()).expect("reference .sla reads"))
}
