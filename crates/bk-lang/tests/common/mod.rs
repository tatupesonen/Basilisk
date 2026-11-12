//! Helpers shared by the integration tests.
//!
//! Local stand-in for the spec-root helper that `bk-testkit` will provide
//! (this crate may not depend on it in wave 1).

#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use bk_lang::LanguageRegistry;

/// The Ghidra tree to read spec files from: `BASILISK_GHIDRA_DIR`, or
/// `../ghidra` beside the workspace. `None`, with the reason printed, when
/// it does not exist — the calling test then skips.
pub(crate) fn ghidra_dir() -> Option<PathBuf> {
    let dir = std::env::var_os(bk_lang::SPEC_ROOT_ENV).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
        PathBuf::from,
    );
    if dir.join("Ghidra/Processors").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "skipping: no Ghidra tree at {} (set {} to one)",
            dir.display(),
            bk_lang::SPEC_ROOT_ENV
        );
        None
    }
}

/// The directory holding Ghidra's RELAX NG schemas.
pub(crate) fn schema_dir(ghidra: &Path) -> PathBuf {
    ghidra.join("Ghidra/Framework/SoftwareModeling/data/languages")
}

/// A strict-mode registry of the whole Ghidra tree, built once per test
/// binary.
pub(crate) fn registry() -> Option<&'static LanguageRegistry> {
    static REGISTRY: OnceLock<Option<LanguageRegistry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let dir = ghidra_dir()?;
            Some(LanguageRegistry::from_ghidra_root(dir).expect("the Ghidra tree scans"))
        })
        .as_ref()
}

/// Every file under `dir` whose name ends with `extension`, sorted.
pub(crate) fn files_with_extension(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.file_name().to_string_lossy().ends_with(extension))
        .map(walkdir::DirEntry::into_path)
        .collect();
    files.sort();
    files
}
