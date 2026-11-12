//! Helpers shared by the integration tests.
//!
//! `bk-testkit` will own the spec-root lookup; until this crate may depend
//! on it, this is a local copy of the rule in `docs/LOOP.md`.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use std::path::{Path, PathBuf};

/// The workspace root (two levels above this crate).
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Ghidra source tree: `BASILISK_GHIDRA_DIR`, or `../ghidra` beside the
/// workspace. Prints why and returns `None` when it is absent, so the
/// calling test can skip.
pub(crate) fn ghidra_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("BASILISK_GHIDRA_DIR")
        .map_or_else(|| workspace_root().join("../ghidra"), PathBuf::from);
    if dir.join("Ghidra/Processors").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "SKIPPED: Ghidra source tree not found at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

/// Every `.slaspec` under `Ghidra/Processors/*/data/languages`, sorted.
pub(crate) fn slaspec_files(ghidra: &Path) -> Vec<PathBuf> {
    let mut specs = Vec::new();
    let processors = ghidra.join("Ghidra/Processors");
    for entry in std::fs::read_dir(&processors).unwrap().flatten() {
        let languages = entry.path().join("data/languages");
        let Ok(files) = std::fs::read_dir(&languages) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().is_some_and(|e| e == "slaspec") {
                specs.push(path);
            }
        }
    }
    specs.sort();
    specs
}

/// Definitions Ghidra's build passes with `-dMODULE`: each processor
/// module's name mapped to its directory.
pub(crate) fn module_defines(ghidra: &Path) -> bk_sleigh_syntax::Defines {
    let mut defines = bk_sleigh_syntax::Defines::new();
    for entry in std::fs::read_dir(ghidra.join("Ghidra/Processors"))
        .unwrap()
        .flatten()
    {
        if entry.path().is_dir() {
            defines.set(
                entry.file_name().to_string_lossy(),
                entry.path().to_string_lossy(),
            );
        }
    }
    defines
}
