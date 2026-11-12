//! Helpers shared by the integration tests.

#![allow(dead_code, reason = "each test binary uses a different part")]

use std::path::PathBuf;

/// The Ghidra source tree: `BASILISK_GHIDRA_DIR`, or `../ghidra` beside the
/// repository root (docs/LOOP.md). `None`, with the reason printed, when it
/// is absent. The path is used as spelled (with any `..` in it), never
/// canonicalised or compared as text.
pub(crate) fn ghidra_root() -> Option<PathBuf> {
    let root = match std::env::var_os("BASILISK_GHIDRA_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
    };
    if root.join("Ghidra/Processors").is_dir() {
        Some(root)
    } else {
        eprintln!(
            "skipped: no Ghidra tree at {} (set BASILISK_GHIDRA_DIR)",
            root.display()
        );
        None
    }
}

/// Deterministic pseudo-random bytes (xorshift).
pub(crate) fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 24) as u8
        })
        .collect()
}
