//! Real ELF files: Ghidra's (referenced in place) and the fixtures produced
//! by clang and lld in `tests/fixtures` (see its README).

use std::path::{Path, PathBuf};

/// The Ghidra tree, or `None` with a printed reason.
pub fn ghidra_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("BASILISK_GHIDRA_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
        PathBuf::from,
    );
    if dir.is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "skipping Ghidra's files: tree not found at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

/// Every file with the ELF magic under the directories the spec names.
pub fn ghidra_elf_files(ghidra: &Path) -> Vec<PathBuf> {
    elf_files_under(&[
        ghidra.join("GPL/GnuDisassembler/data"),
        ghidra.join("GhidraDocs/GhidraClass/ExerciseFiles"),
    ])
}

/// The checked-in fixture directory.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The bytes of fixture `name`.
pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir().join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// Every ELF fixture.
pub fn fixture_files() -> Vec<PathBuf> {
    elf_files_under(&[fixture_dir()])
}

fn elf_files_under(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = dirs.to_vec();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if std::fs::read(&path).is_ok_and(|b| b.starts_with(b"\x7fELF")) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}
