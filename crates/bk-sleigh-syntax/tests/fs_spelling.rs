//! The file-system loader reaches a specification, and recognises a file it
//! has already read, however the path is spelled: with `.` and `..`,
//! relative to a symbolic link (on macOS the temporary directory is one),
//! and on Windows in verbatim form (`\\?\C:\…`), with a lower-case drive
//! letter or with `/` separators.

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

use bk_sleigh_syntax::{Defines, FsLoader, preprocess};
use tempfile::TempDir;

/// `a.slaspec` includes `t.sinc` under two spellings and `self.sinc`,
/// which includes itself.
fn tree() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| std::fs::write(dir.path().join(name), text).unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    write(
        "a.slaspec",
        "@include \"t.sinc\"\n@include \"sub/../t.sinc\"\n@include \"self.sinc\"\n",
    );
    write("t.sinc", "t\n");
    write("self.sinc", "s\n@include \"./self.sinc\"\n");
    dir
}

/// What preprocessing the specification at `path` gives: the non-empty
/// output lines, the number of files read and the number of errors.
fn outcome(path: &Path) -> (Vec<String>, usize, usize) {
    let p = preprocess(path, &Defines::new(), &mut FsLoader);
    let lines = p
        .sources
        .text()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.replace('\u{8}', ""))
        .collect();
    (lines, p.sources.files().len(), p.diagnostics.len())
}

fn expected() -> (Vec<String>, usize, usize) {
    (vec!["t".into(), "t".into(), "s".into()], 3, 1)
}

#[test]
fn every_spelling_of_a_specification_reads_the_same() {
    let dir = tree();
    let canonical = dir.path().canonicalize().unwrap();
    let spellings: Vec<PathBuf> = vec![
        canonical.join("a.slaspec"),
        dir.path().join("a.slaspec"),
        dir.path().join(".").join("a.slaspec"),
        dir.path().join("sub").join("..").join("a.slaspec"),
    ];
    for path in spellings {
        assert_eq!(outcome(&path), expected(), "{}", path.display());
    }
}

#[cfg(windows)]
#[test]
fn every_windows_spelling_of_a_specification_reads_the_same() {
    let dir = tree();
    let canonical = dir.path().canonicalize().unwrap();
    let verbatim = canonical.to_str().unwrap().to_owned();
    // A canonical path on Windows is verbatim: `\\?\C:\…`.
    let plain = verbatim.strip_prefix(r"\\?\").unwrap().to_owned();
    assert_eq!(plain.as_bytes()[1], b':', "{plain}");
    let lower = plain.get(..1).unwrap().to_ascii_lowercase() + plain.get(1..).unwrap();
    let spellings = [
        format!(r"{verbatim}\a.slaspec"),
        format!(r"{plain}\a.slaspec"),
        format!(r"{lower}\a.slaspec"),
        format!(r"\\?\{lower}\a.slaspec"),
        format!("{}/a.slaspec", plain.replace('\\', "/")),
        format!(r"{verbatim}\sub\..\.\a.slaspec"),
        format!("{verbatim}/sub/../a.slaspec"),
    ];
    for path in spellings {
        assert_eq!(outcome(Path::new(&path)), expected(), "{path}");
    }
}
