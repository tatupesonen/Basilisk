//! A registry is the same however its root is spelled: with `..`, `.`, a
//! trailing slash or through a symbolic link, every path it reports, and
//! every count, equals what the canonical spelling gives.
//!
//! Before roots were made canonical, a root such as `basilisk/../ghidra`
//! made the registry reach one file under two names (one from the
//! directory walk, one from joining a name to a lexically normalised
//! directory), so a `.pspec` shared by languages from two `.ldefs` files
//! was counted twice and the `.sla` overlay was not found.

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

mod common;

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use bk_lang::LanguageRegistry;
use common::tree::{canonical, tree, write};

/// Everything path-shaped a registry reports, as text.
fn describe(registry: &LanguageRegistry) -> String {
    let mut out = String::new();
    for language in registry.languages() {
        writeln!(out, "{} {:?}", language.id(), language.files()).unwrap();
        for compiler in language.compiler_specs() {
            writeln!(out, "  {} {}", compiler.id, compiler.file.display()).unwrap();
        }
        writeln!(out, "  sla {:?}", registry.sla_file(language.id()).unwrap()).unwrap();
    }
    writeln!(out, "ldefs {:?}", registry.ldefs_files()).unwrap();
    writeln!(out, "opinion {:?}", registry.opinion_files()).unwrap();
    writeln!(
        out,
        "pspec {:?}",
        registry.pspec_files().collect::<Vec<_>>()
    )
    .unwrap();
    writeln!(out, "failures {:?}", registry.failures()).unwrap();
    out
}

/// The ways of spelling an existing directory `root` (whose parent is
/// `parent`) other than the canonical one.
fn spellings(root: &Path) -> Vec<PathBuf> {
    let name = root.file_name().unwrap();
    let parent = root.parent().unwrap();
    let mut slash = root.as_os_str().to_owned();
    slash.push("/");
    vec![
        root.to_owned(),
        parent
            .join("..")
            .join(parent.file_name().unwrap())
            .join(name),
        root.join("."),
        PathBuf::from(slash),
        root.join("Ghidra").join(".."),
    ]
}

fn build(root: &Path, overlay: &Path) -> LanguageRegistry {
    LanguageRegistry::builder()
        .ghidra_root(root)
        .sla_overlay(overlay)
        .build()
        .unwrap()
}

#[test]
fn every_spelling_of_a_root_gives_the_same_registry() {
    let dir = tree();
    let overlay = tempfile::tempdir().unwrap();
    // A compiled file only in the overlay, found through the language's
    // path relative to its root.
    write(
        overlay
            .path()
            .join("Ghidra/Processors/Zeta/data/languages/zeta.sla"),
        "",
    );
    let root = canonical(dir.path());
    let expected = describe(&build(&root, overlay.path()));
    assert!(expected.contains("/Ghidra/Processors/Zeta/data/languages/zeta.sla"));
    // The fixture shares alpha.pspec between a .ldefs beside it and one in
    // a subdirectory, which finds it by name: one file, counted once.
    assert_eq!(build(&root, overlay.path()).pspec_files().count(), 2);

    for spelling in spellings(&root).into_iter().chain([dir.path().to_owned()]) {
        let registry = build(&spelling, overlay.path());
        assert_eq!(
            describe(&registry),
            expected,
            "root spelled {}",
            spelling.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn a_root_reached_through_a_symbolic_link_gives_the_same_registry() {
    let dir = tree();
    let overlay = tempfile::tempdir().unwrap();
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("ghidra-link");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();
    let expected = describe(&build(&canonical(dir.path()), overlay.path()));
    assert_eq!(describe(&build(&link, overlay.path())), expected);
    // A `..` after a link leaves the link's target, as the file system
    // resolves it, not the directory holding the link.
    let through = link.join("Ghidra/Processors/..").join("..");
    assert_eq!(describe(&build(&through, overlay.path())), expected);
}

#[test]
fn every_spelling_of_the_ghidra_tree_gives_the_same_registry() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let empty = tempfile::tempdir().unwrap();
    let root = canonical(&ghidra);
    let canonical_registry = build(&root, empty.path());
    assert_eq!(canonical_registry.languages().len(), 202);
    assert_eq!(canonical_registry.pspec_files().count(), 87);
    let expected = describe(&canonical_registry);
    for spelling in spellings(&root) {
        assert_eq!(
            describe(&build(&spelling, empty.path())),
            expected,
            "root spelled {}",
            spelling.display()
        );
    }
}
