//! Building a registry from module trees: Ghidra's search order, file
//! resolution, and what happens when files are missing or wrong.

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

use std::path::Path;

use bk_lang::{LanguageRegistry, LoadFailure, Mode, RegistryError};
use common::tree::{canonical, id, ids, language, ldefs, registry, tree, write};

#[test]
fn languages_load_in_ghidras_order() {
    let dir = tree();
    let registry = registry(&dir);
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    // Modules by name (code-point order: "Zeta" < "alpha"); within a
    // module, files by path ("a/nested.ldefs" < "b.ldefs"); then file order.
    assert_eq!(
        ids(&registry),
        [
            "Zeta:BE:32:default",
            "Zeta:BE:32:old",
            "Alpha:LE:32:wide",
            "Alpha:LE:16:default",
            "Alpha:BE:16:default"
        ]
    );
    assert_eq!(registry.processors().collect::<Vec<_>>(), ["Zeta", "Alpha"]);
    assert_eq!(registry.ldefs_files().len(), 3);
    assert_eq!(registry.opinion_files().len(), 1);
    assert_eq!(registry.pspec_files().count(), 2);
}

#[test]
fn files_resolve_beside_the_ldefs_or_by_name_across_modules() {
    let dir = tree();
    let registry = registry(&dir);
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    let nested = registry.find("Alpha:LE:32:wide").unwrap();
    assert_eq!(nested.files().ldefs, languages.join("a/nested.ldefs"));
    assert_eq!(nested.files().pspec, languages.join("alpha.pspec"));
    assert_eq!(nested.files().slaspec, languages.join("alpha.slaspec"));
    assert_eq!(
        nested.files().sla,
        languages.join("alpha.sla"),
        "expected beside the .slaspec"
    );
    assert_eq!(
        nested.compiler_specs()[0].file,
        languages.join("alpha.cspec")
    );
    assert_eq!(nested.files().manual_index, None);
    // slafile="alpha" (no extension) names the same files.
    assert_eq!(
        registry
            .find("Alpha:LE:16:default")
            .unwrap()
            .files()
            .slaspec,
        languages.join("alpha.slaspec")
    );
}

#[test]
fn a_name_found_in_several_modules_resolves_to_the_first_module() {
    // SleighLanguageFile.findFile: when the file is not beside the .ldefs
    // and several modules hold a file of that name, Ghidra takes the first
    // one found, as long as the path it looked for ends with the name minus
    // its leading relative part (which, for a name written in the
    // definition, it always does).
    let dir = tempfile::tempdir().unwrap();
    let processors = canonical(dir.path()).join("Ghidra/Processors");
    for module in ["Gamma", "Beta"] {
        write(processors.join(module).join("Module.manifest"), "");
        write(
            processors.join(module).join("data/languages/shared.cspec"),
            "",
        );
    }
    let omega = processors.join("Omega");
    write(omega.join("Module.manifest"), "");
    let languages = omega.join("data/languages");
    write(
        languages.join("omega.ldefs"),
        &ldefs(&[
            language(
                "Omega:LE:32:plain",
                "",
                "omega.sla",
                "omega.pspec",
                &[("default", "shared.cspec")],
            ),
            language(
                "Omega:LE:32:relative",
                "",
                "omega.sla",
                "omega.pspec",
                &[("default", "../../../Gamma/data/languages/shared.cspec")],
            ),
            language(
                "Omega:LE:32:dotted",
                "",
                "omega.sla",
                "omega.pspec",
                &[("default", "./shared.cspec")],
            ),
            // A name with a directory that does not exist beside the
            // definition: found by file name, on Windows too, where the
            // path searched for is spelled with `\`.
            language(
                "Omega:LE:32:subdir",
                "",
                "omega.sla",
                "omega.pspec",
                &[("default", "nowhere/shared.cspec")],
            ),
        ]),
    );
    write(languages.join("omega.slaspec"), "");
    write(languages.join("omega.pspec"), "<processor_spec/>");

    let registry = registry(&dir);
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    let beta = processors.join("Beta/data/languages/shared.cspec");
    let gamma = processors.join("Gamma/data/languages/shared.cspec");
    let cspec = |id: &str| registry.find(id).unwrap().compiler_specs()[0].file.clone();
    // Not beside the definition: the first module in name order wins.
    assert_eq!(cspec("Omega:LE:32:plain"), beta);
    assert_eq!(cspec("Omega:LE:32:dotted"), beta);
    assert_eq!(cspec("Omega:LE:32:subdir"), beta);
    // A relative path that exists is taken as written.
    assert_eq!(cspec("Omega:LE:32:relative"), gamma);
}

#[test]
fn a_language_with_a_missing_file_is_reported_and_left_out() {
    let dir = tree();
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    write(
        languages.join("c.ldefs"),
        &ldefs(&[
            language(
                "Alpha:LE:8:nocspec",
                "",
                "alpha.sla",
                "alpha.pspec",
                &[("default", "missing.cspec")],
            ),
            language(
                "Alpha:LE:8:nopspec",
                "",
                "alpha.sla",
                "missing.pspec",
                &[("default", "alpha.cspec")],
            ),
            language(
                "Alpha:LE:8:nosla",
                "",
                "missing.sla",
                "alpha.pspec",
                &[("default", "alpha.cspec")],
            ),
            // Letter case must match the file's, on any file system.
            language(
                "Alpha:LE:8:case",
                "",
                "alpha.sla",
                "Alpha.pspec",
                &[("default", "alpha.cspec")],
            ),
            language(
                "Alpha:LE:8:nomanual",
                "manualindexfile=\"../manuals/alpha.idx\"",
                "alpha.sla",
                "alpha.pspec",
                &[("default", "alpha.cspec")],
            ),
            language(
                "Alpha:LE:8:fine",
                "",
                "alpha.sla",
                "alpha.pspec",
                &[("default", "alpha.cspec")],
            ),
        ]),
    );
    let registry = registry(&dir);
    let failures: Vec<String> = registry
        .failures()
        .iter()
        .map(|f| {
            f.to_string()
                .replace(&languages.display().to_string(), "<dir>")
                .replace(&languages.parent().unwrap().display().to_string(), "<data>")
        })
        .collect();
    // Expected paths are built from `Path` values: the registry reports a
    // path as the operating system spells it (with `\` on Windows).
    let in_dir = |name: &str| Path::new("<dir>").join(name).display().to_string();
    let ldefs_file = in_dir("c.ldefs");
    let manual = Path::new("<data>").join("manuals").join("alpha.idx");
    assert_eq!(
        failures,
        [
            format!(
                "language Alpha:LE:8:nocspec in {ldefs_file}: missing sleigh file(.cspec): {}",
                in_dir("missing.cspec")
            ),
            format!(
                "language Alpha:LE:8:nopspec in {ldefs_file}: missing sleigh file(.pspec): {}",
                in_dir("missing.pspec")
            ),
            format!(
                "language Alpha:LE:8:nosla in {ldefs_file}: missing sleigh file(.slaspec): {}",
                in_dir("missing.slaspec")
            ),
            format!(
                "language Alpha:LE:8:case in {ldefs_file}: missing sleigh file(.pspec): {}",
                in_dir("Alpha.pspec")
            ),
            format!(
                "language Alpha:LE:8:nomanual: missing manual index {}",
                manual.display()
            ),
        ]
    );
    // The language without a manual and the one after the failures exist.
    assert!(registry.find("Alpha:LE:8:nocspec").is_none());
    assert!(registry.find("Alpha:LE:8:case").is_none());
    assert_eq!(
        registry
            .find("Alpha:LE:8:nomanual")
            .unwrap()
            .files()
            .manual_index,
        None
    );
    assert!(registry.find("Alpha:LE:8:fine").is_some());
}

#[test]
fn a_compiled_sla_without_source_still_describes_the_language() {
    // Ghidra falls back to the .sla when there is no .slaspec, so that the
    // language can be described (loading it is another matter).
    let dir = tree();
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    write(languages.join("binary.sla"), "");
    write(
        languages.join("c.ldefs"),
        &ldefs(&[language(
            "Alpha:LE:8:binary",
            "",
            "binary.sla",
            "alpha.pspec",
            &[("default", "alpha.cspec")],
        )]),
    );
    let registry = registry(&dir);
    assert!(registry.failures().is_empty());
    let files = registry.find("Alpha:LE:8:binary").unwrap().files();
    assert_eq!(files.sla, languages.join("binary.sla"));
    assert_eq!(files.slaspec, languages.join("binary.slaspec"));
    assert!(!files.slaspec.exists());
    assert_eq!(
        registry.sla_file(&id("Alpha:LE:8:binary")).unwrap(),
        Some(languages.join("binary.sla"))
    );
}

#[test]
fn a_repeated_language_id_is_reported_and_the_later_definition_takes_its_place() {
    let dir = tree();
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    write(
        languages.join("z.ldefs"),
        &ldefs(&[language(
            "Zeta:BE:32:default",
            "",
            "alpha.sla",
            "alpha.pspec",
            &[("other", "alpha.cspec")],
        )]),
    );
    let registry = registry(&dir);
    assert_eq!(
        ids(&registry)[0],
        "Zeta:BE:32:default",
        "the id keeps its first position"
    );
    assert_eq!(registry.languages().len(), 5);
    let kept = registry.find("Zeta:BE:32:default").unwrap();
    assert_eq!(kept.files().ldefs, languages.join("z.ldefs"));
    assert_eq!(kept.compiler_specs()[0].id.as_str(), "other");
    assert!(
        matches!(registry.failures(), [LoadFailure::DuplicateLanguage { language, .. }] if language.as_str() == "Zeta:BE:32:default")
    );
}

#[test]
fn an_invalid_ldefs_file_is_skipped_whole_in_strict_mode() {
    let dir = tree();
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    write(
        languages.join("c.ldefs"),
        &ldefs(&[language(
            "Alpha:LE:8:extra",
            "colour=\"red\"",
            "alpha.sla",
            "alpha.pspec",
            &[("default", "alpha.cspec")],
        )]),
    );
    let strict = registry(&dir);
    assert!(strict.find("Alpha:LE:8:extra").is_none());
    let [LoadFailure::LanguageDefinitions(error)] = strict.failures() else {
        panic!("one failure")
    };
    assert!(
        error
            .to_string()
            .contains("attribute \"colour\" is not allowed on <language>"),
        "{error}"
    );
    assert_eq!(strict.languages().len(), 5, "the other files still load");

    let lenient = LanguageRegistry::builder()
        .ghidra_root(dir.path())
        .mode(Mode::Lenient)
        .build()
        .unwrap();
    assert!(lenient.failures().is_empty());
    assert!(lenient.find("Alpha:LE:8:extra").is_some());
}

#[test]
fn hidden_languages_need_to_be_asked_for() {
    let dir = tree();
    let languages = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages");
    write(
        languages.join("c.ldefs"),
        // Ghidra skips a hidden language before looking at its files.
        &ldefs(&[language(
            "Alpha:LE:8:hidden",
            "hidden=\"true\"",
            "alpha.sla",
            "alpha.pspec",
            &[("default", "alpha.cspec")],
        )]),
    );
    assert!(registry(&dir).find("Alpha:LE:8:hidden").is_none());
    let with_hidden = LanguageRegistry::builder()
        .ghidra_root(dir.path())
        .include_hidden(true)
        .build()
        .unwrap();
    assert!(with_hidden.find("Alpha:LE:8:hidden").is_some());
}

#[test]
fn search_skips_what_ghidra_skips_and_includes_build_output() {
    let dir = tree();
    let alpha = canonical(dir.path()).join("Ghidra/Processors/alpha");
    let extra = |variant: &str| {
        ldefs(&[language(
            &format!("Alpha:LE:8:{variant}"),
            "",
            "alpha.sla",
            "alpha.pspec",
            &[("default", "alpha.cspec")],
        )])
    };
    write(alpha.join("data/test/skipped.ldefs"), &extra("in-test-dir"));
    write(
        alpha.join("data/ignored/skipped.ldefs"),
        &extra("in-manifest-ignored-dir"),
    );
    write(
        alpha.join("data/languages/._fork.ldefs"),
        &extra("resource-fork"),
    );
    write(alpha.join("src/data/skipped.ldefs"), &extra("outside-data"));
    write(
        alpha.join("build/data/languages/built.ldefs"),
        &extra("built"),
    );
    // Not a module: no Module.manifest.
    write(
        dir.path()
            .join("Ghidra/Processors/loose/data/languages/loose.ldefs"),
        &extra("no-manifest"),
    );
    // A module four levels down is too deep; three is the limit.
    write(dir.path().join("Ghidra/a/b/c/deep/Module.manifest"), "");
    write(
        dir.path().join("Ghidra/a/b/c/deep/data/deep.ldefs"),
        &extra("too-deep"),
    );
    write(dir.path().join("Ghidra/a/b/ok/Module.manifest"), "");
    write(
        dir.path().join("Ghidra/a/b/ok/data/ok.ldefs"),
        &extra("depth-three"),
    );
    // GPL modules sit beside the Ghidra directory.
    write(dir.path().join("GPL/Gnu/Module.manifest"), "");
    write(dir.path().join("GPL/Gnu/data/gnu.ldefs"), &extra("gpl"));

    let registry = registry(&dir);
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    let extra: Vec<&str> = ids(&registry)
        .into_iter()
        .filter(|id| id.starts_with("Alpha:LE:8:"))
        .collect();
    // "Gnu" < "Zeta" < "alpha" < "ok"; a module's build/data follows its data.
    assert_eq!(
        extra,
        [
            "Alpha:LE:8:gpl",
            "Alpha:LE:8:built",
            "Alpha:LE:8:depth-three"
        ]
    );
}

#[test]
fn a_user_module_can_be_added_beside_a_ghidra_root() {
    let dir = tree();
    let user = tempfile::tempdir().unwrap();
    let module = user.path().join("MyProcessor");
    write(
        module.join("data/languages/mine.ldefs"),
        // Its .pspec is found by name in the Ghidra tree.
        &ldefs(&[language(
            "Mine:LE:16:default",
            "",
            "mine.sla",
            "zeta.pspec",
            &[("default", "mine.cspec")],
        )]),
    );
    write(module.join("data/languages/mine.slaspec"), "");
    write(module.join("data/languages/mine.cspec"), "");
    let registry = LanguageRegistry::builder()
        .ghidra_root(dir.path())
        .module(&module)
        .build()
        .unwrap();
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    // "MyProcessor" sorts first.
    assert_eq!(ids(&registry)[0], "Mine:LE:16:default");
    let mine = registry.find("Mine:LE:16:default").unwrap();
    assert!(
        mine.files()
            .pspec
            .ends_with("Zeta/data/languages/zeta.pspec")
    );

    // Alone, the module's language lacks its .pspec.
    let alone = LanguageRegistry::builder().module(&module).build().unwrap();
    assert!(alone.languages().is_empty());
    assert!(matches!(
        alone.failures(),
        [LoadFailure::MissingFile {
            extension: ".pspec",
            ..
        }]
    ));
}

#[test]
fn building_fails_only_for_unusable_roots() {
    let empty = tempfile::tempdir().unwrap();
    let error = LanguageRegistry::from_ghidra_root(empty.path()).unwrap_err();
    assert!(matches!(error, RegistryError::Scan { .. }), "{error}");
    assert!(error.to_string().contains("not a directory"));

    let dir = tree();
    write(dir.path().join("Ghidra/Features/Zeta/Module.manifest"), "");
    let error = LanguageRegistry::from_ghidra_root(dir.path()).unwrap_err();
    assert!(
        matches!(&error, RegistryError::DuplicateModule { name, .. } if name == "Zeta"),
        "{error}"
    );

    assert!(
        LanguageRegistry::builder()
            .build()
            .unwrap()
            .languages()
            .is_empty()
    );
}

#[test]
fn compiled_sla_is_found_beside_the_source_or_in_an_overlay() {
    let dir = tree();
    let overlay = tempfile::tempdir().unwrap();
    let registry = LanguageRegistry::builder()
        .ghidra_root(dir.path())
        .sla_overlay(overlay.path())
        .build()
        .unwrap();
    let zeta = id("Zeta:BE:32:default");
    assert_eq!(registry.sla_file(&zeta).unwrap(), None);

    // The overlay mirrors the root's layout.
    let in_overlay =
        canonical(overlay.path()).join("Ghidra/Processors/Zeta/data/languages/zeta.sla");
    write(&in_overlay, "");
    assert_eq!(registry.sla_file(&zeta).unwrap(), Some(in_overlay));

    // A .sla beside the .slaspec wins, and is seen without rebuilding.
    let beside = canonical(dir.path()).join("Ghidra/Processors/Zeta/data/languages/zeta.sla");
    write(&beside, "");
    assert_eq!(registry.sla_file(&zeta).unwrap(), Some(beside));
    assert!(matches!(
        registry.sla_file(&id("No:LE:8:such")),
        Err(RegistryError::LanguageNotFound(_))
    ));
}

#[test]
fn processor_specs_are_read_on_demand_not_at_scan() {
    let dir = tree();
    let pspec = canonical(dir.path()).join("Ghidra/Processors/alpha/data/languages/alpha.pspec");
    write(&pspec, "<processor_spec><bogus/></processor_spec>");
    let registry = registry(&dir);
    assert!(
        registry.failures().is_empty(),
        "scanning does not open .pspec files"
    );

    let zeta = registry.processor_spec(&id("Zeta:BE:32:default")).unwrap();
    assert_eq!(zeta.program_counter.as_deref(), Some("PC"));
    let error = registry
        .processor_spec(&id("Alpha:LE:16:default"))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "processor spec of 'Alpha:LE:16:default': {}: line 1, column 17: element <bogus> is not allowed in <processor_spec>",
            pspec.display()
        )
    );
    // The failure is cached too: fixing the file needs a new registry.
    write(&pspec, "<processor_spec/>");
    assert!(registry.processor_spec(&id("Alpha:BE:16:default")).is_err());
}

#[test]
fn registry_is_shareable_between_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LanguageRegistry>();
    let dir = tree();
    let registry = registry(&dir);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                assert!(registry.processor_spec(&id("Zeta:BE:32:default")).is_ok());
                assert_eq!(
                    registry
                        .query_opinions("Test Loader", Some("7"), None)
                        .len(),
                    2
                );
            });
        }
    });
}
