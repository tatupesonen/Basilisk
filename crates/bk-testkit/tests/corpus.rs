//! The test kit against the real Ghidra tree: every data test parses, and
//! the corpus is the size the project's inventories say it is.
//!
//! Skipped when the Ghidra tree is absent.

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

use bk_testkit::datatest::{DataTest, read_data_test};

// Sizes for the pinned Ghidra commit (docs/DIRECTION.md, 42db038f3c). A
// change here means the Ghidra tree moved: update the inventories with it.
const DATA_TESTS: usize = 93;
const BYTE_CHUNKS: usize = 181;
const SCRIPT_COMMANDS: usize = 1102;
const STRING_MATCHES: usize = 760;
const SLASPEC_FILES: usize = 150;
const LANGUAGE_DIRS: usize = 39;

#[test]
fn every_data_test_parses() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let files = ghidra.data_tests().unwrap();
    let tests: Vec<(String, DataTest)> = files
        .iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let test = read_data_test(path).unwrap_or_else(|error| panic!("{name}: {error}"));
            (name, test)
        })
        .collect();

    let chunks: usize = tests.iter().map(|(_, test)| test.image.chunks.len()).sum();
    let bytes: usize = tests.iter().map(|(_, test)| test.image.byte_count()).sum();
    let symbols: usize = tests.iter().map(|(_, test)| test.image.symbols.len()).sum();
    let commands: usize = tests.iter().map(|(_, test)| test.script.len()).sum();
    let matches: usize = tests.iter().map(|(_, test)| test.matches.len()).sum();
    let multi_line = tests
        .iter()
        .flat_map(|(_, test)| &test.matches)
        .filter(|check| check.lines.len() > 1)
        .count();
    eprintln!(
        "data tests: {} files, {chunks} byte chunks ({bytes} bytes), {symbols} symbols, \
         {commands} script commands, {matches} string matches ({multi_line} multi-line)",
        tests.len()
    );

    assert_eq!(tests.len(), DATA_TESTS);
    assert_eq!(chunks, BYTE_CHUNKS);
    assert_eq!(commands, SCRIPT_COMMANDS);
    assert_eq!(matches, STRING_MATCHES);

    for (name, test) in &tests {
        assert!(!test.image.arch.is_empty(), "{name}: no architecture");
        assert!(test.image.byte_count() > 0, "{name}: no bytes");
        assert!(!test.script.is_empty(), "{name}: empty script");
        for command in &test.script {
            assert!(
                !command.contains(['\n', '\r']),
                "{name}: line break in {command:?}"
            );
        }
        for check in &test.matches {
            assert!(
                !check.lines.is_empty(),
                "{name}: {} has no pattern",
                check.name
            );
            assert!(
                check.min <= check.max,
                "{name}: {} has min > max",
                check.name
            );
        }
    }
}

/// Writing an image back as XML and reading it again loses nothing, for
/// every image Ghidra ships. This is what lets the console wrapper load a
/// data test's image.
#[test]
fn every_image_survives_a_round_trip() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    for path in ghidra.data_tests().unwrap() {
        let test = read_data_test(&path).unwrap();
        let document = format!(
            "<decompilertest>{}<script><com>quit</com></script>\
             <stringmatch name=\"n\" min=\"1\" max=\"1\">x</stringmatch></decompilertest>",
            test.image.to_xml()
        );
        let reread = bk_testkit::parse_data_test(&document).unwrap();
        assert_eq!(reread.image, test.image, "{}", path.display());
    }
}

#[test]
fn corpus_has_every_language() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let dirs = ghidra.language_dirs().unwrap();
    let specs = ghidra.slaspec_files().unwrap();
    eprintln!(
        "corpus: {} language directories, {} .slaspec files",
        dirs.len(),
        specs.len()
    );
    assert_eq!(dirs.len(), LANGUAGE_DIRS);
    assert_eq!(specs.len(), SLASPEC_FILES);

    for spec in &specs {
        assert_eq!(
            spec.path,
            ghidra
                .language_dir(&spec.module)
                .join(format!("{}.slaspec", spec.name))
        );
    }
    assert!(
        specs
            .iter()
            .any(|spec| spec.module == "x86" && spec.name == "x86-64")
    );
    assert!(
        specs.windows(2).all(|pair| pair[0].path < pair[1].path),
        "sorted by path"
    );
}

/// The overlay has a compiled language for every specification in Ghidra.
#[test]
fn overlay_has_a_sla_for_every_slaspec() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let specs: Vec<_> = ghidra
        .slaspec_files()
        .unwrap()
        .into_iter()
        .map(|spec| (spec.module, spec.name))
        .collect();
    let slas = reference.sla_files().unwrap();
    for sla in &slas {
        let size = std::fs::metadata(&sla.path).unwrap().len();
        assert!(size > 0, "{} is empty", sla.path.display());
    }
    let compiled: Vec<_> = slas.into_iter().map(|sla| (sla.module, sla.name)).collect();
    assert_eq!(compiled, specs);
}
