//! Port of `ghidra.sleigh.grammar.SleighPreprocessorTest` and of
//! `SourceFileIndexerTest`.
//!
//! `SleighPreprocessorTest.testExternal` preprocesses every `*.input` file
//! in `SoftwareModeling/src/test/resources` with `REPLACE` defined as
//! `includes` and compares the result, line by line, with the matching
//! `*.output` file. The expected files are in Ghidra's marker format
//! (`\bfile###line\b`, `\b$(NAME)\b`); `SourceMap::to_ghidra_text` renders
//! basilisk's result in that format. The files are read in place from the
//! Ghidra tree (ADR-002) and the test skips when the tree is absent.

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

use bk_sleigh_syntax::{Defines, FsLoader, SourceFileIndexer, preprocess};

#[test]
fn sleigh_preprocessor_test_external() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let resources = ghidra.join("Ghidra/Framework/SoftwareModeling/src/test/resources");
    let mut inputs = Vec::new();
    let mut targets = Vec::new();
    for entry in std::fs::read_dir(&resources).unwrap().flatten() {
        let path = entry.path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("input") => inputs.push(path),
            Some("output") => targets.push(path),
            _ => {}
        }
    }
    inputs.sort();
    targets.sort();
    assert!(
        !inputs.is_empty(),
        "found 0 test input files in {}",
        resources.display()
    );
    assert_eq!(inputs.len(), targets.len(), "# inputs != # targets");

    let defines = Defines::new().with("REPLACE", "includes");
    for (input, target) in inputs.iter().zip(&targets) {
        assert_eq!(
            input.file_stem(),
            target.file_stem(),
            "inputs and targets pair up by name"
        );
        let result = preprocess(input, &defines, &mut FsLoader);
        let name = input.file_name().unwrap().to_string_lossy();
        assert!(
            result.diagnostics.is_empty(),
            "{name}: {:?}",
            result
                .diagnostics
                .iter()
                .map(|d| result.sources.render(d))
                .collect::<Vec<_>>()
        );
        let actual = result.sources.to_ghidra_text();
        let expected = std::fs::read_to_string(target).unwrap();
        let actual_lines: Vec<&str> = actual.lines().collect();
        let expected_lines: Vec<&str> = expected.lines().collect();
        for (i, (a, e)) in actual_lines.iter().zip(&expected_lines).enumerate() {
            assert_eq!(a, e, "{name}: difference at line {}", i + 1);
        }
        assert_eq!(
            actual_lines.len(),
            expected_lines.len(),
            "{name}: line count"
        );
    }
    eprintln!(
        "compared {} preprocessor inputs with Ghidra's expected outputs",
        inputs.len()
    );
}

/// `SourceFileIndexerTest.basicTest`: a file gets one index however many
/// locations in it are indexed, and distinct files get distinct indices.
/// (Ghidra's test also feeds a null location and a null file name; neither
/// can be expressed here.)
#[test]
fn source_file_indexer_basic_test() {
    let mut indexer = SourceFileIndexer::new();
    indexer.index("file1");
    indexer.index("file1");
    indexer.index("file3");
    let ret2_1 = indexer.index("file2");
    indexer.index("file3");
    let ret2_2 = indexer.index("file2");
    assert_eq!(ret2_1, ret2_2);

    let file1 = indexer.get_index("file1").unwrap();
    let file2 = indexer.get_index("file2").unwrap();
    let file3 = indexer.get_index("file3").unwrap();
    assert_eq!(file2, ret2_1);
    assert_ne!(file1, file2);
    assert_ne!(file1, file3);
    assert_ne!(file2, file3);

    // Indices are dense, in order of first use, and map back to names.
    assert_eq!((file1, file3, file2), (0, 1, 2));
    assert_eq!(indexer.file_name(file3), Some("file3"));
    assert_eq!(indexer.file_name(3), None);
    assert_eq!(indexer.get_index("file4"), None);
    assert_eq!(
        indexer.iter().collect::<Vec<_>>(),
        ["file1", "file3", "file2"]
    );
    assert_eq!(indexer.len(), 3);
}
