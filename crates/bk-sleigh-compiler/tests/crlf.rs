//! Line endings and path spellings do not change the result (spec 4.6,
//! ADR-022): every diagnostic case, read with CRLF line endings and from a
//! directory spelled differently, gives the same diagnostics (text, line,
//! inner location) and the same canonical form as with LF.

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

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use bk_sleigh_compiler::{Options, canon, elaborate};
use bk_sleigh_syntax::{Defines, MemoryLoader, parse_file};

fn cases_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("diagnostics")
}

/// Elaborates `case` with its prelude, both converted by `convert`, from
/// the directory `dir`; renders diagnostics and the canonical form.
fn run(dir: &Path, case: &str, text: &str, prelude: &str, convert: fn(&str) -> String) -> String {
    let mut loader = MemoryLoader::new()
        .with(dir.join(case), convert(text))
        .with(dir.join("prelude.sinc"), convert(prelude));
    let parsed = parse_file(&dir.join(case), &Defines::new(), &mut loader);
    let outcome = elaborate(&parsed, Options::default());
    let mut out = String::new();
    for d in &outcome.diagnostics {
        let loc = d
            .span
            .and_then(|s| parsed.sources.locate(s.start))
            .map(|l| {
                (
                    parsed.sources.file(l.file).unwrap().name().to_owned(),
                    l.line,
                )
            });
        let _ = writeln!(out, "{:?} {loc:?} {} {}", d.severity, d.located, d.message);
    }
    if let Some(spec) = &outcome.spec {
        for (path, value) in canon::of_elaborated(spec).iter() {
            let _ = writeln!(out, "{path} = {value}");
        }
    }
    out
}

#[test]
fn crlf_and_path_spelling_do_not_matter() {
    let prelude = std::fs::read_to_string(cases_dir().join("prelude.sinc"))
        .unwrap()
        .replace("\r\n", "\n");
    let mut count = 0;
    for entry in std::fs::read_dir(cases_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "slaspec") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let lf = run(Path::new("cases"), &name, &text, &prelude, str::to_owned);
        let crlf = run(
            &Path::new("other").join("..").join("deep").join("cases"),
            &name,
            &text,
            &prelude,
            |t| t.replace('\n', "\r\n"),
        );
        assert_eq!(lf, crlf, "{name}");
        count += 1;
    }
    assert!(count > 50);
}
