//! Regenerates the oracle table with `tests/oracle/regen.sh` from the
//! reference build and requires it to equal the checked-in table of the
//! C++ standard library the host's compiler uses (libc++ on macOS,
//! libstdc++ on Linux). Proves the generator deterministic and the
//! checked-in table current. Needs the reference directory (kind L), a C++
//! compiler and bash; skipped with a printed reason otherwise.

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
mod oracle_common;

use std::path::Path;
use std::process::Command;

use oracle_common::Lib;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn regenerated_table_equals_the_checked_in_one() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    if !reference.root().join("src/cpp/com_opt").is_dir() {
        eprintln!(
            "SKIPPED: {} has no src/cpp/com_opt objects (scripts/build-reference.sh builds them)",
            reference.root().display()
        );
        return;
    }
    if !have("bash") || !have("c++") {
        eprintln!("SKIPPED: regenerating the oracle table needs bash and a C++ compiler (c++)");
        return;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bk-cspec-oracle-regen");
    let _ = std::fs::remove_dir_all(&out);
    let status = Command::new("bash")
        .arg(manifest.join("tests/oracle/regen.sh"))
        .arg(reference.root())
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "regen.sh failed: {status}");
    let written: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let Some(lib) = Lib::ALL.into_iter().find(|l| {
        written
            .iter()
            .any(|w| *w == format!("cspec_oracle.{}.txt.gz", l.name()))
    }) else {
        eprintln!("SKIPPED: regen.sh wrote {written:?}, a library with no checked-in table");
        return;
    };
    let fresh = oracle_common::gunzip(&out.join(format!("cspec_oracle.{}.txt.gz", lib.name())));
    let checked_in = oracle_common::table_of(lib);
    assert_eq!(
        fresh.lines().count(),
        checked_in.lines().count(),
        "line counts differ"
    );
    for (i, (f, c)) in fresh.lines().zip(checked_in.lines()).enumerate() {
        assert_eq!(
            f,
            c,
            "line {} of the {} table differs from a fresh generation",
            i + 1,
            lib.name()
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}
