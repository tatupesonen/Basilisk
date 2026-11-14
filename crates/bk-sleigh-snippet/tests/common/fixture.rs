//! The fixture language (`tests/fixture/fixture.slaspec`), compiled with
//! `bk-sleigh-compiler`, and a directory holding it as a `.sla` beside an
//! `.ldefs` for the `snippetdump` oracle.

use std::path::{Path, PathBuf};

use bk_sla::Sla;

/// The fixture's source.
pub(crate) const SPEC: &str = include_str!("../fixture/fixture.slaspec");

/// The fixture's language id in the written `.ldefs`.
pub(crate) const LANGUAGE_ID: &str = "Fixture:LE:32:default";

/// The fixture compiled.
pub(crate) fn sla() -> Sla {
    let parsed =
        bk_sleigh_syntax::parse_str("fixture.slaspec", SPEC, &bk_sleigh_syntax::Defines::new());
    assert!(!parsed.has_errors(), "{:?}", parsed.diagnostics);
    let compiled =
        bk_sleigh_compiler::compile_parsed(&parsed, bk_sleigh_compiler::Options::default());
    compiled
        .sla
        .unwrap_or_else(|| panic!("fixture compiles: {:?}", compiled.diagnostics))
}

/// Writes the fixture as a language directory under `dir` (created if
/// needed) and returns the directory, a root `snippetdump` accepts.
pub(crate) fn write_root(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("fixture directory");
    let bytes = sla().write().expect("fixture .sla encodes");
    std::fs::write(dir.join("fixture.sla"), bytes).expect("write .sla");
    std::fs::write(
        dir.join("fixture.pspec"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<processor_spec/>\n",
    )
    .expect("write .pspec");
    let ldefs = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<language_definitions>\n  \
         <language processor=\"Fixture\" endian=\"little\" size=\"32\" variant=\"default\" \
         version=\"1.0\" slafile=\"fixture.sla\" processorspec=\"fixture.pspec\" \
         id=\"{LANGUAGE_ID}\">\n    <description>fixture</description>\n  </language>\n\
         </language_definitions>\n"
    );
    std::fs::write(dir.join("fixture.ldefs"), ldefs).expect("write .ldefs");
    dir.to_path_buf()
}
