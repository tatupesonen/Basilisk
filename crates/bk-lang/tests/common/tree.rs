//! Small Ghidra-shaped module trees in temporary directories.

use std::{fmt::Write as _, fs, path::Path};

use bk_lang::{LanguageCompilerSpecPair, LanguageId, LanguageRegistry};
use tempfile::TempDir;

pub(crate) fn write(path: impl AsRef<Path>, content: &str) {
    let path = path.as_ref();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// One `<language>` element. `extra` holds further attributes.
pub(crate) fn language(
    id: &str,
    extra: &str,
    sla: &str,
    pspec: &str,
    compilers: &[(&str, &str)],
) -> String {
    let [processor, endian, size, variant] = id.split(':').collect::<Vec<_>>()[..] else {
        panic!("id has four parts")
    };
    let endian = if endian == "BE" { "big" } else { "little" };
    let mut compiler_elements = String::new();
    for (id, spec) in compilers {
        write!(
            compiler_elements,
            r#"<compiler name="{id} compiler" spec="{spec}" id="{id}"/>"#
        )
        .unwrap();
    }
    let compilers = compiler_elements;
    format!(
        r#"<language processor="{processor}" endian="{endian}" size="{size}" variant="{variant}"
            version="1.0" slafile="{sla}" processorspec="{pspec}" id="{id}" {extra}>
            <description>{id}</description>{compilers}
            <external_name tool="gnu" name="{processor}-gnu"/>
        </language>"#
    )
}

pub(crate) fn ldefs(languages: &[String]) -> String {
    format!(
        "<language_definitions>{}</language_definitions>",
        languages.concat()
    )
}

/// A Ghidra-shaped tree with two processor modules:
///
/// * `Zeta` (sorts before `alpha`: upper case first) with two languages,
///   one deprecated;
/// * `alpha` with three languages over two `.ldefs` files, one in a
///   subdirectory.
pub(crate) fn tree() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let processors = dir.path().join("Ghidra/Processors");
    let zeta = processors.join("Zeta");
    write(zeta.join("Module.manifest"), "");
    let languages = zeta.join("data/languages");
    write(
        languages.join("zeta.ldefs"),
        &ldefs(&[
            language(
                "Zeta:BE:32:default",
                "",
                "zeta.sla",
                "zeta.pspec",
                &[("default", "zeta.cspec"), ("gcc", "zeta-gcc.cspec")],
            ),
            language(
                "Zeta:BE:32:old",
                "deprecated=\"true\"",
                "zeta.sla",
                "zeta.pspec",
                &[("default", "zeta.cspec")],
            ),
        ]),
    );
    write(languages.join("zeta.slaspec"), "");
    write(
        languages.join("zeta.pspec"),
        r#"<processor_spec><programcounter register="PC"/></processor_spec>"#,
    );
    write(languages.join("zeta.cspec"), "");
    write(languages.join("zeta-gcc.cspec"), "");
    write(
        languages.join("zeta.opinion"),
        r#"<opinions>
            <constraint loader="Test Loader" compilerSpecID="gcc">
              <constraint primary="7" processor="Zeta" endian="big" size="32"/>
              <constraint primary="8, 9" processor="Alpha" size="16">
                <constraint secondary="0b 1..." compilerSpecID="default"/>
                <constraint secondary="0x4" endian="little"/>
                <constraint secondary="77" endian="big"/>
              </constraint>
            </constraint>
        </opinions>"#,
    );

    let alpha = processors.join("alpha");
    write(
        alpha.join("Module.manifest"),
        "MODULE NAME: alpha\nDATA SEARCH IGNORE DIR: ignored\n",
    );
    let languages = alpha.join("data/languages");
    write(
        languages.join("b.ldefs"),
        &ldefs(&[
            language(
                "Alpha:LE:16:default",
                "",
                "alpha",
                "alpha.pspec",
                &[("default", "alpha.cspec"), ("gcc", "alpha.cspec")],
            ),
            language(
                "Alpha:BE:16:default",
                "",
                "alpha.sla",
                "alpha.pspec",
                &[("default", "alpha.cspec")],
            ),
        ]),
    );
    // Found although it is in a subdirectory, and its files one level up.
    write(
        languages.join("a/nested.ldefs"),
        &ldefs(&[language(
            "Alpha:LE:32:wide",
            "",
            "alpha.sla",
            "alpha.pspec",
            &[("gcc", "alpha.cspec")],
        )]),
    );
    write(languages.join("alpha.slaspec"), "");
    write(languages.join("alpha.pspec"), "<processor_spec/>");
    write(languages.join("alpha.cspec"), "");
    dir
}

pub(crate) fn registry(dir: &TempDir) -> LanguageRegistry {
    LanguageRegistry::from_ghidra_root(dir.path()).unwrap()
}

pub(crate) fn ids(registry: &LanguageRegistry) -> Vec<&str> {
    registry
        .languages()
        .iter()
        .map(|l| l.id().as_str())
        .collect()
}

pub(crate) fn id(text: &str) -> LanguageId {
    LanguageId::new(text).unwrap()
}

pub(crate) fn show(pairs: &[LanguageCompilerSpecPair]) -> Vec<String> {
    pairs.iter().map(ToString::to_string).collect()
}
