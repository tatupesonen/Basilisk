//! Every GNU architecture name Ghidra's processors give
//! (`external_name tool="gnu"` in the `.ldefs` files) resolves and yields a
//! disassembler, with the language's byte order and `.gdis` options; every
//! `.gdis` file parses. Needs the Ghidra tree (skips without it).

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
#![cfg(not(windows))]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bk_gnu_disasm::gdis_config::{self, GdisConfig};
use bk_gnu_disasm::{Architecture, Disassembler, Endian};

/// One language with a GNU name.
#[derive(Debug)]
struct Language {
    id: String,
    /// Every `gnu` name; Ghidra uses the first (and warns about more), the
    /// test tries them all.
    gnu: Vec<String>,
    endian: Endian,
    gdis: Option<PathBuf>,
}

fn ldefs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for processor in std::fs::read_dir(root.join("Ghidra/Processors")).unwrap() {
        let languages = processor.unwrap().path().join("data/languages");
        let Ok(entries) = std::fs::read_dir(&languages) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "ldefs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn languages(root: &Path) -> Vec<Language> {
    let mut out = Vec::new();
    for path in ldefs_files(root) {
        let text = std::fs::read_to_string(&path).unwrap();
        let doc = roxmltree::Document::parse(&text).unwrap();
        for lang in doc.descendants().filter(|n| n.has_tag_name("language")) {
            let external = |tool: &str| {
                lang.children()
                    .filter(|n| {
                        n.has_tag_name("external_name") && n.attribute("tool") == Some(tool)
                    })
                    .filter_map(|n| n.attribute("name"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            let gnu = external("gnu");
            if gnu.is_empty() {
                continue;
            }
            out.push(Language {
                id: lang.attribute("id").unwrap().to_owned(),
                gnu,
                endian: if lang.attribute("endian") == Some("big") {
                    Endian::Big
                } else {
                    Endian::Little
                },
                gdis: external("gdis.disassembler.options.file")
                    .first()
                    .map(|f| path.parent().unwrap().join(f)),
            });
        }
    }
    out
}

/// Options for a language as Ghidra would send them, with every context
/// register at zero.
fn options(config: Option<&GdisConfig>) -> Option<String> {
    config.and_then(|c| c.options_for(|_| Some(0)).unwrap())
}

#[test]
fn every_gnu_name_of_ghidra_gives_a_disassembler() {
    let Some(root) = common::ghidra_root() else {
        return;
    };
    let languages = languages(&root);
    let names: BTreeSet<&str> = languages
        .iter()
        .flat_map(|l| l.gnu.iter().map(String::as_str))
        .collect();
    assert_eq!(
        names.len(),
        65,
        "Ghidra 42db038f3c has 65 distinct gnu names"
    );

    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let code = common::noise(64, 7);
    for (lang, gnu) in languages
        .iter()
        .flat_map(|l| l.gnu.iter().map(move |g| (l, g)))
    {
        let config = lang
            .gdis
            .as_ref()
            .map(|p| gdis_config::read_file(p).unwrap());
        let result = Architecture::from_gnu_name(gnu).and_then(|arch| {
            let mut dis =
                Disassembler::new(&arch, lang.endian, options(config.as_ref()).as_deref())?;
            dis.block(&code, 0x1000)
        });
        match result {
            Ok(block) => assert!(
                !block.instructions.is_empty(),
                "{} ({gnu}): nothing decoded",
                lang.id
            ),
            Err(e) => {
                failures.insert(gnu.clone(), e.to_string());
            }
        }
    }
    for (name, error) in &failures {
        eprintln!("{name}: {error}");
    }
    let failed: Vec<&str> = failures.keys().map(String::as_str).collect();
    assert_eq!(failed, KNOWN_FAILURES, "{failures:#?}");
}

/// GNU names in Ghidra's `.ldefs` that binutils 2.41 does not know; each
/// is explained in docs/features/gnu-disasm.md.
const KNOWN_FAILURES: &[&str] = &[];

/// Hexagon's `0x18:0x5` resolves, but to the wrong processor: upstream
/// binutils has no Hexagon disassembler, and in 2.41's
/// `enum bfd_architecture` 0x18 is `bfd_arch_m9s12x`. The number must come
/// from another binutils. `gdis` built from 2.41 does the same.
#[test]
fn hexagons_numeric_name_is_m9s12x_in_binutils_2_41() {
    let m9s12x = Architecture::from_gnu_name("m9s12x").unwrap();
    assert_eq!(m9s12x.arch(), 0x18);
    let hexagon = Architecture::from_gnu_name("0x18:0x5").unwrap();
    assert_eq!(hexagon.arch(), m9s12x.arch());
    assert!(
        !Architecture::names()
            .unwrap()
            .iter()
            .any(|n| n.contains("hexagon"))
    );
}

#[test]
fn every_gdis_file_parses() {
    let Some(root) = common::ghidra_root() else {
        return;
    };
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    for lang in languages(&root) {
        files.extend(lang.gdis);
    }
    assert_eq!(files.len(), 2, "{files:?}");
    for file in files {
        let config = gdis_config::read_file(&file).unwrap();
        assert!(
            config.global.is_some() || config.context.is_some(),
            "{}",
            file.display()
        );
    }
}
