//! Real code for the differential test: the `.text` sections of the ELF
//! fixtures `bk-elf`'s tests use (`crates/bk-elf/tests/fixtures`, made by
//! clang and lld; provenance in its `README.md`).

use std::collections::BTreeMap;

use bk_bin::MemoryProvider;
use bk_elf::ElfFile;

use super::coverage::Extra;

/// (file, language, configurations to run it under).
/// Context settings of one run.
type Settings = &'static [(&'static str, u32)];

const FILES: &[(&str, &str, &[Settings])] = &[
    ("plain-x86_64.so", "x86:LE:64:default", &[&[]]),
    ("rela-x86_64.o", "x86:LE:64:default", &[&[]]),
    ("zdebug-x86_64.o", "x86:LE:64:default", &[&[]]),
    ("plain-i686.so", "x86:LE:32:default", &[&[]]),
    ("rel-i686.o", "x86:LE:32:default", &[&[]]),
    ("plain-aarch64.so", "AARCH64:LE:64:v8A", &[&[]]),
    ("plain-aarch64be.so", "AARCH64:BE:64:v8A", &[&[]]),
    // Android ARMv7 code is Thumb; run it both ways.
    ("plain-arm.so", "ARM:LE:32:v8", &[&[], &[("TMode", 1)]]),
    ("plain-armbe.so", "ARM:BE:32:v8", &[&[], &[("TMode", 1)]]),
];

/// The `.text` bytes and address of a fixture.
pub(crate) fn text_section(file: &str) -> Option<(u64, Vec<u8>)> {
    let path = bk_testkit::workspace_root()
        .join("crates")
        .join("bk-elf")
        .join("tests")
        .join("fixtures")
        .join(file);
    let bytes = std::fs::read(path).ok()?;
    let elf = ElfFile::parse(MemoryProvider::new(bytes)).ok()?;
    let section = elf.section_by_name(".text")?;
    let data = elf.section_data(section).ok()?.into_owned();
    Some((section.address(), data))
}

/// Real-code streams by language.
pub(crate) fn extras(_reference: &bk_testkit::ReferenceDir) -> BTreeMap<String, Vec<Extra>> {
    let mut out: BTreeMap<String, Vec<Extra>> = BTreeMap::new();
    for &(file, id, configs) in FILES {
        let Some((base, bytes)) = text_section(file) else {
            panic!("fixture {file} has no readable .text section");
        };
        for config in configs {
            out.entry(id.to_owned()).or_default().push(Extra {
                name: format!("real {file}"),
                base,
                bytes: bytes.clone(),
                config: config.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect(),
            });
        }
    }
    out
}
