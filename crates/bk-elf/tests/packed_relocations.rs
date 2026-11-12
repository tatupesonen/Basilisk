//! Packed relocation tables against independent references.
//!
//! The fixtures were linked by lld twice from the same objects: once with
//! packed relocations (`RELR`, Android `APS2`) and once without. Decoding the
//! packed tables must give the same relocations as the plain `REL`/`RELA`
//! tables of the twin. Layouts differ between the two links, so every
//! address is compared as (containing section's name, offset into it).

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

#[allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses part of the support code"
)]
mod common;

use std::collections::BTreeMap;

use bk_bin::MemoryProvider;
use bk_elf::{ElfFile, Machine, RelocationFormat};
use rstest::rstest;

/// An address as (section name, offset into the section).
type Place = (String, u64);

/// What a relocation does, independent of the layout.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A relative relocation (or a `RELR` entry), with its target when the
    /// table carries addends.
    Relative(Option<Place>),
    /// Anything else: type, symbol name and addend.
    Other(u32, String, i64),
}

fn place(elf: &ElfFile<&MemoryProvider<&[u8]>>, address: u64) -> Place {
    let section = elf
        .sections()
        .iter()
        .filter(|s| s.is_alloc() && s.sh_size > 0)
        .find(|s| s.address() <= address && address < s.address() + s.sh_size)
        .or_else(|| {
            elf.sections()
                .iter()
                .find(|s| s.is_alloc() && s.address() == address)
        })
        .unwrap_or_else(|| panic!("no section holds 0x{address:x}"));
    (
        elf.section_name(section).into_owned(),
        address - section.address(),
    )
}

fn relative_type(machine: Machine) -> u32 {
    match machine.0 {
        3 | 62 => 8, // R_386_RELATIVE, R_X86_64_RELATIVE
        40 => 23,    // R_ARM_RELATIVE
        183 => 1027, // R_AARCH64_RELATIVE
        other => panic!("machine {other}"),
    }
}

/// Every relocation of the file, by place, with how many tables of each
/// format were read.
fn relocations(bytes: &[u8]) -> (BTreeMap<Place, Vec<Kind>>, BTreeMap<String, usize>) {
    let provider = MemoryProvider::new(bytes);
    let elf = ElfFile::parse(&provider).unwrap();
    assert_eq!(elf.diagnostics(), []);
    let relative = relative_type(elf.header().e_machine);
    let mut out: BTreeMap<Place, Vec<Kind>> = BTreeMap::new();
    let mut formats = BTreeMap::new();
    for table in elf.relocation_tables() {
        assert!(!table.truncated);
        *formats.entry(format!("{:?}", table.format)).or_default() += 1;
        let symbols = table.symbol_table.map(|i| &elf.symbol_tables()[i]);
        let decoded: Vec<_> = elf.relocations(table).collect();
        if let Some(count) = table.relocation_count() {
            assert_eq!(decoded.len() as u64, count);
        }
        for r in decoded {
            let kind = if table.format == RelocationFormat::Relr {
                Kind::Relative(None)
            } else if r.relocation_type() == relative {
                Kind::Relative(r.has_addend.then(|| place(&elf, r.r_addend as u64)))
            } else {
                let name = symbols
                    .and_then(|t| elf.symbol(t, r.symbol_index()))
                    .and_then(|s| elf.symbol_name(symbols.unwrap(), &s).ok().flatten())
                    .map(std::borrow::Cow::into_owned)
                    .unwrap_or_default();
                Kind::Other(r.relocation_type(), name, r.r_addend)
            };
            out.entry(place(&elf, r.r_offset)).or_default().push(kind);
        }
    }
    (out, formats)
}

/// RELR entries carry no addend; drop the targets of relative relocations
/// when comparing with a file that uses RELR.
fn without_relative_targets(map: &BTreeMap<Place, Vec<Kind>>) -> BTreeMap<Place, Vec<Kind>> {
    map.iter()
        .map(|(place, kinds)| {
            let kinds = kinds
                .iter()
                .map(|k| match k {
                    Kind::Relative(_) => Kind::Relative(None),
                    other @ Kind::Other(..) => other.clone(),
                })
                .collect();
            (place.clone(), kinds)
        })
        .collect()
}

#[rstest]
#[case::aps2_rela_aarch64("aps2-aarch64.so", "plain-aarch64.so", "Android", false)]
#[case::aps2_rel_arm("aps2-arm.so", "plain-arm.so", "Android", false)]
#[case::aps2_rel_arm_big_endian("aps2-armbe.so", "plain-armbe.so", "Android", false)]
#[case::aps2_and_android_relr("aps2-relr-aarch64.so", "plain-aarch64.so", "Relr", true)]
#[case::relr_x86_64("relr-x86_64.so", "plain-x86_64.so", "Relr", true)]
#[case::relr_i686("relr-i686.so", "plain-i686.so", "Relr", true)]
#[case::relr_aarch64_big_endian("relr-aarch64be.so", "plain-aarch64be.so", "Relr", true)]
fn packed_tables_decode_to_the_plain_twin(
    #[case] packed: &str,
    #[case] plain: &str,
    #[case] format: &str,
    #[case] relr: bool,
) {
    let (mut packed_relocs, packed_formats) = relocations(&common::files::fixture(packed));
    let (mut plain_relocs, plain_formats) = relocations(&common::files::fixture(plain));
    assert!(packed_formats.contains_key(format), "{packed_formats:?}");
    assert!(!plain_formats.contains_key(format), "{plain_formats:?}");
    if relr {
        packed_relocs = without_relative_targets(&packed_relocs);
        plain_relocs = without_relative_targets(&plain_relocs);
    }
    for kinds in packed_relocs.values_mut().chain(plain_relocs.values_mut()) {
        kinds.sort();
    }
    assert!(plain_relocs.len() >= 20, "{plain_relocs:?}");
    assert_eq!(packed_relocs, plain_relocs);
}
