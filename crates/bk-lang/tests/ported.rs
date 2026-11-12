//! Ghidra's own tests of the classes this crate reimplements, ported:
//! `QueryOpinionServiceTest` and the applicable part of
//! `SleighLanguageProviderTest`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

mod common;

use bk_lang::{LanguageRegistry, opinion::secondary_attribute_matches};
use common::tree::{id, language, ldefs, write};

// ------------------------------------------- ported: QueryOpinionServiceTest

/// `QueryOpinionServiceTest.testSecondaryAttributeMatches`.
#[test]
fn ghidra_secondary_attribute_matches() {
    // Values taken from MIPS.opinion:
    //   00110000111100000011000100001111
    //   00010000000011110001010000000000
    //   00000000101001010001000100000101
    let attribute = "0b 00.. ..00 .... .... 00.1 0.0. 0000 ....";
    assert!(!secondary_attribute_matches("111", attribute));
    assert!(secondary_attribute_matches("821047567", attribute));
    assert!(secondary_attribute_matches("821047567", attribute));
    assert!(secondary_attribute_matches("269423616", attribute));
    assert!(secondary_attribute_matches("10817797", attribute));
}

/// `QueryOpinionServiceTest.testHexConstraint`.
#[test]
fn ghidra_hex_constraint() {
    assert!(secondary_attribute_matches("85", "0x55"));
    assert!(secondary_attribute_matches("-1", "0xff ff_ff ff"));
}

/// `QueryOpinionServiceTest.testNotBinaryOrHexConstraint`.
#[test]
fn ghidra_not_binary_or_hex_constraint() {
    assert!(!secondary_attribute_matches("1", "not_a_valid_constraint"));
    assert!(!secondary_attribute_matches("1", "0b1x"));
    assert!(!secondary_attribute_matches("1", ""));
}

/// `QueryOpinionServiceTest.testNotIntegerKey`.
#[test]
fn ghidra_not_integer_key() {
    assert!(!secondary_attribute_matches("abc", "0x1"));
    assert!(!secondary_attribute_matches("", "0b...."));
}

/// Behaviour of `secondaryAttributeMatches` that Ghidra's test leaves out,
/// derived from its source.
#[test]
fn secondary_attribute_edge_cases() {
    assert!(
        secondary_attribute_matches("85", "0X55"),
        "letter case is ignored"
    );
    assert!(secondary_attribute_matches("85", " 0x_5 5 "));
    assert!(
        secondary_attribute_matches("+85", "0x55"),
        "Java's parseInt accepts a plus sign"
    );
    assert!(!secondary_attribute_matches("85", "0x"));
    assert!(!secondary_attribute_matches("85", "0x-55"));
    assert!(
        !secondary_attribute_matches("85", "0x100000055"),
        "wider than 32 bits"
    );
    assert!(
        !secondary_attribute_matches("4294967295", "0xffffffff"),
        "the key is a signed int"
    );
    assert!(
        !secondary_attribute_matches("85", "85"),
        "plain decimal is compared by the query"
    );
    // A short binary pattern is right-aligned and padded with zeros.
    assert!(secondary_attribute_matches("5", "0b101"));
    assert!(secondary_attribute_matches("5", "0b1.1"));
    assert!(!secondary_attribute_matches("13", "0b101"));
    assert!(secondary_attribute_matches("0", "0b"));
    assert!(!secondary_attribute_matches("1", "0b"));
    assert!(secondary_attribute_matches("8", "0b1..."));
    assert!(
        !secondary_attribute_matches("-1", "0b1..."),
        "bits above the pattern must be zero"
    );
    assert!(secondary_attribute_matches(
        "-1",
        &format!("0b{}", ".".repeat(32))
    ));
    // Beyond 32 characters only the first 32 are compared.
    let long = format!("0b{}1111", "0".repeat(32));
    assert!(secondary_attribute_matches("0", &long));
}

// --------------------------------------- ported: SleighLanguageProviderTest

/// The discovery half of `SleighLanguageProviderTest.testSlaThunderingHerds`
/// and `testSlaLockTimeout`: a provider built from `x86.ldefs` alone
/// describes `x86:LE:32:default` and knows its language files. (Their
/// other half — compiling the `.sla` under a file lock shared by many
/// processes — belongs to the SLEIGH compiler, M2.)
#[test]
fn ghidra_provider_from_one_ldefs_file_describes_x86() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let registry = LanguageRegistry::builder()
        .module(ghidra.join("Ghidra/Processors/x86"))
        .build()
        .unwrap();
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    assert_eq!(registry.ldefs_files().len(), 1);
    let x86 = registry.language(&id("x86:LE:32:default")).unwrap();
    let files = x86.files();
    assert!(files.ldefs.ends_with("data/languages/x86.ldefs"));
    assert!(files.slaspec.ends_with("data/languages/x86.slaspec"));
    assert!(files.slaspec.is_file());
    assert_eq!(files.sla, files.slaspec.with_extension("sla"));
    assert!(files.pspec.is_file());
    assert_eq!(registry.languages().len(), 6);
}

/// The file-finding half of
/// `SleighLanguageProviderTest.testSlaLockFileInReadOnlyDirectory` and
/// `testSlaLockFileReadOnlyFile`: `SleighLanguageFile.fromSlaFilename`
/// on a directory holding `mylang.slaspec` and `mylang.sla` finds both.
/// (What they go on to assert — whether a lock file can be created in a
/// read-only directory — belongs with `.sla` compilation, M2.)
#[test]
fn ghidra_language_file_from_sla_filename() {
    let dir = tempfile::tempdir().unwrap();
    let module = dir.path().join("sleighlockfiletest");
    let languages = module.join("data/languages");
    write(languages.join("mylang.slaspec"), "slaspec");
    write(languages.join("mylang.sla"), "sla");
    write(languages.join("mylang.pspec"), "<processor_spec/>");
    write(languages.join("mylang.cspec"), "");
    write(
        languages.join("mylang.ldefs"),
        &ldefs(&[language(
            "My:LE:32:default",
            "",
            "mylang.sla",
            "mylang.pspec",
            &[("default", "mylang.cspec")],
        )]),
    );
    let registry = LanguageRegistry::builder().module(&module).build().unwrap();
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    let mine = id("My:LE:32:default");
    let files = registry.language(&mine).unwrap().files();
    assert_eq!(files.slaspec, languages.join("mylang.slaspec"));
    assert_eq!(files.sla, languages.join("mylang.sla"));
    assert_eq!(
        registry.sla_file(&mine).unwrap(),
        Some(languages.join("mylang.sla"))
    );
}
