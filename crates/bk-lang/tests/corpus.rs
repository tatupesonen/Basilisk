//! Corpus tests: every language file Ghidra ships reads, and the registry
//! built from them is what Ghidra's would be. Skipped without a Ghidra
//! tree.

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

use std::{collections::BTreeSet, sync::Arc};

use bk_lang::{
    CompilerSpecId, Endian, LanguageCompilerSpecQuery, LanguageId, Mode, ldefs, opinion, pspec,
};

/// The module directories under `Ghidra/Processors`.
const PROCESSOR_MODULES: usize = 39;

#[test]
fn every_spec_file_reads_in_strict_mode() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let processors = ghidra.join("Ghidra/Processors");
    assert_eq!(
        std::fs::read_dir(&processors).unwrap().count(),
        PROCESSOR_MODULES
    );

    let mut languages = 0;
    let ldefs_files = common::files_with_extension(&processors, ".ldefs");
    for file in &ldefs_files {
        let parsed = ldefs::read_file(file, Mode::Strict).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.warnings, []);
        languages += parsed.value.languages.len();
    }
    let pspec_files = common::files_with_extension(&processors, ".pspec");
    for file in &pspec_files {
        pspec::read_file(file, Mode::Strict).unwrap_or_else(|e| panic!("{e}"));
    }
    let opinion_files = common::files_with_extension(&processors, ".opinion");
    for file in &opinion_files {
        opinion::read_file(file, Mode::Strict).unwrap_or_else(|e| panic!("{e}"));
    }
    eprintln!(
        "{} .ldefs ({languages} languages), {} .pspec, {} .opinion",
        ldefs_files.len(),
        pspec_files.len(),
        opinion_files.len()
    );
    // 51 .ldefs files sit directly in a data/languages directory; the 52nd
    // is RISCV/data/languages/old/riscv_deprecated.ldefs, which Ghidra also
    // finds because it searches data trees recursively. Z80/temp/z8401x.pspec
    // is outside any data tree and no language names it.
    assert_eq!(ldefs_files.len(), 52);
    assert_eq!(languages, 202);
    assert_eq!(pspec_files.len(), 89);
    assert_eq!(opinion_files.len(), 29);
}

#[test]
fn registry_holds_every_language_once() {
    let Some(registry) = common::registry() else {
        return;
    };
    assert!(registry.failures().is_empty(), "{:?}", registry.failures());
    assert_eq!(registry.ldefs_files().len(), 52);
    assert_eq!(registry.languages().len(), 202);
    let ids: BTreeSet<&LanguageId> = registry
        .languages()
        .iter()
        .map(bk_lang::LanguageDescription::id)
        .collect();
    assert_eq!(
        ids.len(),
        registry.languages().len(),
        "language ids are unique"
    );
    assert_eq!(registry.language_descriptions(false).count(), 190);
    assert_eq!(registry.language_descriptions(true).count(), 202);
    // The 51 files directly in a data/languages directory hold 193.
    let direct = registry
        .languages()
        .iter()
        .filter(|l| !l.files().ldefs.ends_with("old/riscv_deprecated.ldefs"))
        .count();
    assert_eq!(direct, 193);
    // 29 opinion files in processor modules and 3 in Features/FileFormats.
    assert_eq!(registry.opinion_files().len(), 32);
    // 88 .pspec files are in data trees; one of them no language names.
    assert_eq!(registry.pspec_files().count(), 87);
    assert_eq!(registry.processors().count(), 60);

    // Modules load in name order, which is not alphabetical: digits, then
    // upper case, then lower case.
    let first = registry.languages().first().unwrap();
    assert_eq!(first.id().as_str(), "6502:LE:16:default");
    let last = registry.languages().last().unwrap();
    assert_eq!(last.id().as_str(), "x86:LE:64:compat32");
    assert_eq!(registry.processors().next(), Some("6502"));
    assert_eq!(registry.processors().last(), Some("x86"));

    // No language in the tree is hidden.
    let ghidra = common::ghidra_dir().unwrap();
    let with_hidden = bk_lang::LanguageRegistry::builder()
        .ghidra_root(ghidra)
        .include_hidden(true)
        .build()
        .unwrap();
    assert_eq!(with_hidden.languages().len(), 202);
}

#[test]
fn every_file_a_language_names_exists() {
    let Some(registry) = common::registry() else {
        return;
    };
    let mut with_sla = 0;
    for language in registry.languages() {
        let files = language.files();
        assert!(files.ldefs.is_file(), "{}", files.ldefs.display());
        assert!(files.slaspec.is_file(), "{}", files.slaspec.display());
        assert!(files.pspec.is_file(), "{}", files.pspec.display());
        assert_eq!(files.sla.with_extension("slaspec"), files.slaspec);
        if let Some(manual) = &files.manual_index {
            assert!(manual.is_file(), "{}", manual.display());
        }
        assert!(!language.compiler_specs().is_empty(), "{}", language.id());
        for compiler in language.compiler_specs() {
            assert!(compiler.file.is_file(), "{}", compiler.file.display());
        }
        // The compiled .sla may be absent in a source tree.
        with_sla += usize::from(registry.sla_file(language.id()).unwrap().is_some());
    }
    eprintln!(
        "{with_sla} of {} languages have a compiled .sla",
        registry.languages().len()
    );
}

#[test]
fn deprecated_riscv_languages_find_their_files_one_directory_up() {
    let Some(registry) = common::registry() else {
        return;
    };
    // Defined in data/languages/old/, naming files that live in
    // data/languages/: found through the application-wide search by name.
    let language = registry
        .find("RISCV:LE:64:RV64I")
        .expect("deprecated language is registered");
    assert!(language.is_deprecated());
    assert!(
        language
            .files()
            .ldefs
            .ends_with("old/riscv_deprecated.ldefs")
    );
    assert!(
        language
            .files()
            .slaspec
            .ends_with("data/languages/riscv.lp64d.slaspec")
    );
    assert!(
        language
            .files()
            .pspec
            .ends_with("data/languages/RV64.pspec")
    );
    assert!(
        language.compiler_specs()[0]
            .file
            .ends_with("data/languages/riscv64.cspec")
    );
}

#[test]
fn every_processor_spec_loads_lazily_and_is_shared() {
    let Some(registry) = common::registry() else {
        return;
    };
    for language in registry.languages() {
        registry
            .processor_spec(language.id())
            .unwrap_or_else(|e| panic!("{e}"));
    }
    // Two x86 languages name x86-16.pspec: it is read once and shared.
    let id = |text: &str| LanguageId::new(text).unwrap();
    let a = registry
        .processor_spec(&id("x86:LE:32:System Management Mode"))
        .unwrap();
    let b = registry
        .processor_spec(&id("x86:LE:16:Protected Mode"))
        .unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    let c = registry.processor_spec(&id("x86:LE:32:default")).unwrap();
    assert!(!Arc::ptr_eq(&a, &c));
    assert_eq!(c.program_counter.as_deref(), Some("EIP"));
}

#[test]
fn every_opinion_constraint_selects_a_language() {
    let Some(registry) = common::registry() else {
        return;
    };
    assert!(
        registry.opinion_failures().is_empty(),
        "{:?}",
        registry.opinion_failures()
    );
    let mut constraints = 0;
    let mut without_language = Vec::new();
    for file in registry.opinion_files() {
        let opinions = opinion::read_file(file, Mode::Strict).unwrap().value;
        for constraint in opinions.resolved() {
            constraints += 1;
            if registry.pairs_for_constraint(&constraint).is_empty() {
                without_language.push(format!(
                    "{}: {:?}/{:?}/{:?}/{:?}",
                    file.file_name().unwrap().to_string_lossy(),
                    constraint.processor,
                    constraint.endian,
                    constraint.size,
                    constraint.variant
                ));
            }
        }
    }
    eprintln!("{constraints} constraints; without a language: {without_language:#?}");
    assert_eq!(constraints, 339);
    // Five constraints in Ghidra's own files name a processor, size or
    // variant that no language has (for instance processor "AVR8" has no
    // 16-bit "extended" variant, and "PIC24" is spelled "PIC-24" in its
    // .ldefs). They are valid files; the constraints simply never match.
    assert_eq!(
        without_language,
        [
            r#"avr8.opinion: Some("AVR8")/None/Some(16)/Some("extended")"#,
            r#"minidump.opinion: Some("ARM")/Some(Little)/Some(64)/None"#,
            r#"pagedump.opinion: Some("SuperH3")/Some(Little)/Some(32)/None"#,
            r#"PIC24.opinion: Some("PIC24")/Some(Little)/Some(16)/None"#,
            r#"V850.opinion: Some("V850")/None/Some(32)/Some("default")"#,
        ]
    );
    assert!(registry.opinions().order_is_exact());
}

#[test]
fn lookups_on_the_real_corpus() {
    let Some(registry) = common::registry() else {
        return;
    };
    let x86_64 = registry.find("x86:LE:64:default").unwrap();
    assert_eq!(x86_64.to_string(), "x86/little/64/default");
    assert_eq!(x86_64.endian(), Endian::Little);
    assert_eq!(x86_64.size(), 64);
    assert_eq!(
        x86_64.default_compiler_spec().unwrap().id.as_str(),
        "windows"
    );
    let ids: Vec<&str> = x86_64
        .compiler_specs()
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(ids, ["windows", "clangwindows", "gcc", "golang"]);
    assert_eq!(
        x86_64.external_names("IDA-PRO").collect::<Vec<_>>(),
        ["metapc"]
    );
    assert_eq!(
        registry.default_language("x86").unwrap().id().as_str(),
        "x86:LE:32:default"
    );

    let pairs = registry.pairs(&LanguageCompilerSpecQuery {
        processor: Some("x86".into()),
        size: Some(64),
        compiler_spec_id: Some(CompilerSpecId::new("gcc")),
        ..LanguageCompilerSpecQuery::default()
    });
    let pairs: Vec<String> = pairs.iter().map(ToString::to_string).collect();
    assert_eq!(pairs, ["x86:LE:64:default:gcc", "x86:LE:64:compat32:gcc"]);
    // File name order puts andestar_v5.ldefs before riscv.ldefs.
    assert_eq!(
        registry.default_language("RISCV").unwrap().id().as_str(),
        "RISCV:LE:32:AndeStar_v5"
    );
    assert!(registry.default_language("Z8000").is_err());
}

fn show(results: &[opinion::QueryResult]) -> Vec<String> {
    results
        .iter()
        .map(|r| format!("{}{}", r.pair, if r.preferred { " *" } else { "" }))
        .collect()
}

/// The name of Ghidra's ELF loader.
const ELF: &str = "Executable and Linking Format (ELF)";

#[test]
fn opinion_queries_on_the_real_corpus() {
    let Some(registry) = common::registry() else {
        return;
    };
    // ELF, e_machine 62 (x86-64): gcc is preferred. The order is the
    // iteration order of Ghidra's HashSet.
    assert_eq!(
        show(&registry.query_opinions(ELF, Some("62"), Some("0"))),
        [
            "x86:LE:64:default:windows",
            "x86:LE:64:default:clangwindows",
            "x86:LE:64:default:golang",
            "x86:LE:64:default:gcc *",
        ]
    );
    // PE, machine 0x8664: the same languages, windows preferred.
    assert_eq!(
        show(&registry.query_opinions("Portable Executable (PE)", Some("34404"), None)),
        [
            "x86:LE:64:default:windows *",
            "x86:LE:64:default:clangwindows",
            "x86:LE:64:default:golang",
            "x86:LE:64:default:gcc",
        ]
    );
    // MIPS lists its primary key as "8,10": both select the same
    // constraints, and the e_flags value is matched against binary
    // patterns such as "0b 00.. ..00 .... .... 00.1 0.0. 0000 ....".
    let mips = registry.query_opinions(ELF, Some("10"), Some("821047567"));
    assert_eq!(
        show(&mips),
        show(&registry.query_opinions(ELF, Some("8"), Some("821047567")))
    );
    assert_eq!(
        show(&mips),
        [
            "MIPS:BE:32:default:default *",
            "MIPS:BE:32:default:windows",
            "MIPS:LE:32:default:default *",
            "MIPS:LE:32:default:windows",
            "MIPS:BE:32:default:eabi",
            "MIPS:LE:32:default:eabi",
        ]
    );
    // Flags no pattern matches fall back to the constraints without a
    // secondary key: every MIPS language.
    assert_eq!(registry.query_opinions(ELF, Some("8"), Some("0")).len(), 56);
    // Unknown keys give nothing.
    assert_eq!(registry.query_opinions(ELF, Some("99999"), None), []);
    assert_eq!(
        registry.query_opinions("No Such Loader", Some("62"), None),
        []
    );
    // A loader constraint with no keys registers every language, which a
    // query without a primary key reaches (Ghidra does the same).
    let all = registry.query_opinions(ELF, None, None);
    assert_eq!(
        all.len(),
        registry.pairs(&LanguageCompilerSpecQuery::default()).len()
    );
    assert_eq!(registry.opinions().loaders().count(), 22);
}
