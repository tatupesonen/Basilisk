//! Registry lookups and queries, and opinion queries, on a small module
//! tree.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

mod common;

use bk_lang::{
    CompilerSpecId, Endian, ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair,
    LanguageCompilerSpecQuery, LanguageRegistry, LoadFailure, Mode,
    opinion::{self, OpinionDatabase},
};
use common::tree::{id, registry, show, tree, write};

#[test]
fn lookups_by_id_processor_and_compiler() {
    let dir = tree();
    let registry = registry(&dir);
    let zeta = registry.language(&id("Zeta:BE:32:default")).unwrap();
    assert_eq!(zeta.to_string(), "Zeta/big/32/default");
    assert_eq!(zeta.processor_name(), "Zeta");
    assert_eq!(registry.processor_name(zeta.processor()), Some("Zeta"));
    assert_eq!(registry.processor("Zeta"), Some(zeta.processor()));
    assert_eq!(
        registry.processor("zeta"),
        None,
        "processor names are case sensitive"
    );
    assert_eq!(
        (zeta.endian(), zeta.instruction_endian(), zeta.size()),
        (Endian::Big, Endian::Big, 32)
    );
    assert_eq!(zeta.variant(), "default");
    assert_eq!(zeta.version().to_string(), "1.0");
    assert_eq!(zeta.description(), "Zeta:BE:32:default");
    assert_eq!(zeta.external_names("gnu").collect::<Vec<_>>(), ["Zeta-gnu"]);
    assert_eq!(zeta.all_external_names().len(), 1);
    assert!(zeta.truncated_spaces().is_empty());
    assert_eq!(zeta.truncated_space_size("ram"), None);

    // The default compiler spec is the first listed; there is no fallback
    // to it, nor to "default", for an id the language lacks.
    assert_eq!(zeta.default_compiler_spec().unwrap().id.as_str(), "default");
    assert_eq!(
        zeta.default_compiler_spec().unwrap().to_string(),
        "default compiler"
    );
    let gcc = registry
        .compiler_spec(zeta.id(), &CompilerSpecId::new("gcc"))
        .unwrap();
    assert!(gcc.file.ends_with("zeta-gcc.cspec"));
    let wide = id("Alpha:LE:32:wide");
    let error = registry
        .compiler_spec(&wide, &CompilerSpecId::default())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "compiler spec not found for 'Alpha:LE:32:wide/default'"
    );
    assert_eq!(
        registry
            .language(&wide)
            .unwrap()
            .default_compiler_spec()
            .unwrap()
            .id
            .as_str(),
        "gcc"
    );

    let error = registry.language(&id("Zeta:LE:32:default")).unwrap_err();
    assert_eq!(
        error.to_string(),
        "language not found for 'Zeta:LE:32:default'"
    );

    // Deprecated languages are found by id and listed on request.
    assert!(registry.find("Zeta:BE:32:old").unwrap().is_deprecated());
    assert_eq!(registry.language_descriptions(false).count(), 4);
    assert_eq!(registry.language_descriptions(true).count(), 5);

    // The default language of a processor is its first in load order.
    assert_eq!(
        registry.default_language("Alpha").unwrap().id().as_str(),
        "Alpha:LE:32:wide"
    );
    assert_eq!(
        registry.default_language("Beta").unwrap_err().to_string(),
        "language not found for processor: Beta"
    );
    let of_zeta: Vec<&str> = registry
        .for_processor("Zeta")
        .map(|l| l.id().as_str())
        .collect();
    assert_eq!(
        of_zeta,
        ["Zeta:BE:32:default", "Zeta:BE:32:old"],
        "deprecated included"
    );
}

#[test]
fn pair_queries_follow_load_order_and_skip_deprecated_languages() {
    let dir = tree();
    let registry = registry(&dir);
    let query =
        |processor: Option<&str>, endian, size, variant: Option<&str>, compiler: Option<&str>| {
            show(&registry.pairs(&LanguageCompilerSpecQuery {
                processor: processor.map(str::to_owned),
                endian,
                size,
                variant: variant.map(str::to_owned),
                compiler_spec_id: compiler.map(CompilerSpecId::new),
            }))
        };
    assert_eq!(
        query(None, None, None, None, None),
        [
            "Zeta:BE:32:default:default",
            "Zeta:BE:32:default:gcc",
            "Alpha:LE:32:wide:gcc",
            "Alpha:LE:16:default:default",
            "Alpha:LE:16:default:gcc",
            "Alpha:BE:16:default:default",
        ]
    );
    assert_eq!(
        query(Some("Alpha"), None, None, None, Some("gcc")),
        ["Alpha:LE:32:wide:gcc", "Alpha:LE:16:default:gcc"]
    );
    assert_eq!(
        query(None, Some(Endian::Big), Some(16), None, None),
        ["Alpha:BE:16:default:default"]
    );
    assert_eq!(
        query(None, None, None, Some("wide"), None),
        ["Alpha:LE:32:wide:gcc"]
    );
    assert_eq!(
        query(Some("Zeta"), None, None, Some("old"), None),
        Vec::<String>::new()
    );
    assert_eq!(
        query(Some("Unknown"), None, None, None, None),
        Vec::<String>::new()
    );
    assert_eq!(
        query(None, None, Some(64), None, None),
        Vec::<String>::new()
    );

    // The description query underneath includes deprecated languages.
    assert_eq!(
        registry
            .matching(Some("Zeta"), None, None, Some("old"))
            .count(),
        1
    );

    let all = LanguageCompilerSpecQuery::default();
    assert_eq!(
        all.to_string(),
        "processor=null; endian=null; size=null; variant=null; compiler=null"
    );
    let some = LanguageCompilerSpecQuery {
        processor: Some("Zeta".into()),
        endian: Some(Endian::Big),
        size: Some(32),
        variant: Some("default".into()),
        compiler_spec_id: Some(CompilerSpecId::new("gcc")),
    };
    assert_eq!(
        some.to_string(),
        "processor=Zeta; endian=big; size=32; variant=default; compiler=gcc"
    );
}

#[test]
fn external_name_queries() {
    let dir = tree();
    let registry = registry(&dir);
    let query = |name: Option<&str>, tool: Option<&str>, compiler: Option<&str>| {
        show(
            &registry.external_pairs(&ExternalLanguageCompilerSpecQuery {
                external_processor_name: name.map(str::to_owned),
                external_tool: tool.map(str::to_owned),
                endian: None,
                size: None,
                compiler_spec_id: compiler.map(CompilerSpecId::new),
            }),
        )
    };
    // The name is compared without regard to case; the tool exactly.
    assert_eq!(
        query(Some("ALPHA-GNU"), Some("gnu"), None),
        [
            "Alpha:LE:32:wide:gcc",
            "Alpha:LE:16:default:default",
            "Alpha:LE:16:default:gcc",
            "Alpha:BE:16:default:default",
        ]
    );
    assert_eq!(
        query(Some("alpha-gnu"), Some("GNU"), None),
        Vec::<String>::new()
    );
    // A name without a tool matches nothing; no name matches everything.
    assert_eq!(query(Some("alpha-gnu"), None, None), Vec::<String>::new());
    assert_eq!(query(None, None, None).len(), 6);
    // A preferred compiler narrows a language that has it; a language
    // without it contributes all of its compiler specs.
    assert_eq!(
        query(Some("alpha-gnu"), Some("gnu"), Some("default")),
        [
            "Alpha:LE:32:wide:gcc",
            "Alpha:LE:16:default:default",
            "Alpha:BE:16:default:default"
        ]
    );
    assert_eq!(
        query(Some("zeta-gnu"), Some("gnu"), Some("gcc")),
        ["Zeta:BE:32:default:gcc"]
    );

    let big =
        registry.external_descriptions(Some("alpha-gnu"), Some("gnu"), Some(Endian::Big), Some(16));
    assert_eq!(
        big.map(|l| l.id().as_str()).collect::<Vec<_>>(),
        ["Alpha:BE:16:default"]
    );

    assert_eq!(
        registry.defined_external_tool_names("Zeta:BE:32:default", "gnu", false),
        Some(vec!["Zeta-gnu"])
    );
    assert_eq!(
        registry.defined_external_tool_names("Zeta:BE:32:default", "ida", false),
        None
    );
    assert_eq!(
        registry.defined_external_tool_names("Zeta:BE:32:old", "gnu", false),
        None
    );
    assert_eq!(
        registry.defined_external_tool_names("Zeta:BE:32:old", "gnu", true),
        Some(vec!["Zeta-gnu"])
    );
    assert_eq!(registry.defined_external_tool_names("", "gnu", true), None);
    assert_eq!(
        registry.defined_external_tool_names("Zeta:BE:32:default", "", true),
        None
    );

    let query = ExternalLanguageCompilerSpecQuery {
        external_processor_name: Some("metapc".into()),
        external_tool: Some("IDA-PRO".into()),
        endian: Some(Endian::Little),
        size: Some(32),
        compiler_spec_id: None,
    };
    assert_eq!(
        query.to_string(),
        "externalProcessorName=metapc; externalTool=IDA-PRO; endian=little; size=32; compiler=null"
    );
}

fn results(
    registry: &LanguageRegistry,
    primary: Option<&str>,
    secondary: Option<&str>,
) -> Vec<String> {
    let mut all: Vec<String> = registry
        .query_opinions("Test Loader", primary, secondary)
        .iter()
        .map(|r| format!("{}{}", r.pair, if r.preferred { " *" } else { "" }))
        .collect();
    all.sort();
    all
}

#[test]
fn opinion_queries_inherit_override_and_match_like_ghidra() {
    let dir = tree();
    let registry = registry(&dir);
    assert!(registry.opinion_failures().is_empty());
    assert!(registry.opinions().order_is_exact());
    assert_eq!(
        registry.opinions().loaders().collect::<Vec<_>>(),
        ["Test Loader"]
    );

    // Languages are matched by processor, endian, size and variant, never
    // by id; deprecated ones are left out. The inherited compilerSpecID
    // marks the preferred pair.
    assert_eq!(
        results(&registry, Some("7"), None),
        ["Zeta:BE:32:default:default", "Zeta:BE:32:default:gcc *"]
    );
    // An unknown secondary key falls back to the constraints without one.
    assert_eq!(
        results(&registry, Some("7"), Some("123")),
        results(&registry, Some("7"), None)
    );

    // primary="8, 9" is a list: either value selects it.
    let alpha16 = [
        "Alpha:BE:16:default:default",
        "Alpha:LE:16:default:default",
        "Alpha:LE:16:default:gcc *",
    ];
    assert_eq!(results(&registry, Some("8"), None), alpha16);
    assert_eq!(results(&registry, Some("9"), None), alpha16);
    assert!(
        results(&registry, Some("8, 9"), None).len() == 3,
        "the attribute text itself also matches"
    );
    assert!(results(&registry, Some("89"), None).is_empty());

    // secondary: exact text first …
    assert_eq!(
        results(&registry, Some("8"), Some("77")),
        ["Alpha:BE:16:default:default"]
    );
    // … then every hexadecimal or binary pattern the key matches: 4 is
    // 0x4 (little endian only, gcc preferred by inheritance) but not
    // 0b1...; 8 to 15 match 0b1... (default preferred by override) …
    assert_eq!(
        results(&registry, Some("9"), Some("4")),
        ["Alpha:LE:16:default:default", "Alpha:LE:16:default:gcc *"]
    );
    assert_eq!(
        results(&registry, Some("9"), Some("12")),
        [
            "Alpha:BE:16:default:default *",
            "Alpha:LE:16:default:default *",
            "Alpha:LE:16:default:gcc"
        ]
    );
    // … and otherwise the constraints with no secondary.
    assert_eq!(results(&registry, Some("9"), Some("16")), alpha16);
    assert_eq!(results(&registry, Some("9"), Some("not a number")), alpha16);

    // Every constraint element registers, not only leaves: the loader-level
    // constraint holds every language under no keys at all.
    assert_eq!(results(&registry, None, None).len(), 6);
    assert_eq!(results(&registry, None, Some("5")).len(), 6);
    assert!(
        registry
            .query_opinions("Other Loader", Some("7"), None)
            .is_empty()
    );
    assert!(results(&registry, Some("1"), None).is_empty());
}

#[test]
fn an_unreadable_opinion_file_is_reported_and_the_rest_still_answer() {
    let dir = tree();
    write(
        dir.path()
            .join("Ghidra/Processors/alpha/data/languages/bad.opinion"),
        r#"<opinions><constraint loader="Test Loader" primary="1" endian="sideways"/></opinions>"#,
    );
    let registry = registry(&dir);
    assert!(
        registry.failures().is_empty(),
        "opinions are read on first use, not at scan"
    );
    assert_eq!(results(&registry, Some("7"), None).len(), 2);
    let [LoadFailure::Opinions(error)] = registry.opinion_failures() else {
        panic!("one failure")
    };
    assert!(
        error.to_string().contains("big, little, BE or LE"),
        "{error}"
    );
}

fn pair(language: &str, compiler: &str) -> LanguageCompilerSpecPair {
    LanguageCompilerSpecPair::from_strs(language, compiler).unwrap()
}

#[test]
fn the_first_of_two_equal_results_keeps_its_preferred_flag() {
    let preferred = |text: &str| {
        let opinions = opinion::parse(text, Mode::Strict).unwrap().value;
        let mut database = OpinionDatabase::new();
        database.add(&opinions, |_| vec![pair("P:LE:32:default", "gcc")]);
        let results = database.query("L", Some("1"), None);
        assert_eq!(results.len(), 1);
        results[0].preferred
    };
    // Two constraints under the same keys select the same pair, one
    // preferring it and one not: Ghidra's HashSet keeps the first.
    for (first, second, expected) in [("gcc", "other", true), ("other", "gcc", false)] {
        assert_eq!(
            preferred(&format!(
                r#"<opinions><constraint loader="L">
                     <constraint primary="1" compilerSpecID="{first}"/>
                     <constraint primary="1" compilerSpecID="{second}"/>
                   </constraint></opinions>"#
            )),
            expected
        );
    }
    // The same rule has a consequence worth knowing: an enclosing
    // constraint registers too, before its children. If it already has
    // the keys and no compiler, its unpreferred results shadow those of a
    // child that adds only the compiler.
    assert!(!preferred(
        r#"<opinions><constraint loader="L" primary="1">
             <constraint compilerSpecID="gcc"/>
           </constraint></opinions>"#
    ));
    assert!(preferred(
        r#"<opinions><constraint loader="L" compilerSpecID="gcc">
             <constraint primary="1"/>
           </constraint></opinions>"#
    ));
}

#[test]
fn results_come_in_the_order_of_javas_hash_set() {
    // The order OpenJDK 25 prints for a HashSet of 100 QueryResults — with
    // Ghidra's hashCode — inserted in index order, where result i is
    // language "P<i/3>:LE:32:default" with compiler default, gcc or
    // windows by i % 3.
    const JAVA_ORDER: [usize; 100] = [
        28, 79, 87, 32, 64, 72, 6, 13, 95, 83, 51, 68, 21, 52, 89, 45, 58, 43, 12, 36, 99, 8, 19,
        78, 88, 4, 91, 73, 23, 47, 66, 0, 7, 81, 27, 39, 62, 38, 46, 26, 63, 70, 10, 84, 2, 3, 29,
        49, 41, 60, 42, 67, 20, 55, 5, 86, 71, 33, 40, 96, 44, 1, 61, 50, 69, 76, 35, 16, 98, 59,
        9, 80, 11, 65, 24, 48, 90, 15, 34, 97, 85, 77, 31, 56, 14, 22, 57, 94, 18, 30, 93, 75, 74,
        92, 37, 82, 54, 53, 17, 25,
    ];
    let pairs: Vec<LanguageCompilerSpecPair> = (0..100)
        .map(|i| {
            pair(
                &format!("P{}:LE:32:default", i / 3),
                ["default", "gcc", "windows"][i % 3],
            )
        })
        .collect();
    let opinions = opinion::parse(
        r#"<opinions><constraint loader="L" primary="1"/></opinions>"#,
        Mode::Strict,
    )
    .unwrap()
    .value;
    let mut database = OpinionDatabase::new();
    database.add(&opinions, |_| pairs.clone());
    // Adding the same results again changes nothing.
    database.add(&opinions, |_| pairs.clone());
    let order: Vec<usize> = database
        .query("L", Some("1"), None)
        .iter()
        .map(|r| pairs.iter().position(|p| *p == r.pair).unwrap())
        .collect();
    assert_eq!(order, JAVA_ORDER);
    assert!(database.order_is_exact());

    // The first twenty alone, in the smaller table Java uses for them.
    let mut small = OpinionDatabase::new();
    small.add(&opinions, |_| pairs[..20].to_vec());
    let order: Vec<usize> = small
        .query("L", Some("1"), None)
        .iter()
        .map(|r| pairs.iter().position(|p| *p == r.pair).unwrap())
        .collect();
    assert_eq!(
        order,
        [
            18, 0, 5, 10, 2, 3, 7, 15, 16, 6, 12, 13, 9, 8, 19, 11, 4, 14, 17, 1
        ]
    );
}
