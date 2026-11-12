//! The `.ldefs` reader on hand-written documents: every attribute and
//! child, defaults, versions, strict errors and lenient warnings.

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

use bk_lang::{
    CompilerSpecId, Endian, Mode, ParseErrorKind,
    ldefs::{self, LanguageVersion},
};
use common::documents::LDEFS;
use rstest::rstest;

#[test]
fn ldefs_reads_every_attribute_and_child() {
    let parsed = ldefs::parse(LDEFS, Mode::Strict).unwrap();
    assert!(parsed.warnings.is_empty());
    let [first, second] = parsed.value.languages.as_slice() else {
        panic!("two languages")
    };

    assert_eq!(first.id.as_str(), "Toy:BE:32:default");
    assert_eq!(first.processor, "Toy");
    assert_eq!(first.endian, Endian::Big);
    assert_eq!(
        first.instruction_endian,
        Endian::Big,
        "defaults to the data endian"
    );
    assert_eq!(first.size, 32);
    assert_eq!(first.variant, "default");
    assert_eq!(first.version, LanguageVersion { major: 1, minor: 4 });
    assert_eq!(first.sla_file, "toy.sla");
    assert_eq!(first.processor_spec, "toy.pspec");
    assert_eq!(
        first.manual_index_file.as_deref(),
        Some("../manuals/toy.idx")
    );
    assert!(!first.deprecated && !first.hidden);
    // Text is kept as written, comments removed, nothing trimmed.
    assert_eq!(first.description, " Toy (test)  language ");
    assert_eq!(first.truncated_spaces.len(), 1);
    assert_eq!(
        (
            first.truncated_spaces[0].space.as_str(),
            first.truncated_spaces[0].size
        ),
        ("ram", 3)
    );
    // A repeated compiler id replaces the first entry where it stands, so
    // the default compiler spec is still the first one listed.
    let compilers: Vec<_> = first
        .compilers
        .iter()
        .map(|c| (c.id.as_str(), c.name.as_str(), c.spec.as_str()))
        .collect();
    assert_eq!(
        compilers,
        [
            ("default", "replaced", "toy-other.cspec"),
            ("gcc", "GCC", "toy-gcc.cspec")
        ]
    );
    assert_eq!(
        first.external_names_for("gnu").collect::<Vec<_>>(),
        ["toy:be", "toy:be:32"]
    );
    assert_eq!(
        first.external_names_for("IDA-PRO").collect::<Vec<_>>(),
        ["toy"]
    );
    assert_eq!(
        first.external_names.len(),
        3,
        "an entry with an empty tool is dropped"
    );

    assert_eq!(second.endian, Endian::Little);
    assert_eq!(second.instruction_endian, Endian::Big);
    assert_eq!(second.size, 64, "sizes decode 0x as hexadecimal");
    assert_eq!(second.version, LanguageVersion { major: 2, minor: 0 });
    assert_eq!(second.sla_file, "toy64");
    assert_eq!(second.manual_index_file, None);
    assert!(second.deprecated && second.hidden);
    assert_eq!(second.description, "");
    assert_eq!(second.compilers[0].id, CompilerSpecId::default());
}

#[rstest]
#[case("1.4", Some((1, 4)))]
#[case("2", Some((2, 0)))]
#[case("1.2.3", Some((1, 2)))]
#[case("1.", Some((1, 0)))]
#[case("0x10.010", Some((16, 8)))]
#[case("", None)]
#[case(".", None)]
#[case(".5", None)]
#[case("1..2", None)]
#[case("a.b", None)]
#[case("1.x", None)]
#[case("-1.0", None)]
fn version_parses_like_ghidra(#[case] text: &str, #[case] expected: Option<(u32, u32)>) {
    assert_eq!(
        LanguageVersion::parse(text).map(|v| (v.major, v.minor)),
        expected
    );
}

#[test]
fn versions_compare_by_major_then_minor() {
    let v = |text: &str| LanguageVersion::parse(text).unwrap();
    assert!(v("1.9") < v("2.0"));
    assert!(v("2.0") < v("2.1"));
    assert!(v("2.10") > v("2.9"), "numeric, not textual");
    assert_eq!(v("3"), v("3.0"));
    assert_eq!(v("1.4").to_string(), "1.4");
    assert_eq!(v("7").to_string(), "7.0");
}

fn language(attributes: &str, children: &str) -> String {
    format!(
        "<language_definitions>\n<language {attributes}>{children}</language>\n</language_definitions>"
    )
}

const ATTRS: &str = r#"processor="P" endian="big" size="8" variant="v" version="1" slafile="p.sla" processorspec="p.pspec" id="P:BE:8:v""#;
const CHILDREN: &str = r#"<description>d</description><compiler name="c" spec="c.cspec" id="c"/>"#;

#[rstest]
#[case::bad_version(&ATTRS.replace("version=\"1\"", "version=\"one\""), CHILDREN, "<major>[.<minor>] version numbers")]
#[case::bad_size(&ATTRS.replace("size=\"8\"", "size=\"eight\""), CHILDREN, "a non-negative integer")]
#[case::empty_id(&ATTRS.replace("id=\"P:BE:8:v\"", "id=\"\""), CHILDREN, "a non-empty language id")]
fn ldefs_rejects_what_ghidra_rejects_in_both_modes(
    #[case] attributes: &str,
    #[case] children: &str,
    #[case] message: &str,
) {
    let text = language(attributes, children);
    for mode in [Mode::Strict, Mode::Lenient] {
        let error = ldefs::parse(&text, mode).unwrap_err().to_string();
        assert!(error.contains(message), "{mode:?}: {error}");
    }
}

#[test]
fn ldefs_truncating_a_space_twice_is_rejected() {
    // One <truncate_space> is all the schema allows, so strict mode stops
    // at the second; lenient mode gets as far as Ghidra's own check.
    let text = language(
        ATTRS,
        r#"<description/><truncate_space space="ram" size="2"/><truncate_space space="ram" size="3"/><compiler name="c" spec="c" id="c"/>"#,
    );
    let strict = ldefs::parse(&text, Mode::Strict).unwrap_err().to_string();
    assert!(
        strict.ends_with("<language> has more than one <truncate_space>"),
        "{strict}"
    );
    let lenient = ldefs::parse(&text, Mode::Lenient).unwrap_err().to_string();
    assert!(
        lenient.ends_with("truncated space 'ram' already specified"),
        "{lenient}"
    );

    let two = text.replacen("space=\"ram\" size=\"3\"", "space=\"rom\" size=\"3\"", 1);
    let parsed = ldefs::parse(&two, Mode::Lenient).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    assert_eq!(parsed.value.languages[0].truncated_spaces.len(), 2);
}

#[test]
fn ldefs_lenient_mode_warns_and_reads_on() {
    let text = language(
        &format!(
            "{} endian=\"BIG\" color=\"red\"",
            ATTRS.replace("endian=\"big\" ", "")
        ),
        r#"<compiler name="c" spec="c.cspec" id="c"/><legacy/><description>d</description>"#,
    );
    let strict = ldefs::parse(&text, Mode::Strict).unwrap_err();
    assert!(matches!(strict.kind, ParseErrorKind::Schema(_)), "{strict}");

    let parsed = ldefs::parse(&text, Mode::Lenient).unwrap();
    let warnings: Vec<String> = parsed
        .warnings
        .iter()
        .map(|w| w.violation.to_string())
        .collect();
    assert_eq!(
        warnings,
        [
            "<language> attribute endian=\"BIG\": expected big or little",
            "attribute \"color\" is not allowed on <language>",
            "element <legacy> is not allowed in <language>",
            "<description> is out of order in <language>",
        ]
    );
    let language = &parsed.value.languages[0];
    assert_eq!(
        language.endian,
        Endian::Big,
        "Ghidra upper-cases the name before decoding"
    );
    assert_eq!(language.description, "d");
    assert_eq!(language.compilers.len(), 1);
}
