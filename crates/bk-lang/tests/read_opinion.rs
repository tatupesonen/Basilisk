//! The `.opinion` reader, and what all three readers do with errors:
//! positions, messages, malformed input, file paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

mod common;

use bk_lang::{
    CompilerSpecId, Endian, Mode, ParseErrorKind, Position, Violation,
    ldefs::{self},
    opinion,
    pspec::{self},
};
use common::documents::{LDEFS, OPINION};
use rstest::rstest;

#[test]
fn opinion_reads_nesting_and_resolves_inheritance() {
    let parsed = opinion::parse(OPINION, Mode::Strict).unwrap();
    let opinions = parsed.value;
    let constraints = opinions.constraints();
    assert_eq!(constraints.len(), 6);

    // Document order, each naming its parent.
    let parents: Vec<Option<usize>> = constraints
        .iter()
        .map(|c| c.parent.map(bk_lang::opinion::ConstraintId::index))
        .collect();
    assert_eq!(parents, [None, Some(0), Some(1), Some(1), Some(0), None]);
    assert_eq!(
        opinions
            .get(constraints[2].parent.unwrap())
            .unwrap()
            .primary
            .as_deref(),
        Some("40")
    );

    // As written: only the element's own attributes.
    assert_eq!(constraints[2].loader, None);
    assert_eq!(constraints[2].endian, Some(Endian::Little));
    assert_eq!(
        constraints[3].endian,
        Some(Endian::Big),
        "short names are accepted"
    );
    assert_eq!(
        constraints[4].size,
        Some(32),
        "sizes are decimal integers; a sign is allowed"
    );
    assert_eq!(constraints[4].primary.as_deref(), Some("8, 10"));

    // Resolved: ancestors fill the gaps, the element's own values win.
    let resolved = opinions.resolved();
    let leaf = &resolved[2];
    assert_eq!(
        leaf.loader.as_deref(),
        Some("Executable and Linking Format (ELF)")
    );
    assert_eq!(leaf.primary.as_deref(), Some("40"));
    assert_eq!(leaf.secondary, None);
    assert_eq!(leaf.processor.as_deref(), Some("ARM"));
    assert_eq!(
        (leaf.endian, leaf.size, leaf.variant.as_deref()),
        (Some(Endian::Little), Some(32), Some("v8"))
    );
    assert_eq!(leaf.compiler_spec_id, Some(CompilerSpecId::new("gcc")));
    let overriding = &resolved[3];
    assert_eq!(
        overriding.compiler_spec_id,
        Some(CompilerSpecId::new("default"))
    );
    assert_eq!(overriding.secondary.as_deref(), Some("0x05000000"));
    assert_eq!(
        resolved[0].processor, None,
        "an outer constraint has only what it states"
    );
    assert_eq!(
        resolved[5].loader.as_deref(),
        Some("Portable Executable (PE)")
    );
}

#[rstest]
#[case(
    r#"<opinions><constraint endian="middle"/></opinions>"#,
    "big, little, BE or LE"
)]
#[case(
    r#"<opinions><constraint size="0x20"/></opinions>"#,
    "a decimal integer"
)]
#[case(r#"<opinions><constraint size=""/></opinions>"#, "a decimal integer")]
fn opinion_rejects_what_ghidra_rejects_in_both_modes(#[case] text: &str, #[case] message: &str) {
    for mode in [Mode::Strict, Mode::Lenient] {
        let error = opinion::parse(text, mode).unwrap_err().to_string();
        assert!(error.contains(message), "{mode:?}: {error}");
    }
}

#[test]
fn opinion_lenient_mode_skips_what_the_schema_does_not_allow() {
    let text = r#"<opinions>
        <constraint loader="L" extra="x"><note/>text<constraint primary="1"/></constraint>
        <other><constraint loader="ignored"/></other>
    </opinions>"#;
    assert!(opinion::parse(text, Mode::Strict).is_err());
    let parsed = opinion::parse(text, Mode::Lenient).unwrap();
    assert_eq!(
        parsed.value.constraints().len(),
        2,
        "constraints inside unknown elements are not read"
    );
    let warnings: Vec<String> = parsed
        .warnings
        .iter()
        .map(|w| w.violation.to_string())
        .collect();
    assert_eq!(
        warnings,
        [
            "element <other> is not allowed in <opinions>",
            "attribute \"extra\" is not allowed on <constraint>",
            "element <note> is not allowed in <constraint>",
            "<constraint> may not contain text",
        ]
    );
}

#[test]
fn opinion_nesting_has_no_depth_limit() {
    let depth = 100_000;
    let mut text = String::from("<opinions>");
    for _ in 0..depth {
        text.push_str("<constraint>");
    }
    for _ in 0..depth {
        text.push_str("</constraint>");
    }
    text.push_str("</opinions>");
    let opinions = opinion::parse(&text, Mode::Strict).unwrap().value;
    assert_eq!(opinions.constraints().len(), depth);
    assert_eq!(opinions.resolved().len(), depth);
}

#[test]
fn errors_name_the_position_and_what_was_expected() {
    let text = "<language_definitions>\n  <language processor=\"P\"\n     endian=\"sideways\"/>\n</language_definitions>";
    let error = ldefs::parse(text, Mode::Strict).unwrap_err();
    assert_eq!(error.position, Position { line: 2, column: 3 });
    assert_eq!(
        error.to_string(),
        "line 2, column 3: <language> attribute endian=\"sideways\": expected big or little"
    );
    assert_eq!(
        error.kind,
        ParseErrorKind::Schema(Violation::InvalidAttributeValue {
            element: "language",
            name: "endian",
            value: "sideways".into(),
            expected: "big or little",
        })
    );

    let error = pspec::parse(
        "<processor_spec>\n\n   <programcounter/>\n</processor_spec>",
        Mode::Strict,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "line 3, column 4: <programcounter> is missing required attribute \"register\""
    );
    // Lenient mode cannot invent the register either.
    let error = pspec::parse(
        "<processor_spec><programcounter/></processor_spec>",
        Mode::Lenient,
    )
    .unwrap_err();
    assert!(
        matches!(error.kind, ParseErrorKind::MissingAttribute { .. }),
        "{error}"
    );

    let error = opinion::parse(
        "<opinions>\n<constraint>\n  <bogus/></constraint></opinions>",
        Mode::Strict,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "line 3, column 3: element <bogus> is not allowed in <constraint>"
    );
}

#[test]
fn malformed_documents_are_errors_not_panics() {
    let error = pspec::parse(
        "<processor_spec><properties></processor_spec>",
        Mode::Lenient,
    )
    .unwrap_err();
    assert!(matches!(error.kind, ParseErrorKind::Xml(_)), "{error}");
    assert_eq!(error.position.line, 1);

    let error = pspec::parse("<compiler_spec/>", Mode::Lenient).unwrap_err();
    assert_eq!(
        error.to_string(),
        "line 1, column 1: expected root element <processor_spec>, found <compiler_spec>"
    );
    assert!(ldefs::parse("", Mode::Strict).is_err());
    assert!(opinion::parse("not xml", Mode::Strict).is_err());

    // A document type declaration is refused: no spec file has one, and
    // entity expansion is how XML readers are made to exhaust memory.
    let dtd = "<!DOCTYPE opinions [<!ENTITY a \"aaaa\">]><opinions/>";
    assert!(matches!(
        opinion::parse(dtd, Mode::Lenient).unwrap_err().kind,
        ParseErrorKind::Xml(_)
    ));

    // Namespaced elements are not the schema's elements.
    let namespaced = r#"<opinions xmlns:x="urn:x"><x:constraint/></opinions>"#;
    assert!(opinion::parse(namespaced, Mode::Strict).is_err());
    assert!(
        opinion::parse(namespaced, Mode::Lenient)
            .unwrap()
            .value
            .constraints()
            .is_empty()
    );
}

#[test]
fn xml_declaration_variants_are_accepted() {
    // Four shipped .ldefs files declare XML 1.1.
    for prolog in [
        "",
        "<?xml version=\"1.0\"?>",
        "<?xml version=\"1.1\" encoding=\"UTF-8\"?>",
        "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    ] {
        let text = format!("{prolog}\n<opinions><constraint loader=\"L\"/></opinions>");
        let text = text.trim_start_matches('\n');
        let opinions =
            opinion::parse(text, Mode::Strict).unwrap_or_else(|e| panic!("{prolog:?}: {e}"));
        assert_eq!(opinions.value.constraints().len(), 1);
    }
}

#[test]
fn reading_a_file_reports_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pspec");
    let error = pspec::read_file(&missing, Mode::Strict).unwrap_err();
    assert!(matches!(error, bk_lang::ReadError::Io { .. }));
    assert!(
        error
            .to_string()
            .starts_with(&missing.display().to_string())
    );

    let bad = dir.path().join("bad.opinion");
    std::fs::write(&bad, "<opinions>\n<constraint size=\"big\"/></opinions>").unwrap();
    let error = opinion::read_file(&bad, Mode::Strict).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "{}: line 2, column 1: <constraint> attribute size=\"big\": expected a decimal integer",
            bad.display()
        )
    );

    let binary = dir.path().join("binary.ldefs");
    std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).unwrap();
    assert!(matches!(
        ldefs::read_file(&binary, Mode::Strict).unwrap_err(),
        bk_lang::ReadError::Encoding { .. }
    ));

    let good = dir.path().join("good.ldefs");
    std::fs::write(&good, LDEFS).unwrap();
    assert_eq!(
        ldefs::read_file(&good, Mode::Strict)
            .unwrap()
            .value
            .languages
            .len(),
        2
    );
}
