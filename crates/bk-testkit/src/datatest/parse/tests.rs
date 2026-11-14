//! Tests for the data-test parser.

use super::*;
use proptest::prelude::*;
use rstest::rstest;

const SAMPLE: &str = r#"<decompilertest>
<binaryimage arch="x86:LE:64:default:gcc">
<!-- a comment is not an element -->
<bytechunk space="ram" offset="0x100000" readonly="true">
                              f3
0f1efa 4889F8
c3
</bytechunk>
<bytechunk space="ram" offset="4096">
</bytechunk>
<symbol space="ram" offset="0x100000" name="identity"/>
</binaryimage>
<script>
  <com>option readonly on</com>
  <com>parse line extern int4
       identity(int4 a);</com>
  <com><![CDATA[parse line struct s { int4 a<b>; };]]></com>
  <com>lo fu identity</com>
  <com>decompile</com>
  <com>print C</com>
  <com>quit</com>
</script>
<stringmatch name="Identity #1" min="1" max="1">return a;</stringmatch>
<stringmatch name="Identity #2" min="0" max="2">if \(a &lt; 0\) \{
   a = -a;
  \}
</stringmatch>
</decompilertest>
"#;

#[test]
fn sample_parses_into_the_model() {
    let test = parse_data_test(SAMPLE).unwrap();

    assert_eq!(test.image.arch, "x86:LE:64:default:gcc");
    assert_eq!(test.image.language_id(), "x86:LE:64:default");
    assert_eq!(test.image.chunks.len(), 2);
    let first = &test.image.chunks[0];
    assert_eq!(
        (first.space.as_str(), first.offset, first.readonly),
        ("ram", 0x10_0000, true)
    );
    assert_eq!(
        first.bytes,
        [0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x89, 0xf8, 0xc3]
    );
    let second = &test.image.chunks[1];
    assert_eq!(
        (second.offset, second.readonly, second.bytes.len()),
        (4096, false, 0)
    );
    assert_eq!(test.image.byte_count(), 8);
    assert_eq!(
        test.image.symbols,
        [ImageSymbol {
            space: "ram".to_owned(),
            offset: 0x10_0000,
            name: "identity".to_owned()
        }]
    );

    assert_eq!(test.script.len(), 7);
    assert_eq!(test.script[0], "option readonly on");
    assert_eq!(
        test.script[1],
        "parse line extern int4        identity(int4 a);"
    );
    assert_eq!(test.script[2], "parse line struct s { int4 a<b>; };");
    assert_eq!(test.script[6], "quit");

    assert_eq!(test.matches.len(), 2);
    assert_eq!(test.matches[0].name, "Identity #1");
    assert_eq!((test.matches[0].min, test.matches[0].max), (1, 1));
    assert_eq!(test.matches[0].lines, ["return a;"]);
    assert_eq!((test.matches[1].min, test.matches[1].max), (0, 2));
    assert_eq!(
        test.matches[1].lines,
        [r"if \(a < 0\) \{", "a = -a;", r"\}"]
    );
}

#[rstest]
#[case("one", &["one"])]
#[case("  one\n\ttwo", &["one", "two"])]
#[case("one\n", &["one"])]
#[case("one\n   ", &["one"])]
#[case("one\n\ntwo", &["one", "", "two"])]
#[case("one  \ntwo", &["one  ", "two"])]
#[case("", &[])]
#[case(" \t ", &[])]
#[case("\nlate", &["", "late"])]
fn pattern_lines_follow_ghidra(#[case] pattern: &str, #[case] expected: &[&str]) {
    assert_eq!(pattern_lines(pattern), expected);
}

#[rstest]
#[case("0x10", 16)]
#[case("0X1f", 31)]
#[case("010", 8)]
#[case("10", 10)]
#[case("0", 0)]
#[case("0xffffffffffffffff", u64::MAX)]
fn offsets_use_c_notation(#[case] text: &str, #[case] expected: u64) {
    let xml = format!(
        "<decompilertest><binaryimage arch=\"a\"><symbol space=\"ram\" offset=\"{text}\" \
             name=\"s\"/></binaryimage><script/><stringmatch name=\"n\" min=\"1\" \
             max=\"1\">x</stringmatch></decompilertest>"
    );
    assert_eq!(
        parse_data_test(&xml).unwrap().image.symbols[0].offset,
        expected
    );
}

#[rstest]
#[case("true", true)]
#[case("1", true)]
#[case("yes", true)]
#[case("false", false)]
#[case("0", false)]
#[case("", false)]
fn readonly_follows_xml_readbool(#[case] text: &str, #[case] expected: bool) {
    assert_eq!(xml_bool(text), expected);
}

/// Wrap fragments into an otherwise valid test.
fn document(image: &str, rest: &str) -> String {
    format!("<decompilertest>{image}{rest}</decompilertest>")
}

const IMAGE: &str = "<binaryimage arch=\"a\"/>";
const SCRIPT: &str = "<script><com>quit</com></script>";
const CHECK: &str = "<stringmatch name=\"n\" min=\"1\" max=\"1\">x</stringmatch>";

#[test]
fn minimal_test_parses() {
    let test = parse_data_test(&document(IMAGE, &format!("{SCRIPT}{CHECK}"))).unwrap();
    assert_eq!(test.script, ["quit"]);
    assert_eq!(test.image.chunks, []);
}

#[test]
fn each_part_is_required() {
    let no_script = parse_data_test(&document(IMAGE, CHECK)).unwrap_err();
    assert!(
        matches!(no_script, DataTestError::MissingScript),
        "{no_script}"
    );
    let no_check = parse_data_test(&document(IMAGE, SCRIPT)).unwrap_err();
    assert!(
        matches!(no_check, DataTestError::MissingStringMatch),
        "{no_check}"
    );
    let no_image = parse_data_test(&document("", &format!("{SCRIPT}{CHECK}"))).unwrap_err();
    assert!(
        matches!(no_image, DataTestError::MissingImage),
        "{no_image}"
    );
}

#[test]
fn malformed_input_is_an_error_with_a_place() {
    let cases = [
        ("<decompilertest", "not well-formed XML"),
        ("<other/>", "root element is <other>"),
        ("<binaryimage arch=\"a\"/>", "old-format test"),
        (
            "<decompilertest>\n<extra/></decompilertest>",
            "line 2: unknown element <extra>",
        ),
        (
            "<decompilertest><binaryimage/></decompilertest>",
            "line 1: <binaryimage> has no `arch` attribute",
        ),
        (
            "<decompilertest><binaryimage arch=\"a\"><segment/></binaryimage></decompilertest>",
            "unknown element <segment> in <binaryimage>",
        ),
        (
            "<decompilertest><binaryimage arch=\"a\"><bytechunk space=\"ram\" \
                 offset=\"zz\"/></binaryimage></decompilertest>",
            "attribute `offset` is not a number: \"zz\"",
        ),
        (
            "<decompilertest><binaryimage arch=\"a\"><bytechunk space=\"ram\" \
                 offset=\"0\">0g</bytechunk></binaryimage></decompilertest>",
            "not hexadecimal byte pairs (at \"0g\")",
        ),
        (
            "<decompilertest><binaryimage arch=\"a\"><bytechunk space=\"ram\" \
                 offset=\"0\">abc</bytechunk></binaryimage></decompilertest>",
            "not hexadecimal byte pairs (at \"c\")",
        ),
        (
            "<decompilertest><stringmatch name=\"n\" min=\"-1\" max=\"1\">x</stringmatch>\
                 </decompilertest>",
            "attribute `min` is not a number: \"-1\"",
        ),
        (
            "<decompilertest><stringmatch min=\"1\" max=\"1\">x</stringmatch></decompilertest>",
            "<stringmatch> has no `name` attribute",
        ),
        (
            "<decompilertest><binaryimage arch=\"a\"/>\n<binaryimage arch=\"b\"/>\
                 </decompilertest>",
            "line 2: more than one <binaryimage>",
        ),
    ];
    for (xml, expected) in cases {
        let error = parse_data_test(xml).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{xml}\n  gave: {error}\n  wanted: {expected}"
        );
    }
}

#[test]
fn a_missing_file_names_the_path() {
    let error = read_data_test(Path::new("/nonexistent/test.xml")).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("cannot read /nonexistent/test.xml:"),
        "{error}"
    );
}

fn arbitrary_image() -> impl Strategy<Value = BinaryImage> {
    let chunk = (
        "[a-z]{1,8}",
        any::<u64>(),
        any::<bool>(),
        prop::collection::vec(any::<u8>(), 0..80),
    )
        .prop_map(|(space, offset, readonly, bytes)| ByteChunk {
            space,
            offset,
            readonly,
            bytes,
        });
    let symbol =
        ("[a-z]{1,8}", any::<u64>(), "[ -~]{0,16}").prop_map(|(space, offset, name)| ImageSymbol {
            space,
            offset,
            name,
        });
    (
        "[ -~]{0,24}",
        prop::collection::vec(chunk, 0..4),
        prop::collection::vec(symbol, 0..4),
    )
        .prop_map(|(arch, chunks, symbols)| BinaryImage {
            arch,
            chunks,
            symbols,
        })
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
        let _ = parse_data_test(&text);
    }

    #[test]
    fn arbitrary_documents_never_panic(
        body in "(<(script|com|stringmatch|binaryimage|bytechunk|symbol)( (name|min|max|space|offset|arch)=\"[0-9a-fx]{0,4}\"){0,3}>[0-9a-f \n]{0,12}){0,6}"
    ) {
        let _ = parse_data_test(&format!("<decompilertest>{body}</decompilertest>"));
    }

    #[test]
    fn images_survive_a_round_trip_through_xml(image in arbitrary_image()) {
        let xml = document(&image.to_xml(), &format!("{SCRIPT}{CHECK}"));
        let parsed = parse_data_test(&xml).unwrap();
        prop_assert_eq!(parsed.image, image);
    }
}
