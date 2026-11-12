//! Decoder behaviour Ghidra does not test, part 2: the structure of a
//! document — reads without a current attribute, nothing open, close and
//! skip checks, truncated and malformed packed input, attribute iteration
//! after children and by id, indexed attributes, XML value forms, subtree
//! decoders, the nesting limit and error messages. Derived from `XmlDecode`
//! and `PackedDecode` in `marshal.cc`.

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

mod decoder_support;

use bk_marshal::ids::{
    ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_UNKNOWN, ELEM_DATA, ELEM_INPUT,
    ELEM_OFF, ELEM_UNKNOWN, ELEM_VOID,
};
use bk_marshal::{
    DecodeError, Decoder, Document, ElemCode, Encoder, MAX_ELEMENT_DEPTH, PackedEncoder,
    XmlDecoder, XmlEncoder,
};
use decoder_support::*;

#[test]
fn reads_need_a_current_attribute() {
    fn check(d: &mut dyn Decoder<'_>) {
        let no_current = Err(DecodeError::NoCurrentAttribute);
        assert_eq!(d.read_bool(), no_current, "before next_attribute");
        d.next_attribute().unwrap().unwrap();
        assert!(d.read_bool().unwrap());
        assert_eq!(d.next_attribute().unwrap(), None);
        assert_eq!(d.read_bool(), no_current, "after the last attribute");
        assert_eq!(d.read_signed(), Err(DecodeError::NoCurrentAttribute));
        assert_eq!(d.read_unsigned(), Err(DecodeError::NoCurrentAttribute));
        assert_eq!(d.read_string(), Err(DecodeError::NoCurrentAttribute));
        assert_eq!(d.read_space(), Err(DecodeError::NoCurrentAttribute));
        assert_eq!(
            d.read_signed_or_string("x", 1),
            Err(DecodeError::NoCurrentAttribute)
        );
        assert_eq!(d.read_enum(&by_name), Err(DecodeError::NoCurrentAttribute));
        d.rewind_attributes();
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
        // An attribute may be skipped without reading it.
        assert_eq!(d.next_attribute().unwrap(), None);
    }
    packed(&data_with(&[0xc2, 0x11]), |d| {
        d.open_element().unwrap();
        check(d);
    });
    xml("<data align='true'/>", |d| {
        d.open_element().unwrap();
        check(d);
    });
}

#[test]
fn nothing_open() {
    fn check(d: &mut dyn Decoder<'_>) {
        assert_eq!(
            d.close_element(ELEM_DATA.code()),
            Err(DecodeError::NoOpenElement)
        );
        assert_eq!(
            d.read_bool_attr(ATTRIB_ALIGN),
            Err(DecodeError::NoOpenElement)
        );
        let element = d.open_element().unwrap().unwrap();
        d.close_element(element).unwrap();
        assert_eq!(d.peek_element(), None);
        assert_eq!(d.open_element().unwrap(), None);
        d.skip_element().unwrap();
        assert_eq!(
            d.open_element_expecting(ELEM_DATA),
            Err(DecodeError::NoElement { expected: "data" })
        );
        assert_eq!(
            d.read_bool_attr(ATTRIB_ALIGN),
            Err(DecodeError::NoOpenElement)
        );
    }
    xml("<data/>", |d| {
        assert_eq!(d.next_attribute(), Err(DecodeError::NoOpenElement));
        assert_eq!(
            d.close_element_skipping(ELEM_DATA.code()),
            Err(DecodeError::NoOpenElement)
        );
        assert!(d.current_element().is_none());
        check(d);
    });
    // The packed form sees the end of the data where XML sees an empty stack.
    packed(&[0x41, 0x81], |d| {
        assert_eq!(d.next_attribute().unwrap(), None);
        assert_eq!(
            d.read_bool_attr(ATTRIB_ALIGN),
            Err(DecodeError::NoOpenElement)
        );
        let element = d.open_element().unwrap().unwrap();
        d.close_element(element).unwrap();
        assert_eq!(d.peek_element(), None);
        assert_eq!(d.open_element().unwrap(), None);
        d.skip_element().unwrap();
        assert_eq!(
            d.open_element_expecting(ELEM_DATA),
            Err(DecodeError::NoElement { expected: "data" })
        );
        assert_eq!(
            d.close_element(element),
            Err(DecodeError::UnexpectedEof { offset: 2 })
        );
        assert_eq!(
            d.close_element_skipping(element),
            Err(DecodeError::UnexpectedEof { offset: 2 })
        );
    });
    packed(&[], |d| {
        assert_eq!(d.peek_element(), None);
        assert_eq!(d.open_element().unwrap(), None);
        assert_eq!(d.position(), 0);
    });
}

#[test]
fn close_checks() {
    // <data><input/><off/></data>
    let bytes = [0x41, 0x42, 0x82, 0x43, 0x83, 0x81];
    packed(&bytes, |d| {
        let data = d.open_element().unwrap().unwrap();
        let input = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element(ELEM_OFF.code()),
            Err(DecodeError::CloseMismatch {
                expected: 3,
                found: 2
            })
        );
        let _ = (data, input);
    });
    packed(&bytes, |d| {
        let data = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element(data),
            Err(DecodeError::UnreadChildren {
                element: "id 1".into()
            })
        );
    });
    xml("<data><input/><off/></data>", |d| {
        let data = d.open_element().unwrap().unwrap();
        let input = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element(ELEM_OFF.code()),
            Err(DecodeError::CloseMismatch {
                expected: 3,
                found: 2
            })
        );
        assert_eq!(
            d.close_element_skipping(ELEM_OFF.code()),
            Err(DecodeError::CloseMismatch {
                expected: 3,
                found: 2
            })
        );
        d.close_element(input).unwrap();
        assert_eq!(
            d.close_element(data),
            Err(DecodeError::UnreadChildren {
                element: "<data>".into()
            })
        );
        d.close_element_skipping(data).unwrap();
    });
    // An element whose name is not registered closes with the unknown code.
    xml("<mystery><data/></mystery>", |d| {
        let element = d.open_element().unwrap().unwrap();
        assert_eq!(element, ELEM_UNKNOWN);
        assert_eq!(d.peek_element().unwrap(), ELEM_DATA);
        d.close_element_skipping(element).unwrap();
    });
}

#[test]
fn skipping_checks_the_stream() {
    // <data><input><off/></input><void/></data> with the inner close id wrong.
    let bytes = [0x41, 0x42, 0x43, 0x83, 0x8a, 0x4a, 0x8a, 0x81];
    packed(&bytes, |d| {
        let data = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element_skipping(data),
            Err(DecodeError::CloseMismatch {
                expected: 2,
                found: 10
            })
        );
    });
    // A byte that is no record header where a child or close must be.
    let bytes = [0x41, 0x42, 0x05, 0x82, 0x81];
    packed(&bytes, |d| {
        let data = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element_skipping(data),
            Err(DecodeError::CorruptStream { offset: 2 })
        );
    });
    packed(&bytes, |d| {
        d.open_element().unwrap();
        let input = d.open_element().unwrap().unwrap();
        assert_eq!(
            d.close_element(input),
            Err(DecodeError::CorruptStream { offset: 2 })
        );
    });
    // An extended close id.
    let bytes = [0x62, 0xa4, 0x41, 0x81, 0xa2, 0xa4];
    packed(&bytes, |d| {
        assert_eq!(d.peek_element().unwrap(), ELEM_UNKNOWN);
        let element = d.open_element_expecting(ELEM_UNKNOWN).unwrap();
        d.close_element_skipping(element).unwrap();
        assert_eq!(d.position(), 6);
    });
}

#[test]
fn truncated_packed_input() {
    let whole = data_with(&[
        0xce, 0x71, 0x85, b'h', b'e', b'l', b'l', b'o', 0xd3, 0x23, 0x81, 0x80, 0x80,
    ]);
    for cut in 1..whole.len() - 1 {
        let part = &whole[..cut];
        packed(part, |d| {
            // An attribute cut short is found when the element is opened,
            // because opening scans to the end of the attributes.
            assert!(
                matches!(d.open_element(), Err(DecodeError::UnexpectedEof { .. }))
                    || cut == 1
                    || cut == 9,
                "cut at {cut}"
            );
        });
    }
    // A string whose length runs past the end.
    let bytes = [0x41, 0xce, 0x71, 0xff, b'x'];
    packed(&bytes, |d| {
        assert_eq!(
            d.open_element(),
            Err(DecodeError::UnexpectedEof { offset: 5 })
        );
    });
    // A string length that does not fit in memory.
    let bytes = [
        0x41, 0xce, 0x7a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    packed(&bytes, |d| {
        assert!(matches!(
            d.open_element(),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    });
    // An extended header id cut off: Ghidra reads the padding byte as its low bits.
    packed(&[0x62], |d| {
        assert_eq!(d.peek_element(), Some(ElemCode::new(0x100)));
        assert_eq!(
            d.open_element(),
            Err(DecodeError::UnexpectedEof { offset: 1 })
        );
    });
}

#[test]
fn packed_strings_must_be_utf8() {
    let bytes = data_with(&[0xce, 0x72, 0x80, 0x82, 0xff, 0xfe]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(
            d.read_string_attr(ATTRIB_NAME),
            Err(DecodeError::InvalidUtf8 { offset: 5 })
        );
    });
}

#[test]
fn attributes_after_a_child_is_closed() {
    // <data align="true"><input id="false"/></data>
    let bytes = [0x41, 0xc2, 0x11, 0x42, 0xc9, 0x10, 0x82, 0x81];
    packed(&bytes, |d| {
        let data = d.open_element().unwrap().unwrap();
        let input = d.open_element().unwrap().unwrap();
        d.close_element(input).unwrap();
        // The stream has moved past the parent's attributes.
        assert_eq!(d.next_attribute().unwrap(), None);
        d.rewind_attributes();
        assert_eq!(d.next_attribute().unwrap(), None);
        assert_eq!(
            d.read_bool_attr(ATTRIB_ALIGN),
            Err(DecodeError::AttributesUnavailable)
        );
        assert_eq!(d.read_bool(), Err(DecodeError::NoCurrentAttribute));
        d.close_element(data).unwrap();
    });
    xml("<data align='true'><input id='false'/></data>", |d| {
        let data = d.open_element().unwrap().unwrap();
        let input = d.open_element().unwrap().unwrap();
        d.close_element(input).unwrap();
        // As in Ghidra's XmlDecode: iteration is over until rewound, and a
        // lookup by name works on the parent.
        assert_eq!(d.next_attribute().unwrap(), None);
        assert!(d.read_bool_attr(ATTRIB_ALIGN).unwrap());
        d.rewind_attributes();
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
        assert!(d.read_bool().unwrap());
        d.close_element(data).unwrap();
    });
}

#[test]
fn lookup_by_id_and_iteration() {
    // The packed form restarts iteration after a lookup by id; the XML form
    // leaves it where it was (both as in Ghidra).
    let bytes = data_with(&[0xc2, 0x11, 0xc9, 0x10]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
        assert!(!d.read_bool_attr(ATTRIB_ID).unwrap());
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
    });
    xml("<data align='true' id='false'/>", |d| {
        d.open_element().unwrap();
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
        assert!(!d.read_bool_attr(ATTRIB_ID).unwrap());
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ID);
    });
}

#[test]
fn indexed_attributes() {
    xml(
        "<data piece1='a' piece12='b' name='n' piece='c' piecemeal='d' other='e'/>",
        |d| {
            d.open_element().unwrap();
            // Before any attribute is current there is nothing to reinterpret.
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE).unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(
                d.indexed_attribute(ATTRIB_PIECE).unwrap(),
                ATTRIB_PIECE.indexed(0)
            );
            assert_eq!(d.read_string().unwrap(), "a");
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(
                d.indexed_attribute(ATTRIB_PIECE).unwrap(),
                ATTRIB_PIECE.indexed(11)
            );
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_NAME);
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE).unwrap(), ATTRIB_UNKNOWN);
            // The bare base name is registered; asked for as an index it is malformed.
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_PIECE);
            let bad = Err(DecodeError::BadIndexedAttribute { name: "piece" });
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE), bad);
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE), bad);
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE).unwrap(), ATTRIB_UNKNOWN);
            assert_eq!(d.next_attribute().unwrap(), None);
            assert_eq!(d.indexed_attribute(ATTRIB_PIECE).unwrap(), ATTRIB_UNKNOWN);
        },
    );
    // The packed form stores each member under its own id.
    let mut encoder = PackedEncoder::new();
    encoder.open_element(ELEM_DATA);
    encoder.write_string_indexed(ATTRIB_PIECE, 0, "a").unwrap();
    encoder.write_string_indexed(ATTRIB_PIECE, 11, "b").unwrap();
    encoder.close_element(ELEM_DATA);
    packed(encoder.as_bytes(), |d| {
        d.open_element().unwrap();
        assert_eq!(
            d.next_attribute().unwrap().unwrap(),
            ATTRIB_PIECE.indexed(0)
        );
        assert_eq!(d.indexed_attribute(ATTRIB_PIECE).unwrap(), ATTRIB_UNKNOWN);
        assert_eq!(
            d.next_attribute().unwrap().unwrap(),
            ATTRIB_PIECE.indexed(11)
        );
        assert_eq!(d.read_string().unwrap(), "b");
    });
}

#[test]
fn xml_value_forms() {
    xml(
        "<data a='0x1F' b='-12' c='010' d='yes' e='  7 ' f=''>  0x20  </data>",
        |d| {
            d.open_element().unwrap();
            let mut values = Vec::new();
            while d.next_attribute().unwrap().is_some() {
                values.push((
                    d.read_unsigned().unwrap(),
                    d.read_signed().unwrap(),
                    d.read_bool().unwrap(),
                ));
            }
            assert_eq!(
                values,
                [
                    (0x1f, 0x1f, false),
                    (12u64.wrapping_neg(), -12, false),
                    (8, 8, false),
                    (0, 0, true),
                    (7, 7, false),
                    (0, 0, false),
                ]
            );
            assert_eq!(d.read_unsigned_attr(ATTRIB_CONTENT).unwrap(), 0x20);
            assert_eq!(d.read_string_attr(ATTRIB_CONTENT).unwrap(), "  0x20  ");
            assert!(format!("{d:?}").contains("XmlDecoder"));
        },
    );
}

#[test]
fn subtree_decoder() {
    let ids = ids();
    let document = Document::parse("<data><input id='5'><off/></input><void/></data>").unwrap();
    let input = document.root().first_child().unwrap();
    let mut decoder = XmlDecoder::at(input, &ids, &Spaces);
    let element = decoder.open_element_expecting(ELEM_INPUT).unwrap();
    assert_eq!(decoder.current_element().unwrap().name(), "input");
    assert_eq!(decoder.read_signed_attr(ATTRIB_ID).unwrap(), 5);
    decoder.close_element_skipping(element).unwrap();
    // The decoder does not walk on to the subtree root's siblings.
    assert_eq!(decoder.peek_element(), None);
}

#[test]
fn nesting_limit() {
    let mut encoder = PackedEncoder::new();
    let mut text = XmlEncoder::new(false);
    for _ in 0..=MAX_ELEMENT_DEPTH {
        encoder.open_element(ELEM_VOID);
        text.open_element(ELEM_VOID);
    }
    for _ in 0..=MAX_ELEMENT_DEPTH {
        encoder.close_element(ELEM_VOID);
        text.close_element(ELEM_VOID);
    }
    let too_deep = Err(DecodeError::TooDeep {
        limit: MAX_ELEMENT_DEPTH,
    });
    packed(encoder.as_bytes(), |d| {
        for _ in 0..MAX_ELEMENT_DEPTH {
            d.open_element().unwrap().unwrap();
        }
        assert_eq!(d.open_element(), too_deep);
        assert_eq!(
            d.open_element_expecting(ELEM_VOID),
            Err(DecodeError::TooDeep {
                limit: MAX_ELEMENT_DEPTH
            })
        );
        assert!(format!("{d:?}").contains("PackedDecoder"));
    });
    // Skipping does not recurse, so it is not limited.
    packed(encoder.as_bytes(), |d| {
        let outer = d.open_element().unwrap().unwrap();
        d.close_element_skipping(outer).unwrap();
        assert_eq!(d.position(), encoder.len());
    });
    xml(text.as_str(), |d| {
        for _ in 0..MAX_ELEMENT_DEPTH {
            d.open_element().unwrap().unwrap();
        }
        assert_eq!(d.open_element(), too_deep);
    });
    xml(text.as_str(), |d| {
        let outer = d.open_element().unwrap().unwrap();
        d.close_element_skipping(outer).unwrap();
    });
}

#[test]
fn error_messages_follow_ghidra() {
    let cases = [
        (
            DecodeError::UnexpectedEof { offset: 9 },
            "Unexpected end of stream (at byte 9)",
        ),
        (
            DecodeError::NoElement { expected: "off" },
            "Expecting <off> but no element remains",
        ),
        (
            DecodeError::ElementMismatch {
                expected: "off",
                found: "<data>".into(),
            },
            "Expecting <off> but got <data>",
        ),
        (
            DecodeError::CorruptStream { offset: 3 },
            "Corrupt stream (at byte 3)",
        ),
        (
            DecodeError::UnknownSpaceName("x".into()),
            "Unknown address space name: x",
        ),
        (
            DecodeError::InvalidSpaceIndex(9),
            "Invalid address space index: 9",
        ),
        (
            DecodeError::UnknownSpaceIndex(2),
            "Unknown address space index: 2",
        ),
        (
            DecodeError::UnsupportedSpecialSpace(3),
            "Cannot marshal special address space (code 3)",
        ),
        (
            DecodeError::BadIndexedAttribute { name: "piece" },
            "Bad indexed attribute: piece",
        ),
        (
            DecodeError::UnexpectedString {
                expected: "a".into(),
                found: "b".into(),
            },
            "Expecting string \"a\" but read \"b\"",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
    let xml_error = Document::parse("<a").unwrap_err();
    assert!(
        DecodeError::from(xml_error.clone())
            .to_string()
            .starts_with("XML error at 1:")
    );
    assert_eq!(
        DecodeError::from(xml_error.clone()),
        DecodeError::Xml(xml_error)
    );
}
