//! Decoder behaviour Ghidra does not test: every error path of both decoders,
//! hand-written packed input for each type code, and the rules for attribute
//! iteration. Derived from `XmlDecode` and `PackedDecode` in `marshal.cc`.

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

use bk_marshal::ids::{
    ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE,
    ATTRIB_UNKNOWN, ATTRIB_VAL, ATTRIB_VALUE, ATTRIBUTES, ELEM_DATA, ELEM_INPUT, ELEM_OFF,
    ELEM_UNKNOWN, ELEM_VOID, ELEMENTS,
};
use bk_marshal::{
    AttributeId, AttributeKind, DecodeError, Decoder, Document, ElemCode, Encoder, IdTable,
    MAX_ELEMENT_DEPTH, NoSpaces, PackedDecoder, PackedEncoder, SpaceId, SpaceResolver, XmlDecoder,
    XmlEncoder,
};

const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 94);

/// Spaces 0, 1 and 3 exist (2 is an empty slot); 1 is the stack.
struct Spaces;

impl SpaceResolver for Spaces {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        match name {
            "const" => Some(SpaceId::new(0)),
            "stack" => Some(SpaceId::new(1)),
            "ram" => Some(SpaceId::new(3)),
            _ => None,
        }
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        matches!(index, 0 | 1 | 3).then(|| SpaceId::new(index as u32))
    }

    fn space_count(&self) -> u64 {
        4
    }

    fn stack_space(&self) -> Option<SpaceId> {
        Some(SpaceId::new(1))
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

fn ids() -> IdTable {
    IdTable::new(&[ATTRIBUTES, &[ATTRIB_PIECE]], &[ELEMENTS]).unwrap()
}

/// Runs `read` on an XML decoder over `text`.
fn xml<T>(text: &str, read: impl FnOnce(&mut XmlDecoder<'_>) -> T) -> T {
    let ids = ids();
    let document = Document::parse(text).unwrap();
    read(&mut XmlDecoder::new(&document, &ids, &Spaces))
}

fn packed<T>(bytes: &[u8], read: impl FnOnce(&mut PackedDecoder<'_>) -> T) -> T {
    read(&mut PackedDecoder::new(bytes, &Spaces))
}

/// `<data>` holding the attributes in `bytes`, in the packed form.
fn data_with(attributes: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x41];
    bytes.extend_from_slice(attributes);
    bytes.push(0x81);
    bytes
}

fn by_name(name: &str) -> Option<i64> {
    match name {
        "COPY" => Some(1),
        "LOAD" => Some(2),
        _ => None,
    }
}

#[test]
fn packed_values_for_each_type_code() {
    // One attribute of each type, written by hand from PackedFormat.
    let bytes = data_with(&[
        0xc2, 0x11, // align = true
        0xc9, 0x10, // id = false
        0xd3, 0x22, 0x82, 0x80, // size = +0x100
        0xd8, 0x31, 0x85, // val = -5
        0xd9, 0x42, 0xff, 0xff, // value = 0x3fff unsigned
        0xd4, 0x51, 0x83, // space = index 3
        0xce, 0x72, 0x80, 0x82, b'h', b'i', // name = "hi" with a two-byte length
        0xe1, 0xa1, 0x60, // unknown (161) = stack space
    ]);
    packed(&bytes, |d| {
        let element = d.open_element_expecting(ELEM_DATA).unwrap();
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
        assert!(d.read_bool().unwrap());
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ID);
        assert!(!d.read_bool().unwrap());
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_SIZE);
        assert_eq!(d.read_signed().unwrap(), 0x100);
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_VAL);
        assert_eq!(d.read_signed().unwrap(), -5);
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_VALUE);
        assert_eq!(d.read_unsigned().unwrap(), 0x3fff);
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_SPACE);
        assert_eq!(d.read_space().unwrap(), SpaceId::new(3));
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_NAME);
        assert_eq!(d.read_string().unwrap(), "hi");
        assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_UNKNOWN);
        assert_eq!(d.read_space().unwrap(), SpaceId::new(1));
        assert_eq!(d.next_attribute().unwrap(), None);
        assert_eq!(d.next_attribute().unwrap(), None);
        // By id, in any order, repeatedly.
        assert_eq!(d.read_string_attr(ATTRIB_NAME).unwrap(), "hi");
        assert_eq!(d.read_signed_attr(ATTRIB_VAL).unwrap(), -5);
        assert_eq!(d.read_signed_attr(ATTRIB_VAL).unwrap(), -5);
        assert!(d.read_bool_attr(ATTRIB_ALIGN).unwrap());
        assert_eq!(d.read_unsigned_attr(ATTRIB_VALUE).unwrap(), 0x3fff);
        assert_eq!(d.read_space_attr(ATTRIB_SPACE).unwrap(), SpaceId::new(3));
        assert_eq!(d.read_enum_attr(ATTRIB_SIZE, &by_name).unwrap(), 0x100);
        d.close_element(element).unwrap();
    });
}

#[test]
fn packed_integers_longer_than_ten_groups_drop_high_bits() {
    // Length code 11: Ghidra shifts the excess bits out.
    let bytes = data_with(&[
        0xc2, 0x4b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81,
    ]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(
            d.read_unsigned_attr(ATTRIB_ALIGN).unwrap(),
            0xffff_ffff_ffff_ff81
        );
    });
    // The marker bit of a group is not checked.
    let bytes = data_with(&[0xc2, 0x42, 0x01, 0x02]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(d.read_unsigned_attr(ATTRIB_ALIGN).unwrap(), 0x82);
    });
    // The most negative signed value.
    let bytes = data_with(&[
        0xc2, 0x3a, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    ]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(d.read_signed_attr(ATTRIB_ALIGN).unwrap(), i64::MIN);
    });
}

#[test]
fn wrong_kind_reads_fail_and_skip_the_attribute() {
    type Read = fn(&mut PackedDecoder<'_>) -> Result<(), DecodeError>;
    // name = "hi", then align = true.
    let bytes = data_with(&[0xce, 0x71, 0x82, b'h', b'i', 0xc2, 0x11]);
    let kinds: [(AttributeKind, Read); 4] = [
        (AttributeKind::Boolean, |d| d.read_bool().map(drop)),
        (AttributeKind::SignedInteger, |d| d.read_signed().map(drop)),
        (AttributeKind::UnsignedInteger, |d| {
            d.read_unsigned().map(drop)
        }),
        (AttributeKind::Space, |d| d.read_space().map(drop)),
    ];
    for (expected, read) in kinds {
        packed(&bytes, |d| {
            d.open_element().unwrap();
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_NAME);
            assert_eq!(
                read(d),
                Err(DecodeError::WrongAttributeKind {
                    expected,
                    offset: 2
                })
            );
            // The string was skipped: iteration continues with the next attribute.
            assert_eq!(d.next_attribute().unwrap().unwrap(), ATTRIB_ALIGN);
            assert!(d.read_bool().unwrap());
            assert_eq!(d.next_attribute().unwrap(), None);
        });
    }
    packed(&bytes, |d| {
        d.open_element().unwrap();
        d.next_attribute().unwrap();
        d.next_attribute().unwrap();
        let wrong = DecodeError::WrongAttributeKind {
            expected: AttributeKind::String,
            offset: 7,
        };
        assert_eq!(d.read_string(), Err(wrong.clone()));
        assert_eq!(d.read_string_attr(ATTRIB_ALIGN), Err(wrong));
        assert_eq!(
            d.read_enum_attr(ATTRIB_NAME, &by_name),
            Err(DecodeError::WrongAttributeKind {
                expected: AttributeKind::SignedInteger,
                offset: 2
            })
        );
        assert_eq!(wrong_message(), "Expecting string attribute (at byte 7)");
    });
}

fn wrong_message() -> String {
    DecodeError::WrongAttributeKind {
        expected: AttributeKind::String,
        offset: 7,
    }
    .to_string()
}

#[test]
fn signed_or_string_forms() {
    let bytes = data_with(&[
        0xce, 0x71, 0x82, b'h', b'i', 0xc2, 0x21, 0x87, 0xc9, 0x41, 0x81,
    ]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_NAME, "hi", 800)
                .unwrap(),
            800
        );
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_NAME, "ho", 800),
            Err(DecodeError::UnexpectedString {
                expected: "ho".into(),
                found: "hi".into()
            })
        );
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_ALIGN, "hi", 800)
                .unwrap(),
            7
        );
        assert!(matches!(
            d.read_signed_or_string_attr(ATTRIB_ID, "hi", 800),
            Err(DecodeError::WrongAttributeKind {
                expected: AttributeKind::SignedInteger,
                ..
            })
        ));
    });
    xml("<data name='hi' align='7' id='junk'/>", |d| {
        d.open_element().unwrap();
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_NAME, "hi", 800)
                .unwrap(),
            800
        );
        // The XML form has no types: text that is not the stand-in is read as
        // a number, and text that is no number reads as 0, as in Ghidra.
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_NAME, "ho", 800)
                .unwrap(),
            0
        );
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_ALIGN, "hi", 800)
                .unwrap(),
            7
        );
        assert_eq!(
            d.read_signed_or_string_attr(ATTRIB_ID, "hi", 800).unwrap(),
            0
        );
    });
}

#[test]
fn space_attributes() {
    let cases: [(&[u8], Result<SpaceId, DecodeError>); 9] = [
        (&[0xd4, 0x50], Ok(SpaceId::new(0))),
        (&[0xd4, 0x51, 0x83], Ok(SpaceId::new(3))),
        (&[0xd4, 0x51, 0x82], Err(DecodeError::UnknownSpaceIndex(2))),
        (&[0xd4, 0x51, 0x84], Err(DecodeError::InvalidSpaceIndex(4))),
        (&[0xd4, 0x60], Ok(SpaceId::new(1))),
        (&[0xd4, 0x61], Err(DecodeError::UnsupportedSpecialSpace(1))),
        (&[0xd4, 0x62], Err(DecodeError::UnsupportedSpecialSpace(2))),
        (&[0xd4, 0x63], Err(DecodeError::UnsupportedSpecialSpace(3))),
        (&[0xd4, 0x64], Err(DecodeError::UnsupportedSpecialSpace(4))),
    ];
    for (attribute, expected) in cases {
        let bytes = data_with(attribute);
        packed(&bytes, |d| {
            d.open_element().unwrap();
            assert_eq!(d.read_space_attr(ATTRIB_SPACE), expected, "{attribute:x?}");
        });
    }
    xml("<data space='ram' name='nowhere'>stack</data>", |d| {
        d.open_element().unwrap();
        assert_eq!(d.read_space_attr(ATTRIB_SPACE).unwrap(), SpaceId::new(3));
        assert_eq!(d.read_space_attr(ATTRIB_CONTENT).unwrap(), SpaceId::new(1));
        assert_eq!(
            d.read_space_attr(ATTRIB_NAME),
            Err(DecodeError::UnknownSpaceName("nowhere".into()))
        );
        d.next_attribute().unwrap();
        assert_eq!(d.read_space().unwrap(), SpaceId::new(3));
    });
    // A decoder without spaces rejects every reference.
    let bytes = data_with(&[0xd4, 0x50]);
    let mut decoder = PackedDecoder::new(&bytes, &NoSpaces);
    decoder.open_element().unwrap();
    assert_eq!(
        decoder.read_space_attr(ATTRIB_SPACE),
        Err(DecodeError::InvalidSpaceIndex(0))
    );
}

#[test]
fn enum_attributes() {
    xml("<data name='LOAD' val='nonesuch'>COPY</data>", |d| {
        d.open_element().unwrap();
        assert_eq!(d.read_enum_attr(ATTRIB_NAME, &by_name).unwrap(), 2);
        assert_eq!(d.read_enum_attr(ATTRIB_CONTENT, &by_name).unwrap(), 1);
        assert_eq!(
            d.read_enum_attr(ATTRIB_VAL, &by_name),
            Err(DecodeError::UnknownEnumName("nonesuch".into()))
        );
        d.next_attribute().unwrap();
        assert_eq!(d.read_enum(&by_name).unwrap(), 2);
    });
    let mut encoder = PackedEncoder::new();
    encoder.open_element(ELEM_DATA);
    encoder.write_enum(ATTRIB_NAME, 2, "LOAD");
    encoder.close_element(ELEM_DATA);
    packed(encoder.as_bytes(), |d| {
        d.open_element().unwrap();
        d.next_attribute().unwrap();
        assert_eq!(d.read_enum(&by_name).unwrap(), 2);
        assert_eq!(d.read_enum_attr(ATTRIB_NAME, &by_name).unwrap(), 2);
    });
    let mut encoder = XmlEncoder::new(false);
    encoder.open_element(ELEM_DATA);
    encoder.write_enum(ATTRIB_NAME, 2, "LOAD");
    encoder.close_element(ELEM_DATA);
    assert_eq!(encoder.as_str(), "<data name=\"LOAD\"/>");
}

#[test]
fn missing_attributes() {
    let bytes = data_with(&[0xc2, 0x11]);
    packed(&bytes, |d| {
        d.open_element().unwrap();
        let missing = DecodeError::AttributeMissing { name: "name" };
        assert_eq!(d.read_string_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_bool_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_signed_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_unsigned_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_space_attr(ATTRIB_NAME), Err(missing.clone()));
        // In the packed form the content is an attribute like any other.
        assert_eq!(
            d.read_string_attr(ATTRIB_CONTENT),
            Err(DecodeError::AttributeMissing { name: "XMLcontent" })
        );
        assert_eq!(missing.to_string(), "Attribute name is not present");
        // The element is still usable.
        assert!(d.read_bool_attr(ATTRIB_ALIGN).unwrap());
    });
    xml("<data align='true'/>", |d| {
        d.open_element().unwrap();
        let missing = DecodeError::AttributeMissing { name: "name" };
        assert_eq!(d.read_string_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_bool_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_signed_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_unsigned_attr(ATTRIB_NAME), Err(missing.clone()));
        assert_eq!(d.read_space_attr(ATTRIB_NAME), Err(missing));
        // In XML the content always exists; it may be empty.
        assert_eq!(d.read_string_attr(ATTRIB_CONTENT).unwrap(), "");
        assert!(!d.read_bool_attr(ATTRIB_CONTENT).unwrap());
        assert_eq!(d.read_signed_attr(ATTRIB_CONTENT).unwrap(), 0);
        assert_eq!(d.read_unsigned_attr(ATTRIB_CONTENT).unwrap(), 0);
        assert!(d.read_bool_attr(ATTRIB_ALIGN).unwrap());
    });
}

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
