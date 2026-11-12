//! Decoder behaviour Ghidra does not test, part 1: the values of each
//! attribute type in both forms — hand-written packed input for each type
//! code, reads of the wrong kind, signed-or-string, spaces, enumerations and
//! missing attributes. Derived from `XmlDecode` and `PackedDecode` in
//! `marshal.cc`.

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
    ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE,
    ATTRIB_UNKNOWN, ATTRIB_VAL, ATTRIB_VALUE, ELEM_DATA,
};
use bk_marshal::{
    AttributeKind, DecodeError, Decoder, Encoder, NoSpaces, PackedDecoder, PackedEncoder, SpaceId,
    XmlEncoder,
};
use decoder_support::*;

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
