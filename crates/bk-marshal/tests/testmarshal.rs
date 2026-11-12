//! Port of Ghidra's `unittests/testmarshal.cc` (18 tests) and of its Java twin
//! `ghidra.program.model.pcode.EncodeDecodeTest` (10 tests, the packed half).
//!
//! Each C++ test body runs here against both forms where the C++ does; the
//! test names are Ghidra's. On top of what Ghidra checks, the encoded bytes
//! and text of every test document are compared with vectors produced by an
//! independent transliteration of `PackedEncode` and `XmlEncode`
//! (`gen_marshal_vectors.py` next to this file), which is what shows the
//! packed form byte-identical and the XML text identical to Ghidra's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use bk_marshal::ids::{
    ATTRIB_ALIGN, ATTRIB_BIGENDIAN, ATTRIB_CONSTRUCTOR, ATTRIB_CONTENT, ATTRIB_DESTRUCTOR,
    ATTRIB_EXTRAPOP, ATTRIB_FORMAT, ATTRIB_ID, ATTRIB_INDEX, ATTRIB_METATYPE, ATTRIB_MODEL,
    ATTRIB_NAME, ATTRIB_SPACE, ATTRIB_VAL, ATTRIB_VALUE, ATTRIBUTES, ELEM_DATA, ELEM_INPUT,
    ELEM_OFF, ELEM_OUTPUT, ELEM_SYMBOL, ELEM_TARGET, ELEMENTS,
};
use bk_marshal::{
    DecodeError, Decoder, Document, ElementId, Encoder, IdTable, PackedDecoder, PackedEncoder,
    PackedSpace, SpaceId, SpaceRef, SpaceResolver, XmlDecoder, XmlEncoder,
};

/// `<addr>` is defined in Ghidra's `address.cc`, which belongs to `bk-core`.
const ELEM_ADDR: ElementId = ElementId::new("addr", 11);

/// Ghidra's `TestAddrSpaceManager`: one space, `ram`, at index 3.
struct TestSpaces;

const RAM: SpaceId = SpaceId::new(3);

impl SpaceResolver for TestSpaces {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        (name == "ram").then_some(RAM)
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        (index == 3).then_some(RAM)
    }

    fn space_count(&self) -> u64 {
        4
    }

    fn stack_space(&self) -> Option<SpaceId> {
        None
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Packed,
    Xml,
}

/// Runs `build` against the encoder of the given form and returns the bytes.
fn encode(form: Form, build: impl FnOnce(&mut dyn Encoder)) -> Vec<u8> {
    match form {
        Form::Packed => {
            let mut encoder = PackedEncoder::new();
            build(&mut encoder);
            encoder.into_bytes()
        }
        Form::Xml => {
            let mut encoder = XmlEncoder::new(true);
            build(&mut encoder);
            encoder.into_string().into_bytes()
        }
    }
}

/// Ingests `bytes` and runs `read` against the decoder of the given form.
fn decode<T>(
    form: Form,
    bytes: &[u8],
    read: impl FnOnce(&mut dyn Decoder<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    match form {
        Form::Packed => read(&mut PackedDecoder::new(bytes, &TestSpaces)),
        Form::Xml => {
            let ids = IdTable::new(&[ATTRIBUTES], &[ELEMENTS, &[ELEM_ADDR]]).unwrap();
            let text = std::str::from_utf8(bytes).unwrap();
            let document = Document::parse(text)?;
            read(&mut XmlDecoder::new(&document, &ids, &TestSpaces))
        }
    }
}

/// Checks the encoding against the vector derived from `marshal.cc`.
fn assert_encoding(form: Form, bytes: &[u8], packed: &[u8], xml: &str) {
    match form {
        Form::Packed => assert_eq!(bytes, packed, "packed bytes differ from Ghidra's"),
        Form::Xml => assert_eq!(std::str::from_utf8(bytes).unwrap(), xml),
    }
}

const SIGNED_PACKED: &[u8] = &[
    0x4b, 0xc2, 0x21, 0x83, 0xc3, 0x32, 0x82, 0x80, 0xc4, 0x23, 0xff, 0xff, 0xff, 0xc5, 0x34, 0xd5,
    0xf3, 0xbd, 0xfa, 0xc6, 0x25, 0xb0, 0x80, 0x80, 0x80, 0x80, 0xc7, 0x36, 0xe0, 0x90, 0x88, 0x84,
    0x82, 0x81, 0xc9, 0x27, 0x84, 0xc6, 0xc5, 0xb3, 0xe2, 0xa0, 0x91, 0xca, 0x38, 0xf8, 0xbc, 0x9e,
    0x8f, 0x87, 0xc3, 0xe1, 0xf0, 0xcc, 0x29, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x8b,
];
const SIGNED_XML: &str = "\n<addr align=\"3\" bigendian=\"-256\" constructor=\"2097151\" destructor=\"-180150010\" extrapop=\"12884901888\" format=\"-3302846693633\" id=\"20015998341137\" index=\"-67818912035696880\" metatype=\"9223372036854775807\"/>";
const UNSIGNED_PACKED: &[u8] = &[
    0x4b, 0xc2, 0x41, 0x83, 0xc3, 0x42, 0x82, 0x80, 0xc4, 0x43, 0xff, 0xff, 0xff, 0xc5, 0x44, 0xd5,
    0xf3, 0xbd, 0xfa, 0xc6, 0x45, 0xb0, 0x80, 0x80, 0x80, 0x80, 0xc7, 0x46, 0xe0, 0x90, 0x88, 0x84,
    0x82, 0x81, 0xc9, 0x47, 0x84, 0xc6, 0xc5, 0xb3, 0xe2, 0xa0, 0x91, 0xca, 0x48, 0xf8, 0xbc, 0x9e,
    0x8f, 0x87, 0xc3, 0xe1, 0xf0, 0xcc, 0x49, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xcd, 0x4a, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x8b,
];
const UNSIGNED_XML: &str = "\n<addr align=\"0x3\" bigendian=\"0x100\" constructor=\"0x1fffff\" destructor=\"0xabcdefa\" extrapop=\"0x300000000\" format=\"0x30101010101\" id=\"0x123456789011\" index=\"0xf0f0f0f0f0f0f0\" metatype=\"0x7fffffffffffffff\" model=\"0x8000000000000000\"/>";
const MIXED_PACKED: &[u8] = &[
    0x4b, 0xc2, 0x22, 0x83, 0xc8, 0xc6, 0x71, 0x87, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x8b,
];
const MIXED_XML: &str = "\n<addr align=\"456\" extrapop=\"unknown\"/>";
const ATTRIBUTES_PACKED: &[u8] = &[
    0x41, 0xc2, 0x11, 0xc3, 0x10, 0xd4, 0x51, 0x83, 0xd8, 0x70, 0xd9, 0x71, 0x85, 0x68, 0x65, 0x6c,
    0x6c, 0x6f, 0xc4, 0x71, 0x98, 0x3c, 0x3c, 0xe2, 0x82, 0xac, 0x3e, 0x3e, 0x26, 0x22, 0x62, 0x6c,
    0x20, 0x61, 0x20, 0x20, 0x68, 0x27, 0x5c, 0x62, 0x6c, 0x65, 0x68, 0x0a, 0x09, 0xc5, 0x72, 0x81,
    0xd6, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x72, 0x65, 0x65, 0x20, 0x66, 0x6f,
    0x75, 0x72, 0x20, 0x66, 0x69, 0x76, 0x65, 0x20, 0x73, 0x69, 0x78, 0x20, 0x73, 0x65, 0x76, 0x65,
    0x6e, 0x20, 0x65, 0x69, 0x67, 0x68, 0x74, 0x20, 0x6e, 0x69, 0x6e, 0x65, 0x20, 0x74, 0x65, 0x6e,
    0x20, 0x65, 0x6c, 0x65, 0x76, 0x65, 0x6e, 0x20, 0x74, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x20, 0x74,
    0x68, 0x69, 0x72, 0x74, 0x65, 0x65, 0x6e, 0x20, 0x66, 0x6f, 0x75, 0x72, 0x74, 0x65, 0x65, 0x6e,
    0x20, 0x66, 0x69, 0x66, 0x74, 0x65, 0x65, 0x6e, 0x20, 0x73, 0x69, 0x78, 0x74, 0x65, 0x65, 0x6e,
    0x20, 0x73, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x65, 0x65, 0x6e, 0x20, 0x65, 0x69, 0x67, 0x68, 0x74,
    0x65, 0x65, 0x6e, 0x20, 0x6e, 0x69, 0x6e, 0x65, 0x74, 0x65, 0x65, 0x6e, 0x20, 0x74, 0x77, 0x65,
    0x6e, 0x74, 0x79, 0x20, 0x74, 0x77, 0x65, 0x6e, 0x74, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x62,
    0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62,
    0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62,
    0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62,
    0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x62,
    0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x81,
];
const ATTRIBUTES_XML: &str = "\n<data align=\"true\" bigendian=\"false\" space=\"ram\" val=\"\" value=\"hello\" constructor=\"&lt;&lt;€&gt;&gt;&amp;&quot;bl a  h&apos;\\bleh\n\t\" destructor=\"one to three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty one blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah\"/>";
const HIERARCHY_PACKED: &[u8] = &[
    0x41, 0xc1, 0x11, 0x42, 0x44, 0xc9, 0x22, 0xa0, 0x80, 0x41, 0x41, 0x43, 0x83, 0x43, 0xc9, 0x71,
    0x88, 0x62, 0x6c, 0x61, 0x68, 0x62, 0x6c, 0x61, 0x68, 0x83, 0x43, 0x83, 0x81, 0x81, 0x46, 0xc9,
    0x41, 0x91, 0x47, 0x87, 0x86, 0x84, 0x82, 0x42, 0x82, 0x42, 0x82, 0x42, 0x82, 0x42, 0x82, 0x42,
    0x82, 0x42, 0x82, 0x81,
];
const HIERARCHY_XML: &str = "\n<data>true\n  <input>\n    <output id=\"4096\">\n      <data>\n        <data>\n          <off/>\n          <off id=\"blahblah\"/>\n          <off/>\n        </data>\n      </data>\n      <symbol id=\"0x11\">\n        <target/>\n      </symbol>\n    </output>\n  </input>\n  <input/>\n  <input/>\n  <input/>\n  <input/>\n  <input/>\n  <input/>\n</data>";

fn test_signed_attributes(form: Form) {
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_ADDR);
        encoder.write_signed(ATTRIB_ALIGN, 3); // 7-bits
        encoder.write_signed(ATTRIB_BIGENDIAN, -0x100); // 14-bits
        encoder.write_signed(ATTRIB_CONSTRUCTOR, 0x1f_ffff); // 21-bits
        encoder.write_signed(ATTRIB_DESTRUCTOR, -0xabc_defa); // 28-bits
        encoder.write_signed(ATTRIB_EXTRAPOP, 0x3_0000_0000); // 35-bits
        encoder.write_signed(ATTRIB_FORMAT, -0x301_0101_0101); // 42-bits
        encoder.write_signed(ATTRIB_ID, 0x1234_5678_9011); // 49-bits
        encoder.write_signed(ATTRIB_INDEX, -0xf0_f0f0_f0f0_f0f0); // 56-bits
        encoder.write_signed(ATTRIB_METATYPE, 0x7fff_ffff_ffff_ffff); // 63-bits
        encoder.close_element(ELEM_ADDR);
    });
    assert_encoding(form, &bytes, SIGNED_PACKED, SIGNED_XML);
    let flags = decode(form, &bytes, |decoder| {
        let element = decoder.open_element_expecting(ELEM_ADDR)?;
        let mut flags = 0u32;
        while let Some(attribute) = decoder.next_attribute()? {
            let expected = [
                (ATTRIB_ALIGN, 3, 1),
                (ATTRIB_BIGENDIAN, -0x100, 2),
                (ATTRIB_CONSTRUCTOR, 0x1f_ffff, 4),
                (ATTRIB_DESTRUCTOR, -0xabc_defa, 8),
                (ATTRIB_EXTRAPOP, 0x3_0000_0000, 0x10),
                (ATTRIB_FORMAT, -0x301_0101_0101, 0x20),
                (ATTRIB_ID, 0x1234_5678_9011, 0x40),
                (ATTRIB_INDEX, -0xf0_f0f0_f0f0_f0f0, 0x80),
                (ATTRIB_METATYPE, 0x7fff_ffff_ffff_ffff, 0x100),
            ];
            for (id, value, flag) in expected {
                if attribute == id {
                    assert_eq!(decoder.read_signed()?, value);
                    flags |= flag;
                }
            }
        }
        decoder.close_element(element)?;
        Ok(flags)
    })
    .unwrap();
    assert_eq!(flags, 0x1ff);
}

fn test_unsigned_attributes(form: Form) {
    let values = [
        (ATTRIB_ALIGN, 3),                        // 7-bits
        (ATTRIB_BIGENDIAN, 0x100),                // 14-bits
        (ATTRIB_CONSTRUCTOR, 0x1f_ffff),          // 21-bits
        (ATTRIB_DESTRUCTOR, 0xabc_defa),          // 28-bits
        (ATTRIB_EXTRAPOP, 0x3_0000_0000),         // 35-bits
        (ATTRIB_FORMAT, 0x301_0101_0101),         // 42-bits
        (ATTRIB_ID, 0x1234_5678_9011),            // 49-bits
        (ATTRIB_INDEX, 0xf0_f0f0_f0f0_f0f0),      // 56-bits
        (ATTRIB_METATYPE, 0x7fff_ffff_ffff_ffff), // 63-bits
        (ATTRIB_MODEL, 0x8000_0000_0000_0000),    // 64-bits
    ];
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_ADDR);
        for (id, value) in values {
            encoder.write_unsigned(id, value);
        }
        encoder.close_element(ELEM_ADDR);
    });
    assert_encoding(form, &bytes, UNSIGNED_PACKED, UNSIGNED_XML);
    decode(form, &bytes, |decoder| {
        let element = decoder.open_element_expecting(ELEM_ADDR)?;
        for (id, value) in values {
            assert_eq!(decoder.read_unsigned_attr(id)?, value);
        }
        decoder.close_element(element)
    })
    .unwrap();
}

fn test_mixed_attributes(form: Form) {
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_ADDR);
        encoder.write_signed(ATTRIB_ALIGN, 456);
        encoder.write_string(ATTRIB_EXTRAPOP, "unknown").unwrap();
        encoder.close_element(ELEM_ADDR);
    });
    assert_encoding(form, &bytes, MIXED_PACKED, MIXED_XML);
    let (align, extrapop) = decode(form, &bytes, |decoder| {
        let mut align = -1;
        let mut extrapop = -1;
        let element = decoder.open_element_expecting(ELEM_ADDR)?;
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_ALIGN {
                align = decoder.read_signed_or_string("00blah", 700)?;
            } else if attribute == ATTRIB_EXTRAPOP {
                extrapop = decoder.read_signed_or_string("unknown", 800)?;
            }
        }
        decoder.close_element(element)?;
        Ok((align, extrapop))
    })
    .unwrap();
    assert_eq!(align, 456);
    assert_eq!(extrapop, 800);
}

const TRICKY: &str = "<<\u{20ac}>>&\"bl a  h'\\bleh\n\t";
const LONG: &str = "one to three four five six seven eight nine ten eleven twelve thirteen \
                    fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty one \
                    blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah";

fn test_attributes(form: Form) {
    let ram = SpaceRef {
        name: "ram",
        packed: PackedSpace::Index(3),
    };
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_DATA);
        encoder.write_bool(ATTRIB_ALIGN, true);
        encoder.write_bool(ATTRIB_BIGENDIAN, false);
        encoder.write_space(ATTRIB_SPACE, &ram);
        encoder.write_string(ATTRIB_VAL, "").unwrap(); // Empty string
        encoder.write_string(ATTRIB_VALUE, "hello").unwrap();
        encoder.write_string(ATTRIB_CONSTRUCTOR, TRICKY).unwrap();
        encoder.write_string(ATTRIB_DESTRUCTOR, LONG).unwrap();
        encoder.close_element(ELEM_DATA);
    });
    assert_encoding(form, &bytes, ATTRIBUTES_PACKED, ATTRIBUTES_XML);
    decode(form, &bytes, |decoder| {
        let element = decoder.open_element_expecting(ELEM_DATA)?;
        assert!(decoder.read_bool_attr(ATTRIB_ALIGN)?);
        assert!(!decoder.read_bool_attr(ATTRIB_BIGENDIAN)?);
        assert_eq!(decoder.read_space_attr(ATTRIB_SPACE)?, RAM);
        assert_eq!(decoder.read_string_attr(ATTRIB_VAL)?, "");
        assert_eq!(decoder.read_string_attr(ATTRIB_VALUE)?, "hello");
        assert_eq!(decoder.read_string_attr(ATTRIB_CONSTRUCTOR)?, TRICKY);
        assert_eq!(decoder.read_string_attr(ATTRIB_DESTRUCTOR)?, LONG);
        decoder.close_element(element)
    })
    .unwrap();
}

fn test_hierarchy(form: Form) {
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_DATA); // el1
        encoder.write_bool(ATTRIB_CONTENT, true);
        encoder.open_element(ELEM_INPUT); // el2
        encoder.open_element(ELEM_OUTPUT); // el3
        encoder.write_signed(ATTRIB_ID, 0x1000);
        encoder.open_element(ELEM_DATA); // el4
        encoder.open_element(ELEM_DATA); // el5
        encoder.open_element(ELEM_OFF); // el6
        encoder.close_element(ELEM_OFF);
        encoder.open_element(ELEM_OFF); // el6
        encoder.write_string(ATTRIB_ID, "blahblah").unwrap();
        encoder.close_element(ELEM_OFF);
        encoder.open_element(ELEM_OFF); // el6
        encoder.close_element(ELEM_OFF);
        encoder.close_element(ELEM_DATA); // close el5
        encoder.close_element(ELEM_DATA); // close el4
        encoder.open_element(ELEM_SYMBOL); // skip4
        encoder.write_unsigned(ATTRIB_ID, 17);
        encoder.open_element(ELEM_TARGET); // skip5
        encoder.close_element(ELEM_TARGET); // close skip5
        encoder.close_element(ELEM_SYMBOL); // close skip4
        encoder.close_element(ELEM_OUTPUT); // close el3
        encoder.close_element(ELEM_INPUT); // close el2
        for _ in 0..6 {
            encoder.open_element(ELEM_INPUT); // el2
            encoder.close_element(ELEM_INPUT);
        }
        encoder.close_element(ELEM_DATA); // close el1
    });
    assert_encoding(form, &bytes, HIERARCHY_PACKED, HIERARCHY_XML);
    decode(form, &bytes, |decoder| {
        let el1 = decoder.open_element_expecting(ELEM_DATA)?;
        // Skip over the bool
        let el2 = decoder.open_element_expecting(ELEM_INPUT)?;
        let el3 = decoder.open_element_expecting(ELEM_OUTPUT)?;
        assert_eq!(decoder.read_signed_attr(ATTRIB_ID)?, 0x1000);
        let el4 = decoder.peek_element().unwrap();
        assert_eq!(el4, ELEM_DATA);
        decoder.open_element()?;
        let el5 = decoder.open_element()?.unwrap();
        assert_eq!(el5, ELEM_DATA);
        for _ in 0..3 {
            let el6 = decoder.open_element_expecting(ELEM_OFF)?;
            decoder.close_element(el6)?;
        }
        decoder.close_element(el5)?;
        decoder.close_element(el4)?;
        decoder.close_element_skipping(el3)?;
        decoder.close_element(el2)?;
        for _ in 0..2 {
            let el2 = decoder.open_element_expecting(ELEM_INPUT)?;
            decoder.close_element(el2)?;
        }
        decoder.close_element_skipping(el1)?;
        assert_eq!(decoder.peek_element(), None);
        Ok(())
    })
    .unwrap();
}

fn test_unexpected_eof(form: Form) {
    let bytes = encode(form, |encoder| {
        encoder.open_element(ELEM_DATA);
        encoder.open_element(ELEM_INPUT);
        encoder.write_string(ATTRIB_NAME, "hello").unwrap();
        encoder.close_element(ELEM_INPUT);
    });
    let result = decode(form, &bytes, |decoder| {
        let el1 = decoder.open_element_expecting(ELEM_DATA)?;
        let el2 = decoder.open_element_expecting(ELEM_INPUT)?;
        decoder.close_element(el2)?;
        decoder.close_element(el1)
    });
    match form {
        Form::Packed => assert_eq!(
            result,
            Err(DecodeError::UnexpectedEof {
                offset: bytes.len()
            })
        ),
        Form::Xml => assert!(matches!(result, Err(DecodeError::Xml(_))), "{result:?}"),
    }
}

fn nested_input_off(form: Form) -> Vec<u8> {
    encode(form, |encoder| {
        encoder.open_element(ELEM_INPUT);
        encoder.open_element(ELEM_OFF);
        encoder.close_element(ELEM_OFF);
        encoder.close_element(ELEM_INPUT);
    })
}

fn test_noremaining(form: Form) {
    let bytes = nested_input_off(form);
    let result = decode(form, &bytes, |decoder| {
        decoder.open_element_expecting(ELEM_INPUT)?;
        let el2 = decoder.open_element_expecting(ELEM_OFF)?;
        decoder.close_element(el2)?;
        Ok(decoder.open_element_expecting(ELEM_OFF))
    })
    .unwrap();
    assert_eq!(result, Err(DecodeError::NoElement { expected: "off" }));
}

fn test_openmismatch(form: Form) {
    let bytes = nested_input_off(form);
    let result = decode(form, &bytes, |decoder| {
        decoder.open_element_expecting(ELEM_INPUT)?;
        Ok(decoder.open_element_expecting(ELEM_OUTPUT))
    })
    .unwrap();
    let found = match form {
        Form::Packed => "id 3".to_owned(),
        Form::Xml => "<off>".to_owned(),
    };
    assert_eq!(
        result,
        Err(DecodeError::ElementMismatch {
            expected: "output",
            found
        })
    );
}

fn test_closemismatch(form: Form) {
    let bytes = nested_input_off(form);
    let result = decode(form, &bytes, |decoder| {
        let el1 = decoder.open_element_expecting(ELEM_INPUT)?;
        Ok(decoder.close_element(el1))
    })
    .unwrap();
    let element = match form {
        Form::Packed => "id 2".to_owned(),
        Form::Xml => "<input>".to_owned(),
    };
    assert_eq!(result, Err(DecodeError::UnreadChildren { element }));
}

#[test]
fn marshal_signed_packed() {
    test_signed_attributes(Form::Packed);
}

#[test]
fn marshal_signed_xml() {
    test_signed_attributes(Form::Xml);
}

#[test]
fn marshal_unsigned_packed() {
    test_unsigned_attributes(Form::Packed);
}

#[test]
fn marshal_unsigned_xml() {
    test_unsigned_attributes(Form::Xml);
}

#[test]
fn marshal_mixed_packed() {
    test_mixed_attributes(Form::Packed);
}

#[test]
fn marshal_mixed_xml() {
    test_mixed_attributes(Form::Xml);
}

#[test]
fn marshal_attribs_packed() {
    test_attributes(Form::Packed);
}

#[test]
fn marshal_attribs_xml() {
    test_attributes(Form::Xml);
}

#[test]
fn marshal_hierarchy_packed() {
    test_hierarchy(Form::Packed);
}

#[test]
fn marshal_hierarchy_xml() {
    test_hierarchy(Form::Xml);
}

#[test]
fn marshal_unexpected_packed() {
    test_unexpected_eof(Form::Packed);
}

#[test]
fn marshal_unexpected_xml() {
    test_unexpected_eof(Form::Xml);
}

#[test]
fn marshal_noremaining_packed() {
    test_noremaining(Form::Packed);
}

#[test]
fn marshal_noremaining_xml() {
    test_noremaining(Form::Xml);
}

#[test]
fn marshal_openmismatch_packed() {
    test_openmismatch(Form::Packed);
}

#[test]
fn marshal_openmismatch_xml() {
    test_openmismatch(Form::Xml);
}

#[test]
fn marshal_closemismatch_packed() {
    test_closemismatch(Form::Packed);
}

/// Ghidra has no XML variant of this test, because its XML decoder checks for
/// unread children only in debug builds. basilisk's always checks.
#[test]
fn marshal_closemismatch_xml() {
    test_closemismatch(Form::Xml);
}

/// Ghidra's test fills exactly one 1,024-byte ingest buffer to exercise the
/// padding byte its decoder appends. basilisk decodes a contiguous slice (see
/// "Differences from Ghidra" in `docs/features/core-marshal.md`); what the
/// test checks still holds: all 511 attributes decode, no child is seen at the
/// end of the data, and the element closes.
#[test]
fn marshal_bufferpad() {
    let mut encoder = PackedEncoder::new();
    encoder.open_element(ELEM_INPUT); // 1-byte
    for i in 0..511 {
        encoder.write_bool(ATTRIB_CONTENT, i & 1 == 0); // 1022-bytes
    }
    encoder.close_element(ELEM_INPUT);
    let bytes = encoder.into_bytes();
    assert_eq!(bytes.len(), 1024); // Encoding should exactly fill one buffer
    let mut decoder = PackedDecoder::new(&bytes, &TestSpaces);
    let element = decoder.open_element_expecting(ELEM_INPUT).unwrap();
    for i in 0..511 {
        let attribute = decoder.next_attribute().unwrap().unwrap();
        assert_eq!(attribute, ATTRIB_CONTENT);
        assert_eq!(decoder.read_bool().unwrap(), i & 1 == 0);
    }
    assert_eq!(decoder.peek_element(), None);
    decoder.close_element(element).unwrap();
    assert_eq!(decoder.position(), 1024);
}

/// What the Java `LinkedByteBufferTest.testString` and `testIngestStream`
/// check about data crossing a 1,024-byte buffer boundary, against the
/// contiguous decoder: values on either side of and across the boundary read
/// back, and reading past the end is an error rather than garbage.
#[test]
fn values_across_the_ingest_buffer_boundary() {
    for lead in 1000..1030 {
        let filler = "f".repeat(lead);
        let mut encoder = PackedEncoder::new();
        encoder.open_element(ELEM_DATA);
        encoder.write_string(ATTRIB_NAME, &filler).unwrap();
        encoder.write_string(ATTRIB_VALUE, "crossing").unwrap();
        encoder.write_unsigned(ATTRIB_ID, 0x8000_0000_0000_0001);
        encoder.write_string(ATTRIB_VAL, "cat").unwrap();
        encoder.close_element(ELEM_DATA);
        let bytes = encoder.into_bytes();
        let mut decoder = PackedDecoder::new(&bytes, &TestSpaces);
        let element = decoder.open_element_expecting(ELEM_DATA).unwrap();
        assert_eq!(decoder.read_string_attr(ATTRIB_VALUE).unwrap(), "crossing");
        assert_eq!(
            decoder.read_unsigned_attr(ATTRIB_ID).unwrap(),
            0x8000_0000_0000_0001
        );
        assert_eq!(decoder.read_string_attr(ATTRIB_VAL).unwrap(), "cat");
        assert_eq!(decoder.read_string_attr(ATTRIB_NAME).unwrap(), filler);
        decoder.close_element(element).unwrap();
        assert_eq!(
            decoder.close_element(element),
            Err(DecodeError::UnexpectedEof {
                offset: bytes.len()
            })
        );
        // Cut anywhere inside, the document fails to open or to close.
        for cut in [lead, 1023, 1024, bytes.len() - 1] {
            let mut decoder = PackedDecoder::new(&bytes[..cut], &TestSpaces);
            let outcome = decoder
                .open_element_expecting(ELEM_DATA)
                .and_then(|element| decoder.close_element(element));
            assert!(
                matches!(outcome, Err(DecodeError::UnexpectedEof { .. })),
                "{outcome:?}"
            );
        }
    }
}
