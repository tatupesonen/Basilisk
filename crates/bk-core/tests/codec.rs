//! Marshalling of the address model: the `<spaces>` element in both forms,
//! exact XML and packed output, and decoding errors.

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

use bk_core::ids::{
    ATTRIB_BASE, ATTRIB_CONTAIN, ATTRIB_DEADCODEDELAY, ATTRIB_DEFAULTSPACE, ATTRIB_DELAY,
    ATTRIB_PHYSICAL, ATTRIB_UNIQBASE, ELEM_SLEIGH, ELEM_SPACE, ELEM_SPACE_BASE, ELEM_SPACE_OTHER,
    ELEM_SPACE_OVERLAY, ELEM_SPACE_UNIQUE, ELEM_SPACES, ELEM_TRUNCATE_SPACE, id_table,
};
use bk_core::{
    Address, Range, RangeList, RangeProperties, SeqNum, Space, SpaceError, SpaceFlags, SpaceId,
    SpaceKind, SpaceManager, TruncationTag, VarnodeData,
};
use bk_marshal::ids::{
    ATTRIB_BIGENDIAN, ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_WORDSIZE,
};
use bk_marshal::{
    DecodeError, Decoder, Document, Encoder, PackedDecoder, PackedEncoder, PackedSpace, SpaceRef,
    XmlDecoder, XmlEncoder,
};
use common::{JOIN, RAM, REGISTER, manager, vn};

/// Writes a `<sleigh>` element as Ghidra's Java side does
/// (`SleighLanguage.encodeTranslator`), plus a register-relative space, an
/// overlay and a word-addressed space, a truncation, and an address in the
/// overlay to read back through the directory.
fn encode_translator(enc: &mut dyn Encoder) {
    let space = |enc: &mut dyn Encoder, element, name: &str, index: i64, size: i64, delay: i64| {
        enc.open_element(element);
        enc.write_string(ATTRIB_NAME, name).unwrap();
        enc.write_signed(ATTRIB_INDEX, index);
        enc.write_signed(ATTRIB_SIZE, size);
        enc.write_bool(ATTRIB_BIGENDIAN, false);
        enc.write_signed(ATTRIB_DELAY, delay);
        enc.write_bool(ATTRIB_PHYSICAL, true);
    };
    enc.open_element(ELEM_SLEIGH);
    enc.write_bool(ATTRIB_BIGENDIAN, false);
    enc.write_unsigned(ATTRIB_UNIQBASE, 0x1000_0000);
    enc.open_element(ELEM_SPACES);
    enc.write_string(ATTRIB_DEFAULTSPACE, "ram").unwrap();
    space(enc, ELEM_SPACE_OTHER, "OTHER", 1, 8, 0);
    enc.close_element(ELEM_SPACE_OTHER);
    space(enc, ELEM_SPACE, "ram", 2, 4, 1);
    enc.close_element(ELEM_SPACE);
    space(enc, ELEM_SPACE, "register", 3, 4, 0);
    enc.close_element(ELEM_SPACE);
    space(enc, ELEM_SPACE_UNIQUE, "unique", 4, 4, 0);
    enc.close_element(ELEM_SPACE_UNIQUE);
    enc.open_element(ELEM_SPACE_BASE);
    enc.write_string(ATTRIB_NAME, "stack").unwrap();
    enc.write_signed(ATTRIB_INDEX, 5);
    enc.write_signed(ATTRIB_SIZE, 4);
    enc.write_signed(ATTRIB_DELAY, 1);
    enc.write_space(
        ATTRIB_CONTAIN,
        &SpaceRef {
            name: "ram",
            packed: PackedSpace::Index(2),
        },
    );
    enc.close_element(ELEM_SPACE_BASE);
    enc.open_element(ELEM_SPACE_OVERLAY);
    enc.write_string(ATTRIB_NAME, "ov").unwrap();
    enc.write_signed(ATTRIB_INDEX, 6);
    enc.write_space(
        ATTRIB_BASE,
        &SpaceRef {
            name: "ram",
            packed: PackedSpace::Index(2),
        },
    );
    enc.close_element(ELEM_SPACE_OVERLAY);
    space(enc, ELEM_SPACE, "code", 7, 2, 1);
    enc.write_unsigned(ATTRIB_WORDSIZE, 2);
    enc.write_signed(ATTRIB_DEADCODEDELAY, 3);
    enc.close_element(ELEM_SPACE);
    enc.close_element(ELEM_SPACES);
    enc.open_element(ELEM_TRUNCATE_SPACE);
    enc.write_string(ATTRIB_SPACE, "ram").unwrap();
    enc.write_unsigned(ATTRIB_SIZE, 2);
    enc.close_element(ELEM_TRUNCATE_SPACE);
    Address::new(SpaceId::new(6), 0x10)
        .encode(enc, &overlay_layout())
        .unwrap();
    enc.close_element(ELEM_SLEIGH);
}

/// A manager with just enough spaces to encode the trailing address.
fn overlay_layout() -> SpaceManager {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    let ram = Space::processor("ram", false, 4, 1, 2, true, 1, 1).unwrap();
    m.insert_space(ram.clone()).unwrap();
    m.insert_space(Space::overlay("ov", 6, &ram).unwrap())
        .unwrap();
    m
}

/// Decodes the translator document: `<spaces>` through the manager's
/// directory, the truncation, and the trailing address with the same decoder.
fn decode_translator(dec: &mut dyn Decoder<'_>, m: &mut SpaceManager) -> Address {
    let sleigh = dec.open_element_expecting(ELEM_SLEIGH).unwrap();
    m.decode_spaces(dec).unwrap();
    let tag = TruncationTag::decode(dec).unwrap();
    m.truncate_space(&tag).unwrap();
    let address = Address::decode(dec, m).unwrap();
    dec.close_element(sleigh).unwrap();
    address
}

fn check_translator(m: &SpaceManager, address: Address) {
    assert_eq!(address, Address::new(SpaceId::new(6), 0x10));
    let names: Vec<&str> = m.spaces().map(Space::name).collect();
    assert_eq!(
        names,
        [
            "const", "OTHER", "ram", "register", "unique", "stack", "ov", "code"
        ]
    );
    assert_eq!(m.default_code_space().unwrap().name(), "ram");
    let ram = m.space(RAM).unwrap();
    assert!(ram.is_truncated() && ram.is_overlay_base());
    assert_eq!(
        (ram.addr_size(), ram.delay(), ram.deadcode_delay()),
        (2, 1, 1)
    );
    // Decoded spaces get neither addressable flag.
    assert!(
        !ram.flags()
            .intersects(SpaceFlags::ADDRESSABLE_ALL | SpaceFlags::ADDRESSABLE_NONE)
    );
    let other = m.space_at(1).unwrap();
    assert!(other.is_other_space() && !other.is_heritaged() && other.has_physical());
    let unique = m.unique_space().unwrap();
    assert!(unique.has_physical() && unique.is_heritaged());
    let stack = m.stack_space().unwrap();
    assert!(matches!(stack.kind(), SpaceKind::Spacebase { contain, .. } if *contain == RAM));
    assert!(
        stack
            .flags()
            .contains(SpaceFlags::PROGRAM_SPECIFIC | SpaceFlags::ALLOWS_WRAPPED_RANGE)
    );
    // Ghidra's decoded spacebase is not marked as the formal stack.
    assert!(!stack.is_formal_stack_space());
    let ov = m.space_by_name("ov").unwrap();
    assert!(ov.is_overlay() && ov.has_physical());
    // Overlays copy the base's size as it was when they were decoded.
    assert_eq!(ov.addr_size(), 4);
    let code = m.space_by_name("code").unwrap();
    assert_eq!((code.word_size(), code.deadcode_delay()), (2, 3));
    assert_eq!(code.highest(), 0x1_ffff);
    let shortcuts: String = m.spaces().filter_map(Space::shortcut).collect();
    assert_eq!(shortcuts, "#or%uspc");
}

#[test]
fn spaces_decode_from_xml_and_packed_alike() {
    let ids = id_table();
    let mut xml = XmlEncoder::new(true);
    encode_translator(&mut xml);
    let text = xml.into_string();
    let doc = Document::parse(&text).unwrap();
    let mut from_xml = SpaceManager::new();
    let dir = from_xml.directory();
    let mut dec = XmlDecoder::new(&doc, &ids, &*dir);
    let address = decode_translator(&mut dec, &mut from_xml);
    check_translator(&from_xml, address);

    let mut packed = PackedEncoder::new();
    encode_translator(&mut packed);
    let bytes = packed.into_bytes();
    let mut from_packed = SpaceManager::new();
    let dir = from_packed.directory();
    let mut dec = PackedDecoder::new(&bytes, &*dir);
    let address = decode_translator(&mut dec, &mut from_packed);
    check_translator(&from_packed, address);

    let xml_spaces: Vec<&Space> = from_xml.spaces().collect();
    let packed_spaces: Vec<&Space> = from_packed.spaces().collect();
    assert_eq!(xml_spaces, packed_spaces);
}

fn decode_spaces_xml(text: &str) -> Result<SpaceManager, SpaceError> {
    let ids = id_table();
    let doc = Document::parse(text).unwrap();
    let mut m = SpaceManager::new();
    let dir = m.directory();
    let mut dec = XmlDecoder::new(&doc, &ids, &*dir);
    m.decode_spaces(&mut dec)?;
    Ok(m)
}

#[test]
fn spaces_decode_errors() {
    let ok = r#"<spaces defaultspace="ram"><space name="ram" index="2" size="4"/></spaces>"#;
    let m = decode_spaces_xml(ok).unwrap();
    // A missing delay reads as 0.
    assert_eq!(m.space(RAM).unwrap().delay(), 0);
    let cases: &[(&str, SpaceError)] = &[
        (
            r#"<spaces defaultspace="rom"><space name="ram" index="2" size="4"/></spaces>"#,
            SpaceError::BadDefaultSpaceName("rom".into()),
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" size="4"/></spaces>"#,
            SpaceError::MissingSpaceAttribute { attribute: "index" },
        ),
        (
            r#"<spaces defaultspace="ram"><space index="2" size="4"/></spaces>"#,
            SpaceError::MissingSpaceAttribute { attribute: "name" },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="2"/></spaces>"#,
            SpaceError::MissingSpaceAttribute { attribute: "size" },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="2" size="4" wordsize="0"/></spaces>"#,
            SpaceError::ZeroWordSize { name: "ram".into() },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="70000" size="4"/></spaces>"#,
            SpaceError::IndexTooLarge {
                name: "ram".into(),
                index: 70000,
                limit: 0xffff,
            },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="-1" size="4"/></spaces>"#,
            SpaceError::IndexTooLarge {
                name: "ram".into(),
                index: -1,
                limit: 0xffff,
            },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="0" size="4"/></spaces>"#,
            SpaceError::ReservedIndexZero { name: "ram".into() },
        ),
        (
            r#"<spaces defaultspace="ram"><space name="ram" index="2" size="4"/><space name="rom" index="2" size="4"/></spaces>"#,
            SpaceError::DuplicateIndex {
                name: "rom".into(),
                existing: "ram".into(),
            },
        ),
        (
            r#"<spaces defaultspace="ram"><space_unique name="tmp" index="2" size="4"/></spaces>"#,
            SpaceError::WrongSpaceType { name: "tmp".into() },
        ),
        (
            r#"<spaces defaultspace="ram"><space_other name="OTHER" index="3" size="8"/></spaces>"#,
            SpaceError::OtherSpaceIndex,
        ),
        (
            r#"<spaces defaultspace="ram"><addr/></spaces>"#,
            SpaceError::InvalidSpaceElement,
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            decode_spaces_xml(text).err().as_ref(),
            Some(expected),
            "{text}"
        );
    }
    // An overlay naming a space that does not exist yet.
    let err = decode_spaces_xml(
        r#"<spaces defaultspace="ram"><space_overlay name="ov" index="3" base="ram"/><space name="ram" index="2" size="4"/></spaces>"#,
    )
    .unwrap_err();
    assert!(matches!(err, SpaceError::Decode(_)), "{err:?}");
}

fn xml_of(f: impl Fn(&mut dyn Encoder)) -> String {
    let mut enc = XmlEncoder::new(false);
    f(&mut enc);
    enc.into_string()
}

fn packed_of(f: impl Fn(&mut dyn Encoder)) -> Vec<u8> {
    let mut enc = PackedEncoder::new();
    f(&mut enc);
    enc.into_bytes()
}

/// Encodes with `encode` in both forms, decodes each with `decode`, and
/// returns the XML text and the two decoded values.
fn round_trip<T>(
    m: &SpaceManager,
    encode: impl Fn(&mut dyn Encoder),
    decode: impl for<'a> Fn(&mut dyn Decoder<'a>) -> T,
) -> (String, T, T) {
    let ids = id_table();
    let text = xml_of(&encode);
    let doc = Document::parse(&text).unwrap();
    let from_xml = decode(&mut XmlDecoder::new(&doc, &ids, m));
    let bytes = packed_of(&encode);
    let from_packed = decode(&mut PackedDecoder::new(&bytes, m));
    (text, from_xml, from_packed)
}

#[test]
fn address_and_varnode_forms() {
    let m = manager(false);
    let addr = Address::new(RAM, 0x1000);
    let (text, xml, packed) = round_trip(
        &m,
        |e| addr.encode(e, &m).unwrap(),
        |d| Address::decode(d, &m).unwrap(),
    );
    assert_eq!(text, r#"<addr space="ram" offset="0x1000"/>"#);
    assert_eq!((xml, packed), (addr, addr));
    // Hand-computed packed bytes: element 11, space attribute 20 holding
    // space index 2, offset attribute 16 holding 0x1000, end.
    assert_eq!(
        packed_of(|e| addr.encode(e, &m).unwrap()),
        [0x4b, 0xd4, 0x51, 0x82, 0xd0, 0x42, 0xa0, 0x80, 0x8b]
    );

    let (text, xml, packed) = round_trip(
        &m,
        |e| addr.encode_sized(e, &m, 4).unwrap(),
        |d| Address::decode_sized(d, &m).unwrap(),
    );
    assert_eq!(text, r#"<addr space="ram" offset="0x1000" size="4"/>"#);
    assert_eq!((xml, packed), ((addr, 4), (addr, 4)));

    let (text, xml, packed) = round_trip(
        &m,
        |e| Address::INVALID.encode(e, &m).unwrap(),
        |d| VarnodeData::decode(d, &m).unwrap(),
    );
    assert_eq!(text, "<addr/>");
    assert_eq!((xml, packed), (VarnodeData::NONE, VarnodeData::NONE));

    let varnode = vn(REGISTER, 8, 4);
    let (text, xml, packed) = round_trip(
        &m,
        |e| varnode.encode(e, &m).unwrap(),
        |d| VarnodeData::decode(d, &m).unwrap(),
    );
    assert_eq!(text, r#"<addr space="register" offset="0x8" size="4"/>"#);
    assert_eq!((xml, packed), (varnode, varnode));

    // The stack is written as a special space in the packed form.
    let stack = Address::new(common::STACK, 0xffff_fff0);
    let (_, xml, packed) = round_trip(
        &m,
        |e| stack.encode(e, &m).unwrap(),
        |d| Address::decode(d, &m).unwrap(),
    );
    assert_eq!((xml, packed), (stack, stack));
}

#[test]
fn join_forms() {
    let m = manager(false);
    let join = m
        .construct_join_address(vn(REGISTER, 8, 4).addr(), 4, vn(REGISTER, 0, 4).addr(), 4)
        .unwrap();
    let (text, xml, packed) = round_trip(
        &m,
        |e| join.encode_sized(e, &m, 8).unwrap(),
        |d| VarnodeData::decode(d, &m).unwrap(),
    );
    assert_eq!(
        text,
        r#"<addr space="join" piece1="register:0x8:4" piece2="register:0x0:4"/>"#
    );
    assert_eq!(
        (xml, packed),
        (vn(JOIN, join.offset(), 8), vn(JOIN, join.offset(), 8))
    );

    let ext = m
        .construct_float_extension_address(vn(REGISTER, 0, 4).addr(), 4, 10)
        .unwrap();
    let (text, xml, _) = round_trip(
        &m,
        |e| ext.encode(e, &m).unwrap(),
        |d| VarnodeData::decode(d, &m).unwrap(),
    );
    assert_eq!(
        text,
        r#"<addr space="join" piece1="register:0x0:4" logicalsize="0xa"/>"#
    );
    assert_eq!(xml, vn(JOIN, ext.offset(), 10));

    // Decoding creates the record when it does not exist yet.
    let fresh = manager(false);
    let ids = id_table();
    let doc =
        Document::parse(r#"<addr space="join" piece1="register:0x10:4" piece2="eax"/>"#).unwrap();
    let got = VarnodeData::decode(&mut XmlDecoder::new(&doc, &ids, &fresh), &fresh).unwrap();
    assert_eq!(
        fresh.find_join(got.offset).unwrap().pieces(),
        [vn(REGISTER, 16, 4), vn(REGISTER, 0, 4)]
    );
    // An unlinked join offset cannot be encoded.
    assert_eq!(
        Address::new(JOIN, 0x500)
            .encode(&mut XmlEncoder::new(false), &fresh)
            .unwrap_err(),
        SpaceError::UnlinkedJoin
    );
    // More than 64 pieces cannot be encoded.
    let pieces: Vec<VarnodeData> = (0..65).map(|i| vn(RAM, i * 8, 4)).collect();
    let big = fresh.find_add_join(pieces, 0).unwrap();
    assert_eq!(
        big.unified()
            .addr()
            .encode(&mut PackedEncoder::new(), &fresh)
            .unwrap_err(),
        SpaceError::TooManyJoinPieces
    );
}

fn decode_xml<T>(m: &SpaceManager, text: &str, f: impl for<'a> Fn(&mut dyn Decoder<'a>) -> T) -> T {
    let ids = id_table();
    let doc = Document::parse(text).unwrap();
    f(&mut XmlDecoder::new(&doc, &ids, m))
}

#[test]
fn varnode_decode_forms_and_errors() {
    let m = manager(false);
    let vd = |text: &str| decode_xml(&m, text, |d| VarnodeData::decode(d, &m));
    assert_eq!(vd(r#"<register name="eax"/>"#).unwrap(), vn(REGISTER, 0, 4));
    assert_eq!(
        vd(r#"<varnode space="register" offset="0x4" size="4"/>"#).unwrap(),
        vn(REGISTER, 4, 4)
    );
    // Without a size the size is 0.
    assert_eq!(
        vd(r#"<addr space="ram" offset="16"/>"#).unwrap(),
        vn(RAM, 16, 0)
    );
    assert_eq!(
        vd(r#"<addr space="ram"/>"#).unwrap_err(),
        SpaceError::MissingOffset
    );
    assert_eq!(
        vd(r#"<register name="zz"/>"#).unwrap_err(),
        SpaceError::UnknownRegister("zz".into())
    );
    assert!(matches!(
        vd(r#"<addr space="rom" offset="1"/>"#).unwrap_err(),
        SpaceError::Decode(_)
    ));
    let join_cases: &[(&str, SpaceError)] = &[
        (
            r#"<addr space="join" piece1="register:0x8:4" piece3="eax"/>"#,
            SpaceError::MalformedJoinPiece,
        ),
        (
            r#"<addr space="join" piece1="register:0x8"/>"#,
            SpaceError::MalformedJoinPiece,
        ),
        (
            r#"<addr space="join" piece1="rom:0x8:4" piece2="eax"/>"#,
            SpaceError::UnknownSpaceName("rom".into()),
        ),
        (
            r#"<addr space="join" piece1="nosuch"/>"#,
            SpaceError::UnknownRegister("nosuch".into()),
        ),
        (r#"<addr space="join"/>"#, SpaceError::JoinWithoutPieces),
        (
            r#"<addr space="join" piece1="eax"/>"#,
            SpaceError::JoinWithoutLogicalSize,
        ),
    ];
    for (text, expected) in join_cases {
        assert_eq!(vd(text).as_ref().err(), Some(expected), "{text}");
    }
    assert!(matches!(
        vd(r#"<addr space="join" piece0="eax"/>"#).unwrap_err(),
        SpaceError::Decode(DecodeError::BadIndexedAttribute { .. })
    ));
}

#[test]
fn seqnum_forms() {
    let m = manager(false);
    let s = SeqNum::new(Address::new(RAM, 0x100), 5);
    let (text, xml, packed) = round_trip(
        &m,
        |e| s.encode(e, &m).unwrap(),
        |d| SeqNum::decode(d, &m).unwrap(),
    );
    assert_eq!(text, r#"<seqnum space="ram" offset="0x100" uniq="0x5"/>"#);
    assert_eq!((xml, packed), (s, s));
    let missing = decode_xml(&m, r#"<seqnum space="ram" offset="0x100"/>"#, |d| {
        SeqNum::decode(d, &m).unwrap()
    });
    assert_eq!(missing.time(), u32::MAX);
    assert_eq!(
        SeqNum::new(Address::INVALID, 1)
            .encode(&mut XmlEncoder::new(false), &m)
            .unwrap_err(),
        SpaceError::InvalidAddress
    );
    assert_eq!(s.raw(&m).to_string(), "0x00000100:5");
}

#[test]
fn range_forms() {
    let m = manager(false);
    let r = Range::new(RAM, 0x10, 0x20);
    let (text, xml, packed) = round_trip(
        &m,
        |e| r.encode(e, &m).unwrap(),
        |d| Range::decode(d, &m).unwrap(),
    );
    assert_eq!(text, r#"<range space="ram" first="0x10" last="0x20"/>"#);
    assert_eq!((xml, packed), (r, r));
    let range = |text: &str| decode_xml(&m, text, |d| Range::decode(d, &m));
    assert_eq!(
        range(r#"<range space="ram" first="0x10"/>"#).unwrap(),
        Range::new(RAM, 0x10, 0xffff_ffff)
    );
    assert_eq!(
        range(r#"<register name="eax"/>"#).unwrap(),
        Range::new(REGISTER, 0, 3)
    );
    assert_eq!(
        range(r#"<range first="1"/>"#).unwrap_err(),
        SpaceError::RangeWithoutSpace
    );
    for bad in [
        r#"<range space="ram" first="5" last="4"/>"#,
        r#"<range space="ram" first="0x100000000"/>"#,
        r#"<range space="ram" last="0x100000000"/>"#,
    ] {
        assert_eq!(range(bad).unwrap_err(), SpaceError::IllegalRange, "{bad}");
    }
    assert!(matches!(
        range(r#"<addr space="ram"/>"#).unwrap_err(),
        SpaceError::Decode(_)
    ));

    // Properties are read without a manager and resolved later.
    let props = decode_xml(&m, r#"<range space="ram" first="0x10"/>"#, |d| {
        RangeProperties::decode(d).unwrap()
    });
    assert_eq!(props.space_name(), "ram");
    assert_eq!(
        Range::from_properties(&props, &m).unwrap(),
        Range::new(RAM, 0x10, 0xffff_ffff)
    );
    let props = decode_xml(&m, r#"<register name="ecx"/>"#, |d| {
        RangeProperties::decode(d).unwrap()
    });
    assert!(props.is_register());
    assert_eq!(
        Range::from_properties(&props, &m).unwrap(),
        Range::new(REGISTER, 4, 7)
    );
    let props = decode_xml(&m, r#"<range space="rom"/>"#, |d| {
        RangeProperties::decode(d).unwrap()
    });
    assert_eq!(
        Range::from_properties(&props, &m).unwrap_err(),
        SpaceError::UnknownSpaceName("rom".into())
    );
}

#[test]
fn range_list_forms() {
    let m = manager(false);
    let mut list = RangeList::new();
    list.insert_range(RAM, 0x10, 0x1f);
    list.insert_range(REGISTER, 0, 7);
    let (text, xml, packed) = round_trip(
        &m,
        |e| list.encode(e, &m).unwrap(),
        |d| {
            let mut decoded = RangeList::new();
            decoded.decode(d, &m).unwrap();
            decoded
        },
    );
    assert_eq!(
        text,
        r#"<rangelist><range space="ram" first="0x10" last="0x1f"/><range space="register" first="0x0" last="0x7"/></rangelist>"#
    );
    assert_eq!((&xml, &packed), (&list, &list));
    // Decoding neither merges overlaps nor keeps a second range with the same
    // start.
    let decoded = decode_xml(
        &m,
        r#"<rangelist><range space="ram" first="0" last="0x10"/><range space="ram" first="8" last="0x20"/><range space="ram" first="0" last="0x30"/></rangelist>"#,
        |d| {
            let mut decoded = RangeList::new();
            decoded.decode(d, &m).unwrap();
            decoded
        },
    );
    let ranges: Vec<Range> = decoded.iter().collect();
    assert_eq!(ranges, [Range::new(RAM, 0, 0x10), Range::new(RAM, 8, 0x20)]);
    assert_eq!(decoded.bounds(&m).to_string(), "ram: 0-10\nram: 8-20\n");
    assert_eq!(RangeList::new().bounds(&m).to_string(), "all\n");
    let last_open = Range::new(RAM, 0, 0xffff_ffff).last_addr_open(&m);
    assert_eq!(last_open, Address::new(REGISTER, 0));
    assert_eq!(
        Range::new(RAM, 0, 0x10).last_addr_open(&m),
        Address::new(RAM, 0x11)
    );
}
