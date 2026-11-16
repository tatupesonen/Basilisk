//! The side tables and their codecs (spec 6.1, 4.12–4.15, 4.17): comments
//! (comment.cc), strings (stringmanage.cc), the constant pool (cpool.cc),
//! overrides (override.cc) and the XML load image (`loadimage_xml.cc`). The
//! `<context_points>` codec is the context table's (6.2): every `encode`
//! and `redecode` row of 85,713 replays equal.
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

use std::sync::Arc;

use bk_core::{Address, SpaceManager};
use bk_cspec::FuncProto;
use bk_decomp_symbols::comment::{CommentDb, kind};
use bk_decomp_symbols::cpool::{CPoolRecord, CPoolTag, ConstantPool};
use bk_decomp_symbols::image::{LoadImage, RawImage, XmlImage};
use bk_decomp_symbols::overrides::{OverrideRecord, Overrides, ProtoCodec};
use bk_decomp_symbols::strings::{
    CharType, StringCache, StringData, codepoint, internal_hash, write_utf8,
};
use bk_decomp_symbols::{SymbolError, ids};
use bk_decomp_types::Metatype;
use bk_marshal::{Decoder, Document, Encoder, XmlDecoder, XmlEncoder};
use common::small::{self, RAM, STACK};

fn spaces() -> Arc<SpaceManager> {
    Arc::new(small::spaces(false))
}

/// Encodes with `f` and gives the text.
fn encoded(f: impl FnOnce(&mut XmlEncoder)) -> String {
    let mut enc = XmlEncoder::new(true);
    f(&mut enc);
    enc.into_string()
}

/// Decodes `text` with `f`.
fn decoded<T>(text: &str, spaces: &SpaceManager, f: impl FnOnce(&mut dyn Decoder<'_>) -> T) -> T {
    let doc = Document::parse(text).unwrap();
    let table = ids::id_table();
    let mut dec = XmlDecoder::new(&doc, &table, spaces);
    f(&mut dec)
}

// ----- comments ------------------------------------------------------------

#[test]
fn comment_uniq_numbering_and_no_duplicates() {
    let sp = spaces();
    let f = Address::new(RAM, 0x1000);
    let a = Address::new(RAM, 0x1004);
    let b = Address::new(RAM, 0x1008);
    let mut db = CommentDb::new();
    db.add_comment(kind::USER1, f, a, "one").unwrap();
    db.add_comment(kind::USER2, f, a, "two").unwrap();
    db.add_comment(kind::WARNING, f, b, "w").unwrap();
    // Another function at the same address starts again at 0.
    db.add_comment(kind::USER1, a, a, "other").unwrap();
    let uniqs: Vec<(u64, u64, u32)> = db
        .iter()
        .map(|c| (c.func_addr.offset(), c.addr.offset(), c.uniq))
        .collect();
    assert_eq!(
        uniqs,
        [
            (0x1000, 0x1004, 0),
            (0x1000, 0x1004, 1),
            (0x1000, 0x1008, 0),
            (0x1004, 0x1004, 0)
        ]
    );
    // Same text at the same place: refused; elsewhere: stored after the last.
    assert!(
        !db.add_comment_no_duplicate(kind::USER3, f, a, "one")
            .unwrap()
    );
    assert!(
        db.add_comment_no_duplicate(kind::USER3, f, a, "three")
            .unwrap()
    );
    assert_eq!(
        db.function_range(f)
            .filter(|c| c.addr == a)
            .last()
            .unwrap()
            .uniq,
        2
    );
    // clearType removes by type bit within the function only.
    db.clear_type(f, kind::USER1 | kind::WARNING);
    let left: Vec<&str> = db.iter().map(|c| c.text.as_str()).collect();
    assert_eq!(left, ["two", "three", "other"]);
    // Round trip: decoding renumbers from 0 in order.
    let text = encoded(|e| db.encode(e, &sp).unwrap());
    let mut back = CommentDb::new();
    decoded(&text, &sp, |d| back.decode(d, &sp)).unwrap();
    let got: Vec<_> = back
        .iter()
        .map(|c| (c.kind, c.addr, c.uniq, c.text.clone()))
        .collect();
    assert_eq!(
        got,
        [
            (kind::USER2, a, 0, "two".to_owned()),
            (kind::USER3, a, 1, "three".to_owned()),
            (kind::USER1, a, 0, "other".to_owned()),
        ]
    );
}

#[test]
fn comment_types_by_name_and_errors() {
    let sp = spaces();
    let bad = r#"<commentdb><comment type="user4"><addr space="ram" offset="0x0"/><addr space="ram" offset="0x0"/></comment></commentdb>"#;
    let mut db = CommentDb::new();
    let got = decoded(bad, &sp, |d| db.decode(d, &sp));
    assert!(
        matches!(got, Err(SymbolError::UnknownCommentType { ref name }) if name == "user4"),
        "{got:?}"
    );
    // A comment without its <text> child decodes with empty text.
    let no_text = r#"<commentdb><comment type="header"><addr space="ram" offset="0x10"/><addr space="ram" offset="0x14"/></comment></commentdb>"#;
    let mut db = CommentDb::new();
    decoded(no_text, &sp, |d| db.decode(d, &sp)).unwrap();
    let c = db.iter().next().unwrap();
    assert_eq!((c.kind, c.text.as_str()), (kind::HEADER, ""));
}

#[test]
fn the_comment_after_the_last_uniq_at_one_address_is_refused() {
    let f = Address::new(RAM, 0x1000);
    let mut db = CommentDb::new();
    // uniq 0 ..= 65535: 65,536 comments fit.
    for _ in 0..65_536 {
        db.add_comment(kind::USER1, f, f, "x").unwrap();
    }
    assert_eq!(db.iter().last().unwrap().uniq, 65_535);
    // The next one computes uniq 65535 again (the look-up bound): Ghidra's
    // set refuses it and leaks it (spec 4.21 #17); Basilisk errors.
    assert!(matches!(
        db.add_comment(kind::USER1, f, f, "y"),
        Err(SymbolError::CommentKey)
    ));
    assert_eq!(db.len(), 65_536);
}

// ----- strings ------------------------------------------------------------

#[test]
fn codepoints_from_every_branch() {
    // (bytes, charsize, big endian, codepoint and bytes taken)
    type Case<'a> = (&'a [u8], usize, bool, Option<(u32, usize)>);
    let cases: &[Case<'_>] = &[
        // UTF-8
        (b"A", 1, false, Some((0x41, 1))),
        (&[0xc3, 0xa9], 1, false, Some((0xe9, 2))),
        (&[0xc0, 0x80], 1, false, Some((0, 2))), // overlong forms are accepted
        (&[0xc3], 1, false, None),               // too short
        (&[0xc3, 0x41], 1, false, None),         // not a continuation byte
        (&[0xe2, 0x82, 0xac], 1, false, Some((0x20ac, 3))),
        (&[0xe2, 0x82], 1, false, None),
        (&[0xed, 0xa0, 0x80], 1, false, None), // a surrogate
        (&[0xf0, 0x9f, 0x98, 0x80], 1, false, Some((0x1f600, 4))),
        (&[0xf4, 0x90, 0x80, 0x80], 1, false, None), // past 0x10ffff
        (&[0xf0, 0x9f, 0x98], 1, false, None),
        (&[0x80], 1, false, None), // a lone continuation byte
        (&[0xf8, 0x80, 0x80, 0x80], 1, false, None),
        // UTF-16
        (&[0x41, 0x00], 2, false, Some((0x41, 2))),
        (&[0x00, 0x41], 2, true, Some((0x41, 2))),
        (&[0x3d, 0xd8, 0x00, 0xde], 2, false, Some((0x1f600, 4))),
        (&[0xd8, 0x3d, 0xde, 0x00], 2, true, Some((0x1f600, 4))),
        (&[0x3d, 0xd8], 2, false, None), // lead without trail
        (&[0x3d, 0xd8, 0x41, 0x00], 2, false, None), // bad trail
        (&[0x00, 0xdc], 2, false, None), // trail first
        (&[0x41], 2, false, None),       // shorter than a character
        // UTF-32
        (&[0x00, 0xf6, 0x01, 0x00], 4, false, Some((0x1f600, 4))),
        (&[0x00, 0x01, 0xf6, 0x00], 4, true, Some((0x1f600, 4))),
        (&[0x00, 0x00, 0x11, 0x00], 4, false, None), // past 0x10ffff
        (&[0x00, 0xd8, 0x00, 0x00], 4, false, None), // a surrogate
        (&[0x00, 0x00, 0x00, 0x80], 4, false, None), // negative in Ghidra's int4
        // Other sizes are never characters.
        (&[0x41, 0, 0], 3, false, None),
    ];
    for (bytes, size, big, want) in cases {
        assert_eq!(
            codepoint(bytes, *size, *big),
            *want,
            "{bytes:02x?} {size} {big}"
        );
    }
}

#[test]
fn utf8_writing() {
    let cases: &[(u32, &[u8])] = &[
        (0x41, b"A"),
        (0x7f, &[0x7f]),
        (0x80, &[0xc2, 0x80]),
        (0x7ff, &[0xdf, 0xbf]),
        (0x800, &[0xe0, 0xa0, 0x80]),
        (0xd800, &[0xed, 0xa0, 0x80]), // Ghidra writes surrogates
        (0xffff, &[0xef, 0xbf, 0xbf]),
        (0x10000, &[0xf0, 0x90, 0x80, 0x80]),
        (0x10_ffff, &[0xf4, 0x8f, 0xbf, 0xbf]),
        (0x1f_ffff, &[0xf7, 0xbf, 0xbf, 0xbf]), // 21 bits still fit
    ];
    for (cp, want) in cases {
        let mut out = Vec::new();
        write_utf8(&mut out, *cp).unwrap();
        assert_eq!(&out, want, "{cp:#x}");
    }
    let mut out = Vec::new();
    assert!(matches!(
        write_utf8(&mut out, 0x20_0000),
        Err(SymbolError::BadCodepoint)
    ));
    assert!(matches!(
        write_utf8(&mut out, 0x8000_0000),
        Err(SymbolError::NegativeCodepoint)
    ));
    assert_eq!(out, Vec::<u8>::new());
}

#[test]
fn strings_read_from_the_image() {
    let sp = spaces();
    let mut bytes = vec![0u8; 0x100];
    bytes[..3].copy_from_slice(b"hi\0");
    bytes[3..7].copy_from_slice(b"junk");
    // A UTF-8 string of 40 characters: the terminator is in the second read.
    for (i, b) in bytes[0x40..0x68].iter_mut().enumerate() {
        *b = b'a' + (i % 26) as u8;
    }
    // UTF-16 "AB".
    bytes[0x80..0x86].copy_from_slice(&[0x41, 0, 0x42, 0, 0, 0]);
    // Invalid UTF-8 before the terminator.
    bytes[0xa0..0xa3].copy_from_slice(&[0xff, 0x41, 0]);
    let image = RawImage::new(bytes, RAM, 0x1000, Arc::clone(&sp));
    let utf8 = CharType {
        size: 1,
        opaque: false,
    };
    let utf16 = CharType {
        size: 2,
        opaque: false,
    };
    let at = |o: u64| Address::new(RAM, 0x1000 + o);
    let mut cache = StringCache::default();
    // One-byte characters keep the whole 32-byte read, past the terminator.
    let got = cache.string_data(at(0), utf8, &image, &sp).unwrap().clone();
    assert_eq!(got.bytes.len(), 32);
    assert_eq!(&got.bytes[..7], b"hi\0junk");
    assert!(!got.truncated);
    let long = cache.string_data(at(0x40), utf8, &image, &sp).unwrap();
    assert_eq!(long.bytes.len(), 64);
    // Wider characters are converted to UTF-8 with a terminator.
    let wide = cache.string_data(at(0x80), utf16, &image, &sp).unwrap();
    assert_eq!(wide.bytes, b"AB\0");
    // Failures are cached as empty answers: an invalid encoding, an
    // opaque type, bytes the image lacks.
    let opaque = CharType {
        size: 1,
        opaque: true,
    };
    for (addr, ch) in [(at(0xa0), utf8), (at(0), opaque), (at(0x1000), utf8)] {
        let mut fresh = StringCache::default();
        assert!(!fresh.is_string(addr, ch, &image, &sp).unwrap(), "{addr:?}");
        assert_eq!(fresh.cached(addr), Some(&StringData::default()));
    }
    // A cached answer is returned without reading again.
    cache.insert(
        at(0x80),
        StringData {
            truncated: true,
            bytes: b"Z\0".to_vec(),
        },
    );
    assert_eq!(
        cache
            .string_data(at(0x80), utf16, &image, &sp)
            .unwrap()
            .bytes,
        b"Z\0"
    );
}

#[test]
fn internal_strings_are_stored_under_their_hash() {
    let sp = spaces();
    let addr = Address::new(RAM, 0x1234);
    let mut cache = StringCache::new(4);
    let hash = cache.register_internal(addr, b"abcdefg\0", 1, &sp).unwrap();
    assert_eq!(hash, internal_hash(addr, b"abcdefg\0"));
    // The low half is the address; the high half the CRC of the bytes.
    assert_eq!(hash & 0xffff_ffff, 0x1234);
    assert_ne!(hash >> 32, 0);
    // Seven characters with a limit of four: converted and truncated.
    let data = cache.cached(Address::constant(hash)).unwrap();
    assert_eq!(
        (data.bytes.as_slice(), data.truncated),
        (&b"abcd\0"[..], true)
    );
    // An invalid encoding stores nothing and returns 0.
    assert_eq!(
        cache.register_internal(addr, &[0xff, 0], 1, &sp).unwrap(),
        0
    );
    assert_eq!(cache.entries().count(), 1);
}

#[test]
fn stringmanage_round_trip_and_repeated_addresses() {
    let sp = spaces();
    let mut cache = StringCache::default();
    cache.insert(
        Address::new(RAM, 0x10),
        StringData {
            truncated: false,
            bytes: b"hello\0".to_vec(),
        },
    );
    cache.insert(
        Address::new(STACK, 0x20),
        StringData {
            truncated: true,
            bytes: (0..=255).collect(),
        },
    );
    let text = encoded(|e| cache.encode(e, &sp).unwrap());
    let mut back = StringCache::default();
    decoded(&text, &sp, |d| back.decode(d, &sp)).unwrap();
    assert_eq!(
        back.entries().collect::<Vec<_>>(),
        cache.entries().collect::<Vec<_>>()
    );
    // Two <string> elements for one address: the bytes are appended.
    let doubled = r#"<stringmanage>
      <string><addr space="ram" offset="0x10"/><bytes trunc="false">41 42</bytes></string>
      <string><addr space="ram" offset="0x10"/><bytes trunc="true">43 00</bytes></string>
    </stringmanage>"#;
    let mut back = StringCache::default();
    decoded(doubled, &sp, |d| back.decode(d, &sp)).unwrap();
    let data = back.cached(Address::new(RAM, 0x10)).unwrap();
    assert_eq!(
        (data.bytes.as_slice(), data.truncated),
        (&b"ABC\0"[..], true)
    );
}

// ----- constant pool -------------------------------------------------------

#[test]
fn constant_pool_round_trip() {
    let m = small::spaces(false);
    let mut types = small::types(&m);
    let sp = Arc::new(m);
    let int4 = types.base(4, Metatype::Int).unwrap();
    let byte = types.base(1, Metatype::Uint).unwrap();
    let mut pool = ConstantPool::new();
    pool.insert(
        &[1, 2],
        CPoolRecord {
            tag: CPoolTag::Primitive,
            flags: 0,
            token: "seven".into(),
            value: 7,
            ty: int4,
            data: None,
        },
    )
    .unwrap();
    pool.insert(
        &[3],
        CPoolRecord {
            tag: CPoolTag::StringLiteral,
            flags: 0,
            token: String::new(),
            value: 0,
            ty: byte,
            data: Some((0..40).collect()),
        },
    )
    .unwrap();
    pool.put_record(&[4, 0], CPoolTag::PointerMethod, "m", int4)
        .unwrap();
    pool.insert(
        &[5],
        CPoolRecord {
            tag: CPoolTag::CheckCast,
            flags: 0,
            token: "c".into(),
            value: 0,
            ty: int4,
            data: None,
        },
    )
    .unwrap();
    // A second record under one key is refused.
    assert!(matches!(
        pool.put_record(&[1, 2], CPoolTag::Primitive, "again", int4),
        Err(SymbolError::DuplicateCpool { ref token }) if token == "seven"
    ));
    let text = encoded(|e| pool.encode(e, &types).unwrap());
    let mut back = ConstantPool::new();
    decoded(&text, &sp, |d| back.decode(d, &mut types)).unwrap_or_else(|e| panic!("{e}\n{text}"));
    for refs in [&[1u64, 2][..], &[3], &[4, 0], &[5]] {
        assert_eq!(
            back.record(refs).unwrap(),
            pool.record(refs).unwrap(),
            "{refs:?}"
        );
    }
    assert!(back.record(&[9]).unwrap().is_none());
    // An unknown tag name decodes as a primitive; too few data bytes is an
    // error (Ghidra leaves them indeterminate).
    let text = encoded(|e| {
        pool.record(&[1, 2])
            .unwrap()
            .unwrap()
            .encode(e, &types)
            .unwrap();
    });
    let odd = text.replace("\"primitive\"", "\"nonsense\"");
    assert_ne!(odd, text);
    let rec = decoded(&odd, &sp, |d| CPoolRecord::decode(d, &mut types)).unwrap();
    assert_eq!((rec.tag, rec.value), (CPoolTag::Primitive, 7));
    let short = r#"<cpoolrec tag="string"><data length="3">41 42</data><type name="uint1" size="1" metatype="uint"/></cpoolrec>"#;
    let got = decoded(short, &sp, |d| CPoolRecord::decode(d, &mut types));
    assert!(got.is_err(), "{got:?}");
}

// ----- overrides -----------------------------------------------------------

/// Prototype overrides need `bk-cspec`'s codec (D07); none are used here.
struct NoProtos;

impl ProtoCodec for NoProtos {
    fn encode(&self, _: &FuncProto, _: &mut dyn Encoder) -> bk_decomp_symbols::Result<()> {
        Err(SymbolError::Unimplemented("prototype encoding"))
    }
    fn decode(&self, _: &mut dyn Decoder<'_>) -> bk_decomp_symbols::Result<FuncProto> {
        Err(SymbolError::Unimplemented("prototype decoding"))
    }
    fn print_raw(&self, _: &FuncProto) -> String {
        String::new()
    }
}

#[test]
fn overrides_print_encode_and_decode() {
    let sp = spaces();
    let a = |o| Address::new(RAM, o);
    let mut ov = Overrides::default();
    let mut empty = String::new();
    {
        let mut enc = XmlEncoder::new(true);
        ov.encode(&mut enc, &sp, &NoProtos).unwrap();
        empty.push_str(enc.as_str());
    }
    assert_eq!(empty, "", "nothing is written for no overrides");
    ov.insert_force_goto(a(0x10), a(0x20));
    ov.insert_deadcode_delay(RAM, 2);
    ov.insert_deadcode_delay(STACK, 0);
    ov.insert_multistage_jump(a(0x30));
    ov.insert_flow_override(a(0x40), "callreturn").unwrap();
    ov.insert_destination_override(a(0x50), a(0x60), "call_call")
        .unwrap();
    assert!(matches!(
        ov.insert_flow_override(a(0x40), "jump"),
        Err(SymbolError::UnknownFlowOverride { .. })
    ));
    // The space's own delay is not an override.
    assert!(ov.has_deadcode_delay(RAM, &sp));
    assert!(!ov.has_deadcode_delay(STACK, &sp));
    assert!(!ov.has_deadcode_delay(small::REG, &sp));
    assert_eq!(
        ov.override_messages(&sp),
        [
            "Restarted to delay deadcode elimination for space: ram",
            "Restarted to delay deadcode elimination for space: stack"
        ]
    );
    let raw = |x: u64| a(x).raw(&sp).to_string();
    assert_eq!(
        ov.print_raw(&sp, &NoProtos),
        format!(
            "force goto at {} jumping to {}\n\
             dead code delay on ram set to 2\n\
             dead code delay on stack set to 0\n\
             override BRANCH, BRANCHIND, or RETURN at {} to a CALL followed by a RETURN\n\
             override CALL at {} to call to a new address {}\n",
            raw(0x10),
            raw(0x20),
            raw(0x40),
            raw(0x50),
            raw(0x60)
        )
    );
    // Round trip, with an unknown child that decoding skips.
    let text = encoded(|e| ov.encode(e, &sp, &NoProtos).unwrap());
    let text = text.replacen(
        "<forcegoto>",
        "<future_thing x=\"1\"><y/></future_thing><forcegoto>",
        1,
    );
    let mut back = Overrides::default();
    decoded(&text, &sp, |d| back.decode(d, &sp, &NoProtos)).unwrap();
    assert_eq!(back.force_goto, ov.force_goto);
    assert_eq!(back.deadcode_delay, ov.deadcode_delay);
    assert_eq!(back.multistage_jump, ov.multistage_jump);
    assert_eq!(back.pcode, ov.pcode);
    assert!(back.query_multistage_jumptable(a(0x30)));
    assert_eq!(
        back.pcode_override(a(0x40)),
        Some(OverrideRecord::CallReturn)
    );
    assert_eq!(
        back.pcode_override(a(0x50)),
        Some(OverrideRecord::CallCall(a(0x60)))
    );
}

// ----- the XML load image --------------------------------------------------

#[test]
fn binary_image_round_trip_and_reads() {
    let sp = spaces();
    let text = r#"<binaryimage arch="x86:LE:64:default">
      <bytechunk space="ram" offset="0x1000" readonly="true">
        0102 0304
        05
      </bytechunk>
      <bytechunk space="ram" offset="0x2000">ff</bytechunk>
      <symbol space="ram" offset="0x1000" name="start"/>
    </binaryimage>"#;
    let image = decoded(text, &sp, |d| XmlImage::decode(d, Arc::clone(&sp), "t.xml")).unwrap();
    assert_eq!(image.arch_type(), "x86:LE:64:default");
    assert!(image.is_readonly_chunk(Address::new(RAM, 0x1000)));
    let mut buf = [0u8; 5];
    image
        .load_fill(&mut buf, Address::new(RAM, 0x1000))
        .unwrap();
    assert_eq!(buf, [1, 2, 3, 4, 5]);
    assert_eq!(image.symbols().len(), 1);
    // Encoding and decoding again keeps every chunk; Ghidra's padding (512
    // zero bytes after each chunk, up to the next) adds a further pad chunk
    // after each pad on every decode.
    let once = encoded(|e| image.encode(e).unwrap());
    let again = decoded(&once, &sp, |d| {
        XmlImage::decode(d, Arc::clone(&sp), "t.xml")
    })
    .unwrap();
    let chunks = |i: &XmlImage| -> Vec<(Address, Vec<u8>)> {
        i.chunks().map(|(a, v)| (*a, v.clone())).collect()
    };
    let (first, second) = (chunks(&image), chunks(&again));
    assert!(first.iter().all(|c| second.contains(c)));
    assert_eq!(
        first
            .iter()
            .map(|(a, v)| (a.offset(), v.len()))
            .collect::<Vec<_>>(),
        [(0x1000, 5), (0x1005, 0x200), (0x2000, 1), (0x2001, 0x200)]
    );
    assert_eq!(second.len(), 6);
    assert!(again.is_readonly_chunk(Address::new(RAM, 0x1000)));
    // Another root names the file.
    let got = decoded("<other/>", &sp, |d| {
        XmlImage::decode(d, Arc::clone(&sp), "t.xml")
    });
    assert!(
        matches!(got, Err(SymbolError::MissingBinaryImage { ref file }) if file == "t.xml"),
        "{got:?}"
    );
}
