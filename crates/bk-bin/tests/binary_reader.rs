//! Port of Ghidra's `ghidra.app.util.bin.BinaryReaderTest` (53 tests).
//!
//! Each test keeps the name of the JUnit method it ports. Where Java needs a
//! signed and an unsigned accessor returning a wider type, the Rust reader
//! has `read_iN`/`read_uN`; where Java expects `EOFException`, the port
//! checks [`BinError::is_eof`].

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

use bk_bin::{BinError, BinaryReader, Charset, Endian, FillProvider, MemoryProvider};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// Ghidra's `br(isLE, values...)`: the tests own their bytes, so the reader
/// is built over a slice.
fn br(endian: Endian, bytes: &[u8]) -> BinaryReader<'_> {
    BinaryReader::from_slice(bytes, endian)
}

/// Ghidra's `staticValueBR`: a provider of 100 × 2³² − 100 bytes of 0xaa.
fn huge() -> FillProvider {
    FillProvider::new(u64::from(u32::MAX) * 100, 0xaa)
}

/// A count just under Java's `Integer.MAX_VALUE`, above the sane limit.
const OVERSIZE: usize = i32::MAX as usize - 10;

fn utf16(text: &[u16], endian: Endian) -> Vec<u8> {
    text.iter()
        .flat_map(|u| {
            if endian == LE {
                u.to_le_bytes()
            } else {
                u.to_be_bytes()
            }
        })
        .collect()
}

#[test]
fn test_clone() {
    let provider = MemoryProvider::new(vec![0u8; 1024]);
    let mut reader = BinaryReader::new(&provider, LE);
    reader.set_position(0x100);
    let reader_clone = reader.at(0x200);
    assert_eq!(reader.position(), 0x100);
    assert_eq!(reader_clone.position(), 0x200);
}

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

#[test]
fn test_read_byte() {
    let r = br(LE, &[1, 2, 127, 255, 0]);
    assert_eq!(r.read_i8_at(0).unwrap(), 1);
    assert_eq!(r.read_i8_at(1).unwrap(), 2);
    assert_eq!(r.read_i8_at(2).unwrap(), 127);
    assert_eq!(r.read_i8_at(3).unwrap(), -1);
    assert_eq!(r.read_i8_at(4).unwrap(), 0);
    assert!(r.read_i8_at(5).is_err());
}

#[test]
fn test_read_unsigned_byte() {
    let r = br(LE, &[1, 2, 127, 255, 0]);
    assert_eq!(r.read_u8_at(0).unwrap(), 1);
    assert_eq!(r.read_u8_at(1).unwrap(), 2);
    assert_eq!(r.read_u8_at(2).unwrap(), 127);
    assert_eq!(r.read_u8_at(3).unwrap(), 255);
    assert_eq!(r.read_u8_at(4).unwrap(), 0);
    assert!(r.read_u8_at(5).is_err());
}

#[test]
fn test_read_next_byte() {
    let mut r = br(LE, &[1, 2, 127, 255, 0]);
    assert_eq!(r.read_i8().unwrap(), 1);
    assert_eq!(r.read_i8().unwrap(), 2);
    assert_eq!(r.read_i8().unwrap(), 127);
    assert_eq!(r.read_i8().unwrap(), -1);
    assert_eq!(r.read_i8().unwrap(), 0);
    assert!(r.read_i8().is_err());
}

#[test]
fn test_read_next_unsigned_byte() {
    let mut r = br(LE, &[1, 2, 127, 255, 0]);
    assert_eq!(r.read_u8().unwrap(), 1);
    assert_eq!(r.read_u8().unwrap(), 2);
    assert_eq!(r.read_u8().unwrap(), 127);
    assert_eq!(r.read_u8().unwrap(), 255);
    assert_eq!(r.read_u8().unwrap(), 0);
    assert!(r.read_u8().is_err());
}

#[test]
fn test_read_byte_array_oversize() {
    let provider = huge();
    let mut r = BinaryReader::new(&provider, LE);
    assert!(r.read_bytes(OVERSIZE).is_err());
}

// ---------------------------------------------------------------------------
// Shorts
// ---------------------------------------------------------------------------

const SHORTS: [u8; 8] = [1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80];

#[test]
fn test_read_short() {
    let r = br(LE, &SHORTS);
    assert_eq!(r.read_i16_at(0).unwrap(), 1);
    assert_eq!(r.read_i16_at(2).unwrap(), i16::MAX);
    assert_eq!(r.read_i16_at(4).unwrap(), -1);
    assert_eq!(r.read_i16_at(6).unwrap(), i16::MIN);
    assert!(r.read_i16_at(8).is_err());
}

#[test]
fn test_read_unsigned_short() {
    let r = br(LE, &SHORTS);
    assert_eq!(r.read_u16_at(0).unwrap(), 1);
    assert_eq!(r.read_u16_at(2).unwrap(), 0x7fff);
    assert_eq!(r.read_u16_at(4).unwrap(), 0xffff);
    assert_eq!(r.read_u16_at(6).unwrap(), 0x8000);
    assert!(r.read_u16_at(8).is_err());
}

#[test]
fn test_read_next_short() {
    let mut r = br(LE, &SHORTS);
    assert_eq!(r.read_i16().unwrap(), 1);
    assert_eq!(r.read_i16().unwrap(), i16::MAX);
    assert_eq!(r.read_i16().unwrap(), -1);
    assert_eq!(r.read_i16().unwrap(), i16::MIN);
    assert!(r.read_i16().is_err());
}

#[test]
fn test_read_next_unsigned_short() {
    let mut r = br(LE, &SHORTS);
    assert_eq!(r.read_u16().unwrap(), 1);
    assert_eq!(r.read_u16().unwrap(), 0x7fff);
    assert_eq!(r.read_u16().unwrap(), 0xffff);
    assert_eq!(r.read_u16().unwrap(), 0x8000);
    assert!(r.read_u16().is_err());
}

#[test]
fn test_read_short_array_oversize() {
    let provider = huge();
    let mut r = BinaryReader::new(&provider, LE);
    assert!(r.read_i16_array(OVERSIZE).is_err());
    assert!(r.read_u16_array(OVERSIZE).is_err());
}

// ---------------------------------------------------------------------------
// Ints
// ---------------------------------------------------------------------------

const INTS: [u8; 16] = [
    1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80,
];

#[test]
fn test_read_int() {
    let r = br(LE, &INTS);
    assert_eq!(r.read_i32_at(0).unwrap(), 1);
    assert_eq!(r.read_i32_at(4).unwrap(), i32::MAX);
    assert_eq!(r.read_i32_at(8).unwrap(), -1);
    assert_eq!(r.read_i32_at(12).unwrap(), i32::MIN);
    assert!(r.read_i32_at(16).is_err());
}

#[test]
fn test_read_unsigned_int() {
    let r = br(LE, &INTS);
    assert_eq!(r.read_u32_at(0).unwrap(), 1);
    assert_eq!(r.read_u32_at(4).unwrap(), 0x7fff_ffff);
    assert_eq!(r.read_u32_at(8).unwrap(), 0xffff_ffff);
    assert_eq!(r.read_u32_at(12).unwrap(), 0x8000_0000);
    assert!(r.read_u32_at(16).is_err());
}

#[test]
fn test_read_next_int() {
    let mut r = br(LE, &INTS);
    assert_eq!(r.read_i32().unwrap(), 1);
    assert_eq!(r.read_i32().unwrap(), i32::MAX);
    assert_eq!(r.read_i32().unwrap(), -1);
    assert_eq!(r.read_i32().unwrap(), i32::MIN);
    assert!(r.read_i32().is_err());
}

#[test]
fn test_read_next_unsigned_int() {
    let mut r = br(LE, &INTS);
    assert_eq!(r.read_u32().unwrap(), 1);
    assert_eq!(r.read_u32().unwrap(), 0x7fff_ffff);
    assert_eq!(r.read_u32().unwrap(), 0xffff_ffff);
    assert_eq!(r.read_u32().unwrap(), 0x8000_0000);
    assert!(r.read_u32().is_err());
}

#[test]
fn test_uint32_max() {
    let mut r = br(LE, &[0xff, 0xff, 0xff, 0x7f, 0xff]);
    assert_eq!(r.read_u32_count().unwrap(), i32::MAX as usize);
}

#[test]
fn test_uint32_overflow() {
    // 0xffff_ffff does not fit what Java calls a positive int.
    let mut r = br(LE, &[0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(
        r.read_u32_count(),
        Err(BinError::ValueOutOfRange { .. })
    ));
}

#[test]
fn test_read_int_array_oversize() {
    let provider = huge();
    let mut r = BinaryReader::new(&provider, LE);
    assert!(r.read_i32_array(OVERSIZE).is_err());
    assert!(r.read_u32_array(OVERSIZE).is_err());
}

// ---------------------------------------------------------------------------
// UTF-16 Unicode strings
// ---------------------------------------------------------------------------

#[test]
fn test_read_unicode_string_fixedlen_le() {
    let r = br(LE, &[1, 1, 1, b'A', 0, b'B', 0, b'C', 0, 0, 0x80, 0]);
    assert_eq!(r.read_utf16_fixed_at(3, 4).unwrap(), "ABC\u{8000}");
}

#[test]
fn test_read_unicode_string_fixedlen_be() {
    let r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0x80, 0, 0]);
    assert_eq!(r.read_utf16_fixed_at(3, 4).unwrap(), "ABC\u{8000}");
}

#[test]
fn test_read_unicode_string_le() {
    let r = br(LE, &[1, 1, 1, b'A', 0, b'B', 0, b'C', 0, 0, 0x80, 0, 0]);
    assert_eq!(r.read_utf16_at(3).unwrap(), "ABC\u{8000}");
}

#[test]
fn test_read_unicode_string_be() {
    let r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0x80, 0, 0, 0]);
    assert_eq!(r.read_utf16_at(3).unwrap(), "ABC\u{8000}");
}

#[test]
fn test_read_unicode_string_empty_str() {
    let r = br(BE, &[1, 1, 1, 0, 0, 0, b'B', 0, b'C', 0x80, 0, 0, 0]);
    assert_eq!(r.read_utf16_at(3).unwrap(), "");
}

#[test]
fn test_read_unicode_string_eof_terminated() {
    let r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C']);
    assert!(r.read_utf16_at(3).unwrap_err().is_eof());
}

#[test]
fn test_read_unicode_string_missing_full_terminator() {
    let r = br(BE, &[0, b'A', 0, b'B', 0, b'C', 0]);
    assert!(r.read_utf16_at(0).unwrap_err().is_eof());
}

#[test]
fn test_read_unicode_string_at_eof() {
    let r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C']);
    assert!(r.read_utf16_at(9).unwrap_err().is_eof());
}

#[test]
fn test_read_unicode_string_past_eof() {
    let r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C']);
    assert!(r.read_utf16_at(10).unwrap_err().is_eof());
}

#[test]
fn test_read_next_unicode_string_le() {
    let mut r = br(LE, &[1, 1, 1, b'A', 0, b'B', 0, b'C', 0, 0, 0x80, 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16().unwrap(), "ABC\u{8000}");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_be() {
    let mut r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0x80, 0, 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16().unwrap(), "ABC\u{8000}");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_with_trailing_whitespace() {
    let mut r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0, b' ', 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16().unwrap(), "ABC ");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_empty() {
    let mut r = br(BE, &[1, 1, 1, 0, 0, 0, b'B', 0, b'C', 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16().unwrap(), "");
    assert_eq!(r.read_utf16().unwrap(), "BC");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_fixedlen() {
    let mut r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0, b' ', 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16_fixed(4).unwrap(), "ABC ");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_fixedlen_nullterms() {
    let mut r = br(BE, &[1, 1, 1, 0, b'A', 0, b'B', 0, b'C', 0, 0, 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16_fixed(5).unwrap(), "ABC");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_fixedlen_emptystr() {
    let mut r = br(BE, &[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]);
    r.set_position(3);
    assert_eq!(r.read_utf16_fixed(5).unwrap(), "");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_unicode_string_null_term_at_eof() {
    let mut r = br(BE, &[0, b'A', 0, b'B', 0, b'C', 0, 0]);
    assert_eq!(r.read_utf16().unwrap(), "ABC");
    assert!(r.read_utf16().is_err());
}

#[test]
fn test_read_next_unicode_string_null_term_to_eof() {
    let mut r = br(BE, &[0, b'A', 0, b'B', 0, b'C']);
    assert!(r.read_utf16().unwrap_err().is_eof());
}

// ---------------------------------------------------------------------------
// 'Ascii' strings
// ---------------------------------------------------------------------------

#[test]
fn test_read_ascii_string_null_term() {
    let r = br(LE, b"ABC\0\x2a");
    assert_eq!(r.read_ascii_at(0).unwrap(), "ABC");
}

#[test]
fn test_read_ascii_string_not_terminated() {
    let r = br(LE, b"ABC");
    assert!(r.read_ascii_at(0).unwrap_err().is_eof());
}

#[test]
fn test_read_ascii_string_at_eof() {
    let r = br(LE, b"ABC");
    assert!(r.read_ascii_at(3).unwrap_err().is_eof());
}

#[test]
fn test_read_ascii_string_past_eof() {
    let r = br(LE, b"ABC");
    assert!(r.read_ascii_at(4).unwrap_err().is_eof());
}

#[test]
fn test_read_ascii_string_not_trimed() {
    let r = br(LE, b" ABC \0\x2a");
    assert_eq!(r.read_ascii_at(0).unwrap(), " ABC ");
}

#[test]
fn test_read_ascii_string_tab_terminates() {
    // A tab does not end the string.
    let r = br(LE, b"ABC\tDEF\0\x2a");
    assert_eq!(r.read_ascii_at(0).unwrap(), "ABC\tDEF");
}

#[test]
fn test_read_next_ascii_string() {
    let mut r = br(LE, b" ABC \0\x2a");
    assert_eq!(r.read_ascii().unwrap(), " ABC ");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_ascii_string_emtpy_str() {
    let mut r = br(LE, b" ABC \0\x2a");
    r.set_position(5);
    assert_eq!(r.read_ascii().unwrap(), "");
    assert_eq!(r.read_u8().unwrap(), 42);
}

#[test]
fn test_read_next_ascii_string_at_eof() {
    let mut r = br(LE, b"ABC\0");
    assert_eq!(r.read_ascii().unwrap(), "ABC");
    assert!(r.read_ascii().is_err());
}

#[test]
fn test_read_next_ascii_string_fixed_length() {
    let mut r = br(LE, b"ABCDEF\0\x2a");
    assert_eq!(r.read_ascii_fixed(3).unwrap(), "ABC");
    assert_eq!(r.read_ascii_fixed(4).unwrap(), "DEF");
    assert_eq!(r.read_i8().unwrap(), 42);
}

#[test]
fn test_read_next_ascii_string_fixed_length_with_whitespace() {
    let mut r = br(LE, b"AB \0DEF\0\x2a");
    assert_eq!(r.read_ascii_fixed(4).unwrap(), "AB ");
    assert_eq!(r.read_ascii().unwrap(), "DEF");
    assert_eq!(r.read_i8().unwrap(), 42);
}

#[test]
fn test_read_next_ascii_string_fixed_length_empty_str() {
    let mut r = br(LE, b"\0\0\0DEF\0\x2a");
    assert_eq!(r.read_ascii_fixed(3).unwrap(), "");
    assert_eq!(r.read_ascii().unwrap(), "DEF");
    assert_eq!(r.read_i8().unwrap(), 42);
}

#[test]
fn test_read_ascii_string_to_eof() {
    let r = br(LE, b"ABC");
    assert!(matches!(
        r.read_ascii_at(0),
        Err(BinError::UnterminatedString { start: 0, end: 3 })
    ));
}

#[test]
fn test_read_ascii_string_oversize() {
    let provider = huge();
    let r = BinaryReader::new(&provider, LE);
    assert!(r.read_fixed_string_at(0, OVERSIZE, Charset::Ascii).is_err());
}

#[test]
fn test_read_utf8_string() {
    // Variable-length decoding: U+AA55 (3 bytes) and U+00FF (2 bytes).
    let r = br(LE, &[0xea, 0xa9, 0x95, 0xc3, 0xbf, 0]);
    assert_eq!(r.read_utf8_at(0).unwrap(), "\u{aa55}\u{ff}");
}

#[test]
fn test_read_next_utf8_string() {
    let mut r = br(LE, &[0xea, 0xa9, 0x95, 0xc3, 0xbf, 0, 0xea, 0xa9, 0x95, 0]);
    assert_eq!(r.read_utf8().unwrap(), "\u{aa55}\u{ff}");
    assert_eq!(r.read_utf8().unwrap(), "\u{aa55}");
}

#[test]
fn test_read_utf8_string_bad_data() {
    // A truncated 3-byte sequence becomes one replacement character.
    let r = br(LE, &[0xea, 0xa9, b'A', 0]);
    assert_eq!(r.read_utf8_at(0).unwrap(), "\u{fffd}A");
}

// ---------------------------------------------------------------------------
// Not in Ghidra's test: the same string cases through a provider-backed
// reader, so both the slice path and the provider path are held to them.
// ---------------------------------------------------------------------------

#[test]
fn unicode_strings_through_a_provider() {
    for endian in [LE, BE] {
        let mut bytes = vec![1, 1, 1];
        bytes.extend(utf16(&[0x41, 0x42, 0x43, 0x8000, 0], endian));
        bytes.push(42);
        let provider = MemoryProvider::new(bytes);
        let mut r = BinaryReader::new(&provider, endian);
        assert_eq!(r.read_utf16_at(3).unwrap(), "ABC\u{8000}");
        assert_eq!(r.read_utf16_fixed_at(3, 5).unwrap(), "ABC\u{8000}");
        r.set_position(3);
        assert_eq!(r.read_utf16().unwrap(), "ABC\u{8000}");
        assert_eq!(r.read_u8().unwrap(), 42);
        assert!(r.read_utf16().unwrap_err().is_eof());
    }
}
