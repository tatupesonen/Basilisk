//! Port of Ghidra's `ghidra.program.model.data.LEB128Test` (5 tests).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use bk_bin::leb128::{self, DecodeError};
use bk_bin::{BinError, BinaryReader, Endian};

/// Ghidra's `unsignedTestEntries`: expected value and encoding.
const UNSIGNED: &[(u64, &[u8])] = &[
    // misc
    (0, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x0]), // zero, encoded non-optimally
    (1, &[0x81, 0x80, 0x80, 0x80, 0x80, 0x0]), // one, encoded non-optimally
    (
        u64::MAX,
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
    ),
    (0xf_ffff_ffff, &[0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), // shifts past 32 bits
    // 1 byte
    (1, &[0x01]),
    (63, &[0x3f]),
    (64, &[0x40]),
    // 1 byte to 2 byte transition
    (125, &[0x7d]),
    (126, &[0x7e]),
    (127, &[0x7f]),
    (128, &[0x80, 0x01]),
    (129, &[0x81, 0x01]),
    (130, &[0x82, 0x01]),
    (131, &[0x83, 0x01]),
    (254, &[0xfe, 0x01]),
    (255, &[0xff, 0x01]),
    (256, &[0x80, 0x02]),
    (257, &[0x81, 0x02]),
    // 2 byte to 3 byte transition
    (16382, &[0xfe, 0x7f]),
    (16383, &[0xff, 0x7f]),
    (16384, &[0x80, 0x80, 0x01]),
    (16385, &[0x81, 0x80, 0x01]),
    // 3 byte to 4 byte transition
    (2_097_151, &[0xff, 0xff, 0x7f]),
    (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
    (2_097_153, &[0x81, 0x80, 0x80, 0x01]),
    // 4 byte to 5 byte transition
    (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
    (268_435_456, &[0x80, 0x80, 0x80, 0x80, 0x01]),
    (268_435_457, &[0x81, 0x80, 0x80, 0x80, 0x01]),
    // 5 byte to 6 byte transition
    (34_359_738_367, &[0xff, 0xff, 0xff, 0xff, 0x7f]),
    (34_359_738_368, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
    (34_359_738_369, &[0x81, 0x80, 0x80, 0x80, 0x80, 0x01]),
];

/// Ghidra's `signedTestEntries`.
const SIGNED: &[(i64, &[u8])] = &[
    // misc
    (-2_130_303_778_817, &[0xff, 0xff, 0xff, 0xff, 0xff, 0x41]),
    // 1 byte positive
    (0, &[0x00]),
    (1, &[0x01]),
    // 1 byte to 2 byte transition (positive)
    (63, &[0x3f]),
    (64, &[0xc0, 0x00]),
    (65, &[0xc1, 0x00]),
    (66, &[0xc2, 0x00]),
    (126, &[0xfe, 0x00]),
    (127, &[0xff, 0x00]),
    (128, &[0x80, 0x01]),
    (129, &[0x81, 0x01]),
    (254, &[0xfe, 0x01]),
    (255, &[0xff, 0x01]),
    (256, &[0x80, 0x02]),
    (257, &[0x81, 0x02]),
    // 2 byte to 3 byte transition
    (8190, &[0xfe, 0x3f]),
    (8191, &[0xff, 0x3f]),
    (8192, &[0x80, 0xc0, 0x00]),
    (8193, &[0x81, 0xc0, 0x00]),
    // 1 byte negative
    (-1, &[0x7f]),
    (-2, &[0x7e]),
    (-3, &[0x7d]),
    (-4, &[0x7c]),
    (-5, &[0x7b]),
    (-6, &[0x7a]),
    // 1 byte to 2 byte transition (negative)
    (-64, &[0x40]),
    (-65, &[0xbf, 0x7f]),
    (-127, &[0x81, 0x7f]),
    (-128, &[0x80, 0x7f]),
    (-129, &[0xff, 0x7e]),
    // 2 byte to 3 byte transition (negative)
    (-8191, &[0x81, 0x40]),
    (-8192, &[0x80, 0x40]),
    (-8193, &[0xff, 0xbf, 0x7f]),
    (-8194, &[0xfe, 0xbf, 0x7f]),
];

#[test]
fn test_unsigned_test_entries() {
    for (i, &(expected, bytes)) in UNSIGNED.iter().enumerate() {
        // No bytes may be left over: the value must use the whole encoding.
        assert_eq!(
            leb128::decode_unsigned(bytes),
            Ok((expected, bytes.len())),
            "entry {i}"
        );
        let mut reader = BinaryReader::from_slice(bytes, Endian::Little);
        assert_eq!(reader.read_uleb128().unwrap(), expected, "entry {i}");
        assert_eq!(reader.remaining(), 0, "entry {i}");
    }
}

#[test]
fn test_signed_test_entries() {
    for (i, &(expected, bytes)) in SIGNED.iter().enumerate() {
        assert_eq!(
            leb128::decode_signed(bytes),
            Ok((expected, bytes.len())),
            "entry {i}"
        );
        let mut reader = BinaryReader::from_slice(bytes, Endian::Little);
        assert_eq!(reader.read_sleb128().unwrap(), expected, "entry {i}");
        assert_eq!(reader.remaining(), 0, "entry {i}");
    }
}

#[test]
fn test_toolarge_unsigned() {
    // One bit too large for 64 bits.
    let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
    assert_eq!(
        leb128::decode_unsigned(&bytes),
        Err(DecodeError::TooLarge { consumed: 10 })
    );
    let mut reader = BinaryReader::from_slice(&bytes, Endian::Little);
    assert!(matches!(
        reader.read_uleb128(),
        Err(BinError::Leb128TooLarge { offset: 0 })
    ));
}

#[test]
fn test_too_large_value_binary_reader_stream_position() {
    // After a value that is too large, the stream stands right after the
    // ten bytes that were examined.
    let bytes = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x1, 0x2,
    ];
    let mut reader = BinaryReader::from_slice(&bytes, Endian::Little);
    assert!(reader.read_uleb128().is_err());
    assert_eq!(reader.remaining(), bytes.len() as u64 - 10);
    assert_eq!(
        leb128::decode_unsigned(&bytes),
        Err(DecodeError::TooLarge { consumed: 10 })
    );
}

fn assert_round_trip_unsigned(value: u64) {
    let mut bytes = Vec::new();
    let len = leb128::encode_unsigned(value, &mut bytes);
    assert_eq!(
        leb128::decode_unsigned(&bytes),
        Ok((value, len)),
        "{value:#x} as {bytes:x?}"
    );
}

fn assert_round_trip_signed(value: i64) {
    let mut bytes = Vec::new();
    let len = leb128::encode_signed(value, &mut bytes);
    assert_eq!(
        leb128::decode_signed(&bytes),
        Ok((value, len)),
        "{value:#x} as {bytes:x?}"
    );
}

#[test]
fn test_encode() {
    let i32_max = i64::from(i32::MAX);
    let i32_min = i64::from(i32::MIN);
    // positive unsigned
    (0..65536 + 10).for_each(assert_round_trip_unsigned);
    (i32_max - 1000..i32_max + 1000).for_each(|v| assert_round_trip_unsigned(v as u64));
    (i64::MAX - 1000..i64::MAX).for_each(|v| assert_round_trip_unsigned(v as u64));
    // beyond Ghidra's ranges: the top of the unsigned range
    (u64::MAX - 1000..=u64::MAX).for_each(assert_round_trip_unsigned);
    // positive signed
    (0..65536 + 10).for_each(assert_round_trip_signed);
    (i32_max - 1000..i32_max + 1000).for_each(assert_round_trip_signed);
    (i64::MAX - 1000..=i64::MAX).for_each(assert_round_trip_signed);
    // negative signed
    (-65536 - 10..10).for_each(assert_round_trip_signed);
    (i32_min - 1000..i32_min + 1000).for_each(assert_round_trip_signed);
    (i64::MIN..i64::MIN + 1000).for_each(assert_round_trip_signed);
}
