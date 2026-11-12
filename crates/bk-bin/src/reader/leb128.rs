//! LEB128: the variable-length integer encoding of DWARF, WebAssembly and
//! Android packed relocations.
//!
//! This is Ghidra's `ghidra.program.model.data.LEB128` and
//! `ghidra.app.util.bin.LEB128Info`. Values are limited to 64 bits, with
//! Ghidra's rules for what is too large:
//!
//! * an unsigned value may use ten bytes only if the tenth is 0 or 1;
//! * a signed value may use ten bytes whatever the tenth is (its upper bits
//!   are dropped), and an eleventh byte is always an error;
//! * a decoder that reports "too large" has consumed exactly the bytes up to
//!   and including the one that proved it — ten for unsigned, eleven for
//!   signed.
//!
//! The `leb128` crate was evaluated and not used: its signed decoder
//! rejects ten-byte values Ghidra accepts, and on overflow it consumes all
//! following continuation bytes, which moves the cursor to a different place
//! than Ghidra's (the ported `LEB128Test` checks that position).

use crate::error::{BinError, Result};
use crate::reader::cursor::BinaryReader;

/// The largest number of bytes a decodable value occupies.
pub const MAX_LEN: usize = 10;

/// Why decoding a LEB128 value from a byte slice failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The slice ended before the last byte of the value.
    #[error("LEB128 value is cut off after {consumed} byte(s)")]
    Truncated {
        /// Number of bytes that were available.
        consumed: usize,
    },
    /// The value needs more than 64 bits.
    #[error("LEB128 value does not fit in 64 bits")]
    TooLarge {
        /// Number of bytes examined before giving up.
        consumed: usize,
    },
}

/// What stopped the decoding loop, generic over the byte source's error.
enum Stop<E> {
    Source(E),
    TooLarge,
}

/// Decodes one value, pulling bytes from `next`. Returns the raw 64 bits and
/// leaves it to the caller to interpret them as signed or unsigned.
fn decode_with<E>(signed: bool, mut next: impl FnMut() -> Result<u8, E>) -> Result<u64, Stop<E>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = next().map_err(Stop::Source)?;
        if shift == 70 || (!signed && shift == 63 && byte > 1) {
            return Err(Stop::TooLarge);
        }
        // `shift` is at most 63 here.
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if signed && shift < u64::BITS && byte & 0x40 != 0 {
                value |= u64::MAX << shift;
            }
            return Ok(value);
        }
    }
}

fn decode(bytes: &[u8], signed: bool) -> Result<(u64, usize), DecodeError> {
    let mut consumed = 0usize;
    let result = decode_with(signed, || {
        let byte = bytes.get(consumed).copied().ok_or(())?;
        consumed += 1;
        Ok(byte)
    });
    match result {
        Ok(value) => Ok((value, consumed)),
        Err(Stop::Source(())) => Err(DecodeError::Truncated { consumed }),
        Err(Stop::TooLarge) => Err(DecodeError::TooLarge { consumed }),
    }
}

/// Decodes an unsigned value from the start of `bytes`; returns the value
/// and the number of bytes it occupied.
pub fn decode_unsigned(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    decode(bytes, false)
}

/// Decodes a signed value from the start of `bytes`; returns the value and
/// the number of bytes it occupied.
pub fn decode_signed(bytes: &[u8]) -> Result<(i64, usize), DecodeError> {
    decode(bytes, true).map(|(value, len)| (value as i64, len))
}

/// Length in bytes of the value at the start of `bytes`, or `None` if it
/// does not end within [`MAX_LEN`] bytes or within the slice (Ghidra's
/// `LEB128.getLength`).
pub fn encoded_len(bytes: &[u8]) -> Option<usize> {
    bytes
        .iter()
        .take(MAX_LEN)
        .position(|&b| b & 0x80 == 0)
        .map(|i| i + 1)
}

/// Appends the unsigned encoding of `value` to `out`; returns the number of
/// bytes written (1 to 10).
pub fn encode_unsigned(mut value: u64, out: &mut Vec<u8>) -> usize {
    let start = out.len();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out.len() - start;
        }
        out.push(byte | 0x80);
    }
}

/// Appends the signed encoding of `value` to `out`; returns the number of
/// bytes written (1 to 10).
pub fn encode_signed(mut value: i64, out: &mut Vec<u8>) -> usize {
    let start = out.len();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        // Done once the remaining bits are pure sign extension of this byte.
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out.len() - start;
        }
        out.push(byte | 0x80);
    }
}

/// A decoded LEB128 value together with where it was and how long it was
/// (Ghidra's `LEB128Info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Leb128Info {
    offset: u64,
    value: u64,
    len: usize,
    signed: bool,
}

impl Leb128Info {
    /// Offset of the first byte of the value in the data it was read from.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Number of bytes the value occupied.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: a value occupies at least one byte.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when the value was decoded as signed.
    pub const fn is_signed(&self) -> bool {
        self.signed
    }

    /// The value as a signed 64-bit integer (Ghidra's `asLong`): the same
    /// bits whichever way it was decoded.
    pub const fn as_i64(&self) -> i64 {
        self.value as i64
    }

    /// The value as an unsigned 64-bit integer: the same bits whichever way
    /// it was decoded.
    pub const fn as_u64(&self) -> u64 {
        self.value
    }

    /// The value if it lies in `0..=i32::MAX`, as Ghidra's `asUInt32`
    /// requires; an error otherwise.
    pub fn as_u32(&self) -> Result<u32> {
        u32::try_from(self.as_i64())
            .ok()
            .filter(|&v| i32::try_from(v).is_ok())
            .ok_or(BinError::ValueOutOfRange {
                value: if self.signed {
                    i128::from(self.as_i64())
                } else {
                    i128::from(self.value)
                },
                target: "an unsigned 31-bit integer",
            })
    }

    /// The value if it fits a signed 32-bit integer (Ghidra's `asInt32`); an
    /// error otherwise.
    pub fn as_i32(&self) -> Result<i32> {
        i32::try_from(self.as_i64()).map_err(|_| BinError::ValueOutOfRange {
            value: i128::from(self.as_i64()),
            target: "a signed 32-bit integer",
        })
    }
}

/// LEB128 reads. Unlike other reads, a failed LEB128 read leaves the
/// position after the bytes it examined, as Ghidra's does.
impl BinaryReader<'_> {
    fn read_leb128(&mut self, signed: bool) -> Result<Leb128Info> {
        let offset = self.position();
        let result = decode_with(signed, || self.read_u8());
        let len = usize::try_from(self.position().wrapping_sub(offset)).unwrap_or(MAX_LEN);
        match result {
            Ok(value) => Ok(Leb128Info {
                offset,
                value,
                len,
                signed,
            }),
            Err(Stop::Source(error)) => Err(error),
            Err(Stop::TooLarge) => Err(BinError::Leb128TooLarge { offset }),
        }
    }

    /// Reads an unsigned LEB128 value at the position and advances past it.
    pub fn read_uleb128(&mut self) -> Result<u64> {
        self.read_leb128(false).map(|info| info.as_u64())
    }

    /// Reads a signed LEB128 value at the position and advances past it.
    pub fn read_sleb128(&mut self) -> Result<i64> {
        self.read_leb128(true).map(|info| info.as_i64())
    }

    /// Reads an unsigned LEB128 value at the position, keeping its offset
    /// and length (Ghidra's `LEB128Info.unsigned`).
    pub fn read_uleb128_info(&mut self) -> Result<Leb128Info> {
        self.read_leb128(false)
    }

    /// Reads a signed LEB128 value at the position, keeping its offset and
    /// length (Ghidra's `LEB128Info.signed`).
    pub fn read_sleb128_info(&mut self) -> Result<Leb128Info> {
        self.read_leb128(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Endian;

    #[test]
    fn decode_reports_length() {
        assert_eq!(decode_unsigned(&[0x7f, 0xff]), Ok((127, 1)));
        assert_eq!(decode_unsigned(&[0x80, 0x01, 0xff]), Ok((128, 2)));
        assert_eq!(decode_signed(&[0x7f]), Ok((-1, 1)));
        assert_eq!(decode_signed(&[0x80, 0x7f]), Ok((-128, 2)));
    }

    #[test]
    fn decode_errors() {
        assert_eq!(
            decode_unsigned(&[]),
            Err(DecodeError::Truncated { consumed: 0 })
        );
        assert_eq!(
            decode_unsigned(&[0x80, 0x80]),
            Err(DecodeError::Truncated { consumed: 2 })
        );
        assert_eq!(
            decode_signed(&[0xff]),
            Err(DecodeError::Truncated { consumed: 1 })
        );
        let mut big = vec![0xffu8; 9];
        big.push(0x02);
        assert_eq!(
            decode_unsigned(&big),
            Err(DecodeError::TooLarge { consumed: 10 })
        );
        // Signed: the tenth byte is accepted whatever it holds…
        assert_eq!(decode_signed(&big), Ok((i64::MAX, 10)));
        // …but an eleventh byte is not.
        let eleven = [0x80u8; 11];
        assert_eq!(
            decode_signed(&eleven),
            Err(DecodeError::TooLarge { consumed: 11 })
        );
        assert_eq!(
            decode_unsigned(&eleven),
            Err(DecodeError::TooLarge { consumed: 10 })
        );
        assert_eq!(
            DecodeError::TooLarge { consumed: 10 }.to_string(),
            "LEB128 value does not fit in 64 bits"
        );
    }

    #[test]
    fn extreme_values() {
        let mut max = vec![0xffu8; 9];
        max.push(0x01);
        assert_eq!(decode_unsigned(&max), Ok((u64::MAX, 10)));
        let mut out = Vec::new();
        assert_eq!(encode_unsigned(u64::MAX, &mut out), 10);
        assert_eq!(out, max);
        for value in [i64::MIN, i64::MAX, 0, -1, 63, 64, -64, -65] {
            let mut out = Vec::new();
            let len = encode_signed(value, &mut out);
            assert_eq!(decode_signed(&out), Ok((value, len)), "{value}");
        }
        let mut out = vec![0xaa];
        assert_eq!(encode_unsigned(0, &mut out), 1);
        assert_eq!(out, [0xaa, 0x00], "encoding appends");
        assert_eq!(encode_signed(-1, &mut out), 1);
        assert_eq!(out, [0xaa, 0x00, 0x7f]);
    }

    #[test]
    fn encoded_length() {
        assert_eq!(encoded_len(&[0x00]), Some(1));
        assert_eq!(encoded_len(&[0x80, 0x80, 0x01, 0x80]), Some(3));
        assert_eq!(encoded_len(&[0x80, 0x80]), None);
        assert_eq!(encoded_len(&[]), None);
        assert_eq!(encoded_len(&[0x80; 20]), None);
        let mut ten = vec![0x80u8; 9];
        ten.push(0);
        assert_eq!(encoded_len(&ten), Some(10));
        ten.insert(0, 0x80);
        assert_eq!(
            encoded_len(&ten),
            None,
            "an eleven-byte value is not supported"
        );
    }

    #[test]
    fn reader_keeps_offset_and_length() {
        let bytes = [0xaa, 0xe5, 0x8e, 0x26, 0x7f, 0x05];
        let mut r = BinaryReader::from_slice(&bytes, Endian::Big).at(1);
        let info = r.read_uleb128_info().unwrap();
        assert_eq!((info.offset(), info.len(), info.as_u64()), (1, 3, 624_485));
        assert!(!info.is_signed() && !info.is_empty());
        assert_eq!(info.as_u32().unwrap(), 624_485);
        assert_eq!(info.as_i32().unwrap(), 624_485);
        let info = r.read_sleb128_info().unwrap();
        assert_eq!((info.offset(), info.len(), info.as_i64()), (4, 1, -1));
        assert!(info.is_signed());
        assert_eq!(info.as_i32().unwrap(), -1);
        assert!(matches!(
            info.as_u32(),
            Err(BinError::ValueOutOfRange { value: -1, .. })
        ));
        assert_eq!(r.read_uleb128().unwrap(), 5);
        assert!(r.read_uleb128().unwrap_err().is_eof());
        assert!(r.read_sleb128().is_err());
    }

    #[test]
    fn range_checks() {
        let mut out = Vec::new();
        encode_unsigned(u64::from(u32::MAX), &mut out);
        let info = BinaryReader::from_slice(&out, Endian::Little)
            .read_uleb128_info()
            .unwrap();
        assert!(
            info.as_u32().is_err(),
            "above i32::MAX is rejected, as in Ghidra"
        );
        assert!(info.as_i32().is_err());
        let mut out = Vec::new();
        encode_unsigned(u64::MAX, &mut out);
        let info = BinaryReader::from_slice(&out, Endian::Little)
            .read_uleb128_info()
            .unwrap();
        assert!(matches!(
            info.as_u32(),
            Err(BinError::ValueOutOfRange { value, .. }) if value == i128::from(u64::MAX)
        ));
        let mut out = Vec::new();
        encode_signed(i64::from(i32::MIN), &mut out);
        let info = BinaryReader::from_slice(&out, Endian::Little)
            .read_sleb128_info()
            .unwrap();
        assert_eq!(info.as_i32().unwrap(), i32::MIN);
    }

    #[test]
    fn failed_reads_consume_what_they_examined() {
        let mut bytes = vec![0xffu8; 11];
        bytes.extend_from_slice(&[0x02, 0x01, 0x02]);
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        assert!(matches!(
            r.read_uleb128(),
            Err(BinError::Leb128TooLarge { offset: 0 })
        ));
        assert_eq!(r.position(), 10);
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        assert!(matches!(
            r.read_sleb128(),
            Err(BinError::Leb128TooLarge { offset: 0 })
        ));
        assert_eq!(r.position(), 11);
        let mut r = BinaryReader::from_slice(&[0x80, 0x80], Endian::Little);
        assert!(r.read_uleb128().unwrap_err().is_eof());
        assert_eq!(r.position(), 2);
    }
}
