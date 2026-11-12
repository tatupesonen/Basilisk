//! String reads: NUL-terminated and fixed-length, in the character sets
//! binary formats use.

use std::borrow::Cow;

use crate::endian::Endian;
use crate::error::{BinError, Result};
use crate::reader::cursor::BinaryReader;

/// The largest terminated string, in bytes, the reader will collect before
/// giving up with [`BinError::RunOnString`]: Ghidra's `MAX_SANE_BUFFER`
/// (2³¹ − 1025).
pub const MAX_STRING_BYTES: usize = i32::MAX as usize - 1024;

/// A character set for string reads.
///
/// Ghidra passes a Java `Charset` together with the size of one character;
/// here the size follows from the character set. Decoding never fails:
/// malformed input becomes U+FFFD, as with Java's `new String(bytes, charset)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Charset {
    /// 7-bit US-ASCII; bytes above 0x7f decode to U+FFFD.
    Ascii,
    /// ISO-8859-1: every byte is the code point of the same value.
    Latin1,
    /// UTF-8.
    Utf8,
    /// UTF-16, little-endian code units.
    Utf16Le,
    /// UTF-16, big-endian code units.
    Utf16Be,
    /// UTF-32, little-endian.
    Utf32Le,
    /// UTF-32, big-endian.
    Utf32Be,
}

impl Charset {
    /// UTF-16 in the given byte order.
    pub const fn utf16(endian: Endian) -> Self {
        match endian {
            Endian::Little => Self::Utf16Le,
            Endian::Big => Self::Utf16Be,
        }
    }

    /// UTF-32 in the given byte order.
    pub const fn utf32(endian: Endian) -> Self {
        match endian {
            Endian::Little => Self::Utf32Le,
            Endian::Big => Self::Utf32Be,
        }
    }

    /// Size in bytes of one code unit: the granularity at which terminators
    /// are searched for and fixed lengths are counted.
    pub const fn unit_len(self) -> usize {
        match self {
            Self::Ascii | Self::Latin1 | Self::Utf8 => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32Le | Self::Utf32Be => 4,
        }
    }

    /// Decodes `bytes`, replacing malformed sequences with U+FFFD.
    pub fn decode(self, bytes: &[u8]) -> String {
        const REPLACEMENT: char = char::REPLACEMENT_CHARACTER;
        match self {
            Self::Ascii => bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b)
                    } else {
                        REPLACEMENT
                    }
                })
                .collect(),
            Self::Latin1 => bytes.iter().map(|&b| char::from(b)).collect(),
            Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Utf16Le | Self::Utf16Be => {
                let (units, rest) = bytes.as_chunks::<2>();
                let from_bytes = if self == Self::Utf16Le {
                    u16::from_le_bytes
                } else {
                    u16::from_be_bytes
                };
                let mut text: String = char::decode_utf16(units.iter().map(|&u| from_bytes(u)))
                    .map(|c| c.unwrap_or(REPLACEMENT))
                    .collect();
                if !rest.is_empty() {
                    text.push(REPLACEMENT);
                }
                text
            }
            Self::Utf32Le | Self::Utf32Be => {
                let (units, rest) = bytes.as_chunks::<4>();
                let from_bytes = if self == Self::Utf32Le {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                };
                let mut text: String = units
                    .iter()
                    .map(|&u| char::from_u32(from_bytes(u)).unwrap_or(REPLACEMENT))
                    .collect();
                if !rest.is_empty() {
                    text.push(REPLACEMENT);
                }
                text
            }
        }
    }
}

/// Length of `bytes` after removing trailing all-zero units of `unit` bytes
/// (Ghidra's `getLengthWithoutTrailingNullTerms`).
fn len_without_trailing_nuls(bytes: &[u8], unit: usize) -> usize {
    let mut len = bytes.len() - bytes.len() % unit;
    while len >= unit
        && bytes
            .get(len - unit..len)
            .is_some_and(|u| u.iter().all(|&b| b == 0))
    {
        len -= unit;
    }
    len
}

/// Offset of the first all-zero unit of `unit` bytes in `bytes`, looking only
/// at unit boundaries.
fn find_terminator(bytes: &[u8], unit: usize) -> Option<usize> {
    if unit == 1 {
        return memchr::memchr(0, bytes);
    }
    bytes
        .chunks_exact(unit)
        .position(|u| u.iter().all(|&b| b == 0))
        .map(|i| i * unit)
}

/// NUL-terminated strings.
///
/// A terminated read stops at the first all-zero code unit, which is not
/// part of the result; nothing is trimmed. It fails with
/// [`BinError::StringAtEof`] when not even the first code unit can be read,
/// and with [`BinError::UnterminatedString`] when the data ends before a
/// terminator — both are "end of data" errors ([`BinError::is_eof`]). The
/// advancing forms move past the terminator.
impl<'a> BinaryReader<'a> {
    /// The raw bytes of the terminated string at `index`, without the
    /// terminator and without decoding; `unit_len` is the size of a code
    /// unit (and of the terminator) in bytes. Borrowed when the data is in
    /// memory.
    pub fn read_terminated_bytes_at(&self, index: u64, unit_len: usize) -> Result<Cow<'a, [u8]>> {
        let unit = unit_len.max(1);
        if let Some(mem) = self.as_slice()
            && let Some(tail) = usize::try_from(index)
                .ok()
                .and_then(|start| mem.get(start..))
            && let Some(end) = find_terminator(tail, unit)
        {
            return Ok(Cow::Borrowed(tail.get(..end).unwrap_or_default()));
        }
        self.read_terminated_slow(index, unit).map(Cow::Owned)
    }

    /// Collects a terminated string through the provider, a block at a time
    /// while whole blocks are readable and a unit at a time near the end.
    fn read_terminated_slow(&self, index: u64, unit: usize) -> Result<Vec<u8>> {
        const BLOCK_UNITS: usize = 64;
        let mut out = Vec::new();
        let mut block = vec![0u8; unit * BLOCK_UNITS];
        let mut position = index;
        loop {
            if out.len() + unit >= MAX_STRING_BYTES {
                return Err(BinError::RunOnString {
                    start: index,
                    end: position,
                });
            }
            let want = if self.is_valid_range(position, block.len() as u64) {
                block.len()
            } else {
                unit
            };
            let chunk = block.get_mut(..want).unwrap_or_default();
            if self.read_exact_at(position, chunk).is_err() {
                return Err(if out.is_empty() {
                    BinError::StringAtEof { offset: index }
                } else {
                    BinError::UnterminatedString {
                        start: index,
                        end: position,
                    }
                });
            }
            if let Some(end) = find_terminator(chunk, unit) {
                out.extend_from_slice(chunk.get(..end).unwrap_or_default());
                return Ok(out);
            }
            out.extend_from_slice(chunk);
            position = position
                .checked_add(want as u64)
                .ok_or(BinError::UnterminatedString {
                    start: index,
                    end: position,
                })?;
        }
    }

    /// Reads the terminated string at `index` in `charset` (Ghidra's
    /// `readString(index, charset, charLen)`).
    pub fn read_string_at(&self, index: u64, charset: Charset) -> Result<String> {
        Ok(charset.decode(&self.read_terminated_bytes_at(index, charset.unit_len())?))
    }

    /// Reads the terminated string at the position in `charset` and advances
    /// past its terminator.
    pub fn read_string(&mut self, charset: Charset) -> Result<String> {
        let unit = charset.unit_len();
        let bytes = self.read_terminated_bytes_at(self.position(), unit)?;
        self.skip((bytes.len() + unit) as u64);
        Ok(charset.decode(&bytes))
    }

    /// Reads the terminated US-ASCII string at `index`.
    pub fn read_ascii_at(&self, index: u64) -> Result<String> {
        self.read_string_at(index, Charset::Ascii)
    }

    /// Reads the terminated US-ASCII string at the position and advances
    /// past its terminator.
    pub fn read_ascii(&mut self) -> Result<String> {
        self.read_string(Charset::Ascii)
    }

    /// Reads the terminated UTF-8 string at `index`.
    pub fn read_utf8_at(&self, index: u64) -> Result<String> {
        self.read_string_at(index, Charset::Utf8)
    }

    /// Reads the terminated UTF-8 string at the position and advances past
    /// its terminator.
    pub fn read_utf8(&mut self) -> Result<String> {
        self.read_string(Charset::Utf8)
    }

    /// Reads the terminated UTF-16 string at `index`, in the reader's byte
    /// order (Ghidra's `readUnicodeString`). The terminator is a two-byte zero.
    pub fn read_utf16_at(&self, index: u64) -> Result<String> {
        self.read_string_at(index, Charset::utf16(self.endian()))
    }

    /// Reads the terminated UTF-16 string at the position, in the reader's
    /// byte order, and advances past its terminator.
    pub fn read_utf16(&mut self) -> Result<String> {
        self.read_string(Charset::utf16(self.endian()))
    }

    /// Reads the terminated UTF-32 string at `index`, in the reader's byte order.
    pub fn read_utf32_at(&self, index: u64) -> Result<String> {
        self.read_string_at(index, Charset::utf32(self.endian()))
    }

    /// Reads the terminated UTF-32 string at the position, in the reader's
    /// byte order, and advances past its terminator.
    pub fn read_utf32(&mut self) -> Result<String> {
        self.read_string(Charset::utf32(self.endian()))
    }
}

/// Fixed-length strings.
///
/// A fixed-length read takes exactly `unit_count` code units (bytes for
/// ASCII and UTF-8, two-byte units for UTF-16, four-byte units for UTF-32),
/// removes trailing all-zero units — the padding of a fixed-size field — and
/// decodes the rest; nothing else is trimmed and an embedded NUL does not end
/// the string. The whole field must be inside the data. The advancing forms
/// move past the whole field.
impl BinaryReader<'_> {
    /// Reads a string of `unit_count` code units at `index` in `charset`
    /// (Ghidra's `readString(index, charCount, charset, charLen)`).
    pub fn read_fixed_string_at(
        &self,
        index: u64,
        unit_count: usize,
        charset: Charset,
    ) -> Result<String> {
        let unit = charset.unit_len();
        let len = unit_count
            .checked_mul(unit)
            .ok_or(BinError::InvalidElementCount {
                offset: index,
                count: unit_count as u64,
                element_size: unit,
            })?;
        let bytes = self.read_bytes_at(index, len)?;
        let kept = len_without_trailing_nuls(&bytes, unit);
        Ok(charset.decode(bytes.get(..kept).unwrap_or_default()))
    }

    /// Reads a string of `unit_count` code units at the position in
    /// `charset` and advances past the field.
    pub fn read_fixed_string(&mut self, unit_count: usize, charset: Charset) -> Result<String> {
        let text = self.read_fixed_string_at(self.position(), unit_count, charset)?;
        self.skip((unit_count * charset.unit_len()) as u64);
        Ok(text)
    }

    /// Reads a US-ASCII string of `len` bytes at `index`.
    pub fn read_ascii_fixed_at(&self, index: u64, len: usize) -> Result<String> {
        self.read_fixed_string_at(index, len, Charset::Ascii)
    }

    /// Reads a US-ASCII string of `len` bytes at the position and advances
    /// past the field.
    pub fn read_ascii_fixed(&mut self, len: usize) -> Result<String> {
        self.read_fixed_string(len, Charset::Ascii)
    }

    /// Reads a UTF-8 string of `len` bytes at `index`.
    pub fn read_utf8_fixed_at(&self, index: u64, len: usize) -> Result<String> {
        self.read_fixed_string_at(index, len, Charset::Utf8)
    }

    /// Reads a UTF-8 string of `len` bytes at the position and advances past
    /// the field.
    pub fn read_utf8_fixed(&mut self, len: usize) -> Result<String> {
        self.read_fixed_string(len, Charset::Utf8)
    }

    /// Reads a UTF-16 string of `unit_count` two-byte units at `index`, in
    /// the reader's byte order.
    pub fn read_utf16_fixed_at(&self, index: u64, unit_count: usize) -> Result<String> {
        self.read_fixed_string_at(index, unit_count, Charset::utf16(self.endian()))
    }

    /// Reads a UTF-16 string of `unit_count` two-byte units at the position,
    /// in the reader's byte order, and advances past the field.
    pub fn read_utf16_fixed(&mut self, unit_count: usize) -> Result<String> {
        self.read_fixed_string(unit_count, Charset::utf16(self.endian()))
    }

    /// Reads a UTF-32 string of `unit_count` four-byte units at `index`, in
    /// the reader's byte order.
    pub fn read_utf32_fixed_at(&self, index: u64, unit_count: usize) -> Result<String> {
        self.read_fixed_string_at(index, unit_count, Charset::utf32(self.endian()))
    }

    /// Reads a UTF-32 string of `unit_count` four-byte units at the
    /// position, in the reader's byte order, and advances past the field.
    pub fn read_utf32_fixed(&mut self, unit_count: usize) -> Result<String> {
        self.read_fixed_string(unit_count, Charset::utf32(self.endian()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FillProvider, MemoryProvider, SubProvider, UnlimitedProvider};

    /// A provider that hides that its bytes are in memory, to force the
    /// reader's slow path.
    #[derive(Debug)]
    struct Opaque(MemoryProvider);

    impl crate::ByteProvider for Opaque {
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.0.read_into(offset, buf)
        }
    }

    #[test]
    fn charset_properties() {
        assert_eq!(Charset::utf16(Endian::Little), Charset::Utf16Le);
        assert_eq!(Charset::utf16(Endian::Big), Charset::Utf16Be);
        assert_eq!(Charset::utf32(Endian::Little), Charset::Utf32Le);
        assert_eq!(Charset::utf32(Endian::Big), Charset::Utf32Be);
        assert_eq!(Charset::Ascii.unit_len(), 1);
        assert_eq!(Charset::Latin1.unit_len(), 1);
        assert_eq!(Charset::Utf8.unit_len(), 1);
        assert_eq!(Charset::Utf16Be.unit_len(), 2);
        assert_eq!(Charset::Utf32Le.unit_len(), 4);
    }

    #[test]
    fn decoding_replaces_malformed_input() {
        assert_eq!(Charset::Ascii.decode(b"a\x80b\xff"), "a\u{fffd}b\u{fffd}");
        assert_eq!(Charset::Latin1.decode(b"a\xe9"), "a\u{e9}");
        assert_eq!(Charset::Utf8.decode(b"\xea\xa9A"), "\u{fffd}A");
        // An unpaired high surrogate, then 'A'.
        assert_eq!(Charset::Utf16Le.decode(&[0x00, 0xd8, b'A', 0]), "\u{fffd}A");
        // A valid surrogate pair (U+1F600) in both byte orders.
        assert_eq!(
            Charset::Utf16Le.decode(&[0x3d, 0xd8, 0x00, 0xde]),
            "\u{1f600}"
        );
        assert_eq!(
            Charset::Utf16Be.decode(&[0xd8, 0x3d, 0xde, 0x00]),
            "\u{1f600}"
        );
        // A dangling odd byte.
        assert_eq!(Charset::Utf16Be.decode(&[0, b'A', 0]), "A\u{fffd}");
        assert_eq!(
            Charset::Utf32Le.decode(&[0x00, 0xf6, 0x01, 0x00]),
            "\u{1f600}"
        );
        assert_eq!(
            Charset::Utf32Be.decode(&[0x00, 0x01, 0xf6, 0x00]),
            "\u{1f600}"
        );
        // Out of range, a surrogate code point, and dangling bytes.
        assert_eq!(
            Charset::Utf32Be.decode(&[0x00, 0x11, 0x00, 0x00]),
            "\u{fffd}"
        );
        assert_eq!(
            Charset::Utf32Be.decode(&[0x00, 0x00, 0xd8, 0x00, 1, 2]),
            "\u{fffd}\u{fffd}"
        );
        assert_eq!(Charset::Utf8.decode(b""), "");
    }

    #[test]
    fn trailing_nul_trimming() {
        assert_eq!(len_without_trailing_nuls(b"ab\0\0", 1), 2);
        assert_eq!(
            len_without_trailing_nuls(b"a\0b\0", 1),
            3,
            "embedded NULs stay"
        );
        assert_eq!(len_without_trailing_nuls(b"\0\0", 1), 0);
        assert_eq!(len_without_trailing_nuls(b"", 1), 0);
        assert_eq!(len_without_trailing_nuls(&[0, b'A', 0, 0, 0, 0], 2), 2);
        // A zero byte that is half of a non-zero unit is not padding.
        assert_eq!(len_without_trailing_nuls(&[b'A', 0, 0, 1], 2), 4);
    }

    #[test]
    fn terminator_search_respects_unit_boundaries() {
        assert_eq!(find_terminator(b"ab\0c", 1), Some(2));
        assert_eq!(find_terminator(b"abc", 1), None);
        // The zero pair straddling two units (…'A',0 | 0,'B'…) is not a terminator.
        assert_eq!(find_terminator(&[b'A', 0, 0, b'B', 0, 0], 2), Some(4));
        assert_eq!(find_terminator(&[1, 0, 0, 0, 0, 0, 0, 0, 9], 4), Some(4));
        assert_eq!(find_terminator(&[1, 0, 0, 0, 0, 0, 0], 4), None);
    }

    #[test]
    fn terminated_utf32() {
        let bytes = [b'A', 0, 0, 0, 0x00, 0xf6, 0x01, 0, 0, 0, 0, 0, 42];
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        assert_eq!(r.read_utf32_at(0).unwrap(), "A\u{1f600}");
        assert_eq!(r.read_utf32().unwrap(), "A\u{1f600}");
        assert_eq!(r.read_u8().unwrap(), 42);
        assert_eq!(r.read_utf32_fixed_at(0, 3).unwrap(), "A\u{1f600}");
        r.set_position(0);
        assert_eq!(r.read_utf32_fixed(2).unwrap(), "A\u{1f600}");
        assert_eq!(r.position(), 8);
        assert!(r.read_utf32_at(12).unwrap_err().is_eof());
    }

    #[test]
    fn explicit_charsets() {
        let bytes = [0, b'A', 0, b'B', 0, 0, 0xe9, 0];
        let r = BinaryReader::from_slice(&bytes, Endian::Little);
        // Big-endian UTF-16 through a little-endian reader.
        assert_eq!(r.read_string_at(0, Charset::Utf16Be).unwrap(), "AB");
        assert_eq!(
            r.read_fixed_string_at(0, 3, Charset::Utf16Be).unwrap(),
            "AB"
        );
        assert_eq!(r.read_string_at(6, Charset::Latin1).unwrap(), "\u{e9}");
        assert_eq!(r.read_string_at(6, Charset::Ascii).unwrap(), "\u{fffd}");
    }

    #[test]
    fn raw_terminated_bytes_borrow_from_memory() {
        let provider = MemoryProvider::new(b"one\0two\0".to_vec());
        let r = BinaryReader::new(&provider, Endian::Little);
        let bytes = r.read_terminated_bytes_at(4, 1).unwrap();
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(&*bytes, b"two");
        assert!(r.read_terminated_bytes_at(7, 1).unwrap().is_empty());
        // A unit length of zero is treated as one.
        assert_eq!(&*r.read_terminated_bytes_at(0, 0).unwrap(), b"one");
    }

    #[test]
    fn slow_path_matches_fast_path() {
        // A string long enough to span several blocks, read through a
        // provider that is not in memory.
        let mut data = vec![b'x'; 1000];
        data.push(0);
        data.extend_from_slice(b"tail");
        let memory = MemoryProvider::new(data.clone());
        let fast = BinaryReader::new(&memory, Endian::Little);
        let opaque = Opaque(memory.clone());
        let slow = BinaryReader::new(&opaque, Endian::Little);
        assert!(slow.as_slice().is_none());
        for index in [0u64, 1, 936, 937, 999, 1000] {
            assert_eq!(
                slow.read_ascii_at(index).unwrap(),
                fast.read_ascii_at(index).unwrap()
            );
        }
        for index in [1001u64, 1004] {
            let (a, b) = (
                slow.read_ascii_at(index).unwrap_err(),
                fast.read_ascii_at(index).unwrap_err(),
            );
            assert!(
                matches!(a, BinError::UnterminatedString { start, end: 1005 } if start == index),
                "{a}"
            );
            assert!(
                matches!(b, BinError::UnterminatedString { start, end: 1005 } if start == index),
                "{b}"
            );
        }
        for index in [1005u64, 2000] {
            assert!(
                matches!(slow.read_ascii_at(index), Err(BinError::StringAtEof { offset }) if offset == index)
            );
            assert!(
                matches!(fast.read_ascii_at(index), Err(BinError::StringAtEof { offset }) if offset == index)
            );
        }
        let wide = SubProvider::new(&opaque, 0, 1000);
        let r = BinaryReader::new(&wide, Endian::Little);
        assert!(matches!(
            r.read_utf16_at(0),
            Err(BinError::UnterminatedString {
                start: 0,
                end: 1000
            })
        ));
    }

    #[test]
    fn zero_padded_provider_terminates_at_the_end() {
        let memory = MemoryProvider::new(b"abc".to_vec());
        let unlimited = UnlimitedProvider::new(&memory);
        let mut r = BinaryReader::new(&unlimited, Endian::Little);
        assert_eq!(r.read_utf8_at(1).unwrap(), "bc");
        assert_eq!(r.read_utf8_at(3).unwrap(), "");
        assert_eq!(r.read_utf8_at(1 << 40).unwrap(), "");
        assert_eq!(r.read_ascii().unwrap(), "abc");
        assert_eq!(r.position(), 4);
    }

    #[test]
    fn run_on_strings_are_cut_off() {
        // Checked with a provider that never ends and never yields a NUL; the
        // limit is lowered by starting close to it would take too long, so
        // only the at-or-past-the-end rule is asserted on a huge provider.
        let fill = FillProvider::new(8, b'x');
        let r = BinaryReader::new(&fill, Endian::Little);
        assert!(matches!(
            r.read_ascii_at(0),
            Err(BinError::UnterminatedString { start: 0, end: 8 })
        ));
        assert!(matches!(
            r.read_ascii_at(8),
            Err(BinError::StringAtEof { offset: 8 })
        ));
        assert!(matches!(
            r.read_ascii_at(u64::MAX),
            Err(BinError::StringAtEof { .. })
        ));
    }

    #[test]
    fn fixed_length_edge_cases() {
        let bytes = *b"ab\0\0cd";
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        assert_eq!(r.read_ascii_fixed_at(0, 0).unwrap(), "");
        assert_eq!(r.read_ascii_fixed_at(6, 0).unwrap(), "");
        assert!(r.read_ascii_fixed_at(7, 0).is_err());
        assert_eq!(
            r.read_ascii_fixed_at(0, 6).unwrap(),
            "ab\0\0cd",
            "embedded NULs are kept"
        );
        assert!(
            r.read_ascii_fixed_at(0, 7).is_err(),
            "the whole field must be readable"
        );
        assert!(r.read_utf16_fixed_at(0, 4).is_err());
        assert!(matches!(
            r.read_utf32_fixed_at(0, usize::MAX),
            Err(BinError::InvalidElementCount { .. })
        ));
        assert_eq!(r.read_utf8_fixed(4).unwrap(), "ab");
        assert_eq!(r.position(), 4);
        assert!(r.read_utf8_fixed(3).is_err());
        assert_eq!(r.position(), 4);
        assert_eq!(r.read_utf8_fixed_at(4, 2).unwrap(), "cd");
    }
}
