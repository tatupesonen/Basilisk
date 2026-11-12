//! Property tests for the reader and the providers: integers and LEB128
//! round-trip, the provider-backed path agrees with the slice path, and no
//! input makes any read panic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use std::borrow::Cow;

use bk_bin::leb128;
use bk_bin::{
    BinaryReader, ByteProvider, Charset, Endian, MemoryProvider, RangeMappedProvider, Result,
    SubProvider, UnlimitedProvider,
};
use proptest::prelude::*;

/// A provider that does not expose its bytes as a slice, so the reader has
/// to go through `read_into`.
#[derive(Debug)]
struct Opaque(Vec<u8>);

impl ByteProvider for Opaque {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        MemoryProvider::new(&self.0[..]).read_into(offset, buf)
    }
}

fn endian() -> impl Strategy<Value = Endian> {
    prop_oneof![Just(Endian::Little), Just(Endian::Big)]
}

const CHARSETS: [Charset; 7] = [
    Charset::Ascii,
    Charset::Latin1,
    Charset::Utf8,
    Charset::Utf16Le,
    Charset::Utf16Be,
    Charset::Utf32Le,
    Charset::Utf32Be,
];

proptest! {
    #[test]
    fn integers_round_trip(value: u64, endian in endian(), pad in 0usize..4) {
        let mut bytes = vec![0xa5u8; pad];
        bytes.extend(match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        });
        let at = pad as u64;
        let r = BinaryReader::from_slice(&bytes, endian);
        prop_assert_eq!(r.read_u64_at(at).unwrap(), value);
        prop_assert_eq!(r.read_i64_at(at).unwrap(), value as i64);
        // Narrower reads see the low or the high part, depending on the order.
        let (lo32, hi32) = (value as u32, (value >> 32) as u32);
        let first32 = if endian == Endian::Little { lo32 } else { hi32 };
        prop_assert_eq!(r.read_u32_at(at).unwrap(), first32);
        prop_assert_eq!(r.read_i32_at(at).unwrap(), first32 as i32);
        let first16 = if endian == Endian::Little { value as u16 } else { (value >> 48) as u16 };
        prop_assert_eq!(r.read_u16_at(at).unwrap(), first16);
        prop_assert_eq!(r.read_i16_at(at).unwrap(), first16 as i16);
        prop_assert_eq!(r.read_u8_at(at).unwrap(), bytes[pad]);
    }

    #[test]
    fn sized_values_round_trip(value: u64, len in 1usize..=8, endian in endian()) {
        let masked = if len == 8 { value } else { value & ((1u64 << (8 * len)) - 1) };
        let bytes: Vec<u8> = match endian {
            Endian::Little => masked.to_le_bytes()[..len].to_vec(),
            Endian::Big => masked.to_be_bytes()[8 - len..].to_vec(),
        };
        let mut r = BinaryReader::from_slice(&bytes, endian);
        prop_assert_eq!(r.read_uint_at(0, len).unwrap(), masked);
        let shift = 64 - 8 * len as u32;
        prop_assert_eq!(r.read_sint_at(0, len).unwrap(), ((masked << shift) as i64) >> shift);
        prop_assert_eq!(r.read_uint(len).unwrap(), masked);
        prop_assert!(!r.has_next());
    }

    #[test]
    fn arrays_match_single_reads(bytes in prop::collection::vec(any::<u8>(), 0..64), endian in endian()) {
        let r = BinaryReader::from_slice(&bytes, endian);
        let count = bytes.len() / 4;
        let array = r.read_u32_array_at(0, count).unwrap();
        for (i, &value) in array.iter().enumerate() {
            prop_assert_eq!(value, r.read_u32_at(4 * i as u64).unwrap());
        }
        prop_assert!(r.read_u32_array_at(0, count + 1).is_err());
    }

    #[test]
    fn leb128_unsigned_round_trips(value: u64, trailing in prop::collection::vec(any::<u8>(), 0..4)) {
        let mut bytes = Vec::new();
        let len = leb128::encode_unsigned(value, &mut bytes);
        prop_assert!((1..=leb128::MAX_LEN).contains(&len));
        prop_assert_eq!(leb128::encoded_len(&bytes), Some(len));
        bytes.extend(&trailing);
        prop_assert_eq!(leb128::decode_unsigned(&bytes), Ok((value, len)));
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        let info = r.read_uleb128_info().unwrap();
        prop_assert_eq!((info.as_u64(), info.len(), info.offset()), (value, len, 0));
        prop_assert_eq!(r.position(), len as u64);
    }

    #[test]
    fn leb128_signed_round_trips(value: i64, trailing in prop::collection::vec(any::<u8>(), 0..4)) {
        let mut bytes = Vec::new();
        let len = leb128::encode_signed(value, &mut bytes);
        prop_assert!((1..=leb128::MAX_LEN).contains(&len));
        bytes.extend(&trailing);
        prop_assert_eq!(leb128::decode_signed(&bytes), Ok((value, len)));
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        prop_assert_eq!(r.read_sleb128().unwrap(), value);
        prop_assert_eq!(r.position(), len as u64);
    }

    #[test]
    fn leb128_decoding_never_panics_and_agrees_with_the_reader(
        bytes in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        for signed in [false, true] {
            let direct = if signed {
                leb128::decode_signed(&bytes).map(|(v, n)| (v as u64, n))
            } else {
                leb128::decode_unsigned(&bytes)
            };
            let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
            let through_reader =
                if signed { r.read_sleb128().map(|v| v as u64) } else { r.read_uleb128() };
            match direct {
                Ok((value, len)) => {
                    prop_assert_eq!(through_reader.unwrap(), value);
                    prop_assert_eq!(r.position(), len as u64);
                    prop_assert!(len <= leb128::MAX_LEN);
                }
                Err(e) => {
                    prop_assert!(through_reader.is_err());
                    let consumed = match e {
                        leb128::DecodeError::Truncated { consumed }
                        | leb128::DecodeError::TooLarge { consumed } => consumed,
                    };
                    prop_assert_eq!(r.position(), consumed as u64);
                }
            }
        }
    }

    /// The slice fast path and the provider slow path must give the same
    /// answer — value or kind of error — for every read at every index.
    #[test]
    fn provider_path_agrees_with_slice_path(
        bytes in prop::collection::vec(prop_oneof![3 => Just(0u8), 5 => any::<u8>()], 0..48),
        index in 0u64..56,
        count in 0usize..12,
        endian in endian(),
    ) {
        let opaque = Opaque(bytes.clone());
        let fast = BinaryReader::from_slice(&bytes, endian);
        let slow = BinaryReader::new(&opaque, endian);
        prop_assert!(slow.as_slice().is_none());

        prop_assert_eq!(fast.read_u8_at(index).ok(), slow.read_u8_at(index).ok());
        prop_assert_eq!(fast.read_u16_at(index).ok(), slow.read_u16_at(index).ok());
        prop_assert_eq!(fast.read_u32_at(index).ok(), slow.read_u32_at(index).ok());
        prop_assert_eq!(fast.read_u64_at(index).ok(), slow.read_u64_at(index).ok());
        prop_assert_eq!(
            fast.read_bytes_at(index, count).ok().map(Cow::into_owned),
            slow.read_bytes_at(index, count).ok().map(Cow::into_owned)
        );
        prop_assert_eq!(
            fast.read_u16_array_at(index, count).ok(),
            slow.read_u16_array_at(index, count).ok()
        );
        if (1..=8).contains(&count) {
            prop_assert_eq!(fast.read_sint_at(index, count).ok(), slow.read_sint_at(index, count).ok());
        }
        for charset in CHARSETS {
            let (a, b) = (fast.read_string_at(index, charset), slow.read_string_at(index, charset));
            prop_assert_eq!(a.is_ok(), b.is_ok());
            match (a, b) {
                (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
                (Err(a), Err(b)) => prop_assert_eq!(a.to_string(), b.to_string()),
                _ => unreachable!(),
            }
            prop_assert_eq!(
                fast.read_fixed_string_at(index, count, charset).ok(),
                slow.read_fixed_string_at(index, count, charset).ok()
            );
            let (mut f, mut s) = (fast.at(index), slow.at(index));
            prop_assert_eq!(f.read_string(charset).ok(), s.read_string(charset).ok());
            prop_assert_eq!(f.position(), s.position());
        }
    }

    /// A terminated string is exactly the units before the first terminator,
    /// and the advancing form lands just past that terminator.
    #[test]
    fn terminated_strings_end_at_the_first_terminator(
        text in "[a-zA-Z0-9 \\t]{0,20}",
        rest in prop::collection::vec(any::<u8>(), 0..8),
        endian in endian(),
    ) {
        for charset in [Charset::Ascii, Charset::Utf8, Charset::utf16(endian), Charset::utf32(endian)] {
            let unit = charset.unit_len();
            let mut bytes: Vec<u8> = Vec::new();
            for c in text.chars() {
                let mut unit_bytes = (c as u32).to_le_bytes()[..unit].to_vec();
                if endian == Endian::Big {
                    unit_bytes.reverse();
                }
                bytes.extend(unit_bytes);
            }
            bytes.extend(std::iter::repeat_n(0u8, unit));
            bytes.extend(&rest);
            let mut r = BinaryReader::from_slice(&bytes, endian);
            prop_assert_eq!(r.read_string(charset).unwrap(), text.clone());
            prop_assert_eq!(r.position(), ((text.len() + 1) * unit) as u64);
            // Fixed-length: the field of the text plus its terminator trims to the text.
            prop_assert_eq!(
                r.read_fixed_string_at(0, text.len() + 1, charset).unwrap(),
                text.clone()
            );
        }
    }

    #[test]
    fn decoding_any_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        for charset in CHARSETS {
            let text = charset.decode(&bytes);
            // Every code unit yields at most one character.
            prop_assert!(text.chars().count() <= bytes.len());
        }
        prop_assert_eq!(Charset::Latin1.decode(&bytes).chars().count(), bytes.len());
    }

    /// Wrappers agree with a model computed directly from the bytes.
    #[test]
    fn wrappers_match_a_model(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
        sub_offset in 0u64..80,
        sub_len in 0u64..80,
        offset in 0u64..100,
        len in 0usize..40,
    ) {
        let base = MemoryProvider::new(bytes.clone());
        let end = offset + len as u64;

        let sub = SubProvider::new(&base, sub_offset, sub_len);
        let expected = (end <= sub_len && sub_offset + end <= bytes.len() as u64)
            .then(|| bytes[(sub_offset + offset) as usize..(sub_offset + end) as usize].to_vec());
        prop_assert_eq!(sub.read_bytes(offset, len).ok().map(Cow::into_owned), expected.clone());
        if len > 0 {
            prop_assert_eq!(sub.is_valid_range(offset, len as u64), expected.is_some());
        }

        let unlimited = UnlimitedProvider::new(&base);
        let padded: Vec<u8> =
            (offset..end).map(|i| bytes.get(i as usize).copied().unwrap_or(0)).collect();
        prop_assert_eq!(unlimited.read_bytes(offset, len).unwrap().into_owned(), padded);
    }

    #[test]
    fn range_mapped_matches_a_model(
        bytes in prop::collection::vec(any::<u8>(), 1..48),
        ranges in prop::collection::vec((prop::option::of(0u64..48), 1u64..12), 0..8),
        offset in 0u64..100,
        len in 0usize..40,
    ) {
        let base = MemoryProvider::new(bytes.clone());
        let mut mapped = RangeMappedProvider::new(&base);
        // The model: for each byte of the mapped provider, its value, or
        // None if the delegate cannot supply it.
        let mut model: Vec<Option<u8>> = Vec::new();
        for &(source, range_len) in &ranges {
            if let Some(start) = source {
                mapped.add_range(start, range_len);
                model.extend((start..start + range_len).map(|i| bytes.get(i as usize).copied()));
            } else {
                mapped.add_sparse_range(range_len);
                model.extend(std::iter::repeat_n(Some(0), range_len as usize));
            }
        }
        prop_assert_eq!(mapped.len(), model.len() as u64);
        prop_assert!(mapped.range_count() <= ranges.len());
        let end = offset as usize + len;
        let expected: Option<Vec<u8>> = (end <= model.len())
            .then(|| model[offset as usize..end].iter().copied().collect())
            .flatten();
        prop_assert_eq!(mapped.read_bytes(offset, len).ok().map(Cow::into_owned), expected);
    }
}
