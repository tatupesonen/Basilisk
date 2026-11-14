//! Integer and array reads.

use std::borrow::Cow;

use crate::endian::Endian;
use crate::error::{BinError, Result};
use crate::reader::cursor::BinaryReader;

/// The largest number of elements one array read may ask for: Ghidra's
/// `MAX_SANE_ARRAY_ELEMENT_COUNT` (2³¹ − 1025). A larger count is always an
/// error, whatever the size of the provider.
pub const MAX_ARRAY_ELEMENTS: usize = i32::MAX as usize - 1024;

macro_rules! fixed_width_reads {
    ($($ty:ty, $size:literal, $read:ident, $read_at:ident, $peek:ident;)+) => {
        /// Fixed-width integers. The signed and unsigned forms replace
        /// Ghidra's `readX`/`readUnsignedX`; the `peek_` forms are its
        /// `peekNextX`.
        impl BinaryReader<'_> {$(
            #[doc = concat!("Reads the `", stringify!($ty), "` at `index`.")]
            pub fn $read_at(&self, index: u64) -> Result<$ty> {
                let bytes = self.read_array_at::<$size>(index)?;
                Ok(match self.endian() {
                    Endian::Little => <$ty>::from_le_bytes(bytes),
                    Endian::Big => <$ty>::from_be_bytes(bytes),
                })
            }

            #[doc = concat!("Reads the `", stringify!($ty), "` at the position and advances past it.")]
            pub fn $read(&mut self) -> Result<$ty> {
                let value = self.$read_at(self.position())?;
                self.skip($size);
                Ok(value)
            }

            #[doc = concat!("Reads the `", stringify!($ty), "` at the position without advancing.")]
            pub fn $peek(&self) -> Result<$ty> {
                self.$read_at(self.position())
            }
        )+}
    };
}

fixed_width_reads! {
    u8, 1, read_u8, read_u8_at, peek_u8;
    i8, 1, read_i8, read_i8_at, peek_i8;
    u16, 2, read_u16, read_u16_at, peek_u16;
    i16, 2, read_i16, read_i16_at, peek_i16;
    u32, 4, read_u32, read_u32_at, peek_u32;
    i32, 4, read_i32, read_i32_at, peek_i32;
    u64, 8, read_u64, read_u64_at, peek_u64;
    i64, 8, read_i64, read_i64_at, peek_i64;
}

macro_rules! array_reads {
    ($($ty:ty, $size:literal, $read:ident, $read_at:ident;)+) => {
        /// Arrays of fixed-width integers. The element count is checked
        /// against [`MAX_ARRAY_ELEMENTS`] and the provider's bounds before
        /// anything is allocated.
        impl BinaryReader<'_> {$(
            #[doc = concat!("Reads `count` `", stringify!($ty), "` values starting at `index`.")]
            pub fn $read_at(&self, index: u64, count: usize) -> Result<Vec<$ty>> {
                let bytes = self.array_bytes_at(index, count, $size)?;
                let (chunks, _) = bytes.as_chunks::<$size>();
                let endian = self.endian();
                Ok(chunks
                    .iter()
                    .map(|chunk| match endian {
                        Endian::Little => <$ty>::from_le_bytes(*chunk),
                        Endian::Big => <$ty>::from_be_bytes(*chunk),
                    })
                    .collect())
            }

            #[doc = concat!(
                "Reads `count` `", stringify!($ty),
                "` values at the position and advances past them."
            )]
            pub fn $read(&mut self, count: usize) -> Result<Vec<$ty>> {
                let values = self.$read_at(self.position(), count)?;
                self.skip(count as u64 * $size);
                Ok(values)
            }
        )+}
    };
}

array_reads! {
    u16, 2, read_u16_array, read_u16_array_at;
    i16, 2, read_i16_array, read_i16_array_at;
    u32, 4, read_u32_array, read_u32_array_at;
    i32, 4, read_i32_array, read_i32_array_at;
    u64, 8, read_u64_array, read_u64_array_at;
    i64, 8, read_i64_array, read_i64_array_at;
}

impl<'a> BinaryReader<'a> {
    /// Reads `count` bytes at `index` (Ghidra's `readByteArray`).
    ///
    /// The bytes are borrowed when the data is in memory and copied into a
    /// new buffer otherwise. The count is checked against
    /// [`MAX_ARRAY_ELEMENTS`] and the provider's bounds before anything is
    /// allocated.
    pub fn read_bytes_at(&self, index: u64, count: usize) -> Result<Cow<'a, [u8]>> {
        self.array_bytes_at(index, count, 1)
    }

    /// Reads `count` bytes at the position and advances past them.
    pub fn read_bytes(&mut self, count: usize) -> Result<Cow<'a, [u8]>> {
        let bytes = self.read_bytes_at(self.position(), count)?;
        self.skip(count as u64);
        Ok(bytes)
    }

    /// The bytes of an array of `count` elements of `element_size` bytes at
    /// `index`, after Ghidra's `ensureArrayRead` checks.
    pub(crate) fn array_bytes_at(
        &self,
        index: u64,
        count: usize,
        element_size: usize,
    ) -> Result<Cow<'a, [u8]>> {
        let invalid = || BinError::InvalidElementCount {
            offset: index,
            count: count as u64,
            element_size,
        };
        if count > MAX_ARRAY_ELEMENTS {
            return Err(invalid());
        }
        let len = count.checked_mul(element_size).ok_or_else(invalid)?;
        if !self.is_valid_range(index, len as u64) {
            return Err(BinError::out_of_bounds(index, len as u64, self.len()));
        }
        self.raw_bytes_at(index, len)
    }

    /// Reads an unsigned integer of `len` bytes (1 to 8) at `index`
    /// (Ghidra's `readUnsignedValue`).
    pub fn read_uint_at(&self, index: u64, len: usize) -> Result<u64> {
        let mut buf = [0u8; 8];
        let invalid = BinError::InvalidValueLength { len };
        if len == 0 {
            return Err(invalid);
        }
        match self.endian() {
            Endian::Little => {
                self.read_exact_at(index, buf.get_mut(..len).ok_or(invalid)?)?;
                Ok(u64::from_le_bytes(buf))
            }
            Endian::Big => {
                let start = 8usize.checked_sub(len).ok_or(invalid)?;
                self.read_exact_at(index, buf.get_mut(start..).unwrap_or_default())?;
                Ok(u64::from_be_bytes(buf))
            }
        }
    }

    /// Reads a signed integer of `len` bytes (1 to 8) at `index`, sign
    /// extended to 64 bits (Ghidra's `readValue`).
    pub fn read_sint_at(&self, index: u64, len: usize) -> Result<i64> {
        let value = self.read_uint_at(index, len)?;
        // `len` is 1..=8 here, so the shift is 0..=56.
        let shift = 64 - 8 * len as u32;
        Ok(((value << shift) as i64) >> shift)
    }

    /// Reads an unsigned integer of `len` bytes (1 to 8) at the position and
    /// advances past it.
    pub fn read_uint(&mut self, len: usize) -> Result<u64> {
        let value = self.read_uint_at(self.position(), len)?;
        self.skip(len as u64);
        Ok(value)
    }

    /// Reads a signed integer of `len` bytes (1 to 8) at the position and
    /// advances past it.
    pub fn read_sint(&mut self, len: usize) -> Result<i64> {
        let value = self.read_sint_at(self.position(), len)?;
        self.skip(len as u64);
        Ok(value)
    }

    /// Reads a `u32` that is going to be used as a count or a length, and
    /// rejects values above `i32::MAX` (Ghidra's `readNextUnsignedIntExact`).
    ///
    /// The position advances past the value even when it is rejected.
    pub fn read_u32_count(&mut self) -> Result<usize> {
        let value = self.read_u32()?;
        usize::try_from(value)
            .ok()
            .filter(|_| i32::try_from(value).is_ok())
            .ok_or_else(|| BinError::ValueOutOfRange {
                value: i128::from(value),
                target: "a count (0..=i32::MAX)",
            })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::{FillProvider, MemoryProvider};

    const BYTES: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    #[test]
    fn fixed_width_in_both_orders() {
        let le = BinaryReader::from_slice(&BYTES, Endian::Little);
        let be = le.as_big_endian();
        assert_eq!(le.read_u8_at(4).unwrap(), 0x89);
        assert_eq!(le.read_i8_at(4).unwrap(), -0x77);
        assert_eq!(le.read_u16_at(0).unwrap(), 0x2301);
        assert_eq!(be.read_u16_at(0).unwrap(), 0x0123);
        assert_eq!(le.read_i16_at(6).unwrap(), 0xefcd_u16 as i16);
        assert_eq!(be.read_i16_at(6).unwrap(), 0xcdef_u16 as i16);
        assert_eq!(le.read_u32_at(0).unwrap(), 0x6745_2301);
        assert_eq!(be.read_u32_at(0).unwrap(), 0x0123_4567);
        assert_eq!(le.read_i32_at(4).unwrap(), 0xefcd_ab89_u32 as i32);
        assert_eq!(be.read_i32_at(4).unwrap(), 0x89ab_cdef_u32 as i32);
        assert_eq!(le.read_u64_at(0).unwrap(), 0xefcd_ab89_6745_2301);
        assert_eq!(be.read_u64_at(0).unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(le.read_i64_at(0).unwrap(), 0xefcd_ab89_6745_2301_u64 as i64);
        assert_eq!(be.read_i64_at(0).unwrap(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn next_forms_advance_and_peeks_do_not() {
        let mut r = BinaryReader::from_slice(&BYTES, Endian::Big);
        assert_eq!(r.peek_u8().unwrap(), 0x01);
        assert_eq!(r.peek_i8().unwrap(), 0x01);
        assert_eq!(r.peek_u16().unwrap(), 0x0123);
        assert_eq!(r.peek_i16().unwrap(), 0x0123);
        assert_eq!(r.peek_u32().unwrap(), 0x0123_4567);
        assert_eq!(r.peek_i32().unwrap(), 0x0123_4567);
        assert_eq!(r.peek_u64().unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(r.peek_i64().unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(r.position(), 0);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_i8().unwrap(), 0x23);
        assert_eq!(r.read_u16().unwrap(), 0x4567);
        assert_eq!(r.read_i32().unwrap(), 0x89ab_cdef_u32 as i32);
        assert_eq!(r.position(), 8);
        assert!(r.peek_u8().is_err());
        r.set_position(0);
        assert_eq!(r.read_i16().unwrap(), 0x0123);
        assert_eq!(r.read_u32().unwrap(), 0x4567_89ab);
        r.set_position(0);
        assert_eq!(r.read_u64().unwrap(), 0x0123_4567_89ab_cdef);
        r.set_position(0);
        assert_eq!(r.read_i64().unwrap(), 0x0123_4567_89ab_cdef);
        // A read that does not fit leaves the position where it was.
        r.set_position(5);
        assert!(r.read_u32().is_err());
        assert_eq!(r.position(), 5);
    }

    #[rstest]
    #[case(1, 0x01, 0x01)]
    #[case(2, 0x2301, 0x0123)]
    #[case(3, 0x45_2301, 0x01_2345)]
    #[case(4, 0x6745_2301, 0x0123_4567)]
    #[case(5, 0x89_6745_2301, 0x01_2345_6789)]
    #[case(6, 0xab89_6745_2301, 0x0123_4567_89ab)]
    #[case(7, 0xcd_ab89_6745_2301, 0x01_2345_6789_abcd)]
    #[case(8, 0xefcd_ab89_6745_2301, 0x0123_4567_89ab_cdef)]
    fn unsigned_values_of_any_length(#[case] len: usize, #[case] le: u64, #[case] be: u64) {
        let r = BinaryReader::from_slice(&BYTES, Endian::Little);
        assert_eq!(r.read_uint_at(0, len).unwrap(), le);
        assert_eq!(r.as_big_endian().read_uint_at(0, len).unwrap(), be);
    }

    #[test]
    fn signed_values_are_sign_extended() {
        let bytes = [0xff, 0xfe, 0x7f, 0x80, 0x00];
        let le = BinaryReader::from_slice(&bytes, Endian::Little);
        let be = le.as_big_endian();
        assert_eq!(le.read_sint_at(0, 1).unwrap(), -1);
        assert_eq!(le.read_sint_at(0, 2).unwrap(), -257);
        assert_eq!(be.read_sint_at(0, 2).unwrap(), -2);
        assert_eq!(le.read_sint_at(0, 3).unwrap(), 0x7f_feff);
        assert_eq!(be.read_sint_at(0, 3).unwrap(), -385);
        assert_eq!(le.read_sint_at(2, 2).unwrap(), -32641);
        assert_eq!(be.read_sint_at(3, 2).unwrap(), -32768);
        assert_eq!(le.read_uint_at(3, 1).unwrap(), 0x80);
        let all = [0xffu8; 8];
        let r = BinaryReader::from_slice(&all, Endian::Big);
        assert_eq!(r.read_sint_at(0, 8).unwrap(), -1);
        assert_eq!(r.read_uint_at(0, 8).unwrap(), u64::MAX);
    }

    #[test]
    fn value_length_must_be_one_to_eight() {
        let data = [0u8; 16];
        for endian in [Endian::Little, Endian::Big] {
            let mut r = BinaryReader::from_slice(&data, endian);
            for len in [0usize, 9, 100] {
                assert!(matches!(
                    r.read_uint_at(0, len),
                    Err(BinError::InvalidValueLength { len: l }) if l == len
                ));
                assert!(r.read_sint_at(0, len).is_err());
                assert!(r.read_uint(len).is_err());
                assert!(r.read_sint(len).is_err());
                assert_eq!(r.position(), 0);
            }
        }
    }

    #[test]
    fn next_values_advance() {
        let mut r = BinaryReader::from_slice(&BYTES, Endian::Little);
        assert_eq!(r.read_uint(3).unwrap(), 0x45_2301);
        assert_eq!(r.read_sint(1).unwrap(), 0x67);
        assert_eq!(r.read_sint(4).unwrap(), i64::from(0xefcd_ab89_u32 as i32));
        assert_eq!(r.position(), 8);
        assert!(r.read_uint(1).is_err());
    }

    #[test]
    fn arrays() {
        let mut r = BinaryReader::from_slice(&BYTES, Endian::Little);
        assert_eq!(
            r.read_u16_array_at(0, 4).unwrap(),
            [0x2301, 0x6745, 0xab89, 0xefcd]
        );
        assert_eq!(
            r.as_big_endian().read_u16_array_at(2, 2).unwrap(),
            [0x4567, 0x89ab]
        );
        assert_eq!(r.read_i16_array_at(6, 1).unwrap(), [0xefcd_u16 as i16]);
        assert_eq!(
            r.read_u32_array_at(0, 2).unwrap(),
            [0x6745_2301, 0xefcd_ab89]
        );
        assert_eq!(r.read_i32_array_at(4, 1).unwrap(), [0xefcd_ab89_u32 as i32]);
        assert_eq!(r.read_u64_array_at(0, 1).unwrap(), [0xefcd_ab89_6745_2301]);
        assert_eq!(
            r.read_i64_array_at(0, 1).unwrap(),
            [0xefcd_ab89_6745_2301_u64 as i64]
        );
        assert_eq!(r.read_u16_array_at(8, 0).unwrap(), []);
        assert!(r.read_u16_array_at(7, 1).is_err());
        assert!(r.read_u64_array_at(1, 1).is_err());

        assert_eq!(r.read_u16_array(1).unwrap(), [0x2301]);
        assert_eq!(r.read_i16_array(1).unwrap(), [0x6745]);
        assert_eq!(r.position(), 4);
        assert_eq!(r.read_u32_array(1).unwrap(), [0xefcd_ab89]);
        assert!(r.read_i32_array(1).is_err());
        assert_eq!(r.position(), 8);
        r.set_position(0);
        assert_eq!(r.read_u64_array(1).unwrap().len(), 1);
        r.set_position(0);
        assert_eq!(r.read_i64_array(1).unwrap().len(), 1);
    }

    #[test]
    fn byte_arrays_borrow_from_memory_and_copy_otherwise() {
        let provider = MemoryProvider::new(BYTES.to_vec());
        let mut r = BinaryReader::new(&provider, Endian::Little);
        let bytes = r.read_bytes(3).unwrap();
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(&*bytes, &BYTES[..3]);
        assert_eq!(r.position(), 3);
        assert!(r.read_bytes(6).is_err());
        assert_eq!(r.position(), 3);
        assert!(r.read_bytes_at(8, 0).unwrap().is_empty());

        let fill = FillProvider::new(16, 0x5a);
        let r = BinaryReader::new(&fill, Endian::Little);
        let bytes = r.read_bytes_at(4, 4).unwrap();
        assert!(matches!(bytes, Cow::Owned(_)));
        assert_eq!(&*bytes, &[0x5a; 4]);
        assert_eq!(r.read_u16_array_at(0, 8).unwrap(), [0x5a5a; 8]);
    }

    #[test]
    fn oversized_arrays_are_rejected_before_allocating() {
        let fill = FillProvider::new(u64::from(u32::MAX) * 100, 0xaa);
        let mut r = BinaryReader::new(&fill, Endian::Little);
        let count = i32::MAX as usize - 10;
        assert!(matches!(
            r.read_bytes(count),
            Err(BinError::InvalidElementCount { .. })
        ));
        assert!(matches!(
            r.read_u64_array(count),
            Err(BinError::InvalidElementCount { .. })
        ));
        assert!(matches!(
            r.read_bytes_at(0, usize::MAX),
            Err(BinError::InvalidElementCount { .. })
        ));
        // Within the element limit but outside a small provider.
        let small = BinaryReader::from_slice(&BYTES, Endian::Little);
        assert!(matches!(
            small.read_u64_array_at(0, MAX_ARRAY_ELEMENTS),
            Err(BinError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn counts_above_i32_max_are_rejected() {
        let mut r = BinaryReader::from_slice(
            &[0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80],
            Endian::Little,
        );
        assert_eq!(r.read_u32_count().unwrap(), i32::MAX as usize);
        let err = r.read_u32_count().unwrap_err();
        assert!(
            matches!(
                err,
                BinError::ValueOutOfRange {
                    value: 0x8000_0000,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(r.position(), 8);
        assert!(r.read_u32_count().is_err());
    }
}
