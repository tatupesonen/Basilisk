//! The reader itself: source, position, byte order and raw byte access.

use std::borrow::Cow;

use crate::endian::Endian;
use crate::error::{BinError, Result};
use crate::provider::ByteProvider;

/// Reads integers, arrays and strings from a [`ByteProvider`] (or a plain
/// byte slice) in either byte order. This is Ghidra's `BinaryReader`.
///
/// Every kind of read comes in two forms:
///
/// * `read_x()` reads at the reader's position and advances it — Ghidra's
///   `readNextX()`;
/// * `read_x_at(index)` reads at an explicit index and leaves the position
///   alone — Ghidra's `readX(index)`.
///
/// A failed read never moves the position (LEB128 reads excepted: they
/// consume the bytes they examined, as in Ghidra). Signedness is in the
/// type: `read_u32` and `read_i32` replace Ghidra's `readInt` and
/// `readUnsignedInt`-returning-`long`.
///
/// The reader is a small `Copy` value. Copying it gives an independent
/// cursor over the same bytes (Ghidra's `clone()`); [`at`](Self::at),
/// [`with_endian`](Self::with_endian), [`as_big_endian`](Self::as_big_endian)
/// and [`as_little_endian`](Self::as_little_endian) give a copy with a
/// different position or byte order. Where Ghidra has an overload taking an
/// explicit `DataConverter`, use `reader.with_endian(e).read_x_at(i)`.
///
/// When the provider's bytes are in memory the reader keeps the slice and
/// reads from it directly, without a virtual call and without copying; byte
/// arrays and unterminated-length raw strings are then returned borrowed.
#[derive(Debug, Clone, Copy)]
pub struct BinaryReader<'a> {
    /// The provider, absent when the reader was created over a bare slice.
    provider: Option<&'a dyn ByteProvider>,
    /// The provider's in-memory content, or the bare slice.
    mem: Option<&'a [u8]>,
    position: u64,
    endian: Endian,
}

impl<'a> BinaryReader<'a> {
    /// Creates a reader over `provider`, positioned at 0.
    pub fn new(provider: &'a dyn ByteProvider, endian: Endian) -> Self {
        Self {
            provider: Some(provider),
            mem: provider.as_slice(),
            position: 0,
            endian,
        }
    }

    /// Creates a reader over a byte slice, positioned at 0.
    pub const fn from_slice(bytes: &'a [u8], endian: Endian) -> Self {
        Self {
            provider: None,
            mem: Some(bytes),
            position: 0,
            endian,
        }
    }

    /// A copy of this reader positioned at `index` (Ghidra's `clone(newIndex)`).
    #[must_use]
    pub const fn at(mut self, index: u64) -> Self {
        self.position = index;
        self
    }

    /// A copy of this reader that reads in `endian` order.
    #[must_use]
    pub const fn with_endian(mut self, endian: Endian) -> Self {
        self.endian = endian;
        self
    }

    /// A copy of this reader in big-endian mode, at the same position.
    #[must_use]
    pub const fn as_big_endian(self) -> Self {
        self.with_endian(Endian::Big)
    }

    /// A copy of this reader in little-endian mode, at the same position.
    #[must_use]
    pub const fn as_little_endian(self) -> Self {
        self.with_endian(Endian::Little)
    }

    /// The byte order of this reader.
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Changes the byte order of this reader.
    pub const fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    /// True when the reader assembles values least significant byte first.
    pub const fn is_little_endian(&self) -> bool {
        self.endian.is_little()
    }

    /// True when the reader assembles values most significant byte first.
    pub const fn is_big_endian(&self) -> bool {
        self.endian.is_big()
    }

    /// The provider this reader reads from; `None` for a reader created with
    /// [`from_slice`](Self::from_slice).
    pub const fn provider(&self) -> Option<&'a dyn ByteProvider> {
        self.provider
    }

    /// The whole content as a slice, when it is in memory.
    pub const fn as_slice(&self) -> Option<&'a [u8]> {
        self.mem
    }

    /// Length of the underlying data in bytes.
    pub fn len(&self) -> u64 {
        match (self.provider, self.mem) {
            (Some(provider), _) => provider.len(),
            (None, Some(mem)) => mem.len() as u64,
            (None, None) => 0,
        }
    }

    /// True when the underlying data is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when a byte can be read at `index`.
    pub fn is_valid_index(&self, index: u64) -> bool {
        match self.provider {
            Some(provider) => provider.is_valid_index(index),
            None => index < self.len(),
        }
    }

    /// True when `count` bytes can be read at `start`, without wrapping
    /// around the end of the index space. Zero bytes at the end are readable.
    pub fn is_valid_range(&self, start: u64, count: u64) -> bool {
        match self.provider {
            Some(provider) => provider.is_valid_range(start, count),
            None => start
                .checked_add(count)
                .is_some_and(|end| end <= self.len()),
        }
    }

    /// The current position (Ghidra's `getPointerIndex`).
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Moves to `index` and returns the previous position, which can be
    /// passed back to restore it (Ghidra's `setPointerIndex`).
    pub const fn set_position(&mut self, index: u64) -> u64 {
        std::mem::replace(&mut self.position, index)
    }

    /// Moves the position forward by `count` bytes without reading them.
    /// The position wraps at `u64::MAX`, as Ghidra's does.
    pub const fn skip(&mut self, count: u64) {
        self.position = self.position.wrapping_add(count);
    }

    /// True when a byte can be read at the current position.
    pub fn has_next(&self) -> bool {
        self.is_valid_index(self.position)
    }

    /// True when `count` bytes can be read at the current position.
    pub fn has_remaining(&self, count: u64) -> bool {
        self.is_valid_range(self.position, count)
    }

    /// Number of bytes between the position and the end of the data
    /// (0 when the position is at or past the end).
    pub fn remaining(&self) -> u64 {
        self.len().saturating_sub(self.position)
    }

    /// Advances the position to the next multiple of `alignment`, if it is
    /// not already one, and returns the number of bytes skipped
    /// (`0..alignment`). An alignment of 0 does nothing.
    pub const fn align(&mut self, alignment: u64) -> u64 {
        if alignment == 0 {
            return 0;
        }
        let excess = self.position % alignment;
        if excess == 0 {
            return 0;
        }
        let pad = alignment - excess;
        self.position = self.position.wrapping_add(pad);
        pad
    }

    /// Copies exactly `buf.len()` bytes at `index` into `buf`.
    pub fn read_exact_at(&self, index: u64, buf: &mut [u8]) -> Result<()> {
        if let Some(bytes) = self.mem_range(index, buf.len()) {
            buf.copy_from_slice(bytes);
            return Ok(());
        }
        match self.provider {
            Some(provider) => provider.read_into(index, buf),
            None => Err(BinError::out_of_bounds(index, buf.len() as u64, self.len())),
        }
    }

    /// Copies exactly `buf.len()` bytes at the position into `buf` and advances.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.read_exact_at(self.position, buf)?;
        self.skip(buf.len() as u64);
        Ok(())
    }

    /// Reads `N` bytes at `index` into an array.
    pub fn read_array_at<const N: usize>(&self, index: u64) -> Result<[u8; N]> {
        if let Some(mem) = self.mem
            && let Ok(start) = usize::try_from(index)
            && let Some(chunk) = mem.get(start..).and_then(|tail| tail.first_chunk::<N>())
        {
            return Ok(*chunk);
        }
        match self.provider {
            Some(provider) => {
                let mut buf = [0u8; N];
                provider.read_into(index, &mut buf)?;
                Ok(buf)
            }
            None => Err(BinError::out_of_bounds(index, N as u64, self.len())),
        }
    }

    /// Reads `N` bytes at the position into an array and advances.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_array_at::<N>(self.position)?;
        self.skip(N as u64);
        Ok(bytes)
    }

    /// `len` bytes at `index` from the in-memory content, if they are there.
    pub(crate) fn mem_range(&self, index: u64, len: usize) -> Option<&'a [u8]> {
        let start = usize::try_from(index).ok()?;
        self.mem?.get(start..start.checked_add(len)?)
    }

    /// Reads `len` bytes at `index` without any limit other than the
    /// provider's own bounds, borrowing when possible.
    pub(crate) fn raw_bytes_at(&self, index: u64, len: usize) -> Result<Cow<'a, [u8]>> {
        if let Some(bytes) = self.mem_range(index, len) {
            return Ok(Cow::Borrowed(bytes));
        }
        match self.provider {
            Some(provider) => provider.read_bytes(index, len),
            None => Err(BinError::out_of_bounds(index, len as u64, self.len())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FillProvider, MemoryProvider, UnlimitedProvider};

    #[test]
    fn copies_are_independent() {
        let provider = MemoryProvider::new(vec![0u8; 1024]);
        let mut reader = BinaryReader::new(&provider, Endian::Little);
        reader.set_position(0x100);
        let copy = reader.at(0x200);
        assert_eq!(reader.position(), 0x100);
        assert_eq!(copy.position(), 0x200);
        let same = reader;
        assert_eq!(same.position(), 0x100);
    }

    #[test]
    fn endian_switching() {
        let reader = BinaryReader::from_slice(&[1, 2], Endian::Little);
        assert!(reader.is_little_endian() && !reader.is_big_endian());
        let big = reader.as_big_endian();
        assert!(big.is_big_endian());
        assert_eq!(big.as_little_endian().endian(), Endian::Little);
        assert_eq!(reader.with_endian(Endian::Big).endian(), Endian::Big);
        let mut r = reader;
        r.set_endian(Endian::Big);
        assert_eq!(r.endian(), Endian::Big);
        assert!(reader.is_little_endian(), "the original is unchanged");
    }

    #[test]
    fn position_and_validity() {
        let mut reader = BinaryReader::from_slice(&[1, 2, 3], Endian::Little);
        assert_eq!(reader.len(), 3);
        assert!(!reader.is_empty());
        assert!(reader.provider().is_none());
        assert_eq!(reader.as_slice(), Some(&[1u8, 2, 3][..]));
        assert!(reader.has_next());
        assert!(reader.has_remaining(3) && !reader.has_remaining(4));
        assert_eq!(reader.remaining(), 3);
        assert_eq!(reader.set_position(3), 0);
        assert!(!reader.has_next());
        assert!(reader.has_remaining(0));
        assert_eq!(reader.remaining(), 0);
        reader.skip(10);
        assert_eq!(reader.position(), 13);
        assert_eq!(reader.remaining(), 0);
        assert!(!reader.has_remaining(0));
        assert!(reader.is_valid_index(2) && !reader.is_valid_index(3));
        assert!(reader.is_valid_range(1, 2) && !reader.is_valid_range(1, 3));
        assert!(!reader.is_valid_range(1, u64::MAX));
        assert!(BinaryReader::from_slice(&[], Endian::Big).is_empty());
    }

    #[test]
    fn align_advances_to_the_next_multiple() {
        let mut reader = BinaryReader::from_slice(&[], Endian::Little).at(123);
        assert_eq!(reader.align(16), 5);
        assert_eq!(reader.position(), 128);
        assert_eq!(reader.align(16), 0);
        assert_eq!(reader.align(0), 0);
        assert_eq!(reader.align(1), 0);
        assert_eq!(reader.align(3), 1); // not a power of two
        assert_eq!(reader.position(), 129);
    }

    #[test]
    fn exact_and_array_reads() {
        let provider = MemoryProvider::new(vec![1u8, 2, 3, 4, 5]);
        let mut reader = BinaryReader::new(&provider, Endian::Little);
        assert!(reader.provider().is_some());
        assert_eq!(reader.read_array::<2>().unwrap(), [1, 2]);
        assert_eq!(reader.read_array_at::<3>(2).unwrap(), [3, 4, 5]);
        assert!(reader.read_array_at::<3>(3).is_err());
        let mut buf = [0u8; 3];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [3, 4, 5]);
        assert_eq!(reader.position(), 5);
        assert!(reader.read_exact(&mut buf).is_err());
        assert_eq!(
            reader.position(),
            5,
            "a failed read does not move the cursor"
        );
        assert!(reader.read_array::<1>().is_err());
        let slice_reader = BinaryReader::from_slice(&[9], Endian::Big);
        assert!(slice_reader.read_exact_at(0, &mut buf).is_err());
        assert_eq!(slice_reader.read_array_at::<1>(0).unwrap(), [9]);
    }

    #[test]
    fn providers_without_memory_use_the_slow_path() {
        let fill = FillProvider::new(10, 7);
        let reader = BinaryReader::new(&fill, Endian::Little);
        assert!(reader.as_slice().is_none());
        assert_eq!(reader.read_array_at::<4>(6).unwrap(), [7; 4]);
        assert!(reader.read_array_at::<4>(7).is_err());
        assert_eq!(&*reader.raw_bytes_at(8, 2).unwrap(), &[7, 7]);
    }

    #[test]
    fn unlimited_provider_reads_past_the_slice() {
        let memory = MemoryProvider::new(vec![1u8, 2, 3]);
        let unlimited = UnlimitedProvider::new(&memory);
        let reader = BinaryReader::new(&unlimited, Endian::Little);
        assert_eq!(reader.len(), 3);
        assert_eq!(reader.read_array_at::<4>(1).unwrap(), [2, 3, 0, 0]);
        assert_eq!(reader.read_array_at::<2>(100).unwrap(), [0, 0]);
        let mut buf = [9u8; 4];
        reader.read_exact_at(2, &mut buf).unwrap();
        assert_eq!(buf, [3, 0, 0, 0]);
        assert!(reader.is_valid_index(1000));
    }
}
