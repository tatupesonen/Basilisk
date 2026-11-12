//! Views of a sub-range of another provider.

use crate::error::{BinError, Result};
use crate::provider::traits::{ByteProvider, sub_slice};

/// Largest offset Ghidra can express: it indexes with a signed 64-bit value,
/// so anything above this is "negative" there and rejected.
const MAX_OFFSET: u64 = i64::MAX as u64;

fn describe(parent: Option<&str>, offset: u64, len: u64) -> String {
    format!("{}[0x{offset:x},0x{len:x}]", parent.unwrap_or("<unnamed>"))
}

/// A provider restricted to `len` bytes of another provider, starting at
/// `offset` (Ghidra's `ByteProviderWrapper`).
///
/// `P` may be a reference (`SubProvider<&dyn ByteProvider>`), an `Arc`, or an
/// owned provider. Wrappers nest: a `SubProvider` of a `SubProvider`
/// addresses the innermost provider with both offsets added.
///
/// The range is not checked against the wrapped provider when the view is
/// created, exactly as in Ghidra: a view that reaches past the end of its
/// parent reports those indexes as invalid and fails reads that touch them.
#[derive(Debug, Clone)]
pub struct SubProvider<P> {
    inner: P,
    offset: u64,
    len: u64,
    name: String,
    path: String,
}

impl<P: ByteProvider> SubProvider<P> {
    /// Creates a view of `len` bytes of `inner` starting at `offset`.
    pub fn new(inner: P, offset: u64, len: u64) -> Self {
        let name = describe(inner.name(), offset, len);
        let path = describe(inner.path(), offset, len);
        Self {
            inner,
            offset,
            len,
            name,
            path,
        }
    }

    /// Creates a view of the whole of `inner` (same bytes, new identity).
    pub fn whole(inner: P) -> Self {
        let len = inner.len();
        Self::new(inner, 0, len)
    }

    /// Replaces the generated name (`parent[0xoffset,0xlen]`).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Offset of the view inside the wrapped provider.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// The wrapped provider.
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    fn check(&self, offset: u64, len: u64) -> Result<u64> {
        let end = offset.checked_add(len);
        if end.is_none_or(|end| end > self.len) {
            return Err(BinError::out_of_bounds(offset, len, self.len));
        }
        self.offset
            .checked_add(offset)
            .ok_or_else(|| BinError::out_of_bounds(offset, len, self.len))
    }
}

impl<P: ByteProvider> ByteProvider for SubProvider<P> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let inner_offset = self.check(offset, buf.len() as u64)?;
        self.inner.read_into(inner_offset, buf)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        let len = usize::try_from(self.len).ok()?;
        sub_slice(self.inner.as_slice()?, self.offset, len)
    }

    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }

    fn path(&self) -> Option<&str> {
        Some(&self.path)
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.len
            && self
                .offset
                .checked_add(index)
                .is_some_and(|i| self.inner.is_valid_index(i))
    }

    fn is_valid_range(&self, start: u64, count: u64) -> bool {
        if count == 0 {
            return start <= self.len;
        }
        start.checked_add(count).is_some_and(|end| end <= self.len)
            && self
                .offset
                .checked_add(start)
                .is_some_and(|s| self.inner.is_valid_range(s, count))
    }
}

/// A view of a sub-range of another provider in which reads past the end of
/// the range succeed and yield zero bytes (Ghidra's
/// `UnlimitedByteProviderWrapper`).
///
/// [`len`](ByteProvider::len) still reports the length of the range. Ghidra's
/// ELF parser reads headers through this wrapper so that truncated files
/// parse with zero-filled fields instead of failing.
///
/// Because every range is readable, the caller must bound read lengths
/// itself: [`read_bytes`](ByteProvider::read_bytes) allocates what it is
/// asked for. Offsets above `i64::MAX` are rejected, as in Ghidra, where
/// they are negative.
#[derive(Debug, Clone)]
pub struct UnlimitedProvider<P> {
    sub: SubProvider<P>,
}

impl<P: ByteProvider> UnlimitedProvider<P> {
    /// Wraps the whole of `inner`.
    pub fn new(inner: P) -> Self {
        Self {
            sub: SubProvider::whole(inner),
        }
    }

    /// Wraps `len` bytes of `inner` starting at `offset`.
    pub fn with_range(inner: P, offset: u64, len: u64) -> Self {
        Self {
            sub: SubProvider::new(inner, offset, len),
        }
    }

    /// The wrapped provider.
    pub const fn inner(&self) -> &P {
        self.sub.inner()
    }
}

impl<P: ByteProvider> ByteProvider for UnlimitedProvider<P> {
    fn len(&self) -> u64 {
        self.sub.len
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset > MAX_OFFSET {
            return Err(BinError::out_of_bounds(
                offset,
                buf.len() as u64,
                self.sub.len,
            ));
        }
        // Bytes available in the range from `offset` on; the rest is zero fill.
        let available = self.sub.len.saturating_sub(offset);
        let real = usize::try_from(available).map_or(buf.len(), |a| a.min(buf.len()));
        let (head, tail) = buf.split_at_mut(real);
        tail.fill(0);
        if head.is_empty() {
            Ok(())
        } else {
            self.sub.read_into(offset, head)
        }
    }

    fn as_slice(&self) -> Option<&[u8]> {
        self.sub.as_slice()
    }

    fn name(&self) -> Option<&str> {
        self.sub.inner.name()
    }

    fn path(&self) -> Option<&str> {
        self.sub.inner.path()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index <= MAX_OFFSET
    }

    fn is_valid_range(&self, start: u64, _count: u64) -> bool {
        start <= MAX_OFFSET
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{FileProvider, MemoryProvider};

    fn digits() -> MemoryProvider {
        MemoryProvider::new((0u8..10).collect::<Vec<_>>()).with_name("digits")
    }

    #[test]
    fn sub_range_reads() {
        let parent = digits();
        let sub = SubProvider::new(&parent, 2, 5);
        assert_eq!(sub.len(), 5);
        assert_eq!(sub.offset(), 2);
        assert_eq!(sub.inner().len(), 10);
        assert_eq!(sub.read_byte(0).unwrap(), 2);
        assert_eq!(sub.read_byte(4).unwrap(), 6);
        assert!(sub.read_byte(5).is_err());
        assert_eq!(&*sub.read_bytes(1, 4).unwrap(), &[3, 4, 5, 6]);
        assert!(sub.read_bytes(1, 5).is_err());
        assert!(sub.read_bytes(5, 0).unwrap().is_empty());
        assert!(sub.read_bytes(6, 0).is_err());
        assert!(matches!(sub.read_bytes(0, 5).unwrap(), Cow::Borrowed(_)));
        assert_eq!(sub.as_slice(), Some(&[2u8, 3, 4, 5, 6][..]));
    }

    #[test]
    fn sub_names() {
        let parent = digits().with_path("/data/digits");
        let sub = SubProvider::new(&parent, 0x10, 0x20);
        assert_eq!(sub.name(), Some("digits[0x10,0x20]"));
        assert_eq!(sub.path(), Some("/data/digits[0x10,0x20]"));
        let renamed = SubProvider::new(&parent, 0, 1).with_name("first");
        assert_eq!(renamed.name(), Some("first"));
        let unnamed = MemoryProvider::new(vec![0u8; 4]);
        assert_eq!(
            SubProvider::whole(&unnamed).name(),
            Some("<unnamed>[0x0,0x4]")
        );
    }

    #[test]
    fn nested_wrappers_compose() {
        let parent = digits();
        let outer = SubProvider::new(&parent, 2, 6); // 2..8
        let inner = SubProvider::new(&outer, 3, 2); // 5..7
        assert_eq!(&*inner.read_bytes(0, 2).unwrap(), &[5, 6]);
        assert_eq!(inner.as_slice(), Some(&[5u8, 6][..]));
        assert_eq!(inner.name(), Some("digits[0x2,0x6][0x3,0x2]"));
        let owned = SubProvider::new(SubProvider::new(digits(), 1, 8), 1, 3);
        assert_eq!(&*owned.read_bytes(0, 3).unwrap(), &[2, 3, 4]);
    }

    #[test]
    fn view_past_parent_end_is_invalid_there() {
        let parent = digits();
        let sub = SubProvider::new(&parent, 8, 5); // parent has only 2 bytes here
        assert_eq!(sub.len(), 5);
        assert!(sub.is_valid_index(1));
        assert!(!sub.is_valid_index(2));
        assert!(sub.is_valid_range(0, 2));
        assert!(!sub.is_valid_range(0, 3));
        assert!(sub.read_bytes(0, 3).is_err());
        assert!(sub.as_slice().is_none());
        assert_eq!(&*sub.read_bytes(0, 2).unwrap(), &[8, 9]);
        let wrapping = SubProvider::new(&parent, u64::MAX, 4);
        assert!(!wrapping.is_valid_index(1));
        assert!(wrapping.read_byte(1).is_err());
    }

    #[test]
    fn unlimited_pads_with_zeros() {
        let parent = digits();
        let p = UnlimitedProvider::new(&parent);
        assert_eq!(p.len(), 10);
        assert_eq!(p.name(), Some("digits"));
        assert_eq!(p.inner().len(), 10);
        assert_eq!(p.read_byte(9).unwrap(), 9);
        assert_eq!(p.read_byte(10).unwrap(), 0);
        assert_eq!(p.read_byte(1 << 40).unwrap(), 0);
        assert_eq!(&*p.read_bytes(8, 4).unwrap(), &[8, 9, 0, 0]);
        assert_eq!(&*p.read_bytes(100, 3).unwrap(), &[0, 0, 0]);
        assert!(p.is_valid_index(1 << 50));
        assert!(p.is_valid_range(1 << 50, 1 << 20));
        // "negative" offsets are rejected
        assert!(!p.is_valid_index(u64::MAX));
        assert!(p.read_byte(u64::MAX).is_err());
        assert!(p.read_bytes(i64::MAX as u64 + 1, 1).is_err());
        assert_eq!(p.read_byte(i64::MAX as u64).unwrap(), 0);
    }

    #[test]
    fn unlimited_sub_range() {
        let parent = digits();
        let p = UnlimitedProvider::with_range(&parent, 4, 3);
        assert_eq!(p.len(), 3);
        assert_eq!(&*p.read_bytes(0, 5).unwrap(), &[4, 5, 6, 0, 0]);
        assert_eq!(p.as_slice(), Some(&[4u8, 5, 6][..]));
    }

    #[test]
    fn unlimited_over_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, [1u8, 2, 3]).unwrap();
        let file = FileProvider::open(&path).unwrap();
        let p = UnlimitedProvider::new(&file);
        assert!(p.as_slice().is_none());
        assert_eq!(&*p.read_bytes(1, 4).unwrap(), &[2, 3, 0, 0]);
        assert_eq!(&*p.read_bytes(3, 2).unwrap(), &[0, 0]);
    }
}
