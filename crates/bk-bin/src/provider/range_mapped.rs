//! A provider assembled from ranges of another provider.

use crate::error::{BinError, Result};
use crate::provider::traits::ByteProvider;

/// One mapped range: where it starts in this provider and where its bytes
/// come from in the delegate (`None` for a sparse, zero-filled range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range {
    start: u64,
    source: Option<u64>,
}

/// A provider that is the concatenation of ranges of another provider, with
/// optional sparse (zero-filled) ranges in between (Ghidra's
/// `RangeMappedByteProvider`).
///
/// Ranges are appended with [`add_range`](Self::add_range) and
/// [`add_sparse_range`](Self::add_sparse_range); a range that continues the
/// previous one is merged into it. Adding takes `&mut self`, so a provider
/// that is being read cannot change underneath its readers.
#[derive(Debug, Clone)]
pub struct RangeMappedProvider<P> {
    delegate: P,
    /// Sorted by `start`; a range ends where the next begins, the last at `len`.
    ranges: Vec<Range>,
    len: u64,
    name: Option<String>,
}

impl<P: ByteProvider> RangeMappedProvider<P> {
    /// Creates an empty provider that will map ranges of `delegate`.
    pub const fn new(delegate: P) -> Self {
        Self {
            delegate,
            ranges: Vec::new(),
            len: 0,
            name: None,
        }
    }

    /// Sets the name reported by [`ByteProvider::name`].
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Appends `len` bytes of the delegate starting at `offset`.
    ///
    /// A range of length zero, or one that would make the provider longer
    /// than `u64::MAX` bytes, is ignored (Ghidra throws
    /// `IllegalArgumentException` for the former).
    pub fn add_range(&mut self, offset: u64, len: u64) {
        self.push(Some(offset), len);
    }

    /// Appends `len` zero bytes that have no storage in the delegate.
    pub fn add_sparse_range(&mut self, len: u64) {
        self.push(None, len);
    }

    fn push(&mut self, source: Option<u64>, len: u64) {
        let Some(new_len) = self.len.checked_add(len) else {
            return;
        };
        if len == 0 {
            return;
        }
        if let Some(last) = self.ranges.last() {
            let last_len = self.len - last.start;
            let continues = match (last.source, source) {
                (None, None) => true,
                (Some(prev), Some(next)) => prev.checked_add(last_len) == Some(next),
                _ => false,
            };
            if continues {
                self.len = new_len;
                return;
            }
        }
        self.ranges.push(Range {
            start: self.len,
            source,
        });
        self.len = new_len;
    }

    /// Number of ranges; adjacent ranges that were merged count once.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// The provider the ranges refer to.
    pub const fn delegate(&self) -> &P {
        &self.delegate
    }
}

impl<P: ByteProvider> ByteProvider for RangeMappedProvider<P> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let wanted = buf.len() as u64;
        let out_of_bounds = || BinError::out_of_bounds(offset, wanted, self.len);
        if !self.is_valid_range(offset, wanted) {
            return Err(out_of_bounds());
        }
        // Index of the range containing `offset`: the last one starting at or before it.
        let mut index = self
            .ranges
            .partition_point(|r| r.start <= offset)
            .saturating_sub(1);
        let mut position = offset;
        let mut remaining = &mut *buf;
        while !remaining.is_empty() {
            let range = self.ranges.get(index).ok_or_else(out_of_bounds)?;
            let end = self
                .ranges
                .get(index + 1)
                .map_or(self.len, |next| next.start);
            let in_range = end - position;
            let take =
                usize::try_from(in_range).map_or(remaining.len(), |n| n.min(remaining.len()));
            let (chunk, rest) = remaining.split_at_mut(take);
            match range.source {
                Some(source) => {
                    let delegate_offset = source
                        .checked_add(position - range.start)
                        .ok_or_else(out_of_bounds)?;
                    self.delegate.read_into(delegate_offset, chunk)?;
                }
                None => chunk.fill(0),
            }
            position += take as u64;
            remaining = rest;
            index += 1;
        }
        Ok(())
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryProvider;

    #[test]
    fn empty_until_ranges_are_added() {
        let delegate = MemoryProvider::new(vec![1u8, 2, 3, 4]);
        let mut p = RangeMappedProvider::new(&delegate).with_name("mapped");
        assert_eq!(p.len(), 0);
        assert_eq!(p.range_count(), 0);
        assert_eq!(p.name(), Some("mapped"));
        assert!(p.read_bytes(0, 0).unwrap().is_empty());
        p.add_range(0, 0);
        assert_eq!(p.range_count(), 0, "zero-length ranges are ignored");
        p.add_range(2, 2);
        assert_eq!(p.delegate().len(), 4);
        assert_eq!(&*p.read_bytes(0, 2).unwrap(), &[3, 4]);
    }

    #[test]
    fn range_past_delegate_end_fails_on_read() {
        let delegate = MemoryProvider::new(vec![1u8, 2, 3, 4]);
        let mut p = RangeMappedProvider::new(&delegate);
        p.add_range(2, 4);
        assert_eq!(p.len(), 4);
        assert_eq!(&*p.read_bytes(0, 2).unwrap(), &[3, 4]);
        assert!(p.read_bytes(0, 3).is_err());
    }

    #[test]
    fn length_overflow_is_ignored() {
        let delegate = MemoryProvider::new(vec![1u8]);
        let mut p = RangeMappedProvider::new(&delegate);
        p.add_sparse_range(u64::MAX);
        p.add_range(0, 1);
        assert_eq!(p.len(), u64::MAX);
        assert_eq!(p.range_count(), 1);
        assert_eq!(p.read_byte(u64::MAX - 1).unwrap(), 0);
    }
}
