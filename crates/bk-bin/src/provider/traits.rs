//! The provider contract.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use crate::error::{BinError, Result};

/// A random-access, read-only byte source with a known length.
///
/// This is Ghidra's `ByteProvider` interface. Implementations take `&self`
/// and are `Send + Sync`, so one provider can be read from many threads
/// without external locking.
///
/// Implementors supply [`len`](Self::len) and [`read_into`](Self::read_into);
/// providers whose bytes are in memory also override
/// [`as_slice`](Self::as_slice), which lets [`read_bytes`](Self::read_bytes)
/// and the [`BinaryReader`](crate::BinaryReader) borrow instead of copying.
///
/// References, `Box` and `Arc` of a provider are providers themselves, so a
/// wrapper such as [`SubProvider`](crate::SubProvider) can either borrow or
/// own what it wraps.
pub trait ByteProvider: Send + Sync + fmt::Debug {
    /// Number of bytes in the provider.
    fn len(&self) -> u64;

    /// Copies exactly `buf.len()` bytes starting at `offset` into `buf`.
    ///
    /// Fails with [`BinError::OutOfBounds`] if the range is not inside the
    /// provider; `buf` is then left in an unspecified state. Reading zero
    /// bytes at any offset up to and including [`len`](Self::len) succeeds.
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// The whole content as one slice, if it is in memory.
    ///
    /// The default is `None`. A provider that returns a slice must return the
    /// same bytes that [`read_into`](Self::read_into) yields for offsets
    /// inside the slice; it may accept reads outside it (as
    /// [`UnlimitedProvider`](crate::UnlimitedProvider) does).
    fn as_slice(&self) -> Option<&[u8]> {
        None
    }

    /// True when the provider holds no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A name for messages — for example the file name — if there is one.
    fn name(&self) -> Option<&str> {
        None
    }

    /// The path of the underlying file (or a path-like description of where
    /// the bytes come from), if there is one.
    fn path(&self) -> Option<&str> {
        None
    }

    /// True when a byte can be read at `index`.
    fn is_valid_index(&self, index: u64) -> bool {
        index < self.len()
    }

    /// True when `count` bytes can be read at `start`. Reading zero bytes at
    /// the end of the provider is valid.
    fn is_valid_range(&self, start: u64, count: u64) -> bool {
        let len = self.len();
        if count == 0 {
            return start <= len;
        }
        self.is_valid_index(start) && start.checked_add(count).is_some_and(|end| end <= len)
    }

    /// Reads the byte at `offset`.
    fn read_byte(&self, offset: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_into(offset, &mut buf)?;
        Ok(buf[0])
    }

    /// Reads `len` bytes at `offset`, borrowing them when the provider is in
    /// memory and copying them into a new buffer otherwise.
    ///
    /// The range is validated before anything is allocated, so for a provider
    /// with a real length the allocation is bounded by that length.
    fn read_bytes(&self, offset: u64, len: usize) -> Result<Cow<'_, [u8]>> {
        if let Some(slice) = self.as_slice()
            && let Some(bytes) = sub_slice(slice, offset, len)
        {
            return Ok(Cow::Borrowed(bytes));
        }
        if !self.is_valid_range(offset, len as u64) {
            return Err(BinError::out_of_bounds(offset, len as u64, self.len()));
        }
        let mut buf = vec![0u8; len];
        self.read_into(offset, &mut buf)?;
        Ok(Cow::Owned(buf))
    }
}

/// `slice[offset..offset + len]`, or `None` if that is not inside the slice.
pub(crate) fn sub_slice(slice: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(len)?;
    slice.get(start..end)
}

/// Copies `slice[offset..offset + buf.len()]` into `buf`, or reports the
/// read as out of bounds.
pub(crate) fn copy_from_slice(slice: &[u8], offset: u64, buf: &mut [u8]) -> Result<()> {
    match sub_slice(slice, offset, buf.len()) {
        Some(bytes) => {
            buf.copy_from_slice(bytes);
            Ok(())
        }
        None => Err(BinError::out_of_bounds(
            offset,
            buf.len() as u64,
            slice.len() as u64,
        )),
    }
}

macro_rules! forward_provider {
    ($($ty:ty),+) => {$(
        impl<P: ByteProvider + ?Sized> ByteProvider for $ty {
            fn len(&self) -> u64 {
                (**self).len()
            }
            fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                (**self).read_into(offset, buf)
            }
            fn as_slice(&self) -> Option<&[u8]> {
                (**self).as_slice()
            }
            fn is_empty(&self) -> bool {
                (**self).is_empty()
            }
            fn name(&self) -> Option<&str> {
                (**self).name()
            }
            fn path(&self) -> Option<&str> {
                (**self).path()
            }
            fn is_valid_index(&self, index: u64) -> bool {
                (**self).is_valid_index(index)
            }
            fn is_valid_range(&self, start: u64, count: u64) -> bool {
                (**self).is_valid_range(start, count)
            }
            fn read_byte(&self, offset: u64) -> Result<u8> {
                (**self).read_byte(offset)
            }
            fn read_bytes(&self, offset: u64, len: usize) -> Result<Cow<'_, [u8]>> {
                (**self).read_bytes(offset, len)
            }
        }
    )+};
}

forward_provider!(&P, Box<P>, Arc<P>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryProvider;

    #[test]
    fn default_range_rules() {
        let p = MemoryProvider::new(vec![1u8, 2, 3]);
        assert!(p.is_valid_index(0) && p.is_valid_index(2) && !p.is_valid_index(3));
        assert!(p.is_valid_range(0, 3));
        assert!(p.is_valid_range(3, 0), "zero bytes at the end are readable");
        assert!(!p.is_valid_range(4, 0));
        assert!(!p.is_valid_range(3, 1));
        assert!(!p.is_valid_range(1, u64::MAX), "must not wrap");
        assert!(!p.is_empty());
    }

    #[test]
    fn smart_pointers_and_references_are_providers() {
        fn total(p: &dyn ByteProvider) -> u64 {
            p.len()
        }
        let p = MemoryProvider::new(vec![9u8; 4]).with_name("blob");
        assert_eq!(total(&&p), 4);
        let boxed: Box<dyn ByteProvider> = Box::new(p.clone());
        assert_eq!(boxed.read_byte(3).unwrap(), 9);
        assert_eq!(boxed.name(), Some("blob"));
        let shared: Arc<dyn ByteProvider> = Arc::new(p);
        assert_eq!(shared.as_slice(), Some(&[9u8; 4][..]));
        assert!(shared.read_bytes(2, 3).is_err());
        assert!(matches!(shared.read_bytes(2, 2).unwrap(), Cow::Borrowed(_)));
    }

    #[test]
    fn helpers_reject_out_of_range() {
        let data = [1u8, 2, 3];
        assert_eq!(sub_slice(&data, 1, 2), Some(&data[1..]));
        assert_eq!(sub_slice(&data, 3, 0), Some(&data[3..]));
        assert_eq!(sub_slice(&data, 2, 2), None);
        assert_eq!(sub_slice(&data, u64::MAX, 1), None);
        assert_eq!(sub_slice(&data, 1, usize::MAX), None);
        let mut buf = [0u8; 2];
        assert!(copy_from_slice(&data, 2, &mut buf).is_err());
        copy_from_slice(&data, 1, &mut buf).unwrap();
        assert_eq!(buf, [2, 3]);
    }
}
