//! In-memory providers.

use crate::error::Result;
use crate::provider::traits::{ByteProvider, copy_from_slice};

/// A provider over bytes held in memory (Ghidra's `ByteArrayProvider`).
///
/// The storage `B` is anything that derefs to a byte slice and can be shared
/// between threads: `Vec<u8>` (the default, owned), `&[u8]` (borrowed),
/// `Box<[u8]>`, `Arc<[u8]>`, or a memory map supplied by a crate that is
/// allowed to create one. Reads through this provider never copy: see
/// [`ByteProvider::as_slice`].
///
/// ```
/// use bk_bin::{ByteProvider, MemoryProvider};
///
/// let owned = MemoryProvider::new(vec![1u8, 2, 3]);
/// let borrowed = MemoryProvider::new(&[1u8, 2, 3][..]);
/// assert_eq!(owned.len(), borrowed.len());
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MemoryProvider<B = Vec<u8>> {
    bytes: B,
    name: Option<String>,
    path: Option<String>,
}

impl<B: AsRef<[u8]>> MemoryProvider<B> {
    /// Creates an unnamed provider over `bytes`.
    pub fn new(bytes: B) -> Self {
        Self {
            bytes,
            name: None,
            path: None,
        }
    }

    /// Sets the name reported by [`ByteProvider::name`].
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the path reported by [`ByteProvider::path`].
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Gives the storage back.
    pub fn into_inner(self) -> B {
        self.bytes
    }
}

impl<B: AsRef<[u8]>> std::fmt::Debug for MemoryProvider<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The content can be large: print its size, not the bytes.
        f.debug_struct("MemoryProvider")
            .field("len", &self.bytes.as_ref().len())
            .field("name", &self.name)
            .field("path", &self.path)
            .finish()
    }
}

impl<B: AsRef<[u8]> + Send + Sync> ByteProvider for MemoryProvider<B> {
    fn len(&self) -> u64 {
        self.bytes.as_ref().len() as u64
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        copy_from_slice(self.bytes.as_ref(), offset, buf)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self.bytes.as_ref())
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl From<Vec<u8>> for MemoryProvider<Vec<u8>> {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl<'a> From<&'a [u8]> for MemoryProvider<&'a [u8]> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use super::*;

    #[test]
    fn storage_kinds() {
        let v = MemoryProvider::new(vec![1u8, 2, 3]);
        let s = MemoryProvider::new(&[1u8, 2, 3][..]);
        let a = MemoryProvider::new(Arc::<[u8]>::from(vec![1u8, 2, 3]));
        for p in [&v as &dyn ByteProvider, &s, &a] {
            assert_eq!(p.len(), 3);
            assert_eq!(p.read_byte(1).unwrap(), 2);
            assert_eq!(p.as_slice(), Some(&[1u8, 2, 3][..]));
        }
        assert_eq!(v.clone().into_inner(), vec![1, 2, 3]);
        assert_eq!(MemoryProvider::from(vec![7u8]).bytes(), &[7]);
        assert_eq!(MemoryProvider::from(&[7u8][..]).bytes(), &[7]);
    }

    #[test]
    fn reads_borrow() {
        let p = MemoryProvider::new(vec![1u8, 2, 3, 4]);
        let bytes = p.read_bytes(1, 2).unwrap();
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(&*bytes, &[2, 3]);
    }

    #[test]
    fn names_and_debug() {
        let p = MemoryProvider::new(vec![0u8; 1000])
            .with_name("a.out")
            .with_path("/tmp/a.out");
        assert_eq!(p.name(), Some("a.out"));
        assert_eq!(p.path(), Some("/tmp/a.out"));
        let debug = format!("{p:?}");
        assert!(debug.contains("len: 1000") && debug.len() < 200, "{debug}");
        let unnamed = MemoryProvider::new(Vec::new());
        assert_eq!(unnamed.name(), None);
        assert!(unnamed.is_empty());
    }

    #[test]
    fn empty_storage_rejects_any_byte_read() {
        let p = MemoryProvider::new(Vec::new());
        assert!(p.read_byte(0).is_err());
        assert!(p.read_bytes(0, 0).unwrap().is_empty());
    }
}
