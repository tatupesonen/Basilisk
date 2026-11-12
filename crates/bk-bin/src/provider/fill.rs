//! Providers without storage: empty and constant-fill.

use crate::error::{BinError, Result};
use crate::provider::traits::ByteProvider;

/// A provider with no content (Ghidra's `EmptyByteProvider`).
///
/// Every read of at least one byte fails; reading zero bytes at offset 0
/// succeeds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmptyProvider {
    name: Option<String>,
}

impl EmptyProvider {
    /// Creates an unnamed empty provider.
    pub const fn new() -> Self {
        Self { name: None }
    }

    /// Sets the name reported by [`ByteProvider::name`].
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl ByteProvider for EmptyProvider {
    fn len(&self) -> u64 {
        0
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset == 0 && buf.is_empty() {
            Ok(())
        } else {
            Err(BinError::out_of_bounds(offset, buf.len() as u64, 0))
        }
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(&[])
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// A provider whose every byte has the same value (Ghidra's
/// `StaticValueByteProvider`). It needs no storage, so it can be far larger
/// than memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillProvider {
    len: u64,
    value: u8,
    name: Option<String>,
}

impl FillProvider {
    /// Creates a provider of `len` bytes, all equal to `value`.
    pub const fn new(len: u64, value: u8) -> Self {
        Self {
            len,
            value,
            name: None,
        }
    }

    /// A provider of `len` zero bytes.
    pub const fn zeros(len: u64) -> Self {
        Self::new(len, 0)
    }

    /// Sets the name reported by [`ByteProvider::name`].
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The value of every byte.
    pub const fn value(&self) -> u8 {
        self.value
    }
}

impl ByteProvider for FillProvider {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.is_valid_range(offset, buf.len() as u64) {
            return Err(BinError::out_of_bounds(offset, buf.len() as u64, self.len));
        }
        buf.fill(self.value);
        Ok(())
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provider() {
        let p = EmptyProvider::new().with_name("nothing");
        assert_eq!(p.len(), 0);
        assert!(p.is_empty());
        assert_eq!(p.name(), Some("nothing"));
        assert!(!p.is_valid_index(0));
        assert!(p.read_byte(0).is_err());
        assert!(p.read_bytes(0, 0).unwrap().is_empty());
        assert!(p.read_bytes(1, 0).is_err());
        assert!(p.read_into(1, &mut []).is_err());
        assert_eq!(EmptyProvider::default(), EmptyProvider::new());
    }

    #[test]
    fn fill_provider() {
        let p = FillProvider::new(u64::from(u32::MAX) * 100, 0xaa).with_name("fill");
        assert_eq!(p.len(), u64::from(u32::MAX) * 100);
        assert_eq!(p.value(), 0xaa);
        assert_eq!(p.name(), Some("fill"));
        assert_eq!(p.read_byte(0).unwrap(), 0xaa);
        assert_eq!(p.read_byte(p.len() - 1).unwrap(), 0xaa);
        assert!(p.read_byte(p.len()).is_err());
        assert_eq!(&*p.read_bytes(1 << 38, 3).unwrap(), &[0xaa; 3]);
        assert!(p.read_bytes(p.len() - 1, 2).is_err());
        assert!(p.read_bytes(p.len(), 0).unwrap().is_empty());
        assert!(p.as_slice().is_none());
        assert_eq!(
            FillProvider::zeros(2).read_bytes(0, 2).unwrap().as_ref(),
            &[0, 0]
        );
    }
}
