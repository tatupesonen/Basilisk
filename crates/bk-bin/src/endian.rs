//! Byte order.

/// The byte order used to assemble multi-byte integers.
///
/// Ghidra passes a `DataConverter` (or an `isLittleEndian` flag) around;
/// here the order is a plain value held by the [`BinaryReader`](crate::BinaryReader).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Endian {
    /// Least significant byte first.
    #[default]
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// The byte order of the machine this code runs on.
    pub const NATIVE: Self = if cfg!(target_endian = "big") {
        Self::Big
    } else {
        Self::Little
    };

    /// Returns [`Endian::Little`] when `little` is true, [`Endian::Big`] otherwise.
    pub const fn from_little(little: bool) -> Self {
        if little { Self::Little } else { Self::Big }
    }

    /// True for [`Endian::Little`].
    pub const fn is_little(self) -> bool {
        matches!(self, Self::Little)
    }

    /// True for [`Endian::Big`].
    pub const fn is_big(self) -> bool {
        matches!(self, Self::Big)
    }

    /// The other byte order.
    #[must_use]
    pub const fn swapped(self) -> Self {
        match self {
            Self::Little => Self::Big,
            Self::Big => Self::Little,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Endian;

    #[test]
    fn conversions() {
        assert_eq!(Endian::from_little(true), Endian::Little);
        assert_eq!(Endian::from_little(false), Endian::Big);
        assert!(Endian::Little.is_little() && !Endian::Little.is_big());
        assert!(Endian::Big.is_big() && !Endian::Big.is_little());
        assert_eq!(Endian::Little.swapped(), Endian::Big);
        assert_eq!(Endian::Big.swapped(), Endian::Little);
        assert_eq!(Endian::default(), Endian::Little);
    }
}
