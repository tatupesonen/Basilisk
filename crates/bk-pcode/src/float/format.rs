//! The layout of a floating-point encoding and the table of formats by size.
//!
//! Ghidra sources: the constructor and field accessors of `FloatFormat` in
//! `float.hh`/`float.cc` (C++, sizes 4 and 8) and in
//! `ghidra/pcode/floatformat/FloatFormat.java` (sizes 2, 4, 8, 10, 16, 32),
//! `FloatFormatFactory.java`, and `Translate::setDefaultFloatFormats` /
//! `getFloatFormat` in `translate.cc`.

/// The class of a floating-point encoding (`FloatFormat::floatclass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FloatClass {
    /// A normal floating-point number.
    Normalized = 0,
    /// An infinite value.
    Infinity = 1,
    /// The value zero.
    Zero = 2,
    /// Not-a-Number.
    Nan = 3,
    /// A denormalized encoding (a very small value).
    Denormalized = 4,
}

/// One floating-point encoding: where the sign, exponent and fraction sit in
/// the encoded value, the exponent bias and whether the integer bit is
/// implied.
///
/// A format serves two levels of emulation, as in Ghidra:
///
/// - the *host* level (`float::host`): encodings of at most 8 bytes held in a
///   `u64` and computed through `f64`, exactly as the decompiler's C++ does;
/// - the *exact* level (`float::encode`, [`BigFloat`](crate::float::BigFloat)):
///   encodings of any size held in a [`Wide`](crate::wide::Wide) and computed
///   with correct rounding, exactly as the Java emulator does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FloatFormat {
    pub(crate) size: u32,
    pub(crate) signbit_pos: u32,
    pub(crate) frac_pos: u32,
    pub(crate) frac_size: u32,
    pub(crate) exp_pos: u32,
    pub(crate) exp_size: u32,
    pub(crate) bias: i32,
    pub(crate) jbit_implied: bool,
    pub(crate) display_precision: u32,
}

impl FloatFormat {
    /// IEEE 754 binary16 (2 bytes). Java only.
    pub const HALF: Self = Self::standard(2, 5, 10, true, 4);
    /// IEEE 754 binary32 (4 bytes).
    pub const SINGLE: Self = Self::standard(4, 8, 23, true, 8);
    /// IEEE 754 binary64 (8 bytes).
    pub const DOUBLE: Self = Self::standard(8, 11, 52, true, 16);
    /// The x87 80-bit double extended format (10 bytes), whose integer bit is
    /// stored explicitly as the top bit of its 64-bit fraction field. Java
    /// only.
    pub const EXTENDED: Self = Self::standard(10, 15, 64, false, 18);
    /// IEEE 754 binary128 (16 bytes). Java only.
    pub const QUAD: Self = Self::standard(16, 15, 112, true, 34);
    /// IEEE 754 binary256 (32 bytes). Java only.
    pub const OCTUPLE: Self = Self::standard(32, 19, 236, true, 71);

    /// A format laid out as sign, exponent, fraction from the top bit down.
    const fn standard(
        size: u32,
        exp_size: u32,
        frac_size: u32,
        jbit_implied: bool,
        display_precision: u32,
    ) -> Self {
        Self {
            size,
            signbit_pos: size * 8 - 1,
            frac_pos: 0,
            frac_size,
            exp_pos: frac_size,
            exp_size,
            bias: (1 << (exp_size - 1)) - 1,
            jbit_implied,
            display_precision,
        }
    }

    /// The standard format for an encoding of `size` bytes, as Java's
    /// `FloatFormatFactory.getFloatFormat` gives it: sizes 2, 4, 8, 10, 16
    /// and 32. `None` for any other size (Java throws
    /// `UnsupportedFloatFormatException`).
    pub const fn ieee(size: u32) -> Option<Self> {
        match size {
            2 => Some(Self::HALF),
            4 => Some(Self::SINGLE),
            8 => Some(Self::DOUBLE),
            10 => Some(Self::EXTENDED),
            16 => Some(Self::QUAD),
            32 => Some(Self::OCTUPLE),
            _ => None,
        }
    }

    /// The size of the encoding in bytes.
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// The number of bits in the fraction field.
    pub const fn frac_size(&self) -> u32 {
        self.frac_size
    }

    /// The number of significant bits of a normal value: the fraction field
    /// plus the integer bit when that is implied (Java's
    /// `effective_frac_size`). This is the `fracbits` of the format's
    /// [`BigFloat`](crate::float::BigFloat) values.
    pub const fn effective_frac_size(&self) -> u32 {
        self.frac_size + self.jbit_implied as u32
    }

    /// The number of bits in the exponent field.
    pub const fn exp_size(&self) -> u32 {
        self.exp_size
    }

    /// What is added to the true exponent to get its encoding.
    pub const fn bias(&self) -> i32 {
        self.bias
    }

    /// The largest exponent code, which marks infinities and NaNs.
    pub const fn max_exponent(&self) -> i32 {
        ((1u32 << self.exp_size) - 1) as i32
    }

    /// Whether the integer bit of a normal value is implied rather than
    /// stored.
    pub const fn jbit_implied(&self) -> bool {
        self.jbit_implied
    }

    /// The decimal digits of precision the format guarantees (the C++
    /// `decimalMinPrecision`): `floor(frac_size * 0.30103)`.
    pub const fn decimal_min_precision(&self) -> u32 {
        self.frac_size * 30103 / 100_000
    }

    /// The decimal digits needed to identify every value of the format (the
    /// C++ `decimalMaxPrecision`): `ceil((frac_size + 1) * 0.30103) + 1`.
    pub const fn decimal_max_precision(&self) -> u32 {
        ((self.frac_size + 1) * 30103).div_ceil(100_000) + 1
    }

    /// The number of significant decimal digits Java displays for the format
    /// (the precision of its `displayContext`).
    pub const fn display_precision(&self) -> u32 {
        self.display_precision
    }

    /// Whether the host level can compute with the format: the encoding fits
    /// a `u64` and the integer bit is implied. These are the formats the C++
    /// can construct, plus binary16.
    pub const fn is_host_format(&self) -> bool {
        self.size <= 8 && self.jbit_implied
    }
}

/// A table from operand size to floating-point format, which the float
/// operations are evaluated against.
///
/// Ghidra reaches the format through `Translate::getFloatFormat` (C++) or
/// `FloatFormatFactory` (Java); here the caller passes the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatFormats {
    formats: [Option<FloatFormat>; Self::CAPACITY],
}

impl FloatFormats {
    /// The largest number of formats a table holds.
    pub const CAPACITY: usize = 8;

    /// The formats the decompiler uses: 4 and 8 bytes
    /// (`Translate::setDefaultFloatFormats`).
    pub const DEFAULT: Self = Self {
        formats: [
            Some(FloatFormat::SINGLE),
            Some(FloatFormat::DOUBLE),
            None,
            None,
            None,
            None,
            None,
            None,
        ],
    };

    /// Every standard format: 2, 4, 8, 10, 16 and 32 bytes
    /// (`FloatFormatFactory`).
    pub const IEEE: Self = Self {
        formats: [
            Some(FloatFormat::SINGLE),
            Some(FloatFormat::DOUBLE),
            Some(FloatFormat::HALF),
            Some(FloatFormat::EXTENDED),
            Some(FloatFormat::QUAD),
            Some(FloatFormat::OCTUPLE),
            None,
            None,
        ],
    };

    /// A table with no formats: every float operation fails.
    pub const NONE: Self = Self {
        formats: [None; Self::CAPACITY],
    };

    /// The table with `format` added, replacing a format of the same size.
    /// `None` if the table is full.
    #[must_use]
    pub fn with(mut self, format: FloatFormat) -> Option<Self> {
        let same_size =
            |slot: &&mut Option<FloatFormat>| slot.is_some_and(|held| held.size == format.size);
        let slot = match self.formats.iter_mut().find(same_size) {
            Some(slot) => slot,
            None => self.formats.iter_mut().find(|slot| slot.is_none())?,
        };
        *slot = Some(format);
        Some(self)
    }

    /// The format for operands of `size` bytes, if the table has one.
    #[inline]
    pub fn get(&self, size: u32) -> Option<&FloatFormat> {
        self.formats
            .iter()
            .flatten()
            .find(|format| format.size == size)
    }
}

impl Default for FloatFormats {
    /// [`FloatFormats::DEFAULT`].
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_layouts_match_ghidra() {
        // (size, signbit_pos, exp_pos, exp_size, frac_size, bias, jbit, display precision)
        let table = [
            (2, 15, 10, 5, 10, 15, true, 4),
            (4, 31, 23, 8, 23, 127, true, 8),
            (8, 63, 52, 11, 52, 1023, true, 16),
            (10, 79, 64, 15, 64, 16383, false, 18),
            (16, 127, 112, 15, 112, 16383, true, 34),
            (32, 255, 236, 19, 236, 262_143, true, 71),
        ];
        for (size, signbit_pos, exp_pos, exp_size, frac_size, bias, jbit, precision) in table {
            let format = FloatFormat::ieee(size).unwrap();
            assert_eq!(format.size(), size);
            assert_eq!(format.signbit_pos, signbit_pos);
            assert_eq!(format.exp_pos, exp_pos);
            assert_eq!(format.exp_size(), exp_size);
            assert_eq!(format.frac_pos, 0);
            assert_eq!(format.frac_size(), frac_size);
            assert_eq!(format.bias(), bias);
            assert_eq!(format.jbit_implied(), jbit);
            assert_eq!(format.display_precision(), precision);
            assert_eq!(format.max_exponent(), (1 << exp_size) - 1);
            assert_eq!(format.effective_frac_size(), frac_size + u32::from(jbit));
            assert_eq!(format.is_host_format(), size <= 8);
        }
        for size in [0, 1, 3, 5, 6, 7, 9, 12, 20, 64] {
            assert_eq!(FloatFormat::ieee(size), None);
        }
    }

    #[test]
    fn decimal_precision_matches_calc_precision() {
        // floor(frac_size * 0.30103) and ceil((frac_size + 1) * 0.30103) + 1.
        assert_eq!(FloatFormat::SINGLE.decimal_min_precision(), 6);
        assert_eq!(FloatFormat::SINGLE.decimal_max_precision(), 9);
        assert_eq!(FloatFormat::DOUBLE.decimal_min_precision(), 15);
        assert_eq!(FloatFormat::DOUBLE.decimal_max_precision(), 17);
        assert_eq!(FloatFormat::HALF.decimal_min_precision(), 3);
        assert_eq!(FloatFormat::HALF.decimal_max_precision(), 5);
    }

    #[test]
    fn tables() {
        assert_eq!(FloatFormats::DEFAULT.get(4), Some(&FloatFormat::SINGLE));
        assert_eq!(FloatFormats::DEFAULT.get(8), Some(&FloatFormat::DOUBLE));
        for size in [0, 2, 10, 16, 32] {
            assert_eq!(FloatFormats::DEFAULT.get(size), None);
        }
        for size in [2, 4, 8, 10, 16, 32] {
            assert_eq!(
                FloatFormats::IEEE.get(size),
                FloatFormat::ieee(size).as_ref()
            );
        }
        assert_eq!(FloatFormats::IEEE.get(12), None);
        assert_eq!(FloatFormats::NONE.get(4), None);
        assert_eq!(FloatFormats::default(), FloatFormats::DEFAULT);

        let table = FloatFormats::NONE.with(FloatFormat::QUAD).unwrap();
        assert_eq!(table.get(16), Some(&FloatFormat::QUAD));
        assert_eq!(table.get(8), None);
        // Replacing a size does not use another slot.
        let mut custom = FloatFormat::QUAD;
        custom.display_precision = 30;
        let table = table.with(custom).unwrap();
        assert_eq!(table.get(16), Some(&custom));
        assert_eq!(table.formats.iter().flatten().count(), 1);
        // A full table refuses another size.
        let mut full = FloatFormats::NONE;
        for size in 1..=8 {
            let mut format = FloatFormat::SINGLE;
            format.size = size;
            full = full.with(format).unwrap();
        }
        let mut ninth = FloatFormat::SINGLE;
        ninth.size = 9;
        assert_eq!(full.with(ninth), None);
        assert!(full.with(FloatFormat::SINGLE).is_some());
    }
}
