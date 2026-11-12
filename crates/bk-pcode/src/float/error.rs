//! Errors of the exact float level.

/// Why an exact-level float value could not be built.
///
/// Java throws `IllegalArgumentException` or `NumberFormatException` in
/// these places.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum FloatError {
    /// The significand does not fit the format.
    #[error("unscaled value exceeds {fracbits} bits in length (length={bits})")]
    UnscaledTooLong {
        /// The bit length of the significand given.
        bits: u64,
        /// The number of significand bits the format has.
        fracbits: u32,
    },
    /// The exponent is outside the format's range.
    #[error("scale out of bounds {min} to {max} (scale={scale})")]
    ScaleOutOfBounds {
        /// The exponent given.
        scale: i32,
        /// The format's smallest exponent.
        min: i32,
        /// The format's largest exponent.
        max: i32,
    },
    /// The text is not a decimal number.
    #[error("{0:?} is not a decimal number")]
    InvalidDecimal(String),
}
