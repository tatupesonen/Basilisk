//! [`BigFloat`]: an arbitrary-precision IEEE 754 value.
//!
//! This is Ghidra's `ghidra.pcode.floatformat.BigFloat`: the value type of
//! the exact float level. Arithmetic is in [`super::arith`]; this module has
//! the representation, construction, classification and conversions.

use core::fmt;
use core::hash::{Hash, Hasher};

use num_bigint::{BigInt, BigUint, Sign};

use super::convert::round_to_f64;
use super::decimal::Decimal;
use super::error::FloatError;
use super::format::FloatFormat;

/// The kind of a [`BigFloat`] (Java's `FloatKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloatKind {
    /// A finite value, normal or subnormal.
    Finite,
    /// An infinity.
    Infinite,
    /// A quiet NaN.
    QuietNan,
    /// A signalling NaN.
    SignalingNan,
}

/// An IEEE 754 floating-point value of any precision.
///
/// A finite value is `sign * unscaled * 2^(scale - fracbits + 1)`, where
/// `fracbits` is the number of significand bits of the format *including*
/// the leading integer bit (24 for binary32, 53 for binary64, 64 for the x87
/// format, 113 for binary128) and `expbits` the width of its exponent field.
/// A normal value has an `unscaled` of exactly `fracbits` bits; a subnormal
/// has fewer and the smallest scale.
///
/// Operations compute the exact result and round to nearest, halfway cases
/// to even.
///
/// Equality is Java's `BigFloat.equals`, which compares representations:
/// same format and kind, and for finite values the same sign, scale and
/// significand (so `+0` and `-0` differ); for infinities the same sign; all
/// NaNs of one kind are equal.
#[derive(Debug, Clone)]
pub struct BigFloat {
    pub(super) fracbits: u32,
    pub(super) expbits: u32,
    pub(super) kind: FloatKind,
    pub(super) negative: bool,
    pub(super) unscaled: BigUint,
    pub(super) scale: i32,
}

/// The scale Java's `toBigDecimal` gives an infinity: `1E+65536`.
const INFINITE_DECIMAL_SCALE: i32 = -(64 * 1024);

/// `value << amount`, shifting right when `amount` is negative, as Java's
/// `BigInteger.shiftLeft` does.
pub(super) fn shift_left(value: &BigUint, amount: i64) -> BigUint {
    if amount >= 0 {
        value << amount.unsigned_abs()
    } else {
        value >> amount.unsigned_abs()
    }
}

/// `value >> amount`, shifting left when `amount` is negative, as Java's
/// `BigInteger.shiftRight` does.
pub(super) fn shift_right(value: &BigUint, amount: i64) -> BigUint {
    shift_left(value, amount.saturating_neg())
}

/// The bit length of a value as a signed count (`BigInteger.bitLength`).
pub(super) fn bit_length(value: &BigUint) -> i64 {
    i64::try_from(value.bits()).unwrap_or(i64::MAX)
}

/// The index of the lowest set bit, or -1 for zero
/// (`BigInteger.getLowestSetBit`).
pub(super) fn lowest_set_bit(value: &BigUint) -> i64 {
    value
        .trailing_zeros()
        .and_then(|zeros| i64::try_from(zeros).ok())
        .unwrap_or(-1)
}

impl BigFloat {
    /// Builds a value from its parts.
    ///
    /// # Errors
    ///
    /// As in Java, the significand must have at most `fracbits` bits and the
    /// scale must be within the format's exponent range.
    pub fn new(
        fracbits: u32,
        expbits: u32,
        kind: FloatKind,
        negative: bool,
        unscaled: BigUint,
        scale: i32,
    ) -> Result<Self, FloatError> {
        let value = Self {
            fracbits,
            expbits,
            kind,
            negative,
            unscaled,
            scale,
        };
        if value.unscaled.bits() > u64::from(fracbits) {
            return Err(FloatError::UnscaledTooLong {
                bits: value.unscaled.bits(),
                fracbits,
            });
        }
        let (min, max) = (value.min_scale(), value.max_scale());
        if scale < min || scale > max {
            return Err(FloatError::ScaleOutOfBounds { scale, min, max });
        }
        Ok(value)
    }

    /// A value whose parts are known to satisfy [`BigFloat::new`]'s checks.
    pub(super) fn from_parts(
        fracbits: u32,
        expbits: u32,
        kind: FloatKind,
        negative: bool,
        unscaled: BigUint,
        scale: i32,
    ) -> Self {
        Self {
            fracbits,
            expbits,
            kind,
            negative,
            unscaled,
            scale,
        }
    }

    /// Zero with the given sign.
    pub fn zero(fracbits: u32, expbits: u32, negative: bool) -> Self {
        let mut value = Self::from_parts(
            fracbits,
            expbits,
            FloatKind::Finite,
            negative,
            BigUint::ZERO,
            0,
        );
        value.scale = value.min_scale();
        value
    }

    /// Infinity with the given sign.
    pub fn infinity(fracbits: u32, expbits: u32, negative: bool) -> Self {
        let unscaled = BigUint::from(1u8) << fracbits.saturating_sub(1);
        let mut value = Self::from_parts(
            fracbits,
            expbits,
            FloatKind::Infinite,
            negative,
            unscaled,
            0,
        );
        value.scale = value.max_scale();
        value
    }

    /// The quiet NaN. The sign is kept in the value but never encoded.
    pub fn quiet_nan(fracbits: u32, expbits: u32, negative: bool) -> Self {
        let mut value = Self::from_parts(
            fracbits,
            expbits,
            FloatKind::QuietNan,
            negative,
            BigUint::ZERO,
            0,
        );
        value.scale = value.max_scale();
        value
    }

    /// The value of an `f32`, in the binary32 format (Java's static
    /// `FloatFormat.toBigFloat(float)`).
    pub fn from_f32(value: f32) -> Self {
        FloatFormat::SINGLE.decode_big_float_u64(u64::from(value.to_bits()))
    }

    /// The value of an `f64`, in the binary64 format (Java's static
    /// `FloatFormat.toBigFloat(double)`).
    pub fn from_f64(value: f64) -> Self {
        FloatFormat::DOUBLE.decode_big_float_u64(value.to_bits())
    }

    /// The number of significand bits of the format, including the leading
    /// integer bit.
    pub fn fracbits(&self) -> u32 {
        self.fracbits
    }

    /// The number of exponent bits of the format.
    pub fn expbits(&self) -> u32 {
        self.expbits
    }

    /// The kind of the value.
    pub fn kind(&self) -> FloatKind {
        self.kind
    }

    /// Whether the sign is negative.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The significand.
    pub fn unscaled(&self) -> &BigUint {
        &self.unscaled
    }

    /// The exponent of the leading significand bit of a normal value.
    pub fn scale(&self) -> i32 {
        self.scale
    }

    /// The largest scale of the format.
    pub fn max_scale(&self) -> i32 {
        ((1i64 << self.expbits.saturating_sub(1).min(31)) - 1).min(i64::from(i32::MAX)) as i32
    }

    /// The smallest scale of the format.
    pub fn min_scale(&self) -> i32 {
        1 - self.max_scale()
    }

    /// Whether the value is finite with a full-width significand.
    pub fn is_normal(&self) -> bool {
        self.kind == FloatKind::Finite && self.unscaled.bits() == u64::from(self.fracbits)
    }

    /// Whether the value is finite, non-zero and has a significand narrower
    /// than the format's.
    pub fn is_denormal(&self) -> bool {
        self.kind == FloatKind::Finite
            && self.unscaled != BigUint::ZERO
            && self.unscaled.bits() < u64::from(self.fracbits)
    }

    /// Whether the value is a NaN of either kind.
    pub fn is_nan(&self) -> bool {
        matches!(self.kind, FloatKind::QuietNan | FloatKind::SignalingNan)
    }

    /// Whether the value is an infinity.
    pub fn is_infinite(&self) -> bool {
        self.kind == FloatKind::Infinite
    }

    /// Whether the value is a zero of either sign.
    pub fn is_zero(&self) -> bool {
        self.kind == FloatKind::Finite && self.unscaled == BigUint::ZERO
    }

    /// The exact decimal value of a finite value; `1E+65536` with the
    /// value's sign for an infinity; `None` for a NaN (`toBigDecimal`).
    pub fn to_big_decimal(&self) -> Option<Decimal> {
        let sign = if self.negative {
            Sign::Minus
        } else {
            Sign::Plus
        };
        match self.kind {
            FloatKind::Finite => {}
            FloatKind::Infinite => {
                return Some(Decimal::new(
                    BigInt::from_biguint(sign, BigUint::from(1u8)),
                    INFINITE_DECIMAL_SCALE,
                ));
            }
            FloatKind::QuietNan | FloatKind::SignalingNan => return None,
        }
        if self.is_zero() {
            return Some(Decimal::zero());
        }
        let unused_bits = lowest_set_bit(&self.unscaled).max(0);
        let iscale = i64::from(self.scale) - i64::from(self.fracbits) + 1;
        if iscale >= -unused_bits {
            let integer = shift_left(&self.unscaled, iscale);
            return Some(Decimal::new(BigInt::from_biguint(sign, integer), 0));
        }
        // A fraction: value = odd * 2^-k = odd * 5^k * 10^-k.
        let odd = shift_right(&self.unscaled, unused_bits);
        let fraction_bits = u32::try_from(-(iscale + unused_bits)).unwrap_or(u32::MAX);
        let unscaled = odd * BigUint::from(5u8).pow(fraction_bits);
        Some(Decimal::new(
            BigInt::from_biguint(sign, unscaled),
            i32::try_from(fraction_bits).unwrap_or(i32::MAX),
        ))
    }

    /// The nearest `f64` (`doubleValue`). A NaN gives the positive quiet
    /// NaN.
    pub fn to_f64(&self) -> f64 {
        self.to_binary(53, -1022)
    }

    /// The nearest `f32` (`floatValue`). A NaN gives the positive quiet NaN.
    pub fn to_f32(&self) -> f32 {
        self.to_binary(24, -126) as f32
    }

    fn to_binary(&self, precision: u32, min_exp: i64) -> f64 {
        let magnitude = match self.kind {
            FloatKind::Finite => {
                let exp2 = i64::from(self.scale) - i64::from(self.fracbits) + 1;
                round_to_f64(&self.unscaled, false, exp2, precision, min_exp)
            }
            FloatKind::Infinite => f64::INFINITY,
            FloatKind::QuietNan | FloatKind::SignalingNan => return f64::NAN,
        };
        if self.negative { -magnitude } else { magnitude }
    }

    /// The integer part of the value, rounding towards zero
    /// (`toBigInteger`).
    ///
    /// As in Java the kind is not checked: an infinity gives its
    /// placeholder magnitude `2^max_scale` and a NaN gives zero.
    pub fn to_big_integer(&self) -> BigInt {
        let shift = i64::from(self.fracbits) - i64::from(self.scale) - 1;
        let magnitude = shift_right(&self.unscaled, shift);
        BigInt::from_biguint(
            if self.negative {
                Sign::Minus
            } else {
                Sign::Plus
            },
            magnitude,
        )
    }

    /// A binary rendering for diagnostics, such as `-0b1.01 * 2^3`
    /// (`toBinaryString`).
    pub fn to_binary_string(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        match self.kind {
            FloatKind::QuietNan => return "qNaN".to_owned(),
            FloatKind::SignalingNan => return "sNaN".to_owned(),
            FloatKind::Infinite => return format!("{}inf", if self.negative { '-' } else { '+' }),
            FloatKind::Finite => {}
        }
        let bits = self.unscaled.to_str_radix(2);
        let mut binary = if self.is_normal() {
            format!("1.{}", bits.get(1..).unwrap_or(""))
        } else {
            if self.unscaled == BigUint::ZERO {
                return format!("{sign}0b0.0");
            }
            let padding = (self.fracbits as usize).saturating_sub(bits.len() + 1);
            format!("0.{}{bits}", "0".repeat(padding))
        };
        binary.truncate(binary.trim_end_matches('0').len());
        if binary.ends_with('.') {
            binary.push('0');
        }
        format!("{sign}0b{binary} * 2^{}", self.scale)
    }

    /// `NaN`, `+Infinity`, `-Infinity`, `0.0` or `-0.0` for the values that
    /// have no decimal digits to round (`formatSpecialCase`).
    pub(super) fn format_special_case(&self) -> Option<&'static str> {
        if self.is_nan() {
            Some("NaN")
        } else if self.is_infinite() {
            Some(if self.negative {
                "-Infinity"
            } else {
                "+Infinity"
            })
        } else if self.is_zero() {
            Some(if self.negative { "-0.0" } else { "0.0" })
        } else {
            None
        }
    }

    /// The decimal text of the value rounded to `precision` significant
    /// digits (`toString(MathContext)` with `HALF_EVEN`).
    pub fn to_string_with_precision(&self, precision: u32) -> String {
        match (self.format_special_case(), self.to_big_decimal()) {
            (Some(special), _) => special.to_owned(),
            (None, Some(decimal)) => decimal.round(precision).to_string(),
            (None, None) => "NaN".to_owned(),
        }
    }
}

impl fmt::Display for BigFloat {
    /// The decimal text of the value rounded to the format's default
    /// precision, `floor(0.30103 * fracbits)` digits (`toString`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let precision = (u64::from(self.fracbits) * 30103 / 100_000) as u32;
        f.write_str(&self.to_string_with_precision(precision))
    }
}

impl PartialEq for BigFloat {
    fn eq(&self, other: &Self) -> bool {
        if self.expbits != other.expbits
            || self.fracbits != other.fracbits
            || self.kind != other.kind
        {
            return false;
        }
        match self.kind {
            FloatKind::Finite => {
                self.negative == other.negative
                    && self.scale == other.scale
                    && self.unscaled == other.unscaled
            }
            FloatKind::Infinite => self.negative == other.negative,
            FloatKind::QuietNan | FloatKind::SignalingNan => true,
        }
    }
}

impl Eq for BigFloat {}

impl Hash for BigFloat {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expbits.hash(state);
        self.fracbits.hash(state);
        self.kind.hash(state);
        match self.kind {
            FloatKind::Finite => {
                self.negative.hash(state);
                self.scale.hash(state);
                self.unscaled.hash(state);
            }
            FloatKind::Infinite => self.negative.hash(state),
            FloatKind::QuietNan | FloatKind::SignalingNan => {}
        }
    }
}
