//! [`Decimal`]: an arbitrary-precision decimal number with the semantics of
//! Java's `BigDecimal`, as far as Ghidra's float formatting uses it.
//!
//! Ghidra's `BigFloat.toBigDecimal`, `FloatFormat.round`,
//! `FloatFormat.toDecimalString` and `FloatFormat.getBigFloat(BigDecimal)`
//! are defined in terms of `BigDecimal`: its `MathContext` rounding, its
//! canonical `toString` (when it switches to scientific notation and how it
//! writes the exponent) and its `String` constructor. Those rules decide the
//! text basilisk prints for a float, so they are implemented here on top of
//! `num_bigint`; a general decimal crate formats and parses by different
//! rules.

use core::fmt;
use core::str::FromStr;

use num_bigint::{BigInt, BigUint, Sign};

use super::convert::round_to_f64;
use super::error::FloatError;

/// The value `unscaled * 10^-scale`.
///
/// Equality is Java's `BigDecimal.equals`: the same unscaled value *and* the
/// same scale, so `2.0` and `2.00` differ.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Decimal {
    unscaled: BigInt,
    scale: i32,
}

/// `10^exp`.
pub(crate) fn pow10(exp: u32) -> BigUint {
    BigUint::from(10u8).pow(exp)
}

impl Decimal {
    /// The value `unscaled * 10^-scale`.
    pub fn new(unscaled: BigInt, scale: i32) -> Self {
        Self { unscaled, scale }
    }

    /// Zero with scale 0 (`BigDecimal.ZERO`).
    pub fn zero() -> Self {
        Self::new(BigInt::ZERO, 0)
    }

    /// The unscaled value.
    pub fn unscaled(&self) -> &BigInt {
        &self.unscaled
    }

    /// The scale: the number of digits to the right of the decimal point,
    /// negative when the unscaled value is multiplied by a power of ten.
    pub fn scale(&self) -> i32 {
        self.scale
    }

    /// -1, 0 or 1 as the value is negative, zero or positive.
    pub fn signum(&self) -> i32 {
        match self.unscaled.sign() {
            Sign::Minus => -1,
            Sign::NoSign => 0,
            Sign::Plus => 1,
        }
    }

    /// The number of decimal digits in the unscaled value; 1 for zero.
    pub fn precision(&self) -> u32 {
        self.digits().len() as u32
    }

    /// The decimal digits of the magnitude of the unscaled value.
    fn digits(&self) -> String {
        self.unscaled.magnitude().to_string()
    }

    /// The value with its sign flipped.
    #[must_use]
    pub fn negate(&self) -> Self {
        Self::new(-&self.unscaled, self.scale)
    }

    /// Rounds to at most `precision` significant digits, halfway cases to
    /// the even digit (`BigDecimal.round` with a `HALF_EVEN` `MathContext`).
    /// A precision of 0 means unlimited and returns the value unchanged.
    #[must_use]
    pub fn round(&self, precision: u32) -> Self {
        let mut value = self.clone();
        if precision == 0 {
            return value;
        }
        // A carry out of the top digit (999 -> 1000) needs a second pass.
        loop {
            let digits = value.precision();
            if digits <= precision {
                return value;
            }
            let drop = digits - precision;
            let divisor = pow10(drop);
            let magnitude = value.unscaled.magnitude();
            let mut quotient = magnitude / &divisor;
            let twice_remainder = (magnitude % &divisor) << 1u32;
            let round_up = match twice_remainder.cmp(&divisor) {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Equal => quotient.bit(0),
                core::cmp::Ordering::Less => false,
            };
            if round_up {
                quotient += 1u32;
            }
            value = Self::new(
                BigInt::from_biguint(value.unscaled.sign(), quotient),
                value.scale.saturating_sub(drop as i32),
            );
        }
    }

    /// The same value with the given scale, or `None` if that would lose
    /// digits (`BigDecimal.setScale` without a rounding mode, which throws
    /// `ArithmeticException` then).
    pub fn with_scale(&self, scale: i32) -> Option<Self> {
        let unscaled = if scale >= self.scale {
            let raise = u32::try_from(i64::from(scale) - i64::from(self.scale)).ok()?;
            &self.unscaled * BigInt::from(pow10(raise))
        } else {
            let lower = u32::try_from(i64::from(self.scale) - i64::from(scale)).ok()?;
            let divisor = BigInt::from(pow10(lower));
            if &self.unscaled % &divisor != BigInt::ZERO {
                return None;
            }
            &self.unscaled / divisor
        };
        Some(Self::new(unscaled, scale))
    }

    /// The integer part of the value (`BigDecimal.toBigInteger`).
    pub fn to_bigint(&self) -> BigInt {
        match u32::try_from(self.scale) {
            Ok(lower) => &self.unscaled / BigInt::from(pow10(lower)),
            Err(_) => &self.unscaled * BigInt::from(pow10(self.scale.unsigned_abs())),
        }
    }

    /// The nearest `f64`, halfway cases to even (`BigDecimal.doubleValue`).
    /// Zero converts to positive zero.
    pub fn to_f64(&self) -> f64 {
        self.to_binary(53, -1022)
    }

    /// The nearest `f32`, halfway cases to even (`BigDecimal.floatValue`).
    /// Zero converts to positive zero.
    pub fn to_f32(&self) -> f32 {
        // Already rounded to the `f32` grid, so the cast is exact (or the
        // overflow to infinity).
        self.to_binary(24, -126) as f32
    }

    /// The value rounded once to `precision` significant bits, with
    /// `min_exp` the exponent of the smallest normal value.
    fn to_binary(&self, precision: u32, min_exp: i64) -> f64 {
        let magnitude = self.unscaled.magnitude();
        let negative = self.unscaled.sign() == Sign::Minus;
        let rounded = match u32::try_from(self.scale) {
            // An integer.
            Err(_) | Ok(0) => {
                let integer = magnitude * pow10(self.scale.unsigned_abs());
                round_to_f64(&integer, false, 0, precision, min_exp)
            }
            // A ratio: scale the numerator so the quotient carries more than
            // 64 significant bits, and keep the remainder as a sticky bit.
            Ok(lower) => {
                let divisor = pow10(lower);
                let shift = (divisor.bits() + 64).saturating_sub(magnitude.bits());
                let numerator = magnitude << shift;
                let quotient = &numerator / &divisor;
                let sticky = numerator % &divisor != BigUint::ZERO;
                let exp2 = -i64::try_from(shift).unwrap_or(i64::MAX);
                round_to_f64(&quotient, sticky, exp2, precision, min_exp)
            }
        };
        if negative { -rounded } else { rounded }
    }
}

impl From<BigInt> for Decimal {
    /// The integer with scale 0 (`new BigDecimal(BigInteger)`).
    fn from(unscaled: BigInt) -> Self {
        Self::new(unscaled, 0)
    }
}

impl fmt::Display for Decimal {
    /// Java's `BigDecimal.toString`: plain notation when the scale is not
    /// negative and the adjusted exponent is at least -6, otherwise
    /// scientific notation (`1.23E+7`, `4.9E-324`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.digits();
        if self.unscaled.sign() == Sign::Minus {
            f.write_str("-")?;
        }
        if self.scale == 0 {
            return f.write_str(&digits);
        }
        let len = digits.len() as i64;
        let scale = i64::from(self.scale);
        let adjusted = len - 1 - scale;
        if scale >= 0 && adjusted >= -6 {
            if scale >= len {
                f.write_str("0.")?;
                for _ in len..scale {
                    f.write_str("0")?;
                }
                f.write_str(&digits)
            } else {
                let (whole, fraction) = digits
                    .split_at_checked((len - scale) as usize)
                    .unwrap_or((&digits, ""));
                write!(f, "{whole}.{fraction}")
            }
        } else {
            let (first, rest) = digits.split_at_checked(1).unwrap_or((&digits, ""));
            f.write_str(first)?;
            if !rest.is_empty() {
                write!(f, ".{rest}")?;
            }
            match adjusted {
                0 => Ok(()),
                1.. => write!(f, "E+{adjusted}"),
                _ => write!(f, "E{adjusted}"),
            }
        }
    }
}

impl FromStr for Decimal {
    type Err = FloatError;

    /// Java's `new BigDecimal(String)`: an optional sign, digits with an
    /// optional decimal point, and an optional exponent (`e` or `E`, an
    /// optional sign, digits).
    fn from_str(text: &str) -> Result<Self, FloatError> {
        let error = || FloatError::InvalidDecimal(text.to_owned());
        let (negative, body) = match text.as_bytes().first() {
            Some(b'-') => (true, text.get(1..).ok_or_else(error)?),
            Some(b'+') => (false, text.get(1..).ok_or_else(error)?),
            _ => (false, text),
        };
        let (mantissa, exponent) = match body.find(['e', 'E']) {
            Some(at) => {
                let (mantissa, exponent) = body.split_at_checked(at).ok_or_else(error)?;
                let exponent = exponent.get(1..).ok_or_else(error)?;
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(error());
                }
                let exponent = exponent.strip_prefix('+').unwrap_or(exponent);
                (
                    mantissa,
                    exponent.parse::<i32>().map_err(|_overflow| error())?,
                )
            }
            None => (body, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let all_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
        if (whole.is_empty() && fraction.is_empty()) || !all_digits(whole) || !all_digits(fraction)
        {
            return Err(error());
        }
        let digits = [whole, fraction].concat();
        let magnitude = BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(error)?;
        let sign = if negative { Sign::Minus } else { Sign::Plus };
        let scale =
            i64::try_from(fraction.len()).map_err(|_overflow| error())? - i64::from(exponent);
        let scale = i32::try_from(scale).map_err(|_overflow| error())?;
        Ok(Self::new(BigInt::from_biguint(sign, magnitude), scale))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(text: &str) -> Decimal {
        text.parse().unwrap()
    }

    #[test]
    fn parses_like_big_decimal() {
        let cases = [
            ("0", 0, 0),
            ("0.0", 0, 1),
            ("1", 1, 0),
            ("-1", -1, 0),
            ("+12", 12, 0),
            ("1.5", 15, 1),
            ("-0.001", -1, 3),
            ("001.50", 150, 2),
            (".5", 5, 1),
            ("5.", 5, 0),
            ("1e3", 1, -3),
            ("1E+3", 1, -3),
            ("1.25E-2", 125, 4),
            ("-12.5e1", -125, 0),
            ("4.9E-324", 49, 325),
        ];
        for (text, unscaled, scale) in cases {
            let value = dec(text);
            assert_eq!(value.unscaled(), &BigInt::from(unscaled), "{text}");
            assert_eq!(value.scale(), scale, "{text}");
        }
        for text in [
            "",
            "+",
            "-",
            ".",
            "e5",
            "1e",
            "1e+",
            "1.2.3",
            "1,5",
            " 1",
            "1 ",
            "0x10",
            "NaN",
            "1e99999999999",
            "--1",
            "1e-+2",
        ] {
            assert_eq!(
                text.parse::<Decimal>(),
                Err(FloatError::InvalidDecimal(text.to_owned())),
                "{text:?}"
            );
        }
    }

    #[test]
    fn formats_like_big_decimal_to_string() {
        let cases = [
            (0, 0, "0"),
            (0, 1, "0.0"),
            (0, -2, "0E+2"),
            (0, 7, "0E-7"),
            (0, 6, "0.000000"),
            (123, 0, "123"),
            (-123, 0, "-123"),
            (123, 1, "12.3"),
            (123, 3, "0.123"),
            (123, 5, "0.00123"),
            (123, 8, "0.00000123"),
            (123, 9, "1.23E-7"),
            (-123, 9, "-1.23E-7"),
            (123, -1, "1.23E+3"),
            (1, -1, "1E+1"),
            (1, 7, "1E-7"),
            (1, 6, "0.000001"),
            (12, -5, "1.2E+6"),
            (49, 325, "4.9E-324"),
            (5, 1, "0.5"),
        ];
        for (unscaled, scale, text) in cases {
            assert_eq!(
                Decimal::new(BigInt::from(unscaled), scale).to_string(),
                text
            );
        }
        assert_eq!(
            dec("1.7976931348623157E+308").to_string(),
            "1.7976931348623157E+308"
        );
        assert_eq!(
            dec("1.7976931348623157E308").to_string(),
            "1.7976931348623157E+308"
        );
    }

    #[test]
    fn rounds_half_even_to_a_precision() {
        let cases = [
            ("123456", 3, "1.23E+5"),
            ("123500", 3, "1.24E+5"),
            ("122500", 3, "1.22E+5"),
            ("122501", 3, "1.23E+5"),
            ("-122500", 3, "-1.22E+5"),
            ("-123500", 3, "-1.24E+5"),
            ("999.96", 4, "1000"),
            ("9.9996", 4, "10.00"),
            ("0.099996", 4, "0.1000"),
            ("1.5", 1, "2"),
            ("2.5", 1, "2"),
            ("12.3", 5, "12.3"),
            ("12.3", 0, "12.3"),
            ("0", 3, "0"),
        ];
        for (text, precision, rounded) in cases {
            assert_eq!(
                dec(text).round(precision).to_string(),
                rounded,
                "{text} to {precision}"
            );
        }
        assert_eq!(dec("999.96").round(4), Decimal::new(BigInt::from(1000), 0));
        assert_eq!(dec("9995").round(3), Decimal::new(BigInt::from(100), -2));
    }

    #[test]
    fn precision_signum_negate() {
        assert_eq!(dec("0").precision(), 1);
        assert_eq!(dec("0.000").precision(), 1);
        assert_eq!(dec("-123.45").precision(), 5);
        assert_eq!(dec("-123.45").signum(), -1);
        assert_eq!(dec("0.0").signum(), 0);
        assert_eq!(dec("7").signum(), 1);
        assert_eq!(dec("-123.45").negate(), dec("123.45"));
        assert_eq!(Decimal::zero(), dec("0"));
        assert_ne!(dec("2.0"), dec("2.00"));
        assert_eq!(Decimal::from(BigInt::from(42)), dec("42"));
    }

    #[test]
    fn rescales_exactly_or_not_at_all() {
        assert_eq!(dec("1.5").with_scale(3), Some(dec("1.500")));
        assert_eq!(dec("1.500").with_scale(1), Some(dec("1.5")));
        assert_eq!(dec("1.5").with_scale(0), None);
        assert_eq!(
            dec("1500").with_scale(-2),
            Some(Decimal::new(BigInt::from(15), -2))
        );
        assert_eq!(dec("1E+3").with_scale(0), Some(dec("1000")));
        assert_eq!(dec("-0.125").with_scale(2), None);
    }

    #[test]
    fn integer_part() {
        assert_eq!(dec("123.99").to_bigint(), BigInt::from(123));
        assert_eq!(dec("-123.99").to_bigint(), BigInt::from(-123));
        assert_eq!(dec("1.5E+3").to_bigint(), BigInt::from(1500));
        assert_eq!(dec("0.5").to_bigint(), BigInt::ZERO);
    }

    #[test]
    fn converts_to_the_nearest_binary_float() {
        // Agreement with the standard library's correctly rounded parser.
        let texts = [
            "0",
            "1",
            "-1",
            "0.1",
            "2.5",
            "123456789.125",
            "1.7976931348623157E+308",
            "1.7976931348623158E+308",
            "1.7976931348623159E+308",
            "1E+400",
            "-1E+400",
            "4.9E-324",
            "2.4703282292062327E-324",
            "2.4703282292062328E-324",
            "2.2250738585072014E-308",
            "2.2250738585072011E-308",
            "1E-400",
            "9007199254740993",
            "9007199254740995",
            "0.30000000000000004",
            "1.00000000000000011102230246251565404236316680908203125",
            "1.00000000000000011102230246251565404236316680908203126",
            "3.4028235E+38",
            "3.4028236E+38",
            "1.4E-45",
            "7.0064923216240854E-46",
            "7.0064923216240853E-46",
            "16777217",
        ];
        for text in texts {
            let value = dec(text);
            let plain = text.replace("E+", "e").replace('E', "e");
            assert_eq!(
                value.to_f64().to_bits(),
                plain.parse::<f64>().unwrap().to_bits(),
                "{text}"
            );
            assert_eq!(
                value.to_f32().to_bits(),
                plain.parse::<f32>().unwrap().to_bits(),
                "{text}"
            );
        }
        assert_eq!(dec("-0.0").to_f64().to_bits(), 0.0f64.to_bits());
        assert_eq!(dec("-2.5").to_f64(), -2.5);
    }
}
