//! Decimal text for floating-point values.
//!
//! Two printers, as in Ghidra:
//!
//! - [`FloatFormat::print_decimal`]: the decompiler's (`printDecimal` in
//!   `float.cc`), for a host `f64`: the fewest digits that read back as the
//!   same value, in C's `%g` or `%e` style.
//! - [`FloatFormat::to_decimal_string`]: Java's (`toDecimalString`,
//!   `BigFloat.toString(FloatFormat, boolean)`), for a [`BigFloat`] of any
//!   precision.

use super::bigfloat::BigFloat;
use super::decimal::Decimal;
use super::format::FloatFormat;

/// Splits Rust's `{:e}` output into its mantissa text and exponent.
fn split_exponent(text: &str) -> (&str, i32) {
    let (mantissa, exponent) = text.split_once('e').unwrap_or((text, "0"));
    (mantissa, exponent.parse().unwrap_or(0))
}

/// C's `%.{precision}e`: one digit, `precision` decimals, and an exponent
/// with a sign and at least two digits.
fn format_scientific(host: f64, precision: usize) -> String {
    let text = format!("{host:.precision$e}");
    let (mantissa, exponent) = split_exponent(&text);
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent.unsigned_abs())
}

/// C's `%.{precision}g`: `precision` significant digits (at least one),
/// fixed notation when the exponent is in `-4..precision`, scientific
/// otherwise, with trailing zeros removed.
fn format_general(host: f64, precision: usize) -> String {
    let precision = precision.max(1);
    let scientific = format!("{host:.*e}", precision - 1);
    let (mantissa, exponent) = split_exponent(&scientific);
    let strip = |text: &str| {
        if text.contains('.') {
            text.trim_end_matches('0').trim_end_matches('.').to_owned()
        } else {
            text.to_owned()
        }
    };
    if exponent < -4 || i64::from(exponent) >= precision as i64 {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{sign}{:02}", strip(mantissa), exponent.unsigned_abs())
    } else {
        let decimals = (precision as i64 - 1 - i64::from(exponent)).max(0) as usize;
        strip(&format!("{host:.decimals$}"))
    }
}

/// Reads decimal text back as C++ stream extraction does: an overflow gives
/// the largest finite value rather than infinity.
fn read_back(text: &str, single: bool) -> f64 {
    if single {
        let value: f32 = text.parse().unwrap_or(0.0);
        f64::from(if value.is_infinite() {
            f32::MAX.copysign(value)
        } else {
            value
        })
    } else {
        let value: f64 = text.parse().unwrap_or(0.0);
        if value.is_infinite() {
            f64::MAX.copysign(value)
        } else {
            value
        }
    }
}

/// Removes the last digit of the fraction of a decimal string, keeping any
/// exponent, unless that would leave fewer than `min_digits` fraction digits
/// (`removeFractionalDigit`). With `zero_only`, only a `0` is removed.
fn remove_fractional_digit(text: &str, min_digits: usize, zero_only: bool) -> Option<String> {
    let point = text.find('.')?;
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) if at > 0 => text.split_at_checked(at)?,
        _ => (text, ""),
    };
    if mantissa.len().saturating_sub(point + 1) <= min_digits {
        return None;
    }
    if zero_only && !mantissa.ends_with('0') {
        return None;
    }
    let shortened = mantissa.get(..mantissa.len() - 1)?;
    Some(format!("{shortened}{exponent}"))
}

impl FloatFormat {
    /// Prints a host value with the fewest digits that identify it in this
    /// format, between the format's minimum and maximum decimal precision
    /// (`printDecimal`). With `force_sci` the text is always in scientific
    /// notation.
    ///
    /// Infinities and NaNs print as `inf`, `-inf`, `nan` and `-nan`.
    pub fn print_decimal(&self, host: f64, force_sci: bool) -> String {
        if host.is_nan() {
            return if host.is_sign_negative() {
                "-nan"
            } else {
                "nan"
            }
            .to_owned();
        }
        if host.is_infinite() {
            return if host < 0.0 { "-inf" } else { "inf" }.to_owned();
        }
        let max_precision = self.decimal_max_precision() as usize;
        let mut precision = self.decimal_min_precision() as usize;
        loop {
            let text = if force_sci {
                format_scientific(host, precision.saturating_sub(1))
            } else {
                format_general(host, precision)
            };
            if precision >= max_precision || read_back(&text, self.size <= 4) == host {
                return text;
            }
            precision += 1;
        }
    }

    /// The exact decimal value of `value` rounded to this format's display
    /// precision; `None` for a NaN (`round`).
    pub fn round_decimal(&self, value: &BigFloat) -> Option<Decimal> {
        value
            .to_big_decimal()
            .map(|decimal| decimal.round(self.display_precision))
    }

    /// The decimal text of `value` at this format's display precision
    /// (`toDecimalString`).
    ///
    /// With `compact`, digits are then removed from the end of the fraction
    /// for as long as the shorter text still converts back to the same
    /// encoding. Trailing zeros are removed either way, and `.0` is appended
    /// to a text without a decimal point (which, as in Java, includes
    /// scientific notation with a one-digit mantissa: `1E+10.0`).
    #[expect(
        clippy::wrong_self_convention,
        reason = "converts `value`, not `self`; named after Java's `toDecimalString`"
    )]
    pub fn to_decimal_string(&self, value: &BigFloat, compact: bool) -> String {
        if let Some(special) = value.format_special_case() {
            return special.to_owned();
        }
        let Some(decimal) = self.round_decimal(value) else {
            return "NaN".to_owned();
        };
        let mut text = decimal.to_string();
        if compact && decimal.precision() > 2 {
            let encoding = self.encode_big_float(value);
            let mut candidate = remove_fractional_digit(&text, 1, false);
            while let Some(shorter) = candidate.take() {
                // Keep the scale, which the conversion back depends on.
                let same = shorter
                    .parse::<Decimal>()
                    .ok()
                    .and_then(|parsed| parsed.with_scale(decimal.scale()))
                    .is_some_and(|parsed| {
                        self.encode_big_float(&self.big_float_from_decimal(&parsed)) == encoding
                    });
                if same {
                    candidate = remove_fractional_digit(&shorter, 1, false);
                    text = shorter;
                }
            }
        }
        while let Some(shorter) = remove_fractional_digit(&text, 1, true) {
            text = shorter;
        }
        if !text.contains('.') {
            text.push_str(".0");
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_style_formatting() {
        assert_eq!(format_scientific(0.123, 14), "1.23000000000000e-01");
        assert_eq!(format_scientific(-1.5e100, 2), "-1.50e+100");
        assert_eq!(format_scientific(0.0, 3), "0.000e+00");
        assert_eq!(format_scientific(9.99, 0), "1e+01");
        assert_eq!(format_general(0.25, 6), "0.25");
        assert_eq!(format_general(100_000.0, 6), "100000");
        assert_eq!(format_general(1_000_000.0, 6), "1e+06");
        assert_eq!(format_general(0.0001, 6), "0.0001");
        assert_eq!(format_general(0.000_01, 6), "1e-05");
        assert_eq!(format_general(1.192_092_9e-7, 7), "1.192093e-07");
        assert_eq!(format_general(123_456_789.0, 3), "1.23e+08");
        assert_eq!(format_general(99.99, 3), "100");
        assert_eq!(format_general(999.9, 3), "1e+03");
        assert_eq!(format_general(-0.0, 6), "-0");
        assert_eq!(format_general(0.0, 6), "0");
        assert_eq!(format_general(1.5, 0), "2");
        assert_eq!(format_general(0.1, 17), "0.10000000000000001");
    }

    #[test]
    fn reads_back_like_a_cpp_stream() {
        assert_eq!(read_back("1.5", false), 1.5);
        assert_eq!(read_back("1.79769313486232e+308", false), f64::MAX);
        assert_eq!(read_back("-1e999", false), -f64::MAX);
        assert_eq!(read_back("3.5e38", true), f64::from(f32::MAX));
        assert_eq!(read_back("0.1", true), f64::from(0.1f32));
        assert_eq!(read_back("junk", false), 0.0);
    }

    #[test]
    fn print_decimal_specials() {
        let f8 = FloatFormat::DOUBLE;
        assert_eq!(f8.print_decimal(f64::INFINITY, false), "inf");
        assert_eq!(f8.print_decimal(f64::NEG_INFINITY, true), "-inf");
        assert_eq!(f8.print_decimal(f64::NAN, false), "nan");
        assert_eq!(f8.print_decimal(-f64::NAN, false), "-nan");
        assert_eq!(f8.print_decimal(0.0, false), "0");
        assert_eq!(f8.print_decimal(-0.0, false), "-0");
        assert_eq!(f8.print_decimal(1.0, false), "1");
        assert_eq!(f8.print_decimal(1.0, true), "1.00000000000000e+00");
        assert_eq!(f8.print_decimal(0.1 + 0.2, false), "0.30000000000000004");
    }

    #[test]
    fn remove_fractional_digit_rules() {
        assert_eq!(
            remove_fractional_digit("1.250", 1, true).as_deref(),
            Some("1.25")
        );
        assert_eq!(remove_fractional_digit("1.25", 1, true), None);
        assert_eq!(
            remove_fractional_digit("1.25", 1, false).as_deref(),
            Some("1.2")
        );
        assert_eq!(remove_fractional_digit("1.2", 1, false), None);
        assert_eq!(remove_fractional_digit("125", 1, false), None);
        assert_eq!(
            remove_fractional_digit("1.250E+10", 1, true).as_deref(),
            Some("1.25E+10")
        );
        assert_eq!(
            remove_fractional_digit("1.25E-7", 1, false).as_deref(),
            Some("1.2E-7")
        );
        assert_eq!(remove_fractional_digit("1.0E-7", 1, true), None);
    }

    #[test]
    fn to_decimal_string_basics() {
        let f8 = FloatFormat::DOUBLE;
        let text =
            |value: f64, compact: bool| f8.to_decimal_string(&BigFloat::from_f64(value), compact);
        assert_eq!(text(0.0, false), "0.0");
        assert_eq!(text(-0.0, true), "-0.0");
        assert_eq!(text(f64::NAN, false), "NaN");
        assert_eq!(text(f64::INFINITY, false), "+Infinity");
        assert_eq!(text(f64::NEG_INFINITY, true), "-Infinity");
        assert_eq!(text(1.0, false), "1.0");
        assert_eq!(text(-2.5, false), "-2.5");
        assert_eq!(text(0.1, false), "0.1");
        assert_eq!(text(0.1, true), "0.1");
        assert_eq!(text(1.0 / 3.0, false), "0.3333333333333333");
        assert_eq!(text(1e10, false), "10000000000.0");
        assert_eq!(text(1e300, true), "1.0E+300");
        assert_eq!(text(1e-7, false), "1.0E-7");
        assert_eq!(text(123_456.789, true), "123456.789");
        assert_eq!(text(f64::MAX, false), "1.797693134862316E+308");
        assert_eq!(text(5e-324, false), "4.940656458412465E-324");
        assert_eq!(text(5e-324, true), "4.9E-324");
        assert_eq!(f8.round_decimal(&BigFloat::from_f64(f64::NAN)), None);
        assert_eq!(
            f8.round_decimal(&BigFloat::from_f64(0.5))
                .map(|d| d.to_string())
                .as_deref(),
            Some("0.5")
        );
    }
}
