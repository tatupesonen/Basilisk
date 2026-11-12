//! The exact float level of a [`FloatFormat`]: decoding an encoding to a
//! [`BigFloat`], encoding one back with round-to-nearest-even, and building
//! values from integers, decimals and native floats.
//!
//! This is the `BigInteger`/`BigFloat` half of Ghidra's
//! `ghidra.pcode.floatformat.FloatFormat`. Encodings are held in a
//! [`Wide`].

use num_bigint::{BigInt, BigUint, Sign};

use super::bigfloat::{BigFloat, FloatKind, bit_length, lowest_set_bit, shift_left, shift_right};
use super::convert::round_to_f64;
use super::decimal::{Decimal, pow10};
use super::error::FloatError;
use super::format::FloatFormat;
use crate::wide::Wide;

/// Shifts `i`, whose lead bit is at some position, so the lead bit lands on
/// `new_lead_bit`: a left shift, or a right shift rounded to nearest even.
/// The round up may carry into bit `new_lead_bit + 1`
/// (`roundToLeadBit`).
fn round_to_lead_bit(i: &BigUint, new_lead_bit: i64) -> BigUint {
    let amt = bit_length(i) - 1 - new_lead_bit;
    if amt <= 0 {
        return shift_left(i, -amt);
    }
    let midbit = amt - 1;
    let midset = i.bit(midbit.unsigned_abs());
    let eps = lowest_set_bit(i) < midbit;
    let mut rounded = shift_right(i, amt);
    if midset && (eps || rounded.bit(0)) {
        rounded += 1u32;
    }
    rounded
}

impl FloatFormat {
    fn frac_mask(&self) -> Wide {
        !(Wide::MAX << self.frac_size)
    }

    fn big_fraction(&self, encoding: &Wide) -> Wide {
        (*encoding >> self.frac_pos) & self.frac_mask()
    }

    fn big_exponent_code(&self, encoding: &Wide) -> i32 {
        ((*encoding >> self.exp_pos).low_u64() & self.max_exponent() as u64) as i32
    }

    fn big_sign(&self, encoding: &Wide) -> bool {
        encoding.bit(self.signbit_pos)
    }

    fn with_sign(&self, encoding: Wide, negative: bool) -> Wide {
        if negative {
            encoding | (Wide::ONE << self.signbit_pos)
        } else {
            encoding
        }
    }

    /// The encoding of zero with the given sign (`getBigZeroEncoding`).
    pub fn big_zero_encoding(&self, negative: bool) -> Wide {
        self.with_sign(Wide::ZERO, negative)
    }

    /// The encoding of infinity with the given sign
    /// (`getBigInfinityEncoding`).
    pub fn big_infinity_encoding(&self, negative: bool) -> Wide {
        self.with_sign(
            Wide::from_u64(self.max_exponent() as u64) << self.exp_pos,
            negative,
        )
    }

    /// The encoding of the quiet NaN with the given sign
    /// (`getBigNaNEncoding`).
    pub fn big_nan_encoding(&self, negative: bool) -> Wide {
        let quiet = Wide::ONE << (self.frac_pos + self.frac_size).saturating_sub(1);
        self.with_sign(
            quiet | (Wide::from_u64(self.max_exponent() as u64) << self.exp_pos),
            negative,
        )
    }

    /// Zero of this format with the given sign (`getBigZero`).
    pub fn big_zero(&self, negative: bool) -> BigFloat {
        BigFloat::zero(self.effective_frac_size(), self.exp_size, negative)
    }

    /// Infinity of this format with the given sign (`getBigInfinity`).
    pub fn big_infinity(&self, negative: bool) -> BigFloat {
        BigFloat::infinity(self.effective_frac_size(), self.exp_size, negative)
    }

    /// The quiet NaN of this format (`getBigNaN`).
    pub fn big_nan(&self, negative: bool) -> BigFloat {
        BigFloat::quiet_nan(self.effective_frac_size(), self.exp_size, negative)
    }

    /// The largest finite value of the format (Java's `maxValue`).
    pub fn max_value(&self) -> BigFloat {
        let fracbits = self.effective_frac_size();
        let unscaled = (BigUint::from(1u8) << fracbits) - 1u32;
        BigFloat::from_parts(
            fracbits,
            self.exp_size,
            FloatKind::Finite,
            false,
            unscaled,
            self.bias,
        )
    }

    /// The smallest positive value of the format, a subnormal (Java's
    /// `minValue`).
    pub fn min_value(&self) -> BigFloat {
        BigFloat::from_parts(
            self.effective_frac_size(),
            self.exp_size,
            FloatKind::Finite,
            false,
            BigUint::from(1u8),
            1 - self.bias,
        )
    }

    /// Decodes an encoding of at most 8 bytes (`decodeBigFloat(long)`).
    ///
    /// Unlike [`FloatFormat::decode_big_float`] this tells quiet NaNs from
    /// signalling ones.
    pub fn decode_big_float_u64(&self, encoding: u64) -> BigFloat {
        let wide = Wide::from_u64(encoding);
        let negative = self.big_sign(&wide);
        let exp = self.big_exponent_code(&wide);
        let frac = self.big_fraction(&wide);
        let mut unscaled = frac.to_biguint();
        let (kind, scale) = if exp == self.max_exponent() {
            let kind = if frac.is_zero() {
                FloatKind::Infinite
            } else if frac.bit(self.frac_size.saturating_sub(1)) {
                FloatKind::QuietNan
            } else {
                FloatKind::SignalingNan
            };
            (kind, 0)
        } else if exp == 0 {
            (FloatKind::Finite, 1 - self.bias)
        } else {
            if self.jbit_implied {
                unscaled.set_bit(u64::from(self.frac_size), true);
            }
            (FloatKind::Finite, exp - self.bias)
        };
        BigFloat::from_parts(
            self.effective_frac_size(),
            self.exp_size,
            kind,
            negative,
            unscaled,
            scale,
        )
    }

    /// Decodes an encoding (`decodeBigFloat(BigInteger)`).
    ///
    /// Every NaN decodes to the quiet NaN. For the x87 format the encoding
    /// is taken as Ghidra takes it: the 64-bit fraction field including the
    /// explicit integer bit is the significand, an exponent code of 0 marks
    /// a subnormal, and the largest exponent code is an infinity only when
    /// the whole fraction field (integer bit included) is zero.
    pub fn decode_big_float(&self, encoding: &Wide) -> BigFloat {
        let negative = self.big_sign(encoding);
        let frac = self.big_fraction(encoding);
        let exp = self.big_exponent_code(encoding);
        let fracbits = self.effective_frac_size();
        if exp == 0 {
            if frac.is_zero() {
                return self.big_zero(negative);
            }
            return BigFloat::from_parts(
                fracbits,
                self.exp_size,
                FloatKind::Finite,
                negative,
                frac.to_biguint(),
                1 - self.bias,
            );
        }
        if exp == self.max_exponent() {
            return if frac.is_zero() {
                self.big_infinity(negative)
            } else {
                self.big_nan(negative)
            };
        }
        let mut unscaled = frac.to_biguint();
        if self.jbit_implied {
            unscaled.set_bit(u64::from(self.frac_size), true);
        }
        BigFloat::from_parts(
            fracbits,
            self.exp_size,
            FloatKind::Finite,
            negative,
            unscaled,
            exp - self.bias,
        )
    }

    /// Encodes a value, rounding to nearest even when it has more precision
    /// than the format (`getEncoding(BigFloat)`).
    ///
    /// A NaN encodes as the positive quiet NaN. The x87 format has no
    /// subnormals here: a value below its smallest normal encodes as zero.
    pub fn encode_big_float(&self, value: &BigFloat) -> Wide {
        let negative = value.is_negative();
        match value.kind() {
            FloatKind::QuietNan | FloatKind::SignalingNan => return self.big_nan_encoding(false),
            FloatKind::Infinite => return self.big_infinity_encoding(negative),
            FloatKind::Finite => {}
        }
        if value.is_zero() {
            return self.big_zero_encoding(negative);
        }
        let frac_size = i64::from(self.frac_size);
        let bias = i64::from(self.bias);
        let lb_unscaled = bit_length(value.unscaled()) - 1;
        // The exponent of the lead bit, less one.
        let lead = i64::from(value.scale()) - i64::from(value.fracbits()) + lb_unscaled;
        let mut exp;
        let fraction;
        if lead >= -bias {
            // Normal.
            exp = lead + 1 + bias;
            let lead_bit = frac_size - i64::from(!self.jbit_implied);
            let mut rounded = round_to_lead_bit(value.unscaled(), lead_bit);
            if bit_length(&rounded) - 1 > lead_bit {
                // The round up carried.
                rounded >>= 1u32;
                exp += 1;
            }
            if self.jbit_implied {
                rounded.set_bit(u64::from(self.frac_size), false);
            }
            fraction = rounded;
        } else if !self.jbit_implied {
            // Subnormals are not supported.
            return self.big_zero_encoding(negative);
        } else {
            exp = 0;
            let n = lead + bias + frac_size;
            if n < 0 {
                // Exactly half the minimum subnormal ties to even (zero).
                if n < -1 || value.unscaled().count_ones() == 1 {
                    return self.big_zero_encoding(negative);
                }
                fraction = BigUint::from(1u8);
            } else {
                // A round up to 2^frac_size lands in the exponent field,
                // giving the smallest normal value.
                fraction = round_to_lead_bit(value.unscaled(), n);
            }
        }
        if exp >= i64::from(self.max_exponent()) {
            return self.big_infinity_encoding(negative);
        }
        let exponent = Wide::from_u64(exp.unsigned_abs()) << self.exp_pos;
        self.with_sign(exponent | Wide::from_biguint(&fraction), negative)
    }

    /// A [`BigFloat`] decoded in another format, re-expressed with this
    /// format's precision and exponent range without rounding
    /// (the tail of `getBigFloat(float)` and `getBigFloat(double)`).
    fn widen(&self, value: &BigFloat) -> Result<BigFloat, FloatError> {
        let fracbits = self.effective_frac_size();
        let shift = i64::from(fracbits) - i64::from(value.fracbits());
        BigFloat::new(
            fracbits,
            self.exp_size,
            value.kind(),
            value.is_negative(),
            shift_left(value.unscaled(), shift),
            value.scale(),
        )
    }

    /// The value of an `f32` in this format (`getBigFloat(float)`).
    ///
    /// # Errors
    ///
    /// As in Java, a value whose exponent is outside this format's range is
    /// rejected; a format with less precision truncates the significand.
    pub fn big_float_from_f32(&self, value: f32) -> Result<BigFloat, FloatError> {
        self.widen(&BigFloat::from_f32(value))
    }

    /// The value of an `f64` in this format (`getBigFloat(double)`).
    ///
    /// # Errors
    ///
    /// As [`FloatFormat::big_float_from_f32`].
    pub fn big_float_from_f64(&self, value: f64) -> Result<BigFloat, FloatError> {
        self.widen(&BigFloat::from_f64(value))
    }

    /// The value of an integer in this format (`getBigFloat(BigInteger)`).
    ///
    /// The 4- and 8-byte formats round to nearest even. As in Java, the
    /// other formats *truncate* an integer with more bits than the
    /// significand holds, and leave a smaller one unnormalised.
    pub fn big_float_from_int(&self, value: &BigInt) -> BigFloat {
        let negative = value.sign() == Sign::Minus;
        let magnitude = value.magnitude();
        let signed = |host: f64| if negative { -host } else { host };
        match self.size {
            8 => {
                let host = signed(round_to_f64(magnitude, false, 0, 53, -1022));
                return self
                    .big_float_from_f64(host)
                    .unwrap_or_else(|_| self.big_nan(false));
            }
            4 => {
                let host = signed(round_to_f64(magnitude, false, 0, 24, -126)) as f32;
                return self
                    .big_float_from_f32(host)
                    .unwrap_or_else(|_| self.big_nan(false));
            }
            _ => {}
        }
        let fracbits = self.effective_frac_size();
        let ulen = bit_length(magnitude);
        let (unscaled, scale) = if ulen > i64::from(fracbits) {
            let scale = ulen - 1;
            if scale > i64::from(self.bias) {
                return self.big_infinity(negative);
            }
            (
                shift_right(magnitude, ulen - i64::from(fracbits)),
                scale as i32,
            )
        } else {
            (magnitude.clone(), fracbits.saturating_sub(1) as i32)
        };
        BigFloat::from_parts(
            fracbits,
            self.exp_size,
            FloatKind::Finite,
            negative,
            unscaled,
            scale,
        )
    }

    /// The value of a decimal in this format (`getBigFloat(BigDecimal)`).
    ///
    /// The 4- and 8-byte formats give the nearest value. The other formats
    /// follow the Java: the unscaled integer and the power of ten are
    /// converted separately and then multiplied or divided, so the result
    /// can differ from the nearest value in the last place.
    pub fn big_float_from_decimal(&self, value: &Decimal) -> BigFloat {
        match self.size {
            8 => {
                let host = value.to_f64();
                return self
                    .big_float_from_f64(host)
                    .unwrap_or_else(|_| self.big_nan(false));
            }
            4 => {
                let host = value.to_f32();
                return self
                    .big_float_from_f32(host)
                    .unwrap_or_else(|_| self.big_nan(false));
            }
            _ => {}
        }
        if *value == Decimal::zero() {
            return self.big_zero(false);
        }
        let unscaled = self.big_float_from_int(value.unscaled());
        let fracbits = f64::from(self.effective_frac_size());
        match u32::try_from(value.scale()) {
            Err(_) => {
                // A negative scale: multiply by a power of ten.
                let scale10 = value.scale().unsigned_abs();
                let scalar = BigInt::from(pow10(scale10));
                if f64::from(scale10) / 0.3 > fracbits {
                    // Will be a whole integer.
                    self.big_float_from_int(&(scalar * value.unscaled()))
                } else {
                    // May have a fractional value.
                    unscaled.mul(&self.big_float_from_int(&scalar))
                }
            }
            Ok(scale10) if f64::from(scale10) / 0.3 >= f64::from(self.bias) => {
                // Divide down in two passes to avoid dividing by infinity.
                let s1 = scale10 / 2;
                let bf2 = self.big_float_from_int(&BigInt::from(pow10(scale10 - s1)));
                if bf2.is_infinite() {
                    return self.big_zero(value.signum() < 0);
                }
                let bf1 = self.big_float_from_int(&BigInt::from(pow10(s1)));
                unscaled.div(&bf1).div(&bf2)
            }
            Ok(scale10) => unscaled.div(&self.big_float_from_int(&BigInt::from(pow10(scale10)))),
        }
    }

    /// The value of a decimal string in this format
    /// (`getBigFloat(String)`): a decimal number in Java's `BigDecimal`
    /// syntax, or `NaN`, `Infinity`, `+Infinity` or `-Infinity` in any
    /// letter case.
    ///
    /// # Errors
    ///
    /// [`FloatError::InvalidDecimal`] when the text is neither.
    pub fn big_float_from_str(&self, text: &str) -> Result<BigFloat, FloatError> {
        if text.eq_ignore_ascii_case("NaN") {
            Ok(self.big_nan(false))
        } else if text.eq_ignore_ascii_case("Infinity") || text.eq_ignore_ascii_case("+Infinity") {
            Ok(self.big_infinity(false))
        } else if text.eq_ignore_ascii_case("-Infinity") {
            Ok(self.big_infinity(true))
        } else {
            Ok(self.big_float_from_decimal(&text.parse()?))
        }
    }
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
