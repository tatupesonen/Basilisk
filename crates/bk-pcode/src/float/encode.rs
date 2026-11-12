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
mod tests {
    use super::*;

    #[test]
    fn special_encodings() {
        let f8 = FloatFormat::DOUBLE;
        assert_eq!(f8.big_zero_encoding(true).low_u64(), (-0.0f64).to_bits());
        assert_eq!(
            f8.big_infinity_encoding(false).low_u64(),
            f64::INFINITY.to_bits()
        );
        assert_eq!(f8.big_nan_encoding(false).low_u64(), 0x7ff8_0000_0000_0000);
        let quad = FloatFormat::QUAD;
        assert_eq!(
            quad.big_infinity_encoding(true).low_u128(),
            0xffff_u128 << 112
        );
        assert_eq!(
            quad.big_nan_encoding(false).low_u128(),
            0x0007_fff8_u128 << 108
        );
        let x87 = FloatFormat::EXTENDED;
        assert_eq!(
            x87.big_infinity_encoding(false).low_u128(),
            0x7fff_u128 << 64
        );
        assert_eq!(
            x87.big_nan_encoding(false).low_u128(),
            (0x7fff_u128 << 64) | (1 << 63)
        );
        assert_eq!(x87.big_zero_encoding(true).low_u128(), 1 << 79);
    }

    #[test]
    fn decode_and_encode_round_trip_native_floats() {
        for bits in [
            0u64,
            1,
            0x000f_ffff_ffff_ffff,
            0x0010_0000_0000_0000,
            0x3ff0_0000_0000_0000,
            0x7fef_ffff_ffff_ffff,
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0x8000_0000_0000_0000,
            0xc008_0000_0000_0001,
        ] {
            let format = FloatFormat::DOUBLE;
            let value = format.decode_big_float(&Wide::from_u64(bits));
            assert_eq!(
                format.encode_big_float(&value),
                Wide::from_u64(bits),
                "{bits:#x}"
            );
            assert_eq!(value, format.decode_big_float_u64(bits));
            assert_eq!(value.to_f64().to_bits(), bits);
        }
        // Signalling and quiet NaNs are told apart only by the `u64` decoder.
        let f4 = FloatFormat::SINGLE;
        assert_eq!(
            f4.decode_big_float_u64(0x7f80_0001).kind(),
            FloatKind::SignalingNan
        );
        assert_eq!(
            f4.decode_big_float_u64(0x7fc0_0000).kind(),
            FloatKind::QuietNan
        );
        assert_eq!(
            f4.decode_big_float(&Wide::from_u64(0x7f80_0001)).kind(),
            FloatKind::QuietNan
        );
        assert_eq!(
            f4.encode_big_float(&f4.decode_big_float_u64(0xff80_0001))
                .low_u64(),
            0x7fc0_0000
        );
    }

    #[test]
    fn narrowing_rounds_to_nearest_even() {
        let f4 = FloatFormat::SINGLE;
        for host in [
            1.0f64,
            1.000_000_059_604_644_8,
            1.000_000_178_813_934_3,
            1e-40,
            1e-46,
            3.5e38,
            f64::from(f32::MAX),
            16_777_217.0,
            -0.1,
        ] {
            let encoded = f4.encode_big_float(&BigFloat::from_f64(host)).low_u64();
            assert_eq!(encoded, u64::from((host as f32).to_bits()), "{host:e}");
        }
    }

    #[test]
    fn x87_values() {
        let x87 = FloatFormat::EXTENDED;
        // 1.0: exponent 16383, explicit integer bit set.
        let one = Wide::from_u128((16383u128 << 64) | (1 << 63));
        let value = x87.decode_big_float(&one);
        assert!(value.is_normal());
        assert_eq!(value.to_f64(), 1.0);
        assert_eq!(x87.encode_big_float(&value), one);
        // Widening a double is exact and round-trips.
        for host in [1.5f64, -2.25, 1e300, 1e-300, f64::MAX, f64::MIN_POSITIVE] {
            let wide =
                FloatFormat::DOUBLE.op_float2float_exact(&Wide::from_u64(host.to_bits()), &x87);
            assert_eq!(x87.decode_big_float(&wide).to_f64(), host);
            assert_eq!(
                x87.op_float2float_exact(&wide, &FloatFormat::DOUBLE)
                    .low_u64(),
                host.to_bits()
            );
        }
        // No x87 subnormals: a value below the smallest normal encodes as zero.
        let tiny = x87.min_value();
        assert_eq!(x87.encode_big_float(&tiny), Wide::ZERO);
        // A rounding carry bumps the exponent (Ghidra's Java loses the value).
        let quad = FloatFormat::QUAD;
        let all_ones = Wide::from_u128((16383u128 << 112) | ((1u128 << 112) - 1));
        let narrowed = quad.op_float2float_exact(&all_ones, &x87);
        assert_eq!(narrowed, Wide::from_u128((16384u128 << 64) | (1 << 63)));
        assert_eq!(x87.decode_big_float(&narrowed).to_f64(), 2.0);
    }

    #[test]
    fn integers_to_floats() {
        let f8 = FloatFormat::DOUBLE;
        assert_eq!(f8.big_float_from_int(&BigInt::from(-3)).to_f64(), -3.0);
        let big = (BigInt::from(1) << 53u32) + 1;
        assert_eq!(
            f8.big_float_from_int(&big).to_f64(),
            9_007_199_254_740_992.0
        );
        assert!(
            f8.big_float_from_int(&(BigInt::from(1) << 1024u32))
                .is_infinite()
        );
        assert_eq!(
            FloatFormat::SINGLE
                .big_float_from_int(&BigInt::from(16_777_217))
                .to_f64(),
            16_777_216.0
        );

        // Other sizes truncate and stay unnormalised.
        let x87 = FloatFormat::EXTENDED;
        let small = x87.big_float_from_int(&BigInt::from(5));
        assert!(!small.is_normal());
        assert_eq!(small.scale(), 63);
        assert_eq!(small.to_f64(), 5.0);
        let wide = (BigInt::from(1) << 70u32) + 255;
        assert_eq!(
            x87.big_float_from_int(&wide).to_big_integer(),
            (BigInt::from(1) << 70u32) + 128
        );
        assert!(
            x87.big_float_from_int(&-(BigInt::from(1) << 16384u32))
                .is_infinite()
        );
        assert_eq!(x87.big_float_from_int(&BigInt::ZERO).to_f64(), 0.0);
    }

    #[test]
    fn decimals_and_strings_to_floats() {
        let f8 = FloatFormat::DOUBLE;
        assert_eq!(f8.big_float_from_str("0.1").unwrap().to_f64(), 0.1);
        assert_eq!(f8.big_float_from_str("-1.5E+3").unwrap().to_f64(), -1500.0);
        assert!(f8.big_float_from_str("nan").unwrap().is_nan());
        assert!(f8.big_float_from_str("INFINITY").unwrap().is_infinite());
        assert!(f8.big_float_from_str("+infinity").unwrap().is_infinite());
        let negative = f8.big_float_from_str("-Infinity").unwrap();
        assert!(negative.is_infinite() && negative.is_negative());
        assert_eq!(
            f8.big_float_from_str("bogus"),
            Err(FloatError::InvalidDecimal("bogus".to_owned()))
        );
        assert_eq!(
            FloatFormat::SINGLE
                .big_float_from_str("0.1")
                .unwrap()
                .to_f32(),
            0.1f32
        );

        let quad = FloatFormat::QUAD;
        assert_eq!(quad.big_float_from_str("0.5").unwrap().to_f64(), 0.5);
        assert_eq!(quad.big_float_from_str("1E+3").unwrap().to_f64(), 1000.0);
        assert_eq!(
            quad.big_float_from_str("12.5E+30").unwrap().to_f64(),
            12.5e30
        );
        assert_eq!(quad.big_float_from_str("-0.375").unwrap().to_f64(), -0.375);
        assert!(quad.big_float_from_str("0").unwrap().is_zero());
        assert!(quad.big_float_from_str("0.000").unwrap().is_zero());
        assert!(quad.big_float_from_str("1E-6000").unwrap().is_zero());
        assert!(quad.big_float_from_str("1E+6000").unwrap().is_infinite());
        assert_eq!(quad.big_float_from_str("1E-4000").unwrap().to_f64(), 0.0);
        assert!(!quad.big_float_from_str("1E-4000").unwrap().is_zero());
    }

    #[test]
    fn format_extremes() {
        let f8 = FloatFormat::DOUBLE;
        assert_eq!(f8.max_value().to_f64(), f64::MAX);
        assert_eq!(f8.min_value().to_f64(), f64::from_bits(1));
        assert_eq!(
            f8.encode_big_float(&f8.max_value()).low_u64(),
            f64::MAX.to_bits()
        );
        assert_eq!(f8.encode_big_float(&f8.min_value()).low_u64(), 1);
        assert!(f8.big_float_from_f64(1e300).is_ok());
        assert!(matches!(
            FloatFormat::HALF.big_float_from_f64(1e300),
            Err(FloatError::ScaleOutOfBounds { .. })
        ));
        assert_eq!(
            FloatFormat::QUAD.big_float_from_f32(1.5).unwrap().to_f64(),
            1.5
        );
    }
}
