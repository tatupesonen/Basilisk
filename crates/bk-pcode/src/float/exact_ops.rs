//! The p-code floating-point operations at the exact level, on [`Wide`]
//! encodings: the `BigInteger` overloads of `opEqual` … `opRound` in
//! Ghidra's Java `FloatFormat`.
//!
//! Each operation decodes its operands to [`BigFloat`], computes exactly,
//! rounds to nearest even and encodes the result. A NaN result is always the
//! positive quiet NaN.
//!
//! The four comparisons follow IEEE 754: a NaN is unordered and the two
//! zeros are equal. (Java's `BigInteger` overloads compare representations
//! and use `BigFloat.compareTo`'s total order instead, so there `+0 == -0`
//! is false, `-0 < +0` is true and `x < NaN` is true. Those are corrected
//! here; the host level and Java's own `long` overloads already agree with
//! IEEE.)

use core::cmp::Ordering;

use num_bigint::BigInt;

use super::bigfloat::BigFloat;
use super::format::FloatFormat;
use crate::wide::Wide;

impl FloatFormat {
    /// The IEEE ordering of two encodings; `None` when either is a NaN.
    fn compare_exact(&self, a: &Wide, b: &Wide) -> Option<Ordering> {
        let (fa, fb) = (self.decode_big_float(a), self.decode_big_float(b));
        if fa.is_nan() || fb.is_nan() {
            None
        } else if fa.is_zero() && fb.is_zero() {
            Some(Ordering::Equal)
        } else {
            Some(fa.compare(&fb))
        }
    }

    /// `a == b`.
    pub fn op_equal_exact(&self, a: &Wide, b: &Wide) -> bool {
        self.compare_exact(a, b) == Some(Ordering::Equal)
    }

    /// `a != b`.
    pub fn op_not_equal_exact(&self, a: &Wide, b: &Wide) -> bool {
        !self.op_equal_exact(a, b)
    }

    /// `a < b`.
    pub fn op_less_exact(&self, a: &Wide, b: &Wide) -> bool {
        self.compare_exact(a, b) == Some(Ordering::Less)
    }

    /// `a <= b`.
    pub fn op_less_equal_exact(&self, a: &Wide, b: &Wide) -> bool {
        matches!(
            self.compare_exact(a, b),
            Some(Ordering::Less | Ordering::Equal)
        )
    }

    /// Whether `a` is a NaN.
    pub fn op_nan_exact(&self, a: &Wide) -> bool {
        self.decode_big_float(a).is_nan()
    }

    /// `a + b`.
    pub fn op_add_exact(&self, a: &Wide, b: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).add(&self.decode_big_float(b)))
    }

    /// `a - b`.
    pub fn op_sub_exact(&self, a: &Wide, b: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).sub(&self.decode_big_float(b)))
    }

    /// `a / b`.
    pub fn op_div_exact(&self, a: &Wide, b: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).div(&self.decode_big_float(b)))
    }

    /// `a * b`.
    pub fn op_mult_exact(&self, a: &Wide, b: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).mul(&self.decode_big_float(b)))
    }

    /// `-a`.
    pub fn op_neg_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).negate())
    }

    /// `abs(a)`.
    pub fn op_abs_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).abs())
    }

    /// `sqrt(a)`.
    pub fn op_sqrt_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).sqrt())
    }

    /// Converts the integer `a` of `size_in` bytes, twos-complement if
    /// `signed`, to floating point. See
    /// [`FloatFormat::big_float_from_int`] for how each format rounds.
    pub fn op_int2float_exact(&self, a: &Wide, size_in: u32, signed: bool) -> Wide {
        let value = if signed {
            a.to_bigint_signed(size_in)
        } else {
            BigInt::from(a.to_biguint())
        };
        self.encode_big_float(&self.big_float_from_int(&value))
    }

    /// Converts `a` to the format `out`, rounding to nearest even.
    pub fn op_float2float_exact(&self, a: &Wide, out: &FloatFormat) -> Wide {
        out.encode_big_float(&self.decode_big_float(a))
    }

    /// Converts `a` to an integer, rounding towards zero. The result is the
    /// low 512 bits of the twos-complement integer; the caller cuts it to
    /// the output size.
    ///
    /// As in Java, a NaN gives 0, and an infinity gives the largest or
    /// smallest signed integer *of this format's size* (not of the output's).
    pub fn op_trunc_exact(&self, a: &Wide) -> Wide {
        let fa = self.decode_big_float(a);
        if fa.is_nan() {
            return Wide::ZERO;
        }
        let sign_bit = Wide::ONE << (self.size * 8).saturating_sub(1);
        if fa.is_infinite() {
            return if fa.is_negative() {
                sign_bit.wrapping_neg()
            } else {
                sign_bit.wrapping_sub(Wide::ONE)
            };
        }
        if left_shift_of_integer(&fa) >= i64::from(Wide::BITS) {
            // Every bit the result keeps is zero.
            return Wide::ZERO;
        }
        Wide::from_bigint(&fa.to_big_integer())
    }

    /// `ceil(a)`.
    pub fn op_ceil_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).ceil())
    }

    /// `floor(a)`.
    pub fn op_floor_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).floor())
    }

    /// The nearest integral value as Java computes it, `floor(a + 0.5)` with
    /// the sum rounded to the format; see [`BigFloat::round`]. (The host
    /// level rounds halfway cases away from zero, as the C++ does.)
    pub fn op_round_exact(&self, a: &Wide) -> Wide {
        self.encode_big_float(&self.decode_big_float(a).round())
    }
}

/// How far `to_big_integer` shifts the significand of `value` to the left.
fn left_shift_of_integer(value: &BigFloat) -> i64 {
    i64::from(value.scale()) + 1 - i64::from(value.fracbits())
}

#[cfg(test)]
mod tests {
    use super::*;

    const F8: FloatFormat = FloatFormat::DOUBLE;

    fn w(value: f64) -> Wide {
        Wide::from_u64(value.to_bits())
    }

    fn f(encoding: Wide) -> f64 {
        f64::from_bits(encoding.low_u64())
    }

    #[test]
    fn comparisons_are_ieee() {
        let nan = F8.big_nan_encoding(false);
        assert!(F8.op_equal_exact(&w(0.0), &w(-0.0)));
        assert!(!F8.op_not_equal_exact(&w(0.0), &w(-0.0)));
        assert!(!F8.op_less_exact(&w(-0.0), &w(0.0)));
        assert!(F8.op_less_equal_exact(&w(0.0), &w(-0.0)));
        assert!(!F8.op_equal_exact(&nan, &nan));
        assert!(F8.op_not_equal_exact(&nan, &nan));
        assert!(!F8.op_less_exact(&w(1.0), &nan));
        assert!(!F8.op_less_exact(&nan, &w(1.0)));
        assert!(!F8.op_less_equal_exact(&nan, &nan));
        assert!(F8.op_less_exact(&w(-1.0), &w(1.0)));
        assert!(F8.op_less_exact(&w(f64::NEG_INFINITY), &w(-1e308)));
        assert!(F8.op_less_equal_exact(&w(2.0), &w(2.0)));
        assert!(!F8.op_less_exact(&w(2.0), &w(2.0)));
        assert!(F8.op_nan_exact(&nan));
        assert!(!F8.op_nan_exact(&w(f64::INFINITY)));
    }

    #[test]
    fn arithmetic_matches_native_doubles() {
        let values = [
            0.0,
            -0.0,
            1.0,
            -1.5,
            0.1,
            1e300,
            -1e300,
            1e-300,
            5e-324,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for a in values {
            for b in values {
                let check = |name: &str, got: Wide, want: f64| {
                    if want.is_nan() {
                        assert_eq!(got, F8.big_nan_encoding(false), "{a:e} {name} {b:e}");
                    } else {
                        assert_eq!(f(got).to_bits(), want.to_bits(), "{a:e} {name} {b:e}");
                    }
                };
                check("+", F8.op_add_exact(&w(a), &w(b)), a + b);
                check("-", F8.op_sub_exact(&w(a), &w(b)), a - b);
                check("*", F8.op_mult_exact(&w(a), &w(b)), a * b);
                check("/", F8.op_div_exact(&w(a), &w(b)), a / b);
            }
            let check = |name: &str, got: Wide, want: f64| {
                if want.is_nan() {
                    assert_eq!(got, F8.big_nan_encoding(false), "{name} {a:e}");
                } else {
                    assert_eq!(f(got).to_bits(), want.to_bits(), "{name} {a:e}");
                }
            };
            check("sqrt", F8.op_sqrt_exact(&w(a)), a.sqrt());
            check("ceil", F8.op_ceil_exact(&w(a)), a.ceil());
            check("floor", F8.op_floor_exact(&w(a)), a.floor());
            check("neg", F8.op_neg_exact(&w(a)), -a);
            check("abs", F8.op_abs_exact(&w(a)), a.abs());
        }
    }

    #[test]
    fn nan_results_are_the_positive_quiet_nan() {
        let nan = F8.big_nan_encoding(false);
        let negative_nan = F8.big_nan_encoding(true);
        assert_eq!(F8.op_neg_exact(&nan), nan);
        assert_eq!(F8.op_neg_exact(&negative_nan), nan);
        assert_eq!(F8.op_add_exact(&negative_nan, &w(1.0)), nan);
        assert_eq!(F8.op_sqrt_exact(&w(-4.0)), nan);
        assert_eq!(F8.op_sub_exact(&w(f64::INFINITY), &w(f64::INFINITY)), nan);
    }

    #[test]
    fn round_is_floor_of_x_plus_half() {
        let round = |x: f64| f(F8.op_round_exact(&w(x)));
        assert_eq!(round(2.5), 3.0);
        assert_eq!(round(-2.5), -2.0);
        assert_eq!(round(2.25), 2.0);
        assert_eq!(round(-2.75), -3.0);
        assert_eq!(round(0.499_999_999_999_999_94), 1.0);
        assert_eq!(round(f64::INFINITY), f64::INFINITY);
    }

    #[test]
    fn trunc_follows_java() {
        let trunc = |x: f64, size: u32| F8.op_trunc_exact(&w(x)).truncate(size);
        assert_eq!(trunc(2.5, 8), Wide::from_u64(2));
        assert_eq!(trunc(-2.5, 8), Wide::from_u64((-2i64) as u64));
        assert_eq!(trunc(-2.5, 16), Wide::from_u128((-2i128) as u128));
        assert_eq!(trunc(f64::NAN, 8), Wide::ZERO);
        assert_eq!(trunc(f64::INFINITY, 8), Wide::from_u64(i64::MAX as u64));
        assert_eq!(trunc(f64::NEG_INFINITY, 8), Wide::from_u64(i64::MIN as u64));
        // The infinity bounds are for the float's 8 bytes, whatever the output size.
        assert_eq!(trunc(f64::INFINITY, 4), Wide::from_u64(0xffff_ffff));
        assert_eq!(trunc(f64::NEG_INFINITY, 4), Wide::ZERO);
        assert_eq!(trunc(f64::INFINITY, 16), Wide::from_u64(i64::MAX as u64));
        // Finite values are not saturated: 2^70 keeps its low bytes (zero).
        assert_eq!(trunc(2f64.powi(70), 8), Wide::ZERO);
        assert_eq!(trunc(2f64.powi(70), 16), Wide::from_u128(1 << 70));
        assert_eq!(
            trunc(1e300, 64),
            Wide::from_biguint(
                &BigFloat::from_f64(1e300)
                    .to_big_integer()
                    .magnitude()
                    .clone()
            )
        );
        // A shift beyond 512 bits leaves nothing.
        let huge = FloatFormat::QUAD.max_value();
        let encoded = FloatFormat::QUAD.encode_big_float(&huge);
        assert_eq!(FloatFormat::QUAD.op_trunc_exact(&encoded), Wide::ZERO);
    }

    #[test]
    fn int2float_by_size_and_sign() {
        assert_eq!(
            f(F8.op_int2float_exact(&Wide::from_u64(0xff), 1, true)),
            -1.0
        );
        assert_eq!(
            f(F8.op_int2float_exact(&Wide::from_u64(0xff), 1, false)),
            255.0
        );
        assert_eq!(
            f(F8.op_int2float_exact(&Wide::from_u64(0xff), 2, true)),
            255.0
        );
        assert_eq!(f(F8.op_int2float_exact(&Wide::MAX, 16, true)), -1.0);
        assert_eq!(
            f(F8.op_int2float_exact(&Wide::from_u128(1 << 100), 16, true)),
            2f64.powi(100)
        );
    }
}
