//! Host-level float emulation: encodings of at most 8 bytes, computed through
//! `f64`.
//!
//! This is a port of the behaviour of `FloatFormat` in Ghidra's `float.cc`,
//! which the decompiler uses to fold floating-point constants: an encoding is
//! converted to the host's `double`, the operation is done by the host, and
//! the result is converted back with round-to-nearest-even.
//!
//! The methods here are meaningful for formats where
//! [`FloatFormat::is_host_format`] holds. For other formats they return an
//! unspecified value; they never panic.
//!
//! Where Ghidra's result depends on the machine it runs on, basilisk gives
//! one result on every host:
//!
//! - **The sign of a NaN result.** The C++ takes it from the host FPU, and
//!   basilisk computes it explicitly as Ghidra's reference build on x86-64
//!   Linux (GCC, SSE2) gives it, never from the host's own arithmetic.
//!   Decoding keeps only a NaN's sign (`getHostFloat` returns the host's
//!   quiet NaN with that sign), so the result is always the quiet NaN of the
//!   format and only its sign varies:
//!   - one input is a NaN: its sign (both hosts agree);
//!   - both inputs are NaNs: SSE2 returns its *first source operand*, which
//!     is the operand the compiler put in the destination register. GCC
//!     computes `val1 - val2` and `val1 / val2` with `val1` there, but
//!     `val1 + val2` and `val1 * val2`, being commutative, with `val2` there
//!     (the value just returned in `xmm0` by the second `getHostFloat`). So
//!     `FLOAT_SUB`/`FLOAT_DIV` take the sign of `a`, `FLOAT_ADD`/
//!     `FLOAT_MULT` the sign of `b`. AArch64 takes the first operand's for
//!     all four. Ghidra's compiled C++ on x86-64 shows this on every such
//!     row of `tests/data/opbehavior_cpp.txt.gz`;
//!   - no input is a NaN (`inf - inf`, `0 / 0`, `0 * inf`, `sqrt(-1)`):
//!     x86-64's default NaN, which is negative (AArch64's is positive).
//!     Ghidra's data test `floatprint.xml` expects the folded `0.0f / 0.0f`
//!     to print as `-NAN` (it fails on AArch64).
//! - **`TRUNC` of a NaN, an infinity or a value outside the `i64` range.**
//!   The C++ cast is undefined; x86-64 (`cvttsd2si`) gives `i64::MIN`,
//!   AArch64 saturates and maps NaN to 0. Here basilisk does not follow
//!   x86-64: it saturates and maps NaN to 0, as Java's `(long)` cast does,
//!   which `FloatFormatTest.testOpTruncLongInt` pins for the emulator's
//!   path.
//! - **A subnormal that rounds up to the smallest normal value.** The C++
//!   shifts by a negative amount (its comment says "TODO handle round to
//!   normal case") and on both hosts returns zero. basilisk returns the
//!   smallest normal value, the correctly rounded result, as Java does.

use super::format::{FloatClass, FloatFormat};
use crate::mask::{calc_mask, sign_extend_bit};

/// The number of bits in the significand word the C++ works with.
const WORD_BITS: i32 = 64;
/// The top bit of the significand word.
const HIGH_BIT: u64 = 1 << 63;

/// `val << sa`, or 0 when `sa` is outside `0..64`.
#[inline]
fn shl(val: u64, sa: i32) -> u64 {
    u32::try_from(sa)
        .ok()
        .and_then(|sa| val.checked_shl(sa))
        .unwrap_or(0)
}

/// `val >> sa`, or 0 when `sa` is outside `0..64`.
#[inline]
fn shr(val: u64, sa: i32) -> u64 {
    u32::try_from(sa)
        .ok()
        .and_then(|sa| val.checked_shr(sa))
        .unwrap_or(0)
}

/// A quiet NaN with the given sign.
#[inline]
fn quiet_nan(negative: bool) -> f64 {
    f64::from_bits(if negative {
        0xfff8_0000_0000_0000
    } else {
        0x7ff8_0000_0000_0000
    })
}

/// The result of a host operation with the NaN x86-64 gives: a NaN result
/// takes the sign of the first NaN among `inputs`, which the caller lists in
/// the order x86-64 gives them priority, and is x86-64's default NaN
/// (negative) when no input is a NaN.
#[inline]
fn settle_nan(result: f64, inputs: [f64; 2]) -> f64 {
    if result.is_nan() {
        let source = inputs.into_iter().find(|input| input.is_nan());
        quiet_nan(source.is_none_or(f64::is_sign_negative))
    } else {
        result
    }
}

/// Which input's NaN a binary operation passes on when both inputs are NaNs.
#[derive(Debug, Clone, Copy)]
enum NanPriority {
    /// The first input (`a`), x86-64's choice for `a - b` and `a / b`.
    First,
    /// The second input (`b`), x86-64's choice for `a + b` and `a * b`.
    Second,
}

/// `createFloat`: the double `signif / 2^63 * 2^exp`, negated if `sign`.
fn create_float(sign: bool, signif: u64, exp: i32) -> f64 {
    // Throw away one bit of precision that is lost anyway, so the high bit is 0.
    let res = libm::ldexp((signif >> 1) as f64, exp.saturating_sub(WORD_BITS - 2));
    if sign { -res } else { res }
}

/// `extractExpSig` for a finite, non-zero, positive double: the significand
/// with its leading bit at the top of the word, and the exponent of that bit.
fn extract_exp_sig(x: f64) -> (u64, i32) {
    let bits = x.to_bits();
    let frac = bits & ((1 << 52) - 1);
    let code = ((bits >> 52) & 0x7ff) as i32;
    if code == 0 {
        let lz = frac.leading_zeros();
        (frac.wrapping_shl(lz), -1011 - lz as i32)
    } else {
        ((frac | (1 << 52)) << 11, code - 1023)
    }
}

/// `roundToNearestEven`: rounds `signif` at bit `lowbitpos` and reports
/// whether it rounded up. The bits below `lowbitpos` are left in place.
fn round_to_nearest_even(signif: &mut u64, lowbitpos: i32) -> bool {
    if !(1..=WORD_BITS).contains(&lowbitpos) {
        return false;
    }
    let lowbitmask = shl(1, lowbitpos);
    let midbitmask = shl(1, lowbitpos - 1);
    let epsmask = midbitmask - 1;
    let odd = *signif & lowbitmask != 0;
    if *signif & midbitmask != 0 && (*signif & epsmask != 0 || odd) {
        *signif = signif.wrapping_add(midbitmask);
        true
    } else {
        false
    }
}

impl FloatFormat {
    /// The fraction field of an encoding, aligned to the top of the word
    /// (`extractFractionalCode`).
    pub fn extract_fractional_code(&self, x: u64) -> u64 {
        shl(
            shr(x, self.frac_pos as i32),
            WORD_BITS - self.frac_size as i32,
        )
    }

    /// The sign bit of an encoding (`extractSign`).
    pub fn extract_sign(&self, x: u64) -> bool {
        shr(x, self.signbit_pos as i32) & 1 != 0
    }

    /// The exponent field of an encoding (`extractExponentCode`).
    pub fn extract_exponent_code(&self, x: u64) -> i32 {
        (shr(x, self.exp_pos as i32) & (shl(1, self.exp_size as i32).wrapping_sub(1))) as i32
    }

    /// The true exponent of an encoding (`getExponent`).
    pub fn exponent(&self, x: u64) -> i32 {
        self.extract_exponent_code(x) - self.bias
    }

    fn set_fractional_code(&self, x: u64, code: u64) -> u64 {
        // Align with the bottom of the word, dropping bits there is no room for.
        x | shl(
            shr(code, WORD_BITS - self.frac_size as i32),
            self.frac_pos as i32,
        )
    }

    fn set_sign(&self, x: u64, sign: bool) -> u64 {
        if sign {
            x | shl(1, self.signbit_pos as i32)
        } else {
            x
        }
    }

    fn set_exponent_code(&self, x: u64, code: u64) -> u64 {
        x | shl(code, self.exp_pos as i32)
    }

    /// The encoding of zero with the given sign (`getZeroEncoding`).
    pub fn zero_encoding(&self, negative: bool) -> u64 {
        self.set_sign(0, negative)
    }

    /// The encoding of infinity with the given sign (`getInfinityEncoding`).
    pub fn infinity_encoding(&self, negative: bool) -> u64 {
        self.set_sign(
            self.set_exponent_code(0, self.max_exponent() as u64),
            negative,
        )
    }

    /// The encoding of the quiet NaN with the given sign (`getNaNEncoding`).
    pub fn nan_encoding(&self, negative: bool) -> u64 {
        let res = self.set_fractional_code(0, HIGH_BIT);
        self.set_sign(
            self.set_exponent_code(res, self.max_exponent() as u64),
            negative,
        )
    }

    /// The class of an encoding (`getClass`).
    pub fn class(&self, encoding: u64) -> FloatClass {
        let exp = self.extract_exponent_code(encoding);
        let zero_frac = self.extract_fractional_code(encoding) == 0;
        if exp == 0 {
            if zero_frac {
                FloatClass::Zero
            } else {
                FloatClass::Denormalized
            }
        } else if exp == self.max_exponent() {
            if zero_frac {
                FloatClass::Infinity
            } else {
                FloatClass::Nan
            }
        } else {
            FloatClass::Normalized
        }
    }

    /// Converts an encoding to the host's double, with its class
    /// (`getHostFloat`).
    ///
    /// A NaN comes back as the quiet NaN with the encoding's sign; its
    /// payload is not kept.
    pub fn host_float(&self, encoding: u64) -> (f64, FloatClass) {
        let sgn = self.extract_sign(encoding);
        let mut frac = self.extract_fractional_code(encoding);
        let class = self.class(encoding);
        match class {
            FloatClass::Zero => return (if sgn { -0.0 } else { 0.0 }, class),
            FloatClass::Infinity => {
                return (
                    if sgn {
                        f64::NEG_INFINITY
                    } else {
                        f64::INFINITY
                    },
                    class,
                );
            }
            FloatClass::Nan => return (quiet_nan(sgn), class),
            FloatClass::Normalized if self.jbit_implied => frac = (frac >> 1) | HIGH_BIT,
            FloatClass::Normalized | FloatClass::Denormalized => {}
        }
        let exp = self.extract_exponent_code(encoding) - self.bias;
        (create_float(sgn, frac, exp), class)
    }

    /// Converts the host's double to this format, rounding to nearest even
    /// (`getEncoding`).
    pub fn encoding(&self, host: f64) -> u64 {
        let sgn = host.is_sign_negative();
        if host == 0.0 {
            return self.zero_encoding(sgn);
        }
        if host.is_infinite() {
            return self.infinity_encoding(sgn);
        }
        if host.is_nan() {
            return self.nan_encoding(sgn);
        }
        let (signif, exp) = extract_exp_sig(host.abs());
        self.round_and_pack(sgn, signif, exp.saturating_add(self.bias))
    }

    /// The common tail of `getEncoding` and `convertEncoding`: encodes the
    /// value `signif / 2^63 * 2^(exp - bias)`, where `signif` has its top bit
    /// set.
    fn round_and_pack(&self, sgn: bool, mut signif: u64, mut exp: i32) -> u64 {
        let frac_size = self.frac_size as i32;
        if exp < -frac_size {
            // Exponent is too small to represent.
            return self.zero_encoding(sgn);
        }
        if exp < 1 {
            // Must be denormalized.
            if round_to_nearest_even(&mut signif, WORD_BITS - frac_size - exp)
                && signif & HIGH_BIT == 0
            {
                signif = HIGH_BIT;
                exp += 1;
            }
            let res = self.zero_encoding(sgn);
            if exp == 1 {
                // Rounded up to the smallest normal value (see the module
                // documentation: the C++ gets this case wrong).
                return self.set_exponent_code(res, 1);
            }
            return self.set_fractional_code(res, shr(signif, -exp));
        }
        if round_to_nearest_even(&mut signif, WORD_BITS - frac_size - 1) && signif & HIGH_BIT == 0 {
            // The add overflowed: increase the exponent and set the significand to 1.
            signif = HIGH_BIT;
            exp += 1;
        }
        if exp >= self.max_exponent() {
            // Exponent is too big to represent.
            return self.infinity_encoding(sgn);
        }
        if self.jbit_implied {
            signif <<= 1; // Cut off the top bit, which is 1.
        }
        let res = self.set_fractional_code(0, signif);
        self.set_sign(self.set_exponent_code(res, exp as u64), sgn)
    }

    /// Converts an encoding in another format to this format, rounding to
    /// nearest even (`convertEncoding`). A NaN becomes the quiet NaN with
    /// the same sign.
    pub fn convert_encoding(&self, encoding: u64, from: &Self) -> u64 {
        let sgn = from.extract_sign(encoding);
        let mut signif = from.extract_fractional_code(encoding);
        let mut exp = from.extract_exponent_code(encoding);

        if exp == from.max_exponent() {
            return if signif == 0 {
                self.infinity_encoding(sgn)
            } else {
                self.nan_encoding(sgn)
            };
        }
        if exp == 0 {
            // Incoming is subnormal.
            if signif == 0 {
                return self.zero_encoding(sgn);
            }
            let lz = signif.leading_zeros();
            signif = signif.wrapping_shl(lz);
            exp = -from.bias - lz as i32;
        } else {
            // Incoming is normal.
            exp -= from.bias;
            if from.jbit_implied {
                signif = HIGH_BIT | (signif >> 1);
            }
        }
        self.round_and_pack(sgn, signif, exp.saturating_add(self.bias))
    }

    /// `a == b` (`opEqual`).
    pub fn op_equal(&self, a: u64, b: u64) -> u64 {
        u64::from(self.host_float(a).0 == self.host_float(b).0)
    }

    /// `a != b` (`opNotEqual`).
    pub fn op_not_equal(&self, a: u64, b: u64) -> u64 {
        u64::from(self.host_float(a).0 != self.host_float(b).0)
    }

    /// `a < b` (`opLess`).
    pub fn op_less(&self, a: u64, b: u64) -> u64 {
        u64::from(self.host_float(a).0 < self.host_float(b).0)
    }

    /// `a <= b` (`opLessEqual`).
    pub fn op_less_equal(&self, a: u64, b: u64) -> u64 {
        u64::from(self.host_float(a).0 <= self.host_float(b).0)
    }

    /// Whether `a` is a NaN (`opNan`).
    pub fn op_nan(&self, a: u64) -> u64 {
        u64::from(self.class(a) == FloatClass::Nan)
    }

    fn binary(
        &self,
        a: u64,
        b: u64,
        nan_from: NanPriority,
        op: impl FnOnce(f64, f64) -> f64,
    ) -> u64 {
        let (val1, val2) = (self.host_float(a).0, self.host_float(b).0);
        let inputs = match nan_from {
            NanPriority::First => [val1, val2],
            NanPriority::Second => [val2, val1],
        };
        self.encoding(settle_nan(op(val1, val2), inputs))
    }

    fn unary(&self, a: u64, op: impl FnOnce(f64) -> f64) -> u64 {
        let val = self.host_float(a).0;
        self.encoding(settle_nan(op(val), [val, val]))
    }

    /// `a + b` (`opAdd`). When both are NaNs, the result has `b`'s sign.
    pub fn op_add(&self, a: u64, b: u64) -> u64 {
        self.binary(a, b, NanPriority::Second, |x, y| x + y)
    }

    /// `a / b` (`opDiv`). When both are NaNs, the result has `a`'s sign.
    pub fn op_div(&self, a: u64, b: u64) -> u64 {
        self.binary(a, b, NanPriority::First, |x, y| x / y)
    }

    /// `a * b` (`opMult`). When both are NaNs, the result has `b`'s sign.
    pub fn op_mult(&self, a: u64, b: u64) -> u64 {
        self.binary(a, b, NanPriority::Second, |x, y| x * y)
    }

    /// `a - b` (`opSub`). When both are NaNs, the result has `a`'s sign.
    pub fn op_sub(&self, a: u64, b: u64) -> u64 {
        self.binary(a, b, NanPriority::First, |x, y| x - y)
    }

    /// `-a` (`opNeg`). The sign of a NaN is flipped too.
    pub fn op_neg(&self, a: u64) -> u64 {
        self.encoding(-self.host_float(a).0)
    }

    /// `abs(a)` (`opAbs`). The sign of a NaN is cleared too.
    pub fn op_abs(&self, a: u64) -> u64 {
        self.encoding(self.host_float(a).0.abs())
    }

    /// `sqrt(a)` (`opSqrt`).
    pub fn op_sqrt(&self, a: u64) -> u64 {
        self.unary(a, f64::sqrt)
    }

    /// Converts the signed integer `a` of `size_in` bytes to floating point
    /// (`opInt2Float`).
    pub fn op_int2float(&self, a: u64, size_in: u32) -> u64 {
        let ival = sign_extend_bit(a, size_in.wrapping_mul(8).wrapping_sub(1));
        self.encoding(ival as f64)
    }

    /// Converts `a` to the format `out` (`opFloat2Float`).
    pub fn op_float2float(&self, a: u64, out: &Self) -> u64 {
        out.convert_encoding(a, self)
    }

    /// Converts `a` to a signed integer of `size_out` bytes, rounding towards
    /// zero (`opTrunc`). The conversion to `i64` saturates and maps NaN to 0
    /// before the result is cut to `size_out` bytes.
    pub fn op_trunc(&self, a: u64, size_out: u32) -> u64 {
        let ival = self.host_float(a).0 as i64;
        ival as u64 & calc_mask(size_out)
    }

    /// `ceil(a)` (`opCeil`).
    ///
    /// `libm::ceil`, not `f64::ceil`: on targets without a rounding
    /// instruction (baseline x86-64) `f64::ceil` calls the C library, and
    /// this crate does not depend on the host's C library (see `op_round`).
    pub fn op_ceil(&self, a: u64) -> u64 {
        self.unary(a, libm::ceil)
    }

    /// `floor(a)` (`opFloor`). `libm::floor`, as in [`Self::op_ceil`].
    pub fn op_floor(&self, a: u64) -> u64 {
        self.unary(a, libm::floor)
    }

    /// `round(a)`: to the nearest integer, halfway cases away from zero
    /// (`opRound`).
    ///
    /// `f64::round` has no machine instruction and calls the C library's
    /// `round`, which on `x86_64-pc-windows-gnu` (MinGW-w64 under Wine)
    /// gives 1 for 0.49999999999999994, the largest double below one half
    /// (it computes `floor(x + 0.5)`). `libm::round` is exact on every
    /// platform.
    pub fn op_round(&self, a: u64) -> u64 {
        self.unary(a, libm::round)
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
