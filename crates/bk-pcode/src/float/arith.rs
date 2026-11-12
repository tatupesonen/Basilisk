//! Arithmetic on [`BigFloat`]: Ghidra's `BigFloat.java` operations.
//!
//! Each operation computes the exact result and rounds once to nearest,
//! halfway cases to even. The algorithms follow the Java step by step
//! (operand alignment, guard bits, the residue flag), because the Java also
//! accepts values that are not normalised and its results for those are part
//! of the behaviour.
//!
//! A NaN result keeps whatever sign the left operand had; the sign of a NaN
//! is never encoded (see `FloatFormat::encode_big_float`).

use core::cmp::Ordering;

use num_bigint::BigUint;

use super::bigfloat::{BigFloat, FloatKind, bit_length, lowest_set_bit, shift_left, shift_right};

impl BigFloat {
    fn make_quiet_nan(mut self) -> Self {
        self.kind = FloatKind::QuietNan;
        self
    }

    fn make_zero(&mut self) {
        self.kind = FloatKind::Finite;
        self.unscaled = BigUint::ZERO;
        self.scale = self.min_scale();
    }

    /// Sets the value to 1 without touching the sign.
    fn make_one(&mut self) {
        self.kind = FloatKind::Finite;
        self.scale = 0;
        self.unscaled = BigUint::from(1u8) << self.fracbits.saturating_sub(1);
    }

    fn upscale(&mut self, nbits: i64) {
        self.unscaled = shift_left(&self.unscaled, nbits);
        self.scale =
            (i64::from(self.scale) - nbits).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    }

    /// Widens the significand to at least `new_length` bits.
    fn scale_up_to(&mut self, new_length: i64) {
        let d = new_length - bit_length(&self.unscaled);
        if d > 0 {
            self.upscale(d);
        }
    }

    /// Rounds after a computation (`internalRound`). The true value is
    /// `(unscaled + eps) * 2^(scale - fracbits + 1)` with `eps` below one
    /// unit, and `unscaled` carries at least one bit more than the format.
    fn internal_round(&mut self, mut eps: bool) {
        if self.unscaled == BigUint::ZERO {
            self.make_zero();
            return;
        }
        let fracbits = i64::from(self.fracbits);
        let extrabits = (bit_length(&self.unscaled) - fracbits)
            .max(i64::from(self.min_scale()) - i64::from(self.scale));
        if extrabits <= 0 {
            // Java asserts this cannot happen; nothing to round.
            return;
        }
        let midbit = extrabits - 1;
        let midbitset = self.unscaled.bit(midbit.unsigned_abs());
        eps |= lowest_set_bit(&self.unscaled) < midbit;
        self.unscaled = shift_right(&self.unscaled, extrabits);
        self.scale = (i64::from(self.scale) + extrabits).min(i64::from(i32::MAX)) as i32;
        let odd = self.unscaled.bit(0);
        if midbitset && (eps || odd) {
            self.unscaled += 1u32;
            // Handle an overflowing carry.
            if bit_length(&self.unscaled) > fracbits {
                self.unscaled >>= 1u32;
                self.scale = self.scale.saturating_add(1);
            }
        }
        if self.scale > self.max_scale() {
            self.kind = FloatKind::Infinite;
        }
    }

    /// `self / other`.
    #[must_use]
    pub fn div(&self, other: &Self) -> Self {
        let mut r = self.clone();
        if r.is_nan() || other.is_nan() {
            return r.make_quiet_nan();
        }
        if r.is_infinite() {
            if other.is_infinite() {
                return r.make_quiet_nan();
            }
            r.negative ^= other.negative;
            return r;
        }
        if other.is_infinite() {
            r.make_zero();
            r.negative ^= other.negative;
            return r;
        }
        if other.is_zero() {
            if r.is_zero() {
                return r.make_quiet_nan();
            }
            r.kind = FloatKind::Infinite;
            r.negative ^= other.negative;
            return r;
        }
        // Both finite, `other` non-zero. Give the quotient the format's
        // precision plus one or two bits for rounding.
        let fracbits = i64::from(r.fracbits);
        let lshift = fracbits + 1 + bit_length(&other.unscaled) - bit_length(&r.unscaled);
        r.upscale(lshift);
        let quotient = &r.unscaled / &other.unscaled;
        let remainder = &r.unscaled % &other.unscaled;
        r.negative ^= other.negative;
        r.scale = (i64::from(r.scale) - (i64::from(other.scale) - fracbits + 1))
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
        r.unscaled = quotient;
        r.internal_round(remainder != BigUint::ZERO);
        r
    }

    /// `self * other`.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        let mut r = self.clone();
        if r.is_nan() || other.is_nan() {
            return r.make_quiet_nan();
        }
        if (r.is_zero() && other.is_infinite()) || (r.is_infinite() && other.is_zero()) {
            return r.make_quiet_nan();
        }
        if r.is_infinite() || other.is_infinite() {
            r.kind = FloatKind::Infinite;
            r.negative ^= other.negative;
            return r;
        }
        let fracbits = i64::from(r.fracbits);
        r.negative ^= other.negative;
        r.unscaled *= &other.unscaled;
        r.scale = (i64::from(r.scale) + i64::from(other.scale) - fracbits + 1)
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
        r.scale_up_to(fracbits + 1);
        r.internal_round(false);
        r
    }

    /// `self + other`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut r = self.clone();
        if r.is_nan() || other.is_nan() {
            return r.make_quiet_nan();
        }
        if r.is_infinite() && other.is_infinite() {
            return if r.negative == other.negative {
                r
            } else {
                r.make_quiet_nan()
            };
        }
        if r.is_infinite() {
            return r;
        }
        if other.is_infinite() {
            return r.with_value_of(other);
        }
        if other.is_zero() {
            if r.is_zero() {
                r.negative = r.negative && other.negative;
            }
            return r;
        }
        if r.is_zero() {
            return r.with_value_of(other);
        }
        if r.negative == other.negative {
            r.add0(other)
        } else {
            r.sub0(other)
        }
    }

    /// `self - other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut negated = other.clone();
        negated.negative = !negated.negative;
        let mut r = self.add(&negated);
        if r.is_zero() {
            r.negative = self.negative && negated.negative;
        }
        r
    }

    /// Takes the kind, sign, significand and scale of `other` (`copyFrom`);
    /// the two are assumed to have the same format.
    fn with_value_of(mut self, other: &Self) -> Self {
        self.kind = other.kind;
        self.negative = other.negative;
        self.unscaled.clone_from(&other.unscaled);
        self.scale = other.scale;
        self
    }

    /// Adds magnitudes: both finite, non-zero, same sign.
    fn add0(mut self, other: &Self) -> Self {
        let fracbits = i64::from(self.fracbits);
        let d = i64::from(self.scale) - i64::from(other.scale);
        if d > fracbits {
            return self;
        }
        if d < -fracbits {
            return self.with_value_of(other);
        }
        // `a` has the larger scale.
        let (a_unscaled, a_scale, b_unscaled, d) = if d >= 0 {
            (&self.unscaled, self.scale, &other.unscaled, d)
        } else {
            (&other.unscaled, other.scale, &self.unscaled, -d)
        };
        let residue = lowest_set_bit(b_unscaled) < d - 1;
        let sum = (a_unscaled << 1u32) + shift_right(b_unscaled, d - 1);
        self.scale = a_scale.saturating_sub(1);
        self.unscaled = sum;
        self.scale_up_to(fracbits + 1);
        self.internal_round(residue);
        self
    }

    /// Subtracts magnitudes: both finite, non-zero, opposite signs.
    fn sub0(mut self, other: &Self) -> Self {
        let fracbits = i64::from(self.fracbits);
        let d = i64::from(self.scale) - i64::from(other.scale);
        if d > fracbits + 1 {
            return self;
        }
        if d < -(fracbits + 1) {
            return self.with_value_of(other);
        }
        // `a` has the larger scale.
        let (a_unscaled, a_scale, a_negative, b_unscaled, d) = if d >= 0 {
            (
                &self.unscaled,
                self.scale,
                self.negative,
                &other.unscaled,
                d,
            )
        } else {
            (
                &other.unscaled,
                other.scale,
                other.negative,
                &self.unscaled,
                -d,
            )
        };
        // A non-positive shift is fine: no residue, and the right shift
        // becomes a left shift.
        let residue = lowest_set_bit(b_unscaled) < d - 2;
        let mut x = shift_right(b_unscaled, d - 2);
        if residue {
            x += 1u32;
        }
        let a4 = a_unscaled << 2u32;
        let (difference, negative) = match a4.cmp(&x) {
            // Cancellation results in positive zero.
            Ordering::Equal => (BigUint::ZERO, false),
            Ordering::Greater => (a4 - x, a_negative),
            Ordering::Less => (x - a4, !a_negative),
        };
        self.negative = negative;
        self.scale = a_scale.saturating_sub(2);
        self.unscaled = difference;
        self.scale_up_to(fracbits + 1);
        self.internal_round(residue);
        self
    }

    /// The square root. The root of a negative value is the quiet NaN; the
    /// root of a zero is that zero.
    #[must_use]
    pub fn sqrt(&self) -> Self {
        let mut r = self.clone();
        if r.is_zero() {
            return r;
        }
        if r.is_nan() || r.negative {
            return r.make_quiet_nan();
        }
        if r.is_infinite() {
            return r;
        }
        let fracbits = i64::from(r.fracbits);
        // Force at least fracbits + 2 bits of precision in the result.
        r.scale_up_to(2 * fracbits + 2);
        // scale + fracbits - 1 must be even for the root of the significand.
        if (i64::from(r.scale) + fracbits - 1) & 1 != 0 {
            r.upscale(1);
        }
        let root = r.unscaled.sqrt();
        let exact = &root * &root == r.unscaled;
        r.unscaled = root;
        r.scale = ((i64::from(r.scale) + fracbits - 1) / 2) as i32;
        r.internal_round(!exact);
        r
    }

    /// Floor of the magnitude.
    fn floor0(&mut self) {
        if self.scale < 0 {
            self.make_zero();
            return;
        }
        let nbits_under_one = i64::from(self.fracbits) - i64::from(self.scale) - 1;
        self.unscaled = shift_left(
            &shift_right(&self.unscaled, nbits_under_one),
            nbits_under_one,
        );
    }

    /// Ceiling of the magnitude.
    fn ceil0(&mut self) {
        if self.is_zero() {
            return;
        }
        if self.scale < 0 {
            self.make_one();
            return;
        }
        let nbits_under_one = i64::from(self.fracbits) - i64::from(self.scale) - 1;
        let increment = lowest_set_bit(&self.unscaled) < nbits_under_one;
        self.unscaled = shift_left(
            &shift_right(&self.unscaled, nbits_under_one),
            nbits_under_one,
        );
        if increment {
            self.unscaled += shift_left(&BigUint::from(1u8), nbits_under_one);
        }
        // A carry into a new bit changes the scale.
        if bit_length(&self.unscaled) > i64::from(self.fracbits) {
            self.upscale(-1);
        }
    }

    /// The finite value both `floor` and `ceil` work on, or the result for
    /// an infinity or a NaN.
    fn rounding_operand(&self) -> Result<Self, Self> {
        match self.kind {
            FloatKind::Finite => Ok(self.clone()),
            FloatKind::Infinite | FloatKind::QuietNan => Err(self.clone()),
            FloatKind::SignalingNan => Err(self.clone().make_quiet_nan()),
        }
    }

    /// The largest integral value not above `self`.
    #[must_use]
    pub fn floor(&self) -> Self {
        match self.rounding_operand() {
            Ok(mut r) => {
                if r.negative {
                    r.ceil0();
                } else {
                    r.floor0();
                }
                r
            }
            Err(result) => result,
        }
    }

    /// The smallest integral value not below `self`.
    #[must_use]
    pub fn ceil(&self) -> Self {
        match self.rounding_operand() {
            Ok(mut r) => {
                if r.negative {
                    r.floor0();
                } else {
                    r.ceil0();
                }
                r
            }
            Err(result) => result,
        }
    }

    /// The integral value towards zero (`trunc`). As in Java this is not
    /// meant for infinities and NaNs.
    #[must_use]
    pub fn trunc(&self) -> Self {
        let mut r = self.clone();
        r.floor0();
        r
    }

    /// The value with its sign flipped.
    #[must_use]
    pub fn negate(&self) -> Self {
        let mut r = self.clone();
        r.negative = !r.negative;
        r
    }

    /// The value with a positive sign.
    #[must_use]
    pub fn abs(&self) -> Self {
        let mut r = self.clone();
        r.negative = false;
        r
    }

    /// The nearest integral value, computed as Java does: add one half (with
    /// the format's rounding) and take the floor. Halfway cases therefore go
    /// towards positive infinity.
    #[must_use]
    pub fn round(&self) -> Self {
        let half = Self::from_parts(
            self.fracbits,
            self.expbits,
            FloatKind::Finite,
            false,
            BigUint::from(1u8) << self.fracbits.saturating_sub(1),
            -1,
        );
        self.add(&half).floor()
    }

    /// Java's `compareTo`: a total order in which a NaN is greater than
    /// everything and equal to any NaN, and `-0` is less than `+0`. (This is
    /// `Float.compare`'s order, not the IEEE comparison.)
    pub fn compare(&self, other: &Self) -> Ordering {
        let by_sign = |negative: bool, ordering: Ordering| {
            if negative {
                ordering.reverse()
            } else {
                ordering
            }
        };
        match (self.is_nan(), other.is_nan()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        if self.is_infinite() {
            let same = other.is_infinite() && other.negative == self.negative;
            return if same {
                Ordering::Equal
            } else {
                by_sign(self.negative, Ordering::Greater)
            };
        }
        if other.is_infinite() {
            return by_sign(other.negative, Ordering::Less);
        }
        if self.negative != other.negative {
            return by_sign(self.negative, Ordering::Greater);
        }
        let magnitude = self
            .scale
            .cmp(&other.scale)
            .then_with(|| self.unscaled.cmp(&other.unscaled));
        by_sign(self.negative, magnitude)
    }
}
