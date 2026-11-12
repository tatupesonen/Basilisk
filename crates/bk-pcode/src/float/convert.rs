//! Correctly rounded conversion of an exact binary value to `f64`/`f32`.

use num_bigint::BigUint;

/// The value `(q + sticky) * 2^exp2`, where `sticky` stands for a non-zero
/// amount below the last bit of `q`, rounded once to `precision` significant
/// bits (fewer in the subnormal range below `2^min_exp`), halfway cases to
/// even. Overflow gives infinity.
///
/// With `precision` 53 and `min_exp` -1022 the result is the nearest `f64`;
/// with 24 and -126 it is the nearest `f32`, held exactly in an `f64`.
///
/// When `sticky` is set, `q` must carry more than `precision` bits.
pub(crate) fn round_to_f64(
    q: &BigUint,
    sticky: bool,
    exp2: i64,
    precision: u32,
    min_exp: i64,
) -> f64 {
    let len = i64::try_from(q.bits()).unwrap_or(i64::MAX);
    if len == 0 {
        return 0.0;
    }
    let lead = (len - 1).saturating_add(exp2);
    let keep = if lead >= min_exp {
        i64::from(precision)
    } else {
        i64::from(precision).saturating_sub(min_exp.saturating_sub(lead))
    };
    if keep < 0 {
        return 0.0;
    }
    let drop = len - keep;
    let (mantissa, exp) = if drop <= 0 {
        (q.clone(), exp2)
    } else {
        let drop_bits = drop.unsigned_abs();
        let mut kept = q >> drop_bits;
        let mid = q.bit(drop_bits - 1);
        let rest = sticky
            || q.trailing_zeros()
                .is_some_and(|zeros| zeros < drop_bits - 1);
        if mid && (rest || kept.bit(0)) {
            kept += 1u32;
        }
        (kept, exp2.saturating_add(drop))
    };
    // The mantissa has at most `precision + 1` bits, so it is exact in an
    // `f64`, and the scaling is exact unless it overflows to infinity.
    let mantissa = mantissa.iter_u64_digits().next().unwrap_or(0) as f64;
    libm::ldexp(mantissa, exp.clamp(-4000, 4000) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f64_of(q: u128, sticky: bool, exp2: i64) -> f64 {
        round_to_f64(&BigUint::from(q), sticky, exp2, 53, -1022)
    }

    #[test]
    fn rounds_integers_like_a_cast() {
        for q in [
            0u128,
            1,
            3,
            (1 << 53) - 1,
            1 << 53,
            (1 << 53) + 1,
            (1 << 53) + 3,
            u128::from(u64::MAX),
            u128::MAX,
            (1 << 100) + (1 << 47),
            (1 << 100) + (1 << 47) + 1,
            (1 << 100) + (3 << 47),
        ] {
            assert_eq!(f64_of(q, false, 0).to_bits(), (q as f64).to_bits(), "{q}");
            let f32_value = round_to_f64(&BigUint::from(q), false, 0, 24, -126) as f32;
            assert_eq!(f32_value.to_bits(), (q as f32).to_bits(), "{q}");
        }
    }

    #[test]
    fn sticky_breaks_ties_upward() {
        let tie = (1u128 << 64) + (1 << 11);
        assert_eq!(f64_of(tie, false, 0), (1u128 << 64) as f64);
        assert_eq!(f64_of(tie, true, 0), ((1u128 << 64) + (1 << 12)) as f64);
    }

    #[test]
    fn subnormals_and_limits() {
        assert_eq!(f64_of(1, false, -1074), f64::from_bits(1));
        assert_eq!(f64_of(1, false, -1075), 0.0);
        assert_eq!(f64_of(3, false, -1076), f64::from_bits(1));
        assert_eq!(f64_of(1 << 70, true, -1145), f64::from_bits(1));
        assert_eq!(f64_of(1, false, -1076), 0.0);
        assert_eq!(f64_of(1, false, -5000), 0.0);
        assert_eq!(
            f64_of((1 << 53) - 1, false, -1074),
            f64::from_bits((1 << 53) - 1)
        );
        assert_eq!(f64_of((1 << 54) - 1, false, -1075), f64::MIN_POSITIVE * 2.0);
        assert_eq!(f64_of((1 << 53) - 1, false, 971), f64::MAX);
        assert_eq!(f64_of((1 << 54) - 1, false, 970), f64::INFINITY);
        assert_eq!(f64_of(1, false, 1024), f64::INFINITY);
        assert_eq!(f64_of(1, false, 1_000_000), f64::INFINITY);
        assert_eq!(f64_of(1, false, 1023), 2f64.powi(1023));
    }
}
