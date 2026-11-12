#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.FloatFormatTest`,
//! part 1 of 5: encoding native values and rounding at the edges of a format.
//!
//! Java methods ported here (each is one `#[test]` with the same name in
//! snake case): `testGetEncodingMinval`,
//! `testDoubleEncodingBelowMinimumSubnormal`,
//! `testBigFloatEncodingBelowMinimumSubnormal`,
//! `testFloatNarrowingBelowMinimumSubnormal`,
//! `testMultiplyBelowMinimumSubnormal`,
//! `testHalfEncodingBelowMinimumSubnormal`,
//! `testQuadNarrowingBelowMinimumDoubleSubnormal`, `testGetEncodingMaxval`,
//! `testGetEncodingRoundToNearestEven`, `testDoubleRoundAtMidpoint`,
//! `testBigRoundAtMidpoint`.
//!
//! Java's `long` overloads map to the host level (`u64` encodings), its
//! `BigInteger`/`BigFloat` overloads to the exact level ([`Wide`] encodings).
//! Where Java compares `BigInteger.longValue()`/`intValue()` the port compares
//! the whole [`Wide`], which is at least as strict.

use bk_pcode::{BigFloat, FloatFormat, Wide};

/// Java's `Float.MIN_VALUE`: the smallest positive `float`, a subnormal.
/// (Rust's `f32::MIN_POSITIVE` is Java's `Float.MIN_NORMAL`.)
const FLOAT_MIN_VALUE: f32 = f32::from_bits(1);

/// Java's `new FloatFormat(size)`.
fn float_format(size: u32) -> FloatFormat {
    FloatFormat::ieee(size).unwrap()
}

/// `Math.scalb(1.0, exp)` for an exponent in the normal range of a double.
fn pow2(exp: i32) -> f64 {
    f64::from_bits(u64::try_from(1023 + exp).unwrap() << 52)
}

/// `sign * value` for the Java loops over `sign` in `{ 1, -1 }`.
fn signed(negative: bool, value: f64) -> f64 {
    if negative { -value } else { value }
}

/// Java's `MIN_SUBNORMAL_INPUTS`. Binary32's minimum subnormal is exactly
/// 2^-149. These dyadic values require no approximate decimal oracle: half
/// ties to zero, values above half round to one.
fn min_subnormal_inputs() -> [f64; 8] {
    let minimum = pow2(-149);
    let half = 0.5 * minimum;
    [
        0.25 * minimum,
        half.next_down(),
        half,
        half.next_up(),
        0.75 * minimum,
        minimum,
        1.5 * minimum,
        1.75 * minimum,
    ]
}

/// Java's `MIN_SUBNORMAL_ENCODINGS`.
const MIN_SUBNORMAL_ENCODINGS: [u64; 8] = [0, 0, 0, 1, 1, 1, 2, 2];

/// The binary32 encoding expected for input `i` of
/// [`min_subnormal_inputs`] with the given sign.
fn min_subnormal_expected(negative: bool, i: usize) -> u64 {
    MIN_SUBNORMAL_ENCODINGS[i] | if negative { 0x8000_0000 } else { 0 }
}

#[test]
fn test_get_encoding_minval() {
    let ff = float_format(4);

    let min_float = FLOAT_MIN_VALUE;
    let d0 = f64::from(min_float);

    let min_float_big4 = BigFloat::from_f32(min_float);
    assert!(!min_float_big4.is_nan() && !min_float_big4.is_normal());

    // doubles have plenty of room at the bottom, so the minimum float is normal
    let min_float_big8 = BigFloat::from_f64(d0);
    assert!(min_float_big8.is_normal());

    let true_encoding = u64::from(min_float.to_bits());
    let ff_encoding = ff.encoding(d0);
    let ff_big_encoding4 = ff.encode_big_float(&min_float_big4);
    let ff_big_encoding8 = ff.encode_big_float(&min_float_big8);

    assert_eq!(true_encoding, ff_encoding);
    assert_eq!(ff.min_value(), min_float_big4);
    // different precision implies different floats
    assert_ne!(ff.min_value(), min_float_big8);
    assert_eq!(Wide::from_u64(true_encoding), ff_big_encoding4);
    assert_eq!(Wide::from_u64(true_encoding), ff_big_encoding8);
}

#[test]
fn test_double_encoding_below_minimum_subnormal() {
    let ff = float_format(4);
    for negative in [false, true] {
        for (i, input) in min_subnormal_inputs().into_iter().enumerate() {
            assert_eq!(
                min_subnormal_expected(negative, i),
                ff.encoding(signed(negative, input)),
                "input {i}, negative {negative}"
            );
        }
    }
}

#[test]
fn test_big_float_encoding_below_minimum_subnormal() {
    let ff = float_format(4);
    for negative in [false, true] {
        for (i, input) in min_subnormal_inputs().into_iter().enumerate() {
            assert_eq!(
                Wide::from_u64(min_subnormal_expected(negative, i)),
                ff.encode_big_float(&BigFloat::from_f64(signed(negative, input))),
                "input {i}, negative {negative}"
            );
        }
    }
}

#[test]
fn test_float_narrowing_below_minimum_subnormal() {
    let source = float_format(8);
    let target = float_format(4);
    for negative in [false, true] {
        for (i, input) in min_subnormal_inputs().into_iter().enumerate() {
            let bits = signed(negative, input).to_bits();
            let expected = min_subnormal_expected(negative, i);
            assert_eq!(
                expected,
                source.op_float2float(bits, &target),
                "long input {i}, negative {negative}"
            );
            assert_eq!(
                Wide::from_u64(expected),
                source.op_float2float_exact(&Wide::from_u64(bits), &target),
                "BigInteger input {i}, negative {negative}"
            );
        }
    }
}

#[test]
fn test_multiply_below_minimum_subnormal() {
    let ff = float_format(4);
    // (a, b, a * b): the minimum subnormal (or three of them) times 0.75,
    // 0.25, 0.5, 0.25 and 1.0.
    let cases: [(u64, u64, u64); 5] = [
        (1, 0x3f40_0000, 1),
        (3, 0x3e80_0000, 1),
        (1, 0x3f00_0000, 0),
        (1, 0x3e80_0000, 0),
        (1, 0x3f80_0000, 1),
    ];
    for (a, b, product) in cases {
        assert_eq!(product, ff.op_mult(a, b), "{a:#x} * {b:#x}");
        assert_eq!(
            product | 0x8000_0000,
            ff.op_mult(a | 0x8000_0000, b),
            "-{a:#x} * {b:#x}"
        );
    }
}

#[test]
fn test_half_encoding_below_minimum_subnormal() {
    let ff = float_format(2);
    // Binary16's minimum subnormal is 2^-24.
    let minimum = pow2(-24);
    let half_minimum = 0.5 * minimum;
    let inputs = [
        0.25 * minimum,
        half_minimum.next_down(),
        half_minimum,
        half_minimum.next_up(),
        0.75 * minimum,
        minimum,
        1.5 * minimum,
    ];
    let encodings: [u64; 7] = [0, 0, 0, 1, 1, 1, 2];
    for negative in [false, true] {
        for (i, input) in inputs.into_iter().enumerate() {
            let expected = encodings[i] | if negative { 0x8000 } else { 0 };
            assert_eq!(
                expected,
                ff.encoding(signed(negative, input)),
                "double input {i}, negative {negative}"
            );
            assert_eq!(
                Wide::from_u64(expected),
                ff.encode_big_float(&BigFloat::from_f64(signed(negative, input))),
                "BigFloat input {i}, negative {negative}"
            );
        }
    }
}

#[test]
fn test_quad_narrowing_below_minimum_double_subnormal() {
    let source = float_format(16);
    let target = float_format(8);
    // Binary128 represents the binary64 underflow boundary exactly: the biased
    // exponent of 2^-1075 is 16383 - 1075 = 15308, with 112 fraction bits.
    let half_minimum = Wide::from_u64(15308) << 112;
    let inputs = [
        Wide::from_u64(15307) << 112,
        half_minimum.wrapping_sub(Wide::ONE),
        half_minimum,
        half_minimum.wrapping_add(Wide::ONE),
        half_minimum | (Wide::ONE << 111),
        Wide::from_u64(15309) << 112,
    ];
    let encodings: [u64; 6] = [0, 0, 0, 1, 1, 1];
    for negative in [false, true] {
        for (i, input) in inputs.into_iter().enumerate() {
            let bits = if negative {
                input | (Wide::ONE << 127)
            } else {
                input
            };
            let expected = encodings[i] | if negative { 1 << 63 } else { 0 };
            assert_eq!(
                Wide::from_u64(expected),
                source.op_float2float_exact(&bits, &target),
                "input {i}, negative {negative}"
            );
        }
    }
}

#[test]
fn test_get_encoding_maxval() {
    let ff = float_format(4);

    let max_float = f32::MAX;
    let d0 = f64::from(max_float);

    let max_float_big4 = BigFloat::from_f32(max_float);
    assert!(max_float_big4.is_normal());

    let max_float_big8 = BigFloat::from_f64(d0);
    assert!(max_float_big8.is_normal());

    let true_encoding = u64::from(max_float.to_bits());
    let ff_encoding = ff.encoding(d0);
    let ff_big_encoding4 = ff.encode_big_float(&max_float_big4);
    let ff_big_encoding8 = ff.encode_big_float(&max_float_big8);

    assert_eq!(true_encoding, ff_encoding);
    assert_eq!(ff.max_value(), max_float_big4);
    // different precision implies different floats
    assert_ne!(ff.max_value(), max_float_big8);
    assert_eq!(Wide::from_u64(true_encoding), ff_big_encoding4);
    assert_eq!(Wide::from_u64(true_encoding), ff_big_encoding8);
}

#[test]
fn test_get_encoding_round_to_nearest_even() {
    let ff = float_format(4);

    // This test is a verbose exposition of the more complete
    // assert_double_midpoint_round.
    //
    // IEEE 754 recommends "round to nearest even" for binary formats: round to
    // the nearest significand when unambiguous, and to the even one on the
    // midpoint. There are 52 bits of significand in a double and 23 in a
    // float.
    //
    //   d0 - zeros in low 29 bits, round down
    //   d1 - on the rounding midpoint with even integer part, round down
    //   d2 - just above the midpoint, round up
    //   d3 - zeros in low 29 bits, round down
    //   d4 - on the rounding midpoint with integer part odd, round up
    //   d5 - just above the midpoint, round up
    let doubles = [
        0x4010_0000_0000_0000_u64,
        0x4010_0000_1000_0000,
        0x4010_0000_1000_0001,
        0x4010_0000_2000_0000,
        0x4010_0000_3000_0000,
        0x4010_0000_3000_0001,
    ]
    .map(f64::from_bits);

    // Java: `(float) d`, the host's round-to-nearest-even narrowing.
    let floats = doubles.map(|d| d as f32);
    let e = doubles.map(|d| ff.encoding(d));

    for i in 0..6 {
        assert_eq!(u64::from(floats[i].to_bits()), e[i], "d{i}");
    }

    assert_eq!(e[0], e[1]);
    assert_ne!(e[1], e[2]);

    assert_ne!(e[3], e[4]);
    assert_eq!(e[4], e[5]);
}

/// Java's `makeDoubleFloat`: the double whose 23 leading fraction bits are
/// `float_frac` and whose other fraction bits are zero.
fn make_double_float(neg: bool, exp: i32, float_frac: u32) -> u64 {
    let mut l: u64 = if neg { 1 << 63 } else { 0 };
    l |= u64::try_from(1023 + exp).unwrap() << 52;
    l |= u64::from(float_frac) << (52 - 23);
    l
}

/// A native double at the rounding middle point for the conversion to float
/// (the common head of Java's `assertDoubleMidpointRound` and
/// `assertBigMidpointRound`).
fn midpoint_double(neg: bool, exp: i32, float_frac: u32) -> f64 {
    let insignif: u64 = 1 << (52 - 23 - 1);
    f64::from_bits(make_double_float(neg, exp, float_frac) + insignif)
}

/// Java's `assertDoubleMidpointRound`: the host-level conversion and the
/// native cast to float produce the same thing.
fn assert_double_midpoint_round(neg: bool, exp: i32, float_frac: u32) {
    let dmid = midpoint_double(neg, exp, float_frac);

    // round from double to single precision
    let ff = float_format(4);
    let actual = ff.encoding(dmid);

    let expected = u64::from((dmid as f32).to_bits());

    assert_eq!(
        expected, actual,
        "expected {expected:08x} != actual {actual:08x}"
    );
}

/// Java's `assertBigMidpointRound`: the exact-level encoding and the native
/// cast to float produce the same thing.
fn assert_big_midpoint_round(neg: bool, exp: i32, float_frac: u32) {
    let dmid = midpoint_double(neg, exp, float_frac);
    let bdmid = BigFloat::from_f64(dmid);

    // round from double to single precision
    let ff = float_format(4);
    let actual = ff.encode_big_float(&bdmid);

    let expected = Wide::from_u64(u64::from((dmid as f32).to_bits()));

    assert_eq!(
        expected, actual,
        "expected {expected:08x} != actual {actual:08x}"
    );
}

/// The even and odd float significands at extremes that both midpoint tests
/// go through: `(neg, exp, float_frac)`.
const MIDPOINT_CASES: [(bool, i32, u32); 16] = [
    (false, 1, 1),
    (false, 1, 2),
    (false, 1, (1 << 23) - 1),
    (false, 1, (1 << 23) - 2),
    (false, 120, 1),
    (false, 120, 2),
    (false, 120, (1 << 23) - 1),
    (false, 120, (1 << 23) - 2),
    (false, -120, 1),
    (false, -120, 2),
    (false, -120, (1 << 23) - 1),
    (false, -120, (1 << 23) - 2),
    (true, 1, 1),
    (true, 1, 2),
    (true, 1, (1 << 23) - 1),
    (true, 1, (1 << 23) - 2),
];

#[test]
fn test_double_round_at_midpoint() {
    // test even and odd float significands at extremes
    for (neg, exp, float_frac) in MIDPOINT_CASES {
        assert_double_midpoint_round(neg, exp, float_frac);
    }

    // overflow (`Float.MAX_EXPONENT` is 127)
    assert_double_midpoint_round(false, f32::MAX_EXP - 1, (1 << 23) - 1);
}

#[test]
fn test_big_round_at_midpoint() {
    // test even and odd float significands at extremes
    for (neg, exp, float_frac) in MIDPOINT_CASES {
        assert_big_midpoint_round(neg, exp, float_frac);
    }
}
