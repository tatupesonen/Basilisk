//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.BigFloatTest`
//! (26 tests): `BigFloat` arithmetic against the machine's `f32`/`f64`
//! arithmetic, over the same special values and the same 1000 pseudo-random
//! bit patterns (`java.util.Random(1)`) the Java uses.
//!
//! The Java compares `BigFloat.toBinaryString()` with the private helper
//! `FloatFormat.toBinaryString(float|double)`, which renders a native
//! float's encoding. That helper is reproduced here as the oracle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::float_cmp,
    reason = "test code"
)]

use std::cmp::Ordering;

use bk_pcode::{BigFloat, Decimal};

/// `java.util.Random`.
struct JavaRandom(u64);

impl JavaRandom {
    const MULTIPLIER: u64 = 0x5_DEEC_E66D;
    const MASK: u64 = (1 << 48) - 1;

    fn new(seed: u64) -> Self {
        Self((seed ^ Self::MULTIPLIER) & Self::MASK)
    }

    fn next(&mut self, bits: u32) -> i32 {
        self.0 = (self.0.wrapping_mul(Self::MULTIPLIER).wrapping_add(0xB)) & Self::MASK;
        (self.0 >> (48 - bits)) as i32
    }

    fn next_int(&mut self) -> i32 {
        self.next(32)
    }

    fn next_long(&mut self) -> i64 {
        let high = i64::from(self.next(32));
        (high << 32).wrapping_add(i64::from(self.next(32)))
    }
}

#[test]
fn java_random_matches_the_jdk() {
    // The first values of `new Random(1)`, from the JDK.
    let mut rand = JavaRandom::new(1);
    assert_eq!(rand.next_int(), -1_155_869_325);
    assert_eq!(rand.next_int(), 431_529_176);
    let mut rand = JavaRandom::new(1);
    assert_eq!(rand.next_long(), -4_964_420_948_893_066_024);
}

/// `FloatFormat.toBinaryString(long)` for a format with `frac_size` fraction
/// bits and `exp_size` exponent bits.
fn encoding_binary_string(encoding: u64, frac_size: u32, exp_size: u32) -> String {
    let bias = (1i64 << (exp_size - 1)) - 1;
    let max_exponent = (1u64 << exp_size) - 1;
    let frac = encoding & ((1 << frac_size) - 1);
    let exp = (encoding >> frac_size) & max_exponent;
    let negative = (encoding >> (frac_size + exp_size)) & 1 != 0;
    if exp == max_exponent {
        return if frac == 0 {
            if negative { "-inf" } else { "+inf" }.to_owned()
        } else if frac >> (frac_size - 1) == 1 {
            "qNaN".to_owned()
        } else {
            "sNaN".to_owned()
        };
    }
    let digits = format!("{frac:0width$b}", width = frac_size as usize);
    let mut binary = digits.trim_end_matches('0');
    if binary.is_empty() {
        binary = "0";
    }
    let s = if negative { "-" } else { "" };
    if exp == 0 {
        if frac == 0 {
            return format!("{s}0b0.0");
        }
        return format!("{s}0b0.{binary} * 2^{}", 1 - bias);
    }
    format!("{s}0b1.{binary} * 2^{}", exp as i64 - bias)
}

fn binary_string_f32(f: f32) -> String {
    encoding_binary_string(u64::from(f.to_bits()), 23, 8)
}

fn binary_string_f64(d: f64) -> String {
    encoding_binary_string(d.to_bits(), 52, 11)
}

const NUM_RANDOM_TEST_VALUES_UNARY: usize = 1000;
const NUM_RANDOM_TEST_VALUES_BINARY: usize = 100;

const MIN_VALUE_F32: f32 = f32::from_bits(1);
const MIN_VALUE_F64: f64 = f64::from_bits(1);

fn float_special_values() -> Vec<f32> {
    vec![
        -0.0,
        0.0,
        -1.0,
        1.0,
        -MIN_VALUE_F32,
        MIN_VALUE_F32,
        -f32::MAX,
        f32::MAX,
        -f32::MIN_POSITIVE - MIN_VALUE_F32,
        -f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE + MIN_VALUE_F32,
        f32::MIN_POSITIVE - MIN_VALUE_F32,
        f32::MIN_POSITIVE,
        f32::MIN_POSITIVE + MIN_VALUE_F32,
        f32::NAN,
        f32::NEG_INFINITY,
        f32::INFINITY,
    ]
}

/// `testFloatList`.
fn test_float_list() -> Vec<f32> {
    let mut rand = JavaRandom::new(1);
    let mut list = float_special_values();
    list.extend((0..NUM_RANDOM_TEST_VALUES_UNARY).map(|_| f32::from_bits(rand.next_int() as u32)));
    list
}

/// `testFloatShortList`.
fn test_float_short_list() -> Vec<f32> {
    let mut list = test_float_list();
    list.truncate(float_special_values().len() + NUM_RANDOM_TEST_VALUES_BINARY);
    list
}

fn double_special_values() -> Vec<f64> {
    vec![
        -0.0,
        0.0,
        -1.0,
        1.0,
        -MIN_VALUE_F64,
        MIN_VALUE_F64,
        -f64::MAX,
        f64::MAX,
        -f64::MIN_POSITIVE - MIN_VALUE_F64,
        -f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE + MIN_VALUE_F64,
        f64::MIN_POSITIVE - MIN_VALUE_F64,
        f64::MIN_POSITIVE,
        f64::MIN_POSITIVE + MIN_VALUE_F64,
        f64::NAN,
        f64::NEG_INFINITY,
        f64::INFINITY,
    ]
}

/// `testDoubleList`.
fn test_double_list() -> Vec<f64> {
    let mut rand = JavaRandom::new(1);
    let mut list = double_special_values();
    list.extend((0..NUM_RANDOM_TEST_VALUES_UNARY).map(|_| f64::from_bits(rand.next_long() as u64)));
    list
}

/// `testDoubleShortList`.
fn test_double_short_list() -> Vec<f64> {
    let mut list = test_double_list();
    list.truncate(double_special_values().len() + NUM_RANDOM_TEST_VALUES_BINARY);
    list
}

fn unary_double_op_test(op: impl Fn(f64) -> f64, bproc: impl Fn(&BigFloat) -> BigFloat) {
    for (i, fa) in test_double_list().into_iter().enumerate() {
        let fb = op(fa);
        let bfa = bproc(&BigFloat::from_f64(fa));
        assert_eq!(fb.is_nan(), bfa.is_nan(), "case #{i}");
        if !fb.is_nan() {
            assert_eq!(binary_string_f64(fb), bfa.to_binary_string(), "case #{i}");
        }
    }
}

fn binary_double_op_test(
    op: impl Fn(f64, f64) -> f64,
    bproc: impl Fn(&BigFloat, &BigFloat) -> BigFloat,
) {
    let list = test_double_short_list();
    for (i, &fa) in list.iter().enumerate() {
        for (j, &fb) in list.iter().enumerate() {
            let fc = op(fa, fb);
            let bfa = bproc(&BigFloat::from_f64(fa), &BigFloat::from_f64(fb));
            assert_eq!(fc.is_nan(), bfa.is_nan(), "case #{i},{j}");
            if !fc.is_nan() {
                assert_eq!(
                    binary_string_f64(fc),
                    bfa.to_binary_string(),
                    "case #{i},{j}"
                );
            }
        }
    }
}

fn unary_float_op_test(op: impl Fn(f32) -> f32, bproc: impl Fn(&BigFloat) -> BigFloat) {
    for (i, fa) in test_float_list().into_iter().enumerate() {
        let fb = op(fa);
        let bfa = bproc(&BigFloat::from_f32(fa));
        assert_eq!(fb.is_nan(), bfa.is_nan(), "case #{i}");
        if !fb.is_nan() {
            assert_eq!(binary_string_f32(fb), bfa.to_binary_string(), "case #{i}");
        }
    }
}

fn binary_float_op_test(
    op: impl Fn(f32, f32) -> f32,
    bproc: impl Fn(&BigFloat, &BigFloat) -> BigFloat,
) {
    let list = test_float_short_list();
    for (i, &fa) in list.iter().enumerate() {
        for (j, &fb) in list.iter().enumerate() {
            let fc = op(fa, fb);
            let bfa = bproc(&BigFloat::from_f32(fa), &BigFloat::from_f32(fb));
            assert_eq!(fc.is_nan(), bfa.is_nan(), "case #{i},{j}");
            if !fc.is_nan() {
                assert_eq!(
                    binary_string_f32(fc),
                    bfa.to_binary_string(),
                    "case #{i},{j}"
                );
            }
        }
    }
}

/// `Double.compare` (and `Float.compare` through widening, which keeps the
/// order): numeric order, then `-0 < +0`, with every NaN equal and greatest.
fn java_compare(a: f64, b: f64) -> Ordering {
    if a < b {
        Ordering::Less
    } else if a > b {
        Ordering::Greater
    } else {
        let canonical = |x: f64| {
            if x.is_nan() {
                f64::NAN.to_bits() as i64
            } else {
                x.to_bits() as i64
            }
        };
        canonical(a).cmp(&canonical(b))
    }
}

/// `new BigDecimal(double)`: the exact decimal expansion, with the smallest
/// scale that holds it.
fn exact_decimal(x: f64) -> Decimal {
    let text = format!("{x:.1100}");
    text.trim_end_matches('0')
        .trim_end_matches('.')
        .parse()
        .unwrap()
}

#[test]
fn test_ieee_float_representation() {
    assert_eq!("0b0.0", binary_string_f32(0.0));
    assert_eq!("0b1.0 * 2^0", binary_string_f32(1.0));
    assert_eq!("0b1.0 * 2^1", binary_string_f32(2.0));
    assert_eq!("0b1.0 * 2^-1", binary_string_f32(0.5));
    assert_eq!("-0b1.0 * 2^1", binary_string_f32(-2.0));
}

#[test]
fn test_ieee_float_as_big_float() {
    for f in [0.0f32, 1.0, 2.0, 0.5, -2.0] {
        assert_eq!(
            BigFloat::from_f32(f).to_binary_string(),
            binary_string_f32(f)
        );
    }
    assert_eq!(BigFloat::from_f32(0.0).to_binary_string(), "0b0.0");
    assert_eq!(BigFloat::from_f32(-2.0).to_binary_string(), "-0b1.0 * 2^1");
}

#[test]
fn test_ieee_float_as_big_float_random() {
    let mut rand = JavaRandom::new(1);
    for _ in 0..100 {
        let f = f32::from_bits(rand.next_int() as u32);
        assert_eq!(
            BigFloat::from_f32(f).to_binary_string(),
            binary_string_f32(f)
        );
    }
}

#[test]
fn test_ieee_double_representation() {
    assert_eq!("0b0.0", binary_string_f64(0.0));
    assert_eq!("0b1.0 * 2^0", binary_string_f64(1.0));
    assert_eq!("0b1.0 * 2^1", binary_string_f64(2.0));
    assert_eq!("0b1.0 * 2^-1", binary_string_f64(0.5));
    assert_eq!("-0b1.0 * 2^1", binary_string_f64(-2.0));
}

#[test]
fn test_ieee_double_as_big_float() {
    for d in [0.0f64, 1.0, 2.0, 0.5, -2.0] {
        assert_eq!(
            BigFloat::from_f64(d).to_binary_string(),
            binary_string_f64(d)
        );
    }
    assert_eq!(BigFloat::from_f64(0.5).to_binary_string(), "0b1.0 * 2^-1");
}

#[test]
fn test_ieee_double_as_big_float_random() {
    let mut rand = JavaRandom::new(1);
    for _ in 0..100 {
        let d = f64::from_bits(rand.next_long() as u64);
        assert_eq!(
            BigFloat::from_f64(d).to_binary_string(),
            binary_string_f64(d)
        );
    }
}

#[test]
fn test_float_add() {
    binary_float_op_test(|a, b| a + b, BigFloat::add);
}

#[test]
fn test_float_substract() {
    binary_float_op_test(|a, b| a - b, BigFloat::sub);
}

#[test]
fn test_float_multiply() {
    binary_float_op_test(|a, b| a * b, BigFloat::mul);
}

#[test]
fn test_float_divide() {
    binary_float_op_test(|a, b| a / b, BigFloat::div);
}

#[test]
fn test_float_compare() {
    let list = test_float_short_list();
    for (i, &a) in list.iter().enumerate() {
        let fa = BigFloat::from_f32(a);
        for (j, &b) in list.iter().enumerate() {
            let fb = BigFloat::from_f32(b);
            assert_eq!(
                java_compare(f64::from(a), f64::from(b)),
                fa.compare(&fb),
                "case #{i},{j}"
            );
        }
    }
}

#[test]
fn test_float_sqrt() {
    unary_float_op_test(|a| f64::from(a).sqrt() as f32, BigFloat::sqrt);
}

#[test]
fn test_float_floor() {
    unary_float_op_test(|a| f64::from(a).floor() as f32, BigFloat::floor);
}

#[test]
fn test_float_ceil() {
    unary_float_op_test(|a| f64::from(a).ceil() as f32, BigFloat::ceil);
}

#[test]
fn test_double_add() {
    binary_double_op_test(|a, b| a + b, BigFloat::add);
}

#[test]
fn test_double_substract() {
    binary_double_op_test(|a, b| a - b, BigFloat::sub);
}

#[test]
fn test_double_multiply() {
    binary_double_op_test(|a, b| a * b, BigFloat::mul);
}

#[test]
fn test_double_divide() {
    binary_double_op_test(|a, b| a / b, BigFloat::div);
}

#[test]
fn test_double_compare() {
    let list = test_double_short_list();
    for (i, &a) in list.iter().enumerate() {
        let fa = BigFloat::from_f64(a);
        for (j, &b) in list.iter().enumerate() {
            let fb = BigFloat::from_f64(b);
            assert_eq!(java_compare(a, b), fa.compare(&fb), "case #{i},{j}");
        }
    }
}

#[test]
fn test_double_sqrt() {
    unary_double_op_test(f64::sqrt, BigFloat::sqrt);
}

#[test]
fn test_double_floor() {
    unary_double_op_test(f64::floor, BigFloat::floor);
}

#[test]
fn test_double_ceil() {
    unary_double_op_test(f64::ceil, BigFloat::ceil);
}

#[test]
fn test_to_big_decimal() {
    let decimal = |d: f64| BigFloat::from_f64(d).to_big_decimal().unwrap();
    assert_eq!(Decimal::zero(), decimal(0.0));
    assert_eq!("1".parse::<Decimal>().unwrap(), decimal(1.0));
    assert_eq!("1".parse::<Decimal>().unwrap().negate(), decimal(-1.0));
    for d in [
        MIN_VALUE_F64,
        f64::MIN_POSITIVE,
        f64::MAX,
        0.5,
        2.5,
        -0.5,
        -2.5,
    ] {
        assert_eq!(exact_decimal(d), decimal(d), "{d:e}");
    }
    // The oracle itself, on values with a known expansion.
    assert_eq!(exact_decimal(0.5).to_string(), "0.5");
    assert_eq!(exact_decimal(-2.5).to_string(), "-2.5");
    assert_eq!(exact_decimal(MIN_VALUE_F64).scale(), 1074);
    assert_eq!(exact_decimal(f64::MAX).scale(), 0);
    assert!(
        decimal(MIN_VALUE_F64)
            .to_string()
            .starts_with("4.940656458412465441765687928682213723650598026143247")
    );
    assert!(decimal(MIN_VALUE_F64).to_string().ends_with("E-324"));
}

#[test]
fn test_to_double() {
    // Finite, including signed zeros and their bit patterns.
    assert_eq!(0.0, BigFloat::from_f64(0.0).to_f64());
    assert_eq!(-0.0, BigFloat::from_f64(-0.0).to_f64());
    assert_eq!(0.0f64.to_bits(), BigFloat::from_f64(0.0).to_f64().to_bits());
    assert_eq!(
        (-0.0f64).to_bits(),
        BigFloat::from_f64(-0.0).to_f64().to_bits()
    );
    assert_eq!(1.0, BigFloat::from_f64(1.0).to_f64());
    assert_eq!(-2.5, BigFloat::from_f64(-2.5).to_f64());
    assert_eq!(f64::MAX, BigFloat::from_f64(f64::MAX).to_f64());
    assert_eq!(MIN_VALUE_F64, BigFloat::from_f64(MIN_VALUE_F64).to_f64());
    // Infinite.
    assert_eq!(f64::INFINITY, BigFloat::from_f64(f64::INFINITY).to_f64());
    assert_eq!(
        f64::NEG_INFINITY,
        BigFloat::from_f64(f64::NEG_INFINITY).to_f64()
    );
    // NaN kinds map to the primitive NaN.
    assert!(BigFloat::from_f64(f64::NAN).to_f64().is_nan());
    assert!(
        BigFloat::from_f64(f64::from_bits(0x7ff0_0000_0000_0001))
            .to_f64()
            .is_nan()
    );
}

#[test]
fn test_to_float() {
    // Finite, including signed zeros and their bit patterns.
    assert_eq!(0.0, BigFloat::from_f32(0.0).to_f32());
    assert_eq!(-0.0, BigFloat::from_f32(-0.0).to_f32());
    assert_eq!(0.0f32.to_bits(), BigFloat::from_f32(0.0).to_f32().to_bits());
    assert_eq!(
        (-0.0f32).to_bits(),
        BigFloat::from_f32(-0.0).to_f32().to_bits()
    );
    assert_eq!(1.0, BigFloat::from_f32(1.0).to_f32());
    assert_eq!(-2.5, BigFloat::from_f32(-2.5).to_f32());
    assert_eq!(f32::MAX, BigFloat::from_f32(f32::MAX).to_f32());
    assert_eq!(MIN_VALUE_F32, BigFloat::from_f32(MIN_VALUE_F32).to_f32());
    // Infinite.
    assert_eq!(f32::INFINITY, BigFloat::from_f32(f32::INFINITY).to_f32());
    assert_eq!(
        f32::NEG_INFINITY,
        BigFloat::from_f32(f32::NEG_INFINITY).to_f32()
    );
    // NaN kinds map to the primitive NaN.
    assert!(BigFloat::from_f32(f32::NAN).to_f32().is_nan());
    assert!(
        BigFloat::from_f32(f32::from_bits(0x7f80_0001))
            .to_f32()
            .is_nan()
    );
}

#[test]
fn test_normal_and_denormal() {
    let bf = BigFloat::from_f64(0.0);
    assert!(!bf.is_normal());
    assert!(!bf.is_denormal());

    let bf = BigFloat::from_f64(f64::MIN_POSITIVE);
    assert!(bf.is_normal());
    assert!(!bf.is_denormal());

    let bf = BigFloat::from_f64(f64::MAX);
    assert!(bf.is_normal());
    assert!(!bf.is_denormal());

    let bf = BigFloat::from_f64(MIN_VALUE_F64);
    assert!(!bf.is_normal());
    assert!(bf.is_denormal());
}
