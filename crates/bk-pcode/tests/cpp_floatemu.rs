//! Port of Ghidra's C++ unit tests `unittests/testfloatemu.cc` (31 tests):
//! the host-level float emulation (`FloatFormat` in `float.cc`) against the
//! machine's own `f32`/`f64` arithmetic.
//!
//! The C++ tests compare with whatever the host FPU produces, including the
//! sign of a NaN it creates. basilisk fixes that sign (see
//! `bk_pcode::float::host`), so where the native result is a NaN the
//! expected encoding is the quiet NaN with the sign basilisk documents: that
//! of the first NaN input, and negative (x86-64's default NaN) when no input
//! is a NaN.

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

use bk_pcode::FloatFormat;

const F4: FloatFormat = FloatFormat::SINGLE;
const F8: FloatFormat = FloatFormat::DOUBLE;

fn float_to_raw_bits(f: f32) -> u64 {
    u64::from(f.to_bits())
}

/// `denorm_min()`.
const DENORM_MIN: f32 = f32::from_bits(1);

/// `float_test_values`.
fn float_test_values() -> Vec<f32> {
    vec![
        -0.0,
        0.0,
        -1.0,
        1.0,
        -1.234,
        1.234,
        -DENORM_MIN,
        DENORM_MIN,
        f32::MIN_POSITIVE - DENORM_MIN,
        f32::MIN_POSITIVE,
        f32::MIN_POSITIVE + DENORM_MIN,
        -f32::MIN_POSITIVE + DENORM_MIN,
        -f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE - DENORM_MIN,
        f32::MAX,
        f32::NAN,
        f32::NEG_INFINITY,
        f32::INFINITY,
    ]
}

/// `int_test_values`.
const INT_TEST_VALUES: [i32; 7] = [0, -1, 1, 1234, -1234, i32::MIN, i32::MAX];

/// The encoding the C++ test expects for a native result, with the sign of a
/// NaN result settled as basilisk does.
fn expected(native: f32, inputs: &[f32]) -> u64 {
    if native.is_nan() {
        let negative = inputs
            .iter()
            .find(|input| input.is_nan())
            .is_none_or(|nan| nan.is_sign_negative());
        F4.nan_encoding(negative)
    } else {
        float_to_raw_bits(native)
    }
}

fn assert_float_encoding(f: f32) {
    assert_eq!(float_to_raw_bits(f), F4.encoding(f64::from(f)), "{f:e}");
}

fn assert_double_encoding(f: f64) {
    assert_eq!(f.to_bits(), F8.encoding(f), "{f:e}");
}

fn unary_op_test(native: impl Fn(f32) -> f32, emulated: impl Fn(u64) -> u64) {
    for f in float_test_values() {
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(expected(native(f), &[f]), emulated(encoding), "{f:e}");
    }
}

fn binary_op_test(native: impl Fn(f32, f32) -> f32, emulated: impl Fn(u64, u64) -> u64) {
    for f1 in float_test_values() {
        let encoding1 = F4.encoding(f64::from(f1));
        for f2 in float_test_values() {
            let encoding2 = F4.encoding(f64::from(f2));
            assert_eq!(
                expected(native(f1, f2), &[f1, f2]),
                emulated(encoding1, encoding2),
                "{f1:e}, {f2:e}"
            );
        }
    }
}

fn compare_op_test(native: impl Fn(f32, f32) -> bool, emulated: impl Fn(u64, u64) -> u64) {
    for f1 in float_test_values() {
        let encoding1 = F4.encoding(f64::from(f1));
        for f2 in float_test_values() {
            let encoding2 = F4.encoding(f64::from(f2));
            assert_eq!(
                u64::from(native(f1, f2)),
                emulated(encoding1, encoding2),
                "{f1:e}, {f2:e}"
            );
        }
    }
}

#[test]
fn float_encoding_normal() {
    // The C++ passes the double literals 1.234 and -1.234, which the macro
    // converts to float for the true encoding and to double for getEncoding.
    assert_float_encoding(1.234);
    assert_float_encoding(-1.234);
    assert_eq!(F4.encoding(1.234), float_to_raw_bits(1.234f64 as f32));
    assert_eq!(F4.encoding(-1.234), float_to_raw_bits(-1.234f64 as f32));
}

#[test]
fn double_encoding_normal() {
    assert_double_encoding(1.234);
    assert_double_encoding(-1.234);
}

#[test]
fn float_encoding_nan() {
    assert_float_encoding(f32::NAN);
    assert_float_encoding(-f32::NAN);
    assert_eq!(F4.encoding(f64::NAN), 0x7fc0_0000);
    assert_eq!(F4.encoding(-f64::NAN), 0xffc0_0000);
}

#[test]
fn double_encoding_nan() {
    assert_double_encoding(f64::NAN);
    assert_double_encoding(-f64::NAN);
}

#[test]
fn float_encoding_subnormal() {
    assert_float_encoding(DENORM_MIN);
    assert_float_encoding(-DENORM_MIN);
}

#[test]
fn double_encoding_subnormal() {
    assert_double_encoding(f64::from_bits(1));
    assert_double_encoding(-f64::from_bits(1));
}

#[test]
fn float_encoding_min_normal() {
    assert_float_encoding(f32::MIN_POSITIVE);
    assert_float_encoding(-f32::MIN_POSITIVE);
}

#[test]
fn double_encoding_min_normal() {
    assert_double_encoding(f64::MIN_POSITIVE);
    assert_double_encoding(-f64::MIN_POSITIVE);
}

#[test]
fn float_encoding_infinity() {
    assert_float_encoding(f32::INFINITY);
    assert_float_encoding(f32::NEG_INFINITY);
}

#[test]
fn double_encoding_infinity() {
    assert_double_encoding(f64::INFINITY);
    assert_double_encoding(f64::NEG_INFINITY);
}

#[test]
fn float_decimal_precision() {
    let print = |bits: u32| F4.print_decimal(f64::from(f32::from_bits(bits)), false);
    assert_eq!(print(0x3400_0001), "1.192093e-07");
    assert_eq!(print(0x3480_0000), "2.3841858e-07");
    assert_eq!(print(0x3eaa_aaab), "0.33333334");
    assert_eq!(print(0x3e80_0000), "0.25");
    assert_eq!(print(0x3de3_ee46), "0.111294314");
}

#[test]
fn double_decimal_precision() {
    let print = |bits: u64, force_sci: bool| F8.print_decimal(f64::from_bits(bits), force_sci);
    assert_eq!(print(0x3fc5_5555_5555_5555, false), "0.16666666666666666");
    assert_eq!(print(0x7fef_ffff_ffff_ffff, false), "1.79769313486232e+308");
    assert_eq!(print(0x3fd5_5555_5c7d_da4b, false), "0.33333334");
    assert_eq!(print(0x3fd0_0000_0000_0000, false), "0.25");
    assert_eq!(print(0x3fb9_9999_9999_999a, false), "0.1");
    assert_eq!(print(0x3fbf_7ced_9168_72b0, true), "1.23000000000000e-01");
}

#[test]
fn float_midpoint_rounding() {
    // d0: zeros in the low 29 bits, round down.
    // d1: on the rounding midpoint with an even integer part, round down.
    // d2: just above the midpoint, round up.
    let d0 = f64::from_bits(0x4010_0000_0000_0000);
    let d1 = f64::from_bits(0x4010_0000_1000_0000);
    let d2 = f64::from_bits(0x4010_0000_1000_0001);
    // d3: zeros in the low 29 bits, round down.
    // d4: on the rounding midpoint with an odd integer part, round up.
    // d5: just above the midpoint, round up.
    let d3 = f64::from_bits(0x4010_0000_2000_0000);
    let d4 = f64::from_bits(0x4010_0000_3000_0000);
    let d5 = f64::from_bits(0x4010_0000_3000_0001);

    let e: Vec<u64> = [d0, d1, d2, d3, d4, d5]
        .iter()
        .map(|&d| F4.encoding(d))
        .collect();
    for (d, e) in [d0, d1, d2, d3, d4, d5].into_iter().zip(&e) {
        assert_eq!(float_to_raw_bits(d as f32), *e);
    }
    assert_eq!(e[0], e[1]);
    assert_ne!(e[1], e[2]);
    assert_ne!(e[3], e[4]);
    assert_eq!(e[4], e[5]);
}

#[test]
fn float_op_nan() {
    for f in float_test_values() {
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(u64::from(f.is_nan()), F4.op_nan(encoding), "{f:e}");
    }
}

#[test]
fn float_op_neg() {
    // Negation flips the sign bit, of a NaN too, natively and emulated.
    for f in float_test_values() {
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(float_to_raw_bits(-f), F4.op_neg(encoding), "{f:e}");
    }
}

#[test]
fn float_op_abs() {
    for f in float_test_values() {
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(float_to_raw_bits(f.abs()), F4.op_abs(encoding), "{f:e}");
    }
}

#[test]
fn float_op_sqrt() {
    unary_op_test(f32::sqrt, |a| F4.op_sqrt(a));
}

#[test]
fn float_op_ceil() {
    unary_op_test(f32::ceil, |a| F4.op_ceil(a));
}

#[test]
fn float_op_floor() {
    unary_op_test(f32::floor, |a| F4.op_floor(a));
}

#[test]
fn float_op_round() {
    unary_op_test(f32::round, |a| F4.op_round(a));
}

#[test]
fn float_op_int2float_size4() {
    for i in INT_TEST_VALUES {
        // The C++ passes the int, which converts to uintb with sign extension.
        let a = i64::from(i) as u64;
        assert_eq!(float_to_raw_bits(i as f32), F4.op_int2float(a, 4), "{i}");
        assert_eq!(
            float_to_raw_bits(i as f32),
            F4.op_int2float(u64::from(i as u32), 4),
            "{i}"
        );
    }
}

#[test]
fn float_to_double_op_float2float() {
    for f in float_test_values() {
        let true_result = if f.is_nan() {
            F8.nan_encoding(f.is_sign_negative())
        } else {
            f64::from(f).to_bits()
        };
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(true_result, F4.op_float2float(encoding, &F8), "{f:e}");
    }
}

#[test]
fn float_op_trunc_to_int() {
    let mut tested = 0;
    for f in float_test_values() {
        // Avoid what is undefined behaviour in the C++.
        if f as i64 > i64::from(i32::MAX) || (f as i64) < i64::from(i32::MIN) {
            continue;
        }
        let true_result = u64::from(f as i32 as u32);
        let encoding = F4.encoding(f64::from(f));
        assert_eq!(true_result, F4.op_trunc(encoding, 4), "{f:e}");
        tested += 1;
    }
    assert_eq!(tested, float_test_values().len() - 3);
}

#[test]
fn float_op_equal() {
    compare_op_test(|a, b| a == b, |a, b| F4.op_equal(a, b));
}

#[test]
fn float_op_not_equal() {
    compare_op_test(|a, b| a != b, |a, b| F4.op_not_equal(a, b));
}

#[test]
fn float_op_less() {
    compare_op_test(|a, b| a < b, |a, b| F4.op_less(a, b));
}

#[test]
fn float_op_less_equal() {
    compare_op_test(|a, b| a <= b, |a, b| F4.op_less_equal(a, b));
}

#[test]
fn float_op_add() {
    binary_op_test(|a, b| a + b, |a, b| F4.op_add(a, b));
}

#[test]
fn float_op_div() {
    binary_op_test(|a, b| a / b, |a, b| F4.op_div(a, b));
}

#[test]
fn float_op_mult() {
    binary_op_test(|a, b| a * b, |a, b| F4.op_mult(a, b));
}

#[test]
fn float_op_sub() {
    binary_op_test(|a, b| a - b, |a, b| F4.op_sub(a, b));
}
