//! Unit tests of `host.rs`.
use super::*;

const F4: FloatFormat = FloatFormat::SINGLE;
const F8: FloatFormat = FloatFormat::DOUBLE;

fn f4(value: f32) -> u64 {
    u64::from(value.to_bits())
}

#[test]
fn classes() {
    assert_eq!(F4.class(f4(0.0)), FloatClass::Zero);
    assert_eq!(F4.class(f4(-0.0)), FloatClass::Zero);
    assert_eq!(F4.class(f4(1.5)), FloatClass::Normalized);
    assert_eq!(F4.class(1), FloatClass::Denormalized);
    assert_eq!(F4.class(f4(f32::INFINITY)), FloatClass::Infinity);
    assert_eq!(F4.class(f4(f32::NAN)), FloatClass::Nan);
    assert_eq!(F8.class(f64::MAX.to_bits()), FloatClass::Normalized);
    assert_eq!(F8.class(0x7ff0_0000_0000_0001), FloatClass::Nan);
}

#[test]
fn field_extraction() {
    let enc = (-1.5f64).to_bits();
    assert!(F8.extract_sign(enc));
    assert_eq!(F8.extract_exponent_code(enc), 1023);
    assert_eq!(F8.exponent(enc), 0);
    assert_eq!(F8.extract_fractional_code(enc), 1 << 63);
    assert_eq!(F4.exponent(f4(8.0)), 3);
    assert_eq!(F4.zero_encoding(true), 0x8000_0000);
    assert_eq!(F4.infinity_encoding(false), 0x7f80_0000);
    assert_eq!(F4.nan_encoding(false), 0x7fc0_0000);
    assert_eq!(F8.nan_encoding(true), 0xfff8_0000_0000_0000);
}

#[test]
fn host_float_is_exact_for_single_and_double() {
    for bits in [
        0u32,
        1,
        0x0080_0000,
        0x007f_ffff,
        0x3f80_0000,
        0x7f7f_ffff,
        0xc2f6_e979,
    ] {
        let (host, _) = F4.host_float(u64::from(bits));
        assert_eq!(
            host.to_bits(),
            f64::from(f32::from_bits(bits)).to_bits(),
            "{bits:#x}"
        );
    }
    for bits in [
        0u64,
        1,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
    ] {
        assert_eq!(F8.host_float(bits).0.to_bits(), bits, "{bits:#x}");
    }
    // NaNs lose their payload and keep their sign.
    assert_eq!(
        F8.host_float(0xfff0_0000_0000_0001).0.to_bits(),
        0xfff8_0000_0000_0000
    );
    assert_eq!(
        F4.host_float(0x7f80_0001).0.to_bits(),
        0x7ff8_0000_0000_0000
    );
}

#[test]
fn subnormal_rounding_up_to_the_smallest_normal() {
    // 2^-126 * (1 - 2^-30) is nearer to the smallest normal float than to
    // the largest subnormal. Ghidra's C++ returns zero here.
    let host = f64::from(f32::MIN_POSITIVE) * (1.0 - (0.5f64).powi(30));
    assert_eq!(F4.encoding(host), 0x0080_0000);
    assert_eq!(F4.encoding(-host), 0x8080_0000);
    assert_eq!(F4.convert_encoding(host.to_bits(), &F8), 0x0080_0000);
    assert_eq!(host as f32, f32::MIN_POSITIVE);
}

#[test]
fn nan_signs_follow_x86_64() {
    let inf = f4(f32::INFINITY);
    let pos_nan = F4.nan_encoding(false);
    let neg_nan = F4.nan_encoding(true);
    // Created NaNs are x86-64's default NaN, which is negative (Ghidra's
    // data test `floatprint.xml` expects `0.0f / 0.0f` to print `-NAN`).
    assert_eq!(F4.op_sub(inf, inf), neg_nan);
    assert_eq!(F4.op_div(f4(0.0), f4(0.0)), neg_nan);
    assert_eq!(F4.op_div(f4(0.0), f4(-0.0)), neg_nan);
    assert_eq!(F4.op_mult(f4(0.0), inf), neg_nan);
    assert_eq!(F4.op_sqrt(f4(-1.0)), neg_nan);
    assert_eq!(F8.op_div(0, 0), F8.nan_encoding(true));
    // A propagated NaN keeps the sign of the NaN input; with two NaN inputs,
    // x86-64 (GCC, SSE2) passes on `b`'s for add and multiply and `a`'s for
    // subtract and divide.
    assert_eq!(F4.op_add(neg_nan, f4(1.0)), neg_nan);
    assert_eq!(F4.op_add(f4(1.0), neg_nan), neg_nan);
    assert_eq!(F4.op_add(pos_nan, f4(1.0)), pos_nan);
    assert_eq!(F4.op_add(f4(1.0), pos_nan), pos_nan);
    assert_eq!(F4.op_sqrt(pos_nan), pos_nan);
    assert_eq!(F4.op_mult(pos_nan, neg_nan), neg_nan);
    assert_eq!(F4.op_add(neg_nan, pos_nan), pos_nan);
    assert_eq!(F4.op_div(neg_nan, pos_nan), neg_nan);
    assert_eq!(F4.op_sub(pos_nan, neg_nan), pos_nan);
    assert_eq!(F4.op_sqrt(neg_nan), neg_nan);
    assert_eq!(F4.op_ceil(neg_nan), neg_nan);
    assert_eq!(F4.op_floor(neg_nan), neg_nan);
    assert_eq!(F4.op_round(neg_nan), neg_nan);
    // Negation and absolute value act on the sign bit of a NaN.
    assert_eq!(F4.op_neg(pos_nan), neg_nan);
    assert_eq!(F4.op_neg(neg_nan), pos_nan);
    assert_eq!(F4.op_abs(neg_nan), pos_nan);
    // A signalling NaN input becomes the quiet NaN.
    assert_eq!(F4.op_add(0xff80_0001, f4(1.0)), neg_nan);
}

#[test]
fn trunc_saturates() {
    assert_eq!(F8.op_trunc(2.5f64.to_bits(), 8), 2);
    assert_eq!(F8.op_trunc((-2.5f64).to_bits(), 8), (-2i64) as u64);
    assert_eq!(F8.op_trunc((-2.5f64).to_bits(), 4), 0xffff_fffe);
    assert_eq!(F8.op_trunc(f64::INFINITY.to_bits(), 8), i64::MAX as u64);
    assert_eq!(F8.op_trunc(f64::NEG_INFINITY.to_bits(), 8), i64::MIN as u64);
    assert_eq!(F8.op_trunc(f64::NAN.to_bits(), 8), 0);
    assert_eq!(F8.op_trunc(1e30f64.to_bits(), 4), 0xffff_ffff);
}

#[test]
fn round_is_half_away_from_zero() {
    let round = |x: f64| f64::from_bits(F8.op_round(x.to_bits()));
    assert_eq!(round(2.5), 3.0);
    assert_eq!(round(-2.5), -3.0);
    assert_eq!(round(0.5), 1.0);
    assert_eq!(round(-0.5), -1.0);
    assert_eq!(round(0.499_999_999_999_999_94), 0.0);
    assert_eq!(round(-0.2).to_bits(), (-0.0f64).to_bits());
}

#[test]
fn int2float_sign_extends_by_size() {
    assert_eq!(F4.op_int2float(0xff, 1), f4(-1.0));
    assert_eq!(F4.op_int2float(0xff, 2), f4(255.0));
    assert_eq!(F8.op_int2float(u64::MAX, 8), (-1.0f64).to_bits());
    assert_eq!(
        F8.op_int2float(0x8000_0000, 4),
        (-2_147_483_648.0f64).to_bits()
    );
    assert_eq!(F4.op_int2float(0x7fff_ffff, 4), f4((1u64 << 31) as f32));
}

#[test]
fn half_precision_through_the_host() {
    let half = FloatFormat::HALF;
    assert_eq!(half.encoding(1.0), 0x3c00);
    assert_eq!(half.encoding(-2.0), 0xc000);
    assert_eq!(half.encoding(65504.0), 0x7bff);
    assert_eq!(half.encoding(65520.0), 0x7c00);
    assert_eq!(half.encoding(5.960_464_477_539_063e-8), 1);
    assert_eq!(half.host_float(0x3555).0, 0.333_251_953_125);
    assert_eq!(half.host_float(1).0, 5.960_464_477_539_063e-8);
    assert_eq!(half.op_add(0x3c00, 0x3c00), 0x4000);
}

#[test]
fn wide_formats_do_not_panic() {
    for format in [
        FloatFormat::EXTENDED,
        FloatFormat::QUAD,
        FloatFormat::OCTUPLE,
    ] {
        for enc in [0, 1, u64::MAX, 0x7ff0_0000_0000_0000] {
            let _ = format.host_float(enc);
            let _ = format.class(enc);
            let _ = format.op_add(enc, enc);
            let _ = format.op_trunc(enc, 8);
            let _ = format.convert_encoding(enc, &FloatFormat::DOUBLE);
            let _ = FloatFormat::DOUBLE.convert_encoding(enc, &format);
        }
        let _ = format.encoding(1.5);
        let _ = format.encoding(f64::MIN_POSITIVE);
        let _ = format.encoding(f64::MAX);
    }
}
