//! Unit tests of `encode.rs`.
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
        let wide = FloatFormat::DOUBLE.op_float2float_exact(&Wide::from_u64(host.to_bits()), &x87);
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
