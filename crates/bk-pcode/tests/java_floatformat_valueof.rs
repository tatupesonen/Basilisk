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
//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.FloatFormatTest`:
//! the conversions from integers, `BigDecimal`s and decimal strings, and
//! decoding to decimal text.
//!
//! Java methods ported here (each is one `#[test]` with the same name in
//! snake case), with the private helpers they call:
//! `testValueOfBigInteger` (`doTestValueOfBigInteger`),
//! `testValueOfBigDecimal` (`doTestValueOfBigDecimal`),
//! `testValueOfDecimalString` (`doTestValueOfDecimalString`),
//! `testDoubleDecodeWithToString`, `testFloatDecodeWithToString`.
//!
//! Java's `BigDecimal` is [`Decimal`], `FloatFormat.round` is
//! [`FloatFormat::round_decimal`], `getDisplayContext()` is
//! [`FloatFormat::display_precision`] (`HALF_EVEN` rounding),
//! `toDecimalString(f)` / `toDecimalString(f, compact)` is
//! [`FloatFormat::to_decimal_string`].
//!
//! `BigDecimal.valueOf(double)` goes through `Double.toString`; each such
//! operand is carried as the text Java produces (checked here against
//! [`java_double_to_string`], and with a JDK), parsed as Java's
//! `new BigDecimal(String)`. `BigDecimal.valueOf(long)` is the integer with
//! scale 0.
//!
//! Where the Java helpers compute an expected value, the port computes it
//! the same way; as an extra, each row also carries the value a JDK run of
//! Ghidra's own code computed, and the test checks the two agree.

use bk_pcode::num_bigint::BigInt;
use bk_pcode::{Decimal, FloatFormat, Wide};

/// Java's `Double.MIN_VALUE`: the smallest positive `double`, a subnormal.
const DOUBLE_MIN_VALUE: f64 = f64::from_bits(1);

/// `FloatFormatFactory.getFloatFormat(size)`.
fn float_format(size: u32) -> FloatFormat {
    FloatFormat::ieee(size).unwrap()
}

/// Java's `Double.toString(d)` for a finite, non-zero `d`: the shortest
/// digits that read back as `d` (at least two in scientific notation), plain
/// for `1e-3 <= |d| < 1e7` and otherwise scientific as `d.dddEn` (always a
/// fraction digit, no `+`). Covers the values of this file.
fn java_double_to_string(d: f64) -> String {
    assert!(d.is_finite() && d != 0.0, "{d:e}");
    let magnitude = d.abs();
    if (1e-3..1e7).contains(&magnitude) {
        // Debug prints the shortest digits with at least one fraction digit.
        return format!("{d:?}");
    }
    let mut text = format!("{d:e}");
    if !text.contains('.') {
        // One shortest digit: Java writes two significant digits, the two
        // nearest the exact value (`4.9E-324`, where the shortest is
        // `5e-324`; `1.0E10`).
        text = format!("{d:.1e}");
    }
    let (mantissa, exponent) = text.split_once('e').unwrap();
    format!("{mantissa}E{exponent}")
}

/// A Java double literal: the nearest double, as `javac` and Rust's parser
/// both give it.
fn literal(text: &str) -> f64 {
    text.parse().unwrap()
}

/// `BigDecimal.valueOf(d)`, `java_text` being Java's `Double.toString(d)`.
fn value_of_double(d: f64, java_text: &str) -> Decimal {
    assert_eq!(java_text, java_double_to_string(d), "Double.toString");
    java_text.parse().unwrap()
}

/// `BigDecimal.valueOf(long)`.
fn value_of_long(value: i64) -> Decimal {
    Decimal::from(BigInt::from(value))
}

/// `FloatFormatTest.doTestValueOfBigInteger`.
#[track_caller]
fn do_test_value_of_big_integer(bd_val: &Decimal) {
    let ff = float_format(8);
    let bd_val = bd_val.round(ff.display_precision());
    let bi_val = bd_val.to_bigint();
    let f = ff.big_float_from_int(&bi_val);
    let bd = ff.round_decimal(&f).unwrap();
    assert_eq!(bi_val, bd.to_bigint());
    assert_eq!(bd_val, bd);
}

#[test]
fn test_value_of_big_integer() {
    let ff = float_format(8);
    let int = |value: i64| ff.big_float_from_int(&BigInt::from(value));

    assert_ne!(ff.big_zero(true), ff.big_zero(false));

    assert_eq!("-0.0", ff.to_decimal_string(&ff.big_zero(true), false));
    assert_eq!("0.0", ff.to_decimal_string(&ff.big_zero(false), false));
    assert_eq!("1.0", ff.to_decimal_string(&int(1), false));
    assert_eq!("2.0", ff.to_decimal_string(&int(2), false));
    assert_eq!("-1.0", ff.to_decimal_string(&int(-1), false));
    assert_eq!("-2.0", ff.to_decimal_string(&int(-2), false));

    let big = value_of_double(
        literal("2.1234567890123456789e123"),
        "2.1234567890123457E123",
    );
    do_test_value_of_big_integer(&big);
    do_test_value_of_big_integer(&big.negate());

    // NOTE: BigDecimal.valueOf(Double.MAX_VALUE) produces a value greater
    // than Double.MAX_VALUE (the Java leaves that case commented out).

    let bf = ff.decode_big_float_u64(f64::MAX.to_bits());
    let bf = ff.big_float_from_int(&bf.to_big_integer());
    assert_eq!("1.797693134862316E+308", ff.to_decimal_string(&bf, false));

    // step just beyond Double.MAX_VALUE - still decodes the same
    let max_bd = value_of_double(f64::MAX, "1.7976931348623157E308");
    // `maxBd.unscaledValue().longValue() + 1`: the unscaled value fits a long.
    let unscaled = i64::try_from(max_bd.unscaled()).unwrap() + 1;
    let v = Decimal::new(BigInt::from(unscaled), max_bd.scale()).to_bigint();
    let f = ff.big_float_from_int(&v);
    assert_eq!("1.797693134862316E+308", ff.to_decimal_string(&f, true));

    // step far beyond Double.MAX_VALUE
    let v = Decimal::new(BigInt::from(1), -309).to_bigint();
    let f = ff.big_float_from_int(&v);
    assert_eq!("+Infinity", ff.to_decimal_string(&f, true));
}

/// `FloatFormatTest.doTestValueOfBigDecimal(v)` (every call in the Java
/// passes no `expect`, so the expected text is computed). The Java compares
/// `FloatFormat.toBinaryString(v.doubleValue())` with
/// `ff.toBinaryString(bf)`: renderings of the two encodings in the same
/// format, equal exactly when the encodings are; this compares the
/// encodings.
#[track_caller]
fn do_test_value_of_big_decimal(v: &Decimal) {
    let ff = float_format(8);
    let mut expect = v.round(ff.display_precision()).to_string();
    if !expect.contains('.') {
        expect.push_str(".0");
    }
    let bf = ff.big_float_from_decimal(v);

    assert_eq!(expect, ff.to_decimal_string(&bf, true), "{v}");

    assert_eq!(
        Wide::from_u64(v.to_f64().to_bits()),
        ff.encode_big_float(&bf),
        "Unexpected encoding: {v}"
    );
}

#[test]
fn test_value_of_big_decimal() {
    let ff = float_format(8);
    // (the operand, then extras: the expected text and the encoding of
    // `v.doubleValue()` as a JDK computed them)
    let rows: Vec<(Decimal, &str, u64)> = vec![
        (value_of_long(0), "0.0", 0),
        (value_of_long(1), "1.0", 0x3ff0_0000_0000_0000),
        (value_of_long(2), "2.0", 0x4000_0000_0000_0000),
        (
            value_of_double(literal("2.123456789"), "2.123456789"),
            "2.123456789",
            0x4000_fcd6_e9b9_cb1b,
        ),
        (
            value_of_double(literal("2.1234567890123456789"), "2.1234567890123457"),
            "2.123456789012346",
            0x4000_fcd6_e9ba_37b3,
        ),
        (
            value_of_double(
                literal("2.1234567890123456789E+123"),
                "2.1234567890123457E123",
            ),
            "2.123456789012346E+123",
            0x5989_b2a0_11f7_1e97,
        ),
        (value_of_long(-1), "-1.0", 0xbff0_0000_0000_0000),
        (value_of_long(-2), "-2.0", 0xc000_0000_0000_0000),
        (
            value_of_double(literal("-2.123456789"), "-2.123456789"),
            "-2.123456789",
            0xc000_fcd6_e9b9_cb1b,
        ),
        (
            value_of_double(literal("-2.1234567890123456789"), "-2.1234567890123457"),
            "-2.123456789012346",
            0xc000_fcd6_e9ba_37b3,
        ),
        (
            value_of_double(
                literal("-2.1234567890123456789E+123"),
                "-2.1234567890123457E123",
            ),
            "-2.123456789012346E+123",
            0xd989_b2a0_11f7_1e97,
        ),
        // Java appears to exceed IEEE 754 decimal precision of 16 by
        // producing "1.7976931348623157E+308"
        (
            value_of_double(f64::MAX, "1.7976931348623157E308"),
            "1.797693134862316E+308",
            0x7fef_ffff_ffff_ffff,
        ),
        (
            value_of_double(
                literal("2.1234567890123456789E-123"),
                "2.1234567890123458E-123",
            ),
            "2.123456789012346E-123",
            0x2676_75a7_1248_6944,
        ),
        (
            value_of_double(
                literal("-2.1234567890123456789E-123"),
                "-2.1234567890123458E-123",
            ),
            "-2.123456789012346E-123",
            0xa676_75a7_1248_6944,
        ),
        // NOTE: Java Double.MIN_VALUE = 0x0.0000000000001P-1022; // 4.9e-324
        // corresponds to the minimum subnormal decoded value of the raw
        // representation. The value 4.9e-324 is the shortest compact
        // representation which retains the same encoded value.
        (
            value_of_double(DOUBLE_MIN_VALUE, "4.9E-324"),
            "4.9E-324",
            0x0000_0000_0000_0001,
        ),
    ];
    for (v, jdk_expect, jdk_encoding) in &rows {
        do_test_value_of_big_decimal(v);
        // Extra: the values the JDK run computed.
        assert_eq!(
            *jdk_expect,
            ff.to_decimal_string(&ff.big_float_from_decimal(v), true)
        );
        assert_eq!(
            Wide::from_u64(*jdk_encoding),
            ff.encode_big_float(&ff.big_float_from_decimal(v))
        );
    }

    // step just beyond Double.MAX_VALUE - still decodes the same
    let max_bd = value_of_double(f64::MAX, "1.7976931348623157E308");
    let v = Decimal::new(max_bd.unscaled() + 1, max_bd.scale());
    let f = ff.big_float_from_decimal(&v);
    assert_eq!(
        max_bd.round(ff.display_precision()).to_string(),
        ff.to_decimal_string(&f, true)
    );

    // step far beyond Double.MAX_VALUE
    let v = Decimal::new(max_bd.unscaled().clone(), max_bd.scale() * 2);
    let f = ff.big_float_from_decimal(&v);
    assert_eq!("+Infinity", ff.to_decimal_string(&f, false));

    // step just beyond Double.MIN_VALUE - still decodes the same
    let min_bd = value_of_double(DOUBLE_MIN_VALUE, "4.9E-324");
    let v = Decimal::new(min_bd.unscaled() + 1, min_bd.scale());
    let f = ff.big_float_from_decimal(&v);
    assert_eq!(
        min_bd.round(ff.display_precision()).to_string(),
        ff.to_decimal_string(&f, true)
    );

    // step far beyond Double.MIN_VALUE
    let v = Decimal::new(min_bd.unscaled().clone(), min_bd.scale() * 2);
    let f = ff.big_float_from_decimal(&v);
    assert_eq!("0.0", ff.to_decimal_string(&f, false));
}

/// `FloatFormatTest.doTestValueOfDecimalString(str, expect)`; with no
/// `expect`, the expected text is that of the double nearest `str`
/// (`Double.valueOf(str)`, which Rust's parser matches).
#[track_caller]
fn do_test_value_of_decimal_string(text: &str, expect: Option<&str>) {
    let ff = float_format(8);
    let expect = expect.map_or_else(
        || {
            // perform double-double conversion
            let bf = ff.decode_big_float_u64(text.parse::<f64>().unwrap().to_bits());
            // done to ensure consistent non-compact formatting
            ff.to_decimal_string(&bf, false)
        },
        str::to_owned,
    );
    let f = ff.big_float_from_str(text).unwrap();
    assert_eq!(expect, ff.to_decimal_string(&f, false), "{text}");
}

#[test]
fn test_value_of_decimal_string() {
    let ff = float_format(8);

    // `BigDecimal.valueOf(Double.MAX_VALUE).toString()` and
    // `BigDecimal.valueOf(Double.MIN_VALUE).toString()`.
    let max_text = value_of_double(f64::MAX, "1.7976931348623157E308").to_string();
    let min_text = value_of_double(DOUBLE_MIN_VALUE, "4.9E-324").to_string();
    // Extra: the texts a JDK prints.
    assert_eq!("1.7976931348623157E+308", max_text);
    assert_eq!("4.9E-324", min_text);

    // (the string, Java's `expect` argument, then an extra: the text a JDK
    // run of Ghidra's code expects)
    let rows: [(&str, Option<&str>, &str); 20] = [
        ("0", None, "0.0"),
        ("1", None, "1.0"),
        ("2", None, "2.0"),
        ("3.141592653589793238462643", None, "3.141592653589793"),
        ("2.123456789", None, "2.123456789"),
        ("2.1234567890123456789", None, "2.123456789012346"),
        ("2.1234567890123456789E+123", None, "2.123456789012346E+123"),
        ("-1", None, "-1.0"),
        ("-2", None, "-2.0"),
        ("-2.123456789", None, "-2.123456789"),
        ("-2.1234567890123456789", None, "-2.123456789012346"),
        (
            "-2.1234567890123456789E+123",
            None,
            "-2.123456789012346E+123",
        ),
        (&max_text, None, "1.797693134862316E+308"),
        // NOTE: compensated for minor precision issue
        ("2.1234567890123456789E-123", None, "2.123456789012346E-123"),
        (
            "-2.1234567890123456789E-123",
            None,
            "-2.123456789012346E-123",
        ),
        (&min_text, None, "4.940656458412465E-324"),
        // step just beyond Double.MAX_VALUE
        ("1.7976931348623159E+308", Some("+Infinity"), "+Infinity"),
        // step far beyond Double.MAX_VALUE
        ("2.2e350", Some("+Infinity"), "+Infinity"),
        // step just beyond Double.MIN_VALUE - still decodes the same
        ("4.98e-324", None, "4.940656458412465E-324"),
        // step far beyond Double.MIN_VALUE
        ("5.1e-350", None, "0.0"),
    ];
    for (text, expect, jdk_expect) in rows {
        do_test_value_of_decimal_string(text, expect);
        // Extra: the value the JDK run computed.
        let f = ff.big_float_from_str(text).unwrap();
        assert_eq!(jdk_expect, ff.to_decimal_string(&f, false), "{text}");
    }
}

#[test]
fn test_double_decode_with_to_string() {
    let ff = float_format(8);
    assert_eq!(
        "9.346009625593543E-307",
        ff.to_decimal_string(&ff.decode_big_float_u64(0x0065_0067_0061_0050), false)
    );
    assert_eq!(
        "2.123456789012346",
        ff.to_decimal_string(&ff.decode_big_float_u64(0x4000_FCD6_E9BA_37B3), false)
    );
    assert_eq!(
        "0.3",
        ff.to_decimal_string(&ff.decode_big_float_u64(0x3FD3_3333_3333_3333), false)
    );
}

#[test]
fn test_float_decode_with_to_string() {
    let ff = float_format(4);
    assert_eq!(
        "-1.4682312",
        ff.to_decimal_string(&ff.decode_big_float_u64(0xbfbb_ef00), true)
    );
}
