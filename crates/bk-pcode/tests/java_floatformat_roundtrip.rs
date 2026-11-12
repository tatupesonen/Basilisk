#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::float_cmp,
    reason = "test code"
)]
//! Port of Ghidra's JUnit class `ghidra.pcode.floatformat.FloatFormatTest`,
//! part 2 of 5: encoding and decoding native values in every format, and the
//! random round trips.
//!
//! Java methods ported here (each is one `#[test]` with the same name in
//! snake case): `testGetHostFloatBigInteger`, `testGetHostFloat`,
//! `testBigFloatFloatFormatRandom`, `testBigFloatDoubleFormatRandom`,
//! `testBigFloatToDoubleEncoding`, `testBigFloatToFloatEncoding`.
//!
//! The random tests use `java.util.Random` with seed 1, and the last two
//! use the value lists of `BigFloatTest` (`testDoubleList`,
//! `testFloatList`), which are built from the same generator; it is
//! reimplemented here as [`JavaRandom`] so the same values are tested.

use bk_pcode::{BigFloat, FloatFormat, Wide};

/// Java's `Float.MIN_VALUE`: the smallest positive `float`, a subnormal.
/// (Rust's `f32::MIN_POSITIVE` is Java's `Float.MIN_NORMAL`.)
const FLOAT_MIN_VALUE: f32 = f32::from_bits(1);
/// Java's `Double.MIN_VALUE`: the smallest positive `double`, a subnormal.
const DOUBLE_MIN_VALUE: f64 = f64::from_bits(1);
/// The bits of Java's `Float.NaN`.
const FLOAT_NAN_BITS: u32 = 0x7fc0_0000;
/// The bits of Java's `Double.NaN`.
const DOUBLE_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

/// Java's `new FloatFormat(size)` / `FloatFormatFactory.getFloatFormat(size)`.
fn float_format(size: u32) -> FloatFormat {
    FloatFormat::ieee(size).unwrap()
}

/// The `long` Java gets from an `int` holding float bits: the test passes
/// `Float.floatToRawIntBits(f)` to `decodeHostFloat(long)` without masking,
/// so the encoding of a negative float arrives sign-extended.
fn int_bits_as_long(bits: u32) -> u64 {
    i64::from(bits as i32) as u64
}

/// `(float) ff.decodeHostFloat(encoding)`.
fn decode_host_f32(ff: &FloatFormat, encoding: u64) -> f32 {
    ff.host_float(encoding).0 as f32
}

/// The exact-level round trip of the Java test: `value` encodes to
/// `expected`, which decodes back to `value`.
fn assert_big_round_trip(ff: &FloatFormat, value: &BigFloat, expected: u64) {
    let encoding = ff.encode_big_float(value);
    assert_eq!(Wide::from_u64(expected), encoding, "{value:?}");
    assert_eq!(*value, ff.decode_big_float(&encoding));
}

/// The round trip the Java test uses for the formats with no native type:
/// "use round trip to verify".
fn assert_round_trip_only(ff: &FloatFormat, value: &BigFloat) {
    let encoding = ff.encode_big_float(value);
    assert_eq!(*value, ff.decode_big_float(&encoding), "{value:?}");
}

#[test]
fn test_get_host_float_big_integer() {
    // 32-bit encoding

    let ff = float_format(4);
    let big = ff.big_float_from_f32(4.5).unwrap();
    assert_big_round_trip(&ff, &big, u64::from(4.5_f32.to_bits()));

    // Float.MIN_VALUE, Float.MAX_VALUE and their negations: the exact level
    // encodes them, the host level decodes the encoding.
    for f in [FLOAT_MIN_VALUE, f32::MAX, -FLOAT_MIN_VALUE, -f32::MAX] {
        let big = ff.big_float_from_f32(f).unwrap();
        let encoding = ff.encode_big_float(&big);
        let intbits = f.to_bits();
        assert_eq!(Wide::from_u64(u64::from(intbits)), encoding, "{f:e}");
        assert_eq!(f, decode_host_f32(&ff, int_bits_as_long(intbits)), "{f:e}");
        // The same encoding without Java's sign extension.
        assert_eq!(f, decode_host_f32(&ff, u64::from(intbits)), "{f:e}");
    }

    for f in [3.75_f32, -4.5] {
        let big = ff.big_float_from_f32(f).unwrap();
        assert_big_round_trip(&ff, &big, u64::from(f.to_bits()));
    }

    let f = f32::INFINITY;
    let encoding = ff.encode_big_float(&ff.big_float_from_f32(f).unwrap());
    assert_eq!(Wide::from_u64(u64::from(f.to_bits())), encoding);
    assert_eq!(ff.big_infinity(false), ff.decode_big_float(&encoding));

    let f = f32::NEG_INFINITY;
    let encoding = ff.encode_big_float(&ff.big_float_from_f32(f).unwrap());
    assert_eq!(Wide::from_u64(u64::from(f.to_bits())), encoding);
    assert_eq!(ff.big_infinity(true), ff.decode_big_float(&encoding));

    let f = f32::from_bits(FLOAT_NAN_BITS);
    let encoding = ff.encode_big_float(&ff.big_float_from_f32(f).unwrap());
    assert_eq!(Wide::from_u64(u64::from(FLOAT_NAN_BITS)), encoding);
    assert_eq!(ff.big_nan(false), ff.decode_big_float(&encoding));

    // 64-bit encoding

    let ff = float_format(8);
    for d in [4.5_f64, 3.75, -4.5] {
        let big = ff.big_float_from_f64(d).unwrap();
        assert_big_round_trip(&ff, &big, d.to_bits());
    }

    let encoding = ff.big_infinity_encoding(false);
    assert_eq!(Wide::from_u64(f64::INFINITY.to_bits()), encoding);
    assert_eq!(ff.big_infinity(false), ff.decode_big_float(&encoding));

    let encoding = ff.big_infinity_encoding(true);
    assert_eq!(Wide::from_u64(f64::NEG_INFINITY.to_bits()), encoding);
    assert_eq!(ff.big_infinity(true), ff.decode_big_float(&encoding));

    let encoding = ff.big_nan_encoding(false);
    assert_eq!(Wide::from_u64(DOUBLE_NAN_BITS), encoding);
    assert_eq!(ff.big_nan(false), ff.decode_big_float(&encoding));

    // 80-bit encoding

    let ff = float_format(10);
    for d in [1.0_f64, 4.5, 3.75, -4.5] {
        assert_round_trip_only(&ff, &ff.big_float_from_f64(d).unwrap());
    }
    assert_round_trip_only(&ff, &ff.big_infinity(false));
    assert_round_trip_only(&ff, &ff.big_infinity(true));
    assert_round_trip_only(&ff, &ff.big_nan(false));

    // 128-bit encoding

    let ff = float_format(16);
    for d in [4.5_f64, 3.75, -4.5] {
        assert_round_trip_only(&ff, &ff.big_float_from_f64(d).unwrap());
    }
    assert_round_trip_only(&ff, &ff.big_infinity(false));
    assert_round_trip_only(&ff, &ff.big_infinity(true));
    assert_round_trip_only(&ff, &ff.big_nan(false));
}

#[test]
fn test_get_host_float() {
    // 32-bit encoding

    let ff = float_format(4);
    let f = 4.5_f32;
    let encoding = ff.encoding(f64::from(f));
    assert_eq!(u64::from(f.to_bits()), encoding);
    assert_eq!(f, decode_host_f32(&ff, encoding));

    // smallest subnormal value
    assert_eq!(FLOAT_MIN_VALUE, decode_host_f32(&ff, 1));

    // smallest subnormal value, negative. Java: `intbits = 0x80000001`, an
    // `int`, which `decodeHostFloat(long)` receives sign-extended.
    assert_eq!(
        -FLOAT_MIN_VALUE,
        decode_host_f32(&ff, int_bits_as_long(0x8000_0001))
    );
    assert_eq!(-FLOAT_MIN_VALUE, decode_host_f32(&ff, 0x8000_0001));

    // A subnormal, 3.75, -4.5 and the infinities.
    for f in [
        8.908_155E-39_f32,
        3.75,
        -4.5,
        f32::INFINITY,
        f32::NEG_INFINITY,
    ] {
        let encoding = ff.encoding(f64::from(f));
        assert_eq!(u64::from(f.to_bits()), encoding, "{f:e}");
        assert_eq!(f, decode_host_f32(&ff, encoding), "{f:e}");
    }

    let f = f32::from_bits(FLOAT_NAN_BITS);
    let encoding = ff.encoding(f64::from(f));
    assert_eq!(u64::from(FLOAT_NAN_BITS), encoding);
    // JUnit's assertEquals(NaN, x, 0) holds exactly when x is a NaN.
    assert!(decode_host_f32(&ff, encoding).is_nan());

    // 64-bit encoding

    let ff = float_format(8);
    for d in [4.5_f64, 3.75, -4.5, f64::INFINITY, f64::NEG_INFINITY] {
        let encoding = ff.encoding(d);
        assert_eq!(d.to_bits(), encoding, "{d:e}");
        assert_eq!(d, ff.host_float(encoding).0, "{d:e}");
    }

    let d = f64::from_bits(DOUBLE_NAN_BITS);
    let encoding = ff.encoding(d);
    assert_eq!(DOUBLE_NAN_BITS, encoding);
    assert!(ff.host_float(encoding).0.is_nan());
}

/// `java.util.Random`: the 48-bit linear congruential generator, so the
/// tests see the values the Java tests see.
struct JavaRandom {
    seed: u64,
}

impl JavaRandom {
    const MULTIPLIER: u64 = 0x5_DEEC_E66D;
    const MASK: u64 = (1 << 48) - 1;

    /// `new Random(seed)`.
    fn new(seed: u64) -> JavaRandom {
        JavaRandom {
            seed: (seed ^ JavaRandom::MULTIPLIER) & JavaRandom::MASK,
        }
    }

    /// `next(bits)`: the top `bits` bits of the next state, as the bit
    /// pattern of Java's `int` result.
    fn next(&mut self, bits: u32) -> u32 {
        self.seed = self
            .seed
            .wrapping_mul(JavaRandom::MULTIPLIER)
            .wrapping_add(0xB)
            & JavaRandom::MASK;
        (self.seed >> (48 - bits)) as u32
    }

    /// `nextInt()`, as its bit pattern.
    fn next_int(&mut self) -> u32 {
        self.next(32)
    }

    /// `nextLong()`, as its bit pattern: `((long) next(32) << 32) + next(32)`
    /// with both halves signed.
    fn next_long(&mut self) -> u64 {
        let high = i64::from(self.next(32) as i32);
        let low = i64::from(self.next(32) as i32);
        (high << 32).wrapping_add(low) as u64
    }

    /// `nextFloat()`: `next(24) / (float) (1 << 24)`.
    fn next_float(&mut self) -> f32 {
        self.next(24) as f32 / (1_u32 << 24) as f32
    }
}

/// Checks [`JavaRandom`] against the well-known first outputs of
/// `new Random(1)`.
fn assert_java_random_matches_java() {
    assert_eq!(JavaRandom::new(1).next_int(), (-1_155_869_325_i32) as u32);
    assert_eq!(
        JavaRandom::new(1).next_long(),
        (-4_964_420_948_893_066_024_i64) as u64
    );
    assert_eq!(JavaRandom::new(1).next_float(), 0.730_878_2);
}

#[test]
fn test_big_float_float_format_random() {
    assert_java_random_matches_java();
    let mut rand = JavaRandom::new(1);
    let float_format = float_format(4);

    for i in 0..1000 {
        let f = rand.next_float();
        let encoding0 = Wide::from_u64(u64::from(f.to_bits()));
        let bf1 = float_format.decode_big_float(&encoding0);
        let bf2 = BigFloat::from_f32(f);
        assert_eq!(bf1.to_string(), bf2.to_string(), "case #{i}");
        let encoding1 = float_format.encode_big_float(&bf1);
        assert_eq!(encoding0, encoding1, "case #{i}");
    }
}

#[test]
fn test_big_float_double_format_random() {
    assert_java_random_matches_java();
    let mut rand = JavaRandom::new(1);
    let float_format = float_format(8);

    for i in 0..1000 {
        // Java: `double f = rand.nextFloat();`
        let f = f64::from(rand.next_float());
        let encoding0 = Wide::from_u64(f.to_bits());
        let bf1 = float_format.decode_big_float(&encoding0);
        let bf2 = BigFloat::from_f64(f);
        assert_eq!(bf1.to_string(), bf2.to_string(), "case #{i}");
        let encoding1 = float_format.encode_big_float(&bf1);
        assert_eq!(encoding0, encoding1, "case #{i}");
    }
}

/// `BigFloatTest.NUM_RANDOM_TEST_VALUES_UNARY`.
const NUM_RANDOM_TEST_VALUES_UNARY: usize = 1000;

/// `BigFloatTest.testDoubleList`: the special values, then
/// `Double.longBitsToDouble` of 1000 `nextLong()` of `new Random(1)`.
fn test_double_list() -> Vec<f64> {
    let mut list = vec![
        -0.0,
        0.0,
        -1.0,
        1.0,
        -DOUBLE_MIN_VALUE,
        DOUBLE_MIN_VALUE,
        -f64::MAX,
        f64::MAX,
        -f64::MIN_POSITIVE - DOUBLE_MIN_VALUE,
        -f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE + DOUBLE_MIN_VALUE,
        f64::MIN_POSITIVE - DOUBLE_MIN_VALUE,
        f64::MIN_POSITIVE,
        f64::MIN_POSITIVE + DOUBLE_MIN_VALUE,
        f64::from_bits(DOUBLE_NAN_BITS),
        f64::NEG_INFINITY,
        f64::INFINITY,
    ];
    let mut rand = JavaRandom::new(1);
    list.extend((0..NUM_RANDOM_TEST_VALUES_UNARY).map(|_| f64::from_bits(rand.next_long())));
    list
}

/// `BigFloatTest.testFloatList`: the special values, then
/// `Float.intBitsToFloat` of 1000 `nextInt()` of `new Random(1)`.
fn test_float_list() -> Vec<f32> {
    let mut list = vec![
        -0.0,
        0.0,
        -1.0,
        1.0,
        -FLOAT_MIN_VALUE,
        FLOAT_MIN_VALUE,
        -f32::MAX,
        f32::MAX,
        -f32::MIN_POSITIVE - FLOAT_MIN_VALUE,
        -f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE + FLOAT_MIN_VALUE,
        f32::MIN_POSITIVE - FLOAT_MIN_VALUE,
        f32::MIN_POSITIVE,
        f32::MIN_POSITIVE + FLOAT_MIN_VALUE,
        f32::from_bits(FLOAT_NAN_BITS),
        f32::NEG_INFINITY,
        f32::INFINITY,
    ];
    let mut rand = JavaRandom::new(1);
    list.extend((0..NUM_RANDOM_TEST_VALUES_UNARY).map(|_| f32::from_bits(rand.next_int())));
    list
}

#[test]
fn test_big_float_to_double_encoding() {
    assert_java_random_matches_java();
    let ff8 = float_format(8);
    for (i, d) in test_double_list().into_iter().enumerate() {
        let e = d.to_bits();
        let bd = BigFloat::from_f64(d);
        let be = ff8.encode_big_float(&bd);
        assert_eq!(Wide::from_u64(e), be, "case #{i}");
    }
}

#[test]
fn test_big_float_to_float_encoding() {
    assert_java_random_matches_java();
    let ff4 = float_format(4);
    for (i, f) in test_float_list().into_iter().enumerate() {
        let e = f.to_bits();
        let bf = BigFloat::from_f32(f);
        if f.is_nan() {
            assert!(bf.is_nan(), "case #{i}");
        } else {
            let be = ff4.encode_big_float(&bf);
            assert_eq!(Wide::from_u64(u64::from(e)), be, "case #{i}");
        }
    }
}
