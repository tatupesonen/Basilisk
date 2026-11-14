//! Property tests of the floating-point operations.
//!
//! - Host level (the `u64` path, C++ `float.cc`) at 4 and 8 bytes against
//!   native `f32`/`f64`. NaN rule (x86-64's, `src/float/host.rs`): a NaN
//!   result is the quiet NaN with the sign of the NaN input; with two NaN
//!   inputs, that of `b` for add and multiply and of `a` for subtract and
//!   divide; negative (x86-64's default NaN) when the operation creates it;
//!   payloads are not kept. `FLOAT_NEG` and
//!   `FLOAT_ABS` act on the sign bit of a NaN.
//! - Exact level (Java `BigFloat`) at 4 and 8 bytes against native: every NaN
//!   result is the positive quiet NaN; comparisons are IEEE.
//! - Encode/decode round trips for every format, decimal conversion against
//!   `str::parse::<f64>`, and `to_decimal_string` reading back.

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

use bk_pcode::behavior::evaluate_unary;
use bk_pcode::{BigFloat, Decimal, FloatFormat, FloatFormats, OpCode, Wide};
use proptest::prelude::*;

const F4: FloatFormat = FloatFormat::SINGLE;
const F8: FloatFormat = FloatFormat::DOUBLE;

/// `f32` bit patterns, weighted towards the classes and edges.
fn f32_bits() -> impl Strategy<Value = u32> {
    prop_oneof![
        3 => any::<u32>(),
        1 => prop::sample::select(vec![
            0u32, 0x8000_0000, 1, 0x8000_0001, 0x007f_ffff, 0x0080_0000, 0x7f7f_ffff,
            0x7f80_0000, 0xff80_0000, 0x7fc0_0000, 0xffc0_0000, 0x7f80_0001, 0xff80_0001,
            0x3f00_0000, 0xbf00_0000, 0x3fc0_0000, 0x4020_0000, 0xc020_0000, 0x5f00_0000,
        ]),
        2 => (-1000.0f32..1000.0).prop_map(f32::to_bits),
        1 => (-8i32..8).prop_map(|n| (n as f32 * 0.5).to_bits()),
    ]
}

/// `f64` bit patterns, weighted towards the classes and edges.
fn f64_bits() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => any::<u64>(),
        1 => prop::sample::select(vec![
            0u64, 1 << 63, 1, 0x000f_ffff_ffff_ffff, 0x0010_0000_0000_0000,
            0x7fef_ffff_ffff_ffff, 0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000,
            0x7ff8_0000_0000_0000, 0xfff8_0000_0000_0000, 0x7ff0_0000_0000_0001,
            0xfff0_0000_0000_0001, 0x43e0_0000_0000_0000, 0xc3e0_0000_0000_0000,
        ]),
        2 => (-1.0e6f64..1.0e6).prop_map(f64::to_bits),
        1 => (-8i32..8).prop_map(|n| (f64::from(n) * 0.5).to_bits()),
    ]
}

/// The sign a host-level NaN result has: that of the first NaN among
/// `inputs` (listed in x86-64's priority order), or negative when no input
/// is a NaN.
fn nan_sign(inputs: &[(bool, bool)]) -> bool {
    inputs
        .iter()
        .find(|(is_nan, _)| *is_nan)
        .is_none_or(|(_, negative)| *negative)
}

macro_rules! host_vs_native {
    ($name:ident, $f:ty, $bits:ident, $fmt:expr, $from_i64:expr) => {
        mod $name {
            use super::*;
            const FMT: FloatFormat = $fmt;

            fn enc(x: $f) -> u64 {
                u64::from(x.to_bits())
            }
            fn expect(native: $f, inputs: &[$f]) -> u64 {
                if native.is_nan() {
                    let info: Vec<(bool, bool)> =
                        inputs.iter().map(|x| (x.is_nan(), x.is_sign_negative())).collect();
                    FMT.nan_encoding(nan_sign(&info))
                } else {
                    enc(native)
                }
            }
            fn exact_expect(native: $f) -> Wide {
                if native.is_nan() {
                    FMT.big_nan_encoding(false)
                } else {
                    Wide::from_u64(enc(native))
                }
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(4096))]

                #[test]
                fn binary_host(a in $bits(), b in $bits()) {
                    let (x, y) = (<$f>::from_bits(a), <$f>::from_bits(b));
                    let (ea, eb) = (u64::from(a), u64::from(b));
                    prop_assert_eq!(FMT.op_add(ea, eb), expect(x + y, &[y, x]));
                    prop_assert_eq!(FMT.op_sub(ea, eb), expect(x - y, &[x, y]));
                    prop_assert_eq!(FMT.op_mult(ea, eb), expect(x * y, &[y, x]));
                    prop_assert_eq!(FMT.op_div(ea, eb), expect(x / y, &[x, y]));
                    prop_assert_eq!(FMT.op_equal(ea, eb), u64::from(x == y));
                    prop_assert_eq!(FMT.op_not_equal(ea, eb), u64::from(x != y));
                    prop_assert_eq!(FMT.op_less(ea, eb), u64::from(x < y));
                    prop_assert_eq!(FMT.op_less_equal(ea, eb), u64::from(x <= y));
                }

                #[test]
                fn unary_host(a in $bits()) {
                    let x = <$f>::from_bits(a);
                    let ea = u64::from(a);
                    prop_assert_eq!(FMT.op_sqrt(ea), expect(x.sqrt(), &[x]));
                    prop_assert_eq!(FMT.op_ceil(ea), expect(x.ceil(), &[x]));
                    prop_assert_eq!(FMT.op_floor(ea), expect(x.floor(), &[x]));
                    // The C++ `round()`: halfway cases away from zero.
                    prop_assert_eq!(FMT.op_round(ea), expect(x.round(), &[x]));
                    prop_assert_eq!(FMT.op_nan(ea), u64::from(x.is_nan()));
                    let (neg, abs) = if x.is_nan() {
                        (FMT.nan_encoding(!x.is_sign_negative()), FMT.nan_encoding(false))
                    } else {
                        (enc(-x), enc(x.abs()))
                    };
                    prop_assert_eq!(FMT.op_neg(ea), neg);
                    prop_assert_eq!(FMT.op_abs(ea), abs);
                    // TRUNC goes through `i64` (saturating, NaN to 0) and is
                    // then cut to the output size.
                    let t = f64::from(x) as i64 as u64;
                    for out in [1u32, 2, 4, 8] {
                        let mask = u64::MAX >> (64 - 8 * out);
                        prop_assert_eq!(FMT.op_trunc(ea, out), t & mask);
                    }
                    // Encode/decode round trip.
                    let (host, _) = FMT.host_float(ea);
                    let back = FMT.encoding(host);
                    if x.is_nan() {
                        prop_assert_eq!(back, FMT.nan_encoding(x.is_sign_negative()));
                    } else {
                        prop_assert_eq!(back, ea);
                        prop_assert_eq!(host, f64::from(x));
                    }
                }

                #[test]
                fn int2float_host(i: i64, size_index in 0usize..4) {
                    let size = [1u32, 2, 4, 8][size_index];
                    let value = (i << (64 - 8 * size)) >> (64 - 8 * size);
                    let a = value as u64 & (u64::MAX >> (64 - 8 * size));
                    // Through a host double, as the C++ does (so an `i64`
                    // into binary32 is rounded twice).
                    let want = enc(($from_i64)(value));
                    prop_assert_eq!(FMT.op_int2float(a, size), want);
                    let via_table = evaluate_unary(
                        OpCode::FloatInt2Float, FMT.size(), size, a, &FloatFormats::DEFAULT,
                    );
                    prop_assert_eq!(via_table, Ok(want));
                }

                #[test]
                fn binary_exact(a in $bits(), b in $bits()) {
                    let (x, y) = (<$f>::from_bits(a), <$f>::from_bits(b));
                    let (wa, wb) = (Wide::from_u64(u64::from(a)), Wide::from_u64(u64::from(b)));
                    prop_assert_eq!(FMT.op_add_exact(&wa, &wb), exact_expect(x + y));
                    prop_assert_eq!(FMT.op_sub_exact(&wa, &wb), exact_expect(x - y));
                    prop_assert_eq!(FMT.op_mult_exact(&wa, &wb), exact_expect(x * y));
                    prop_assert_eq!(FMT.op_div_exact(&wa, &wb), exact_expect(x / y));
                    prop_assert_eq!(FMT.op_equal_exact(&wa, &wb), x == y);
                    prop_assert_eq!(FMT.op_not_equal_exact(&wa, &wb), x != y);
                    prop_assert_eq!(FMT.op_less_exact(&wa, &wb), x < y);
                    prop_assert_eq!(FMT.op_less_equal_exact(&wa, &wb), x <= y);
                }

                #[test]
                fn unary_exact(a in $bits()) {
                    let x = <$f>::from_bits(a);
                    let wa = Wide::from_u64(u64::from(a));
                    prop_assert_eq!(FMT.op_sqrt_exact(&wa), exact_expect(x.sqrt()));
                    prop_assert_eq!(FMT.op_ceil_exact(&wa), exact_expect(x.ceil()));
                    prop_assert_eq!(FMT.op_floor_exact(&wa), exact_expect(x.floor()));
                    // Java: floor(x + 0.5) with the sum rounded to the format.
                    prop_assert_eq!(FMT.op_round_exact(&wa), exact_expect((x + 0.5).floor()));
                    prop_assert_eq!(FMT.op_neg_exact(&wa), exact_expect(-x));
                    prop_assert_eq!(FMT.op_abs_exact(&wa), exact_expect(x.abs()));
                    prop_assert_eq!(FMT.op_nan_exact(&wa), x.is_nan());
                    if x.is_finite() && f64::from(x).abs() < 9.2e18 {
                        let t = FMT.op_trunc_exact(&wa);
                        prop_assert_eq!(t.low_u64(), f64::from(x) as i64 as u64);
                    }
                    // Round trip through BigFloat.
                    let back = FMT.encode_big_float(&FMT.decode_big_float(&wa));
                    prop_assert_eq!(back, if x.is_nan() { FMT.big_nan_encoding(false) } else { wa });
                }
            }
        }
    };
}

host_vs_native!(single, f32, f32_bits, F4, |v: i64| v as f64 as f32);
host_vs_native!(double, f64, f64_bits, F8, |v: i64| v as f64);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn float2float_host_and_exact(a in f32_bits(), b in f64_bits()) {
        let (x, y) = (f32::from_bits(a), f64::from_bits(b));
        let widened = F4.op_float2float(u64::from(a), &F8);
        let want = if x.is_nan() { F8.nan_encoding(x.is_sign_negative()) } else { f64::from(x).to_bits() };
        prop_assert_eq!(widened, want);
        let narrowed = F8.op_float2float(b, &F4);
        let want = if y.is_nan() {
            F4.nan_encoding(y.is_sign_negative())
        } else {
            u64::from((y as f32).to_bits())
        };
        prop_assert_eq!(narrowed, want);
        let exact = F8.op_float2float_exact(&Wide::from_u64(b), &F4);
        let want = if y.is_nan() { F4.big_nan_encoding(false) } else { Wide::from_u64(u64::from((y as f32).to_bits())) };
        prop_assert_eq!(exact, want);
    }

    #[test]
    fn int2float_exact_rounds_once(i: i64) {
        // Java's `BigInteger` overload at 4 and 8 bytes converts directly
        // (`floatValue`, `doubleValue`).
        let wa = Wide::from_u64(i as u64);
        prop_assert_eq!(F4.op_int2float_exact(&wa, 8, true), Wide::from_u64(u64::from((i as f32).to_bits())));
        prop_assert_eq!(F8.op_int2float_exact(&wa, 8, true), Wide::from_u64((i as f64).to_bits()));
    }

    #[test]
    fn half_round_trips_on_the_host_level(a: u16) {
        let half = FloatFormat::HALF;
        let a = u64::from(a);
        let back = half.encoding(half.host_float(a).0);
        if half.op_nan(a) == 1 {
            prop_assert_eq!(back, half.nan_encoding(a >> 15 == 1));
        } else {
            prop_assert_eq!(back, a);
        }
    }

    #[test]
    fn every_format_round_trips_on_the_exact_level(
        index in 0usize..6,
        bytes in proptest::collection::vec(any::<u8>(), 32),
    ) {
        let format = [
            FloatFormat::HALF, FloatFormat::SINGLE, FloatFormat::DOUBLE,
            FloatFormat::EXTENDED, FloatFormat::QUAD, FloatFormat::OCTUPLE,
        ][index];
        let size = format.size() as usize;
        let mut encoding = Wide::from_le_bytes(&bytes[..size]).unwrap();
        if !format.jbit_implied() {
            // x87: Java gives it no subnormals and no unnormals, so only
            // encodings with the integer bit set and an exponent other than
            // 0 and the maximum, or zero, decode to what they encode.
            let exponent_bits = (encoding >> 64).low_u64() & 0x7fff;
            if exponent_bits == 0 || exponent_bits == 0x7fff {
                encoding = encoding & (Wide::ONE << 79);
            } else {
                encoding = encoding | (Wide::ONE << 63);
            }
        }
        let value = format.decode_big_float(&encoding);
        let back = format.encode_big_float(&value);
        if value.is_nan() {
            prop_assert_eq!(back, format.big_nan_encoding(false));
        } else {
            prop_assert_eq!(back, encoding, "{:x}", encoding);
        }
    }

    #[test]
    fn decimal_to_f64_is_correctly_rounded(
        digits in "[0-9]{1,30}",
        point in 0usize..30,
        exponent in -360i32..330,
        negative: bool,
    ) {
        let point = point.min(digits.len());
        let text = format!(
            "{}{}.{}e{}",
            if negative { "-" } else { "" },
            digits.get(..point).unwrap(),
            digits.get(point..).unwrap(),
            exponent
        );
        let text = text.replace("-.", "-0.").replace(".e", ".0e");
        let text = if text.starts_with('.') { format!("0{text}") } else { text };
        let decimal: Decimal = text.parse().unwrap();
        // A decimal has no negative zero (as Java's `BigDecimal`).
        let exact_zero = decimal.signum() == 0;
        let want: f64 = text.parse().unwrap();
        let want = if exact_zero { 0.0 } else { want };
        prop_assert_eq!(decimal.to_f64().to_bits(), want.to_bits(), "{}", text);
        let want: f32 = text.parse().unwrap();
        let want = if exact_zero { 0.0 } else { want };
        prop_assert_eq!(decimal.to_f32().to_bits(), want.to_bits(), "{}", text);
    }

    #[test]
    fn compact_decimal_text_keeps_the_encoding(bits in f64_bits()) {
        // Java first rounds to the display precision (16 digits for
        // binary64, so the text need not read back to `x`), then drops
        // digits while the text still converts to the same encoding.
        let x = f64::from_bits(bits);
        if !x.is_finite() {
            return Ok(());
        }
        let value = BigFloat::from_f64(x);
        let full = F8.to_decimal_string(&value, false);
        let compact = F8.to_decimal_string(&value, true);
        let (full_back, compact_back): (f64, f64) = (full.parse().unwrap(), compact.parse().unwrap());
        prop_assert_eq!(compact_back.to_bits(), full_back.to_bits(), "{} {}", full, compact);
        prop_assert!(compact.len() <= full.len());
        // Rounding to 16 digits can overflow next to the largest value
        // (`1.797693134862316E+308`), as in Java.
        if full_back.is_finite() {
            prop_assert!((full_back - x).abs() <= x.abs() * 1e-15, "{}", full);
        }
    }
}
