//! Derived tests of the wide path (`behavior::wide`, Java `BigInteger`
//! semantics) at sizes the Java tests do not reach, and of its float
//! operations on the exact level.

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

use bk_pcode::behavior::wide;
use bk_pcode::{EvalError, FloatFormat, FloatFormats, OpCode, Wide};

const FORMATS: FloatFormats = FloatFormats::DEFAULT;

fn wide_unary(op: OpCode, size_out: u32, size_in: u32, in1: Wide) -> Wide {
    wide::evaluate_unary(op, size_out, size_in, &in1, &FloatFormats::IEEE).unwrap()
}

fn wide_binary(op: OpCode, size_out: u32, size_in: u32, in1: Wide, in2: Wide) -> Wide {
    wide::evaluate_binary(op, size_out, size_in, &in1, &in2, &FloatFormats::IEEE).unwrap()
}

fn w(value: u128) -> Wide {
    Wide::from_u128(value)
}

#[test]
fn wide_integer_operations() {
    let max16 = w(u128::MAX);
    assert_eq!(wide_binary(OpCode::IntAdd, 16, 16, max16, w(1)), Wide::ZERO);
    assert_eq!(
        wide_binary(OpCode::IntAdd, 32, 32, max16, w(1)),
        Wide::ONE << 128
    );
    assert_eq!(wide_binary(OpCode::IntSub, 16, 16, w(0), w(1)), max16);
    assert_eq!(wide_binary(OpCode::IntSub, 64, 64, w(0), w(1)), Wide::MAX);
    assert_eq!(wide_binary(OpCode::IntMult, 16, 16, max16, max16), w(1));
    assert_eq!(
        wide_binary(OpCode::IntMult, 32, 32, w(1 << 100), w(1 << 100)),
        Wide::ONE << 200
    );
    assert_eq!(wide_unary(OpCode::Int2Comp, 16, 16, w(1)), max16);
    assert_eq!(
        wide_unary(OpCode::IntNegate, 32, 32, Wide::ZERO),
        Wide::mask(32)
    );
    assert_eq!(wide_unary(OpCode::IntZExt, 32, 16, max16), max16);
    assert_eq!(wide_unary(OpCode::IntSExt, 32, 16, max16), Wide::mask(32));
    assert_eq!(
        wide_unary(OpCode::IntSExt, 16, 8, w(1 << 63)),
        w(u128::MAX << 63)
    );
    assert_eq!(wide_unary(OpCode::IntSExt, 32, 16, w(5)), w(5));
    assert_eq!(wide_unary(OpCode::PopCount, 2, 64, Wide::MAX), w(512));
    assert_eq!(wide_unary(OpCode::LzCount, 2, 64, Wide::ZERO), w(512));
    assert_eq!(wide_unary(OpCode::LzCount, 1, 16, w(1)), w(127));
    assert_eq!(wide_unary(OpCode::LzCount, 1, 16, max16), w(0));
    assert_eq!(wide_unary(OpCode::BoolNegate, 1, 1, w(0)), w(1));

    let min16 = w(1 << 127);
    assert_eq!(wide_binary(OpCode::IntLess, 1, 16, w(1), min16), w(1));
    assert_eq!(wide_binary(OpCode::IntSLess, 1, 16, w(1), min16), w(0));
    assert_eq!(wide_binary(OpCode::IntSLess, 1, 16, min16, w(1)), w(1));
    assert_eq!(
        wide_binary(OpCode::IntSLessEqual, 1, 16, max16, max16),
        w(1)
    );
    assert_eq!(wide_binary(OpCode::IntSLessEqual, 1, 16, w(0), max16), w(0));
    assert_eq!(wide_binary(OpCode::IntLessEqual, 1, 16, max16, w(0)), w(0));
    assert_eq!(wide_binary(OpCode::IntEqual, 1, 16, max16, max16), w(1));
    assert_eq!(wide_binary(OpCode::IntNotEqual, 1, 16, max16, max16), w(0));
    assert_eq!(wide_binary(OpCode::IntCarry, 1, 16, max16, w(1)), w(1));
    assert_eq!(wide_binary(OpCode::IntCarry, 1, 16, max16 >> 1, w(1)), w(0));
    assert_eq!(
        wide_binary(OpCode::IntSCarry, 1, 16, max16 >> 1, w(1)),
        w(1)
    );
    assert_eq!(wide_binary(OpCode::IntSCarry, 1, 16, max16, w(1)), w(0));
    assert_eq!(wide_binary(OpCode::IntSBorrow, 1, 16, min16, w(1)), w(1));
    assert_eq!(wide_binary(OpCode::IntSBorrow, 1, 16, w(0), w(1)), w(0));

    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, w(1), w(127)), min16);
    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, max16, w(128)), w(0));
    assert_eq!(wide_binary(OpCode::IntLeft, 16, 16, max16, Wide::MAX), w(0));
    assert_eq!(wide_binary(OpCode::IntRight, 16, 16, min16, w(127)), w(1));
    assert_eq!(wide_binary(OpCode::IntRight, 16, 16, max16, w(128)), w(0));
    assert_eq!(wide_binary(OpCode::IntSRight, 16, 16, min16, w(127)), max16);
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16, w(4)),
        w(0xf8 << 120)
    );
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16, w(1000)),
        max16
    );
    assert_eq!(
        wide_binary(OpCode::IntSRight, 16, 16, min16 >> 1, w(1000)),
        w(0)
    );

    let div_zero = Err(EvalError::DivideByZero);
    let rem_zero = Err(EvalError::RemainderByZero);
    let evaluate = |op, a, b| wide::evaluate_binary(op, 16, 16, &a, &b, &FORMATS);
    assert_eq!(evaluate(OpCode::IntDiv, w(1), w(0)), div_zero);
    assert_eq!(evaluate(OpCode::IntSDiv, w(1), w(0)), div_zero);
    assert_eq!(evaluate(OpCode::IntRem, w(1), w(0)), rem_zero);
    assert_eq!(evaluate(OpCode::IntSRem, w(1), w(0)), rem_zero);
    assert_eq!(wide_binary(OpCode::IntDiv, 16, 16, max16, w(2)), max16 >> 1);
    assert_eq!(wide_binary(OpCode::IntSDiv, 16, 16, max16, w(2)), w(0)); // -1 / 2
    assert_eq!(
        wide_binary(OpCode::IntSDiv, 16, 16, w((-7i128) as u128), w(2)),
        w((-3i128) as u128)
    );
    assert_eq!(wide_binary(OpCode::IntSDiv, 16, 16, min16, max16), min16); // MIN / -1
    assert_eq!(wide_binary(OpCode::IntSRem, 16, 16, min16, max16), w(0)); // MIN % -1
    assert_eq!(
        wide_binary(OpCode::IntSRem, 16, 16, w((-7i128) as u128), w(2)),
        max16
    ); // -1
    assert_eq!(
        wide_binary(OpCode::IntRem, 16, 16, max16, w(10)),
        w(u128::MAX % 10)
    );

    assert_eq!(wide_binary(OpCode::BoolXor, 1, 1, w(1), w(1)), w(0));
    assert_eq!(
        wide_binary(OpCode::IntXor, 16, 16, max16, w(1)),
        w(u128::MAX - 1)
    );
    assert_eq!(wide_binary(OpCode::IntAnd, 16, 16, max16, w(0xf0)), w(0xf0));
    assert_eq!(
        wide_binary(OpCode::IntOr, 16, 16, min16, w(1)),
        w((1 << 127) | 1)
    );
}

#[test]
fn wide_piece_and_subpiece() {
    // An 8-byte high piece on a 16-byte low piece: 24 bytes.
    let high = w(0x1122_3344_5566_7788);
    let low = w(0xaabb_ccdd_eeff_0011_2233_4455_6677_8899);
    let joined = wide_binary(OpCode::Piece, 24, 8, high, low);
    assert_eq!(joined, (high << 128) | low);
    assert_eq!(wide_binary(OpCode::SubPiece, 8, 24, joined, w(16)), high);
    assert_eq!(wide_binary(OpCode::SubPiece, 16, 24, joined, w(0)), low);
    assert_eq!(
        wide_binary(OpCode::SubPiece, 4, 24, joined, w(20)),
        w(0x1122_3344)
    );
    assert_eq!(wide_binary(OpCode::SubPiece, 4, 24, joined, w(24)), w(0));
    assert_eq!(
        wide_binary(OpCode::SubPiece, 4, 24, joined, Wide::MAX),
        w(0)
    );
    // Two 32-byte halves of a 64-byte register.
    let whole = wide_binary(OpCode::Piece, 64, 32, Wide::mask(32), Wide::ONE);
    assert_eq!(whole, (Wide::mask(32) << 256) | Wide::ONE);
    assert_eq!(
        wide_binary(OpCode::SubPiece, 32, 64, whole, w(32)),
        Wide::mask(32)
    );
}

#[test]
fn wide_sizes_are_limited_to_64_bytes() {
    let too_big = Err(EvalError::UnsupportedSize {
        size: 65,
        limit: 64,
    });
    let (a, b) = (Wide::ONE, Wide::ONE);
    assert_eq!(
        wide::evaluate_unary(OpCode::Copy, 65, 4, &a, &FORMATS),
        too_big
    );
    assert_eq!(
        wide::evaluate_unary(OpCode::Copy, 4, 65, &a, &FORMATS),
        too_big
    );
    assert_eq!(
        wide::evaluate_binary(OpCode::IntAdd, 65, 65, &a, &b, &FORMATS),
        too_big
    );
    assert!(wide::evaluate_binary(OpCode::IntAdd, 64, 64, &a, &b, &FORMATS).is_ok());
    assert_eq!(wide_unary(OpCode::Copy, 0, 0, Wide::MAX), Wide::ZERO);
}

#[test]
fn wide_float_operations_use_the_exact_level() {
    let x87 = FloatFormat::EXTENDED;
    let quad = FloatFormat::QUAD;
    let encode = |format: &FloatFormat, value: f64| {
        format.encode_big_float(&format.big_float_from_f64(value).unwrap())
    };
    let decode = |format: &FloatFormat, encoding: Wide| format.decode_big_float(&encoding).to_f64();
    for (format, size) in [(&x87, 10u32), (&quad, 16), (&FloatFormat::OCTUPLE, 32)] {
        let (a, b) = (encode(format, 1.5), encode(format, 2.25));
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatAdd, size, size, a, b)),
            3.75
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatSub, size, size, a, b)),
            -0.75
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatMult, size, size, a, b)),
            3.375
        );
        assert_eq!(
            decode(format, wide_binary(OpCode::FloatDiv, size, size, b, a)),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatSqrt, size, size, b)),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatNeg, size, size, a)),
            -1.5
        );
        assert_eq!(
            decode(
                format,
                wide_unary(OpCode::FloatAbs, size, size, encode(format, -1.5))
            ),
            1.5
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatCeil, size, size, a)),
            2.0
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatFloor, size, size, a)),
            1.0
        );
        assert_eq!(
            decode(format, wide_unary(OpCode::FloatRound, size, size, a)),
            2.0
        );
        assert_eq!(wide_unary(OpCode::FloatTrunc, 8, size, b), w(2));
        assert_eq!(
            wide_unary(OpCode::FloatTrunc, 4, size, encode(format, -2.25)),
            w(0xffff_fffe)
        );
        assert_eq!(wide_binary(OpCode::FloatLess, 1, size, a, b), w(1));
        assert_eq!(wide_binary(OpCode::FloatLessEqual, 1, size, b, a), w(0));
        assert_eq!(wide_binary(OpCode::FloatEqual, 1, size, a, a), w(1));
        assert_eq!(wide_binary(OpCode::FloatNotEqual, 1, size, a, a), w(0));
        assert_eq!(wide_unary(OpCode::FloatNan, 1, size, a), w(0));
        assert_eq!(
            wide_unary(OpCode::FloatNan, 1, size, format.big_nan_encoding(false)),
            w(1)
        );
        // Conversions to and from binary64, and from integers.
        let from_double = wide_unary(
            OpCode::FloatFloat2Float,
            size,
            8,
            w(u128::from(0.1f64.to_bits())),
        );
        assert_eq!(decode(format, from_double), 0.1);
        let to_double = wide_unary(OpCode::FloatFloat2Float, 8, size, from_double);
        assert_eq!(to_double, w(u128::from(0.1f64.to_bits())));
        let from_int = wide_unary(
            OpCode::FloatInt2Float,
            size,
            8,
            w(u128::from((-12345i64) as u64)),
        );
        assert_eq!(decode(format, from_int), -12345.0);
        // The result is a clean value of the format's size.
        assert_eq!(
            wide_binary(OpCode::FloatAdd, size, size, a, b).truncate(size),
            wide_binary(OpCode::FloatAdd, size, size, a, b)
        );
    }
    // 1/3 in binary128 has the repeating fraction 0x5555…
    let third = wide_binary(
        OpCode::FloatDiv,
        16,
        16,
        encode(&quad, 1.0),
        encode(&quad, 3.0),
    );
    assert_eq!(third, w(0x3ffd_5555_5555_5555_5555_5555_5555_5555));
    // sqrt(2) in binary128.
    let root = wide_unary(OpCode::FloatSqrt, 16, 16, encode(&quad, 2.0));
    assert_eq!(root, w(0x3fff_6a09_e667_f3bc_c908_b2fb_1366_ea95));
    // 1/3 in the x87 format: exponent 0x3ffd, significand 0xaaaa…ab.
    let third = wide_binary(
        OpCode::FloatDiv,
        10,
        10,
        encode(&x87, 1.0),
        encode(&x87, 3.0),
    );
    assert_eq!(third, w((0x3ffd_u128 << 64) | 0xaaaa_aaaa_aaaa_aaab));
    // No format for 12 bytes.
    let none = wide::evaluate_binary(
        OpCode::FloatAdd,
        12,
        12,
        &Wide::ZERO,
        &Wide::ZERO,
        &FloatFormats::IEEE,
    );
    assert_eq!(
        none,
        Err(EvalError::NoFloatFormat {
            op: OpCode::FloatAdd,
            size: 12
        })
    );
    // The decompiler's table has no wide formats.
    let none = wide::evaluate_binary(OpCode::FloatAdd, 16, 16, &Wide::ZERO, &Wide::ZERO, &FORMATS);
    assert_eq!(
        none,
        Err(EvalError::NoFloatFormat {
            op: OpCode::FloatAdd,
            size: 16
        })
    );
}
