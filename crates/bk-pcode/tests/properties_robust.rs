//! "Never panics" property tests (spec acceptance 3): every opcode, sizes 0
//! to 64 bytes and a few huge ones, any operand values, through every entry
//! point that takes a size, with the full IEEE format table (so the `u64`
//! path also meets formats it cannot compute with). Each call must return,
//! with a value or an error.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

use bk_pcode::behavior::{
    evaluate_binary, evaluate_ternary, evaluate_unary, recover_input_binary, recover_input_unary,
    wide,
};
use bk_pcode::{FloatFormat, FloatFormats, OpCode, Wide};
use proptest::prelude::*;

fn any_size() -> impl Strategy<Value = u32> {
    prop_oneof![
        8 => 0u32..=64,
        1 => prop::sample::select(vec![65u32, 128, 1000, u32::MAX / 8, u32::MAX - 1, u32::MAX]),
        1 => any::<u32>(),
    ]
}

fn any_wide() -> impl Strategy<Value = Wide> {
    prop_oneof![
        3 => proptest::collection::vec(any::<u8>(), 64)
            .prop_map(|bytes| Wide::from_le_bytes(&bytes).unwrap()),
        1 => any::<u64>().prop_map(Wide::from_u64),
        1 => Just(Wide::MAX),
        1 => Just(Wide::ZERO),
    ]
}

fn any_opcode() -> impl Strategy<Value = OpCode> {
    (0u8..=80).prop_filter_map("not an opcode", |n| OpCode::try_from(n).ok())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn u64_path_never_panics(
        op in any_opcode(),
        size_out in any_size(),
        size_in in any_size(),
        a: u64,
        b: u64,
        c: u64,
        slot in 0u32..3,
    ) {
        for formats in [FloatFormats::IEEE, FloatFormats::DEFAULT, FloatFormats::NONE] {
            let _ = evaluate_unary(op, size_out, size_in, a, &formats);
            let _ = evaluate_binary(op, size_out, size_in, a, b, &formats);
        }
        let _ = evaluate_ternary(op, size_out, size_in, a, b, c);
        let _ = recover_input_unary(op, size_out, a, size_in);
        let _ = recover_input_binary(op, slot, size_out, a, size_in, b);
    }

    #[test]
    fn wide_path_never_panics(
        op in any_opcode(),
        size_out in any_size(),
        size_in in any_size(),
        a in any_wide(),
        b in any_wide(),
    ) {
        for formats in [FloatFormats::IEEE, FloatFormats::NONE] {
            let _ = wide::evaluate_unary(op, size_out, size_in, &a, &formats);
            let _ = wide::evaluate_binary(op, size_out, size_in, &a, &b, &formats);
        }
    }

    #[test]
    fn float_formats_never_panic(index in 0usize..6, a in any_wide(), b in any_wide(), bits: u64, size in any_size()) {
        let format = [
            FloatFormat::HALF, FloatFormat::SINGLE, FloatFormat::DOUBLE,
            FloatFormat::EXTENDED, FloatFormat::QUAD, FloatFormat::OCTUPLE,
        ][index];
        // The host level on any format (meaningless but defined for the
        // formats it cannot compute with).
        let _ = format.host_float(bits);
        let _ = format.encoding(f64::from_bits(bits));
        let _ = format.op_add(bits, bits.rotate_left(17));
        let _ = format.op_trunc(bits, size);
        let _ = format.op_int2float(bits, size);
        let _ = format.print_decimal(f64::from_bits(bits), bits & 1 == 1);
        // The exact level on any encoding.
        let value = format.decode_big_float(&a);
        let _ = format.encode_big_float(&value);
        let _ = format.op_div_exact(&a, &b);
        let _ = format.op_sqrt_exact(&a);
        let _ = format.op_trunc_exact(&a);
        let _ = format.op_round_exact(&a);
        let _ = format.op_int2float_exact(&a, size, bits & 1 == 1);
        let _ = format.op_less_exact(&a, &b);
    }
}

proptest! {
    // Decimal text of the 32-byte format's extremes has about 80,000 digits
    // before rounding (as in Java), about 0.1 s each, so fewer cases.
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn decimal_text_never_panics(index in 0usize..6, a in any_wide(), compact: bool) {
        let format = [
            FloatFormat::HALF, FloatFormat::SINGLE, FloatFormat::DOUBLE,
            FloatFormat::EXTENDED, FloatFormat::QUAD, FloatFormat::OCTUPLE,
        ][index];
        let value = format.decode_big_float(&a);
        let _ = format.to_decimal_string(&value, compact);
        let _ = format.round_decimal(&value);
    }
}
