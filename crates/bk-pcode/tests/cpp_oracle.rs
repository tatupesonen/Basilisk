//! Differential test of the `u64` path against Ghidra's own C++ behaviours.
//!
//! `tests/data/opbehavior_cpp.txt.gz` holds the results of Ghidra's C++
//! `OpBehavior` classes (`opbehavior.cc`, `float.cc`) for about 87,000
//! operations: every opcode, sizes 0 to 8, edge and random operands, both
//! `recoverInput*` functions. It was produced by
//! `tests/oracle/opbehavior_oracle.cc`, linked against the reference build's
//! `libsla.a`, on x86-64 Linux with GCC (`tests/oracle/regen.sh` rebuilds
//! it). Where Ghidra's result depends on the host, basilisk takes x86-64's
//! (ADR-021), so the table is x86-64's.
//!
//! Every row must agree bit for bit, except the documented differences
//! (`docs/features/pcode.md`, section 8), each recognised by a narrow rule
//! and counted:
//!
//! - `FLOAT_TRUNC` of a NaN or of a value outside the `i64` range: x86-64's
//!   `cvttsd2si` gives `i64::MIN` (cut to the output size); basilisk
//!   saturates and maps NaN to 0, as Java's `(long)` cast does and Ghidra's
//!   Java tests pin (ADR-021);
//! - a subnormal that rounds up to the smallest normal value: the C++ gives
//!   zero; basilisk the smallest normal;
//! - recovering the input of a shift by 0 of an 8-byte value: the C++
//!   shifts by 64, which both hosts take as 0, and so reports every non-zero
//!   output as out of range; basilisk returns the output.

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

use std::collections::BTreeMap;
use std::io::Read;

use bk_pcode::behavior::{
    evaluate_binary, evaluate_ternary, evaluate_unary, recover_input_binary, recover_input_unary,
};
use bk_pcode::{FloatFormat, FloatFormats, OpCode};

const TABLE: &[u8] = include_bytes!("data/opbehavior_cpp.txt.gz");

fn hex(field: &str) -> u64 {
    u64::from_str_radix(field, 16).unwrap()
}

fn op(field: &str) -> OpCode {
    OpCode::try_from(u8::try_from(hex(field)).unwrap()).unwrap()
}

fn size(field: &str) -> u32 {
    u32::try_from(hex(field)).unwrap()
}

/// Why a row may differ from the C++ table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Explained {
    TruncSaturates,
    SubnormalRoundsToNormal,
    RecoverShiftByZero,
}

fn is_float_op(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual
            | OpCode::FloatNan
            | OpCode::FloatAdd
            | OpCode::FloatDiv
            | OpCode::FloatMult
            | OpCode::FloatSub
            | OpCode::FloatNeg
            | OpCode::FloatAbs
            | OpCode::FloatSqrt
            | OpCode::FloatInt2Float
            | OpCode::FloatFloat2Float
            | OpCode::FloatTrunc
            | OpCode::FloatCeil
            | OpCode::FloatFloor
            | OpCode::FloatRound
    )
}

/// Classifies a mismatch between the C++ result `cpp` and basilisk's `ours`
/// for a float operation whose result is in `out` and whose inputs are in
/// `input_format`. `None` means unexplained.
fn explain(
    op: OpCode,
    size_out: u32,
    out: &FloatFormat,
    input_format: &FloatFormat,
    inputs: &[u64],
    cpp: u64,
    ours: u64,
) -> Option<Explained> {
    if op == OpCode::FloatTrunc {
        let mask = bk_pcode::mask::calc_mask(size_out);
        let value = input_format.host_float(inputs[0]).0;
        // 2^63: the `i64` range is [-2^63, 2^63).
        let limit = (1u64 << 63) as f64;
        let in_range = (-limit..limit).contains(&value);
        // x86-64's "integer indefinite" value.
        let x86_indefinite = 1u64 << 63;
        let saturated = value as i64 as u64;
        if !in_range && cpp == x86_indefinite & mask && ours == saturated & mask {
            return Some(Explained::TruncSaturates);
        }
        return None;
    }
    let sign = 1u64 << (out.size() * 8 - 1);
    let smallest_normal = 1u64 << out.frac_size();
    let is_float_result = !matches!(
        op,
        OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual
            | OpCode::FloatNan
            | OpCode::FloatTrunc
    );
    if is_float_result && cpp & !sign == 0 && ours == (cpp & sign) | smallest_normal {
        return Some(Explained::SubnormalRoundsToNormal);
    }
    None
}

#[test]
fn u64_path_equals_ghidra_cpp() {
    let mut text = String::new();
    flate2::read::GzDecoder::new(TABLE)
        .read_to_string(&mut text)
        .unwrap();
    let formats = FloatFormats::DEFAULT;
    let mut rows = 0usize;
    let mut explained: BTreeMap<Explained, usize> = BTreeMap::new();
    let mut unexplained = Vec::new();
    for line in text.lines() {
        rows += 1;
        let (call, expected) = line.split_once(" = ").unwrap();
        let f: Vec<&str> = call.split(' ').collect();
        let (opcode, result, float_context) = match f[0] {
            "U" => {
                let (o, out, inp, a) = (op(f[1]), size(f[2]), size(f[3]), hex(f[4]));
                let ctx = formats
                    .get(out)
                    .or_else(|| formats.get(inp))
                    .zip(formats.get(inp).or_else(|| formats.get(out)))
                    .map(|(o, i)| (*o, *i, vec![a]));
                (o, evaluate_unary(o, out, inp, a, &formats), ctx)
            }
            "B" => {
                let (o, out, inp, a, b) = (op(f[1]), size(f[2]), size(f[3]), hex(f[4]), hex(f[5]));
                let ctx = formats.get(inp).map(|i| (*i, *i, vec![a, b]));
                (o, evaluate_binary(o, out, inp, a, b, &formats), ctx)
            }
            "T" => {
                let o = op(f[1]);
                let r =
                    evaluate_ternary(o, size(f[2]), size(f[3]), hex(f[4]), hex(f[5]), hex(f[6]));
                (o, r, None)
            }
            "RU" => {
                let o = op(f[1]);
                (
                    o,
                    recover_input_unary(o, size(f[2]), hex(f[3]), size(f[4])),
                    None,
                )
            }
            "RB" => {
                let o = op(f[1]);
                if matches!(o, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight)
                    && (f[2], f[3], f[5], f[6]) == ("0", "8", "8", "0")
                    && expected == "E"
                    && recover_input_binary(o, 0, 8, hex(f[4]), 8, 0) == Ok(hex(f[4]))
                {
                    *explained.entry(Explained::RecoverShiftByZero).or_default() += 1;
                    continue;
                }
                let r = recover_input_binary(
                    o,
                    size(f[2]),
                    size(f[3]),
                    hex(f[4]),
                    size(f[5]),
                    hex(f[6]),
                );
                (o, r, None)
            }
            other => panic!("unknown row kind {other}"),
        };
        let agrees = match (expected, result) {
            ("E", Err(_)) => true,
            ("E", Ok(_)) | (_, Err(_)) => false,
            (value, Ok(ours)) => hex(value) == ours,
        };
        if agrees {
            continue;
        }
        let reason = match (expected, result, &float_context) {
            (value, Ok(ours), Some((out, input, inputs)))
                if value != "E" && is_float_op(opcode) =>
            {
                explain(opcode, size(f[2]), out, input, inputs, hex(value), ours)
            }
            _ => None,
        };
        match reason {
            Some(reason) => *explained.entry(reason).or_default() += 1,
            None => unexplained.push(format!("{line}  (basilisk: {result:x?})")),
        }
    }
    eprintln!("{rows} rows; explained differences: {explained:?}");
    for line in &unexplained {
        eprintln!("{line}");
    }
    assert!(rows > 80_000, "the table has only {rows} rows");
    assert!(
        unexplained.is_empty(),
        "{} rows differ from Ghidra's C++",
        unexplained.len()
    );
    // Every explained class is still exercised by the table.
    for class in [
        Explained::TruncSaturates,
        Explained::SubnormalRoundsToNormal,
        Explained::RecoverShiftByZero,
    ] {
        assert!(explained.contains_key(&class), "{class:?} no longer occurs");
    }
}
