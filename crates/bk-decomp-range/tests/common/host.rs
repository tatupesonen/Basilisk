//! The rows where Ghidra's compiled `CircleRange` gives a different answer
//! on the two reference hosts. The oracle exists twice: from Apple clang
//! with libc++ on macOS AArch64, and from g++ with libstdc++ on x86-64
//! Linux. Basilisk follows x86-64 (`docs/features/decomp-range.md` 4.3);
//! a row where the macOS table differs passes only when it is one of the
//! causes below, recognised by recomputing what that host does.

use bk_decomp_range::CircleRange;
use bk_pcode::OpCode;

use super::oracle::{Row, put, range, receiver};

/// Why the macOS row differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cause {
    /// `pushForwardBinary`, `INT_LEFT` (rangeutil.cc:1269–1270): `in1.left
    /// << sa` and `in1.right << sa` with a shift amount of 64 or more, which
    /// C++ leaves undefined. g++ on x86-64 shifts by the amount modulo 64
    /// (`shl`); Apple clang on AArch64 vectorises the two shifts into one
    /// `USHL`, which reads the low byte of the amount as a signed count: 64
    /// to 127 give 0, and 128 to 255 shift right by 256 minus the byte.
    NeonShiftLeft,
}

impl Cause {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::NeonShiftLeft => "INT_LEFT push-forward, shift of 64 or more (AArch64 USHL)",
        }
    }
}

/// AArch64 `USHL` on one 64-bit lane: the low byte of `sa` as a signed
/// count; negative shifts right; a count of 64 or more either way gives 0.
fn ushl(v: u64, sa: u32) -> u64 {
    let count = i32::from(sa as u8 as i8);
    if count >= 64 || count <= -64 {
        0
    } else if count >= 0 {
        v << count
    } else {
        v >> -count
    }
}

/// Ghidra's `INT_LEFT` push-forward with its shifts done by `USHL`: Basilisk's
/// result with the bounds recomputed.
fn push_left_ushl(in1: &CircleRange, in2: &CircleRange, max_step: i32) -> (bool, CircleRange) {
    let mut c = receiver();
    let ok = c.push_forward_binary(OpCode::IntLeft, in1, in2, 8, 8, max_step);
    if !in2.is_single() {
        return (ok, c);
    }
    let sa = in2.min() as u32;
    let mask = in1.mask();
    let step = c.step();
    let mut left = ushl(in1.min(), sa) & mask;
    let mut right = ushl(in1.end(), sa) & mask;
    let whole = 64 - mask.leading_zeros();
    if in1.max_info().cast_unsigned().wrapping_add(sa) > whole {
        right = left;
        if left == right {
            left = if step == 1 {
                0
            } else {
                left.checked_rem(i64::from(step).cast_unsigned()).unwrap_or(left)
            };
            right = left;
        }
    }
    (ok, CircleRange::from_parts(left, right, mask, step, false))
}

/// Why `row` (from the macOS table) differs from x86-64's results, or
/// `None` when no known cause explains it. `inputs` are the second inputs
/// of an `F` row, in order.
pub(crate) fn recognise(row: &Row<'_>, inputs: &[CircleRange]) -> Option<Cause> {
    if row.tag != "F" || row.inputs[1] != (OpCode::IntLeft as u8).to_string() {
        return None;
    }
    let in1 = range(row.inputs[0]);
    let max_step: i32 = row.inputs[4].parse().ok()?;
    let mut expected = String::new();
    for b in inputs {
        let (ok, c) = push_left_ushl(&in1, b, max_step);
        if !expected.is_empty() {
            expected.push(' ');
        }
        expected.push(if ok { '1' } else { '0' });
        expected.push(':');
        put(&mut expected, &c);
    }
    (expected == row.results).then_some(Cause::NeonShiftLeft)
}

#[cfg(test)]
mod tests {
    use super::ushl;

    #[test]
    fn ushl_reads_a_signed_byte() {
        assert_eq!(ushl(0xf8, 3), 0x7c0);
        assert_eq!(ushl(0xf8, 64), 0);
        assert_eq!(ushl(0xf8, 0x80), 0);
        assert_eq!(ushl(0xf8, 0x7fff_ffff), 0x7c);
        assert_eq!(ushl(0xf8, 0xffff_fffe), 0x3e);
    }
}
