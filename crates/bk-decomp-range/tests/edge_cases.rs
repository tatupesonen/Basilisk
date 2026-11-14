//! The defined results where Ghidra's C++ would crash, hang or read
//! undefined values (`docs/features/decomp-range.md`, section 8), and a few
//! documented quirks of Ghidra that the port keeps.

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

use bk_decomp_range::{CircleRange, Combined, Translated};
use bk_pcode::OpCode;

#[test]
fn step_zero_divides_as_aarch64() {
    // x / 0 = 0 and x % 0 = x: Ghidra's C++ traps on x86-64.
    let r = CircleRange::from_parts(5, 9, 0xff, 0, false);
    assert_eq!(r.count(), 0); // (9 - 5) / 0
    // The phase test compares 5 % 0 = 5 with v % 0 = v: only 5 matches.
    assert!(r.contains_value(5) && !r.contains_value(7));
    let mut n = CircleRange::from_parts(7, 7, 0xff, 0, false);
    n.widen(&CircleRange::full(1), true);
    assert_eq!((n.min(), n.end()), (7, 7)); // normalize keeps 7 % 0 = 7
}

#[test]
fn int_left_with_an_overflowing_step_bound_terminates() {
    // Ghidra: `step <<= 1` overflows the int4 to 0 and normalize() divides
    // by it (SIGFPE on x86-64). Basilisk: the step wraps to 0 and stays,
    // and the remainder by 0 is the value.
    let in1 = CircleRange::new(0x10, 0x20, 4, 1);
    let mut c = CircleRange::empty();
    assert!(c.push_forward_binary(
        OpCode::IntLeft,
        &in1,
        &CircleRange::single(40, 4),
        4,
        4,
        i32::MAX
    ));
    assert_eq!(c.step(), 0);
    assert_eq!(c.to_string(), "(full,0)");
}

#[test]
fn int_mult_where_ghidra_would_loop_forever_gives_false() {
    // Constant 0 with a step bound above 2^30: Ghidra's doubling loop
    // reaches a step of 0 and never leaves.
    let in1 = CircleRange::new(0x10, 0x20, 4, 1);
    let mut c = CircleRange::empty();
    assert!(!c.push_forward_binary(
        OpCode::IntMult,
        &in1,
        &CircleRange::single(0, 4),
        4,
        4,
        i32::MAX
    ));
}

#[test]
fn subpiece_with_an_overflowing_offset() {
    // (int4)0x20000000 * 8 wraps to 0: the shift is by 0, the step 1.
    let in1 = CircleRange::new(0x14, 0x24, 1, 4);
    let mut c = CircleRange::empty();
    assert!(c.push_forward_binary(
        OpCode::SubPiece,
        &in1,
        &CircleRange::single(0x2000_0000, 8),
        1,
        1,
        32
    ));
    assert_eq!(c.to_string(), "[14,21)");
}

#[test]
fn quirks_kept_from_ghidra() {
    // contains: a full stepped range claims any range, whatever the phase.
    let odds = CircleRange::new(1, 1, 1, 2);
    assert!(odds.contains(&CircleRange::new(0, 0, 1, 2)));
    // intersect with equal steps does not compare phases.
    let mut c = odds;
    assert_eq!(c.intersect(&CircleRange::new(0, 10, 1, 2)), Combined::Done);
    assert!(!c.is_empty());
    // INT_SUB with the variable in slot 1: the bounds are not reversed.
    let mut r = CircleRange::single(0, 1);
    assert!(r.pull_back_binary(OpCode::IntSub, 0, 1, 1, 1));
    assert_eq!(r.to_string(), "[0,ff)");
    // INT_RIGHT of a full range is one short.
    let mut s = CircleRange::empty();
    assert!(s.push_forward_binary(
        OpCode::IntRight,
        &CircleRange::full(1),
        &CircleRange::single(0, 1),
        1,
        1,
        32
    ));
    assert_eq!(s.to_string(), "[0,ff)");
    // A comparison whose range holds both outcomes pulls back to [0,2).
    let mut both = CircleRange::new(0, 2, 1, 1);
    assert!(both.pull_back_binary(OpCode::IntEqual, 5, 0, 4, 1));
    assert_eq!(both.to_string(), "[0,2)");
    // getSize of a full 8-byte range lies by one.
    assert_eq!(CircleRange::full(8).count(), u64::MAX);
    // The empty range has defined fields.
    let e = CircleRange::empty();
    assert_eq!((e.min(), e.end(), e.mask(), e.step()), (0, 0, 0, 1));
    assert_eq!(e.translate_2op(), Translated::Never);
}

#[test]
fn translate_2op_codes() {
    assert_eq!(CircleRange::full(1).translate_2op(), Translated::Always);
    assert_eq!(
        CircleRange::new(0, 4, 1, 2).translate_2op(),
        Translated::NotPossible
    );
    assert_eq!(
        CircleRange::new(0, 0x10, 1, 1).translate_2op(),
        Translated::Comparison {
            op: OpCode::IntLess,
            constant: 0x10,
            slot: 1
        }
    );
}
