//! Ghidra's `unittests/testcirclerange.cc`, all 117 tests, table-driven.
//!
//! Most compare a method against the brute-force model of the C++ test
//! (`common/model.rs`): the range's elements pushed through or pulled back
//! with the op behaviours of `bk-pcode`, then re-described as one range.
//! The pull-backs through shifts and comparisons check bounds directly, as
//! the C++ does. Case names are the C++ test names.

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

mod common;

use bk_decomp_range::{CircleRange, Combined};
use bk_pcode::OpCode::{self, *};
use common::model::Model;
use rstest::rstest;

#[rstest]
#[case::circlerange_intersect1(1, 20, 10, 30, 1, 4)]
#[case::circlerange_intersect2(200, 10, 250, 5, 1, 1)]
#[case::circlerange_intersect3(1, 250, 240, 5, 1, 1)]
#[case::circlerange_intersect4(4, 100, 248, 52, 4, 1)]
#[case::circlerange_intersect5(
    0x10_0000,
    0x10_00fe,
    0xffff_ffff_ffff_fff0,
    0xffff_ffff_ffff_fffe,
    2,
    8
)]
#[case::circlerange_intersect6(0x100, 0x110, 0x110, 0x130, 4, 2)]
#[case::circlerange_intersect7(0xffe0, 0x20, 0, 0x20, 2, 2)]
#[case::circlerange_intersect8(0x80, 0x8, 0xd0, 0x80, 1, 1)]
fn intersect(
    #[case] start1: u64,
    #[case] stop1: u64,
    #[case] start2: u64,
    #[case] stop2: u64,
    #[case] step: i32,
    #[case] bytes: u32,
) {
    let mut r1 = CircleRange::new(start1, stop1, bytes, step);
    let r2 = CircleRange::new(start2, stop2, bytes, step);
    let (mut m1, m2) = (Model::of(&r1), Model::of(&r2));
    let code = r1.intersect(&r2);
    m1.intersect(&m2);
    assert!(m1.agrees(code == Combined::Done, &r1), "{r1} {code:?}");
}

#[rstest]
#[case::circlerange_union1(1, 20, 10, 30, 1, 4)]
#[case::circlerange_union2(200, 10, 250, 5, 1, 1)]
#[case::circlerange_union3(1, 250, 240, 5, 1, 1)]
#[case::circlerange_union4(4, 100, 248, 52, 4, 1)]
#[case::circlerange_union5(
    0x10_0000,
    0x10_00fe,
    0xffff_ffff_ffff_fff0,
    0xffff_ffff_ffff_fffe,
    2,
    8
)]
#[case::circlerange_union6(0x100, 0x110, 0x110, 0x130, 4, 2)]
#[case::circlerange_union7(0xffe0, 0x20, 0, 0x20, 2, 2)]
#[case::circlerange_union8(0x80, 0x8, 0xd0, 0x80, 1, 1)]
fn union(
    #[case] start1: u64,
    #[case] stop1: u64,
    #[case] start2: u64,
    #[case] stop2: u64,
    #[case] step: i32,
    #[case] bytes: u32,
) {
    let mut r1 = CircleRange::new(start1, stop1, bytes, step);
    let r2 = CircleRange::new(start2, stop2, bytes, step);
    let (mut m1, m2) = (Model::of(&r1), Model::of(&r2));
    let code = r1.circle_union(&r2);
    m1.union(&m2);
    assert!(m1.agrees(code == Combined::Done, &r1), "{r1} {code:?}");
}

#[rstest]
#[case::circlerange_pullbacknegate1(1, 20, 1, 4, IntNegate, 4)]
#[case::circlerange_pullbacknegate2(0xf0, 0x10, 1, 1, IntNegate, 1)]
#[case::circlerange_pullbacknegate3(0x10, 0x30, 4, 4, IntNegate, 4)]
#[case::circlerange_pullbacknegate4(0xfff0, 0x0, 4, 2, IntNegate, 2)]
#[case::circlerange_pullbacknegate5(0xd1, 0x11, 4, 1, IntNegate, 1)]
#[case::circlerange_pullbacknegate6(0, 0x30, 4, 1, IntNegate, 1)]
#[case::circlerange_pullbackminus1(1, 20, 1, 4, Int2Comp, 4)]
#[case::circlerange_pullbackminus2(0xf0, 0x10, 1, 1, Int2Comp, 1)]
#[case::circlerange_pullbackminus3(0x10, 0x30, 4, 4, Int2Comp, 4)]
#[case::circlerange_pullbackminus4(0xfff0, 0x0, 4, 2, Int2Comp, 2)]
#[case::circlerange_pullbackminus5(0xd1, 0x11, 4, 1, Int2Comp, 1)]
#[case::circlerange_pullbackminus6(0, 0x30, 4, 1, Int2Comp, 1)]
#[case::circlerange_pullbackzext1(1, 20, 1, 4, IntZExt, 2)]
#[case::circlerange_pullbackzext2(0xfff0, 0xff10, 1, 2, IntZExt, 1)]
#[case::circlerange_pullbackzext3(0x10, 0x30, 4, 4, IntZExt, 1)]
#[case::circlerange_pullbackzext4(0xfff0, 0x0, 4, 2, IntZExt, 1)]
#[case::circlerange_pullbackzext5(0xffd1, 0x11, 4, 2, IntZExt, 1)]
#[case::circlerange_pullbackzext6(0, 0x30, 4, 4, IntZExt, 2)]
#[case::circlerange_pullbacksext1(1, 20, 1, 4, IntSExt, 2)]
#[case::circlerange_pullbacksext2(0xfff0, 0x10, 1, 2, IntSExt, 1)]
#[case::circlerange_pullbacksext3(0x10, 0x30, 4, 4, IntSExt, 2)]
#[case::circlerange_pullbacksext4(0xfff0, 0x0, 4, 2, IntSExt, 1)]
#[case::circlerange_pullbacksext5(0xffd1, 0x11, 4, 2, IntSExt, 1)]
#[case::circlerange_pullbacksext6(0, 0x30, 4, 2, IntSExt, 1)]
fn pull_back_unary(
    #[case] start: u64,
    #[case] stop: u64,
    #[case] step: i32,
    #[case] bytes: u32,
    #[case] op: OpCode,
    #[case] in_size: u32,
) {
    let mut range = CircleRange::new(start, stop, bytes, step);
    let mut model = Model::of(&range);
    let valid = range.pull_back_unary(op, in_size, bytes);
    model.pull_back_unary(op, in_size);
    assert!(model.agrees(valid, &range), "{range} {valid}");
}

#[rstest]
#[case::circlerange_pullbackadd1(1, 20, 1, 4, IntAdd)]
#[case::circlerange_pullbackadd2(0xf0, 0x10, 1, 1, IntAdd)]
#[case::circlerange_pullbackadd3(0x10, 0x30, 4, 4, IntAdd)]
#[case::circlerange_pullbackadd4(0xfff0, 0x0, 4, 2, IntAdd)]
#[case::circlerange_pullbackadd5(0xd1, 0x11, 4, 1, IntAdd)]
#[case::circlerange_pullbackadd6(0, 0x30, 4, 1, IntAdd)]
#[case::circlerange_pullbacksub1(1, 20, 1, 4, IntSub)]
#[case::circlerange_pullbacksub2(0xf0, 0x10, 1, 1, IntSub)]
#[case::circlerange_pullbacksub3(0x10, 0x30, 4, 4, IntSub)]
#[case::circlerange_pullbacksub4(0xfff0, 0x0, 4, 2, IntSub)]
#[case::circlerange_pullbacksub5(0xd1, 0x11, 4, 1, IntSub)]
#[case::circlerange_pullbacksub6(0, 0x30, 4, 1, IntSub)]
fn pull_back_binary(
    #[case] start: u64,
    #[case] stop: u64,
    #[case] step: i32,
    #[case] bytes: u32,
    #[case] op: OpCode,
) {
    let (slot, val) = (0, 0xffff_fffd);
    let mut range = CircleRange::new(start, stop, bytes, step);
    let mut model = Model::of(&range);
    let valid = range.pull_back_binary(op, val, slot, bytes, bytes);
    model.pull_back_binary(op, slot, val);
    assert!(model.agrees(valid, &range), "{range} {valid}");
}

/// `(left, right, size, step)`, the operation, its constant and sizes, and
/// the expected bounds (`None`: the pull-back fails).
#[rstest]
#[case::circlerange_pullbackright1((0x01, 0x0f, 2, 1), IntRight, 8, 2, Some((0x100, 0xf00)))]
#[case::circlerange_pullbackright2((0xf0, 0x10, 2, 1), IntRight, 8, 2, Some((0xf000, 0x1000)))]
#[case::circlerange_pullbackright3((0xf0, 0x10, 1, 1), IntRight, 1, 1, Some((0, 0x20)))]
#[case::circlerange_pullbackright4((0x01, 0x0f, 2, 2), IntRight, 8, 2, None)]
#[case::circlerange_pullbacksright1((0x01, 0x0f, 2, 1), IntSRight, 8, 2, Some((0x100, 0xf00)))]
#[case::circlerange_pullbacksright2((0xf0, 0x10, 1, 1), IntSRight, 2, 1, Some((0xc0, 0x40)))]
#[case::circlerange_pullbacksright3((0x10, 0x30, 1, 1), IntSRight, 2, 1, Some((0x40, 0x80)))]
#[case::circlerange_pullbacksright4((0x01, 0x0f, 2, 2), IntSRight, 8, 2, None)]
fn pull_back_shift(
    #[case] range: (u64, u64, u32, i32),
    #[case] op: OpCode,
    #[case] val: u64,
    #[case] size: u32,
    #[case] expected: Option<(u64, u64)>,
) {
    let mut r = CircleRange::new(range.0, range.1, range.2, range.3);
    let valid = r.pull_back_binary(op, val, 0, size, size);
    assert_eq!(valid, expected.is_some());
    if let Some((min, end)) = expected {
        assert_eq!((r.min(), r.end()), (min, end), "{r}");
    }
}

#[rstest]
#[case::circlerange_pullbackequal1(true, IntEqual, 4, 0x1234, 0x1235)]
#[case::circlerange_pullbackequal2(false, IntEqual, 2, 0x1235, 0x1234)]
#[case::circlerange_pullbacknotequal1(false, IntNotEqual, 4, 0x1234, 0x1235)]
#[case::circlerange_pullbacknotequal2(true, IntNotEqual, 2, 0x1235, 0x1234)]
#[case::circlerange_pullbackcarry1(true, IntCarry, 2, 0xedcc, 0)]
#[case::circlerange_pullbackcarry2(false, IntCarry, 2, 0, 0xedcc)]
#[case::circlerange_pullbackless1(false, IntLess, 4, 0x1234, 0)]
#[case::circlerange_pullbackless2(true, IntLess, 2, 0, 0x1234)]
#[case::circlerange_pullbacklessequal1(false, IntLessEqual, 4, 0x1235, 0)]
#[case::circlerange_pullbacklessequal2(true, IntLessEqual, 2, 0, 0x1235)]
#[case::circlerange_pullbacksless1(false, IntSLess, 4, 0x1234, 0x8000_0000)]
#[case::circlerange_pullbacksless2(true, IntSLess, 2, 0x8000, 0x1234)]
#[case::circlerange_pullbackslessequal1(false, IntSLessEqual, 4, 0x1235, 0x8000_0000)]
#[case::circlerange_pullbackslessequal2(true, IntSLessEqual, 2, 0x8000, 0x1235)]
fn pull_back_comparison(
    #[case] outcome: bool,
    #[case] op: OpCode,
    #[case] in_size: u32,
    #[case] min: u64,
    #[case] end: u64,
) {
    let mut r = CircleRange::from_bool(outcome);
    assert!(r.pull_back_binary(op, 0x1234, 0, in_size, 1));
    assert_eq!((r.min(), r.end()), (min, end), "{r}");
}

#[rstest]
#[case::circlerange_pushnegate1(1, 20, 1, 4, IntNegate, 4)]
#[case::circlerange_pushnegate2(0xf0, 0x10, 1, 1, IntNegate, 1)]
#[case::circlerange_pushnegate3(0x10, 0x30, 4, 4, IntNegate, 4)]
#[case::circlerange_pushnegate4(0xfff0, 0x0, 4, 2, IntNegate, 2)]
#[case::circlerange_pushnegate5(0xd1, 0x11, 4, 1, IntNegate, 1)]
#[case::circlerange_pushnegate6(0, 0x30, 4, 1, IntNegate, 1)]
#[case::circlerange_pushminus1(1, 20, 1, 4, Int2Comp, 4)]
#[case::circlerange_pushminus2(0xf0, 0x10, 1, 1, Int2Comp, 1)]
#[case::circlerange_pushminus3(0x10, 0x30, 4, 4, Int2Comp, 4)]
#[case::circlerange_pushminus4(0xfff0, 0x0, 4, 2, Int2Comp, 2)]
#[case::circlerange_pushminus5(0xd1, 0x11, 4, 1, Int2Comp, 1)]
#[case::circlerange_pushminus6(0, 0x30, 4, 1, Int2Comp, 1)]
#[case::circlerange_pushzext1(1, 20, 1, 2, IntZExt, 4)]
#[case::circlerange_pushzext2(0xfff0, 0xff10, 1, 2, IntZExt, 4)]
#[case::circlerange_pushzext3(0x10, 0x30, 4, 2, IntZExt, 4)]
#[case::circlerange_pushzext4(0xfff0, 0x0, 4, 2, IntZExt, 4)]
#[case::circlerange_pushzext5(0xffd1, 0xfff1, 4, 2, IntZExt, 4)]
#[case::circlerange_pushzext6(0, 0x30, 4, 1, IntZExt, 2)]
#[case::circlerange_pushzext7(0, 0, 4, 1, IntZExt, 2)]
#[case::circlerange_pushsext1(1, 20, 1, 2, IntSExt, 4)]
#[case::circlerange_pushsext2(0xfff0, 0xff10, 1, 2, IntSExt, 4)]
#[case::circlerange_pushsext3(0x10, 0x30, 4, 2, IntSExt, 4)]
#[case::circlerange_pushsext4(0xfff0, 0x0, 4, 2, IntSExt, 4)]
#[case::circlerange_pushsext5(0xffd1, 0xfff1, 4, 2, IntSExt, 4)]
#[case::circlerange_pushsext6(0, 0x30, 4, 1, IntSExt, 2)]
#[case::circlerange_pushsext7(0, 0, 4, 1, IntSExt, 2)]
fn push_unary(
    #[case] start: u64,
    #[case] stop: u64,
    #[case] step: i32,
    #[case] bytes: u32,
    #[case] op: OpCode,
    #[case] out_size: u32,
) {
    let range = CircleRange::new(start, stop, bytes, step);
    let mut res = CircleRange::empty();
    let mut model = Model::of(&range);
    let valid = res.push_forward_unary(op, &range, bytes, out_size);
    model.push_unary(op, out_size);
    assert!(model.agrees(valid, &res), "{res} {valid}");
}

/// `(start, stop, step)` of both inputs, their size, the operation and the
/// output size; `maxStep` is 32 as in the C++.
#[rstest]
#[case::circlerange_pushadd1((10, 15, 1), (30, 35, 1), 1, IntAdd, 1)]
#[case::circlerange_pushadd2((1, 10, 1), (0xffff_fffe, 5, 1), 4, IntAdd, 4)]
#[case::circlerange_pushadd3((0, 20, 4), (0xfff0, 6, 2), 2, IntAdd, 2)]
#[case::circlerange_pushadd4((1, 250, 1), (20, 30, 1), 1, IntAdd, 1)]
#[case::circlerange_pushmult1((0x1000, 0x1010, 1), (2, 3, 1), 4, IntMult, 4)]
#[case::circlerange_pushmult2((0xfffc, 8, 2), (4, 5, 1), 2, IntMult, 2)]
#[case::circlerange_pushmult3((5, 133, 1), (2, 3, 1), 1, IntMult, 1)]
#[case::circlerange_pushleft1((1, 5, 1), (1, 2, 1), 4, IntLeft, 4)]
#[case::circlerange_pushleft2((8, 72, 4), (2, 3, 1), 1, IntLeft, 1)]
#[case::circlerange_pushsubpiece1((0xfffe, 0x1_0005, 1), (0, 1, 1), 4, SubPiece, 1)]
#[case::circlerange_pushsubpiece2((0xfffe, 0x1_0005, 1), (1, 2, 1), 4, SubPiece, 1)]
#[case::circlerange_pushsubpiece3((0x10f0, 0x1200, 1), (0, 1, 1), 4, SubPiece, 1)]
#[case::circlerange_pushright1((0x30a6, 0x30c0, 2), (4, 5, 1), 2, IntRight, 2)]
#[case::circlerange_pushright2((0xfe00, 0xffc0, 0x20), (9, 10, 1), 2, IntRight, 2)]
#[case::circlerange_pushright3((7, 10, 1), (4, 5, 1), 4, IntRight, 4)]
#[case::circlerange_pushsright1((0x3000, 0x3064, 4), (3, 4, 1), 2, IntSRight, 2)]
#[case::circlerange_pushsright2((0xfff0, 0x24, 4), (3, 4, 1), 2, IntSRight, 2)]
fn push_binary(
    #[case] in1: (u64, u64, i32),
    #[case] in2: (u64, u64, i32),
    #[case] bytes: u32,
    #[case] op: OpCode,
    #[case] out_size: u32,
) {
    let r1 = CircleRange::new(in1.0, in1.1, bytes, in1.2);
    let r2 = CircleRange::new(in2.0, in2.1, bytes, in2.2);
    let (m1, m2) = (Model::of(&r1), Model::of(&r2));
    let mut res = CircleRange::empty();
    let valid = res.push_forward_binary(op, &r1, &r2, bytes, out_size, 32);
    let mut model = Model::with_bytes(out_size);
    model.push_binary(op, out_size, &m1, &m2);
    assert!(model.agrees(valid, &res), "{res} {valid}");
}
