//! Pushing ranges forward through an operation: one range containing every
//! output (`rangeutil.cc` lines 1,086–1,389, `pushForwardUnary`,
//! `pushForwardBinary` and `pushForwardTrinary`).

use bk_pcode::OpCode;

use crate::arith::{count, mask_of, rem_step, sar, shl, shr, sign_extend_bit, sign_extend_sizes, wide};
use crate::range::CircleRange;

impl CircleRange {
    /// Sets `self` to the image of `in1` under the unary operation `op`, and
    /// returns `true` when it is known and one range (Ghidra
    /// `pushForwardUnary`). `in_size` and `out_size` are the operand sizes
    /// in bytes.
    ///
    /// Handled: `CAST`, `COPY`, `INT_ZEXT`, `INT_SEXT`, `INT_2COMP`,
    /// `INT_NEGATE`, `BOOL_NEGATE`, `FLOAT_NAN`. An empty input gives an
    /// empty result and `true`; any other operation gives `false`. `self`
    /// may be changed even when the answer is `false`.
    pub fn push_forward_unary(&mut self, op: OpCode, in1: &Self, in_size: u32, out_size: u32) -> bool {
        if in1.empty {
            self.empty = true;
            return true;
        }
        match op {
            OpCode::Cast | OpCode::Copy => *self = *in1,
            OpCode::IntZExt => {
                self.empty = false;
                self.step = in1.step;
                self.mask = mask_of(out_size);
                if in1.left == in1.right {
                    self.left = rem_step(in1.left, self.step);
                    self.right = in1.mask.wrapping_add(1).wrapping_add(self.left);
                } else {
                    self.left = in1.left;
                    self.right = in1.right.wrapping_sub(wide(in1.step)) & in1.mask;
                    if self.right < self.left {
                        return false; // Extending makes two pieces.
                    }
                    self.right = self.right.wrapping_add(wide(self.step));
                }
            }
            OpCode::IntSExt => {
                self.empty = false;
                self.step = in1.step;
                self.mask = mask_of(out_size);
                if in1.left == in1.right {
                    let rem = rem_step(in1.left, self.step);
                    let top = mask_of(in_size) >> 1;
                    self.left = (mask_of(out_size) ^ top).wrapping_add(rem);
                    self.right = top.wrapping_add(1).wrapping_add(rem);
                } else {
                    self.left = sign_extend_sizes(in1.left, in_size, out_size);
                    let last = in1.right.wrapping_sub(wide(in1.step)) & in1.mask;
                    self.right = sign_extend_sizes(last, in_size, out_size);
                    if self.right.cast_signed() < self.left.cast_signed() {
                        return false; // Extending makes two pieces.
                    }
                    self.right = self.right.wrapping_add(wide(self.step)) & self.mask;
                }
            }
            OpCode::Int2Comp => {
                self.empty = false;
                self.step = in1.step;
                self.mask = in1.mask;
                let step = wide(self.step);
                self.right = (!in1.left).wrapping_add(1).wrapping_add(step) & self.mask;
                self.left = (!in1.right).wrapping_add(1).wrapping_add(step) & self.mask;
                self.normalize();
            }
            OpCode::IntNegate => {
                self.empty = false;
                self.step = in1.step;
                self.mask = in1.mask;
                let step = wide(self.step);
                self.left = (!in1.right).wrapping_add(step) & self.mask;
                self.right = (!in1.left).wrapping_add(step) & self.mask;
                self.normalize();
            }
            OpCode::BoolNegate | OpCode::FloatNan => self.set_both_booleans(),
            _ => return false,
        }
        true
    }

    /// `[0,2)` in a 1-byte domain: both boolean outcomes.
    const fn set_both_booleans(&mut self) {
        *self = Self::from_parts(0, 2, 0xff, 1, false);
    }

    /// Sets `self` to a range containing the image of `in1` and `in2` under
    /// the binary operation `op`, and returns `true` when something useful
    /// is known (Ghidra `pushForwardBinary`). `max_step` bounds the step a
    /// multiplication or left shift by a constant may introduce.
    ///
    /// Handled: `PTRSUB`, `INT_ADD`, `INT_MULT` and `INT_LEFT` (one input
    /// a single value), `SUBPIECE`, `INT_RIGHT`, `INT_SRIGHT` (the second
    /// input a single value), and the boolean-valued `INT_EQUAL`,
    /// `INT_NOTEQUAL`, `INT_SLESS`, `INT_SLESSEQUAL`, `INT_LESS`,
    /// `INT_LESSEQUAL`, `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`,
    /// `BOOL_XOR`, `BOOL_AND`, `BOOL_OR`, `FLOAT_EQUAL`, `FLOAT_NOTEQUAL`,
    /// `FLOAT_LESS`, `FLOAT_LESSEQUAL` (always `[0,2)`). An empty input
    /// gives an empty result and `true`. Shift amounts are used modulo 64,
    /// as both reference builds of Ghidra do. `self` may be changed even
    /// when the answer is `false`.
    pub fn push_forward_binary(
        &mut self,
        op: OpCode,
        in1: &Self,
        in2: &Self,
        in_size: u32,
        out_size: u32,
        max_step: i32,
    ) -> bool {
        if in1.empty || in2.empty {
            self.empty = true;
            return true;
        }
        match op {
            OpCode::PtrSub | OpCode::IntAdd => self.push_add(in1, in2),
            OpCode::IntMult => return self.push_mult(in1, in2, max_step),
            OpCode::IntLeft => return self.push_left(in1, in2, max_step),
            OpCode::SubPiece => return self.push_subpiece(in1, in2, out_size),
            OpCode::IntRight => {
                if !in2.is_single() {
                    return false;
                }
                self.empty = false;
                let sa = count(in2.left as i32);
                self.mask = mask_of(out_size);
                self.step = 1;
                if in1.left < in1.right {
                    self.left = shr(in1.left, sa);
                    self.right = shr(in1.right.wrapping_sub(wide(in1.step)), sa).wrapping_add(1);
                } else {
                    self.left = 0;
                    self.right = shr(in1.mask, sa);
                }
                self.keep_from_becoming_full();
            }
            OpCode::IntSRight => {
                if !in2.is_single() {
                    return false;
                }
                self.empty = false;
                let sa = count(in2.left as i32);
                self.mask = mask_of(out_size);
                self.step = 1;
                let bit = (in_size as i32).wrapping_mul(8).wrapping_sub(1);
                let mut val_left = sign_extend_bit(in1.left.cast_signed(), bit);
                let mut val_right = sign_extend_bit(in1.right.cast_signed(), bit);
                if val_left >= val_right {
                    val_right = (self.mask >> 1).cast_signed(); // The largest positive value.
                    val_left = sign_extend_bit(val_right.wrapping_add(1), bit); // The smallest negative.
                }
                self.left = sar(val_left, sa).cast_unsigned() & self.mask;
                self.right = sar(val_right.wrapping_sub(i64::from(in1.step)), sa)
                    .wrapping_add(1)
                    .cast_unsigned()
                    & self.mask;
                self.keep_from_becoming_full();
            }
            OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntCarry
            | OpCode::IntSCarry
            | OpCode::IntSBorrow
            | OpCode::BoolXor
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual => self.set_both_booleans(),
            _ => return false,
        }
        true
    }

    /// The shifts end with: equal bounds would read as the full set, so the
    /// range becomes the single value `left` instead.
    const fn keep_from_becoming_full(&mut self) {
        if self.left == self.right {
            self.right = self.left.wrapping_add(1) & self.mask;
        }
    }

    /// The `PTRSUB` and `INT_ADD` case of `pushForwardBinary`.
    fn push_add(&mut self, in1: &Self, in2: &Self) {
        self.empty = false;
        self.mask = in1.mask | in2.mask;
        if in1.left == in1.right || in2.left == in2.right {
            self.step = in1.step.min(in2.step);
            self.left = rem_step(in1.left.wrapping_add(in2.left), self.step);
            self.right = self.left;
        } else if in2.is_single() {
            self.step = in1.step;
            self.left = in1.left.wrapping_add(in2.left) & self.mask;
            self.right = in1.right.wrapping_add(in2.left) & self.mask;
        } else if in1.is_single() {
            self.step = in2.step;
            self.left = in2.left.wrapping_add(in1.left) & self.mask;
            self.right = in2.right.wrapping_add(in1.left) & self.mask;
        } else {
            self.step = in1.step.min(in2.step);
            let step1 = wide(in1.step);
            let size1 = if in1.left < in1.right {
                in1.right - in1.left
            } else {
                in1.mask.wrapping_sub(in1.left.wrapping_sub(in1.right)).wrapping_add(step1)
            };
            self.left = in1.left.wrapping_add(in2.left) & self.mask;
            self.right = in1
                .right
                .wrapping_sub(step1)
                .wrapping_add(in2.right)
                .wrapping_sub(wide(in2.step))
                .wrapping_add(wide(self.step))
                & self.mask;
            let size_new = if self.left < self.right {
                self.right - self.left
            } else {
                self.mask
                    .wrapping_sub(self.left.wrapping_sub(self.right))
                    .wrapping_add(wide(self.step))
            };
            if size_new < size1 {
                self.right = self.left; // Overflow: everything is covered.
            }
            self.normalize();
        }
    }

    /// The `INT_MULT` case of `pushForwardBinary`.
    fn push_mult(&mut self, in1: &Self, in2: &Self, max_step: i32) -> bool {
        self.empty = false;
        self.mask = in1.mask | in2.mask;
        let const_val;
        if in1.is_single() {
            const_val = in1.left;
            self.step = in2.step;
        } else if in2.is_single() {
            const_val = in2.left;
            self.step = in1.step;
        } else {
            return false;
        }
        // Each factor of 2 in the constant doubles the step, up to
        // `max_step`. The doubling wraps as the C++ `int4` does; where
        // Ghidra would then loop forever (a step of 0 with no factor left),
        // the answer is that nothing is known.
        let mut tmp = const_val as u32;
        while self.step < max_step {
            if tmp & 1 != 0 {
                break;
            }
            if self.step == 0 && tmp == 0 {
                return false;
            }
            self.step = self.step.wrapping_shl(1);
            tmp >>= 1;
        }
        let whole = 64 - self.mask.leading_zeros() as i32;
        if in1.max_info().wrapping_add(in2.max_info()) > whole {
            self.left = rem_step(in1.left.wrapping_mul(in2.left), self.step);
            self.right = self.left; // Everything is covered.
            self.normalize();
            return true;
        }
        let last1 = in1.right.wrapping_sub(wide(in1.step));
        let last2 = in2.right.wrapping_sub(wide(in2.step));
        let step = wide(self.step);
        if const_val & (self.mask ^ (self.mask >> 1)) != 0 {
            // Multiplying by a negative number reverses the order.
            self.left = last1.wrapping_mul(last2) & self.mask;
            self.right = in1.left.wrapping_mul(in2.left).wrapping_add(step) & self.mask;
        } else {
            self.left = in1.left.wrapping_mul(in2.left) & self.mask;
            self.right = last1.wrapping_mul(last2).wrapping_add(step) & self.mask;
        }
        true
    }

    /// The `INT_LEFT` case of `pushForwardBinary`.
    fn push_left(&mut self, in1: &Self, in2: &Self, max_step: i32) -> bool {
        if !in2.is_single() {
            return false;
        }
        self.empty = false;
        self.mask = in1.mask;
        self.step = in1.step;
        let sa = in2.left as u32;
        // Each bit of shift doubles the step, up to `max_step`, wrapping as
        // the C++ `int4` does; a step of 0 stays 0 however many remain.
        let mut tmp = sa;
        while self.step < max_step && tmp > 0 {
            if self.step == 0 {
                break;
            }
            self.step = self.step.wrapping_shl(1);
            tmp -= 1;
        }
        self.left = shl(in1.left, u64::from(sa)) & self.mask;
        self.right = shl(in1.right, u64::from(sa)) & self.mask;
        let whole = 64 - self.mask.leading_zeros();
        // `int4 + uint4` is 32-bit unsigned arithmetic in C++.
        if in1.max_info().cast_unsigned().wrapping_add(sa) > whole {
            self.right = self.left; // Everything is covered.
            self.normalize();
        }
        true
    }

    /// The `SUBPIECE` case of `pushForwardBinary`.
    fn push_subpiece(&mut self, in1: &Self, in2: &Self, out_size: u32) -> bool {
        if !in2.is_single() {
            return false;
        }
        self.empty = false;
        let sa = (in2.left as i32).wrapping_mul(8);
        self.mask = mask_of(out_size);
        self.step = if sa == 0 { in1.step } else { 1 };
        let range = in1.left.abs_diff(in1.right);
        if range == 0 || shr(range, count(sa)) > self.mask {
            self.left = 0; // Everything is covered.
            self.right = 0;
        } else {
            self.left = shr(in1.left, count(sa)) & self.mask;
            self.right = shr(in1.right.wrapping_sub(wide(in1.step)), count(sa)).wrapping_add(wide(self.step)) & self.mask;
            self.normalize();
        }
        true
    }

    /// Sets `self` to a range containing the image of the three inputs
    /// under `op`, and returns `true` when something useful is known
    /// (Ghidra `pushForwardTrinary`). Only `PTRADD` is handled, as
    /// `inputs[0] + inputs[1] * inputs[2]` through the binary cases.
    pub fn push_forward_trinary(
        &mut self,
        op: OpCode,
        inputs: [&Self; 3],
        in_size: u32,
        out_size: u32,
        max_step: i32,
    ) -> bool {
        if op != OpCode::PtrAdd {
            return false;
        }
        let [in1, in2, in3] = inputs;
        let mut product = Self::empty();
        if !product.push_forward_binary(OpCode::IntMult, in2, in3, in_size, in_size, max_step) {
            return false;
        }
        self.push_forward_binary(OpCode::IntAdd, in1, &product, in_size, out_size, max_step)
    }
}
