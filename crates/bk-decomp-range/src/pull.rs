//! Pulling a range back through an operation: the inputs whose image lies
//! in the range (`rangeutil.cc` lines 724–1,003, `pullBackUnary` and
//! `pullBackBinary`).

use bk_pcode::OpCode;

use crate::arith::{mask_of, rem_step, shl, shr, sign_extend_sizes, wide};
use crate::range::CircleRange;
use crate::setops::Combined;

impl CircleRange {
    /// Replaces the range, the set of outputs of the unary operation `op`,
    /// by the set of inputs that produce them, and returns `true` when that
    /// is one range (Ghidra `pullBackUnary`). `in_size` and `out_size` are
    /// the operand sizes in bytes.
    ///
    /// Handled: `BOOL_NEGATE`, `COPY`, `INT_2COMP`, `INT_NEGATE`,
    /// `INT_ZEXT`, `INT_SEXT`. Any other operation gives `false`. An empty
    /// range pulls back to itself with `true`. The range may be changed
    /// even when the answer is `false`.
    pub fn pull_back_unary(&mut self, op: OpCode, in_size: u32, out_size: u32) -> bool {
        if self.empty {
            return true;
        }
        let step = wide(self.step);
        match op {
            OpCode::BoolNegate => {
                if !self.convert_to_boolean() {
                    // As in Ghidra, the bounds flip even when the boolean
                    // range came out empty.
                    self.left ^= 1;
                    self.right = self.left.wrapping_add(1);
                }
            }
            OpCode::Copy => {}
            OpCode::Int2Comp => {
                let val = (!self.left).wrapping_add(1).wrapping_add(step) & self.mask;
                self.left = (!self.right).wrapping_add(1).wrapping_add(step) & self.mask;
                self.right = val;
            }
            OpCode::IntNegate => {
                let val = (!self.left).wrapping_add(step) & self.mask;
                self.left = (!self.right).wrapping_add(step) & self.mask;
                self.right = val;
            }
            OpCode::IntZExt => {
                let val = mask_of(in_size);
                let rem = rem_step(self.left, self.step);
                // The largest range a zero extension can produce.
                let zext = Self::from_parts(
                    rem,
                    val.wrapping_add(1).wrapping_add(rem),
                    self.mask,
                    self.step,
                    false,
                );
                if self.intersect(&zext) != Combined::Done {
                    return false;
                }
                self.restrict_mask(val);
            }
            OpCode::IntSExt => {
                let val = mask_of(in_size);
                // Ghidra takes `left & step` here, not `left % step`.
                let rem = self.left & step;
                let left = (val ^ (val >> 1)).wrapping_add(rem);
                // The outputs no sign extension can produce.
                let mut gap = Self::from_parts(
                    left,
                    sign_extend_sizes(left, in_size, out_size),
                    self.mask,
                    self.step,
                    false,
                );
                if gap.intersect(self) != Combined::Done || !gap.empty {
                    return false;
                }
                self.restrict_mask(val);
            }
            _ => return false,
        }
        true
    }

    /// `left &= val; right &= val; mask &= val`, as the extension cases end.
    const fn restrict_mask(&mut self, val: u64) {
        self.left &= val;
        self.right &= val;
        self.mask &= val;
    }

    /// Ghidra's opening of each comparison case of `pullBackBinary`: the
    /// range becomes boolean and the mask that of the input. Returns
    /// `None` when both outcomes are possible (every input qualifies, and
    /// the range is left as `[0,2)` in the input's mask), otherwise
    /// whether the range is the `false` outcome (`left == 0`), so that the
    /// set built for `true` must be complemented.
    fn boolean_outcome(&mut self, in_size: u32) -> Option<bool> {
        let both = self.convert_to_boolean();
        self.mask = mask_of(in_size);
        if both { None } else { Some(self.left == 0) }
    }

    /// Sets the bounds for the `true` outcome, or empties the range when no
    /// input gives `true` (`None`), then complements for the `false`
    /// outcome.
    const fn finish_comparison(&mut self, bounds: Option<(u64, u64)>, complement: bool) {
        match bounds {
            Some((left, right)) => {
                self.left = left;
                self.right = right;
            }
            None => self.empty = true,
        }
        if complement {
            self.complement();
        }
    }

    /// Replaces the range, the set of outputs of the binary operation `op`
    /// whose other input is the constant `val`, by the set of values of
    /// input `slot` (0 or 1; only `INT_SUB` and the order comparisons look
    /// at it) that produce them, and returns `true` when that is one range
    /// (Ghidra `pullBackBinary`).
    ///
    /// Handled: `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_LESSEQUAL`,
    /// `INT_SLESS`, `INT_SLESSEQUAL`, `INT_CARRY` (the range is read as a
    /// boolean), `INT_ADD`, `INT_SUB`, and `INT_RIGHT` and `INT_SRIGHT` for
    /// a range of step 1. Shift amounts are used modulo 64, as both
    /// reference builds of Ghidra do. Any other operation gives `false`.
    pub fn pull_back_binary(
        &mut self,
        op: OpCode,
        val: u64,
        slot: u32,
        in_size: u32,
        out_size: u32,
    ) -> bool {
        let _ = out_size; // As in Ghidra, the output size is not used.
        if self.empty {
            return true;
        }
        match op {
            OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::IntCarry => {
                let Some(complement) = self.boolean_outcome(in_size) else {
                    return true;
                };
                let bounds = self.true_inputs(op, val, slot);
                self.finish_comparison(bounds, complement);
            }
            OpCode::IntAdd => {
                self.left = self.left.wrapping_sub(val) & self.mask;
                self.right = self.right.wrapping_sub(val) & self.mask;
            }
            OpCode::IntSub => {
                if slot == 0 {
                    self.left = self.left.wrapping_add(val) & self.mask;
                    self.right = self.right.wrapping_add(val) & self.mask;
                } else {
                    self.left = val.wrapping_sub(self.left) & self.mask;
                    self.right = val.wrapping_sub(self.right) & self.mask;
                }
            }
            OpCode::IntRight => {
                if self.step != 1 {
                    return false;
                }
                self.pull_back_right(val, in_size);
            }
            OpCode::IntSRight => {
                if self.step != 1 {
                    return false;
                }
                self.pull_back_sright(val, in_size);
            }
            _ => return false,
        }
        true
    }

    /// The inputs (in the input's mask, already set) for which comparison
    /// `op` with constant `val` is true, or `None` when there are none.
    fn true_inputs(&self, op: OpCode, val: u64, slot: u32) -> Option<(u64, u64)> {
        let mask = self.mask;
        let next = val.wrapping_add(1) & mask;
        let min_signed = (mask >> 1).wrapping_add(1);
        match op {
            OpCode::IntEqual => Some((val, next)),
            OpCode::IntNotEqual => Some((next, val)),
            OpCode::IntLess if slot == 0 => (val != 0).then_some((0, val)),
            OpCode::IntLess => (val != mask).then_some((next, 0)),
            OpCode::IntLessEqual if slot == 0 => Some((0, next)),
            OpCode::IntLessEqual => Some((val, 0)),
            OpCode::IntSLess if slot == 0 => (val != min_signed).then_some((min_signed, val)),
            OpCode::IntSLess => (val != mask >> 1).then_some((next, min_signed)),
            OpCode::IntSLessEqual if slot == 0 => Some((min_signed, next)),
            OpCode::IntSLessEqual => Some((val, min_signed)),
            // INT_CARRY
            _ => (val != 0).then_some((mask.wrapping_sub(val).wrapping_add(1) & mask, 0)),
        }
    }

    /// The `INT_RIGHT` case of `pullBackBinary`, for a range of step 1.
    const fn pull_back_right(&mut self, val: u64, in_size: u32) {
        let right_bound = shr(mask_of(in_size), val).wrapping_add(1);
        let (left, right) = (self.left, self.right);
        if (left >= right_bound && right >= right_bound && left >= right)
            || (left == 0 && right >= right_bound)
            || left == right
        {
            // Covers every value the shift can produce.
            self.left = 0;
            self.right = 0;
        } else {
            let left = if left > right_bound {
                right_bound
            } else {
                left
            };
            let right = if right > right_bound { 0 } else { right };
            self.left = shl(left, val) & self.mask;
            self.right = shl(right, val) & self.mask;
            if self.left == self.right {
                self.empty = true;
            }
        }
    }

    /// The `INT_SRIGHT` case of `pullBackBinary`, for a range of step 1.
    const fn pull_back_sright(&mut self, val: u64, in_size: u32) {
        let full = mask_of(in_size);
        let leftb = shr(full, val.wrapping_add(1));
        // The smallest negative and one past the largest positive result.
        let rightb = leftb ^ full;
        let leftb = leftb.wrapping_add(1);
        let (left, right) = (self.left, self.right);
        if (left >= leftb && left <= rightb && right >= leftb && right <= rightb && left >= right)
            || left == right
        {
            self.left = 0;
            self.right = 0;
        } else {
            let left = if left > leftb && left < rightb {
                leftb
            } else {
                left
            };
            let right = if right > leftb && right < rightb {
                rightb
            } else {
                right
            };
            self.left = shl(left, val) & self.mask;
            self.right = shl(right, val) & self.mask;
            if self.left == self.right {
                self.empty = true;
            }
        }
    }
}
