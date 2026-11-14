//! Containment, intersection, union, the minimal container, complement,
//! masks, strides and widening (`rangeutil.cc` lines 92–168 and 299–722,
//! and `widen` at 1,391–1,411).

use core::cmp::Ordering;

use bk_core::bits::{bit_transitions, leastsigbit_set, mostsigbit_set};

use crate::arith::{mask_of, narrow, rem_step, rem32, wide};
use crate::overlap::{Overlap, encode};
use crate::range::CircleRange;

/// The outcome of [`CircleRange::intersect`] and
/// [`CircleRange::circle_union`] (Ghidra's return codes 0 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum Combined {
    /// Ghidra's 0: `self` now holds the result.
    Done,
    /// Ghidra's 2: the result would be two separate pieces; `self` is
    /// unchanged.
    TwoPieces,
}

/// Ghidra's private static `newStride`: restricts `[left, right)`, which
/// has step `old_step`, to the values congruent to `rem` modulo the larger
/// `step`. Returns `true` when the result is empty.
fn new_stride(
    mask: u64,
    step: i32,
    old_step: i32,
    rem: u32,
    left: &mut u64,
    right: &mut u64,
) -> bool {
    if old_step != 1 {
        let old_rem = rem_step(*left, old_step) as u32;
        if old_rem != rem32(rem, narrow(old_step)) {
            return true;
        }
    }
    let orig_order = *left < *right;
    let left_rem = rem_step(*left, step) as u32;
    let right_rem = rem_step(*right, step) as u32;
    // The adjustment is computed in 32-bit unsigned arithmetic, as in C++.
    let adjust = |rem_now: u32| {
        if rem_now > rem {
            rem.wrapping_add(narrow(step)).wrapping_sub(rem_now)
        } else {
            rem.wrapping_sub(rem_now)
        }
    };
    *left = left.wrapping_add(u64::from(adjust(left_rem))) & mask;
    *right = right.wrapping_add(u64::from(adjust(right_rem))) & mask;
    orig_order != (*left < *right)
}

/// Ghidra's private static `newDomain`: cuts `[left, right)` down to the
/// smaller domain `new_mask`, keeping the phase modulo `new_step`. Returns
/// `true` when nothing is left.
fn new_domain(new_mask: u64, new_step: i32, left: &mut u64, right: &mut u64) -> bool {
    let rem = if new_step == 1 {
        0
    } else {
        rem_step(*left, new_step)
    };
    if *left > new_mask {
        if *right > new_mask {
            if *left < *right {
                return true;
            }
            *left = rem;
            *right = rem;
            return false;
        }
        *left = rem;
    }
    if *right > new_mask {
        *right = rem;
    }
    if *left == *right {
        *left = rem;
        *right = rem;
    }
    false
}

impl CircleRange {
    /// Whether every value of `other` is in `self` (Ghidra
    /// `contains(const CircleRange &)`).
    ///
    /// As in Ghidra this is conservative: when `other` has a larger step
    /// and its bounds do not show containment, the answer is `false` even
    /// if the values themselves are all in `self`.
    pub fn contains(&self, other: &Self) -> bool {
        if self.empty {
            return other.empty;
        }
        if other.empty {
            return true;
        }
        if self.step > other.step && !other.is_single() {
            return false;
        }
        if self.left == self.right {
            return true;
        }
        if other.left == other.right {
            return false;
        }
        if rem_step(self.left, self.step) != rem_step(other.left, self.step) {
            return false;
        }
        if self.left == other.left && self.right == other.right {
            return true;
        }
        match encode(self.left, self.right, other.left, other.right) {
            Overlap::C => true,
            Overlap::B => self.right == other.right,
            _ => false,
        }
    }

    /// Sets `self` to its intersection with `other` when that is one range
    /// (Ghidra `intersect`, return code 0 or 2).
    ///
    /// Different steps are handled by moving the range with the smaller
    /// step onto the larger one when its phase allows (the result is empty
    /// otherwise), and different domains by cutting down to the smaller
    /// one.
    pub fn intersect(&mut self, other: &Self) -> Combined {
        if self.empty {
            return Combined::Done;
        }
        if other.empty {
            self.empty = true;
            return Combined::Done;
        }
        let (mut myleft, mut myright) = (self.left, self.right);
        let (mut op2left, mut op2right) = (other.left, other.right);
        let new_step = match self.step.cmp(&other.step) {
            Ordering::Less => {
                let rem = rem_step(op2left, other.step) as u32;
                if new_stride(
                    self.mask,
                    other.step,
                    self.step,
                    rem,
                    &mut myleft,
                    &mut myright,
                ) {
                    self.empty = true;
                    return Combined::Done;
                }
                other.step
            }
            Ordering::Greater => {
                let rem = rem_step(myleft, self.step) as u32;
                if new_stride(
                    other.mask,
                    self.step,
                    other.step,
                    rem,
                    &mut op2left,
                    &mut op2right,
                ) {
                    self.empty = true;
                    return Combined::Done;
                }
                self.step
            }
            Ordering::Equal => self.step,
        };
        let new_mask = self.mask & other.mask;
        let cut = if self.mask != new_mask {
            new_domain(new_mask, new_step, &mut myleft, &mut myright)
        } else if other.mask != new_mask {
            new_domain(new_mask, new_step, &mut op2left, &mut op2right)
        } else {
            false
        };
        if cut {
            self.empty = true;
            return Combined::Done;
        }
        if myleft == myright {
            self.left = op2left;
            self.right = op2right;
        } else if op2left == op2right {
            self.left = myleft;
            self.right = myright;
        } else {
            // The new bounds, and whether equal bounds mean empty (only
            // where an end is cut; C and D keep one range whole).
            let (left, right, can_vanish) = match encode(myleft, myright, op2left, op2right) {
                Overlap::A | Overlap::F => {
                    // Disjoint: empty, bounds untouched.
                    self.empty = true;
                    (self.left, self.right, false)
                }
                Overlap::B => (op2left, myright, true),
                Overlap::C => (op2left, op2right, false),
                Overlap::D => (myleft, myright, false),
                Overlap::E => (myleft, op2right, true),
                Overlap::G => {
                    if myleft == op2right {
                        (op2left, myright, true)
                    } else if op2left == myright {
                        (myleft, op2right, true)
                    } else {
                        return Combined::TwoPieces;
                    }
                }
            };
            self.left = left;
            self.right = right;
            if can_vanish && left == right {
                self.empty = true;
            }
        }
        self.mask = new_mask;
        self.step = new_step;
        Combined::Done
    }

    /// Sets `self` to the values whose set bits all lie within `nzmask`, a
    /// value of `size` bytes, and returns `true` — or returns `false` and
    /// leaves `self` alone when `nzmask` is not a run of ones possibly
    /// followed by zeros (Ghidra `setNZMask`).
    ///
    /// The step is 2 to the number of trailing zero bits, computed as
    /// Ghidra's `int4` shift is: the count modulo 32.
    pub fn set_nz_mask(&mut self, nzmask: u64, size: u32) -> bool {
        let trans = bit_transitions(nzmask, size);
        if trans > 2 {
            return false;
        }
        let has_step = nzmask & 1 == 0;
        if !has_step && trans == 2 {
            return false;
        }
        self.empty = false;
        self.mask = mask_of(size);
        self.step = 1;
        self.left = 0;
        if trans == 0 {
            // All zeros: only 0. All ones: everything.
            self.right = u64::from(has_step);
            return true;
        }
        let shift = leastsigbit_set(nzmask).cast_unsigned();
        self.step = 1i32.wrapping_shl(shift);
        self.right = nzmask.wrapping_add(wide(self.step)) & self.mask;
        true
    }

    /// Sets `self` to its union with `other` when that is one range (Ghidra
    /// `circleUnion`, return code 0 or 2). The steps must agree, except
    /// that a single value takes the step of the other range.
    pub fn circle_union(&mut self, other: &Self) -> Combined {
        if other.empty {
            return Combined::Done;
        }
        if self.empty {
            *self = *other;
            return Combined::Done;
        }
        if self.mask != other.mask {
            return Combined::TwoPieces;
        }
        let mut a_right = self.right;
        let mut b_right = other.right;
        let mut new_step = self.step;
        if self.step < other.step {
            if !self.is_single() {
                return Combined::TwoPieces;
            }
            new_step = other.step;
            a_right = self.left.wrapping_add(wide(new_step)) & self.mask;
        } else if other.step < self.step {
            if !other.is_single() {
                return Combined::TwoPieces;
            }
            new_step = self.step;
            b_right = other.left.wrapping_add(wide(new_step)) & self.mask;
        }
        let rem = if new_step == 1 {
            0
        } else {
            let rem = rem_step(self.left, new_step);
            if rem != rem_step(other.left, new_step) {
                return Combined::TwoPieces;
            }
            rem
        };
        let (left, right) = if self.left == a_right || other.left == b_right {
            (rem, rem)
        } else {
            match encode(self.left, a_right, other.left, b_right) {
                Overlap::A | Overlap::F => {
                    if a_right == other.left {
                        (self.left, b_right)
                    } else if self.left == b_right {
                        (other.left, a_right)
                    } else {
                        return Combined::TwoPieces;
                    }
                }
                Overlap::B => (self.left, b_right),
                Overlap::C => (self.left, a_right),
                Overlap::D => (other.left, b_right),
                Overlap::E => (other.left, a_right),
                Overlap::G => (rem, rem),
            }
        };
        self.left = left;
        self.right = right;
        self.step = new_step;
        Combined::Done
    }

    /// Sets `self` to a range containing both `self` and `other`, adding as
    /// few values as it can, and returns `true` when the result is
    /// everything (Ghidra `minimalContainer`).
    ///
    /// Two single values a power of two apart, at most `max_step`, give a
    /// stepped range of two values; otherwise the result has step 1. As in
    /// Ghidra, emptiness is not looked at: the bounds of an empty range are
    /// used as they are, and `self` keeps its empty flag.
    pub fn minimal_container(&mut self, other: &Self, max_step: i32) -> bool {
        if self.is_single() && other.is_single() {
            let (min, max) = if self.left < other.left {
                (self.left, other.left)
            } else {
                (other.left, self.left)
            };
            let diff = max.wrapping_sub(min);
            if diff > 0 && diff <= wide(max_step) && leastsigbit_set(diff) == mostsigbit_set(diff) {
                self.step = diff as u32 as i32;
                self.left = min;
                self.right = max.wrapping_add(wide(self.step)) & self.mask;
                return false;
            }
        }
        // Treat both ranges as having step 1.
        let a_right = self.right.wrapping_sub(wide(self.step)).wrapping_add(1);
        let b_right = other.right.wrapping_sub(wide(other.step)).wrapping_add(1);
        self.step = 1;
        self.mask |= other.mask;
        match encode(self.left, a_right, other.left, b_right) {
            Overlap::A => {
                let vacant1 = self
                    .left
                    .wrapping_add(self.mask.wrapping_sub(b_right))
                    .wrapping_add(1);
                let vacant2 = other.left.wrapping_sub(a_right);
                if vacant1 < vacant2 {
                    self.left = other.left;
                    self.right = a_right;
                } else {
                    self.right = b_right;
                }
            }
            Overlap::F => {
                let vacant1 = other
                    .left
                    .wrapping_add(self.mask.wrapping_sub(a_right))
                    .wrapping_add(1);
                let vacant2 = self.left.wrapping_sub(b_right);
                if vacant1 < vacant2 {
                    self.right = b_right;
                } else {
                    self.left = other.left;
                    self.right = a_right;
                }
            }
            Overlap::B => self.right = b_right,
            Overlap::C => self.right = a_right,
            Overlap::D => {
                self.left = other.left;
                self.right = b_right;
            }
            Overlap::E => {
                self.left = other.left;
                self.right = a_right;
            }
            Overlap::G => {
                self.left = 0;
                self.right = 0;
            }
        }
        self.normalize();
        self.left == self.right
    }

    /// Sets `self` to its complement with step 1 and returns the step it
    /// had (Ghidra `invert`). The complement is taken of the bounds alone,
    /// so for a stepped range it is not the set complement.
    pub const fn invert(&mut self) -> i32 {
        let old = self.step;
        self.step = 1;
        self.complement();
        old
    }

    /// Gives the range the step `new_step`, keeping the values congruent to
    /// `rem` (Ghidra `setStride`). The bounds move down to the new phase;
    /// they are not masked, as in Ghidra.
    pub const fn set_stride(&mut self, new_step: i32, rem: u64) {
        let everything = !self.empty && self.left == self.right;
        if new_step == self.step {
            return;
        }
        let a_right = self.right.wrapping_sub(wide(self.step));
        self.step = new_step;
        if new_step == 1 {
            return;
        }
        self.left = self
            .left
            .wrapping_sub(rem_step(self.left, new_step))
            .wrapping_add(rem);
        let a_right = a_right
            .wrapping_sub(rem_step(a_right, new_step))
            .wrapping_add(rem);
        self.right = a_right.wrapping_add(wide(new_step));
        if !everything && self.left == self.right {
            self.empty = true;
        }
    }

    /// Moves one bound of `self` out to the matching bound of `other`, a
    /// range containing it (Ghidra `widen`): the right bound, kept in
    /// `self`'s phase, when `left_is_stable`; otherwise the left bound.
    pub const fn widen(&mut self, other: &Self, left_is_stable: bool) {
        if left_is_stable {
            let lmod = rem_step(self.left, self.step);
            let rmod = rem_step(other.right, self.step);
            self.right = if rmod <= lmod {
                other.right.wrapping_add(lmod - rmod)
            } else {
                other.right.wrapping_sub(rmod - lmod)
            } & self.mask;
        } else {
            self.left = other.left & self.mask;
        }
        self.normalize();
    }
}
