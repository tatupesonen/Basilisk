//! The representation of a circle range, its constructors, its queries and
//! its text form (the first half of `rangeutil.cc`, lines 21–297 and
//! 1,469–1,492, and the inline members of `rangeutil.hh`).

use core::fmt;

use crate::arith::{div, mask_of, rem_step, wide};

/// A set of integers modulo 2ⁿ: the values `left, left+step, …` up to but
/// not including `right`, wrapping at `mask + 1` (Ghidra `CircleRange`).
///
/// `left == right` on a non-empty range means every value congruent to
/// `left` modulo `step`, the whole domain when the step is 1. The bounds of
/// a well-formed range agree modulo the step and the step is a power of
/// two, but nothing enforces that: as in Ghidra, every field can hold any
/// value and every method gives a defined result for it.
///
/// The fields of an empty range carry no meaning, but they are kept and
/// reported exactly as Ghidra keeps them, because several methods read
/// them. A range made empty by [`CircleRange::empty`] or
/// [`Default::default`] has zero bounds and mask and a step of 1, where
/// Ghidra's default constructor leaves them uninitialised.
#[derive(Debug, Clone, Copy)]
pub struct CircleRange {
    pub(crate) left: u64,
    pub(crate) right: u64,
    pub(crate) mask: u64,
    pub(crate) step: i32,
    pub(crate) empty: bool,
}

impl Default for CircleRange {
    fn default() -> Self {
        Self::empty()
    }
}

/// Ghidra `CircleRange::operator==`: two empty ranges are equal; otherwise
/// all four fields must be. Two descriptions of one set that are not in
/// the same form (an unnormalised full range, a different mask) are not.
impl PartialEq for CircleRange {
    fn eq(&self, other: &Self) -> bool {
        if self.empty != other.empty {
            return false;
        }
        self.empty
            || (self.left == other.left
                && self.right == other.right
                && self.mask == other.mask
                && self.step == other.step)
    }
}

impl Eq for CircleRange {}

impl CircleRange {
    /// The empty range (Ghidra's default constructor).
    pub const fn empty() -> Self {
        Self {
            left: 0,
            right: 0,
            mask: 0,
            step: 1,
            empty: true,
        }
    }

    /// The range `[left, right)` of a `size`-byte domain with the given
    /// step (Ghidra `CircleRange(lft, rgt, size, stp)`). Both bounds are
    /// masked to the domain; nothing is normalised or checked.
    pub const fn new(left: u64, right: u64, size: u32, step: i32) -> Self {
        let mask = mask_of(size);
        Self {
            left: left & mask,
            right: right & mask,
            mask,
            step,
            empty: false,
        }
    }

    /// The range holding only 0 (`false`) or 1 (`true`), in a 1-byte
    /// domain (Ghidra `CircleRange(bool)`).
    pub const fn from_bool(val: bool) -> Self {
        Self {
            left: val as u64,
            right: val as u64 + 1,
            mask: 0xff,
            step: 1,
            empty: false,
        }
    }

    /// The range holding the single value `val` of a `size`-byte domain
    /// (Ghidra `CircleRange(val, size)`). As in Ghidra, `val` itself is not
    /// masked; only the end bound is.
    pub const fn single(val: u64, size: u32) -> Self {
        let mask = mask_of(size);
        Self {
            left: val,
            right: val.wrapping_add(1) & mask,
            mask,
            step: 1,
            empty: false,
        }
    }

    /// Every value of a `size`-byte domain (the result of Ghidra's
    /// `setFull`).
    pub const fn full(size: u32) -> Self {
        Self {
            left: 0,
            right: 0,
            mask: mask_of(size),
            step: 1,
            empty: false,
        }
    }

    /// A range with exactly these fields, unchecked. Ghidra has no such
    /// constructor; it is how a caller (or a test) restores a range it took
    /// apart with the accessors.
    pub const fn from_parts(left: u64, right: u64, mask: u64, step: i32, empty: bool) -> Self {
        Self {
            left,
            right,
            mask,
            step,
            empty,
        }
    }

    /// Sets `self` to [`CircleRange::new`]`(left, right, size, step)`
    /// (Ghidra `setRange(lft, rgt, size, step)`).
    pub const fn set_range(&mut self, left: u64, right: u64, size: u32, step: i32) {
        *self = Self::new(left, right, size, step);
    }

    /// Sets `self` to [`CircleRange::single`]`(val, size)` (Ghidra
    /// `setRange(val, size)`).
    pub const fn set_single(&mut self, val: u64, size: u32) {
        *self = Self::single(val, size);
    }

    /// Sets `self` to every value of a `size`-byte domain (Ghidra
    /// `setFull`).
    pub const fn set_full(&mut self, size: u32) {
        *self = Self::full(size);
    }

    /// Whether the range is empty (Ghidra `isEmpty`).
    pub const fn is_empty(&self) -> bool {
        self.empty
    }

    /// Whether the range holds every value of its domain: non-empty, step
    /// 1 and `left == right` (Ghidra `isFull`).
    pub const fn is_full(&self) -> bool {
        !self.empty && self.step == 1 && self.left == self.right
    }

    /// Whether the range holds exactly one value: non-empty and `right` is
    /// one step past `left` (Ghidra `isSingle`).
    pub const fn is_single(&self) -> bool {
        !self.empty && self.right == (self.left.wrapping_add(wide(self.step)) & self.mask)
    }

    /// The left bound, the first value of the range (Ghidra `getMin`).
    pub const fn min(&self) -> u64 {
        self.left
    }

    /// The last value of the range: one step before `right` (Ghidra
    /// `getMax`).
    pub const fn max(&self) -> u64 {
        self.right.wrapping_sub(wide(self.step)) & self.mask
    }

    /// The right bound, one step past the last value (Ghidra `getEnd`).
    pub const fn end(&self) -> u64 {
        self.right
    }

    /// The mask of the domain, 2ⁿ−1 (Ghidra `getMask`).
    pub const fn mask(&self) -> u64 {
        self.mask
    }

    /// The step between consecutive values (Ghidra `getStep`).
    pub const fn step(&self) -> i32 {
        self.step
    }

    /// The number of values in the range (Ghidra `getSize`).
    ///
    /// For the full set of an 8-byte domain the count does not fit, and as
    /// in Ghidra the answer is one short: `mask`, or `mask / step + 1` for
    /// a stepped range ("we lie by one").
    pub const fn count(&self) -> u64 {
        if self.empty {
            return 0;
        }
        let step = wide(self.step);
        if self.left < self.right {
            return div(self.right - self.left, step);
        }
        let val = div(
            self.mask
                .wrapping_sub(self.left.wrapping_sub(self.right))
                .wrapping_add(step),
            step,
        );
        if val != 0 {
            return val;
        }
        if self.step > 1 {
            div(self.mask, step) + 1
        } else {
            self.mask
        }
    }

    /// The largest number of significant bits of any value in the range,
    /// counting a value with its top bit set by its magnitude as a negative
    /// number (Ghidra `getMaxInfo`).
    pub fn max_info(&self) -> i32 {
        let half = self.mask ^ (self.mask >> 1);
        if self.contains_value(half) {
            return 64 - half.leading_zeros() as i32;
        }
        let zeros = |v: u64| {
            if half & v == 0 {
                v.leading_zeros()
            } else {
                (!v & self.mask).leading_zeros()
            }
        };
        64 - zeros(self.left).min(zeros(self.right)) as i32
    }

    /// Advances `val` by one step within the domain and reports whether it
    /// is still inside the range, that is, has not reached `right` (Ghidra
    /// `getNext`). Starting from [`CircleRange::min`], this visits every
    /// value of a well-formed range.
    pub const fn next(&self, val: &mut u64) -> bool {
        *val = val.wrapping_add(wide(self.step)) & self.mask;
        *val != self.right
    }

    /// Whether `val` is in the range (Ghidra `contains(uintb)`).
    pub const fn contains_value(&self, val: u64) -> bool {
        if self.empty {
            return false;
        }
        if self.step != 1 && rem_step(self.left, self.step) != rem_step(val, self.step) {
            return false;
        }
        if self.left < self.right {
            val >= self.left && val < self.right
        } else if self.right < self.left {
            val < self.right || val >= self.left
        } else {
            true
        }
    }

    /// Ghidra's private `normalize`: a full set (`left == right`) gets
    /// `left = right = left % step`, 0 for a step of 1.
    pub(crate) const fn normalize(&mut self) {
        if self.left == self.right {
            self.left = if self.step == 1 {
                0
            } else {
                rem_step(self.left, self.step)
            };
            self.right = self.left;
        }
    }

    /// Ghidra's private `complement`, valid only for a step of 1: empty
    /// becomes full, full becomes empty, otherwise the bounds swap.
    pub(crate) const fn complement(&mut self) {
        if self.empty {
            self.left = 0;
            self.right = 0;
            self.empty = false;
        } else if self.left == self.right {
            self.empty = true;
        } else {
            core::mem::swap(&mut self.left, &mut self.right);
        }
    }
}

/// Ghidra `printRaw`: `(empty)`; `(full)` or `(full,<step>)`; `[<left>]`
/// for a single value; otherwise `[<left>,<right>)` with `,<step>` before
/// the parenthesis when the step is not 1. Bounds in lower-case hex
/// without `0x`, the step in decimal.
impl fmt::Display for CircleRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.empty {
            return f.write_str("(empty)");
        }
        if self.left == self.right {
            f.write_str("(full")?;
            if self.step != 1 {
                write!(f, ",{}", self.step)?;
            }
            f.write_str(")")
        } else if self.right == (self.left.wrapping_add(1) & self.mask) {
            write!(f, "[{:x}]", self.left)
        } else {
            write!(f, "[{:x},{:x}", self.left, self.right)?;
            if self.step != 1 {
                write!(f, ",{}", self.step)?;
            }
            f.write_str(")")
        }
    }
}
