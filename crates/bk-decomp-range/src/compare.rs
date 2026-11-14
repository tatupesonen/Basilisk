//! Ranges as comparisons: `translate2Op` and the private
//! `convertToBoolean` (`rangeutil.cc` lines 56–90 and 1,413–1,467).

use bk_pcode::OpCode;

use crate::range::CircleRange;

/// The comparison a range stands for (Ghidra `translate2Op`, whose return
/// codes are 0–3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Translated {
    /// Ghidra's 0: the range is exactly the inputs for which `op`, with the
    /// constant `constant` in input slot `slot` (0 or 1) and the variable
    /// in the other, is true.
    Comparison {
        /// `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS` or `INT_SLESS`.
        op: OpCode,
        /// The constant input.
        constant: u64,
        /// The slot holding the constant.
        slot: u32,
    },
    /// Ghidra's 1: the range is full; every input makes the comparison
    /// true.
    Always,
    /// Ghidra's 2: no single comparison describes the range (it has a step,
    /// or its bounds are not at a domain edge).
    NotPossible,
    /// Ghidra's 3: the range is empty; no input makes it true.
    Never,
}

impl CircleRange {
    /// Ghidra's private `convertToBoolean`: replaces the range by the
    /// 1-byte boolean range of which of 0 and 1 it contains, and returns
    /// `true` when it contains both. An empty range stays as it is.
    pub(crate) fn convert_to_boolean(&mut self) -> bool {
        if self.empty {
            return false;
        }
        let zero = self.contains_value(0);
        let one = self.contains_value(1);
        self.mask = 0xff;
        self.step = 1;
        match (zero, one) {
            (true, true) => {
                self.left = 0;
                self.right = 2;
                return true;
            }
            (true, false) => {
                self.left = 0;
                self.right = 1;
            }
            (false, true) => {
                self.left = 1;
                self.right = 2;
            }
            (false, false) => self.empty = true,
        }
        false
    }

    /// The comparison whose true inputs are exactly this range (Ghidra
    /// `translate2Op`): a single value is `x == c`, all but one value
    /// `x != c`, and a range touching 0 or the most negative value an
    /// unsigned or signed `<` against a constant.
    pub fn translate_2op(&self) -> Translated {
        if self.empty {
            return Translated::Never;
        }
        if self.step != 1 {
            return Translated::NotPossible;
        }
        let cmp = |op, constant, slot| Translated::Comparison { op, constant, slot };
        let sign = (self.mask >> 1).wrapping_add(1);
        if self.right == (self.left.wrapping_add(1) & self.mask) {
            cmp(OpCode::IntEqual, self.left, 0)
        } else if self.left == (self.right.wrapping_add(1) & self.mask) {
            cmp(OpCode::IntNotEqual, self.right, 0)
        } else if self.left == self.right {
            Translated::Always
        } else if self.left == 0 {
            cmp(OpCode::IntLess, self.right, 1)
        } else if self.right == 0 {
            cmp(OpCode::IntLess, self.left.wrapping_sub(1) & self.mask, 0)
        } else if self.left == sign {
            cmp(OpCode::IntSLess, self.right, 1)
        } else if self.right == sign {
            cmp(OpCode::IntSLess, self.left.wrapping_sub(1) & self.mask, 0)
        } else {
            Translated::NotPossible
        }
    }
}
