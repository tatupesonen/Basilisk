//! Disjoint patterns: over the instruction bytes, over the context, or
//! both (`InstructionPattern`, `ContextPattern`, `CombinePattern`), with the
//! helpers the decision tree uses (`DisjointPattern`, inventory 10 b.3).

use super::block::Block;

/// A pattern without alternatives.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Disjoint {
    /// Constraints on the instruction bytes.
    Instruction(Block),
    /// Constraints on the context.
    Context(Block),
    /// Constraints on both.
    Combine {
        /// The context part.
        context: Block,
        /// The instruction part.
        instr: Block,
    },
}

impl Disjoint {
    /// The always-true instruction pattern.
    pub const TRUE: Self = Self::Instruction(Block::constant(true));
    /// The always-false instruction pattern.
    pub const FALSE: Self = Self::Instruction(Block::constant(false));

    /// Matches everything.
    pub const fn always_true(&self) -> bool {
        match self {
            Self::Instruction(b) | Self::Context(b) => b.always_true(),
            Self::Combine { context, instr } => context.always_true() && instr.always_true(),
        }
    }

    /// Matches nothing.
    pub const fn always_false(&self) -> bool {
        match self {
            Self::Instruction(b) | Self::Context(b) => b.always_false(),
            Self::Combine { context, instr } => context.always_false() || instr.always_false(),
        }
    }

    /// Places no constraint on the instruction bytes.
    pub const fn always_instruction_true(&self) -> bool {
        match self {
            Self::Instruction(b) => b.always_true(),
            Self::Context(_) => true,
            Self::Combine { instr, .. } => instr.always_true(),
        }
    }

    /// Moves the instruction part `sa` bytes later (`shiftInstruction`).
    pub fn shift_instruction(&mut self, sa: i32) {
        match self {
            Self::Instruction(b) | Self::Combine { instr: b, .. } => b.shift(sa),
            Self::Context(_) => {}
        }
    }

    /// `simplifyClone`: a combination with a trivially true part becomes
    /// the other part; one with a false part becomes false.
    pub fn simplified(&self) -> Self {
        match self {
            Self::Combine { context, instr } => {
                if context.always_true() {
                    Self::Instruction(instr.clone())
                } else if instr.always_true() {
                    Self::Context(context.clone())
                } else if context.always_false() || instr.always_false() {
                    Self::FALSE
                } else {
                    self.clone()
                }
            }
            other => other.clone(),
        }
    }

    /// The context part (`context == true`) or instruction part, if the
    /// pattern has one (`getBlock`).
    pub const fn block(&self, context: bool) -> Option<&Block> {
        match (self, context) {
            (Self::Instruction(b), false) | (Self::Context(b), true) => Some(b),
            (Self::Combine { context: c, .. }, true) => Some(c),
            (Self::Combine { instr, .. }, false) => Some(instr),
            _ => None,
        }
    }

    /// Bits of the mask of one part; 0 if the part is absent.
    pub fn mask(&self, start: i32, size: i32, context: bool) -> u32 {
        self.block(context).map_or(0, |b| b.mask(start, size))
    }

    /// Bits of the value of one part; 0 if the part is absent.
    pub fn value(&self, start: i32, size: i32, context: bool) -> u32 {
        self.block(context).map_or(0, |b| b.value(start, size))
    }

    /// The length of one part; 0 if absent.
    pub fn length(&self, context: bool) -> i32 {
        self.block(context).map_or(0, Block::length)
    }

    /// Everything `other` requires is required here (`specializes`).
    pub fn specializes(&self, other: &Self) -> bool {
        [false, true].into_iter().all(|context| {
            match (self.block(context), other.block(context)) {
                (_, None) => true,
                (_, Some(b)) if b.always_true() => true,
                (None, Some(_)) => false,
                (Some(a), Some(b)) => a.specializes(b),
            }
        })
    }

    /// The same constraints (`identical`).
    pub fn identical(&self, other: &Self) -> bool {
        [false, true].into_iter().all(|context| {
            match (self.block(context), other.block(context)) {
                (None, Some(b)) => b.always_true(),
                (Some(a), Some(b)) => a.identical(b),
                (None, None) => true,
                (Some(a), None) => a.always_true(),
            }
        })
    }

    /// This pattern is exactly the intersection of `a` and `b`
    /// (`resolvesIntersect`).
    pub fn resolves_intersect(&self, a: &Self, b: &Self) -> bool {
        [false, true].into_iter().all(|context| {
            let inter = match (a.block(context), b.block(context)) {
                (None, None) => None,
                (Some(x), None) | (None, Some(x)) => Some(x.clone()),
                (Some(x), Some(y)) => Some(x.intersect(y)),
            };
            match (self.block(context), inter) {
                (mine, None) => mine.is_none(),
                (None, Some(_)) => false,
                (Some(mine), Some(inter)) => mine.identical(&inter),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplify_rules() {
        let t = Block::constant(true);
        let f = Block::constant(false);
        let x = Block::word(0, 0xf000_0000, 0x1000_0000);
        let combine = |c: &Block, i: &Block| Disjoint::Combine {
            context: c.clone(),
            instr: i.clone(),
        };
        assert_eq!(combine(&t, &x).simplified(), Disjoint::Instruction(x.clone()));
        assert_eq!(combine(&x, &t).simplified(), Disjoint::Context(x.clone()));
        assert_eq!(combine(&x, &f).simplified(), Disjoint::FALSE);
        assert_eq!(combine(&x, &x).simplified(), combine(&x, &x));
    }

    #[test]
    fn specializes_across_kinds() {
        let x = Block::word(0, 0xf000_0000, 0x1000_0000);
        let c = Block::word(0, 0x8000_0000, 0x8000_0000);
        let both = Disjoint::Combine {
            context: c.clone(),
            instr: x.clone(),
        };
        assert!(both.specializes(&Disjoint::Instruction(x.clone())));
        assert!(both.specializes(&Disjoint::Context(c.clone())));
        assert!(!Disjoint::Instruction(x.clone()).specializes(&both));
        assert!(Disjoint::Instruction(x).specializes(&Disjoint::TRUE));
    }

    #[test]
    fn resolves_intersect_of_instruction_and_context() {
        let x = Block::word(0, 0xf000_0000, 0x1000_0000);
        let c = Block::word(0, 0x8000_0000, 0x8000_0000);
        let both = Disjoint::Combine {
            context: c.clone(),
            instr: x.clone(),
        };
        assert!(both.resolves_intersect(&Disjoint::Instruction(x.clone()), &Disjoint::Context(c)));
        assert!(!Disjoint::Instruction(x.clone()).resolves_intersect(&Disjoint::Instruction(x), &both));
    }
}
