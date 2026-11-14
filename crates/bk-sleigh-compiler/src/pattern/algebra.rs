//! Patterns with alternatives and the operations on them: and, or, the
//! common sub-pattern (`Pattern::doAnd`, `doOr`, `commonSubPattern`,
//! `simplifyClone`, inventory 10 b.4–b.6).
//!
//! The operations reproduce Ghidra's dispatch exactly, including which
//! operand's disjuncts come first in an `or` (the table in b.5) and the
//! shift `sa`: positive shifts the second operand's instruction bytes
//! `sa` bytes later, negative the first operand's by `-sa`.
//!
//! One quirk is not reproduced because it cannot be observed:
//! `OrPattern::doOr` with a negative shift also shifts the stored disjuncts
//! of the pattern it is called on. That pattern is always the result of a
//! child equation, which nothing reads again after the `or` (only its
//! ellipsis flags and token list are, never its blocks).

use super::block::Block;
use super::disjoint::Disjoint;

/// A pattern: one disjoint pattern, or alternatives (`OrPattern`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Pattern {
    /// No alternatives.
    One(Disjoint),
    /// Alternatives, tried in order.
    Or(Vec<Disjoint>),
}

impl Default for Pattern {
    fn default() -> Self {
        Self::TRUE
    }
}

fn instruction_and(a: &Block, b: &Block, sa: i32) -> Block {
    if sa < 0 {
        let mut a = a.clone();
        a.shift(-sa);
        a.intersect(b)
    } else {
        let mut b = b.clone();
        b.shift(sa);
        a.intersect(&b)
    }
}

fn instruction_common(a: &Block, b: &Block, sa: i32) -> Block {
    if sa < 0 {
        let mut a = a.clone();
        a.shift(-sa);
        a.common(b)
    } else {
        let mut b = b.clone();
        b.shift(sa);
        a.common(&b)
    }
}

fn shifted(block: &Block, sa: i32) -> Block {
    let mut block = block.clone();
    if sa < 0 {
        block.shift(-sa);
    }
    block
}

/// `doAnd` of two disjoint patterns.
fn and_disjoint(a: &Disjoint, b: &Disjoint, sa: i32) -> Disjoint {
    use Disjoint::{Combine, Context, Instruction};
    match (a, b) {
        (Instruction(_), Combine { .. }) | (Context(_), Instruction(_) | Combine { .. }) => {
            and_disjoint(b, a, sa.wrapping_neg())
        }
        (Instruction(x), Context(c)) => Combine {
            context: c.clone(),
            instr: shifted(x, sa),
        },
        (Instruction(x), Instruction(y)) => Instruction(instruction_and(x, y, sa)),
        (Context(x), Context(y)) => Context(x.intersect(y)),
        (Combine { context, instr }, Combine { context: c2, instr: i2 }) => Combine {
            context: context.intersect(c2),
            instr: instruction_and(instr, i2, sa),
        },
        (Combine { context, instr }, Instruction(y)) => Combine {
            context: context.clone(),
            instr: instruction_and(instr, y, sa),
        },
        (Combine { context, instr }, Context(c)) => Combine {
            context: context.intersect(c),
            instr: shifted(instr, sa),
        },
    }
}

/// `commonSubPattern` of two disjoint patterns.
fn common_disjoint(a: &Disjoint, b: &Disjoint, sa: i32) -> Disjoint {
    use Disjoint::{Combine, Context, Instruction};
    match (a, b) {
        (Instruction(_), Combine { .. }) | (Context(_), Instruction(_) | Combine { .. }) => {
            common_disjoint(b, a, sa.wrapping_neg())
        }
        (Instruction(_), Context(_)) => Disjoint::TRUE,
        (Instruction(x), Instruction(y)) => Instruction(instruction_common(x, y, sa)),
        (Context(x), Context(y)) => Context(x.common(y)),
        (Combine { context, instr }, Combine { context: c2, instr: i2 }) => Combine {
            context: context.common(c2),
            instr: instruction_common(instr, i2, sa),
        },
        (Combine { instr, .. }, Instruction(y)) => Instruction(instruction_common(instr, y, sa)),
        (Combine { context, .. }, Context(c)) => Context(context.common(c)),
    }
}

/// `doOr` of two disjoint patterns: the two (simplified) in Ghidra's order.
fn or_disjoint(a: &Disjoint, b: &Disjoint, sa: i32) -> Vec<Disjoint> {
    use Disjoint::{Combine, Context, Instruction};
    match (a, b) {
        (Instruction(_), Combine { .. }) | (Context(_), Instruction(_) | Combine { .. }) => {
            or_disjoint(b, a, sa.wrapping_neg())
        }
        (Context(_), Context(_)) => vec![a.simplified(), b.simplified()],
        _ => {
            let mut first = a.simplified();
            let mut second = b.simplified();
            if sa < 0 {
                first.shift_instruction(sa.wrapping_neg());
            } else {
                second.shift_instruction(sa);
            }
            vec![first, second]
        }
    }
}

impl Pattern {
    /// The always-true pattern.
    pub const TRUE: Self = Self::One(Disjoint::TRUE);
    /// The always-false pattern.
    pub const FALSE: Self = Self::One(Disjoint::FALSE);

    /// Matches everything (for alternatives: one of them does).
    pub fn always_true(&self) -> bool {
        match self {
            Self::One(d) => d.always_true(),
            Self::Or(list) => list.iter().any(Disjoint::always_true),
        }
    }

    /// Matches nothing.
    pub fn always_false(&self) -> bool {
        match self {
            Self::One(d) => d.always_false(),
            Self::Or(list) => list.iter().all(Disjoint::always_false),
        }
    }

    /// Places no constraint on the instruction bytes.
    pub fn always_instruction_true(&self) -> bool {
        match self {
            Self::One(d) => d.always_instruction_true(),
            Self::Or(list) => list.iter().all(Disjoint::always_instruction_true),
        }
    }

    /// The disjuncts: one, or the alternatives in order.
    pub fn disjuncts(&self) -> &[Disjoint] {
        match self {
            Self::One(d) => std::slice::from_ref(d),
            Self::Or(list) => list,
        }
    }

    /// `simplifyClone`.
    #[must_use]
    pub fn simplified(&self) -> Self {
        match self {
            Self::One(d) => Self::One(d.simplified()),
            Self::Or(list) => {
                if list.iter().any(Disjoint::always_true) {
                    return Self::TRUE;
                }
                let mut kept: Vec<Disjoint> = list
                    .iter()
                    .filter(|d| !d.always_false())
                    .map(Disjoint::simplified)
                    .collect();
                match kept.len() {
                    0 => Self::FALSE,
                    1 => Self::One(kept.pop().unwrap_or(Disjoint::FALSE)),
                    _ => Self::Or(kept),
                }
            }
        }
    }

    /// `doAnd`, unsimplified.
    #[must_use]
    pub fn and(&self, other: &Self, sa: i32) -> Self {
        match (self, other) {
            (Self::One(a), Self::One(b)) => Self::One(and_disjoint(a, b, sa)),
            (Self::One(_), Self::Or(_)) => other.and(self, sa.wrapping_neg()),
            (Self::Or(list), Self::One(b)) => {
                Self::Or(list.iter().map(|a| and_disjoint(a, b, sa)).collect())
            }
            (Self::Or(list), Self::Or(others)) => Self::Or(
                list.iter()
                    .flat_map(|a| others.iter().map(move |b| and_disjoint(a, b, sa)))
                    .collect(),
            ),
        }
    }

    /// `doOr`, unsimplified.
    #[must_use]
    pub fn or(&self, other: &Self, sa: i32) -> Self {
        match (self, other) {
            (Self::One(a), Self::One(b)) => Self::Or(or_disjoint(a, b, sa)),
            (Self::One(_), Self::Or(_)) => other.or(self, sa.wrapping_neg()),
            (Self::Or(list), _) => {
                let mut out: Vec<Disjoint> = list.iter().map(Disjoint::simplified).collect();
                out.extend(other.disjuncts().iter().map(Disjoint::simplified));
                if sa > 0 {
                    for d in &mut out {
                        d.shift_instruction(sa);
                    }
                }
                Self::Or(out)
            }
        }
    }

    /// `commonSubPattern`.
    #[must_use]
    pub fn common(&self, other: &Self, sa: i32) -> Self {
        match (self, other) {
            (Self::One(a), Self::One(b)) => Self::One(common_disjoint(a, b, sa)),
            (Self::One(_), Self::Or(_)) => other.common(self, sa.wrapping_neg()),
            (Self::Or(list), _) => {
                let Some((first, rest)) = list.split_first() else {
                    return Self::TRUE;
                };
                let mut res = Self::One(first.clone()).common(other, sa);
                let sa = sa.min(0);
                for d in rest {
                    res = Self::One(d.clone()).common(&res, sa);
                }
                res
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(off: i32, mask: u32, value: u32) -> Disjoint {
        Disjoint::Instruction(Block::word(off, mask, value))
    }

    fn ctx(mask: u32, value: u32) -> Disjoint {
        Disjoint::Context(Block::word(0, mask, value))
    }

    fn comb(c: &Disjoint, i: &Disjoint) -> Disjoint {
        match (c, i) {
            (Disjoint::Context(c), Disjoint::Instruction(i)) => Disjoint::Combine {
                context: c.clone(),
                instr: i.clone(),
            },
            _ => unreachable!(),
        }
    }

    /// Each row of the `doOr` order table (inventory 10 b.5).
    #[test]
    fn or_order_table() {
        let a_i = ins(0, 0xf000_0000, 0x1000_0000);
        let b_i = ins(0, 0x0f00_0000, 0x0200_0000);
        let a_c = ctx(0x8000_0000, 0x8000_0000);
        let b_c = ctx(0x4000_0000, 0);
        let a_m = comb(&a_c, &a_i);
        let b_m = comb(&b_c, &b_i);
        let one = |d: &Disjoint| Pattern::One(d.clone());
        let or2 = Pattern::Or(vec![b_i.clone(), b_c.clone()]);
        let or_of = |a: &Disjoint, b: &Disjoint| one(a).or(&one(b), 0);
        assert_eq!(or_of(&a_i, &b_i), Pattern::Or(vec![a_i.clone(), b_i.clone()]));
        assert_eq!(or_of(&a_i, &b_c), Pattern::Or(vec![a_i.clone(), b_c.clone()]));
        assert_eq!(or_of(&a_i, &b_m), Pattern::Or(vec![b_m.clone(), a_i.clone()]));
        assert_eq!(
            one(&a_i).or(&or2, 0),
            Pattern::Or(vec![b_i.clone(), b_c.clone(), a_i.clone()])
        );
        assert_eq!(or_of(&a_c, &b_c), Pattern::Or(vec![a_c.clone(), b_c.clone()]));
        assert_eq!(or_of(&a_c, &b_i), Pattern::Or(vec![b_i.clone(), a_c.clone()]));
        assert_eq!(or_of(&a_c, &b_m), Pattern::Or(vec![b_m.clone(), a_c.clone()]));
        assert_eq!(
            one(&a_c).or(&or2, 0),
            Pattern::Or(vec![b_i.clone(), b_c.clone(), a_c.clone()])
        );
        assert_eq!(or_of(&a_m, &b_i), Pattern::Or(vec![a_m.clone(), b_i.clone()]));
        assert_eq!(or_of(&a_m, &b_c), Pattern::Or(vec![a_m.clone(), b_c.clone()]));
        assert_eq!(or_of(&a_m, &b_m), Pattern::Or(vec![a_m.clone(), b_m.clone()]));
        assert_eq!(
            one(&a_m).or(&or2, 0),
            Pattern::Or(vec![b_i.clone(), b_c.clone(), a_m.clone()])
        );
        assert_eq!(
            or2.or(&one(&a_m), 0),
            Pattern::Or(vec![b_i, b_c, a_m])
        );
    }

    #[test]
    fn or_with_positive_shift_shifts_every_disjunct() {
        let a = Pattern::Or(vec![ins(0, 0xff00_0000, 1 << 24), ins(0, 0xff00_0000, 2 << 24)]);
        let b = Pattern::One(ins(0, 0xff00_0000, 3 << 24));
        let r = a.or(&b, 2);
        for d in r.disjuncts() {
            assert_eq!(d.block(false).map(|b| b.offset), Some(2));
        }
    }

    #[test]
    fn and_shifts_and_combines() {
        let i = Pattern::One(ins(0, 0xff00_0000, 0x1200_0000));
        let j = Pattern::One(ins(0, 0xff00_0000, 0x3400_0000));
        let r = i.and(&j, 1);
        assert_eq!(
            r,
            Pattern::One(Disjoint::Instruction(Block {
                offset: 0,
                nonzero: 2,
                words: vec![bk_sla::MaskWord {
                    mask: 0xffff_0000,
                    value: 0x1234_0000
                }]
            }))
        );
        let c = Pattern::One(ctx(0x8000_0000, 0x8000_0000));
        let r = c.and(&i, 0);
        assert!(matches!(r, Pattern::One(Disjoint::Combine { .. })));
        let impossible = i.and(&Pattern::One(ins(0, 0xff00_0000, 0)), 0);
        assert!(impossible.always_false());
    }

    #[test]
    fn simplify_drops_false_and_collapses_true() {
        let p = Pattern::Or(vec![Disjoint::FALSE, ins(0, 0xff00_0000, 0)]);
        assert_eq!(p.simplified(), Pattern::One(ins(0, 0xff00_0000, 0)));
        let p = Pattern::Or(vec![ins(0, 0xff00_0000, 0), Disjoint::TRUE]);
        assert_eq!(p.simplified(), Pattern::TRUE);
        let p = Pattern::Or(vec![Disjoint::FALSE, Disjoint::FALSE]);
        assert_eq!(p.simplified(), Pattern::FALSE);
    }

    #[test]
    fn common_of_alternatives() {
        let p = Pattern::Or(vec![ins(0, 0xff00_0000, 0x1200_0000), ins(0, 0xff00_0000, 0x1300_0000)]);
        let q = Pattern::One(ins(0, 0xff00_0000, 0x1000_0000));
        let r = p.common(&q, 0);
        assert_eq!(r, Pattern::One(ins(0, 0xfc00_0000, 0x1000_0000)));
        let c = Pattern::One(ctx(0x8000_0000, 0));
        assert_eq!(q.common(&c, 0), Pattern::TRUE);
    }
}
