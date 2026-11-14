//! Absolute operand offsets where they can be known, and the order operands
//! are decoded in (`Constructor::buildPattern`'s unravelling loop and
//! `Constructor::orderOperands`, inventory 10 c.3–c.4).

use crate::equation::Offsets;

/// What the reordering needs to know of one operand (by parse index).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OperandFacts {
    pub(crate) irrelevant: bool,
    pub(crate) variable: bool,
    pub(crate) min_length: i32,
}

/// Rewrites each offset relative to a chain of fixed-length operands as an
/// offset from the constructor's start, where the chain reaches it without
/// crossing a variable-length operand.
pub(crate) fn unravel(offsets: &mut [Offsets], facts: &[OperandFacts]) {
    for i in 0..offsets.len() {
        let fact = facts.get(i).copied().unwrap_or_default();
        if fact.irrelevant {
            if let Some(o) = offsets.get_mut(i) {
                *o = Offsets { base: -1, offset: 0 };
            }
            continue;
        }
        let Some(&Offsets { mut base, mut offset }) = offsets.get(i) else {
            continue;
        };
        // A chain longer than the operand count is a cycle; stop there (the
        // cycle is reported by the ordering).
        let mut steps = 0;
        while base >= 0 && steps <= offsets.len() {
            steps += 1;
            let b = base as usize;
            let Some(link) = offsets.get(b).copied() else {
                break;
            };
            let link_fact = facts.get(b).copied().unwrap_or_default();
            if link_fact.variable {
                break;
            }
            base = link.base;
            offset = offset
                .wrapping_add(link_fact.min_length)
                .wrapping_add(link.offset);
            if base < 0
                && let Some(o) = offsets.get_mut(i)
            {
                *o = Offsets { base, offset };
            }
        }
    }
}

/// The decoding order: operands placed by the equation first, each after
/// the operand its offset depends on, then offset-irrelevant operands.
/// `pattern_order` is the equation's left-to-right order of operand
/// indices. Returns the old index at each new position, or `None` for a
/// circular dependency.
pub(crate) fn order_operands(
    pattern_order: &[usize],
    offsets: &[Offsets],
    facts: &[OperandFacts],
) -> Option<Vec<usize>> {
    let n = offsets.len();
    let mut order: Vec<usize> = pattern_order.to_vec();
    let mut marked = vec![false; n];
    for &i in &order {
        if let Some(m) = marked.get_mut(i) {
            *m = true;
        }
    }
    for i in 0..n {
        if let Some(m) = marked.get_mut(i)
            && !*m
        {
            *m = true;
            order.push(i);
        }
    }
    let irrelevant = |i: usize| facts.get(i).is_some_and(|f| f.irrelevant);
    let mut newops = Vec::with_capacity(n);
    loop {
        let last = newops.len();
        for &i in &order {
            if !marked.get(i).copied().unwrap_or(false) || irrelevant(i) {
                continue;
            }
            let base = offsets.get(i).map_or(-1, |o| o.base);
            let base_pending = usize::try_from(base)
                .ok()
                .is_some_and(|b| marked.get(b).copied().unwrap_or(false));
            if base == -1 || !base_pending {
                newops.push(i);
                if let Some(m) = marked.get_mut(i) {
                    *m = false;
                }
            }
        }
        if newops.len() == last {
            break;
        }
    }
    for &i in &order {
        if irrelevant(i) {
            newops.push(i);
        }
    }
    (newops.len() == n).then_some(newops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(base: i32, offset: i32) -> Offsets {
        Offsets { base, offset }
    }

    fn fixed(len: i32) -> OperandFacts {
        OperandFacts {
            min_length: len,
            ..OperandFacts::default()
        }
    }

    #[test]
    fn unravel_through_fixed_operands_only() {
        // 0 at start; 1 after 0 (len 2); 2 after 1 (variable); 3 after 2.
        let mut offsets = vec![o(-1, 0), o(0, 1), o(-1, 4), o(2, 0)];
        let facts = vec![
            fixed(2),
            fixed(1),
            OperandFacts {
                variable: true,
                ..fixed(1)
            },
            fixed(1),
        ];
        unravel(&mut offsets, &facts);
        assert_eq!(offsets, [o(-1, 0), o(-1, 3), o(-1, 4), o(2, 0)]);
    }

    #[test]
    fn order_puts_dependents_after_their_base() {
        // Pattern order: 2, 0, 1; operand 2 depends on 1; 3 is irrelevant.
        let offsets = vec![o(-1, 0), o(-1, 1), o(1, 0), o(-1, 0)];
        let mut facts = vec![fixed(1); 4];
        facts[3].irrelevant = true;
        assert_eq!(order_operands(&[2, 0, 1], &offsets, &facts), Some(vec![0, 1, 2, 3]));
        // A base placed earlier in the same pass counts at once.
        assert_eq!(order_operands(&[1, 2, 0], &offsets, &facts), Some(vec![1, 2, 0, 3]));
    }

    #[test]
    fn circular_dependency_is_detected() {
        let offsets = vec![o(1, 0), o(0, 0)];
        assert_eq!(order_operands(&[0, 1], &offsets, &[fixed(1); 2]), None);
    }
}
