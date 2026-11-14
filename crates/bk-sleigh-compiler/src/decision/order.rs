//! The order of the patterns at a leaf (`DecisionNode::orderPatterns`,
//! inventory 10 c.9): most specialised first, with identical and
//! conflicting patterns noted.

use super::Properties;
use super::node::Entry;

/// Orders `entries` in place and records identical and unresolved
/// conflicting patterns in `props`.
pub(crate) fn order_patterns(entries: &mut Vec<Entry>, props: &mut Properties) {
    let n = entries.len();
    for i in 0..n {
        for j in 0..i {
            if let (Some(a), Some(b)) = (entries.get(i), entries.get(j))
                && a.pattern.identical(&b.pattern)
            {
                props.identical(a.ctor, b.ctor);
            }
        }
    }
    // Work on positions of the original list: `list` holds the identity
    // (original position) of each placed entry; identity stands in for
    // Ghidra's pattern pointers in the conflict check.
    let original = std::mem::take(entries);
    let mut list: Vec<usize> = (0..n).collect();
    let mut conflicts: Vec<(usize, usize)> = Vec::new();
    for i in 0..n {
        let Some(ipat) = original.get(i) else {
            continue;
        };
        let mut j = 0;
        while j < i {
            let jid = list.get(j).copied().unwrap_or(0);
            let Some(jpat) = original.get(jid) else { break };
            if ipat.pattern.specializes(&jpat.pattern) {
                break;
            }
            if !jpat.pattern.specializes(&ipat.pattern) && ipat.ctor != jpat.ctor {
                conflicts.push((i, jid));
            }
            j += 1;
        }
        // Move entry i to position j, shifting list[j..i] up by one.
        if j < i {
            list.copy_within(j..i, j + 1);
        }
        if let Some(slot) = list.get_mut(j) {
            *slot = i;
        }
    }
    for &(a, b) in &conflicts {
        let (Some(pa), Some(pb)) = (original.get(a), original.get(b)) else {
            continue;
        };
        let mut resolved = false;
        for &t in &list {
            if t == a || t == b {
                break;
            }
            if original
                .get(t)
                .is_some_and(|tp| tp.pattern.resolves_intersect(&pa.pattern, &pb.pattern))
            {
                resolved = true;
                break;
            }
        }
        if !resolved {
            props.conflicting(pa.ctor, pb.ctor);
        }
    }
    let mut slots: Vec<Option<Entry>> = original.into_iter().map(Some).collect();
    entries.extend(
        list.iter()
            .filter_map(|&k| slots.get_mut(k).and_then(Option::take)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::CtorId;
    use crate::pattern::{Block, Disjoint};

    fn entry(ctor: u32, mask: u32, value: u32) -> Entry {
        Entry {
            pattern: Disjoint::Instruction(Block::word(0, mask, value)),
            index: ctor,
            ctor: CtorId::new(ctor),
        }
    }

    fn order(entries: &[Entry]) -> (Vec<u32>, Properties) {
        let mut e = entries.to_vec();
        let mut props = Properties::default();
        order_patterns(&mut e, &mut props);
        (e.iter().map(|e| e.index).collect(), props)
    }

    #[test]
    fn nested_patterns_most_specialised_first() {
        let (o, p) = order(&[
            entry(0, 0x8000_0000, 0x8000_0000),
            entry(1, 0xc000_0000, 0xc000_0000),
            entry(2, 0xe000_0000, 0xe000_0000),
        ]);
        assert_eq!(o, [2, 1, 0]);
        assert_eq!(p.conflicts, []);
    }

    #[test]
    fn identical_patterns_are_recorded_once() {
        let (o, p) = order(&[entry(0, 0x8000_0000, 0), entry(1, 0x8000_0000, 0)]);
        assert_eq!(o, [1, 0]);
        assert_eq!(p.identical, [(CtorId::new(1), CtorId::new(0))]);
    }

    #[test]
    fn overlap_resolved_by_the_intersection() {
        // a: bit0=1, b: bit1=1, c: both (the intersection) — resolved.
        let (o, p) = order(&[
            entry(0, 0x8000_0000, 0x8000_0000),
            entry(1, 0x4000_0000, 0x4000_0000),
            entry(2, 0xc000_0000, 0xc000_0000),
        ]);
        assert_eq!(o, [2, 0, 1]);
        assert_eq!(p.conflicts, []);
        // Without the intersection it is a conflict.
        let (_, p) = order(&[
            entry(0, 0x8000_0000, 0x8000_0000),
            entry(1, 0x4000_0000, 0x4000_0000),
        ]);
        assert_eq!(p.conflicts, [(CtorId::new(1), CtorId::new(0))]);
    }

    #[test]
    fn disjuncts_of_one_constructor_do_not_conflict() {
        let (_, p) = order(&[
            entry(0, 0x8000_0000, 0x8000_0000),
            entry(0, 0x4000_0000, 0x4000_0000),
        ]);
        assert_eq!(p.conflicts, []);
    }
}
