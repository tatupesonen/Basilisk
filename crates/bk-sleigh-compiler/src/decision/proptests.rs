//! Property tests (spec 6.4): the pattern operations mean what they say on
//! bit strings, and a decision tree is an index over its patterns, not a
//! different semantics. Case count from `PROPTEST_CASES` (default 256).

use proptest::prelude::*;

use super::node::Entry;
use super::order::order_patterns;
use super::{DecisionTree, Properties, build_tree};
use crate::ids::CtorId;
use crate::pattern::{Block, Disjoint};

/// Whether `block` matches the instruction bytes `bytes` (zero beyond).
fn matches(block: &Block, bytes: &[u8]) -> bool {
    if block.always_false() {
        return false;
    }
    let byte = |i: i32| {
        usize::try_from(i)
            .ok()
            .and_then(|i| bytes.get(i))
            .copied()
            .unwrap_or(0)
    };
    block.words.iter().enumerate().all(|(k, w)| {
        let at = block.offset + 4 * k as i32;
        let data = u32::from_be_bytes([byte(at), byte(at + 1), byte(at + 2), byte(at + 3)]);
        data & w.mask == w.value
    })
}

fn block() -> impl Strategy<Value = Block> {
    (0_i32..3, any::<u32>(), any::<u32>()).prop_map(|(off, mask, value)| {
        // Sparse masks make overlaps likely.
        let mask = mask & 0xf0f0_0f0f;
        Block::word(off, mask, value & mask)
    })
}

fn bytes() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 7), 48)
}

proptest! {
    #[test]
    fn block_operations_have_their_set_meaning(a in block(), b in block(), xs in bytes()) {
        let inter = a.intersect(&b);
        let common = a.common(&b);
        for x in &xs {
            let (ma, mb) = (matches(&a, x), matches(&b, x));
            prop_assert_eq!(matches(&inter, x), ma && mb);
            if ma || mb {
                prop_assert!(matches(&common, x));
            }
            if a.specializes(&b) && ma {
                prop_assert!(mb);
            }
        }
        // Inputs built to match a and b.
        let mut x = vec![0_u8; 7];
        for blk in [&a, &b] {
            for (k, w) in blk.words.iter().enumerate() {
                let at = blk.offset as usize + 4 * k;
                for (i, byte) in w.value.to_be_bytes().iter().enumerate() {
                    let m = w.mask.to_be_bytes()[i];
                    if let Some(slot) = x.get_mut(at + i) {
                        *slot = (*slot & !m) | (byte & m);
                    }
                }
            }
        }
        prop_assert_eq!(matches(&inter, &x), matches(&a, &x) && matches(&b, &x));
    }
}

/// The constructor the tree picks for `x`: descend by the field values,
/// then the first matching pattern of the leaf.
fn resolve(tree: &DecisionTree, x: &[u8]) -> Option<u32> {
    let mut node = tree.nodes.first()?;
    while node.size > 0 {
        let bit = node.start_bit as usize;
        let mut v = 0_usize;
        for i in 0..usize::from(node.size) {
            let b = bit + i;
            let byte = x.get(b / 8).copied().unwrap_or(0);
            v = (v << 1) | usize::from((byte >> (7 - b % 8)) & 1);
        }
        node = tree.nodes.get(*node.children.get(v)?)?;
    }
    node.pairs
        .iter()
        .find(|(_, p)| p.block(false).is_some_and(|b| matches(b, x)))
        .map(|(c, _)| *c)
}

fn entries(blocks: &[Block]) -> Vec<Entry> {
    blocks
        .iter()
        .enumerate()
        .map(|(i, b)| Entry {
            pattern: Disjoint::Instruction(b.clone()),
            index: i as u32,
            ctor: CtorId::new(i as u32),
        })
        .collect()
}

fn small_block() -> impl Strategy<Value = Block> {
    (any::<u16>(), any::<u16>()).prop_map(|(mask, value)| {
        let mask = u32::from(mask) << 16;
        Block::word(0, mask, (u32::from(value) << 16) & mask)
    })
}

proptest! {
    #[test]
    fn tree_is_an_index_over_its_patterns(
        blocks in prop::collection::vec(small_block(), 1..9),
        xs in prop::collection::vec(any::<u16>(), 64),
    ) {
        let mut props = Properties::default();
        let tree = build_tree(entries(&blocks), &mut props).unwrap();
        let mut linear = entries(&blocks);
        let mut linear_props = Properties::default();
        order_patterns(&mut linear, &mut linear_props);
        let clean = props.identical.is_empty() && props.conflicts.is_empty();
        for x in xs {
            let x = x.to_be_bytes();
            let picked = resolve(&tree, &x);
            let matching: Vec<u32> = (0..blocks.len() as u32)
                .filter(|&i| matches(&blocks[i as usize], &x))
                .collect();
            // Whatever is picked matches; something is picked iff something matches.
            prop_assert_eq!(picked.is_some(), !matching.is_empty());
            if let Some(p) = picked {
                prop_assert!(matching.contains(&p));
            }
            if matching.len() == 1 {
                prop_assert_eq!(picked, matching.first().copied());
            }
            // Without identical or conflicting patterns, the tree agrees with
            // a linear scan of the specialisation-ordered list.
            if clean {
                let scan = linear
                    .iter()
                    .find(|e| e.pattern.block(false).is_some_and(|b| matches(b, &x)))
                    .map(|e| e.index);
                prop_assert_eq!(picked, scan);
            }
        }
    }
}
