//! Building a table's decision tree (`DecisionNode::split`,
//! `chooseOptimalField`, `consistentValues`, inventory 10 c.6–c.8).

use super::order::order_patterns;
use super::score::score;
use super::{DecisionError, DecisionNode, DecisionTree, Properties};
use crate::ids::CtorId;
use crate::pattern::Disjoint;

/// A pattern at a node: the disjunct, the constructor's index in its table
/// and its id.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) pattern: Disjoint,
    pub(crate) index: u32,
    pub(crate) ctor: CtorId,
}

/// A node while it is built: its entries and its parent's entry count.
struct Pending {
    node: usize,
    entries: Vec<Entry>,
    parent_num: Option<usize>,
}

/// `(1 << size) - 1` for a field of 1–32 bits.
const fn field_mask(size: i32) -> u32 {
    if size >= 32 {
        u32::MAX
    } else {
        (1_u32 << size) - 1
    }
}

/// The candidate field of a node.
#[derive(Clone, Copy, Debug, Default)]
struct Field {
    start: i32,
    size: i32,
    context: bool,
}

fn max_length(entries: &[Entry], context: bool) -> i32 {
    entries
        .iter()
        .map(|e| e.pattern.length(context))
        .fold(0, i32::max)
}

fn num_fixed(entries: &[Entry], f: Field) -> usize {
    let m = field_mask(f.size);
    entries
        .iter()
        .filter(|e| e.pattern.mask(f.start, f.size, f.context) & m == m)
        .count()
}

fn field_score(entries: &[Entry], f: Field, counts: &mut Vec<u32>) -> f64 {
    let m = field_mask(f.size);
    counts.clear();
    counts.resize(1 << f.size, 0);
    let mut total = 0_u32;
    for e in entries {
        if e.pattern.mask(f.start, f.size, f.context) & m != m {
            continue;
        }
        let v = e.pattern.value(f.start, f.size, f.context) as usize;
        total += 1;
        if let Some(c) = counts.get_mut(v) {
            *c += 1;
        }
    }
    score(counts, total, entries.len())
}

/// `chooseOptimalField`: the field to split on, or `None` for a leaf.
fn choose_field(entries: &[Entry]) -> Option<Field> {
    let mut best: Option<Field> = None;
    let mut best_score = 0.0_f64;
    let mut max_fixed = 1_usize;
    let mut counts = Vec::with_capacity(256);
    for context in [true, false] {
        let max = 8 * max_length(entries, context);
        for start in 0..max {
            let f = Field {
                start,
                size: 1,
                context,
            };
            let fixed = num_fixed(entries, f);
            if fixed < max_fixed {
                continue;
            }
            let sc = field_score(entries, f, &mut counts);
            if fixed > max_fixed && sc > 0.0 {
                best_score = sc;
                max_fixed = fixed;
                best = Some(f);
                continue;
            }
            if sc > best_score {
                best_score = sc;
                best = Some(f);
            }
        }
    }
    for context in [true, false] {
        let max = 8 * max_length(entries, context);
        for size in 2..=8 {
            for start in 0..(max - size + 1).max(0) {
                let f = Field {
                    start,
                    size,
                    context,
                };
                if num_fixed(entries, f) < max_fixed {
                    continue;
                }
                let sc = field_score(entries, f, &mut counts);
                if sc > best_score {
                    best_score = sc;
                    best = Some(f);
                }
            }
        }
    }
    if best_score <= 0.0 { None } else { best }
}

/// `consistentValues`: every value of the field the pattern allows.
fn consistent_values(pattern: &Disjoint, f: Field, out: &mut Vec<u32>) {
    let m = field_mask(f.size);
    let common_mask = m & pattern.mask(f.start, f.size, f.context);
    let common_value = common_mask & pattern.value(f.start, f.size, f.context);
    let dont_care = m ^ common_mask;
    out.clear();
    let mut i = 0_u32;
    loop {
        if i & dont_care == i {
            out.push(common_value | i);
        }
        if i >= dont_care {
            break;
        }
        i += 1;
    }
}

/// Builds the decision tree of one table from its entries (constructors
/// in order, disjuncts in order).
pub(crate) fn build_tree(
    entries: Vec<Entry>,
    props: &mut Properties,
) -> Result<DecisionTree, DecisionError> {
    let mut tree = DecisionTree {
        nodes: vec![DecisionNode {
            number: entries.len() as i32,
            ..DecisionNode::default()
        }],
    };
    let mut stack = vec![Pending {
        node: 0,
        entries,
        parent_num: None,
    }];
    let mut values = Vec::new();
    while let Some(Pending {
        node,
        mut entries,
        parent_num,
    }) = stack.pop()
    {
        if entries.len() <= 1 {
            if let Some(n) = tree.nodes.get_mut(node) {
                n.pairs = entries.into_iter().map(|e| (e.index, e.pattern)).collect();
            }
            continue;
        }
        let Some(field) = choose_field(&entries) else {
            order_patterns(&mut entries, props);
            if let Some(n) = tree.nodes.get_mut(node) {
                n.pairs = entries.into_iter().map(|e| (e.index, e.pattern)).collect();
            }
            continue;
        };
        if parent_num.is_some_and(|p| entries.len() >= p) {
            return Err(DecisionError::ChildAsLargeAsParent);
        }
        let num_children = 1_usize << field.size;
        let mut children: Vec<Vec<Entry>> = vec![Vec::new(); num_children];
        for e in &entries {
            consistent_values(&e.pattern, field, &mut values);
            for &v in &values {
                if let Some(c) = children.get_mut(v as usize) {
                    c.push(Entry {
                        pattern: e.pattern.simplified(),
                        index: e.index,
                        ctor: e.ctor,
                    });
                }
            }
        }
        let first_child = tree.nodes.len();
        for c in &children {
            tree.nodes.push(DecisionNode {
                number: c.len() as i32,
                ..DecisionNode::default()
            });
        }
        if let Some(n) = tree.nodes.get_mut(node) {
            n.context = field.context;
            n.start_bit = field.start;
            n.size = field.size as u8;
            n.children = (first_child..first_child + num_children).collect();
        }
        let parent = entries.len();
        for (i, c) in children.into_iter().enumerate().rev() {
            stack.push(Pending {
                node: first_child + i,
                entries: c,
                parent_num: Some(parent),
            });
        }
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::Block;

    fn entry(index: u32, mask: u32, value: u32) -> Entry {
        Entry {
            pattern: Disjoint::Instruction(Block::word(0, mask, value)),
            index,
            ctor: CtorId::new(index),
        }
    }

    #[test]
    fn consistent_values_enumerate_dont_cares() {
        let p = Disjoint::Instruction(Block::word(0, 0x8000_0000, 0x8000_0000));
        let mut out = Vec::new();
        consistent_values(&p, Field { start: 0, size: 2, context: false }, &mut out);
        assert_eq!(out, [2, 3]);
    }

    #[test]
    fn chooses_the_most_informative_bit() {
        // Bit 0 splits 2/2, bit 1 splits 1/3: bit 0 wins; then 2-bit fields
        // over bits 0..1 split all four apart, which beats both.
        let e = vec![
            entry(0, 0xc000_0000, 0x0000_0000),
            entry(1, 0xc000_0000, 0x4000_0000),
            entry(2, 0xc000_0000, 0x8000_0000),
            entry(3, 0xc000_0000, 0xc000_0000),
        ];
        let f = choose_field(&e).unwrap();
        assert_eq!((f.start, f.size, f.context), (0, 2, false));
    }

    #[test]
    fn maxfixed_resets_the_score() {
        // Bit 0 is fixed by 2 patterns, bit 4 by 3: bit 4 wins although bit
        // 0's split is better balanced.
        let e = vec![
            entry(0, 0x8800_0000, 0x0000_0000),
            entry(1, 0x8800_0000, 0x8800_0000),
            entry(2, 0x0800_0000, 0x0800_0000),
        ];
        let f = choose_field(&e).unwrap();
        assert_eq!((f.start, f.size), (4, 1));
    }

    #[test]
    fn context_wins_a_tie_with_instruction() {
        let both = |i: u32, v: u32| Entry {
            pattern: Disjoint::Combine {
                context: Block::word(0, 0x8000_0000, v),
                instr: Block::word(0, 0x8000_0000, v),
            },
            index: i,
            ctor: CtorId::new(i),
        };
        let e = vec![both(0, 0), both(1, 0x8000_0000)];
        let f = choose_field(&e).unwrap();
        assert!(f.context);
    }

    #[test]
    fn tree_separates_patterns() {
        let mut props = Properties::default();
        let e = vec![entry(0, 0x8000_0000, 0), entry(1, 0x8000_0000, 0x8000_0000)];
        let t = build_tree(e, &mut props).unwrap();
        assert_eq!(t.nodes.len(), 3);
        assert_eq!(t.nodes[0].size, 1);
        assert_eq!(t.nodes[1].pairs.len(), 1);
        assert_eq!(t.nodes[2].pairs[0].0, 1);
    }
}
