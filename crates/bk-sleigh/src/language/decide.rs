//! The decision trees of every subtable laid out for the decoder (the data
//! of Ghidra `DecisionNode::resolve` and `DisjointPattern::isMatch`).
//!
//! The model keeps a tree as `bk-sla` read it: nodes, pairs that name a
//! pattern by block ids, blocks that name their words by span. Walking that
//! costs a look-up per level and per block. Here each node says directly
//! which bits it tests (byte, bit and shifts precomputed), each leaf's pairs
//! sit in one array with both of their blocks inline, and each subtable's
//! root and constructor range are one look-up away. Nothing about the result
//! changes: node ids are the model's, pairs keep their order, and a model
//! that would fail a look-up fails it at the same point.

use bk_sla::{BlockId, DecisionId, DisjointPattern, MaskWord, Sla, SymbolKind};

use crate::decode::tree::NONE;

/// What a decision node does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// A leaf: pairs `first..first + count` of [`Trees::pairs`].
    Leaf,
    /// Tests instruction bits: `(read(offset + pos, a) << b) >> c`.
    Bits,
    /// Tests context bits: word `pos` shifted `<< a >> b`, and when `c > 0`
    /// the next word `>> (32 - c)` (Ghidra `getContextBits`).
    Context,
    /// A node id the model does not have.
    Missing,
}

/// One decision node, sixteen bytes so that a tree walk touches as few
/// cache lines as possible. Shift counts are stored modulo 32, as the
/// wrapping shifts they feed use them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Step {
    /// The first child (`Bits`, `Context`) or pair (`Leaf`).
    pub(crate) first: u32,
    /// `Bits`: `start_bit / 8`; `Context`: the context word.
    pub(crate) pos: i32,
    /// The number of children (`2^size`) or of pairs.
    pub(crate) count: u32,
    pub(crate) kind: Kind,
    /// `Bits`: bytes read, capped at 255; `Context`: left shift.
    pub(crate) a: u8,
    /// `Bits`: left shift; `Context`: right shift.
    pub(crate) b: u8,
    /// `Bits`: right shift; `Context`: bits taken from the next word.
    pub(crate) c: u8,
}

impl Step {
    const MISSING: Self = Self {
        first: NONE,
        pos: 0,
        count: 0,
        kind: Kind::Missing,
        a: 0,
        b: 0,
        c: 0,
    };
}

/// What one block of a pair tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    /// Always matches (no block, or an empty one).
    True,
    /// Never matches.
    False,
    /// Words `first..first + count` of [`Trees::words`] from byte `offset`.
    Words { offset: i32, first: u32, count: u32 },
    /// A block id the model does not have.
    Missing,
}

/// One pattern/constructor pair of a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pair {
    /// The constructor's index in its subtable.
    pub(crate) constructor: u32,
    /// The instruction block, tested first.
    pub(crate) instruction: Block,
    /// The context block.
    pub(crate) context: Block,
}

/// A subtable's tree root and constructor range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Root {
    /// The root node, or [`NONE`] when the symbol is not a subtable.
    pub(crate) decision: u32,
    /// The subtable's first constructor id.
    pub(crate) first_constructor: u32,
    /// Its number of constructors.
    pub(crate) num_constructors: u32,
}

/// Every subtable's decision tree.
#[derive(Clone, Debug, Default)]
pub(crate) struct Trees {
    /// Indexed by decision id.
    pub(crate) steps: Vec<Step>,
    pub(crate) pairs: Vec<Pair>,
    pub(crate) words: Vec<MaskWord>,
    /// Indexed by symbol id.
    pub(crate) roots: Vec<Root>,
}

impl Trees {
    pub(crate) fn build(sla: &Sla) -> Self {
        let mut trees = Self {
            roots: sla
                .symbols()
                .iter()
                .map(|symbol| match &symbol.kind {
                    SymbolKind::Subtable(table) => Root {
                        decision: table.decision.index(),
                        first_constructor: table.constructors.start(),
                        num_constructors: table.num_constructors(),
                    },
                    _ => Root {
                        decision: NONE,
                        first_constructor: NONE,
                        num_constructors: 0,
                    },
                })
                .collect(),
            ..Self::default()
        };
        let mut id = 0u32;
        while let Some(node) = sla.decision(DecisionId::new(id)) {
            let step = if node.is_leaf() {
                let first = trees.pairs.len() as u32;
                for pair in sla.pairs(node) {
                    let (instruction, context) = match pair.pattern {
                        DisjointPattern::Instruction(block) => {
                            (trees.block(sla, block), Block::True)
                        }
                        DisjointPattern::Context(block) => (Block::True, trees.block(sla, block)),
                        DisjointPattern::Combine {
                            context,
                            instruction,
                        } => (trees.block(sla, instruction), trees.block(sla, context)),
                    };
                    trees.pairs.push(Pair {
                        constructor: pair.constructor,
                        instruction,
                        context,
                    });
                }
                Step {
                    first,
                    pos: 0,
                    count: trees.pairs.len() as u32 - first,
                    kind: Kind::Leaf,
                    a: 0,
                    b: 0,
                    c: 0,
                }
            } else {
                let size = u32::from(node.size);
                let first = sla.decision_child(node, 0).map_or(NONE, DecisionId::index);
                let count = node.num_children();
                if node.context {
                    // The arithmetic of `Env::context_bits`, done once.
                    let bit_offset = node.start_bit.rem_euclid(32) as u32;
                    let remaining = (size as i32 - 32).wrapping_add(bit_offset as i32);
                    Step {
                        first,
                        pos: node.start_bit.div_euclid(32),
                        count,
                        kind: Kind::Context,
                        a: (bit_offset & 31) as u8,
                        b: (32u32.wrapping_sub(size) & 31) as u8,
                        c: remaining.clamp(0, 255) as u8,
                    }
                } else {
                    // The arithmetic of `Env::instruction_bits`, done once.
                    let bit = (node.start_bit % 8) as u32;
                    let byte_size = bit.wrapping_add(size).saturating_sub(1) / 8 + 1;
                    Step {
                        first,
                        pos: node.start_bit / 8,
                        count,
                        kind: Kind::Bits,
                        a: byte_size.min(255) as u8,
                        b: ((8 * (4 - byte_size.min(4))).wrapping_add(bit) & 31) as u8,
                        c: (32u32.wrapping_sub(size) & 31) as u8,
                    }
                }
            };
            trees.steps.push(step);
            id += 1;
        }
        trees
    }

    fn block(&mut self, sla: &Sla, id: BlockId) -> Block {
        let Some(block) = sla.block(id) else {
            return Block::Missing;
        };
        if block.nonzero <= 0 {
            return if block.nonzero == 0 {
                Block::True
            } else {
                Block::False
            };
        }
        let first = self.words.len() as u32;
        self.words.extend_from_slice(sla.block_words(block));
        Block::Words {
            offset: block.offset,
            first,
            count: self.words.len() as u32 - first,
        }
    }

    /// The node with id `id`.
    #[inline]
    pub(crate) fn step(&self, id: u32) -> Step {
        self.steps
            .get(id as usize)
            .copied()
            .unwrap_or(Step::MISSING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_are_small() {
        assert_eq!(size_of::<Step>(), 16);
    }
}
