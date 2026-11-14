//! Walking a subtable's decision tree and matching the patterns of a leaf
//! (Ghidra `DecisionNode::resolve`, `DisjointPattern::isMatch`,
//! `PatternBlock::isInstructionMatch`, `isContextMatch`), over the layout of
//! [`crate::language::decide`].

use bk_sla::{ConstructorId, SymbolId};

use super::bytes::WINDOW;
use super::expr::Env;
use super::fault::{Fault, What};
use crate::language::decide::{Block, Kind, Trees};

impl Env<'_> {
    /// The constructor of subtable `table` that the bytes at `node_offset`
    /// and the local context select.
    pub(crate) fn choose(&self, table: SymbolId, node_offset: u32) -> Result<ConstructorId, Fault> {
        let trees = &self.lang.tables.trees;
        let root = trees
            .roots
            .get(table.index() as usize)
            .filter(|root| root.decision != crate::decode::tree::NONE)
            .ok_or(Fault::Model(What::Subtable))?;
        let mut id = root.decision;
        // A validated tree is at most 64 levels deep; the bound only keeps a
        // malformed one from looping.
        for _ in 0..=256 {
            let step = trees.step(id);
            let value = match step.kind {
                Kind::Leaf => {
                    let pairs = trees
                        .pairs
                        .get(step.first as usize..step.first.wrapping_add(step.count) as usize)
                        .unwrap_or_default();
                    for pair in pairs {
                        if self.block_matches(trees, pair.instruction, node_offset)?
                            && self.context_block_matches(trees, pair.context)?
                        {
                            return (pair.constructor < root.num_constructors)
                                .then(|| {
                                    ConstructorId::new(
                                        root.first_constructor.wrapping_add(pair.constructor),
                                    )
                                })
                                .ok_or(Fault::Model(What::DecisionPairConstructor));
                        }
                    }
                    return Err(Fault::NoConstructor);
                }
                Kind::Bits => {
                    // `getInstructionBits` with the arithmetic done.
                    let pos = node_offset.wrapping_add(step.pos as u32);
                    if pos as usize >= WINDOW {
                        return Err(Fault::TooLong);
                    }
                    let byte_size = u32::from(step.a);
                    if pos as usize + byte_size as usize > WINDOW {
                        self.parse.overhang.set(true);
                    }
                    let raw = self.parse.window.read(pos, byte_size.min(4));
                    raw.wrapping_shl(u32::from(step.b))
                        .wrapping_shr(u32::from(step.c))
                }
                Kind::Context => {
                    // `getContextBits` with the arithmetic done.
                    let word = |i: i32| {
                        usize::try_from(i)
                            .ok()
                            .and_then(|i| self.parse.context.get(i))
                            .copied()
                    };
                    let mut value = word(step.pos)
                        .unwrap_or(0)
                        .wrapping_shl(u32::from(step.a))
                        .wrapping_shr(u32::from(step.b));
                    if step.c > 0
                        && let Some(next) = word(step.pos.wrapping_add(1))
                    {
                        value |= next.wrapping_shr(32u32.wrapping_sub(u32::from(step.c)));
                    }
                    value
                }
                Kind::Missing => return Err(Fault::Model(What::DecisionNode)),
            };
            let (children, first) = (step.count, step.first);
            if value >= children {
                return Err(Fault::Model(What::DecisionChild));
            }
            id = first.wrapping_add(value);
        }
        Err(Fault::Model(What::DecisionTreeTooDeep))
    }

    /// Ghidra `PatternBlock::isInstructionMatch`.
    #[inline]
    fn block_matches(&self, trees: &Trees, block: Block, node_offset: u32) -> Result<bool, Fault> {
        match block {
            Block::True => Ok(true),
            Block::False => Ok(false),
            Block::Missing => Err(Fault::Model(What::PatternBlock)),
            Block::Words {
                offset,
                first,
                count,
            } => {
                let words = trees
                    .words
                    .get(first as usize..first.wrapping_add(count) as usize)
                    .unwrap_or_default();
                let mut off = offset;
                for word in words {
                    let data = self.pattern_word(off, node_offset, word.mask)?;
                    if word.mask & data != word.value {
                        return Ok(false);
                    }
                    off = off.wrapping_add(4);
                }
                Ok(true)
            }
        }
    }

    /// Ghidra `PatternBlock::isContextMatch`.
    #[inline]
    fn context_block_matches(&self, trees: &Trees, block: Block) -> Result<bool, Fault> {
        match block {
            Block::True => Ok(true),
            Block::False => Ok(false),
            Block::Missing => Err(Fault::Model(What::PatternBlock)),
            Block::Words {
                offset,
                first,
                count,
            } => {
                let words = trees
                    .words
                    .get(first as usize..first.wrapping_add(count) as usize)
                    .unwrap_or_default();
                let mut off = offset;
                for word in words {
                    if word.mask & self.context_bytes(off, 4) != word.value {
                        return Ok(false);
                    }
                    off = off.wrapping_add(4);
                }
                Ok(true)
            }
        }
    }
}
